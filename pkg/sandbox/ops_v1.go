// SPDX-License-Identifier: AGPL-3.0-only

package sandbox

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// sandbox-ops-v1 (docs/sandbox-ops-v1.md) is a separately versioned
// extension of sandbox-lease-v1: bounded exec and file operations on a
// running lease. It adds its own capability feature, documents, envelope and
// tables and changes nothing in sandbox-lease-v1.
const (
	// OpsCapabilityFeature is advertised only by a miner agent whose
	// sandbox-lease-v1 lane runs on a backend that implements the ops
	// extension. No released miner agent advertises it yet.
	OpsCapabilityFeature = "sandbox-ops-v1"

	// MaxOpWindow bounds expires_at - issued_at of one op request. It is
	// both the admission deadline and the replay window: a miner keeps the
	// op record at least until expires_at plus IssueSkew.
	MaxOpWindow = 60 * time.Second
	// SyncOpBudget bounds a file operation on the miner.
	SyncOpBudget = 30 * time.Second
	// ExecKillGrace is the delay between SIGTERM and SIGKILL of an exec's
	// process group at timeout, cancel or lease end.
	ExecKillGrace = 5 * time.Second
)

// Op kinds.
const (
	OpExecStart  = "exec_start"
	OpExecRead   = "exec_read"
	OpExecCancel = "exec_cancel"
	OpFileWrite  = "file_write"
	OpFileRead   = "file_read"
	OpFileStat   = "file_stat"
	OpFileList   = "file_list"
	OpFileRemove = "file_remove"
	OpFileMkdir  = "file_mkdir"
)

// Bounds of the ops extension. Payload and result bytes travel base64 in a
// bridge envelope capped at 1 MiB, so one chunk is at most 512 KiB raw.
const (
	MaxChunkBytes       = 512 << 10
	MaxFileWriteBytes   = 256 << 20
	MaxListEntries      = 1000
	MinExecTimeoutMS    = 1000
	MaxExecTimeoutMS    = 24 * 60 * 60 * 1000
	MinExecOutputBytes  = 1 << 10
	MaxExecOutputBytes  = 16 << 20
	MaxRunningExecs     = 16
	MaxExecSessions     = 1024
	MaxExecArgs         = 1024
	MaxExecArgBytes     = 32 << 10
	MaxExecArgvBytes    = 256 << 10
	MaxExecStdinBytes   = 256 << 10
	MaxPathBytes        = 4096
	MaxPathComponent    = 255
	MaxFileModeBits     = 0o777
	ExecStdout          = "stdout"
	ExecStderr          = "stderr"
	FileTypeFile        = "file"
	FileTypeDirectory   = "directory"
	FileTypeSymlink     = "symlink"
	FileTypeOther       = "other"
	ExecStateRunning    = "running"
	ExecStateExited     = "exited"
	ExecStateCancelled  = "cancelled"
	ExecStateTimedOut   = "timed_out"
	ExecStateFailed     = "failed"
	OpStageCompleted    = "completed"
	OpStageRunning      = "running"
	OpStageExited       = "exited"
	OpStageCancelled    = "cancelled"
	OpStageTimedOut     = "timed_out"
	OpStageRefused      = "refused"
	OpStageFailed       = "failed"
	OpCodeOpsDisabled   = "sandbox_disabled"
	OpCodeOpsUnsupport  = "ops_unsupported"
	OpCodeDeadline      = "op_deadline_exceeded"
	OpCodeRuntimeFailed = "op_runtime_failed"
	// OpCodeSandboxFailed and OpCodeResourcesExhausted report failures that
	// originate inside the sandbox (lane 7 B-6): guest code shares the
	// helper's identity and can kill, starve or break it, so they are never
	// miner faults.
	OpCodeSandboxFailed      = "sandbox_op_failed"
	OpCodeResourcesExhausted = "sandbox_resources_exhausted"
)

// OpErrorAttribution maps every op receipt error code to whether it is
// attributed to the miner. Every failure that originates inside the sandbox
// (customer state, a helper error, exit or kill, exhausted lease resources),
// validator decisions and unsupported features are not miner faults; only
// miner-side engine and transport failures (op_runtime_failed) and restart
// are. Ops are score-neutral in v1; attribution is diagnostic only.
var OpErrorAttribution = map[string]bool{
	"lease_not_running":      false,
	"sandbox_exited":         false,
	"lease_expired":          false,
	"released":               false,
	"exec_not_found":         false,
	"exec_limit_exceeded":    false,
	"path_not_found":         false,
	"path_exists":            false,
	"path_not_file":          false,
	"path_not_directory":     false,
	"path_refused":           false,
	"directory_not_empty":    false,
	"permission_denied":      false,
	"no_space":               false,
	"file_too_large":         false,
	"offset_mismatch":        false,
	OpCodeDeadline:           false,
	OpCodeOpsUnsupport:       false,
	OpCodeOpsDisabled:        false,
	OpCodeSandboxFailed:      false,
	OpCodeResourcesExhausted: false,
	OpCodeRuntimeFailed:      true,
	"miner_restart":          true,
}

// ValidOp reports whether value is a v1 op kind.
func ValidOp(value string) bool {
	switch value {
	case OpExecStart, OpExecRead, OpExecCancel, OpFileWrite, OpFileRead, OpFileStat, OpFileList, OpFileRemove, OpFileMkdir:
		return true
	}
	return false
}

// ValidOpPath checks the v1 sandbox path syntax: absolute, printable ASCII
// (signed documents are canonical ASCII JSON), at most 4096 bytes, every
// component 1..255 bytes, no empty, "." or ".." component and no trailing
// slash. The root "/" is valid only where allowRoot is set (stat and list).
//
// Syntax is not containment: a valid path may still name a symlink. How a
// path resolves (always inside the sandbox root) is the backend's duty; see
// pkg/sandbox/fsroot for the reference resolver.
func ValidOpPath(path string, allowRoot bool) error {
	if len(path) == 0 || len(path) > MaxPathBytes || path[0] != '/' {
		return errors.New("sandbox path must be absolute and at most 4096 bytes")
	}
	for index := 0; index < len(path); index++ {
		if path[index] < 0x20 || path[index] > 0x7e {
			return errors.New("sandbox path must be printable ASCII")
		}
	}
	if path == "/" {
		if !allowRoot {
			return errors.New("sandbox path must not be the root")
		}
		return nil
	}
	for _, component := range strings.Split(path[1:], "/") {
		if component == "" || component == "." || component == ".." || len(component) > MaxPathComponent {
			return errors.New("sandbox path has an empty, dot or oversized component")
		}
	}
	return nil
}

// ExecCommand is the exec_start payload. It travels beside the signed
// request, bound by payload_digest, and protocol code never persists or
// logs it. argv and stdin are customer data that the miner operator can
// read: they are not confidential, and must not carry secrets. Env is
// always {} in v1.
type ExecCommand struct {
	Argv  []string          `json:"argv"`
	Cwd   string            `json:"cwd"`
	Env   map[string]string `json:"env"`
	Stdin *string           `json:"stdin_b64"`
}

// Validate checks the payload bounds.
func (c ExecCommand) Validate() error {
	if len(c.Argv) == 0 || len(c.Argv) > MaxExecArgs {
		return errors.New("exec argv must hold 1..1024 arguments")
	}
	total := 0
	for _, argument := range c.Argv {
		if len(argument) > MaxExecArgBytes || strings.IndexByte(argument, 0) >= 0 {
			return errors.New("exec argument is oversized or contains NUL")
		}
		total += len(argument)
	}
	if c.Argv[0] == "" || total > MaxExecArgvBytes {
		return errors.New("exec argv is empty or oversized")
	}
	if err := ValidOpPath(c.Cwd, true); err != nil {
		return fmt.Errorf("exec cwd: %w", err)
	}
	// OPS-D1: per-exec environment would bypass the lease rule that every
	// customer variable goes through secret_env (refused until sealed
	// delivery exists), so v1 carries env only as the empty object.
	if err := ValidateEnv(c.Env); err != nil {
		return fmt.Errorf("exec %w", err)
	}
	if c.Stdin != nil {
		decoded, err := base64.StdEncoding.Strict().DecodeString(*c.Stdin)
		if err != nil || len(decoded) > MaxExecStdinBytes {
			return errors.New("exec stdin_b64 is not canonical base64 of at most 256 KiB")
		}
	}
	return nil
}

// StdinBytes returns the decoded stdin, nil when absent. Call Validate first.
func (c ExecCommand) StdinBytes() []byte {
	if c.Stdin == nil {
		return nil
	}
	decoded, _ := base64.StdEncoding.Strict().DecodeString(*c.Stdin)
	return decoded
}

// DecodeExecCommand strictly decodes and validates an exec_start payload:
// exactly one JSON object, no unknown or duplicate members, every member
// present.
func DecodeExecCommand(payload []byte) (ExecCommand, error) {
	var command ExecCommand
	if len(payload) == 0 || len(payload) > MaxChunkBytes {
		return command, errors.New("exec payload size is invalid")
	}
	if err := rejectDuplicateMembers(payload); err != nil {
		return command, err
	}
	var present map[string]json.RawMessage
	if err := json.Unmarshal(payload, &present); err != nil {
		return command, errors.New("exec payload must be a JSON object")
	}
	for _, member := range []string{"argv", "cwd", "env", "stdin_b64"} {
		if _, ok := present[member]; !ok {
			return command, errors.New("exec payload member " + member + " is missing")
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&command); err != nil {
		return ExecCommand{}, errors.New("exec payload is invalid")
	}
	if _, err := decoder.Token(); err != io.EOF {
		return ExecCommand{}, errors.New("exec payload has trailing data")
	}
	if err := command.Validate(); err != nil {
		return ExecCommand{}, err
	}
	return command, nil
}

// rejectDuplicateMembers refuses a JSON value with a repeated object key at
// any depth, so two parsers can never read different payloads from the
// same digest-bound bytes.
func rejectDuplicateMembers(payload []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return errors.New("exec payload is not valid JSON")
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for decoder.More() {
				key, err := decoder.Token()
				if err != nil {
					return errors.New("exec payload is not valid JSON")
				}
				name, _ := key.(string)
				if seen[name] {
					return errors.New("exec payload has a duplicate member")
				}
				seen[name] = true
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
		}
		if err != nil {
			return errors.New("exec payload is not valid JSON")
		}
		return nil
	}
	return walk()
}

// ExecStatus is the miner's view of one exec session. Byte counts are
// totals produced; *_retained is the prefix kept for exec_read.
type ExecStatus struct {
	EndedAt        *string `json:"ended_at"`
	ExitCode       *int    `json:"exit_code"`
	StartedAt      string  `json:"started_at"`
	State          string  `json:"state"`
	StderrBytes    uint64  `json:"stderr_bytes"`
	StderrRetained uint64  `json:"stderr_retained"`
	StdoutBytes    uint64  `json:"stdout_bytes"`
	StdoutRetained uint64  `json:"stdout_retained"`
}

// FileInfo describes one sandbox path. Mode holds permission bits only.
type FileInfo struct {
	Mode uint32 `json:"mode"`
	Size uint64 `json:"size"`
	Type string `json:"type"`
}

// ValidFileType reports whether value is a v1 file type.
func ValidFileType(value string) bool {
	switch value {
	case FileTypeFile, FileTypeDirectory, FileTypeSymlink, FileTypeOther:
		return true
	}
	return false
}

// ListEntry is one directory entry of a file_list result.
type ListEntry struct {
	FileInfo
	Name string `json:"name"`
}

// ListResult is the file_list result body, carried beside the receipt and
// bound by result_digest. Entries are sorted by name bytes. Names that are
// not addressable v1 path components (non-printable-ASCII) are omitted and
// counted in Unaddressable, never silently renamed.
type ListResult struct {
	Entries       []ListEntry `json:"entries"`
	Unaddressable uint64      `json:"unaddressable"`
}

// Validate checks a file_list result: at most 1000 entries, each a single
// addressable path component, sorted by name bytes and unique.
func (l ListResult) Validate() error {
	if l.Entries == nil || len(l.Entries) > MaxListEntries {
		return errors.New("list entries must be an array of at most 1000")
	}
	for index, entry := range l.Entries {
		if strings.Contains(entry.Name, "/") || ValidOpPath("/"+entry.Name, false) != nil ||
			!ValidFileType(entry.Type) || entry.Mode > MaxFileModeBits {
			return errors.New("list entry is invalid")
		}
		if index > 0 && l.Entries[index-1].Name >= entry.Name {
			return errors.New("list entries must be sorted and unique")
		}
	}
	return nil
}
