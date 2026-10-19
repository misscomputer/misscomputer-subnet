// SPDX-License-Identifier: AGPL-3.0-only

// Package sandboxops is the private wire protocol between a miner backend and
// the in-sandbox helper of sandbox-ops-v1 (cmd/sandbox-ops-helper,
// docs/sandbox-ops-v1-helper.md). It is not a signed document and never
// leaves the miner: the backend writes one Request to the helper's stdin and
// reads one Response from its stdout, both bounded.
//
// Everything the helper answers is untrusted (helper_B_conditions B-5): guest
// code shares the helper's identity and can replace, starve or impersonate
// it. DecodeResponse therefore checks the shape strictly and refuses any code
// a guest must not be able to claim; the miner re-applies every cap.
package sandboxops

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"strings"

	"github.com/misscomputer/misscomputer-subnet/pkg/organic"
	"github.com/misscomputer/misscomputer-subnet/pkg/sandbox"
)

const (
	// Protocol names this wire format in every request and response.
	Protocol = "sandbox-ops-helper.v1"
	// MountTarget is the read-only directory mount that holds only the
	// helper (B-1), and HelperPath the fixed argv[0] of every invocation
	// (B-4).
	MountTarget = "/.misscomputer"
	HelperName  = "sandbox-ops-helper"
	HelperPath  = MountTarget + "/" + HelperName
	// CaptureRoot is the in-sandbox directory, owned by the image user with
	// mode 0700, where the helper keeps each exec's retained output and
	// status (D14). It is charged to the lease's own writable storage.
	CaptureRoot = "/tmp/.misscomputer-ops"
	// MaxRequestBytes and MaxResponseBytes bound one helper exchange: a
	// 512 KiB chunk travels base64 (about 683 KiB) plus members.
	MaxRequestBytes  = 1 << 20
	MaxResponseBytes = 1 << 20
	// MaxExecIDBytes bounds an exec ID, which names a capture directory.
	MaxExecIDBytes = 255
	// OpExecStatus is the helper-only status read of the kill path; it is
	// not a sandbox-ops-v1 op and has no receipt.
	OpExecStatus = "exec_status"
)

// helperCodes are the receipt error codes a helper may report. They are all
// non-fault codes that originate inside the sandbox. The miner-fault codes
// (op_runtime_failed, miner_restart), the lease-state codes and the cap code
// are decided by the miner, never by the helper.
var helperCodes = map[string]bool{
	"exec_not_found": true, "path_not_found": true, "path_exists": true, "path_not_file": true,
	"path_not_directory": true, "path_refused": true, "directory_not_empty": true, "permission_denied": true,
	"no_space": true, "file_too_large": true, "offset_mismatch": true, sandbox.OpCodeDeadline: true,
	sandbox.OpCodeOpsUnsupport: true, sandbox.OpCodeSandboxFailed: true, sandbox.OpCodeResourcesExhausted: true,
}

// HelperCode reports whether code may come from the helper.
func HelperCode(code string) bool { return helperCodes[code] }

// ExecSpec is what exec_start hands the helper: the validated command, the
// remaining time to the exec deadline, and the per-stream retention cap.
type ExecSpec struct {
	Command        sandbox.ExecCommand `json:"command"`
	MaxOutputBytes uint64              `json:"max_output_bytes"`
	TimeoutMS      uint64              `json:"timeout_ms"`
}

// Request is one helper invocation. Members an op does not use are null.
type Request struct {
	Data      *string   `json:"data_b64"`
	Exec      *ExecSpec `json:"exec"`
	ExecID    *string   `json:"exec_id"`
	Force     bool      `json:"force"`
	Limit     *uint64   `json:"limit"`
	Mode      *uint32   `json:"mode"`
	Offset    *uint64   `json:"offset"`
	Op        string    `json:"op"`
	Path      *string   `json:"path"`
	Protocol  string    `json:"protocol"`
	Recursive *bool     `json:"recursive"`
	Stream    *string   `json:"stream"`
}

// ExecObservation is what the helper observed of one exec inside the
// sandbox. It is customer-influenced (B-5): State and ExitCode come from the
// in-sandbox supervisor, and the byte counts from files guest code can write.
type ExecObservation struct {
	ExitCode       *int   `json:"exit_code"`
	State          string `json:"state"`
	StderrBytes    uint64 `json:"stderr_bytes"`
	StderrRetained uint64 `json:"stderr_retained"`
	StdoutBytes    uint64 `json:"stdout_bytes"`
	StdoutRetained uint64 `json:"stdout_retained"`
}

// Response is the helper's answer. Code is set exactly when the op failed.
type Response struct {
	Code     *string             `json:"code"`
	Data     *string             `json:"data_b64"`
	EOF      bool                `json:"eof"`
	Exec     *ExecObservation    `json:"exec"`
	File     *sandbox.FileInfo   `json:"file"`
	Listing  *sandbox.ListResult `json:"listing"`
	Protocol string              `json:"protocol"`
	Size     *uint64             `json:"size"`
}

// ValidExecID reports whether id can name a capture directory: the op ID
// syntax of a lease (ASCII letters, digits and hyphens; the lease ID holds
// the miner's SS58 hotkey), never a path or a dot name.
func ValidExecID(id string) bool {
	if id == "" || len(id) > MaxExecIDBytes || !strings.Contains(id, "-op-") {
		return false
	}
	for index := 0; index < len(id); index++ {
		if c := id[index]; !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

type members struct{ data, exec, execID, force, limit, mode, offset, path, recursive, stream bool }

var requestMembers = map[string]members{
	sandbox.OpExecStart:  {exec: true, execID: true},
	sandbox.OpExecRead:   {execID: true, offset: true, limit: true, stream: true},
	sandbox.OpExecCancel: {execID: true, force: true},
	OpExecStatus:         {execID: true},
	sandbox.OpFileWrite:  {path: true, data: true, offset: true, mode: true},
	sandbox.OpFileRead:   {path: true, offset: true, limit: true},
	sandbox.OpFileStat:   {path: true},
	sandbox.OpFileList:   {path: true, offset: true, limit: true},
	sandbox.OpFileRemove: {path: true, recursive: true},
	sandbox.OpFileMkdir:  {path: true, mode: true, recursive: true},
}

// Validate checks a request's shape and bounds; the helper re-checks paths
// and offsets in fsroot as well.
func (r Request) Validate() error {
	if r.Protocol != Protocol {
		return errors.New("helper request protocol is invalid")
	}
	want, known := requestMembers[r.Op]
	if !known {
		return errors.New("helper request op is invalid")
	}
	for _, member := range []struct {
		name             string
		allowed, present bool
	}{
		{"data_b64", want.data, r.Data != nil}, {"exec", want.exec, r.Exec != nil}, {"exec_id", want.execID, r.ExecID != nil},
		{"force", want.force, r.Force}, {"limit", want.limit, r.Limit != nil}, {"offset", want.offset, r.Offset != nil},
		{"path", want.path, r.Path != nil}, {"recursive", want.recursive, r.Recursive != nil}, {"stream", want.stream, r.Stream != nil},
	} {
		// force is a boolean that defaults to false, so only its presence
		// where the op does not use it is an error.
		if member.present && !member.allowed || !member.present && member.allowed && member.name != "force" {
			return errors.New("helper request member " + member.name + " does not match op " + r.Op)
		}
	}
	switch r.Op {
	case sandbox.OpFileWrite:
		if (*r.Offset == 0) != (r.Mode != nil) {
			return errors.New("helper file_write mode is required exactly at offset 0")
		}
		if _, err := chunk(*r.Data, 1); err != nil {
			return err
		}
	case sandbox.OpFileMkdir:
		if r.Mode == nil {
			return errors.New("helper file_mkdir needs a mode")
		}
	default:
		if r.Mode != nil {
			return errors.New("helper request member mode does not match op " + r.Op)
		}
	}
	if r.Mode != nil && *r.Mode > sandbox.MaxFileModeBits {
		return errors.New("helper request mode must hold permission bits only")
	}
	if r.Path != nil {
		if err := sandbox.ValidOpPath(*r.Path, r.Op == sandbox.OpFileStat || r.Op == sandbox.OpFileList); err != nil {
			return err
		}
	}
	if r.ExecID != nil && !ValidExecID(*r.ExecID) {
		return errors.New("helper request exec_id is invalid")
	}
	if r.Limit != nil && (*r.Limit < 1 || *r.Limit > sandbox.MaxChunkBytes) {
		return errors.New("helper request limit is out of bounds")
	}
	if r.Offset != nil && *r.Offset > sandbox.MaxSafeInteger {
		return errors.New("helper request offset is out of bounds")
	}
	if r.Stream != nil && *r.Stream != sandbox.ExecStdout && *r.Stream != sandbox.ExecStderr {
		return errors.New("helper request stream is invalid")
	}
	if r.Exec != nil {
		if err := r.Exec.Command.Validate(); err != nil {
			return err
		}
		if r.Exec.MaxOutputBytes < sandbox.MinExecOutputBytes || r.Exec.MaxOutputBytes > sandbox.MaxExecOutputBytes ||
			r.Exec.TimeoutMS < 1 || r.Exec.TimeoutMS > sandbox.MaxExecTimeoutMS {
			return errors.New("helper exec bounds are invalid")
		}
	}
	return nil
}

var execStates = map[string]bool{
	sandbox.ExecStateRunning: true, sandbox.ExecStateExited: true, sandbox.ExecStateCancelled: true,
	sandbox.ExecStateTimedOut: true, sandbox.ExecStateFailed: true,
}

// Validate checks the shape of an observation; the caller re-caps counts.
func (e ExecObservation) Validate() error {
	if !execStates[e.State] {
		return errors.New("helper exec state is invalid")
	}
	if (e.State == sandbox.ExecStateExited) != (e.ExitCode != nil) || e.ExitCode != nil && (*e.ExitCode < 0 || *e.ExitCode > 255) {
		return errors.New("helper exec exit_code is present exactly for an exited exec, 0..255")
	}
	if e.StdoutRetained > e.StdoutBytes || e.StderrRetained > e.StderrBytes || e.StdoutBytes > sandbox.MaxSafeInteger ||
		e.StderrBytes > sandbox.MaxSafeInteger || e.StdoutRetained > sandbox.MaxExecOutputBytes || e.StderrRetained > sandbox.MaxExecOutputBytes {
		return errors.New("helper exec byte counts are inconsistent")
	}
	return nil
}

// Validate checks a response's members without knowing the request; Answers
// checks it against the request.
func (r Response) Validate() error {
	if r.Protocol != Protocol {
		return errors.New("helper response protocol is invalid")
	}
	if r.Code != nil && !helperCodes[*r.Code] {
		return errors.New("helper response code is not a helper code")
	}
	if r.Data != nil {
		if _, err := chunk(*r.Data, 0); err != nil {
			return err
		}
	}
	if r.File != nil && (!sandbox.ValidFileType(r.File.Type) || r.File.Mode > sandbox.MaxFileModeBits) {
		return errors.New("helper response file is invalid")
	}
	if r.Listing != nil {
		if err := r.Listing.Validate(); err != nil {
			return err
		}
	}
	if r.Exec != nil {
		return r.Exec.Validate()
	}
	return nil
}

// Answers checks that response has exactly the members request's op
// produces. An exec op may carry an observation alongside its failure code.
func (r Response) Answers(request Request) error {
	failed := r.Code != nil
	if failed && (r.Data != nil || r.File != nil || r.Listing != nil || r.Size != nil || r.EOF) {
		return errors.New("helper failure carries a result")
	}
	if failed {
		if r.Exec != nil && request.Op != sandbox.OpExecStart && request.Op != sandbox.OpExecRead &&
			request.Op != sandbox.OpExecCancel && request.Op != OpExecStatus {
			return errors.New("helper file failure carries an exec")
		}
		return nil
	}
	var want struct{ data, exec, file, listing, size bool }
	switch request.Op {
	case sandbox.OpExecStart, sandbox.OpExecCancel, OpExecStatus:
		want.exec = true
	case sandbox.OpExecRead:
		want.exec, want.data = true, true
	case sandbox.OpFileRead:
		want.data, want.size = true, true
	case sandbox.OpFileWrite, sandbox.OpFileStat, sandbox.OpFileMkdir:
		want.file = true
	case sandbox.OpFileList:
		want.listing = true
	}
	if want.data != (r.Data != nil) || want.exec != (r.Exec != nil) || want.file != (r.File != nil) ||
		want.listing != (r.Listing != nil) || want.size != (r.Size != nil) || r.EOF && request.Op != sandbox.OpFileList {
		return errors.New("helper response members do not answer op " + request.Op)
	}
	if r.Data != nil && request.Limit != nil {
		data, _ := chunk(*r.Data, 0)
		if uint64(len(data)) > *request.Limit {
			return errors.New("helper response data exceeds the request limit")
		}
	}
	if r.Listing != nil && uint64(len(r.Listing.Entries)) > *request.Limit {
		return errors.New("helper listing exceeds the request limit")
	}
	return nil
}

// Bytes returns the decoded data of a validated request, nil when absent.
func (r Request) Bytes() []byte {
	if r.Data == nil {
		return nil
	}
	data, _ := chunk(*r.Data, 1)
	return data
}

// Bytes returns the decoded data of a validated response, nil when absent.
func (r Response) Bytes() []byte {
	if r.Data == nil {
		return nil
	}
	data, _ := chunk(*r.Data, 0)
	return data
}

// EncodeData is the canonical base64 of one chunk.
func EncodeData(data []byte) *string {
	encoded := base64.StdEncoding.EncodeToString(data)
	return &encoded
}

// chunk decodes canonical standard base64 of min..MaxChunkBytes bytes.
func chunk(encoded string, min int) ([]byte, error) {
	data, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(data) < min || len(data) > sandbox.MaxChunkBytes || base64.StdEncoding.EncodeToString(data) != encoded {
		return nil, errors.New("helper data is not canonical base64 of an allowed chunk")
	}
	return data, nil
}

// Encode is the canonical JSON of a request or response.
func Encode(value any) ([]byte, error) {
	switch value.(type) {
	case Request, Response:
	default:
		return nil, errors.New("not a helper message")
	}
	encoded, err := organic.Canonical(value)
	if err != nil {
		return nil, err
	}
	if len(encoded) > MaxResponseBytes {
		return nil, errors.New("helper message exceeds its bound")
	}
	return encoded, nil
}

// ReadBounded reads at most limit bytes from reader and fails beyond it.
func ReadBounded(reader io.Reader, limit int) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > limit {
		return nil, errors.New("helper message exceeds its bound")
	}
	return data, nil
}

// DecodeRequest strictly decodes and validates one request.
func DecodeRequest(payload []byte) (Request, error) {
	var request Request
	if len(payload) > MaxRequestBytes {
		return Request{}, errors.New("helper request exceeds its bound")
	}
	if err := organic.DecodeStrict(bytes.TrimSuffix(payload, []byte("\n")), &request); err != nil {
		return Request{}, err
	}
	return request, nil
}

// DecodeResponse strictly decodes one response and checks it answers
// request. Every failure means the helper (or guest code posing as it)
// broke the protocol, which is sandbox_op_failed, never a miner fault.
func DecodeResponse(payload []byte, request Request) (Response, error) {
	var response Response
	if len(payload) > MaxResponseBytes {
		return Response{}, errors.New("helper response exceeds its bound")
	}
	if err := organic.DecodeStrict(bytes.TrimSuffix(payload, []byte("\n")), &response); err != nil {
		return Response{}, err
	}
	if err := response.Answers(request); err != nil {
		return Response{}, err
	}
	return response, nil
}

// Failure is a response carrying only code.
func Failure(code string) Response {
	return Response{Protocol: Protocol, Code: &code}
}
