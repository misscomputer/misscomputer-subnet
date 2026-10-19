// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package main

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/sandbox"
	"github.com/misscomputer/misscomputer-subnet/pkg/sandboxops"
)

// The supervisor is this test binary re-executed through /proc/self/exe,
// exactly as the helper re-executes itself in a sandbox.
func TestMain(m *testing.M) {
	if len(os.Args) == 4 && os.Args[1] == superviseArg {
		os.Exit(supervise(os.Args[2], os.Args[3]))
	}
	os.Exit(m.Run())
}

const testLease = "sbx-0123456789abcdef0123456789abcdef-5ct2k6e2-1-0123456789abcdef0123456789abcdef"

func execID(n byte) string {
	return testLease + "-op-" + strings.Repeat(string("0123456789abcdef"[n%16]), 32)
}

type harness struct {
	t      *testing.T
	root   string
	server *server
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	root := filepath.Join(t.TempDir(), "ops")
	return &harness{t: t, root: root, server: &server{openFS: openRoot, execs: newExecRunner(root, selfExecutable)}}
}

// call runs one request through the helper's stdin/stdout framing.
func (h *harness) call(request sandboxops.Request) sandboxops.Response {
	h.t.Helper()
	request.Protocol = sandboxops.Protocol
	encoded, err := sandboxops.Encode(request)
	if err != nil {
		h.t.Fatal(err)
	}
	var out bytes.Buffer
	if code := h.server.serve(bytes.NewReader(encoded), &out); code != 0 {
		h.t.Fatalf("serve exit %d", code)
	}
	response, err := sandboxops.DecodeResponse(out.Bytes(), request)
	if err != nil {
		h.t.Fatalf("response %q does not answer %s: %v", out.String(), request.Op, err)
	}
	return response
}

func u64(v uint64) *uint64 { return &v }

func (h *harness) start(id string, timeoutMS, maxOutput uint64, stdin *string, argv ...string) sandboxops.Response {
	h.t.Helper()
	return h.call(sandboxops.Request{Op: sandbox.OpExecStart, ExecID: &id, Exec: &sandboxops.ExecSpec{
		Command:        sandbox.ExecCommand{Argv: argv, Cwd: "/", Env: map[string]string{}, Stdin: stdin},
		MaxOutputBytes: maxOutput, TimeoutMS: timeoutMS,
	}})
}

// wait polls exec_status until the exec is terminal.
func (h *harness) wait(id string) sandboxops.ExecObservation {
	h.t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		response := h.call(sandboxops.Request{Op: sandboxops.OpExecStatus, ExecID: &id})
		if response.Exec == nil {
			h.t.Fatalf("status of %s: %v", id, *response.Code)
		}
		if response.Exec.State != sandbox.ExecStateRunning {
			return *response.Exec
		}
		if time.Now().After(deadline) {
			h.t.Fatalf("exec %s still running", id)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (h *harness) read(id, stream string, offset, limit uint64) []byte {
	h.t.Helper()
	response := h.call(sandboxops.Request{Op: sandbox.OpExecRead, ExecID: &id, Stream: &stream, Offset: &offset, Limit: &limit})
	if response.Code != nil {
		h.t.Fatalf("exec_read: %s", *response.Code)
	}
	return response.Bytes()
}

func TestExecRunsCommandAndRetainsEachStream(t *testing.T) {
	h := newHarness(t)
	id := execID(1)
	stdin := base64.StdEncoding.EncodeToString([]byte("from-stdin"))
	h.start(id, 30_000, 1024, &stdin, "sh", "-c", `cat; printf err >&2; exit 3`)
	got := h.wait(id)
	if got.State != sandbox.ExecStateExited || got.ExitCode == nil || *got.ExitCode != 3 {
		t.Fatalf("observation = %+v, want exited 3", got)
	}
	if out := h.read(id, sandbox.ExecStdout, 0, 4); string(out) != "from" {
		t.Fatalf("stdout page = %q", out)
	}
	if out := h.read(id, sandbox.ExecStdout, 4, 100); string(out) != "-stdin" {
		t.Fatalf("stdout rest = %q", out)
	}
	if out := h.read(id, sandbox.ExecStderr, 0, 100); string(out) != "err" {
		t.Fatalf("stderr = %q", out)
	}
	if got.StdoutRetained != 10 || got.StdoutBytes != 10 || got.StderrRetained != 3 {
		t.Fatalf("counts = %+v", got)
	}
}

func TestExecRetainsOnlyTheFirstMaxOutputBytes(t *testing.T) {
	h := newHarness(t)
	id := execID(2)
	h.start(id, 30_000, 1024, nil, "sh", "-c", `i=0; while [ $i -lt 500 ]; do printf 0123456789; i=$((i+1)); done`)
	got := h.wait(id)
	if got.StdoutBytes != 5000 || got.StdoutRetained != 1024 {
		t.Fatalf("counts = %+v, want 5000 produced and 1024 retained", got)
	}
	if out := h.read(id, sandbox.ExecStdout, 1000, 512); len(out) != 24 {
		t.Fatalf("read past retention returned %d bytes, want 24", len(out))
	}
}

// A replay of exec_start, or a retried backend start, must never run the
// command a second time.
func TestExecStartIsIdempotentPerExecID(t *testing.T) {
	h := newHarness(t)
	id := execID(3)
	marker := filepath.Join(t.TempDir(), "runs")
	script := `printf x >> "$0"`
	h.start(id, 30_000, 1024, nil, "sh", "-c", script, marker)
	h.wait(id)
	h.start(id, 30_000, 1024, nil, "sh", "-c", script, marker)
	if runs, err := os.ReadFile(marker); err != nil || string(runs) != "x" {
		t.Fatalf("command ran %q times (%v), want once", runs, err)
	}
}

func groupAlive(t *testing.T, pidFile string) bool {
	t.Helper()
	raw, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatal(err)
	}
	var pid int
	for _, c := range strings.TrimSpace(string(raw)) {
		pid = pid*10 + int(c-'0')
	}
	// A killed process whose parent cannot reap it yet is a zombie: dead.
	stat, err := os.ReadFile("/proc/" + strings.TrimSpace(string(raw)) + "/stat")
	if err != nil {
		return false
	}
	fields := strings.Fields(string(stat[bytes.LastIndexByte(stat, ')')+1:]))
	return pid > 0 && len(fields) > 0 && fields[0] != "Z"
}

func waitFile(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if raw, err := os.ReadFile(path); err == nil && len(raw) > 0 && raw[len(raw)-1] == '\n' {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s never written", path)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Cancel and the exec deadline both end the exec's whole process group,
// including a background child the command started.
func TestExecCancelAndDeadlineKillTheProcessGroup(t *testing.T) {
	for _, tc := range []struct {
		name      string
		timeoutMS uint64
		cancel    bool
		want      string
	}{
		{"cancel", 60_000, true, sandbox.ExecStateCancelled},
		{"deadline", 500, false, sandbox.ExecStateTimedOut},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			id := execID(4)
			pidFile := filepath.Join(t.TempDir(), "child")
			h.start(id, tc.timeoutMS, 1024, nil, "sh", "-c", `sleep 60 & echo $! > "$0"; wait`, pidFile)
			waitFile(t, pidFile)
			if tc.cancel {
				if response := h.call(sandboxops.Request{Op: sandbox.OpExecCancel, ExecID: &id}); response.Exec == nil {
					t.Fatalf("cancel: %v", *response.Code)
				}
			}
			if got := h.wait(id); got.State != tc.want || got.ExitCode != nil {
				t.Fatalf("observation = %+v, want %s without exit code", got, tc.want)
			}
			deadline := time.Now().Add(10 * time.Second)
			for groupAlive(t, pidFile) {
				if time.Now().After(deadline) {
					t.Fatal("background child survived the exec's end")
				}
				time.Sleep(20 * time.Millisecond)
			}
		})
	}
}

// The second cancel of the kill path kills the group even when guest code
// stopped the supervisor, which then can no longer act on SIGTERM.
func TestForcedCancelKillsGroupWithoutSupervisor(t *testing.T) {
	h := newHarness(t)
	id := execID(5)
	pidFile := filepath.Join(t.TempDir(), "child")
	h.start(id, 60_000, 1024, nil, "sh", "-c", `echo $$ > "$0"; exec sleep 60`, pidFile)
	waitFile(t, pidFile)
	status := h.server.execs.(*linuxExecs)
	_, current, err := status.observe(id)
	if err != nil || !signalable(current.Supervisor) {
		t.Fatalf("status = %+v, %v", current, err)
	}
	if err := syscall.Kill(current.Supervisor, syscall.SIGSTOP); err != nil {
		t.Fatal(err)
	}
	defer syscall.Kill(current.Supervisor, syscall.SIGKILL)
	h.call(sandboxops.Request{Op: sandbox.OpExecCancel, ExecID: &id, Force: true})
	deadline := time.Now().Add(10 * time.Second)
	for groupAlive(t, pidFile) {
		if time.Now().After(deadline) {
			t.Fatal("forced cancel left the command running")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestExecFailuresAreNonFaultCodes(t *testing.T) {
	h := newHarness(t)
	id := execID(6)
	response := h.start(id, 30_000, 1024, nil, "/no/such/command")
	if response.Code == nil || *response.Code != "path_not_found" || response.Exec == nil || response.Exec.State != sandbox.ExecStateFailed {
		t.Fatalf("missing command answered %+v", response)
	}
	unknown := execID(7)
	if response := h.call(sandboxops.Request{Op: sandboxops.OpExecStatus, ExecID: &unknown}); response.Code == nil || *response.Code != "exec_not_found" {
		t.Fatalf("unknown exec answered %+v", response)
	}

	// A capture root the helper cannot use (here a regular file) refuses
	// execs as unsupported, never as a miner fault.
	blocked := newHarness(t)
	if err := os.WriteFile(blocked.root, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if response := blocked.start(execID(8), 30_000, 1024, nil, "true"); response.Code == nil || *response.Code != sandbox.OpCodeOpsUnsupport {
		t.Fatalf("unusable capture root answered %+v", response)
	}
}

// File ops go through fsroot opened at "/": a read-only stat and a missing
// path exercise the real resolver from the helper's framing.
func TestFileOpsResolveThroughFsroot(t *testing.T) {
	h := newHarness(t)
	root := "/"
	if response := h.call(sandboxops.Request{Op: sandbox.OpFileStat, Path: &root}); response.File == nil || response.File.Type != sandbox.FileTypeDirectory {
		t.Fatalf("stat / answered %+v", response)
	}
	missing := "/no-such-sandbox-ops-path"
	response := h.call(sandboxops.Request{Op: sandbox.OpFileRead, Path: &missing, Offset: u64(0), Limit: u64(16)})
	if response.Code == nil || *response.Code != "path_not_found" {
		t.Fatalf("missing read answered %+v", response)
	}
}

func TestMalformedRequestIsSandboxOpFailed(t *testing.T) {
	h := newHarness(t)
	for _, input := range []string{"", "{}", `{"protocol":"sandbox-ops-helper.v1","op":"file_stat"}`, strings.Repeat("x", sandboxops.MaxRequestBytes+1)} {
		var out bytes.Buffer
		if code := h.server.serve(strings.NewReader(input), &out); code != 0 {
			t.Fatalf("serve exit %d", code)
		}
		if !strings.Contains(out.String(), `"code":"sandbox_op_failed"`) {
			t.Fatalf("input %.40q answered %s", input, out.String())
		}
	}
}
