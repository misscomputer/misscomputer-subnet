// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/misscomputer/misscomputer-subnet/cmd/sandbox-ops-helper/internal/fsroot"
	"github.com/misscomputer/misscomputer-subnet/pkg/sandbox"
	"github.com/misscomputer/misscomputer-subnet/pkg/sandboxops"
)

// selfExecutable is how the helper starts its own supervisor: the mounted,
// read-only helper binary this process runs from.
const selfExecutable = "/proc/self/exe"

const (
	// startWait bounds how long exec_start waits for the supervisor to
	// report the command started; past it the exec answers as it is
	// observed (running under R1: admitted and not known to have ended).
	startWait = 10 * time.Second
	// drainWindow bounds how long the supervisor keeps reading a stream
	// after the command exited, for output still in the pipes. A process
	// the command left running that still holds a pipe loses its later
	// output, as the retained prefix must stop growing once the exec is
	// terminal.
	drainWindow = time.Second
	// statusInterval bounds how stale a running exec's counts may be.
	statusInterval = 200 * time.Millisecond
	// maxStatusBytes bounds the status file the helper reads back; guest
	// code can write it.
	maxStatusBytes = 4 << 10
	// defaultPath resolves an argv[0] without a slash. The exec runs with an
	// empty environment (OPS-D1), so the image's PATH is not used.
	defaultPath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	stdoutFile  = "stdout"
	stderrFile  = "stderr"
	statusFile  = "status.json"
)

// execStatus is the supervisor's status file. Guest code can rewrite it, so
// the helper reads it bounded and the miner treats what it says as observed,
// never as proof (B-5).
type execStatus struct {
	Code           *string `json:"code"`
	ExitCode       *int    `json:"exit_code"`
	Group          int     `json:"pgid"`
	MaxOutputBytes uint64  `json:"max_output_bytes"`
	State          string  `json:"state"`
	StderrBytes    uint64  `json:"stderr_bytes"`
	StdoutBytes    uint64  `json:"stdout_bytes"`
	Supervisor     int     `json:"supervisor_pid"`
}

type linuxExecs struct {
	root string
	self string
}

func newExecRunner(root, self string) execRunner { return &linuxExecs{root: root, self: self} }

// prepareRoot creates the capture root (image user, 0700) if absent. It never
// creates /tmp itself; a sandbox without a usable /tmp cannot run execs and
// answers ops_unsupported (D14).
func prepareRoot(root string) error {
	info, err := os.Lstat(root)
	switch {
	case err == nil && info.IsDir():
		return nil
	case err == nil:
		return fsroot.ErrUnsupported
	case !errors.Is(err, os.ErrNotExist):
		return fsroot.ErrUnsupported
	}
	if err := os.Mkdir(root, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return fsroot.ErrUnsupported
	}
	if info, err = os.Lstat(root); err != nil || !info.IsDir() {
		return fsroot.ErrUnsupported
	}
	return nil
}

func (e *linuxExecs) dir(execID string) string { return filepath.Join(e.root, execID) }

// start starts the exec once. A second start of the same exec ID (a replay
// or a retried backend call) never runs the command again: it answers the
// exec as observed.
func (e *linuxExecs) start(execID string, spec sandboxops.ExecSpec) sandboxops.Response {
	if err := prepareRoot(e.root); err != nil {
		return sandboxops.Failure(sandbox.OpCodeOpsUnsupport)
	}
	dir := e.dir(execID)
	if err := os.Mkdir(dir, 0o700); err != nil {
		if errors.Is(err, os.ErrExist) {
			return e.status(execID)
		}
		return sandboxops.Failure(fsroot.Code(err))
	}
	encoded, err := json.Marshal(spec)
	if err != nil {
		return sandboxops.Failure(sandbox.OpCodeSandboxFailed)
	}
	specRead, specWrite, err := os.Pipe()
	if err != nil {
		return sandboxops.Failure(fsroot.Code(err))
	}
	readyRead, readyWrite, err := os.Pipe()
	if err != nil {
		specRead.Close()
		specWrite.Close()
		return sandboxops.Failure(fsroot.Code(err))
	}
	supervisor := exec.Command(e.self, superviseArg, e.root, execID)
	supervisor.Env, supervisor.Dir = []string{}, "/"
	supervisor.ExtraFiles = []*os.File{specRead, readyWrite}
	supervisor.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	err = supervisor.Start()
	specRead.Close()
	readyWrite.Close()
	if err != nil {
		specWrite.Close()
		readyRead.Close()
		writeStatus(dir, execStatus{State: sandbox.ExecStateFailed, Code: code(sandbox.OpCodeSandboxFailed)})
		return e.status(execID)
	}
	_, _ = specWrite.Write(encoded)
	specWrite.Close()
	// The supervisor reports one line once the command started or failed to.
	ready := make(chan struct{})
	go func() {
		_, _ = bufio.NewReader(io.LimitReader(readyRead, 64)).ReadString('\n')
		close(ready)
	}()
	select {
	case <-ready:
	case <-time.After(startWait):
	}
	readyRead.Close()
	_ = supervisor.Process.Release()
	return e.status(execID)
}

// observe reads an exec's status file and capture sizes. A missing status
// file means the supervisor has not written one yet: running.
func (e *linuxExecs) observe(execID string) (sandboxops.ExecObservation, execStatus, error) {
	dir := e.dir(execID)
	if info, err := os.Lstat(dir); err != nil || !info.IsDir() {
		return sandboxops.ExecObservation{}, execStatus{}, errExecNotFound
	}
	status := execStatus{State: sandbox.ExecStateRunning}
	if raw, err := readSmall(filepath.Join(dir, statusFile)); err == nil {
		if json.Unmarshal(raw, &status) != nil {
			return sandboxops.ExecObservation{}, execStatus{}, errExecStatus
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return sandboxops.ExecObservation{}, execStatus{}, errExecStatus
	}
	observation := sandboxops.ExecObservation{State: status.State, ExitCode: status.ExitCode,
		StdoutBytes: status.StdoutBytes, StderrBytes: status.StderrBytes}
	observation.StdoutRetained = retained(filepath.Join(dir, stdoutFile))
	observation.StderrRetained = retained(filepath.Join(dir, stderrFile))
	observation.StdoutBytes = max(observation.StdoutBytes, observation.StdoutRetained)
	observation.StderrBytes = max(observation.StderrBytes, observation.StderrRetained)
	if observation.Validate() != nil {
		return sandboxops.ExecObservation{}, execStatus{}, errExecStatus
	}
	return observation, status, nil
}

var (
	errExecNotFound = errors.New("exec capture directory is absent")
	errExecStatus   = errors.New("exec status is unreadable or inconsistent")
)

func execFailure(err error) sandboxops.Response {
	if errors.Is(err, errExecNotFound) {
		return sandboxops.Failure("exec_not_found")
	}
	return sandboxops.Failure(sandbox.OpCodeSandboxFailed)
}

func (e *linuxExecs) status(execID string) sandboxops.Response {
	observation, status, err := e.observe(execID)
	if err != nil {
		return execFailure(err)
	}
	response := sandboxops.Response{Protocol: sandboxops.Protocol, Exec: &observation}
	if status.State == sandbox.ExecStateFailed {
		failure := sandbox.OpCodeSandboxFailed
		if status.Code != nil && sandboxops.HelperCode(*status.Code) {
			failure = *status.Code
		}
		response.Code = &failure
	}
	return response
}

// read pages one retained stream.
func (e *linuxExecs) read(execID, stream string, offset, limit uint64) sandboxops.Response {
	observation, _, err := e.observe(execID)
	if err != nil {
		return execFailure(err)
	}
	end := observation.StdoutRetained
	if stream == sandbox.ExecStderr {
		end = observation.StderrRetained
	}
	data := []byte{}
	if offset < end {
		file, err := os.OpenFile(filepath.Join(e.dir(execID), stream), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			return sandboxops.Failure(sandbox.OpCodeSandboxFailed)
		}
		defer file.Close()
		data = make([]byte, min(limit, end-offset))
		n, err := file.ReadAt(data, int64(offset))
		if err != nil && !errors.Is(err, io.EOF) {
			return sandboxops.Failure(sandbox.OpCodeSandboxFailed)
		}
		data = data[:n]
	}
	return sandboxops.Response{Protocol: sandboxops.Protocol, Exec: &observation, Data: sandboxops.EncodeData(data)}
}

// cancel asks the supervisor to end the exec: SIGTERM to its process group
// now and SIGKILL after ExecKillGrace. force is the kill path's second
// cancel (B-7): it also kills the group at once, for a supervisor that guest
// code stopped or killed.
func (e *linuxExecs) cancel(execID string, force bool) sandboxops.Response {
	observation, status, err := e.observe(execID)
	if err != nil {
		return execFailure(err)
	}
	if observation.State == sandbox.ExecStateRunning {
		// kill(-1) or kill(0) would signal far more than this exec, so only
		// a real process or group other than this one is signalled.
		if signalable(status.Supervisor) {
			_ = unix.Kill(status.Supervisor, unix.SIGTERM)
		}
		if force && signalable(status.Group) {
			_ = unix.Kill(-status.Group, unix.SIGKILL)
		}
	}
	return e.status(execID)
}

func signalable(pid int) bool { return pid > 1 && pid != os.Getpid() }

func readSmall(path string) ([]byte, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return sandboxops.ReadBounded(file, maxStatusBytes)
}

// retained is the size of a capture file, capped by the protocol bound.
func retained(path string) uint64 {
	var st unix.Stat_t
	if unix.Lstat(path, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Size < 0 {
		return 0
	}
	return min(uint64(st.Size), sandbox.MaxExecOutputBytes)
}

func code(value string) *string { return &value }

// writeStatus replaces the status file atomically.
func writeStatus(dir string, status execStatus) {
	encoded, err := json.Marshal(status)
	if err != nil {
		return
	}
	temporary := filepath.Join(dir, statusFile+".tmp")
	if err := os.WriteFile(temporary, encoded, 0o600); err != nil {
		return
	}
	_ = os.Rename(temporary, filepath.Join(dir, statusFile))
}

// capture copies one stream into its capture file: the first limit bytes
// are kept, the rest counted and dropped (OPS-D2 first-N retention).
type capture struct {
	limit uint64
	file  *os.File
	total atomic.Uint64
}

func (c *capture) run(source io.Reader) {
	buffer := make([]byte, 32<<10)
	kept := uint64(0)
	for {
		n, err := source.Read(buffer)
		if n > 0 {
			c.total.Add(uint64(n))
			if kept < c.limit {
				keep := min(uint64(n), c.limit-kept)
				if _, writeErr := c.file.Write(buffer[:keep]); writeErr == nil {
					kept += keep
				} else {
					// A full disk stops retention; counting continues.
					kept = c.limit
				}
			}
		}
		if err != nil {
			return
		}
	}
}

// supervise runs one exec: it reads its spec from fd 3, reports on fd 4 once
// the command started (or could not), and stays until the exec ends. Its
// exit code is not observed by anyone.
func supervise(root, execID string) int {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || !sandboxops.ValidExecID(execID) {
		return 2
	}
	specFile, ready := os.NewFile(3, "spec"), os.NewFile(4, "ready")
	if specFile == nil || ready == nil {
		return 2
	}
	raw, err := sandboxops.ReadBounded(specFile, sandboxops.MaxRequestBytes)
	specFile.Close()
	var spec sandboxops.ExecSpec
	if err != nil || json.Unmarshal(raw, &spec) != nil || spec.Command.Validate() != nil {
		return 2
	}
	dir := filepath.Join(root, execID)
	status := execStatus{State: sandbox.ExecStateRunning, Supervisor: os.Getpid(), MaxOutputBytes: spec.MaxOutputBytes}
	fail := func(reason string) int {
		status.State, status.Code = sandbox.ExecStateFailed, &reason
		writeStatus(dir, status)
		_, _ = ready.WriteString("failed\n")
		ready.Close()
		return 0
	}
	outputs := [2]*capture{{limit: spec.MaxOutputBytes}, {limit: spec.MaxOutputBytes}}
	for index, name := range []string{stdoutFile, stderrFile} {
		file, err := os.OpenFile(filepath.Join(dir, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
		if err != nil {
			return fail(fsroot.Code(err))
		}
		defer file.Close()
		outputs[index].file = file
	}
	path, err := resolveCommand(spec.Command.Argv[0])
	if err != nil {
		return fail(startCode(err))
	}
	signals := make(chan os.Signal, 4)
	signal.Notify(signals, unix.SIGTERM)
	signal.Ignore(unix.SIGHUP, unix.SIGINT, unix.SIGPIPE)
	stdoutRead, stdoutWrite, err := os.Pipe()
	if err != nil {
		return fail(fsroot.Code(err))
	}
	stderrRead, stderrWrite, err := os.Pipe()
	if err != nil {
		return fail(fsroot.Code(err))
	}
	child := &exec.Cmd{Path: path, Args: spec.Command.Argv, Dir: spec.Command.Cwd, Env: []string{},
		Stdout: stdoutWrite, Stderr: stderrWrite, SysProcAttr: &syscall.SysProcAttr{Setpgid: true}}
	var stdin io.WriteCloser
	if spec.Command.Stdin != nil {
		if stdin, err = child.StdinPipe(); err != nil {
			return fail(fsroot.Code(err))
		}
	}
	if err := child.Start(); err != nil {
		return fail(startCode(err))
	}
	stdoutWrite.Close()
	stderrWrite.Close()
	status.Group = child.Process.Pid
	writeStatus(dir, status)
	_, _ = ready.WriteString("started\n")
	ready.Close()
	if stdin != nil {
		go func() {
			_, _ = stdin.Write(spec.Command.StdinBytes())
			stdin.Close()
		}()
	}
	var drained sync.WaitGroup
	for index, source := range []*os.File{stdoutRead, stderrRead} {
		drained.Add(1)
		go func() {
			defer drained.Done()
			outputs[index].run(source)
		}()
	}
	exited := make(chan int, 1)
	go func() {
		_ = child.Wait()
		exited <- exitCode(child.ProcessState)
	}()
	deadline := time.NewTimer(time.Duration(spec.TimeoutMS) * time.Millisecond)
	defer deadline.Stop()
	ticker := time.NewTicker(statusInterval)
	defer ticker.Stop()
	var ended string
	var kill <-chan time.Time
	stop := func(state string) {
		if ended != "" {
			return
		}
		ended = state
		_ = unix.Kill(-status.Group, unix.SIGTERM)
		kill = time.After(sandbox.ExecKillGrace)
	}
	counts := func() {
		status.StdoutBytes, status.StderrBytes = outputs[0].total.Load(), outputs[1].total.Load()
	}
	for {
		select {
		case <-signals:
			stop(sandbox.ExecStateCancelled)
		case <-deadline.C:
			stop(sandbox.ExecStateTimedOut)
		case <-kill:
			_ = unix.Kill(-status.Group, unix.SIGKILL)
		case <-ticker.C:
			counts()
			writeStatus(dir, status)
		case value := <-exited:
			finished := make(chan struct{})
			go func() {
				drained.Wait()
				close(finished)
			}()
			select {
			case <-finished:
			case <-time.After(drainWindow):
			}
			stdoutRead.Close()
			stderrRead.Close()
			<-finished
			counts()
			if ended == "" {
				status.State, status.ExitCode = sandbox.ExecStateExited, &value
			} else {
				status.State = ended
				// The group may still hold processes the command started.
				_ = unix.Kill(-status.Group, unix.SIGKILL)
			}
			writeStatus(dir, status)
			return 0
		}
	}
}

// resolveCommand finds argv[0] like execvp with the default PATH.
func resolveCommand(name string) (string, error) {
	if strings.Contains(name, "/") {
		return name, nil
	}
	for _, directory := range strings.Split(defaultPath, ":") {
		candidate := directory + "/" + name
		if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() && info.Mode()&0o111 != 0 {
			return candidate, nil
		}
	}
	return "", os.ErrNotExist
}

// startCode is the non-fault code of a command that could not start: the
// customer's argv or cwd, inside the customer's sandbox.
func startCode(err error) string {
	switch {
	case errors.Is(err, os.ErrNotExist):
		return "path_not_found"
	case errors.Is(err, os.ErrPermission):
		return "permission_denied"
	case errors.Is(err, syscall.ENOTDIR):
		return "path_not_directory"
	}
	return fsroot.Code(err)
}

// exitCode is the command's exit status, or 128 plus the signal for a
// command a signal ended, as a shell reports it.
func exitCode(state *os.ProcessState) int {
	if state == nil {
		return 255
	}
	if status, ok := state.Sys().(syscall.WaitStatus); ok && status.Signaled() {
		return min(128+int(status.Signal()), 255)
	}
	return min(max(state.ExitCode(), 0), 255)
}
