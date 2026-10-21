// SPDX-License-Identifier: AGPL-3.0-only

package miner

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/protocol"
	"github.com/misscomputer/misscomputer-subnet/pkg/sandbox"
	"github.com/misscomputer/misscomputer-subnet/pkg/sandboxops"
)

// opsBackend is the lease test backend plus a helper reached through the
// real wire protocol: every request the lane sends is strictly decoded, and
// answer produces the helper's stdout for it.
type opsBackend struct {
	*sbBackend
	mu     sync.Mutex
	calls  []sandboxops.Request
	answer func(ctx context.Context, request sandboxops.Request) ([]byte, error)
}

func (b *opsBackend) RunHelper(ctx context.Context, instance string, encoded []byte) ([]byte, error) {
	request, err := sandboxops.DecodeRequest(encoded)
	if err != nil {
		return nil, fmt.Errorf("lane sent an invalid helper request: %w", err)
	}
	b.mu.Lock()
	b.calls = append(b.calls, request)
	answer := b.answer
	b.mu.Unlock()
	return answer(ctx, request)
}

func (b *opsBackend) count(op string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := 0
	for _, call := range b.calls {
		if call.Op == op {
			n++
		}
	}
	return n
}

func helperOut(t *testing.T, response sandboxops.Response) []byte {
	t.Helper()
	response.Protocol = sandboxops.Protocol
	encoded, err := sandboxops.Encode(response)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

// supervisedHelper answers for one exec the way the real helper's supervisor
// does (cmd/sandbox-ops-helper/exec_linux.go): the exec runs once started,
// and an exec_cancel, forced or not, SIGTERMs the supervisor, which reports
// the exec cancelled from then on, whoever asked for the cancel. The cancel
// itself answers the state it found. While statusGate is set, exec_status
// calls wait for it to close.
type supervisedHelper struct {
	mu         sync.Mutex
	state      string
	cancels    int
	cancelled  chan struct{}
	statusGate chan struct{}
}

func newSupervisedHelper() *supervisedHelper {
	return &supervisedHelper{state: sandbox.ExecStateRunning, cancelled: make(chan struct{})}
}

func (h *supervisedHelper) answer(t *testing.T) func(context.Context, sandboxops.Request) ([]byte, error) {
	return func(ctx context.Context, request sandboxops.Request) ([]byte, error) {
		h.mu.Lock()
		state, gate := h.state, h.statusGate
		if request.Op == sandbox.OpExecCancel {
			h.cancels++
			if h.state == sandbox.ExecStateRunning {
				h.state = sandbox.ExecStateCancelled
				close(h.cancelled)
			}
		}
		h.mu.Unlock()
		if request.Op == sandboxops.OpExecStatus && gate != nil {
			select {
			case <-gate:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			h.mu.Lock()
			state = h.state
			h.mu.Unlock()
		}
		response := sandboxops.Response{Exec: &sandboxops.ExecObservation{State: state}}
		if request.Op == sandbox.OpExecRead {
			response.Data = sandboxops.EncodeData(nil)
		}
		return helperOut(t, response), nil
	}
}

func (h *supervisedHelper) cancelCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.cancels
}

// opsClock is a settable clock shared by the lane and the ops store.
type opsClock struct{ now atomic.Int64 }

func (c *opsClock) Now() time.Time          { return time.Unix(0, c.now.Load()).UTC() }
func (c *opsClock) Set(value time.Time)     { c.now.Store(value.UnixNano()) }
func (c *opsClock) Add(delta time.Duration) { c.now.Add(int64(delta)) }

type opsFixture struct {
	*sbFixture
	backend *opsBackend
	clock   *opsClock
	lease   protocol.SandboxLeaseV1
	release protocol.SandboxReleaseV1
	nonce   atomic.Int64
}

var testOpsConfig = SandboxOpsConfig{
	StartResolution: 2 * time.Second, StateTimeout: 5 * time.Second, KillGrace: 100 * time.Millisecond,
	MaxInFlight: 64, MaxInFlightBytes: 64 << 20, MaxOutcomes: 64,
}

func newOpsFixture(t *testing.T, config SandboxOpsConfig) *opsFixture {
	t.Helper()
	f := &opsFixture{sbFixture: newSBFixture(t), clock: &opsClock{}}
	f.clock.Set(sbT0)
	f.backend = &opsBackend{sbBackend: f.sbFixture.backend}
	lane, err := NewSandboxLane(context.Background(), f.agent(), f.store, f.backend, SandboxLaneConfig{Budget: sbBudget, CgroupRoot: f.root,
		AgentCgroup: "/system.slice/miner-agent.service", DeploymentCgroup: "/system.slice/deployment-v4.slice"})
	if err != nil {
		t.Fatal(err)
	}
	lane.now = f.clock.Now
	f.lane = lane
	t.Cleanup(func() { _ = lane.Close(context.Background()) })
	r, l, receipt, err := f.commitHeld(1, nil)
	f.check(receipt, err, protocol.SandboxLeaseSchema, l, sandbox.StageReady, "")
	f.lease, f.release = l, f.sbFixture.release(r)
	store, err := f.store.EnableSandboxOps(context.Background(), f.clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	if err := lane.EnableOps(store, config); err != nil {
		t.Fatal(err)
	}
	return f
}

func u64(value uint64) *uint64  { return &value }
func text(value string) *string { return &value }

// op signs one op request on the fixture lease, issued now.
func (f *opsFixture) op(kind string, mutate func(*protocol.SandboxOpRequestV1)) protocol.SandboxOpRequestV1 {
	f.t.Helper()
	digest, err := protocol.SandboxDigestV1(f.lease)
	if err != nil {
		f.t.Fatal(err)
	}
	now := f.clock.Now()
	r := protocol.SandboxOpRequestV1{
		ExpiresAt: stamp(now.Add(time.Minute)), Generation: f.lease.Generation, IssuedAt: stamp(now), LeaseDigest: digest,
		LeaseID: protocol.SandboxLeaseIDV1(f.lease), MinerID: f.lease.MinerID, Op: kind, OpNonce: fmt.Sprintf("%032x", f.nonce.Add(1)),
		SandboxID: f.lease.SandboxID, Schema: protocol.SandboxOpRequestSchema, SchemaVersion: 1, Subnet: f.binding(), WorkloadKind: sandbox.WorkloadKind,
	}
	if mutate != nil {
		mutate(&r)
	}
	if err := protocol.SignSandboxOpRequestV1(&r, f.validator); err != nil {
		f.t.Fatal(err)
	}
	return r
}

func (f *opsFixture) withPayload(r *protocol.SandboxOpRequestV1, payload []byte) {
	digest := protocol.SandboxContentDigestV1(payload)
	r.PayloadDigest, r.PayloadBytes = &digest, uint64(len(payload))
}

var execPayload = []byte(`{"argv":["sh","-c","echo hi"],"cwd":"/","env":{},"stdin_b64":null}`)

func (f *opsFixture) execStart(timeoutMS uint64) protocol.SandboxOpRequestV1 {
	return f.op(sandbox.OpExecStart, func(r *protocol.SandboxOpRequestV1) {
		f.withPayload(r, execPayload)
		r.TimeoutMS, r.MaxOutputBytes = u64(timeoutMS), u64(1024)
	})
}

func (f *opsFixture) execOp(kind, execID string) protocol.SandboxOpRequestV1 {
	return f.op(kind, func(r *protocol.SandboxOpRequestV1) {
		r.ExecID = &execID
		if kind == sandbox.OpExecRead {
			r.Stream, r.Offset, r.Limit = text(sandbox.ExecStdout), u64(0), u64(4096)
		}
	})
}

// verify is the validator's acceptance of a receipt and its result.
func (f *opsFixture) verify(receipt protocol.SandboxOpReceiptV1, request protocol.SandboxOpRequestV1, result []byte, stage, code string) {
	f.t.Helper()
	if err := protocol.VerifySandboxOpReceiptV1(receipt, f.miner.Public().(ed25519.PublicKey)); err != nil {
		f.t.Fatalf("receipt signature: %v", err)
	}
	if err := protocol.SandboxOpReceiptAnswersV1(receipt, request, result); err != nil {
		f.t.Fatalf("receipt does not answer the request: %v", err)
	}
	got := ""
	if receipt.ErrorCode != nil {
		got = *receipt.ErrorCode
	}
	if receipt.Stage != stage || got != code {
		f.t.Fatalf("receipt %s/%q, want %s/%q", receipt.Stage, got, stage, code)
	}
}

func (f *opsFixture) run(r protocol.SandboxOpRequestV1, payload []byte) (protocol.SandboxOpReceiptV1, []byte, error) {
	return f.lane.Op(context.Background(), r, payload, f.request())
}

// A file write runs once: its exact replay inside the window is answered
// from the first answer, never by writing again. A read's result is bound by
// the receipt the validator checks.
func TestSandboxOpsFileOpsAnswerVerifiableReceiptsAndNeverRepeatAWrite(t *testing.T) {
	f := newOpsFixture(t, testOpsConfig)
	files := map[string][]byte{}
	f.backend.answer = func(_ context.Context, request sandboxops.Request) ([]byte, error) {
		switch request.Op {
		case sandbox.OpFileWrite:
			files[*request.Path] = request.Bytes()
			return helperOut(t, sandboxops.Response{File: &sandbox.FileInfo{Mode: *request.Mode, Size: uint64(len(request.Bytes())), Type: sandbox.FileTypeFile}}), nil
		case sandbox.OpFileRead:
			data := files[*request.Path][*request.Offset:]
			size := uint64(len(files[*request.Path]))
			return helperOut(t, sandboxops.Response{Data: sandboxops.EncodeData(data[:min(uint64(len(data)), *request.Limit)]), Size: &size}), nil
		}
		return nil, errors.New("unexpected op " + request.Op)
	}
	content := []byte("hello sandbox")
	mode := uint32(0o640)
	write := f.op(sandbox.OpFileWrite, func(r *protocol.SandboxOpRequestV1) {
		f.withPayload(r, content)
		r.Path, r.Offset, r.Mode = text("/work/a.txt"), u64(0), &mode
	})
	first, _, err := f.run(write, content)
	if err != nil {
		t.Fatal(err)
	}
	f.verify(first, write, nil, sandbox.OpStageCompleted, "")
	replay, _, err := f.run(write, content)
	if err != nil {
		t.Fatal(err)
	}
	if replay.Signature != first.Signature || f.backend.count(sandbox.OpFileWrite) != 1 {
		t.Fatalf("replay re-ran the write: %d helper writes", f.backend.count(sandbox.OpFileWrite))
	}
	read := f.op(sandbox.OpFileRead, func(r *protocol.SandboxOpRequestV1) {
		r.Path, r.Offset, r.Limit = text("/work/a.txt"), u64(6), u64(64)
	})
	receipt, result, err := f.run(read, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.verify(receipt, read, result, sandbox.OpStageCompleted, "")
	if string(result) != "sandbox" || !receipt.EOF {
		t.Fatalf("read %q eof=%v", result, receipt.EOF)
	}
}

// How a failed helper call is attributed (OPS-U3 classification): only an
// unanswered engine with a failed liveness check is a miner fault; a stopped
// sandbox, a broken helper or a helper claiming a miner fault is not.
func TestSandboxOpsAttributeHelperFailures(t *testing.T) {
	f := newOpsFixture(t, testOpsConfig)
	for _, tc := range []struct {
		name   string
		answer func() ([]byte, error)
		stage  string
		code   string
	}{
		{"engine unavailable", func() ([]byte, error) { return nil, &SandboxEngineUnavailable{Err: errors.New("no answer")} }, sandbox.OpStageFailed, sandbox.OpCodeRuntimeFailed},
		{"sandbox stopped", func() ([]byte, error) { return nil, ErrSandboxNotRunning }, sandbox.OpStageRefused, "sandbox_exited"},
		{"engine error", func() ([]byte, error) { return nil, errors.New("exec create: 500") }, sandbox.OpStageFailed, sandbox.OpCodeSandboxFailed},
		// A guest-caused stream violation is a plain error from the backend, not an engine fault.
		{"guest stream over its bound", func() ([]byte, error) { return nil, errors.New("helper stdout over its 1 MiB bound") }, sandbox.OpStageFailed, sandbox.OpCodeSandboxFailed},
		{"garbage", func() ([]byte, error) { return []byte("not json"), nil }, sandbox.OpStageFailed, sandbox.OpCodeSandboxFailed},
		{"claims miner fault", func() ([]byte, error) {
			return []byte(`{"code":"op_runtime_failed","data_b64":null,"eof":false,"exec":null,"file":null,"listing":null,"protocol":"sandbox-ops-helper.v1","size":null}`), nil
		}, sandbox.OpStageFailed, sandbox.OpCodeSandboxFailed},
		{"customer path", func() ([]byte, error) { return helperOut(t, sandboxops.Failure("path_not_found")), nil }, sandbox.OpStageRefused, "path_not_found"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f.backend.answer = func(context.Context, sandboxops.Request) ([]byte, error) { return tc.answer() }
			stat := f.op(sandbox.OpFileStat, func(r *protocol.SandboxOpRequestV1) { r.Path = text("/work") })
			receipt, _, err := f.run(stat, nil)
			if err != nil {
				t.Fatal(err)
			}
			f.verify(receipt, stat, nil, tc.stage, tc.code)
		})
	}
}

// exec_start answers running at once (R1, B_exec = 0) and starts the command
// exactly once however many replays race it; reads then return the bytes the
// helper retained and end with eof once the exec exited.
func TestSandboxExecStartsOnceAndReadsUntilExit(t *testing.T) {
	f := newOpsFixture(t, testOpsConfig)
	var exited atomic.Bool
	started := make(chan struct{}, 32)
	f.backend.answer = func(_ context.Context, request sandboxops.Request) ([]byte, error) {
		observation := sandboxops.ExecObservation{State: sandbox.ExecStateRunning}
		if exited.Load() {
			zero := 0
			observation = sandboxops.ExecObservation{State: sandbox.ExecStateExited, ExitCode: &zero, StdoutBytes: 3, StdoutRetained: 3}
		}
		switch request.Op {
		case sandbox.OpExecStart:
			started <- struct{}{}
		case sandbox.OpExecRead:
			data := []byte("hi\n")[min(*request.Offset, observation.StdoutRetained):observation.StdoutRetained]
			return helperOut(t, sandboxops.Response{Exec: &observation, Data: sandboxops.EncodeData(data)}), nil
		}
		return helperOut(t, sandboxops.Response{Exec: &observation}), nil
	}
	start := f.execStart(60_000)
	receipt, _, err := f.run(start, execPayload)
	if err != nil {
		t.Fatal(err)
	}
	f.verify(receipt, start, nil, sandbox.OpStageRunning, "")
	var replays sync.WaitGroup
	for range 20 {
		replays.Add(1)
		go func() {
			defer replays.Done()
			replay, _, err := f.run(start, execPayload)
			if err != nil || replay.Stage != sandbox.OpStageRunning {
				t.Errorf("replay: %v %+v", err, replay.Stage)
			}
		}()
	}
	replays.Wait()
	select {
	case <-started:
	case <-time.After(10 * time.Second):
		t.Fatal("the start owner never called the helper")
	}
	execID := protocol.SandboxOpIDV1(start)
	waitExecState(t, f, execID, sandbox.ExecStateRunning)
	if n := f.backend.count(sandbox.OpExecStart); n != 1 {
		t.Fatalf("%d backend starts, want 1", n)
	}
	exited.Store(true)
	read := f.execOp(sandbox.OpExecRead, execID)
	receipt, result, err := f.run(read, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.verify(receipt, read, result, sandbox.OpStageExited, "")
	if string(result) != "hi\n" || !receipt.EOF || *receipt.Exec.ExitCode != 0 {
		t.Fatalf("read %q eof=%v exec=%+v", result, receipt.EOF, receipt.Exec)
	}
}

func waitExecState(t *testing.T, f *opsFixture, execID, state string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		lookup, _, err := f.lane.ops.store.ExecState(context.Background(), execID)
		if err != nil {
			t.Fatal(err)
		}
		if lookup.State == state {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("exec %s is %s, want %s", execID, lookup.State, state)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// An exec_not_found receipt carries the lookup's own decision time, so once
// that time passes the start's window plus skew it proves non-start (D13).
func TestSandboxExecNotFoundIsDefinitiveAfterTheStartWindow(t *testing.T) {
	f := newOpsFixture(t, testOpsConfig)
	f.backend.answer = func(context.Context, sandboxops.Request) ([]byte, error) {
		return nil, errors.New("no helper call expected")
	}
	start := f.execStart(60_000) // signed, never sent
	f.clock.Add(time.Minute + sandbox.IssueSkew)
	read := f.execOp(sandbox.OpExecRead, protocol.SandboxOpIDV1(start))
	receipt, _, err := f.run(read, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.verify(receipt, read, nil, sandbox.OpStageRefused, "exec_not_found")
	never, err := protocol.SandboxExecNeverStartedV1(receipt, read, start, f.miner.Public().(ed25519.PublicKey))
	if err != nil || !never {
		t.Fatalf("never started = %v, %v", never, err)
	}
	if late, _, err := f.run(start, execPayload); err == nil || late.Signature != "" {
		t.Fatalf("start admitted after a definitive exec_not_found: %+v %v", late, err)
	}
}

// exec_cancel runs the B-7 kill path: a helper that never confirms gets the
// forced second cancel, and the exec still ends cancelled.
func TestSandboxExecCancelForcesTheKillWhenTheHelperNeverConfirms(t *testing.T) {
	f := newOpsFixture(t, testOpsConfig)
	f.backend.answer = func(_ context.Context, request sandboxops.Request) ([]byte, error) {
		return helperOut(t, sandboxops.Response{Exec: &sandboxops.ExecObservation{State: sandbox.ExecStateRunning}}), nil
	}
	start := f.execStart(60_000)
	if _, _, err := f.run(start, execPayload); err != nil {
		t.Fatal(err)
	}
	execID := protocol.SandboxOpIDV1(start)
	waitExecState(t, f, execID, sandbox.ExecStateRunning)
	cancel := f.execOp(sandbox.OpExecCancel, execID)
	began := time.Now()
	receipt, _, err := f.run(cancel, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.verify(receipt, cancel, nil, sandbox.OpStageCancelled, "")
	if waited := time.Since(began); waited < sandbox.ExecKillGrace {
		t.Fatalf("recorded cancelled after %v, before the kill grace", waited)
	}
	f.backend.mu.Lock()
	var forced bool
	for _, call := range f.backend.calls {
		forced = forced || call.Op == sandbox.OpExecCancel && call.Force
	}
	f.backend.mu.Unlock()
	if !forced {
		t.Fatal("no forced second cancel was sent")
	}
	// The slot is free again: cancel is idempotent and answers cancelled.
	again := f.execOp(sandbox.OpExecCancel, execID)
	if receipt, _, err := f.run(again, nil); err != nil || receipt.Stage != sandbox.OpStageCancelled {
		t.Fatalf("second cancel: %+v %v", receipt.Stage, err)
	}
}

// The exec deadline is min(admitted_at + timeout_ms, lease expiry) on the
// durable clock; the kill path then ends the exec timed_out, although the
// helper reports every exec it was asked to cancel as cancelled.
func TestSandboxExecDeadlineEndsTimedOut(t *testing.T) {
	f := newOpsFixture(t, testOpsConfig)
	helper := newSupervisedHelper()
	f.backend.answer = helper.answer(t)
	start := f.execStart(1000)
	if _, _, err := f.run(start, execPayload); err != nil {
		t.Fatal(err)
	}
	execID := protocol.SandboxOpIDV1(start)
	waitExecState(t, f, execID, sandbox.ExecStateRunning)
	f.clock.Add(time.Second)
	waitExecState(t, f, execID, sandbox.ExecStateTimedOut)
	read := f.execOp(sandbox.OpExecRead, execID)
	receipt, result, err := f.run(read, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.verify(receipt, read, result, sandbox.OpStageTimedOut, "")
	if receipt.Exec.EndedAt == nil {
		t.Fatal("timed out exec has no ended_at")
	}
}

// Once the lease is released, ops are answered from the lease state with no
// helper call, and an op naming no lease of this miner gets no receipt.
func TestSandboxOpsAfterReleaseAnswerLeaseState(t *testing.T) {
	f := newOpsFixture(t, testOpsConfig)
	f.backend.answer = func(context.Context, sandboxops.Request) ([]byte, error) {
		return nil, errors.New("no helper call expected")
	}
	receipt, err := f.lane.Release(context.Background(), f.release, f.request())
	f.check(receipt, err, protocol.SandboxReleaseSchema, f.release, sandbox.StageReleased, "")
	stat := f.op(sandbox.OpFileStat, func(r *protocol.SandboxOpRequestV1) { r.Path = text("/") })
	opReceipt, _, err := f.run(stat, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.verify(opReceipt, stat, nil, sandbox.OpStageRefused, "released")
	foreign := f.op(sandbox.OpFileStat, func(r *protocol.SandboxOpRequestV1) {
		r.Path = text("/")
		r.LeaseDigest = "sha256:" + fmt.Sprintf("%064x", 7)
	})
	if receipt, _, err := f.run(foreign, nil); err == nil || receipt.Signature != "" {
		t.Fatalf("foreign op answered %+v", receipt)
	}
}

// Pre-admission overload cannot prove that an exec never started: the request
// may be an exact resend after its original receipt was lost. Both resource
// bounds must answer unsigned busy, leaving the durable replay outcome intact.
func TestSandboxOpsInFlightBound(t *testing.T) {
	for _, bound := range []string{"slots", "bytes"} {
		t.Run(bound, func(t *testing.T) {
			config := testOpsConfig
			if bound == "slots" {
				config.MaxInFlight = 1
			} else {
				config.MaxInFlightBytes = sandbox.MaxChunkBytes
			}
			f := newOpsFixture(t, config)
			entered, unblock := make(chan struct{}), make(chan struct{})
			var release sync.Once
			defer release.Do(func() { close(unblock) })
			f.backend.answer = func(ctx context.Context, request sandboxops.Request) ([]byte, error) {
				if request.Op == sandbox.OpExecStart || request.Op == sandboxops.OpExecStatus {
					return helperOut(t, sandboxops.Response{Exec: &sandboxops.ExecObservation{State: sandbox.ExecStateRunning}}), nil
				}
				close(entered)
				select {
				case <-unblock:
				case <-ctx.Done():
					return nil, ctx.Err()
				}
				return helperOut(t, sandboxops.Response{Data: sandboxops.EncodeData(nil), Size: u64(0)}), nil
			}
			start := f.execStart(60_000)
			first, _, err := f.run(start, execPayload)
			if err != nil {
				t.Fatal(err)
			}
			f.verify(first, start, nil, sandbox.OpStageRunning, "")
			execID := protocol.SandboxOpIDV1(start)
			waitExecState(t, f, execID, sandbox.ExecStateRunning)
			read := f.op(sandbox.OpFileRead, func(r *protocol.SandboxOpRequestV1) {
				r.Path, r.Offset, r.Limit = text("/work/a.txt"), u64(0), u64(sandbox.MaxChunkBytes)
			})
			done := make(chan error, 1)
			go func() {
				_, _, err := f.run(read, nil)
				done <- err
			}()
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("blocking read did not reach the helper")
			}
			stat := f.op(sandbox.OpFileStat, func(r *protocol.SandboxOpRequestV1) { r.Path = text("/") })
			for _, attempt := range []struct {
				name    string
				request protocol.SandboxOpRequestV1
				payload []byte
			}{
				{"admitted replay", start, execPayload},
				{"fresh start", f.execStart(60_000), execPayload},
				{"file op", stat, nil},
			} {
				receipt, result, err := f.run(attempt.request, attempt.payload)
				if !errors.Is(err, ErrSandboxOpsBusy) || receipt.Signature != "" || result != nil {
					t.Errorf("%s under %s saturation: want unsigned busy; stage=%s signature=%q err=%v", attempt.name, bound, receipt.Stage, receipt.Signature, err)
				}
			}
			release.Do(func() { close(unblock) })
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			// Capacity becoming available must not cause the same signed request
			// to repeat its effect or lose its original exec identity.
			replay, _, err := f.run(start, execPayload)
			if err != nil {
				t.Fatal(err)
			}
			f.verify(replay, start, nil, sandbox.OpStageRunning, "")
			if replay.Exec == nil || replay.OpID != execID || f.backend.count(sandbox.OpExecStart) != 1 {
				t.Fatalf("replay lost exec identity or repeated the start: %+v, calls=%d", replay.Exec, f.backend.count(sandbox.OpExecStart))
			}
		})
	}
}

// After Close no op is admitted or signed (SD-2): the answer is
// sandbox_lane_closed without a receipt.
func TestSandboxOpsAfterCloseAreRefusedWithoutReceipt(t *testing.T) {
	f := newOpsFixture(t, testOpsConfig)
	f.backend.answer = func(context.Context, sandboxops.Request) ([]byte, error) {
		return nil, errors.New("no helper call expected")
	}
	if err := f.lane.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	stat := f.op(sandbox.OpFileStat, func(r *protocol.SandboxOpRequestV1) { r.Path = text("/") })
	if receipt, _, err := f.run(stat, nil); !errors.Is(err, ErrSandboxLaneClosed) || receipt.Signature != "" {
		t.Fatalf("op after Close: %+v %v", receipt, err)
	}
}

// Without an ops-capable backend the lane cannot enable ops: the default is
// unsupported, never a silently degraded mode.
func TestSandboxOpsNeedAnOpsCapableBackend(t *testing.T) {
	f := newSBFixture(t)
	store, err := f.store.EnableSandboxOps(context.Background(), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.lane.EnableOps(store, testOpsConfig); err == nil {
		t.Fatal("ops enabled on a backend without the helper")
	}
	if _, _, err := f.lane.Op(context.Background(), protocol.SandboxOpRequestV1{}, nil, f.request()); !errors.Is(err, ErrSandboxOpsDisabled) {
		t.Fatalf("op on a lane without ops: %v", err)
	}
	unset := testOpsConfig
	unset.StartResolution = 0
	ops := newOpsFixture(t, testOpsConfig)
	if err := ops.lane.EnableOps(store, unset); err == nil {
		t.Fatal("ops enabled without an adopted start resolution")
	}
}
