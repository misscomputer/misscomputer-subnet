// SPDX-License-Identifier: AGPL-3.0-only

package miner

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/protocol"
	"github.com/misscomputer/misscomputer-subnet/pkg/sandbox"
	"github.com/misscomputer/misscomputer-subnet/pkg/sandboxops"
)

// slowStore makes the ops store's clock readings (one per durable step)
// outlive D_state, as under store contention: after skip normal readings,
// the next slow readings are slow.
type slowStore struct{ skip, slow atomic.Int64 }

func (s *slowStore) set(skip, slow int64) { s.skip.Store(skip); s.slow.Store(slow) }

// slowStoreFixture is the ops fixture with a slowStore-controlled store.
func slowStoreFixture(t *testing.T, config SandboxOpsConfig) (*opsFixture, *slowStore) {
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
	slow := &slowStore{}
	store, err := f.store.EnableSandboxOps(context.Background(), func() time.Time {
		switch {
		case slow.skip.Add(-1) >= 0:
		case slow.slow.Add(-1) >= 0:
			time.Sleep(3 * config.StateTimeout)
		}
		return f.clock.Now()
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := lane.EnableOps(store, config); err != nil {
		t.Fatal(err)
	}
	return f, slow
}

func waitFor(t *testing.T, what string, done func() bool) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); !done(); time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("still waiting: %s", what)
		}
	}
}

// The exec deadline is min(admitted_at + timeout_ms, current lease expiry).
// When the lease expiry is reached unrenewed, the lane's deadline still
// SIGTERMs the exec through the kill path and records it timed_out: the
// lease is past its expiry but its teardown has not begun. A renewal moves
// the deadline, and a released lease is left to its teardown.
func TestSandboxExecLeaseExpiryEndsTheExec(t *testing.T) {
	for _, tc := range []struct {
		name    string
		renew   bool
		release bool
		killed  bool
	}{
		{"unrenewed lease expiry", false, false, true},
		{"renewed lease", true, false, false},
		{"released lease", false, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newOpsFixture(t, testOpsConfig)
			var cancels atomic.Int64
			f.backend.answer = func(_ context.Context, request sandboxops.Request) ([]byte, error) {
				state := sandbox.ExecStateRunning
				if request.Op == sandbox.OpExecCancel {
					cancels.Add(1)
				}
				if cancels.Load() > 0 {
					state = sandbox.ExecStateTimedOut
				}
				return helperOut(t, sandboxops.Response{Exec: &sandboxops.ExecObservation{State: state}}), nil
			}
			start := f.execStart(uint64(time.Hour / time.Millisecond))
			if _, _, err := f.run(start, execPayload); err != nil {
				t.Fatal(err)
			}
			execID := protocol.SandboxOpIDV1(start)
			waitExecState(t, f, execID, sandbox.ExecStateRunning)
			switch {
			case tc.renew:
				renewal := f.renewal(f.lease, 1)
				receipt, err := f.lane.Renew(context.Background(), renewal, f.request())
				f.check(receipt, err, protocol.SandboxRenewalSchema, renewal, sandbox.StageReady, "")
			case tc.release:
				receipt, err := f.lane.Release(context.Background(), f.release, f.request())
				f.check(receipt, err, protocol.SandboxReleaseSchema, f.release, sandbox.StageReleased, "")
			}
			// Past the fixture lease's own expiry (+10 min); the real-time
			// timer the start owner armed fires now.
			f.clock.Add(10*time.Minute + time.Second)
			exec := f.lane.ops.execEntry(execID)
			if exec == nil {
				if tc.release {
					return // teardown dropped the exec with its sandbox
				}
				t.Fatal("no exec entry")
			}
			f.lane.armDeadline(f.lane.ops, execID, exec, 0)
			if tc.killed {
				waitExecState(t, f, execID, sandbox.ExecStateTimedOut)
				if cancels.Load() == 0 {
					t.Fatal("recorded timed_out without signalling the exec")
				}
				return
			}
			time.Sleep(300 * time.Millisecond)
			if cancels.Load() != 0 {
				t.Fatalf("%d helper cancels at a deadline that did not pass", cancels.Load())
			}
		})
	}
}

// A durable read that fails at the deadline does not disarm the exec's
// termination: the deadline is tried again, and once the store answers the
// exec ends timed_out.
func TestSandboxExecDeadlineSurvivesADurableFailure(t *testing.T) {
	config := testOpsConfig
	config.StateTimeout = 200 * time.Millisecond
	f, slow := slowStoreFixture(t, config)
	f.backend.answer = func(_ context.Context, request sandboxops.Request) ([]byte, error) {
		state := sandbox.ExecStateRunning
		if request.Op == sandbox.OpExecCancel || request.Op == sandboxops.OpExecStatus {
			state = sandbox.ExecStateTimedOut
		}
		return helperOut(t, sandboxops.Response{Exec: &sandboxops.ExecObservation{State: state}}), nil
	}
	start := f.execStart(1000)
	if _, _, err := f.run(start, execPayload); err != nil {
		t.Fatal(err)
	}
	execID := protocol.SandboxOpIDV1(start)
	waitExecState(t, f, execID, sandbox.ExecStateRunning)
	// Every try of the deadline's first durable read outlives D_state.
	slow.set(0, 3)
	f.clock.Add(time.Second)
	waitExecState(t, f, execID, sandbox.ExecStateTimedOut)
}

// A start owner that could not read its exec's state never started it; once
// the store answers again the exec ends failed, instead of answering
// running with nothing left to end it until its own deadline.
func TestSandboxExecStartOwnerEndsFailedAfterTheStoreRecovers(t *testing.T) {
	config := testOpsConfig
	config.StateTimeout = 200 * time.Millisecond
	f, slow := slowStoreFixture(t, config)
	f.backend.answer = func(context.Context, sandboxops.Request) ([]byte, error) {
		return nil, errors.New("no helper call expected: the start owner never read its state")
	}
	start := f.op(sandbox.OpExecStart, func(r *protocol.SandboxOpRequestV1) {
		f.withPayload(r, execPayload)
		r.TimeoutMS, r.MaxOutputBytes = u64(60_000), u64(1024)
	})
	// The admission answers; every try of the start owner's read then
	// outlives D_state.
	slow.set(1, 3)
	if _, _, err := f.run(start, execPayload); err != nil {
		t.Fatal(err)
	}
	execID := protocol.SandboxOpIDV1(start)
	waitExecState(t, f, execID, sandbox.ExecStateFailed)
	if f.backend.count(sandbox.OpExecStart) != 0 {
		t.Fatal("the exec was started")
	}
}

// An exec_start whose admission failed without a durable row keeps no
// in-memory entry beyond its request window: once the window closed it can
// never be admitted, and the entry is dropped. An admitted exec is kept.
func TestSandboxExecFailedAdmissionsAreForgotten(t *testing.T) {
	config := testOpsConfig
	config.StateTimeout = 100 * time.Millisecond
	f, slow := slowStoreFixture(t, config)
	f.backend.answer = func(context.Context, sandboxops.Request) ([]byte, error) {
		return helperOut(t, sandboxops.Response{Exec: &sandboxops.ExecObservation{State: sandbox.ExecStateRunning}}), nil
	}
	shortWindow := func() protocol.SandboxOpRequestV1 {
		return f.op(sandbox.OpExecStart, func(r *protocol.SandboxOpRequestV1) {
			f.withPayload(r, execPayload)
			r.TimeoutMS, r.MaxOutputBytes = u64(60_000), u64(1024)
			now := f.clock.Now()
			r.IssuedAt, r.ExpiresAt = stamp(now.Add(-59*time.Second)), stamp(now.Add(time.Second))
		})
	}
	entries := func() int {
		f.lane.ops.mu.Lock()
		defer f.lane.ops.mu.Unlock()
		return len(f.lane.ops.execs)
	}
	const n = 20
	for i := 0; i < n; i++ {
		slow.set(0, 1)
		if _, _, err := f.run(shortWindow(), execPayload); !errors.Is(err, ErrSandboxOpsBusy) {
			t.Fatalf("start %d: %v, want busy", i, err)
		}
	}
	slow.set(0, 0)
	if got := entries(); got != n {
		t.Fatalf("%d entries right after the failed admissions, want %d (kept while an admission may still come)", got, n)
	}
	f.clock.Add(2 * time.Second)
	waitFor(t, "failed admissions forgotten after their window", func() bool { return entries() == 0 })
	admitted := f.execStart(60_000)
	if _, _, err := f.run(admitted, execPayload); err != nil {
		t.Fatal(err)
	}
	waitExecState(t, f, protocol.SandboxOpIDV1(admitted), sandbox.ExecStateRunning)
	if got := entries(); got != 1 {
		t.Fatalf("%d entries with one admitted exec", got)
	}
}
