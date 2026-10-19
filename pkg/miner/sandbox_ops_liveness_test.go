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
// SIGTERMs the exec through the kill path and records it timed_out, although
// the helper reports the exec it was asked to cancel as cancelled: the lease
// is past its expiry but its teardown has not begun. A renewal moves the
// deadline, and a released lease is left to its teardown.
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
			helper := newSupervisedHelper()
			f.backend.answer = helper.answer(t)
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
				if helper.cancelCount() == 0 {
					t.Fatal("recorded timed_out without signalling the exec")
				}
				return
			}
			time.Sleep(300 * time.Millisecond)
			if n := helper.cancelCount(); n != 0 {
				t.Fatalf("%d helper cancels at a deadline that did not pass", n)
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
	f.backend.answer = newSupervisedHelper().answer(t)
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

// An exec_read that finds the helper's end while the lane's own deadline kill
// is waiting for it records that end as the deadline's: the helper reports
// every exec it was asked to cancel as cancelled, whoever asked. A tenant's
// cancel stays cancelled.
func TestSandboxExecReadDuringAKillKeepsItsCause(t *testing.T) {
	for _, tc := range []struct {
		name     string
		deadline bool
		want     string
	}{
		{"deadline kill", true, sandbox.ExecStateTimedOut},
		{"tenant cancel", false, sandbox.ExecStateCancelled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newOpsFixture(t, testOpsConfig)
			helper := newSupervisedHelper()
			helper.statusGate = make(chan struct{})
			f.backend.answer = helper.answer(t)
			timeoutMS := uint64(time.Hour / time.Millisecond)
			if tc.deadline {
				timeoutMS = 1000
			}
			start := f.execStart(timeoutMS)
			if _, _, err := f.run(start, execPayload); err != nil {
				t.Fatal(err)
			}
			execID := protocol.SandboxOpIDV1(start)
			waitExecState(t, f, execID, sandbox.ExecStateRunning)
			cancelled := make(chan error, 1)
			if tc.deadline {
				f.clock.Add(time.Second) // the start owner's deadline timer fires
			} else {
				cancel := f.execOp(sandbox.OpExecCancel, execID)
				go func() {
					_, _, err := f.run(cancel, nil)
					cancelled <- err
				}()
			}
			select {
			case <-helper.cancelled:
			case <-time.After(10 * time.Second):
				t.Fatal("the kill path never signalled the exec")
			}
			// The kill path waits for the helper; a read sees the end first.
			read := f.execOp(sandbox.OpExecRead, execID)
			receipt, result, err := f.run(read, nil)
			if err != nil {
				t.Fatal(err)
			}
			f.verify(receipt, read, result, map[string]string{sandbox.ExecStateTimedOut: sandbox.OpStageTimedOut,
				sandbox.ExecStateCancelled: sandbox.OpStageCancelled}[tc.want], "")
			close(helper.statusGate)
			if !tc.deadline {
				if err := <-cancelled; err != nil {
					t.Fatal(err)
				}
			}
			waitExecState(t, f, execID, tc.want)
		})
	}
}

// A resolution armed for an exec never displaces its deadline: an exact
// replay whose admission answered an error can arm one after the start owner
// armed the deadline, and a start owner that gave up after its running record
// committed arms one for a running exec. The deadline still ends the exec at
// its own time, and a resolution that finds the lease at its expiry, still
// running, ends the exec as the deadline does. (Both orders come from races
// the store cannot produce on demand, so the lane's arming functions are
// called directly, in the order those races produce.)
func TestSandboxExecResolutionNeverDisplacesTheDeadline(t *testing.T) {
	for _, tc := range []struct {
		name      string
		timeoutMS uint64
		advance   time.Duration
		resolveIn time.Duration
	}{
		{"resolution armed after the deadline", 1000, time.Second, time.Minute},
		{"resolution at an unrenewed lease expiry", uint64(time.Hour / time.Millisecond), 10*time.Minute + time.Second, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newOpsFixture(t, testOpsConfig)
			helper := newSupervisedHelper()
			f.backend.answer = helper.answer(t)
			start := f.execStart(tc.timeoutMS)
			if _, _, err := f.run(start, execPayload); err != nil {
				t.Fatal(err)
			}
			execID := protocol.SandboxOpIDV1(start)
			waitExecState(t, f, execID, sandbox.ExecStateRunning)
			f.lane.armResolve(f.lane.ops, execID, f.lane.ops.execEntry(execID), tc.resolveIn)
			f.clock.Add(tc.advance)
			waitExecState(t, f, execID, sandbox.ExecStateTimedOut)
			if helper.cancelCount() == 0 {
				t.Fatal("recorded timed_out without signalling the exec")
			}
		})
	}
}
