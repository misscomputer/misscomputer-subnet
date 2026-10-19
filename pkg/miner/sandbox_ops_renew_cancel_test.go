// SPDX-License-Identifier: AGPL-3.0-only

package miner

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/protocol"
	"github.com/misscomputer/misscomputer-subnet/pkg/sandbox"
	"github.com/misscomputer/misscomputer-subnet/pkg/sandboxops"
)

// storeScript runs one queued step on each clock reading of the ops store,
// that is once per durable transaction, while the transaction holds the
// store's single connection. A nil step and every reading past the queue are
// plain readings.
type storeScript struct {
	mu    sync.Mutex
	steps []func()
}

func (s *storeScript) queue(steps ...func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.steps = append([]func(){}, steps...)
}

func (s *storeScript) next() {
	s.mu.Lock()
	var step func()
	if len(s.steps) > 0 {
		step, s.steps = s.steps[0], s.steps[1:]
	}
	s.mu.Unlock()
	if step != nil {
		step()
	}
}

// scriptedOpsFixture is the ops fixture whose ops store reads storeClock, not
// the lane's clock, and runs script on each of its clock readings.
func scriptedOpsFixture(t *testing.T, config SandboxOpsConfig) (*opsFixture, *opsClock, *storeScript) {
	t.Helper()
	f := &opsFixture{sbFixture: newSBFixture(t), clock: &opsClock{}}
	f.clock.Set(sbT0)
	storeClock := &opsClock{}
	storeClock.Set(sbT0)
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
	script := &storeScript{}
	store, err := f.store.EnableSandboxOps(context.Background(), func() time.Time {
		script.next()
		return storeClock.Now()
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := lane.EnableOps(store, config); err != nil {
		t.Fatal(err)
	}
	return f, storeClock, script
}

// A renewal on an agent that runs ops is decided inside its own store
// transaction on the ops store's high-water clock, the clock the lease-expiry
// kill decides on, and the store's single connection orders the two. A
// renewal whose transaction runs after the kill's read of the lease at or
// past its expiry, whether it waited behind the deadline's read or behind the
// kill path's own read, is decided at or after that read: it arrived after
// the expiry and is not applied (receipt expired, expiry unchanged), whatever
// the lane's clock read when it arrived, and the exec ends timed_out at the
// old expiry. A renewal decided before the expiry is applied, its receipt is
// observed at that decision time, and the deadline it moved keeps the exec.
func TestSandboxRenewalIsOrderedAgainstTheExpiryKill(t *testing.T) {
	expiry := sbT0.Add(10 * time.Minute) // the fixture lease's expiry
	for _, tc := range []struct {
		name string
		// arrives is the lane's clock, and the renewal's issue time, when the
		// renewal arrives; decides is the ops store's clock.
		arrives, decides time.Duration
		// behind is the store reading of the deadline's kill the renewal
		// waits behind: 1 the deadline's read, 2 the kill path's read; 0 it
		// is decided before the deadline fires.
		behind  int
		applied bool
	}{
		{"renewal waiting behind the deadline's read", -time.Second, time.Second, 1, false},
		{"renewal waiting behind the kill path's read", -time.Second, time.Second, 2, false},
		{"renewal decided before the expiry", -5 * time.Second, -time.Second, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, storeClock, script := scriptedOpsFixture(t, testOpsConfig)
			helper := newSupervisedHelper()
			f.backend.answer = helper.answer(t)
			start := f.execStart(uint64(time.Hour / time.Millisecond))
			if _, _, err := f.run(start, execPayload); err != nil {
				t.Fatal(err)
			}
			execID := protocol.SandboxOpIDV1(start)
			waitExecState(t, f, execID, sandbox.ExecStateRunning)
			f.clock.Set(expiry.Add(tc.arrives))
			f.sbFixture.now = expiry.Add(tc.arrives)
			storeClock.Set(expiry.Add(tc.decides))
			renewal := f.renewal(f.lease, 1)
			renewed := make(chan protocol.SandboxReceiptV1, 1)
			renew := func() {
				receipt, err := f.lane.Renew(context.Background(), renewal, f.request())
				if err != nil {
					t.Error(err)
				}
				renewed <- receipt
			}
			if tc.behind == 0 {
				renew()
				storeClock.Set(expiry.Add(time.Second))
			} else {
				steps := make([]func(), tc.behind)
				steps[tc.behind-1] = func() {
					// Inside that read, holding the store's connection: the
					// renewal arrives and waits for it.
					go renew()
					time.Sleep(200 * time.Millisecond)
				}
				script.queue(steps...)
			}
			f.lane.armDeadline(f.lane.ops, execID, f.lane.ops.execEntry(execID), 0)
			receipt := <-renewed
			if tc.applied {
				f.check(receipt, nil, protocol.SandboxRenewalSchema, renewal, sandbox.StageReady, "")
				if want := stamp(expiry.Add(tc.decides)); receipt.ObservedAt != want {
					t.Fatalf("renewal receipt observed at %s, want its decision time %s", receipt.ObservedAt, want)
				}
				time.Sleep(time.Second)
			} else {
				f.check(receipt, nil, protocol.SandboxRenewalSchema, renewal, sandbox.StageExpired, "")
				waitExecState(t, f, execID, sandbox.ExecStateTimedOut)
			}
			lookup, leaseExpiry, err := f.lane.ops.store.ExecState(context.Background(), execID)
			if err != nil {
				t.Fatal(err)
			}
			switch {
			case tc.applied && (!leaseExpiry.After(expiry) || lookup.State != sandbox.ExecStateRunning || helper.cancelCount() != 0):
				t.Fatalf("renewed lease (expiry %v): exec %s after %d helper cancels, want running", leaseExpiry, lookup.State, helper.cancelCount())
			case !tc.applied && (!leaseExpiry.Equal(expiry) || helper.cancelCount() == 0):
				t.Fatalf("late renewal: lease expiry %v (want %v unchanged), %d helper cancels", leaseExpiry, expiry, helper.cancelCount())
			}
		})
	}
}

// Without ops the lane's own clock decides a renewal, as it always did: the
// receipt is observed at the lane's time; before the expiry the renewal is
// applied, at the expiry it is not.
func TestSandboxRenewalWithoutOpsDecidesOnTheLaneClock(t *testing.T) {
	f := newSBFixture(t)
	_, lease, receipt, err := f.commitHeld(1, nil)
	f.check(receipt, err, protocol.SandboxLeaseSchema, lease, sandbox.StageReady, "")
	beforeExpiry := sbT0.Add(10*time.Minute - time.Second)
	for _, tc := range []struct {
		seq   uint64
		at    time.Time
		stage string
	}{
		{1, beforeExpiry, sandbox.StageReady},
		{2, beforeExpiry.Add(14 * time.Minute), sandbox.StageExpired}, // exactly the expiry renewal 1 set
	} {
		f.now = tc.at
		renewal := f.renewal(lease, tc.seq)
		receipt, err := f.lane.Renew(context.Background(), renewal, f.request())
		f.check(receipt, err, protocol.SandboxRenewalSchema, renewal, tc.stage, "")
		if receipt.ObservedAt != stamp(tc.at) {
			t.Fatalf("renewal %d observed at %s, want the lane's time %s", tc.seq, receipt.ObservedAt, stamp(tc.at))
		}
	}
}

// admitLost leaves start as an exec_start whose durable admission committed
// but answered an error: admitted, held by the lane with no start owner, and a
// resolution armed for its request window, the state execStart's error path
// leaves. The store cannot fail an admission after committing it on demand,
// so the lane's own steps are taken here in that order.
func admitLost(t *testing.T, f *opsFixture, start protocol.SandboxOpRequestV1) {
	t.Helper()
	ops := f.lane.ops
	opID := protocol.SandboxOpIDV1(start)
	expires, _ := time.Parse(time.RFC3339Nano, start.ExpiresAt)
	exec := &opExec{leaseID: start.LeaseID, instance: SandboxInstanceName(start.LeaseID),
		timeout: time.Duration(*start.TimeoutMS) * time.Millisecond, maxOutput: *start.MaxOutputBytes, requestExpires: expires}
	ops.mu.Lock()
	ops.execs[opID] = exec
	ops.mu.Unlock()
	if admission, err := ops.store.AdmitOp(context.Background(), start); err != nil || !admission.Start {
		t.Fatalf("admission %+v %v", admission, err)
	}
	f.lane.armResolve(ops, opID, exec, expires.Sub(f.clock.Now()))
}

// A tenant's exec_cancel is not lost when the store fails every try of its
// kill path's read: once the store answers, the retry runs that cancel (the
// helper cancel, recorded cancelled), not the exec's deadline, which for a
// started exec lies in the future. An exec whose start was in flight is
// killed once started; an admitted exec no start owner took is never started
// by the replay that adopts it; and a lease expiry passing while the cancel
// is pending does not relabel it. The exec starts at most once.
func TestSandboxExecCancelSurvivesAStoreFailure(t *testing.T) {
	config := testOpsConfig
	config.StateTimeout = 200 * time.Millisecond
	config.StartResolution = 30 * time.Second
	const (
		running  = "running exec"
		starting = "start in flight"
		unowned  = "admission answer lost, then replayed"
		lapsed   = "lease expiry passes while the cancel is pending"
	)
	for _, tc := range []struct {
		name   string
		starts int
	}{{running, 1}, {starting, 1}, {unowned, 0}, {lapsed, 1}} {
		t.Run(tc.name, func(t *testing.T) {
			f, storeClock, script := scriptedOpsFixture(t, config)
			helper := newSupervisedHelper()
			answer := helper.answer(t)
			gate, entered := make(chan struct{}), make(chan struct{}, 1)
			f.backend.answer = func(ctx context.Context, request sandboxops.Request) ([]byte, error) {
				if request.Op == sandbox.OpExecStart {
					select {
					case entered <- struct{}{}:
					default:
					}
					select {
					case <-gate:
					case <-ctx.Done():
						return nil, ctx.Err()
					}
				}
				return answer(ctx, request)
			}
			start := f.execStart(uint64(time.Hour / time.Millisecond))
			execID := protocol.SandboxOpIDV1(start)
			switch tc.name {
			case starting:
				if _, _, err := f.run(start, execPayload); err != nil {
					t.Fatal(err)
				}
				select {
				case <-entered: // the start owner read its state and called the helper
				case <-time.After(10 * time.Second):
					t.Fatal("the start owner never called the helper")
				}
			case unowned:
				close(gate)
				admitLost(t, f, start)
			default:
				close(gate)
				if _, _, err := f.run(start, execPayload); err != nil {
					t.Fatal(err)
				}
				waitExecState(t, f, execID, sandbox.ExecStateRunning)
			}
			stall := func() { time.Sleep(3 * config.StateTimeout) }
			last := stall
			if tc.name == lapsed {
				last = func() {
					stall()
					storeClock.Add(10*time.Minute + time.Second) // past the fixture lease's expiry
				}
			}
			// The cancel's admission and lookup answer; every try of its kill
			// path's read outlives D_state.
			script.queue(nil, nil, stall, stall, last)
			cancel := f.execOp(sandbox.OpExecCancel, execID)
			if _, _, err := f.run(cancel, nil); err != nil {
				t.Fatal(err)
			}
			switch tc.name {
			case starting:
				close(gate)
			case unowned:
				// The exact replay inside the request window adopts the
				// admission.
				if _, _, err := f.run(start, execPayload); err != nil {
					t.Fatal(err)
				}
			}
			waitExecState(t, f, execID, sandbox.ExecStateCancelled)
			if n := f.backend.count(sandbox.OpExecStart); n != tc.starts {
				t.Fatalf("%d backend starts, want %d", n, tc.starts)
			}
			if tc.starts > 0 && helper.cancelCount() == 0 {
				t.Fatal("recorded cancelled without signalling the exec")
			}
		})
	}
}

// A tenant's exec_cancel that reads its exec as not yet started must not end a
// start that already recorded running. The store clock hook runs inside the
// kill path's read, frees the helper and holds the store's connection, so the
// start owner's running record queues behind that read: the read still sees
// the row admitted, and the row is running when the kill path writes. The
// kill path must then signal the exec through the helper, and only after that
// end the row, not record cancelled over a running process.
func TestSandboxCancelOfAStartInFlightSignalsTheExec(t *testing.T) {
	f, _, script := scriptedOpsFixture(t, testOpsConfig)
	helper := newSupervisedHelper()
	answer := helper.answer(t)
	gate := make(chan struct{})
	entered := make(chan struct{}, 1)
	f.backend.answer = func(ctx context.Context, request sandboxops.Request) ([]byte, error) {
		if request.Op == sandbox.OpExecStart {
			select {
			case entered <- struct{}{}:
			default:
			}
			select {
			case <-gate:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return answer(ctx, request)
	}
	start := f.execStart(uint64(time.Hour / time.Millisecond))
	if _, _, err := f.run(start, execPayload); err != nil {
		t.Fatal(err)
	}
	execID := protocol.SandboxOpIDV1(start)
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the start owner never called the helper")
	}
	// The cancel takes three store clock readings before its kill path's read:
	// its admission, its lookup, and the kill path's own read. The fourth is
	// the start owner's running record, queued behind that read.
	script.queue(nil, nil, func() {
		close(gate)
		time.Sleep(300 * time.Millisecond)
	})
	cancel := f.execOp(sandbox.OpExecCancel, execID)
	receipt, _, err := f.run(cancel, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.verify(receipt, cancel, nil, sandbox.OpStageCancelled, "")
	lookup, _, err := f.lane.ops.store.ExecState(context.Background(), execID)
	if err != nil {
		t.Fatal(err)
	}
	helper.mu.Lock()
	signalled := helper.state
	helper.mu.Unlock()
	if helper.cancelCount() == 0 || signalled != sandbox.ExecStateCancelled {
		t.Fatalf("exec is %s while the helper reports it %s after %d cancel signals: the started exec was never signalled",
			lookup.State, signalled, helper.cancelCount())
	}
	if n := f.backend.count(sandbox.OpExecStart); n != 1 {
		t.Fatalf("%d helper starts, want 1", n)
	}
}
