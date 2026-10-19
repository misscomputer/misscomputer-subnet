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

// Guest code shares the helper's uid (B-5) and can stop it, so a helper call
// may never return. The kill path still ends: every helper call has its own
// bound, the exec is recorded cancelled whether or not the helper answered,
// and a cancel does not keep the agent-wide in-flight slot while it waits.
func TestSandboxExecKillPathIsBoundedAndReleasesItsSlot(t *testing.T) {
	config := testOpsConfig
	config.MaxInFlight = 1
	f := newOpsFixture(t, config)
	var hung atomic.Int64
	f.backend.answer = func(ctx context.Context, request sandboxops.Request) ([]byte, error) {
		switch request.Op {
		case sandbox.OpExecStart:
			return helperOut(t, sandboxops.Response{Exec: &sandboxops.ExecObservation{State: sandbox.ExecStateRunning}}), nil
		case sandbox.OpExecCancel, sandboxops.OpExecStatus:
			hung.Add(1)
			<-ctx.Done() // a stopped helper: the attached exec ends only with ctx
			return nil, ctx.Err()
		}
		return helperOut(t, sandboxops.Response{File: &sandbox.FileInfo{Type: sandbox.FileTypeDirectory}}), nil
	}
	start := f.execStart(600_000)
	if _, _, err := f.run(start, execPayload); err != nil {
		t.Fatal(err)
	}
	execID := protocol.SandboxOpIDV1(start)
	waitExecState(t, f, execID, sandbox.ExecStateRunning)

	cancel := f.execOp(sandbox.OpExecCancel, execID)
	type answer struct {
		receipt protocol.SandboxOpReceiptV1
		err     error
	}
	done := make(chan answer, 1)
	began := time.Now()
	go func() {
		receipt, _, err := f.run(cancel, nil)
		done <- answer{receipt, err}
	}()
	// While the cancel waits on the stopped helper, another op still gets the
	// one in-flight slot.
	for hung.Load() == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	stat := f.op(sandbox.OpFileStat, func(r *protocol.SandboxOpRequestV1) { r.Path = text("/") })
	if _, _, err := f.run(stat, nil); errors.Is(err, ErrSandboxOpsBusy) {
		t.Errorf("a cancel waiting on its helper holds the in-flight slot: %v", err)
	}
	bound := 2*sandbox.ExecKillGrace + config.KillGrace + 2*config.StateTimeout
	select {
	case got := <-done:
		if got.err != nil {
			t.Fatalf("cancel: %v", got.err)
		}
		f.verify(got.receipt, cancel, nil, sandbox.OpStageCancelled, "")
		t.Logf("cancel with a stopped helper ended cancelled after %v", time.Since(began).Round(time.Millisecond))
	case <-time.After(bound):
		t.Fatalf("exec_cancel still inside Op after %v with a stopped helper (%d helper calls hung)", bound, hung.Load())
	}
}

// The helper's own timer gets the exec's own bound, admitted_at +
// timeout_ms. The lease expiry bound stays with the lane's deadline, which
// renewals move; a helper told the lease expiry at start would end the exec
// early on every renewed lease.
func TestSandboxExecHelperDeadlineIsTheExecsOwnBound(t *testing.T) {
	f := newOpsFixture(t, testOpsConfig)
	var told atomic.Uint64
	f.backend.answer = func(_ context.Context, request sandboxops.Request) ([]byte, error) {
		if request.Op == sandbox.OpExecStart {
			told.Store(request.Exec.TimeoutMS)
		}
		return helperOut(t, sandboxops.Response{Exec: &sandboxops.ExecObservation{State: sandbox.ExecStateRunning}}), nil
	}
	const hour = uint64(time.Hour / time.Millisecond)
	start := f.execStart(hour)
	if _, _, err := f.run(start, execPayload); err != nil {
		t.Fatal(err)
	}
	execID := protocol.SandboxOpIDV1(start)
	waitExecState(t, f, execID, sandbox.ExecStateRunning)
	lookup, leaseExpiry, err := f.lane.ops.store.ExecState(context.Background(), execID)
	if err != nil || !leaseExpiry.Before(lookup.AdmittedAt.Add(time.Hour)) {
		t.Fatalf("fixture lease must end before the exec's own bound: %v %v", leaseExpiry, err)
	}
	if told.Load() != hour {
		t.Fatalf("helper told timeout_ms %d, want the exec's own %d (the lease expiry at start is %v away)", told.Load(), hour, leaseExpiry.Sub(lookup.AdmittedAt))
	}
}

// An exec_read that finds the exec admitted while its start owner records a
// start failure still answers a signed failed receipt: a failed stage carries
// no read result.
func TestSandboxExecReadRacingAStartFailureAnswersFailed(t *testing.T) {
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
	// The read's lookup transaction (third store clock reading once armed)
	// lets the start owner record its failure before the read answers.
	var armed atomic.Int64
	release := make(chan struct{})
	storeClock := func() time.Time {
		if armed.Load() > 0 && armed.Add(1) == 3 {
			close(release)
			time.Sleep(200 * time.Millisecond)
		}
		return f.clock.Now()
	}
	store, err := f.store.EnableSandboxOps(context.Background(), storeClock)
	if err != nil {
		t.Fatal(err)
	}
	if err := lane.EnableOps(store, testOpsConfig); err != nil {
		t.Fatal(err)
	}
	called := make(chan struct{}, 1)
	f.backend.answer = func(_ context.Context, request sandboxops.Request) ([]byte, error) {
		called <- struct{}{}
		<-release
		return helperOut(t, sandboxops.Failure(sandbox.OpCodeOpsUnsupport)), nil
	}
	start := f.execStart(60_000)
	if _, _, err := f.run(start, execPayload); err != nil {
		t.Fatal(err)
	}
	<-called
	armed.Store(1)
	read := f.execOp(sandbox.OpExecRead, protocol.SandboxOpIDV1(start))
	got, result, err := f.run(read, nil)
	if err != nil {
		t.Fatalf("exec_read racing the start failure got no receipt: %v", err)
	}
	f.verify(got, read, result, sandbox.OpStageFailed, sandbox.OpCodeOpsUnsupport)
}

// A durable step that runs out of D_state in the start owner does not strand
// the exec admitted with no start and no deadline: the owner retries and the
// exec starts.
func TestSandboxExecStartSurvivesATransientDurableFailure(t *testing.T) {
	config := testOpsConfig
	config.StateTimeout = 200 * time.Millisecond
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
	// Armed before the start: reading 1 is its admission, reading 2 the start
	// owner's first exec lookup, which outlives D_state.
	var readings atomic.Int64
	storeClock := func() time.Time {
		if readings.Add(1) == 2 {
			time.Sleep(3 * config.StateTimeout)
		}
		return f.clock.Now()
	}
	store, err := f.store.EnableSandboxOps(context.Background(), storeClock)
	if err != nil {
		t.Fatal(err)
	}
	if err := lane.EnableOps(store, config); err != nil {
		t.Fatal(err)
	}
	f.backend.answer = func(_ context.Context, request sandboxops.Request) ([]byte, error) {
		return helperOut(t, sandboxops.Response{Exec: &sandboxops.ExecObservation{State: sandbox.ExecStateRunning}}), nil
	}
	start := f.execStart(60_000)
	if _, _, err := f.run(start, execPayload); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for f.backend.count(sandbox.OpExecStart) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the exec stayed admitted with no start after a transient durable failure")
		}
		time.Sleep(20 * time.Millisecond)
	}
	waitExecState(t, f, protocol.SandboxOpIDV1(start), sandbox.ExecStateRunning)
}
