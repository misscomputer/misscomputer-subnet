// SPDX-License-Identifier: AGPL-3.0-only

package durable

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/sandbox"
)

// reopenOps closes the fixture's store and reopens it from the same file
// with a new clock, as a miner restart would.
func (f *opsFixture) reopenOps(t *testing.T, clock *opsClock) {
	t.Helper()
	if err := f.store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err := Open(f.path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	ctx := context.Background()
	leases, err := store.EnableSandboxLeases(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ops, err := leases.EnableSandboxOps(ctx, clock.read)
	if err != nil {
		t.Fatal(err)
	}
	f.store, f.leases, f.ops, f.clock = store, leases, ops, clock
}

// DP-8: decisions never go back in time. After a later decision, a wall
// clock stepped backward yields the high-water time instead, so a request
// whose window closed by that time stays refused.
func TestSandboxOpDecisionTimeNeverRunsBackwards(t *testing.T) {
	f := newOpsFixture(t)
	ctx := context.Background()
	// Two decisions raise the high-water time twice.
	if _, err := f.ops.AdmitOp(ctx, f.op(t, sandbox.OpFileStat, 3, f.clock.read(), nil)); err != nil {
		t.Fatal(err)
	}
	later := f.clock.read().Add(2 * time.Minute)
	f.clock.set(later)
	if _, err := f.ops.AdmitOp(ctx, f.op(t, sandbox.OpFileStat, 1, later, nil)); err != nil {
		t.Fatal(err)
	}
	stepped := later.Add(-time.Minute)
	f.clock.set(stepped)
	// Issued and expiring before the high-water time: the window is
	// closed by the store's time although the wall clock says it is open.
	inWindowByWallClock := f.op(t, sandbox.OpFileStat, 2, stepped.Add(-10*time.Second), nil)
	if _, err := f.ops.AdmitOp(ctx, inWindowByWallClock); !errors.Is(err, ErrSandboxOpExpired) {
		t.Fatalf("admission after a backward clock step: %v", err)
	}
	lookup, err := f.ops.LookupExec(ctx, f.op(t, sandbox.OpExecRead, 4, stepped, nil))
	if err != nil || lookup.DecidedAt.Before(later) {
		t.Fatalf("lookup decided at %v, before the high-water %v (%v)", lookup.DecidedAt, later, err)
	}
	if ops, _ := opRows(t, f.store); ops != 2 {
		t.Fatalf("%d op rows; the expired request was recorded", ops)
	}
}

// The case D13 relies on: an exec_not_found decided after the start's
// window stays definitive across a restart whose clock is behind. The
// high-water time is durable, so the store cannot later admit that
// exec_start.
func TestSandboxExecNotFoundStaysDefinitiveAcrossBackwardRestart(t *testing.T) {
	f := newOpsFixture(t)
	ctx := context.Background()
	at := f.clock.read()
	start := f.op(t, sandbox.OpExecStart, 1, at, nil)
	read := f.op(t, sandbox.OpExecRead, 2, at.Add(40*time.Second), nil)
	f.clock.set(at.Add(30*time.Second + sandbox.IssueSkew))
	if lookup, err := f.ops.LookupExec(ctx, read); err != nil || lookup.Found || lookup.Unavailable != nil {
		t.Fatalf("lookup %+v %v", lookup, err)
	}
	f.reopenOps(t, &opsClock{now: at.Add(5 * time.Second)})
	if decision, err := f.ops.AdmitOp(ctx, start); !errors.Is(err, ErrSandboxOpExpired) {
		t.Fatalf("exec_start admitted after a definitive exec_not_found and a backward restart: %+v %v", decision, err)
	}
	if _, execs := opRows(t, f.store); execs != 0 {
		t.Fatal("an exec was recorded after a definitive exec_not_found")
	}
}

// A refusal records no op, but its decision time still holds: the same
// request is not admitted after the clock steps back.
func TestSandboxOpWindowRefusalHoldsAfterBackwardStep(t *testing.T) {
	f := newOpsFixture(t)
	ctx := context.Background()
	at := f.clock.read()
	late := f.op(t, sandbox.OpExecStart, 1, at, nil)
	f.clock.set(at.Add(30 * time.Second))
	if _, err := f.ops.AdmitOp(ctx, late); !errors.Is(err, ErrSandboxOpExpired) {
		t.Fatalf("window closed: %v", err)
	}
	f.clock.set(at.Add(time.Second))
	if decision, err := f.ops.AdmitOp(ctx, late); !errors.Is(err, ErrSandboxOpExpired) {
		t.Fatalf("refused request admitted after a backward step: %+v %v", decision, err)
	}
}
