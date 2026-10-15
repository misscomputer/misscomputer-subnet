// SPDX-License-Identifier: AGPL-3.0-only

package durable

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/protocol"
	"github.com/misscomputer/misscomputer-subnet/pkg/sandbox"
)

// U1: every durable lease state, reached through the real lease lane, maps
// to exactly one op answer. The refusal codes are non-fault op codes that
// a miner-signed refused receipt carries; a live lease admits the op.
func TestSandboxOpLeaseStateMapsToOneRefusalCode(t *testing.T) {
	ctx := context.Background()
	leaseID := func(f *opsFixture) string { return protocol.SandboxLeaseIDV1(f.lease) }
	complete := func(t *testing.T, f *opsFixture) {
		if err := f.leases.CompleteLeaseCleanup(ctx, leaseID(f), f.clock.read()); err != nil {
			t.Fatal(err)
		}
	}
	release := func(t *testing.T, f *opsFixture) {
		if _, _, err := f.leases.Release(ctx, f.parties.release(t, 1, f.clock.read()), f.clock.read()); err != nil {
			t.Fatal(err)
		}
	}
	sweep := func(t *testing.T, f *opsFixture) {
		f.clock.set(sandboxT0.Add(10*time.Minute + sandbox.Grace))
		if _, err := f.leases.Sweep(ctx, f.clock.read()); err != nil {
			t.Fatal(err)
		}
	}
	restart := func(t *testing.T, f *opsFixture) {
		if _, err := f.leases.Recover(ctx, f.clock.read()); err != nil {
			t.Fatal(err)
		}
	}
	for _, row := range []struct {
		name, status, code string
		reach              func(t *testing.T, f *opsFixture)
	}{
		{"running", "running", "", func(*testing.T, *opsFixture) {}},
		{"running past expiry", "running", "lease_expired", func(_ *testing.T, f *opsFixture) { f.clock.set(sandboxT0.Add(10 * time.Minute)) }},
		{"cleanup after release", "cleanup", "released", release},
		{"released", "released", "released", func(t *testing.T, f *opsFixture) { release(t, f); complete(t, f) }},
		{"cleanup after expiry", "cleanup", "lease_expired", sweep},
		{"expired", "expired", "lease_expired", func(t *testing.T, f *opsFixture) { sweep(t, f); complete(t, f) }},
		{"cleanup after restart", "cleanup", "lease_not_running", restart},
		{"failed after restart", "failed", "lease_not_running", func(t *testing.T, f *opsFixture) { restart(t, f); complete(t, f) }},
	} {
		t.Run(row.name, func(t *testing.T) {
			f := newOpsFixture(t)
			row.reach(t, f)
			request := f.op(t, sandbox.OpFileStat, 7, f.clock.read(), nil)
			decision, err := f.ops.AdmitOp(ctx, request)
			if err != nil {
				t.Fatal(err)
			}
			if row.code == "" {
				if decision.Unavailable != nil || decision.Replay {
					t.Fatalf("live lease did not admit: %+v", decision)
				}
				return
			}
			if decision.Unavailable == nil || decision.Unavailable.Status != row.status {
				t.Fatalf("decision %+v, want raw status %q", decision, row.status)
			}
			if got := decision.Unavailable.RefusalCode(decision.DecidedAt); got != row.code {
				t.Fatalf("code %q, want %q", got, row.code)
			}
			if ops, _ := opRows(t, f.store); ops != 0 {
				t.Fatal("a refused op was recorded")
			}
			assertRefusedReceipt(t, f, request, row.code)
		})
	}
}

// No lease row means no receipt, even when a release fence exists for the
// identity: a fence carries no lease_id or digest, so the miner would be
// signing for a lease it never held.
func TestSandboxOpOnFencedIdentityWithoutLeaseHasNoAnswer(t *testing.T) {
	f := newOpsFixture(t)
	ctx := context.Background()
	reservation := f.parties.reservation(t, 3, nonce(3), sandboxT0)
	never := f.parties.lease(t, reservation, nonce(301), sandboxT0, nil)
	if _, _, err := f.leases.Release(ctx, f.parties.release(t, 3, f.clock.read()), f.clock.read()); err != nil {
		t.Fatal(err)
	}
	for _, request := range []protocol.SandboxOpRequestV1{
		f.opOn(t, f.parties, never, sandbox.OpFileStat, 1, f.clock.read(), nil),
		f.opOn(t, f.parties, never, sandbox.OpExecStart, 2, f.clock.read(), nil),
	} {
		if _, err := f.ops.AdmitOp(ctx, request); !errors.Is(err, ErrSandboxOpForeign) {
			t.Fatalf("%s on a fenced identity without a lease: %v", request.Op, err)
		}
	}
	if _, err := f.ops.LookupExec(ctx, f.opOn(t, f.parties, never, sandbox.OpExecRead, 4, f.clock.read(), nil)); !errors.Is(err, ErrSandboxOpForeign) {
		t.Fatalf("lookup on a fenced identity without a lease: %v", err)
	}
	if ops, execs := opRows(t, f.store); ops != 0 || execs != 0 {
		t.Fatal("an op on an unheld lease was recorded")
	}
}

// assertRefusedReceipt checks that a refused receipt carrying code for
// request is a valid miner-signed answer, and that code is non-fault.
func assertRefusedReceipt(t *testing.T, f *opsFixture, request protocol.SandboxOpRequestV1, code string) {
	t.Helper()
	if fault, known := sandbox.OpErrorAttribution[code]; !known || fault {
		t.Fatalf("code %q is unknown or a miner fault", code)
	}
	digest, err := protocol.SandboxOpDigestV1(request)
	if err != nil {
		t.Fatal(err)
	}
	receipt := protocol.SandboxOpReceiptV1{
		DocumentDigest: digest, ErrorCode: &code, Generation: request.Generation, LeaseID: request.LeaseID,
		MinerID: request.MinerID, ObservedAt: sandboxStamp(f.clock.read()), Op: request.Op, OpID: protocol.SandboxOpIDV1(request),
		SandboxID: request.SandboxID, Schema: protocol.SandboxOpReceiptSchema, SchemaVersion: 1, Stage: sandbox.OpStageRefused, Subnet: request.Subnet,
	}
	if err := protocol.SignSandboxOpReceiptV1(&receipt, f.parties.miner); err != nil {
		t.Fatalf("refused receipt with %q: %v", code, err)
	}
	if err := protocol.SandboxOpReceiptAnswersV1(receipt, request, nil); err != nil {
		t.Fatalf("refused receipt does not answer the request: %v", err)
	}
}
