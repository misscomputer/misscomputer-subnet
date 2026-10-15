// SPDX-License-Identifier: AGPL-3.0-only

package durable

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/protocol"
	"github.com/misscomputer/misscomputer-subnet/pkg/sandbox"
)

// opsClock is a settable clock. AdmitOp and LookupExec read it inside
// their transactions.
type opsClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *opsClock) read() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *opsClock) set(t time.Time) { c.mu.Lock(); c.now = t; c.mu.Unlock() }

type opsFixture struct {
	store   *Store
	path    string
	leases  *SandboxLeases
	ops     *SandboxOps
	clock   *opsClock
	parties sandboxParties
	lease   protocol.SandboxLeaseV1
}

// newOpsFixture opens a real store with a running lease, created through
// the lease lane itself (hold, commit, mark running).
func newOpsFixture(t *testing.T) *opsFixture {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.db")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	ctx := context.Background()
	leases, err := store.EnableSandboxLeases(ctx)
	if err != nil {
		t.Fatal(err)
	}
	clock := &opsClock{now: sandboxT0.Add(time.Minute)}
	ops, err := leases.EnableSandboxOps(ctx, clock.read)
	if err != nil {
		t.Fatal(err)
	}
	parties := newSandboxParties(0x11, "5Hvalidator")
	reservation := parties.reservation(t, 1, nonce(1), sandboxT0)
	if _, err := leases.Hold(ctx, reservation, capacityFor(4), sandboxT0); err != nil {
		t.Fatal(err)
	}
	lease := parties.lease(t, reservation, nonce(101), sandboxT0, nil)
	if outcome, err := leases.CommitLease(ctx, lease, sandboxT0); err != nil || !outcome.Start {
		t.Fatalf("commit: %+v %v", outcome, err)
	}
	if running, err := leases.MarkLeaseRunning(ctx, protocol.SandboxLeaseIDV1(lease), sandboxT0); err != nil || !running {
		t.Fatalf("mark running: %v %v", running, err)
	}
	return &opsFixture{store: store, path: path, leases: leases, ops: ops, clock: clock, parties: parties, lease: lease}
}

func u64p(value uint64) *uint64 { return &value }

// op returns a signed op request on the fixture lease, issued at issued
// with a 30 s window.
func (f *opsFixture) op(t *testing.T, kind string, opNonce int, issued time.Time, mutate func(*protocol.SandboxOpRequestV1)) protocol.SandboxOpRequestV1 {
	t.Helper()
	return f.opOn(t, f.parties, f.lease, kind, opNonce, issued, mutate)
}

func (f *opsFixture) opOn(t *testing.T, parties sandboxParties, lease protocol.SandboxLeaseV1, kind string, opNonce int, issued time.Time, mutate func(*protocol.SandboxOpRequestV1)) protocol.SandboxOpRequestV1 {
	t.Helper()
	digest, err := protocol.SandboxDigestV1(lease)
	if err != nil {
		t.Fatal(err)
	}
	leaseID := protocol.SandboxLeaseIDV1(lease)
	payload := protocol.SandboxContentDigestV1([]byte(`{"argv":["true"],"cwd":"/","env":{},"stdin_b64":null}`))
	r := protocol.SandboxOpRequestV1{
		ExpiresAt: sandboxStamp(issued.Add(30 * time.Second)), Generation: lease.Generation, IssuedAt: sandboxStamp(issued),
		LeaseDigest: digest, LeaseID: leaseID, MinerID: lease.MinerID, Op: kind, OpNonce: nonce(opNonce), SandboxID: lease.SandboxID,
		Schema: protocol.SandboxOpRequestSchema, SchemaVersion: 1, Subnet: parties.binding(), WorkloadKind: sandbox.WorkloadKind,
	}
	switch kind {
	case sandbox.OpExecStart:
		r.PayloadDigest, r.PayloadBytes, r.TimeoutMS, r.MaxOutputBytes = &payload, 52, u64p(60000), u64p(1<<20)
	case sandbox.OpExecRead:
		execID := leaseID + "-op-" + nonce(opNonce-1)
		r.ExecID, r.Offset, r.Limit, r.Stream = &execID, u64p(0), u64p(4096), sandboxCode(sandbox.ExecStdout)
	case sandbox.OpFileStat:
		r.Path = sandboxCode("/workspace")
	case sandbox.OpFileWrite:
		mode := uint32(0o644)
		r.Path, r.PayloadDigest, r.PayloadBytes, r.Offset, r.Mode = sandboxCode("/workspace/secret-name-7c1f.txt"), &payload, 52, u64p(0), &mode
	}
	if mutate != nil {
		mutate(&r)
	}
	if err := protocol.SignSandboxOpRequestV1(&r, parties.validator); err != nil {
		t.Fatal(err)
	}
	return r
}

func opRows(t *testing.T, store *Store) (ops, execs int) {
	t.Helper()
	if err := store.db.QueryRow(`SELECT (SELECT COUNT(*) FROM sandbox_ops),(SELECT COUNT(*) FROM sandbox_execs)`).Scan(&ops, &execs); err != nil {
		t.Fatal(err)
	}
	return ops, execs
}

func schemaWithoutOps(t *testing.T, store *Store) string {
	t.Helper()
	rows, err := store.db.Query(`SELECT type,name,COALESCE(sql,'') FROM sqlite_master WHERE tbl_name NOT IN ('sandbox_ops','sandbox_execs') ORDER BY type,name`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var dump strings.Builder
	for rows.Next() {
		var kind, name, ddl string
		if err := rows.Scan(&kind, &name, &ddl); err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&dump, "%s %s %s\n", kind, name, ddl)
	}
	return dump.String()
}

func opsTables(t *testing.T, store *Store) int {
	t.Helper()
	var count int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE tbl_name IN ('sandbox_ops','sandbox_execs')`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

// The ops tables exist only after the explicit opt-in. Open and the lease
// lane never create them. Enabling them leaves every other table definition,
// the lease tables included, byte-identical, and that holds across a reopen.
func TestSandboxOpsAreOptInAndLeaveOtherTablesUnchanged(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	leases, err := store.EnableSandboxLeases(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n := opsTables(t, store); n != 0 {
		t.Fatalf("Open plus the lease lane created %d ops schema objects", n)
	}
	before := schemaWithoutOps(t, store)
	for range 2 {
		if _, err := leases.EnableSandboxOps(ctx, time.Now); err != nil {
			t.Fatal(err)
		}
	}
	if opsTables(t, store) == 0 || schemaWithoutOps(t, store) != before {
		t.Fatal("enabling ops did not create only the ops tables")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if schemaWithoutOps(t, reopened) != before {
		t.Fatal("reopening changed the other tables")
	}
}

// D13 write-ahead and replay. The first admission of an exec_start is
// durable and permits a start once; an exact replay never permits a
// second. A different document for the same op_id is equivocation and
// changes nothing. The exec is then found exactly by its exec_id.
func TestSandboxOpAdmissionIsWriteAheadAndReplaySafe(t *testing.T) {
	f := newOpsFixture(t)
	ctx := context.Background()
	at := f.clock.read()
	start := f.op(t, sandbox.OpExecStart, 1, at, nil)
	first, err := f.ops.AdmitOp(ctx, start)
	if err != nil || !first.Start || first.Replay || !first.AdmittedAt.Equal(at) {
		t.Fatalf("first admission %+v %v", first, err)
	}
	f.clock.set(at.Add(5 * time.Second))
	replay, err := f.ops.AdmitOp(ctx, start)
	if err != nil || replay.Start || !replay.Replay || !replay.AdmittedAt.Equal(at) {
		t.Fatalf("replay %+v %v", replay, err)
	}
	other := f.op(t, sandbox.OpExecStart, 1, at, func(r *protocol.SandboxOpRequestV1) { r.TimeoutMS = u64p(1000) })
	if _, err := f.ops.AdmitOp(ctx, other); !errors.Is(err, ErrSandboxConflict) {
		t.Fatalf("equivocating exec_start: %v", err)
	}
	stat := f.op(t, sandbox.OpFileStat, 3, at, nil)
	if decision, err := f.ops.AdmitOp(ctx, stat); err != nil || decision.Start || decision.Replay {
		t.Fatalf("file_stat %+v %v", decision, err)
	}
	if _, err := f.ops.AdmitOp(ctx, f.op(t, sandbox.OpFileStat, 3, at, func(r *protocol.SandboxOpRequestV1) { r.Path = sandboxCode("/etc") })); !errors.Is(err, ErrSandboxConflict) {
		t.Fatalf("equivocating file_stat: %v", err)
	}
	if ops, execs := opRows(t, f.store); ops != 2 || execs != 1 {
		t.Fatalf("rows %d ops %d execs", ops, execs)
	}
	found, err := f.ops.LookupExec(ctx, f.op(t, sandbox.OpExecRead, 2, at, nil))
	if err != nil || !found.Found || found.State != "admitted" || !found.AdmittedAt.Equal(at) {
		t.Fatalf("lookup of the admitted exec %+v %v", found, err)
	}
	missing, err := f.ops.LookupExec(ctx, f.op(t, sandbox.OpExecRead, 9, at, nil))
	if err != nil || missing.Found || missing.Unavailable != nil {
		t.Fatalf("lookup of an exec never admitted %+v %v", missing, err)
	}
}

// SR-28-05: the store re-decides the request window, the lease state and
// the lease expiry with its own in-transaction clock. A refusal records
// nothing, and the liveness fence follows renewals.
func TestSandboxOpAdmissionRedecidesWindowAndLeaseInTransaction(t *testing.T) {
	f := newOpsFixture(t)
	ctx := context.Background()
	at := f.clock.read()
	// The request passed its bound check at issue time; the store
	// decides at the window's end.
	late := f.op(t, sandbox.OpExecStart, 1, at, nil)
	f.clock.set(at.Add(30 * time.Second))
	if _, err := f.ops.AdmitOp(ctx, late); !errors.Is(err, ErrSandboxOpExpired) {
		t.Fatalf("window closed at the store: %v", err)
	}

	// The lease expires at T0+10m; a renewal moves it to T0+20m.
	f.clock.set(sandboxT0.Add(10 * time.Minute))
	expired, err := f.ops.AdmitOp(ctx, f.op(t, sandbox.OpExecStart, 2, f.clock.read(), nil))
	if err != nil || expired.Unavailable == nil || expired.Unavailable.Status != "running" || !expired.Unavailable.ExpiresAt.Equal(sandboxT0.Add(10*time.Minute)) {
		t.Fatalf("op at lease expiry %+v %v", expired, err)
	}
	renewal := f.parties.renewal(t, f.lease, 1, sandboxT0.Add(9*time.Minute), sandboxT0.Add(20*time.Minute))
	if _, err := f.leases.Renew(ctx, renewal, sandboxT0.Add(9*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if renewed, err := f.ops.AdmitOp(ctx, f.op(t, sandbox.OpExecStart, 3, f.clock.read(), nil)); err != nil || !renewed.Start {
		t.Fatalf("op after renewal %+v %v", renewed, err)
	}

	stranger := newSandboxParties(0x33, "5Hstranger")
	if _, err := f.ops.AdmitOp(ctx, f.opOn(t, stranger, f.lease, sandbox.OpFileStat, 4, f.clock.read(), nil)); !errors.Is(err, ErrSandboxOpForeign) {
		t.Fatalf("another validator's op: %v", err)
	}
	sibling := f.parties.lease(t, f.parties.reservation(t, 1, nonce(1), sandboxT0), nonce(102), sandboxT0, nil)
	if _, err := f.ops.AdmitOp(ctx, f.opOn(t, f.parties, sibling, sandbox.OpFileStat, 5, f.clock.read(), nil)); !errors.Is(err, ErrSandboxOpForeign) {
		t.Fatalf("op naming a lease this miner never committed: %v", err)
	}

	if _, _, err := f.leases.Release(ctx, f.parties.release(t, 1, f.clock.read()), f.clock.read()); err != nil {
		t.Fatal(err)
	}
	released, err := f.ops.AdmitOp(ctx, f.op(t, sandbox.OpFileStat, 6, f.clock.read(), nil))
	if err != nil || released.Unavailable == nil || released.Unavailable.Status != "cleanup" ||
		released.Unavailable.CleanupStatus == nil || *released.Unavailable.CleanupStatus != "released" {
		t.Fatalf("op on a released lease %+v %v", released, err)
	}
	if ops, execs := opRows(t, f.store); ops != 1 || execs != 1 {
		t.Fatalf("refusals recorded rows: %d ops %d execs", ops, execs)
	}
}

// A lease that was committed but never started cannot run ops.
func TestSandboxOpOnPendingLeaseRecordsNothing(t *testing.T) {
	f := newOpsFixture(t)
	ctx := context.Background()
	reservation := f.parties.reservation(t, 2, nonce(2), sandboxT0)
	if _, err := f.leases.Hold(ctx, reservation, capacityFor(4), sandboxT0); err != nil {
		t.Fatal(err)
	}
	pending := f.parties.lease(t, reservation, nonce(201), sandboxT0, nil)
	if _, err := f.leases.CommitLease(ctx, pending, sandboxT0); err != nil {
		t.Fatal(err)
	}
	decision, err := f.ops.AdmitOp(ctx, f.opOn(t, f.parties, pending, sandbox.OpExecStart, 1, f.clock.read(), nil))
	if err != nil || decision.Unavailable == nil || decision.Unavailable.Status != "pending" || decision.Start {
		t.Fatalf("op on a pending lease %+v %v", decision, err)
	}
	if ops, _ := opRows(t, f.store); ops != 0 {
		t.Fatal("refused op was recorded")
	}
}

// The caps are decided inside the admission transaction. Twenty concurrent
// exec_starts admit exactly sixteen. Terminal execs free running slots, and
// the session cap holds independently of them.
func TestSandboxExecCapsHoldUnderConcurrency(t *testing.T) {
	f := newOpsFixture(t)
	ctx := context.Background()
	at := f.clock.read()
	var wait sync.WaitGroup
	var mu sync.Mutex
	outcomes := map[string]int{}
	for n := range 20 {
		request := f.op(t, sandbox.OpExecStart, 1000+n, at, nil)
		wait.Add(1)
		go func() {
			defer wait.Done()
			decision, err := f.ops.AdmitOp(ctx, request)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err != nil:
				outcomes["error"]++
			case decision.Start:
				outcomes["start"]++
			case decision.Limited:
				outcomes["limited"]++
			}
		}()
	}
	wait.Wait()
	if outcomes["start"] != sandbox.MaxRunningExecs || outcomes["limited"] != 20-sandbox.MaxRunningExecs {
		t.Fatalf("outcomes %v", outcomes)
	}
	leaseID := protocol.SandboxLeaseIDV1(f.lease)
	finish := func(opNonce int) error {
		return f.ops.RecordExecState(ctx, leaseID+"-op-"+nonce(opNonce), sandbox.ExecStateExited, nil)
	}
	finished := 0
	for n := range 20 {
		if finish(1000+n) == nil {
			finished++
		}
	}
	if finished != sandbox.MaxRunningExecs {
		t.Fatalf("finished %d admitted execs", finished)
	}
	for n := sandbox.MaxRunningExecs; n < sandbox.MaxExecSessions; n++ {
		decision, err := f.ops.AdmitOp(ctx, f.op(t, sandbox.OpExecStart, 5000+n, at, nil))
		if err != nil || !decision.Start {
			t.Fatalf("session %d: %+v %v", n, decision, err)
		}
		if err := finish(5000 + n); err != nil {
			t.Fatal(err)
		}
	}
	if decision, err := f.ops.AdmitOp(ctx, f.op(t, sandbox.OpExecStart, 9999, at, nil)); err != nil || !decision.Limited {
		t.Fatalf("session past the cap %+v %v", decision, err)
	}
}

// Admission is one transaction: if the exec record cannot be written, the
// op record is not written either.
func TestSandboxOpAdmissionIsAtomic(t *testing.T) {
	f := newOpsFixture(t)
	ctx := context.Background()
	if _, err := f.store.db.Exec(`CREATE TRIGGER inject_exec_failure BEFORE INSERT ON sandbox_execs BEGIN SELECT RAISE(ABORT, 'injected'); END`); err != nil {
		t.Fatal(err)
	}
	start := f.op(t, sandbox.OpExecStart, 1, f.clock.read(), nil)
	if _, err := f.ops.AdmitOp(ctx, start); err == nil || !strings.Contains(err.Error(), "injected") {
		t.Fatalf("admission with a failing exec insert: %v", err)
	}
	if ops, execs := opRows(t, f.store); ops != 0 || execs != 0 {
		t.Fatalf("partial admission left %d ops %d execs", ops, execs)
	}
	if _, err := f.store.db.Exec(`DROP TRIGGER inject_exec_failure`); err != nil {
		t.Fatal(err)
	}
	if decision, err := f.ops.AdmitOp(ctx, start); err != nil || !decision.Start {
		t.Fatalf("admission after the failure %+v %v", decision, err)
	}
}

// End to end with the merged protocol rule. An exec_not_found receipt built
// from a lookup whose DecidedAt is at or after the start's expires_at plus
// the skew is a definitive non-start. The store then refuses that
// exec_start for good.
func TestSandboxExecNotFoundFromTheStoreIsDefinitive(t *testing.T) {
	f := newOpsFixture(t)
	ctx := context.Background()
	at := f.clock.read()
	start := f.op(t, sandbox.OpExecStart, 1, at, nil)
	// The read was issued before the window closed; the lookup decides
	// later, and only its own time may stand as observed_at.
	read := f.op(t, sandbox.OpExecRead, 2, at.Add(40*time.Second), nil)
	decided := at.Add(30*time.Second + sandbox.IssueSkew)
	f.clock.set(decided)
	lookup, err := f.ops.LookupExec(ctx, read)
	if err != nil || lookup.Found || lookup.Unavailable != nil || !lookup.DecidedAt.Equal(decided) {
		t.Fatalf("lookup %+v %v", lookup, err)
	}
	digest, err := protocol.SandboxOpDigestV1(read)
	if err != nil {
		t.Fatal(err)
	}
	receipt := protocol.SandboxOpReceiptV1{
		DocumentDigest: digest, ErrorCode: sandboxCode("exec_not_found"), Generation: read.Generation, LeaseID: read.LeaseID,
		MinerID: read.MinerID, ObservedAt: sandboxStamp(lookup.DecidedAt), Op: read.Op, OpID: protocol.SandboxOpIDV1(read),
		SandboxID: read.SandboxID, Schema: protocol.SandboxOpReceiptSchema, SchemaVersion: 1, Stage: sandbox.OpStageRefused, Subnet: read.Subnet,
	}
	if err := protocol.SignSandboxOpReceiptV1(&receipt, f.parties.miner); err != nil {
		t.Fatal(err)
	}
	never, err := protocol.SandboxExecNeverStartedV1(receipt, read, start, f.parties.miner.Public().(ed25519.PublicKey))
	if err != nil || !never {
		t.Fatalf("store lookup did not yield a definitive non-start: %v %v", never, err)
	}
	if _, err := f.ops.AdmitOp(ctx, start); !errors.Is(err, ErrSandboxOpExpired) {
		t.Fatalf("exec_start admitted after a definitive exec_not_found: %v", err)
	}
	if _, execs := opRows(t, f.store); execs != 0 {
		t.Fatal("exec recorded after a definitive exec_not_found")
	}
}

// The store stores caller-supplied exec transitions and only guards their
// monotonicity. It never decides when or why a transition happens.
func TestSandboxExecStateIsMonotonic(t *testing.T) {
	f := newOpsFixture(t)
	ctx := context.Background()
	at := f.clock.read()
	for n := range 2 {
		if _, err := f.ops.AdmitOp(ctx, f.op(t, sandbox.OpExecStart, n+1, at, nil)); err != nil {
			t.Fatal(err)
		}
	}
	leaseID := protocol.SandboxLeaseIDV1(f.lease)
	first, second := leaseID+"-op-"+nonce(1), leaseID+"-op-"+nonce(2)
	code := sandbox.OpCodeSandboxFailed
	for index, step := range []struct {
		exec, state string
		code        *string
		wantErr     bool
	}{
		{first, sandbox.ExecStateRunning, nil, false},
		{first, sandbox.ExecStateRunning, nil, false},
		{first, sandbox.ExecStateExited, nil, false},
		{first, sandbox.ExecStateExited, nil, false},
		{first, sandbox.ExecStateRunning, nil, true},
		{first, sandbox.ExecStateTimedOut, nil, true},
		{second, sandbox.ExecStateFailed, nil, true},
		{second, sandbox.ExecStateExited, &code, true},
		{second, "admitted", nil, true},
		{second, sandbox.ExecStateFailed, &code, false},
		{second, sandbox.ExecStateCancelled, nil, true},
		{leaseID + "-op-" + nonce(3), sandbox.ExecStateRunning, nil, true},
	} {
		if err := f.ops.RecordExecState(ctx, step.exec, step.state, step.code); (err != nil) != step.wantErr {
			t.Fatalf("step %d %s: %v", index, step.state, err)
		}
	}
	lookup, err := f.ops.LookupExec(ctx, f.op(t, sandbox.OpExecRead, 2, at, nil))
	if err != nil || lookup.State != sandbox.ExecStateExited {
		t.Fatalf("recorded state %+v %v", lookup, err)
	}
}

// Rows hold digests and identities only. A path from a signed file_write
// never reaches the database file.
func TestSandboxOpRecordsHoldNoPath(t *testing.T) {
	f := newOpsFixture(t)
	ctx := context.Background()
	write := f.op(t, sandbox.OpFileWrite, 1, f.clock.read(), nil)
	if decision, err := f.ops.AdmitOp(ctx, write); err != nil || decision.Start {
		t.Fatalf("file_write %+v %v", decision, err)
	}
	if _, err := f.store.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(f.path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("secret-name-7c1f")) || bytes.Contains(raw, []byte(*write.PayloadDigest)) {
		t.Fatal("op request content beyond its digest was persisted")
	}
	if !bytes.Contains(raw, []byte(protocol.SandboxOpIDV1(write))) {
		t.Fatal("negative control: the op record itself is not in the database file")
	}
}

// SC-1: an exact replay never permits a second effect, but its answer comes
// from the lease's current state. After a release, or after a miner restart
// (lease Recover through the real lane), replaying an admitted exec_start
// must not come back as a live replay of a running exec. An equivocating
// document is still a conflict whatever the lease state.
func TestSandboxOpReplayOnLeaseThatStoppedAnswersLeaseState(t *testing.T) {
	ctx := context.Background()
	leaseID := func(f *opsFixture) string { return protocol.SandboxLeaseIDV1(f.lease) }
	for _, stop := range []struct {
		name       string
		apply      func(t *testing.T, f *opsFixture)
		wantStatus string
	}{
		{"release", func(t *testing.T, f *opsFixture) {
			if _, _, err := f.leases.Release(ctx, f.parties.release(t, 1, f.clock.read()), f.clock.read()); err != nil {
				t.Fatal(err)
			}
		}, "cleanup"},
		{"restart", func(t *testing.T, f *opsFixture) {
			if _, err := f.leases.Recover(ctx, f.clock.read()); err != nil {
				t.Fatal(err)
			}
			if err := f.leases.CompleteLeaseCleanup(ctx, leaseID(f), f.clock.read()); err != nil {
				t.Fatal(err)
			}
		}, "failed"},
	} {
		t.Run(stop.name, func(t *testing.T) {
			f := newOpsFixture(t)
			at := f.clock.read()
			start := f.op(t, sandbox.OpExecStart, 1, at, nil)
			if first, err := f.ops.AdmitOp(ctx, start); err != nil || !first.Start {
				t.Fatalf("first admission %+v %v", first, err)
			}
			f.clock.set(at.Add(5 * time.Second))
			stop.apply(t, f)
			replay, err := f.ops.AdmitOp(ctx, start)
			if err != nil || replay.Start || replay.Unavailable == nil || replay.Unavailable.Status != stop.wantStatus {
				t.Fatalf("replay after %s answered %+v %v; want the lease state %q and no start", stop.name, replay, err, stop.wantStatus)
			}
			other := f.op(t, sandbox.OpExecStart, 1, at, func(r *protocol.SandboxOpRequestV1) { r.TimeoutMS = u64p(1000) })
			if _, err := f.ops.AdmitOp(ctx, other); !errors.Is(err, ErrSandboxConflict) {
				t.Fatalf("equivocation after %s: %v", stop.name, err)
			}
			if ops, execs := opRows(t, f.store); ops != 1 || execs != 1 {
				t.Fatalf("rows after %s: %d ops %d execs", stop.name, ops, execs)
			}
		})
	}
}

// A replay on a lease that is still running but has passed its expiry also
// answers from the lease state.
func TestSandboxOpReplayPastLeaseExpiryAnswersLeaseState(t *testing.T) {
	f := newOpsFixture(t)
	ctx := context.Background()
	issued := sandboxT0.Add(10*time.Minute - 10*time.Second)
	f.clock.set(issued)
	start := f.op(t, sandbox.OpExecStart, 1, issued, nil)
	if first, err := f.ops.AdmitOp(ctx, start); err != nil || !first.Start {
		t.Fatalf("first admission %+v %v", first, err)
	}
	f.clock.set(sandboxT0.Add(10 * time.Minute))
	replay, err := f.ops.AdmitOp(ctx, start)
	if err != nil || replay.Start || replay.Unavailable == nil || replay.Unavailable.Status != "running" ||
		!replay.Unavailable.ExpiresAt.Equal(sandboxT0.Add(10*time.Minute)) {
		t.Fatalf("replay at lease expiry %+v %v", replay, err)
	}
}
