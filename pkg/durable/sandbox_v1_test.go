// SPDX-License-Identifier: AGPL-3.0-only

package durable

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/protocol"
	"github.com/misscomputer/misscomputer-subnet/pkg/sandbox"
)

var sandboxT0 = time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)

type sandboxParties struct {
	validator, miner ed25519.PrivateKey
	validatorHotkey  string
}

func newSandboxParties(seed byte, validatorHotkey string) sandboxParties {
	return sandboxParties{
		validator:       ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32)),
		miner:           ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x22}, 32)),
		validatorHotkey: validatorHotkey,
	}
}

func (p sandboxParties) binding() *protocol.StaticSubnetBindingV1 {
	pin := strings.Repeat("3a", 32)
	return &protocol.StaticSubnetBindingV1{
		Network: "test", NetUID: 24, ValidatorHotkey: p.validatorHotkey, MinerHotkey: "5Fminer",
		MinerAxonURL: "https://8.8.8.8:8091", MinerTransport: "https", MinerTLSCertificateSHA256: &pin,
		ChainBlock: 100, Epoch: 10, ExpiresAtBlock: 125,
		ValidatorServicePublicKey: hex.EncodeToString(p.validator.Public().(ed25519.PublicKey)),
		MinerServicePublicKey:     hex.EncodeToString(p.miner.Public().(ed25519.PublicKey)),
	}
}

var oneSandbox = sandbox.Resources{CPUMillis: 1000, MemoryMiB: 4096, DiskMiB: 10240, PIDs: 512}

func sandboxID(n int) string { return fmt.Sprintf("sbx-%032x", n) }

func sandboxStamp(value time.Time) string { return *protocol.StaticTime(value) }

func (p sandboxParties) reservation(t *testing.T, n int, nonce string, at time.Time) protocol.SandboxReservationV1 {
	t.Helper()
	r := protocol.SandboxReservationV1{
		Generation: 1, HoldExpiresAt: sandboxStamp(at.Add(time.Minute)), IssuedAt: sandboxStamp(at), MinerID: "5Fminer",
		ReservationNonce: nonce, Resources: oneSandbox, SandboxID: sandboxID(n), Schema: protocol.SandboxReservationSchema,
		SchemaVersion: 1, Subnet: p.binding(), WorkloadKind: sandbox.WorkloadKind,
	}
	if err := protocol.SignSandboxReservationV1(&r, p.validator); err != nil {
		t.Fatal(err)
	}
	return r
}

func (p sandboxParties) lease(t *testing.T, r protocol.SandboxReservationV1, nonce string, at time.Time, mutate func(*protocol.SandboxLeaseV1)) protocol.SandboxLeaseV1 {
	t.Helper()
	digest, err := protocol.SandboxDigestV1(r)
	if err != nil {
		t.Fatal(err)
	}
	image := "sha256:" + strings.Repeat("c4", 32)
	l := protocol.SandboxLeaseV1{
		AssignmentNonce: nonce, Env: map[string]string{}, Generation: r.Generation, ImageDigest: image,
		ImageReference: "docker.io/library/python@" + image, Isolation: sandbox.IsolationGVisor, IssuedAt: sandboxStamp(at),
		LeaseExpiresAt: sandboxStamp(at.Add(10 * time.Minute)), MinerID: r.MinerID,
		Network:           sandbox.NetworkPolicy{Mode: sandbox.NetworkNone, Allow: []string{}},
		ReservationDigest: digest, Resources: r.Resources, SandboxID: r.SandboxID, Schema: protocol.SandboxLeaseSchema, SchemaVersion: 1,
		SecretEnv: sandbox.SecretEnv{Delivery: sandbox.SecretDeliveryNone, Names: []string{}}, Subnet: p.binding(), WorkloadKind: sandbox.WorkloadKind,
	}
	if mutate != nil {
		mutate(&l)
	}
	if err := protocol.SignSandboxLeaseV1(&l, p.validator); err != nil {
		t.Fatal(err)
	}
	return l
}

func (p sandboxParties) renewal(t *testing.T, l protocol.SandboxLeaseV1, seq uint64, issued, expires time.Time) protocol.SandboxRenewalV1 {
	t.Helper()
	digest, err := protocol.SandboxDigestV1(l)
	if err != nil {
		t.Fatal(err)
	}
	r := protocol.SandboxRenewalV1{
		Generation: l.Generation, IssuedAt: sandboxStamp(issued), LeaseDigest: digest, LeaseExpiresAt: sandboxStamp(expires),
		LeaseID: protocol.SandboxLeaseIDV1(l), MinerID: l.MinerID, RenewalSeq: seq, SandboxID: l.SandboxID,
		Schema: protocol.SandboxRenewalSchema, SchemaVersion: 1, Subnet: p.binding(),
	}
	if err := protocol.SignSandboxRenewalV1(&r, p.validator); err != nil {
		t.Fatal(err)
	}
	return r
}

func (p sandboxParties) release(t *testing.T, n int, at time.Time) protocol.SandboxReleaseV1 {
	t.Helper()
	r := protocol.SandboxReleaseV1{
		Generation: 1, IssuedAt: sandboxStamp(at), MinerID: "5Fminer", Reason: sandbox.ReleaseCustomerDelete, SandboxID: sandboxID(n),
		Schema: protocol.SandboxReleaseSchema, SchemaVersion: 1, Subnet: p.binding(),
	}
	if err := protocol.SignSandboxReleaseV1(&r, p.validator); err != nil {
		t.Fatal(err)
	}
	return r
}

func nonce(n int) string { return fmt.Sprintf("%032x", n) }

func openSandboxLeases(t *testing.T) (*Store, *SandboxLeases) {
	t.Helper()
	store, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	lane, err := store.EnableSandboxLeases(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return store, lane
}

func capacityFor(sandboxes int) sandbox.Capacity {
	var total sandbox.Capacity
	for range sandboxes {
		total = total.Add(oneSandbox)
	}
	return total
}

func wantStage(t *testing.T, outcome SandboxOutcome, err error, stage string, code string) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	gotCode := ""
	if outcome.ErrorCode != nil {
		gotCode = *outcome.ErrorCode
	}
	if outcome.Stage != stage || gotCode != code {
		t.Fatalf("outcome %s/%q, want %s/%q", outcome.Stage, gotCode, stage, code)
	}
}

func schemaDump(t *testing.T, store *Store) string {
	t.Helper()
	rows, err := store.db.Query(`SELECT type,name,COALESCE(sql,'') FROM sqlite_master WHERE tbl_name NOT LIKE 'sandbox_%' ORDER BY type,name`)
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

func sandboxTables(t *testing.T, store *Store) int {
	t.Helper()
	var count int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE tbl_name LIKE 'sandbox_%'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

// The lane is off by default: Open creates no sandbox table, and enabling it
// adds only sandbox tables, leaving every deployment.v4, static and edge
// table definition byte-identical and the web path writable.
func TestSandboxLaneIsOffByDefaultAndLeavesWebTablesUnchanged(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if n := sandboxTables(t, store); n != 0 {
		t.Fatalf("Open created %d sandbox schema objects", n)
	}
	before := schemaDump(t, store)
	ctx := context.Background()
	if _, err := store.EnableSandboxLeases(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := store.EnableSandboxLeases(ctx); err != nil {
		t.Fatalf("enabling twice: %v", err)
	}
	if after := schemaDump(t, store); after != before {
		t.Fatalf("enabling the sandbox lane changed web tables:\n%s\nvs\n%s", before, after)
	}
	if err := store.SetTrust(ctx, "5Fminer", 1); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("reopen a store with sandbox tables: %v", err)
	}
	defer reopened.Close()
	if value, ok, err := reopened.Trust(ctx, "5Fminer"); err != nil || !ok || value != 1 {
		t.Fatalf("web state after reopen: %v %v %v", value, ok, err)
	}
	if schemaDump(t, reopened) != before {
		t.Fatal("reopening changed web tables")
	}
}

// Terminal identities remain durable for replay and fences. Capacity and
// expiry work must not inspect that ever-growing history on every request.
func TestSandboxLiveQueriesSkipTerminalHistory(t *testing.T) {
	store, _ := openSandboxLeases(t)
	tx, err := store.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for n := range 512 {
		id := sandboxID(n)
		if _, err := tx.Exec(`INSERT INTO sandbox_holds(hold_id,sandbox_id,generation,miner_hotkey,validator_hotkey,reservation_nonce,reservation_digest,cpu_millis,memory_mib,disk_mib,hold_expires_at_ns,status,reservation_json,updated_at_ns)
VALUES(?,?,1,'miner','validator',?,?,1,1,1,1,'committed','{}',1)`, id, id, nonce(n), "hold-"+id); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(`INSERT INTO sandbox_leases(lease_id,hold_id,sandbox_id,generation,miner_hotkey,validator_hotkey,assignment_nonce,lease_digest,cpu_millis,memory_mib,disk_mib,lease_expires_at_ns,status,lease_json,updated_at_ns)
VALUES(?,?,?,1,'miner','validator',?,?,1,1,1,1,'released','{}',1)`, id, id, id, "lease-"+id, "digest-"+id); err != nil {
			t.Fatal(err)
		}
	}
	for _, update := range []string{
		`UPDATE sandbox_holds SET status='held' WHERE hold_id='sbx-00000000000000000000000000000000'`,
		`UPDATE sandbox_leases SET status='pending' WHERE lease_id='sbx-00000000000000000000000000000001'`,
		`UPDATE sandbox_leases SET status='cleanup',cleanup_status='released' WHERE lease_id='sbx-00000000000000000000000000000002'`,
	} {
		if _, err := tx.Exec(update); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`ANALYZE`); err != nil {
		t.Fatal(err)
	}
	partialIndexes := map[string]bool{}
	for _, table := range []string{"sandbox_holds", "sandbox_leases"} {
		rows, err := store.db.Query(`PRAGMA index_list(` + table + `)`)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var seq, unique, partial int
			var name, origin string
			if err := rows.Scan(&seq, &name, &unique, &origin, &partial); err != nil {
				t.Fatal(err)
			}
			partialIndexes[name] = partial == 1
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		rows.Close()
	}
	for _, tc := range []struct {
		name, table, query string
	}{
		{"live holds", "sandbox_holds", `SELECT COUNT(*),COALESCE(SUM(cpu_millis),0),COALESCE(SUM(memory_mib),0),COALESCE(SUM(disk_mib),0) FROM sandbox_holds WHERE status='held' AND hold_expires_at_ns > 0`},
		{"live leases", "sandbox_leases", `SELECT COUNT(*),COALESCE(SUM(cpu_millis),0),COALESCE(SUM(memory_mib),0),COALESCE(SUM(disk_mib),0) FROM sandbox_leases WHERE status IN ('pending','running','cleanup')`},
		{"expired holds", "sandbox_holds", `UPDATE sandbox_holds SET status='expired' WHERE status='held' AND hold_expires_at_ns <= 1`},
		{"expired leases", "sandbox_leases", `UPDATE sandbox_leases SET status='cleanup' WHERE status IN ('pending','running') AND lease_expires_at_ns <= 1`},
		{"cleanup leases", "sandbox_leases", `SELECT lease_id,status,cleanup_status,cleanup_code,terminal_code,renewal_seq,lease_expires_at_ns,lease_json FROM sandbox_leases WHERE status='cleanup' ORDER BY lease_id`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rows, err := store.db.Query(`EXPLAIN QUERY PLAN ` + tc.query)
			if err != nil {
				t.Fatal(err)
			}
			defer rows.Close()
			var plan []string
			for rows.Next() {
				var id, parent, unused int
				var detail string
				if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
					t.Fatal(err)
				}
				plan = append(plan, detail)
			}
			if err := rows.Err(); err != nil {
				t.Fatal(err)
			}
			usesPartial := false
			for _, detail := range plan {
				if _, after, ok := strings.Cut(detail, " INDEX "); ok {
					usesPartial = partialIndexes[strings.Fields(after)[0]]
				}
				if strings.HasPrefix(tc.name, "expired") && strings.HasPrefix(detail, "SCAN "+tc.table) {
					t.Fatalf("expiry query scans rather than seeks: %v", plan)
				}
			}
			if !usesPartial {
				t.Fatalf("live query does not use a partial index: %v", plan)
			}
		})
	}
}

// Capacity is checked and held in one transaction against a resource
// budget, refused when it does not fit, and freed when the hold lapses.
func TestSandboxHoldsCountAgainstBudgetAndLapse(t *testing.T) {
	_, lane := openSandboxLeases(t)
	ctx := context.Background()
	parties := newSandboxParties(0x11, "5Hvalidator")
	budget := capacityFor(2)
	for n := 1; n <= 2; n++ {
		outcome, err := lane.Hold(ctx, parties.reservation(t, n, nonce(n), sandboxT0), budget, sandboxT0)
		wantStage(t, outcome, err, sandbox.StageHeld, "")
	}
	third := parties.reservation(t, 3, nonce(3), sandboxT0)
	outcome, err := lane.Hold(ctx, third, budget, sandboxT0)
	wantStage(t, outcome, err, sandbox.StageRefused, "capacity_exhausted")
	if outcome.Held != budget || outcome.Active != (sandbox.Capacity{}) {
		t.Fatalf("occupancy held=%+v active=%+v", outcome.Held, outcome.Active)
	}
	// A larger request is refused even with a free slot.
	big := parties.reservation(t, 4, nonce(4), sandboxT0)
	big.Resources.MemoryMiB, big.Signature = 16384, ""
	if err := protocol.SignSandboxReservationV1(&big, parties.validator); err != nil {
		t.Fatal(err)
	}
	outcome, err = lane.Hold(ctx, big, capacityFor(3), sandboxT0)
	wantStage(t, outcome, err, sandbox.StageRefused, "capacity_exhausted")
	// Unused holds lapse at hold_expires_at and free their capacity.
	later := sandboxT0.Add(time.Minute)
	outcome, err = lane.Hold(ctx, parties.reservation(t, 5, nonce(5), later.Add(-time.Second)), budget, later)
	wantStage(t, outcome, err, sandbox.StageHeld, "")
	if outcome.Held.Sandboxes != 1 {
		t.Fatalf("expired holds still count: %+v", outcome.Held)
	}
}

// Twenty concurrent reservations against three sandboxes of budget never
// overbook.
func TestSandboxConcurrentHoldsNeverOverbook(t *testing.T) {
	_, lane := openSandboxLeases(t)
	ctx := context.Background()
	parties := newSandboxParties(0x11, "5Hvalidator")
	budget := capacityFor(3)
	reservations := make([]protocol.SandboxReservationV1, 20)
	for n := range reservations {
		reservations[n] = parties.reservation(t, n+1, nonce(n+1), sandboxT0)
	}
	var wait sync.WaitGroup
	var mu sync.Mutex
	stages := map[string]int{}
	for _, reservation := range reservations {
		wait.Add(1)
		go func(r protocol.SandboxReservationV1) {
			defer wait.Done()
			outcome, err := lane.Hold(ctx, r, budget, sandboxT0)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				stages["error"]++
				return
			}
			stages[outcome.Stage]++
		}(reservation)
	}
	wait.Wait()
	if stages[sandbox.StageHeld] != 3 || stages[sandbox.StageRefused] != 17 {
		t.Fatalf("stages %v", stages)
	}
	held, _, err := lane.Occupancy(ctx, sandboxT0)
	if err != nil || held != budget {
		t.Fatalf("occupancy %+v %v", held, err)
	}
}

// Exact replays answer from durable state; any different document for an
// identity that already has one fails closed as equivocation.
func TestSandboxReplayIsIdempotentAndEquivocationFailsClosed(t *testing.T) {
	_, lane := openSandboxLeases(t)
	ctx := context.Background()
	parties := newSandboxParties(0x11, "5Hvalidator")
	budget := capacityFor(4)
	reservation := parties.reservation(t, 1, nonce(1), sandboxT0)
	for range 2 {
		outcome, err := lane.Hold(ctx, reservation, budget, sandboxT0)
		wantStage(t, outcome, err, sandbox.StageHeld, "")
	}
	if held, _, _ := lane.Occupancy(ctx, sandboxT0); held.Sandboxes != 1 {
		t.Fatalf("replay held twice: %+v", held)
	}
	if _, err := lane.Hold(ctx, parties.reservation(t, 1, nonce(9), sandboxT0), budget, sandboxT0); !errors.Is(err, ErrSandboxConflict) {
		t.Fatalf("second reservation for one identity: %v", err)
	}
	if _, err := lane.Hold(ctx, parties.reservation(t, 2, nonce(1), sandboxT0), budget, sandboxT0); !errors.Is(err, ErrSandboxConflict) {
		t.Fatalf("reused reservation nonce: %v", err)
	}
	lease := parties.lease(t, reservation, nonce(100), sandboxT0.Add(time.Second), nil)
	outcome, err := lane.CommitLease(ctx, lease, sandboxT0.Add(time.Second))
	wantStage(t, outcome, err, sandbox.StageAccepted, "")
	if !outcome.Start {
		t.Fatal("first acceptance did not ask the caller to start the runtime")
	}
	replay, err := lane.CommitLease(ctx, lease, sandboxT0.Add(2*time.Second))
	wantStage(t, replay, err, sandbox.StageAccepted, "")
	if replay.Start {
		t.Fatal("a replayed lease asked for a second runtime")
	}
	if _, err := lane.CommitLease(ctx, parties.lease(t, reservation, nonce(101), sandboxT0.Add(time.Second), nil), sandboxT0.Add(2*time.Second)); !errors.Is(err, ErrSandboxConflict) {
		t.Fatalf("second lease for one hold: %v", err)
	}
	// A lease that changes the held resources is not a commit of the hold.
	other := parties.reservation(t, 2, nonce(2), sandboxT0)
	mustHold(t, lane, other, budget, sandboxT0)
	bigger := parties.lease(t, other, nonce(102), sandboxT0.Add(time.Second), func(l *protocol.SandboxLeaseV1) { l.Resources.CPUMillis = 4000 })
	if _, err := lane.CommitLease(ctx, bigger, sandboxT0.Add(time.Second)); !errors.Is(err, ErrSandboxConflict) {
		t.Fatalf("lease with other resources: %v", err)
	}
	// Another validator cannot commit, release or renew this validator's hold.
	intruder := newSandboxParties(0x55, "5Hintruder")
	if _, err := lane.CommitLease(ctx, intruder.lease(t, other, nonce(103), sandboxT0.Add(time.Second), nil), sandboxT0.Add(time.Second)); !errors.Is(err, ErrSandboxConflict) {
		t.Fatalf("foreign validator lease: %v", err)
	}
	if _, _, err := lane.Release(ctx, intruder.release(t, 2, sandboxT0), sandboxT0); !errors.Is(err, ErrSandboxConflict) {
		t.Fatalf("foreign validator release: %v", err)
	}
}

func mustHold(t *testing.T, lane *SandboxLeases, r protocol.SandboxReservationV1, budget sandbox.Capacity, now time.Time) {
	t.Helper()
	outcome, err := lane.Hold(context.Background(), r, budget, now)
	wantStage(t, outcome, err, sandbox.StageHeld, "")
}

// A release fences its identity before or after the documents it cancels,
// for ever, and a conflicting fence fails closed.
func TestSandboxReleaseFencesIdentityForever(t *testing.T) {
	_, lane := openSandboxLeases(t)
	ctx := context.Background()
	parties := newSandboxParties(0x11, "5Hvalidator")
	budget := capacityFor(4)
	if _, teardown, err := lane.Release(ctx, parties.release(t, 1, sandboxT0), sandboxT0); err != nil || len(teardown) != 0 {
		t.Fatalf("early release: %v %v", teardown, err)
	}
	reservation := parties.reservation(t, 1, nonce(1), sandboxT0)
	outcome, err := lane.Hold(ctx, reservation, budget, sandboxT0)
	wantStage(t, outcome, err, sandbox.StageRefused, "released_before_use")
	outcome, err = lane.CommitLease(ctx, parties.lease(t, reservation, nonce(100), sandboxT0, nil), sandboxT0)
	wantStage(t, outcome, err, sandbox.StageFailed, "released_before_use")
	if outcome.Start {
		t.Fatal("a fenced lease asked for a runtime")
	}
	// Release between reserve and commit frees the hold.
	second := parties.reservation(t, 2, nonce(2), sandboxT0)
	mustHold(t, lane, second, budget, sandboxT0)
	if _, _, err := lane.Release(ctx, parties.release(t, 2, sandboxT0), sandboxT0); err != nil {
		t.Fatal(err)
	}
	if held, _, _ := lane.Occupancy(ctx, sandboxT0); held.Sandboxes != 0 {
		t.Fatalf("released hold still counts: %+v", held)
	}
	outcome, err = lane.CommitLease(ctx, parties.lease(t, second, nonce(101), sandboxT0, nil), sandboxT0)
	wantStage(t, outcome, err, sandbox.StageFailed, "released_before_use")
	intruder := newSandboxParties(0x55, "5Hintruder")
	if _, _, err := lane.Release(ctx, intruder.release(t, 1, sandboxT0), sandboxT0); !errors.Is(err, ErrSandboxConflict) {
		t.Fatalf("another validator's fence: %v", err)
	}
	if _, err := lane.Hold(ctx, intruder.reservation(t, 1, nonce(3), sandboxT0), budget, sandboxT0); !errors.Is(err, ErrSandboxConflict) {
		t.Fatalf("another validator's reservation of a fenced identity: %v", err)
	}
}

// The full lifecycle: commit is write-ahead, renewals are strictly
// monotonic, release tears down, and capacity is held until the runtime is
// gone.
func TestSandboxLeaseLifecycle(t *testing.T) {
	_, lane := openSandboxLeases(t)
	ctx := context.Background()
	parties := newSandboxParties(0x11, "5Hvalidator")
	budget := capacityFor(1)
	reservation := parties.reservation(t, 1, nonce(1), sandboxT0)
	mustHold(t, lane, reservation, budget, sandboxT0)
	at := sandboxT0.Add(5 * time.Second)
	lease := parties.lease(t, reservation, nonce(100), at, nil)
	outcome, err := lane.CommitLease(ctx, lease, at)
	wantStage(t, outcome, err, sandbox.StageAccepted, "")
	leaseID := protocol.SandboxLeaseIDV1(lease)
	if outcome.LeaseID == nil || *outcome.LeaseID != leaseID || outcome.Held.Sandboxes != 0 || outcome.Active.Sandboxes != 1 {
		t.Fatalf("commit outcome %+v", outcome)
	}
	record, ok, err := lane.Lease(ctx, leaseID)
	if err != nil || !ok || record.Status != "pending" {
		t.Fatalf("write-ahead record %+v %v %v", record, ok, err)
	}
	if running, err := lane.MarkLeaseRunning(ctx, leaseID, at); err != nil || !running {
		t.Fatalf("mark running: %v %v", running, err)
	}
	renewal := parties.renewal(t, lease, 1, at.Add(5*time.Minute), at.Add(15*time.Minute))
	outcome, err = lane.Renew(ctx, renewal, at.Add(5*time.Minute))
	wantStage(t, outcome, err, sandbox.StageReady, "")
	if outcome.RenewalSeq != 1 {
		t.Fatalf("renewal seq %d", outcome.RenewalSeq)
	}
	if outcome, err := lane.Renew(ctx, renewal, at.Add(6*time.Minute)); err != nil || outcome.RenewalSeq != 1 {
		t.Fatalf("exact renewal replay: %+v %v", outcome, err)
	}
	if _, err := lane.Renew(ctx, parties.renewal(t, lease, 1, at.Add(5*time.Minute), at.Add(16*time.Minute)), at.Add(6*time.Minute)); !errors.Is(err, ErrSandboxConflict) {
		t.Fatalf("different renewal with the same sequence: %v", err)
	}
	if _, err := lane.Renew(ctx, parties.renewal(t, lease, 2, at.Add(time.Minute), at.Add(11*time.Minute)), at.Add(6*time.Minute)); err == nil {
		t.Fatal("a renewal that shortens the lease was applied")
	}
	// The lease outlives its original expiry because it was renewed.
	if teardown, err := lane.Sweep(ctx, at.Add(11*time.Minute)); err != nil || len(teardown) != 0 {
		t.Fatalf("sweep of a renewed lease: %v %v", teardown, err)
	}
	outcome, teardown, err := lane.Release(ctx, parties.release(t, 1, at.Add(12*time.Minute)), at.Add(12*time.Minute))
	wantStage(t, outcome, err, sandbox.StageReleased, "")
	if len(teardown) != 1 || teardown[0].LeaseID != leaseID || teardown[0].Status != "cleanup" {
		t.Fatalf("release teardown %+v", teardown)
	}
	// Until the runtime is confirmed gone the capacity stays consumed.
	refused := parties.reservation(t, 2, nonce(2), at.Add(12*time.Minute))
	outcome, err = lane.Hold(ctx, refused, budget, at.Add(12*time.Minute))
	wantStage(t, outcome, err, sandbox.StageRefused, "capacity_exhausted")
	if err := lane.CompleteLeaseCleanup(ctx, leaseID, at.Add(12*time.Minute)); err != nil {
		t.Fatal(err)
	}
	outcome, err = lane.CommitLease(ctx, lease, at.Add(12*time.Minute))
	wantStage(t, outcome, err, sandbox.StageReleased, "")
	if _, active, _ := lane.Occupancy(ctx, at.Add(12*time.Minute)); active.Sandboxes != 0 {
		t.Fatalf("released lease still counts: %+v", active)
	}
}

// An unrenewed lease is torn down after its expiry plus Grace, never
// before, and a failed stop keeps its capacity until a retry succeeds.
func TestUnrenewedSandboxLeaseExpiresAfterGrace(t *testing.T) {
	_, lane := openSandboxLeases(t)
	ctx := context.Background()
	parties := newSandboxParties(0x11, "5Hvalidator")
	reservation := parties.reservation(t, 1, nonce(1), sandboxT0)
	mustHold(t, lane, reservation, capacityFor(1), sandboxT0)
	lease := parties.lease(t, reservation, nonce(100), sandboxT0, nil)
	if _, err := lane.CommitLease(ctx, lease, sandboxT0); err != nil {
		t.Fatal(err)
	}
	leaseID := protocol.SandboxLeaseIDV1(lease)
	if _, err := lane.MarkLeaseRunning(ctx, leaseID, sandboxT0); err != nil {
		t.Fatal(err)
	}
	expiry := sandboxT0.Add(10 * time.Minute)
	if teardown, err := lane.Sweep(ctx, expiry.Add(sandbox.Grace-time.Nanosecond)); err != nil || len(teardown) != 0 {
		t.Fatalf("swept inside grace: %v %v", teardown, err)
	}
	if outcome, err := lane.Renew(ctx, parties.renewal(t, lease, 1, expiry.Add(-time.Minute), expiry.Add(5*time.Minute)), expiry.Add(time.Second)); err != nil || outcome.Stage != sandbox.StageExpired {
		t.Fatalf("late renewal: %+v %v", outcome, err)
	}
	teardown, err := lane.Sweep(ctx, expiry.Add(sandbox.Grace))
	if err != nil || len(teardown) != 1 || *teardown[0].CleanupStatus != "expired" {
		t.Fatalf("sweep after grace: %+v %v", teardown, err)
	}
	// The stop failed: the next sweep returns it again and it still counts.
	teardown, err = lane.Sweep(ctx, expiry.Add(time.Hour))
	if err != nil || len(teardown) != 1 {
		t.Fatalf("retry after failed stop: %+v %v", teardown, err)
	}
	if _, active, _ := lane.Occupancy(ctx, expiry.Add(time.Hour)); active.Sandboxes != 1 {
		t.Fatalf("cleanup lease freed capacity before stop: %+v", active)
	}
	if err := lane.CompleteLeaseCleanup(ctx, leaseID, expiry.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	outcome, err := lane.CommitLease(ctx, lease, expiry.Add(time.Hour))
	wantStage(t, outcome, err, sandbox.StageExpired, "")
}

// A renewal that sampled the clock before expiry must not revive a lease
// after startup has atomically chosen expiry and begun teardown.
func TestSandboxStartupExpiryFencesInFlightRenewal(t *testing.T) {
	_, lane := openSandboxLeases(t)
	ctx := context.Background()
	parties := newSandboxParties(0x11, "5Hvalidator")
	reservation := parties.reservation(t, 1, nonce(1), sandboxT0)
	mustHold(t, lane, reservation, capacityFor(1), sandboxT0)
	lease := parties.lease(t, reservation, nonce(100), sandboxT0, nil)
	if _, err := lane.CommitLease(ctx, lease, sandboxT0); err != nil {
		t.Fatal(err)
	}
	leaseID := protocol.SandboxLeaseIDV1(lease)
	expiry := sandboxT0.Add(10 * time.Minute)
	if running, err := lane.MarkLeaseRunning(ctx, leaseID, expiry); err != nil || running {
		t.Fatalf("expired startup became running: %v %v", running, err)
	}
	// Renew's timestamp can precede the startup transition even if its store
	// transaction commits after it. The durable expiry fence must win.
	renewal := parties.renewal(t, lease, 1, expiry.Add(-time.Second), expiry.Add(5*time.Minute))
	outcome, err := lane.Renew(ctx, renewal, expiry.Add(-time.Nanosecond))
	wantStage(t, outcome, err, sandbox.StageExpired, "")
}

// Restart recovery tears down every lease whose runtime may exist,
// including one that crashed between the write-ahead row and the runtime
// start, with the attributable miner_restart code. A release that wins the
// race against a starting runtime makes MarkLeaseRunning report it.
func TestSandboxRecoveryAndStartRace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	lane, err := store.EnableSandboxLeases(ctx)
	if err != nil {
		t.Fatal(err)
	}
	parties := newSandboxParties(0x11, "5Hvalidator")
	budget := capacityFor(3)
	var leases []protocol.SandboxLeaseV1
	for n := 1; n <= 3; n++ {
		reservation := parties.reservation(t, n, nonce(n), sandboxT0)
		mustHold(t, lane, reservation, budget, sandboxT0)
		lease := parties.lease(t, reservation, nonce(100+n), sandboxT0, nil)
		if _, err := lane.CommitLease(ctx, lease, sandboxT0); err != nil {
			t.Fatal(err)
		}
		leases = append(leases, lease)
	}
	running := protocol.SandboxLeaseIDV1(leases[0])
	if ok, err := lane.MarkLeaseRunning(ctx, running, sandboxT0); err != nil || !ok {
		t.Fatal("mark running", err)
	}
	// Lease 2 is released while its runtime is starting.
	starting := protocol.SandboxLeaseIDV1(leases[1])
	if _, _, err := lane.Release(ctx, parties.release(t, 2, sandboxT0), sandboxT0); err != nil {
		t.Fatal(err)
	}
	if ok, err := lane.MarkLeaseRunning(ctx, starting, sandboxT0); err != nil || ok {
		t.Fatalf("a released lease became running: %v %v", ok, err)
	}
	// Crash: lease 3 is still pending. Reopen and recover.
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if lane, err = store.EnableSandboxLeases(ctx); err != nil {
		t.Fatal(err)
	}
	teardown, err := lane.Recover(ctx, sandboxT0.Add(time.Minute))
	if err != nil || len(teardown) != 3 {
		t.Fatalf("recovery teardown %+v %v", teardown, err)
	}
	for _, record := range teardown {
		if err := lane.CompleteLeaseCleanup(ctx, record.LeaseID, sandboxT0.Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	outcome, err := lane.CommitLease(ctx, leases[0], sandboxT0.Add(time.Minute))
	wantStage(t, outcome, err, sandbox.StageFailed, "miner_restart")
	outcome, err = lane.CommitLease(ctx, leases[2], sandboxT0.Add(time.Minute))
	wantStage(t, outcome, err, sandbox.StageFailed, "miner_restart")
	outcome, err = lane.CommitLease(ctx, leases[1], sandboxT0.Add(time.Minute))
	wantStage(t, outcome, err, sandbox.StageReleased, "")
	if held, active, _ := lane.Occupancy(ctx, sandboxT0.Add(time.Minute)); held.Sandboxes != 0 || active.Sandboxes != 0 {
		t.Fatalf("capacity after recovery held=%+v active=%+v", held, active)
	}
}

// A lease that arrives after its hold lapsed starts nothing.
func TestSandboxLeaseAfterHoldExpiryStartsNothing(t *testing.T) {
	_, lane := openSandboxLeases(t)
	ctx := context.Background()
	parties := newSandboxParties(0x11, "5Hvalidator")
	reservation := parties.reservation(t, 1, nonce(1), sandboxT0)
	mustHold(t, lane, reservation, capacityFor(1), sandboxT0)
	late := sandboxT0.Add(time.Minute)
	outcome, err := lane.CommitLease(ctx, parties.lease(t, reservation, nonce(100), late, nil), late)
	wantStage(t, outcome, err, sandbox.StageFailed, "hold_expired")
	if outcome.Start || outcome.Active.Sandboxes != 0 {
		t.Fatalf("expired hold produced a runtime: %+v", outcome)
	}
	outcome, err = lane.CommitLease(ctx, parties.lease(t, parties.reservation(t, 2, nonce(2), sandboxT0), nonce(101), sandboxT0, nil), sandboxT0)
	wantStage(t, outcome, err, sandbox.StageFailed, "hold_expired")
}

// A runtime that fails to start keeps its capacity until cleanup completes
// and then answers failed with the attributable runtime_start_failed code.
func TestSandboxFailedStartIsCleanedUpAndAttributed(t *testing.T) {
	_, lane := openSandboxLeases(t)
	ctx := context.Background()
	parties := newSandboxParties(0x11, "5Hvalidator")
	reservation := parties.reservation(t, 1, nonce(1), sandboxT0)
	mustHold(t, lane, reservation, capacityFor(1), sandboxT0)
	lease := parties.lease(t, reservation, nonce(100), sandboxT0, nil)
	if _, err := lane.CommitLease(ctx, lease, sandboxT0); err != nil {
		t.Fatal(err)
	}
	leaseID := protocol.SandboxLeaseIDV1(lease)
	if lane.BeginLeaseCleanup(ctx, leaseID, "failed", nil, sandboxT0) == nil ||
		lane.BeginLeaseCleanup(ctx, leaseID, "released", sandboxCode("miner_restart"), sandboxT0) == nil ||
		lane.BeginLeaseCleanup(ctx, leaseID, "running", nil, sandboxT0) == nil {
		t.Fatal("an invalid cleanup intent was accepted")
	}
	if err := lane.BeginLeaseCleanup(ctx, leaseID, "failed", sandboxCode("runtime_start_failed"), sandboxT0); err != nil {
		t.Fatal(err)
	}
	// A later release does not overwrite the first intent.
	if _, _, err := lane.Release(ctx, parties.release(t, 1, sandboxT0), sandboxT0); err != nil {
		t.Fatal(err)
	}
	outcome, err := lane.CommitLease(ctx, lease, sandboxT0)
	wantStage(t, outcome, err, sandbox.StageFailed, "runtime_start_failed")
	if outcome.Active.Sandboxes != 1 {
		t.Fatalf("a lease in cleanup freed capacity: %+v", outcome.Active)
	}
	if err := lane.CompleteLeaseCleanup(ctx, leaseID, sandboxT0); err != nil {
		t.Fatal(err)
	}
	record, _, err := lane.Lease(ctx, leaseID)
	if err != nil || record.Status != "failed" || record.TerminalCode == nil || *record.TerminalCode != "runtime_start_failed" {
		t.Fatalf("terminal record %+v %v", record, err)
	}
}
