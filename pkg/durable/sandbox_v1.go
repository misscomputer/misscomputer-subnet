// SPDX-License-Identifier: AGPL-3.0-only

package durable

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/protocol"
	"github.com/misscomputer/misscomputer-subnet/pkg/sandbox"
)

// The sandbox-lease-v1 lane keeps its own tables. They are deliberately not
// registered in schemaExtensions: Open never creates them, so a store whose
// owner has not enabled the lane is byte-identical to one built without
// it. The deployment.v4 and static tables, their fences and their recovery
// queries never see a sandbox document.
const sandboxLeaseSchema = `
CREATE TABLE IF NOT EXISTS sandbox_holds (
  hold_id TEXT PRIMARY KEY,
  sandbox_id TEXT NOT NULL,
  generation INTEGER NOT NULL,
  miner_hotkey TEXT NOT NULL,
  validator_hotkey TEXT NOT NULL,
  reservation_nonce TEXT NOT NULL UNIQUE,
  reservation_digest TEXT NOT NULL UNIQUE,
  cpu_millis INTEGER NOT NULL,
  memory_mib INTEGER NOT NULL,
  disk_mib INTEGER NOT NULL,
  hold_expires_at_ns INTEGER NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('held','committed','released','expired')),
  reservation_json BLOB NOT NULL,
  updated_at_ns INTEGER NOT NULL,
  UNIQUE(sandbox_id, generation, miner_hotkey)
);
CREATE TABLE IF NOT EXISTS sandbox_leases (
  lease_id TEXT PRIMARY KEY,
  hold_id TEXT NOT NULL UNIQUE REFERENCES sandbox_holds(hold_id),
  sandbox_id TEXT NOT NULL,
  generation INTEGER NOT NULL,
  miner_hotkey TEXT NOT NULL,
  validator_hotkey TEXT NOT NULL,
  assignment_nonce TEXT NOT NULL UNIQUE,
  lease_digest TEXT NOT NULL UNIQUE,
  cpu_millis INTEGER NOT NULL,
  memory_mib INTEGER NOT NULL,
  disk_mib INTEGER NOT NULL,
  lease_expires_at_ns INTEGER NOT NULL,
  renewal_seq INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL CHECK(status IN ('pending','running','cleanup','failed','released','expired')),
  cleanup_status TEXT CHECK(cleanup_status IS NULL OR cleanup_status IN ('failed','released','expired')),
  cleanup_code TEXT,
  terminal_code TEXT,
  lease_json BLOB NOT NULL,
  renewal_json BLOB,
  updated_at_ns INTEGER NOT NULL,
  UNIQUE(sandbox_id, generation, miner_hotkey)
);
CREATE TABLE IF NOT EXISTS sandbox_release_fences (
  sandbox_id TEXT NOT NULL,
  generation INTEGER NOT NULL,
  miner_hotkey TEXT NOT NULL,
  validator_hotkey TEXT NOT NULL,
  release_json BLOB NOT NULL,
  updated_at_ns INTEGER NOT NULL,
  PRIMARY KEY(sandbox_id, generation, miner_hotkey)
);
-- Only live rows contribute to capacity. Terminal rows remain durable for
-- replay and release fences, but do not grow these occupancy scans.
CREATE INDEX IF NOT EXISTS sandbox_holds_live_expiry ON sandbox_holds(hold_expires_at_ns, cpu_millis, memory_mib, disk_mib) WHERE status='held';
CREATE INDEX IF NOT EXISTS sandbox_leases_live_capacity ON sandbox_leases(cpu_millis, memory_mib, disk_mib) WHERE status IN ('pending','running','cleanup');
-- Sweep needs the expiry range only for leases that can still be running.
CREATE INDEX IF NOT EXISTS sandbox_leases_live_expiry ON sandbox_leases(lease_expires_at_ns) WHERE status IN ('pending','running');
-- Failed teardown keeps cleanup rows live until the runtime is gone.
CREATE INDEX IF NOT EXISTS sandbox_leases_cleanup ON sandbox_leases(lease_id) WHERE status='cleanup';`

// ErrSandboxConflict reports signer equivocation: a different exact
// document for an identity that already has one, a second lease for one
// hold, or another validator's document for the identity. It fails closed
// and produces no receipt.
var ErrSandboxConflict = errors.New("sandbox identity conflicts with another exact document")

// SandboxLeases is the miner-side durable sandbox-lease-v1 state. Callers
// pass only documents that passed the matching VerifyBoundSandbox*V1
// admission check; the store re-validates their shape, not their signature.
type SandboxLeases struct{ db *sql.DB }

// EnableSandboxLeases creates the sandbox tables in this store, if absent,
// and returns the lane. It is the only path that creates them.
func (s *Store) EnableSandboxLeases(ctx context.Context) (*SandboxLeases, error) {
	if _, err := s.db.ExecContext(ctx, sandboxLeaseSchema); err != nil {
		return nil, fmt.Errorf("migrate sandbox lease tables: %w", err)
	}
	return &SandboxLeases{db: s.db}, nil
}

// SandboxOutcome is the durable answer to one validator document, the
// content of the receipt the miner signs.
type SandboxOutcome struct {
	Stage      string
	ErrorCode  *string
	LeaseID    *string
	RenewalSeq uint64
	Held       sandbox.Capacity
	Active     sandbox.Capacity
	// Start is true only on the first acceptance of a lease: the lease is
	// durable as pending and the caller must now create its runtime.
	Start bool
}

// SandboxLeaseRecord is one durable lease.
type SandboxLeaseRecord struct {
	LeaseID        string
	Status         string
	CleanupStatus  *string
	CleanupCode    *string
	TerminalCode   *string
	RenewalSeq     uint64
	LeaseExpiresAt time.Time
	Lease          protocol.SandboxLeaseV1
}

func sandboxValidator(subnet *protocol.StaticSubnetBindingV1) string {
	if subnet == nil {
		return ""
	}
	return subnet.ValidatorHotkey
}

func sandboxCode(value string) *string { return &value }

func sandboxTime(value string) time.Time {
	parsed, _ := time.Parse(time.RFC3339Nano, value)
	return parsed
}

// sandboxFencedTx reports whether the identity has a release fence. A fence
// by another validator is a conflict.
func sandboxFencedTx(ctx context.Context, tx *sql.Tx, sandboxID string, generation uint64, minerHotkey, validatorHotkey string) (bool, error) {
	var fencedBy string
	err := tx.QueryRowContext(ctx, `SELECT validator_hotkey FROM sandbox_release_fences WHERE sandbox_id=? AND generation=? AND miner_hotkey=?`,
		sandboxID, generation, minerHotkey).Scan(&fencedBy)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return false, nil
	case err != nil:
		return false, err
	case fencedBy != validatorHotkey:
		return false, ErrSandboxConflict
	}
	return true, nil
}

func sandboxSum(ctx context.Context, tx *sql.Tx, query string, args ...any) (sandbox.Capacity, error) {
	var total sandbox.Capacity
	err := tx.QueryRowContext(ctx, query, args...).Scan(&total.Sandboxes, &total.CPUMillis, &total.MemoryMiB, &total.DiskMiB)
	return total, err
}

// sandboxOccupancyTx is the capacity consumed at now: unexpired holds plus
// every lease whose runtime may still exist (pending, running, cleanup). A
// lease in cleanup keeps its capacity until its runtime is gone.
func sandboxOccupancyTx(ctx context.Context, tx *sql.Tx, now time.Time) (held, active sandbox.Capacity, err error) {
	const columns = `COUNT(*),COALESCE(SUM(cpu_millis),0),COALESCE(SUM(memory_mib),0),COALESCE(SUM(disk_mib),0)`
	if held, err = sandboxSum(ctx, tx, `SELECT `+columns+` FROM sandbox_holds WHERE status='held' AND hold_expires_at_ns > ?`, now.UnixNano()); err != nil {
		return
	}
	active, err = sandboxSum(ctx, tx, `SELECT `+columns+` FROM sandbox_leases WHERE status IN ('pending','running','cleanup')`)
	return
}

func (l *SandboxLeases) finish(ctx context.Context, tx *sql.Tx, now time.Time, outcome SandboxOutcome) (SandboxOutcome, error) {
	held, active, err := sandboxOccupancyTx(ctx, tx, now)
	if err != nil {
		return SandboxOutcome{}, err
	}
	if err := tx.Commit(); err != nil {
		return SandboxOutcome{}, err
	}
	outcome.Held, outcome.Active = held, active
	return outcome, nil
}

// Hold checks capacity and durably holds it for one reservation in one
// transaction. An exact replay returns the durable answer again; a
// different reservation for the same identity is ErrSandboxConflict.
func (l *SandboxLeases) Hold(ctx context.Context, r protocol.SandboxReservationV1, budget sandbox.Capacity, now time.Time) (SandboxOutcome, error) {
	if err := r.Validate(); err != nil {
		return SandboxOutcome{}, err
	}
	digest, err := protocol.SandboxDigestV1(r)
	if err != nil {
		return SandboxOutcome{}, err
	}
	payload, err := json.Marshal(r)
	if err != nil {
		return SandboxOutcome{}, err
	}
	expires := sandboxTime(r.HoldExpiresAt)
	tx, err := l.db.BeginTx(ctx, nil)
	if err != nil {
		return SandboxOutcome{}, err
	}
	defer tx.Rollback()
	refused := func(code string) (SandboxOutcome, error) {
		return l.finish(ctx, tx, now, SandboxOutcome{Stage: sandbox.StageRefused, ErrorCode: sandboxCode(code)})
	}
	fenced, err := sandboxFencedTx(ctx, tx, r.SandboxID, r.Generation, r.MinerID, sandboxValidator(r.Subnet))
	if err != nil {
		return SandboxOutcome{}, err
	}
	if fenced {
		return refused("released_before_use")
	}
	var existingDigest, status string
	var existingExpires int64
	err = tx.QueryRowContext(ctx, `SELECT reservation_digest,status,hold_expires_at_ns FROM sandbox_holds WHERE sandbox_id=? AND generation=? AND miner_hotkey=?`,
		r.SandboxID, r.Generation, r.MinerID).Scan(&existingDigest, &status, &existingExpires)
	switch {
	case err == nil && existingDigest != digest:
		return SandboxOutcome{}, ErrSandboxConflict
	case err == nil && (status == "committed" || status == "held" && now.UnixNano() < existingExpires):
		return l.finish(ctx, tx, now, SandboxOutcome{Stage: sandbox.StageHeld})
	case err == nil && status == "released":
		return refused("released_before_use")
	case err == nil:
		if _, err := tx.ExecContext(ctx, `UPDATE sandbox_holds SET status='expired',updated_at_ns=? WHERE hold_id=? AND status='held'`,
			now.UnixNano(), protocol.SandboxHoldIDV1(r)); err != nil {
			return SandboxOutcome{}, err
		}
		return refused("hold_expired")
	case !errors.Is(err, sql.ErrNoRows):
		return SandboxOutcome{}, err
	}
	if !now.Before(expires) {
		return refused("hold_expired")
	}
	held, active, err := sandboxOccupancyTx(ctx, tx, now)
	if err != nil {
		return SandboxOutcome{}, err
	}
	if !held.Plus(active).Add(r.Resources).Within(budget) {
		return refused("capacity_exhausted")
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO sandbox_holds(hold_id,sandbox_id,generation,miner_hotkey,validator_hotkey,reservation_nonce,reservation_digest,cpu_millis,memory_mib,disk_mib,hold_expires_at_ns,status,reservation_json,updated_at_ns)
VALUES(?,?,?,?,?,?,?,?,?,?,?,'held',?,?)`, protocol.SandboxHoldIDV1(r), r.SandboxID, r.Generation, r.MinerID, sandboxValidator(r.Subnet), r.ReservationNonce,
		digest, r.Resources.CPUMillis, r.Resources.MemoryMiB, r.Resources.DiskMiB, expires.UnixNano(), payload, now.UnixNano()); err != nil {
		if isConstraint(err) {
			return SandboxOutcome{}, ErrSandboxConflict
		}
		return SandboxOutcome{}, err
	}
	return l.finish(ctx, tx, now, SandboxOutcome{Stage: sandbox.StageHeld})
}

// sandboxLeaseStage maps a durable lease status to the receipt stage that
// answers a lease or renewal for it.
func sandboxLeaseStage(status string, cleanupStatus, cleanupCode, terminalCode *string) (string, *string) {
	switch status {
	case "pending":
		return sandbox.StageAccepted, nil
	case "running":
		return sandbox.StageReady, nil
	case "cleanup":
		if cleanupStatus != nil {
			return sandboxLeaseStage(*cleanupStatus, nil, nil, cleanupCode)
		}
	case "failed":
		if terminalCode != nil {
			return sandbox.StageFailed, terminalCode
		}
		return sandbox.StageFailed, sandboxCode("runtime_start_failed")
	case "released":
		return sandbox.StageReleased, nil
	case "expired":
		return sandbox.StageExpired, nil
	}
	return sandbox.StageFailed, sandboxCode("runtime_start_failed")
}

// CommitLease converts the exact live hold a lease commits into a pending
// lease, write-ahead of any runtime object: the lease identity, and so its
// deterministic runtime name, is durable before the caller may start it.
func (l *SandboxLeases) CommitLease(ctx context.Context, lease protocol.SandboxLeaseV1, now time.Time) (SandboxOutcome, error) {
	if err := lease.Validate(); err != nil {
		return SandboxOutcome{}, err
	}
	digest, err := protocol.SandboxDigestV1(lease)
	if err != nil {
		return SandboxOutcome{}, err
	}
	payload, err := json.Marshal(lease)
	if err != nil {
		return SandboxOutcome{}, err
	}
	leaseID := protocol.SandboxLeaseIDV1(lease)
	validator := sandboxValidator(lease.Subnet)
	tx, err := l.db.BeginTx(ctx, nil)
	if err != nil {
		return SandboxOutcome{}, err
	}
	defer tx.Rollback()
	failed := func(code string) (SandboxOutcome, error) {
		return l.finish(ctx, tx, now, SandboxOutcome{Stage: sandbox.StageFailed, ErrorCode: sandboxCode(code), LeaseID: &leaseID})
	}
	var existingID, existingDigest, status string
	var cleanupStatus, cleanupCode, terminalCode *string
	var seq uint64
	err = tx.QueryRowContext(ctx, `SELECT lease_id,lease_digest,status,cleanup_status,cleanup_code,terminal_code,renewal_seq FROM sandbox_leases WHERE sandbox_id=? AND generation=? AND miner_hotkey=?`,
		lease.SandboxID, lease.Generation, lease.MinerID).Scan(&existingID, &existingDigest, &status, &cleanupStatus, &cleanupCode, &terminalCode, &seq)
	switch {
	case err == nil && (existingID != leaseID || existingDigest != digest):
		return SandboxOutcome{}, ErrSandboxConflict
	case err == nil:
		stage, code := sandboxLeaseStage(status, cleanupStatus, cleanupCode, terminalCode)
		return l.finish(ctx, tx, now, SandboxOutcome{Stage: stage, ErrorCode: code, LeaseID: &leaseID, RenewalSeq: seq})
	case !errors.Is(err, sql.ErrNoRows):
		return SandboxOutcome{}, err
	}
	fenced, err := sandboxFencedTx(ctx, tx, lease.SandboxID, lease.Generation, lease.MinerID, validator)
	if err != nil {
		return SandboxOutcome{}, err
	}
	if fenced {
		return failed("released_before_use")
	}
	var holdID, holdStatus string
	var holdExpires int64
	var reservationJSON []byte
	err = tx.QueryRowContext(ctx, `SELECT hold_id,status,hold_expires_at_ns,reservation_json FROM sandbox_holds WHERE sandbox_id=? AND generation=? AND miner_hotkey=?`,
		lease.SandboxID, lease.Generation, lease.MinerID).Scan(&holdID, &holdStatus, &holdExpires, &reservationJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return failed("hold_expired")
	}
	if err != nil {
		return SandboxOutcome{}, err
	}
	var reservation protocol.SandboxReservationV1
	if err := json.Unmarshal(reservationJSON, &reservation); err != nil {
		return SandboxOutcome{}, fmt.Errorf("decode sandbox reservation: %w", err)
	}
	// A committed hold already has its lease row, matched above by identity.
	if err := protocol.SandboxLeaseCommitsReservationV1(reservation, lease); err != nil {
		return SandboxOutcome{}, ErrSandboxConflict
	}
	switch {
	case holdStatus == "released":
		return failed("released_before_use")
	case holdStatus == "expired":
		return failed("hold_expired")
	case now.UnixNano() >= holdExpires:
		if _, err := tx.ExecContext(ctx, `UPDATE sandbox_holds SET status='expired',updated_at_ns=? WHERE hold_id=?`, now.UnixNano(), holdID); err != nil {
			return SandboxOutcome{}, err
		}
		return failed("hold_expired")
	}
	expires := sandboxTime(lease.LeaseExpiresAt)
	if !now.Before(expires) {
		return failed("lease_expired")
	}
	if _, err := tx.ExecContext(ctx, `UPDATE sandbox_holds SET status='committed',updated_at_ns=? WHERE hold_id=? AND status='held'`, now.UnixNano(), holdID); err != nil {
		return SandboxOutcome{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO sandbox_leases(lease_id,hold_id,sandbox_id,generation,miner_hotkey,validator_hotkey,assignment_nonce,lease_digest,cpu_millis,memory_mib,disk_mib,lease_expires_at_ns,status,lease_json,updated_at_ns)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,'pending',?,?)`, leaseID, holdID, lease.SandboxID, lease.Generation, lease.MinerID, validator, lease.AssignmentNonce, digest,
		lease.Resources.CPUMillis, lease.Resources.MemoryMiB, lease.Resources.DiskMiB, expires.UnixNano(), payload, now.UnixNano()); err != nil {
		if isConstraint(err) {
			return SandboxOutcome{}, ErrSandboxConflict
		}
		return SandboxOutcome{}, err
	}
	return l.finish(ctx, tx, now, SandboxOutcome{Stage: sandbox.StageAccepted, LeaseID: &leaseID, Start: true})
}

// MarkLeaseRunning records that the runtime of a pending lease started. It
// returns false when a release, expiry or restart moved the lease first; the
// caller must then tear the runtime down.
func (l *SandboxLeases) MarkLeaseRunning(ctx context.Context, leaseID string, now time.Time) (bool, error) {
	result, err := l.db.ExecContext(ctx, `UPDATE sandbox_leases SET status='running',updated_at_ns=? WHERE lease_id=? AND status='pending'`, now.UnixNano(), leaseID)
	if err != nil {
		return false, err
	}
	rows, err := result.RowsAffected()
	return rows == 1, err
}

// BeginLeaseCleanup moves a pending or running lease to cleanup with the
// terminal status (failed, released or expired) it reaches once its runtime
// is gone. A lease already in cleanup keeps its first intent.
func (l *SandboxLeases) BeginLeaseCleanup(ctx context.Context, leaseID, terminal string, code *string, now time.Time) error {
	switch terminal {
	case "failed":
		if code == nil {
			return errors.New("a failed sandbox lease needs an error code")
		}
		if _, known := sandbox.ReceiptErrorAttribution[*code]; !known {
			return errors.New("sandbox lease error code is unknown")
		}
	case "released", "expired":
		if code != nil {
			return errors.New("only a failed sandbox lease carries an error code")
		}
	default:
		return errors.New("sandbox lease terminal status is invalid")
	}
	_, err := l.db.ExecContext(ctx, `UPDATE sandbox_leases SET status='cleanup',cleanup_status=?,cleanup_code=?,updated_at_ns=? WHERE lease_id=? AND status IN ('pending','running')`,
		terminal, code, now.UnixNano(), leaseID)
	return err
}

// CompleteLeaseCleanup closes a lease in cleanup after its runtime is
// gone. Until then the lease keeps its capacity: a failed stop never frees
// a slot.
func (l *SandboxLeases) CompleteLeaseCleanup(ctx context.Context, leaseID string, now time.Time) error {
	_, err := l.db.ExecContext(ctx, `UPDATE sandbox_leases SET status=cleanup_status,terminal_code=cleanup_code,updated_at_ns=? WHERE lease_id=? AND status='cleanup'`,
		now.UnixNano(), leaseID)
	return err
}

// Renew applies a strictly newer renewal of a live lease. An exact replay
// of the latest renewal answers again; a different renewal with the same
// sequence is ErrSandboxConflict. A lease that is no longer live answers
// with its durable stage and is not extended.
func (l *SandboxLeases) Renew(ctx context.Context, r protocol.SandboxRenewalV1, now time.Time) (SandboxOutcome, error) {
	if err := r.Validate(); err != nil {
		return SandboxOutcome{}, err
	}
	payload, err := json.Marshal(r)
	if err != nil {
		return SandboxOutcome{}, err
	}
	tx, err := l.db.BeginTx(ctx, nil)
	if err != nil {
		return SandboxOutcome{}, err
	}
	defer tx.Rollback()
	var digest, sandboxID, minerHotkey, validatorHotkey, status string
	var cleanupStatus, cleanupCode, terminalCode *string
	var generation, seq uint64
	var current int64
	var latest []byte
	if err := tx.QueryRowContext(ctx, `SELECT lease_digest,sandbox_id,generation,miner_hotkey,validator_hotkey,status,cleanup_status,cleanup_code,terminal_code,renewal_seq,lease_expires_at_ns,renewal_json FROM sandbox_leases WHERE lease_id=?`,
		r.LeaseID).Scan(&digest, &sandboxID, &generation, &minerHotkey, &validatorHotkey, &status, &cleanupStatus, &cleanupCode, &terminalCode, &seq, &current, &latest); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return SandboxOutcome{}, fmt.Errorf("sandbox lease %q is unknown", r.LeaseID)
		}
		return SandboxOutcome{}, err
	}
	if digest != r.LeaseDigest || sandboxID != r.SandboxID || generation != r.Generation || minerHotkey != r.MinerID ||
		validatorHotkey != sandboxValidator(r.Subnet) {
		return SandboxOutcome{}, ErrSandboxConflict
	}
	answer := func() (SandboxOutcome, error) {
		stage, code := sandboxLeaseStage(status, cleanupStatus, cleanupCode, terminalCode)
		return l.finish(ctx, tx, now, SandboxOutcome{Stage: stage, ErrorCode: code, LeaseID: &r.LeaseID, RenewalSeq: seq})
	}
	switch {
	case r.RenewalSeq == seq && bytes.Equal(latest, payload):
		return answer()
	case r.RenewalSeq == seq:
		return SandboxOutcome{}, ErrSandboxConflict
	case r.RenewalSeq < seq:
		return SandboxOutcome{}, errors.New("sandbox renewal_seq is not newer")
	case status != "pending" && status != "running":
		return answer()
	case now.UnixNano() >= current:
		// Too late: the lease lapsed and Sweep tears it down after Grace.
		status, cleanupStatus = "expired", nil
		return answer()
	}
	expires := sandboxTime(r.LeaseExpiresAt)
	if expires.UnixNano() <= current {
		return SandboxOutcome{}, errors.New("sandbox renewal does not extend the lease")
	}
	if _, err := tx.ExecContext(ctx, `UPDATE sandbox_leases SET renewal_seq=?,lease_expires_at_ns=?,renewal_json=?,updated_at_ns=? WHERE lease_id=?`,
		r.RenewalSeq, expires.UnixNano(), payload, now.UnixNano(), r.LeaseID); err != nil {
		return SandboxOutcome{}, err
	}
	seq = r.RenewalSeq
	return answer()
}

// Release fences (sandbox_id, generation, miner) for its validator, frees
// a live hold and moves a live lease to cleanup, in one transaction. It is
// idempotent and may precede the documents it cancels. It returns the
// leases whose runtime the caller must stop.
func (l *SandboxLeases) Release(ctx context.Context, r protocol.SandboxReleaseV1, now time.Time) (SandboxOutcome, []SandboxLeaseRecord, error) {
	if err := r.Validate(); err != nil {
		return SandboxOutcome{}, nil, err
	}
	payload, err := json.Marshal(r)
	if err != nil {
		return SandboxOutcome{}, nil, err
	}
	validator := sandboxValidator(r.Subnet)
	tx, err := l.db.BeginTx(ctx, nil)
	if err != nil {
		return SandboxOutcome{}, nil, err
	}
	defer tx.Rollback()
	if _, err := sandboxFencedTx(ctx, tx, r.SandboxID, r.Generation, r.MinerID, validator); err != nil {
		return SandboxOutcome{}, nil, err
	}
	for _, table := range []string{"sandbox_holds", "sandbox_leases"} {
		var owner string
		err := tx.QueryRowContext(ctx, `SELECT validator_hotkey FROM `+table+` WHERE sandbox_id=? AND generation=? AND miner_hotkey=?`,
			r.SandboxID, r.Generation, r.MinerID).Scan(&owner)
		if err == nil && owner != validator {
			return SandboxOutcome{}, nil, ErrSandboxConflict
		}
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return SandboxOutcome{}, nil, err
		}
	}
	stamp := now.UnixNano()
	for _, step := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO sandbox_release_fences(sandbox_id,generation,miner_hotkey,validator_hotkey,release_json,updated_at_ns) VALUES(?,?,?,?,?,?)
ON CONFLICT(sandbox_id,generation,miner_hotkey) DO NOTHING`, []any{r.SandboxID, r.Generation, r.MinerID, validator, payload, stamp}},
		{`UPDATE sandbox_holds SET status='released',updated_at_ns=? WHERE sandbox_id=? AND generation=? AND miner_hotkey=? AND status='held'`,
			[]any{stamp, r.SandboxID, r.Generation, r.MinerID}},
		{`UPDATE sandbox_leases SET status='cleanup',cleanup_status='released',cleanup_code=NULL,updated_at_ns=? WHERE sandbox_id=? AND generation=? AND miner_hotkey=? AND status IN ('pending','running')`,
			[]any{stamp, r.SandboxID, r.Generation, r.MinerID}},
	} {
		if _, err := tx.ExecContext(ctx, step.query, step.args...); err != nil {
			return SandboxOutcome{}, nil, err
		}
	}
	teardown, err := sandboxLeasesWhere(ctx, tx, `sandbox_id=? AND generation=? AND miner_hotkey=? AND status='cleanup'`, r.SandboxID, r.Generation, r.MinerID)
	if err != nil {
		return SandboxOutcome{}, nil, err
	}
	var leaseID *string
	var named string
	if err := tx.QueryRowContext(ctx, `SELECT lease_id FROM sandbox_leases WHERE sandbox_id=? AND generation=? AND miner_hotkey=?`,
		r.SandboxID, r.Generation, r.MinerID).Scan(&named); err == nil {
		leaseID = &named
	} else if !errors.Is(err, sql.ErrNoRows) {
		return SandboxOutcome{}, nil, err
	}
	outcome, err := l.finish(ctx, tx, now, SandboxOutcome{Stage: sandbox.StageReleased, LeaseID: leaseID})
	return outcome, teardown, err
}

// Sweep expires unused holds and moves every lease past its expiry plus
// Grace to cleanup, so a validator that disappears can never pin miner
// capacity. It returns every lease whose runtime the caller must stop.
func (l *SandboxLeases) Sweep(ctx context.Context, now time.Time) ([]SandboxLeaseRecord, error) {
	return l.cleanupWith(ctx, now, `UPDATE sandbox_leases SET status='cleanup',cleanup_status='expired',cleanup_code=NULL,updated_at_ns=? WHERE status IN ('pending','running') AND lease_expires_at_ns <= ?`,
		now.UnixNano(), now.Add(-sandbox.Grace).UnixNano())
}

// Recover is the restart path. v1 follows the deployment.v4 policy: every
// lease whose runtime may exist is torn down before the miner serves, and
// answers failed with the attributable miner_restart code.
func (l *SandboxLeases) Recover(ctx context.Context, now time.Time) ([]SandboxLeaseRecord, error) {
	if _, err := l.Sweep(ctx, now); err != nil {
		return nil, err
	}
	return l.cleanupWith(ctx, now, `UPDATE sandbox_leases SET status='cleanup',cleanup_status='failed',cleanup_code='miner_restart',updated_at_ns=? WHERE status IN ('pending','running')`,
		now.UnixNano())
}

func (l *SandboxLeases) cleanupWith(ctx context.Context, now time.Time, query string, args ...any) ([]SandboxLeaseRecord, error) {
	tx, err := l.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE sandbox_holds SET status='expired',updated_at_ns=? WHERE status='held' AND hold_expires_at_ns <= ?`, now.UnixNano(), now.UnixNano()); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, query, args...); err != nil {
		return nil, err
	}
	records, err := sandboxLeasesWhere(ctx, tx, `status='cleanup'`)
	if err != nil {
		return nil, err
	}
	return records, tx.Commit()
}

// Occupancy reports the capacity held and in use at now.
func (l *SandboxLeases) Occupancy(ctx context.Context, now time.Time) (held, active sandbox.Capacity, err error) {
	tx, err := l.db.BeginTx(ctx, nil)
	if err != nil {
		return sandbox.Capacity{}, sandbox.Capacity{}, err
	}
	defer tx.Rollback()
	return sandboxOccupancyTx(ctx, tx, now)
}

// Lease returns the durable record of leaseID.
func (l *SandboxLeases) Lease(ctx context.Context, leaseID string) (SandboxLeaseRecord, bool, error) {
	tx, err := l.db.BeginTx(ctx, nil)
	if err != nil {
		return SandboxLeaseRecord{}, false, err
	}
	defer tx.Rollback()
	records, err := sandboxLeasesWhere(ctx, tx, `lease_id=?`, leaseID)
	if err != nil || len(records) == 0 {
		return SandboxLeaseRecord{}, false, err
	}
	return records[0], true, nil
}

func sandboxLeasesWhere(ctx context.Context, tx *sql.Tx, where string, args ...any) ([]SandboxLeaseRecord, error) {
	rows, err := tx.QueryContext(ctx, `SELECT lease_id,status,cleanup_status,cleanup_code,terminal_code,renewal_seq,lease_expires_at_ns,lease_json FROM sandbox_leases WHERE `+where+` ORDER BY lease_id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var records []SandboxLeaseRecord
	for rows.Next() {
		var record SandboxLeaseRecord
		var expires int64
		var payload []byte
		if err := rows.Scan(&record.LeaseID, &record.Status, &record.CleanupStatus, &record.CleanupCode, &record.TerminalCode, &record.RenewalSeq, &expires, &payload); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(payload, &record.Lease); err != nil {
			return nil, fmt.Errorf("decode sandbox lease: %w", err)
		}
		record.LeaseExpiresAt = time.Unix(0, expires).UTC()
		records = append(records, record)
	}
	return records, rows.Err()
}
