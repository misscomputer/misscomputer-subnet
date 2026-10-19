// SPDX-License-Identifier: AGPL-3.0-only

package durable

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/protocol"
	"github.com/misscomputer/misscomputer-subnet/pkg/sandbox"
)

// Durable admission for sandbox-ops-v1 (docs/sandbox-ops-v1.md; contract
// D13; review SR-28-05; docs/sandbox-ops-v1-durability.md). This is an
// opt-in development slice: only the default-off miner ops lane calls it,
// and Open never creates its tables. Its tables and semantics are
// provisional until the ops contract freezes.
//
// What it guarantees:
//
//   - every admitted op, including every exec_start, is recorded by op_id
//     and document digest before the caller may cause any effect
//     (write-ahead);
//   - admission is one transaction. It covers the request window, the
//     lease fence, the lease state and expiry, the exec caps, and the
//     insert, all decided with one clock reading taken inside that
//     transaction;
//   - an exec lookup reports the in-transaction time it decided at, so a
//     receipt can carry that time as observed_at;
//   - decision times never go back (DP-8): each transaction decides at the
//     later of the wall clock and the durable high-water time, and raises
//     the high-water time to it. A wall clock stepped backward, before or
//     across a restart, can therefore never re-open a request window that
//     an earlier decision closed, nor admit an exec_start after a
//     definitive exec_not_found;
//   - on an agent that runs ops, a lease renewal decides on that same clock
//     inside its own transaction (RenewLease), so it is ordered against
//     every exec lookup, the lease-expiry kill's included.
//
// The U1 refusal code of a lease state is SandboxOpLeaseState.RefusalCode;
// the store itself reports the raw state.
//
// What it does not decide: how an in-flight exec_start replay is answered,
// who writes exec transitions or when, restart recovery, and file_write
// completion (U3, U4, U5, U6). Nor does it cap non-exec ops (N_ops) or
// prune records (U7, INT-OPS-01). Both build on the high-water time, but
// their parameters are not reviewed yet. Records therefore grow until then,
// which is acceptable only on disposable lab hosts; it blocks activation.
//
// Rows hold identities, digests, states and times only, never a path,
// argv, payload or result.
const sandboxOpsSchema = `
CREATE TABLE IF NOT EXISTS sandbox_ops (
  op_id TEXT PRIMARY KEY,
  lease_id TEXT NOT NULL REFERENCES sandbox_leases(lease_id),
  op TEXT NOT NULL CHECK(op IN ('exec_start','exec_read','exec_cancel','file_write','file_read','file_stat','file_list','file_remove','file_mkdir')),
  document_digest TEXT NOT NULL,
  validator_hotkey TEXT NOT NULL,
  expires_at_ns INTEGER NOT NULL,
  admitted_at_ns INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sandbox_execs (
  exec_id TEXT PRIMARY KEY REFERENCES sandbox_ops(op_id),
  lease_id TEXT NOT NULL REFERENCES sandbox_leases(lease_id),
  state TEXT NOT NULL CHECK(state IN ('admitted','running','exited','cancelled','timed_out','failed')),
  error_code TEXT CHECK((state='failed') = (error_code IS NOT NULL)),
  admitted_at_ns INTEGER NOT NULL,
  updated_at_ns INTEGER NOT NULL
);
-- The per-lease caps count every exec row of the lease.
CREATE INDEX IF NOT EXISTS sandbox_execs_by_lease ON sandbox_execs(lease_id, state);
-- The high-water decision time (DP-8): one row, never decreasing.
CREATE TABLE IF NOT EXISTS sandbox_ops_clock (
  singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
  high_water_ns INTEGER NOT NULL
);`

// ErrSandboxOpForeign reports an op request that does not target the
// stored lease it names: another validator, another generation, a sibling
// lease or an unknown lease_id. Nothing is recorded.
var ErrSandboxOpForeign = errors.New("sandbox op does not target a lease of this miner")

// ErrSandboxOpExpired reports an op request whose window had closed when
// the store decided, although an earlier admission check passed (SR-28-05).
// Nothing is recorded.
var ErrSandboxOpExpired = errors.New("sandbox op request window closed before admission")

// ErrSandboxExecTransition reports an exec state change that would move a
// terminal exec, or move a running exec back to admitted.
var ErrSandboxExecTransition = errors.New("sandbox exec state transition is not allowed")

// SandboxOps is the durable admission state of the ops extension.
type SandboxOps struct {
	db     *sql.DB
	clock  func() time.Time
	leases *SandboxLeases
}

// EnableSandboxOps creates the ops tables, if absent, in a store whose
// sandbox lease lane is enabled. It is the only path that creates them; it
// reads the lease tables and never writes them. clock is the wall clock. It
// is read inside each transaction, after the store's single connection is
// held, and never used below the durable high-water time.
func (l *SandboxLeases) EnableSandboxOps(ctx context.Context, clock func() time.Time) (*SandboxOps, error) {
	if clock == nil {
		return nil, errors.New("sandbox ops admission requires a clock")
	}
	if _, err := l.db.ExecContext(ctx, sandboxOpsSchema); err != nil {
		return nil, fmt.Errorf("migrate sandbox ops tables: %w", err)
	}
	return &SandboxOps{db: l.db, clock: clock, leases: l}, nil
}

// RenewLease is SandboxLeases.Renew for an agent that runs ops. It decides
// the renewal at this store's in-transaction high-water time (nowTx), the
// clock every exec lookup decides on, instead of a time its caller read
// before waiting for the store, and reports that decision time as
// ObservedAt. The store's single connection orders it against every
// ExecState: a renewal ordered before a read moved the lease expiry that
// read sees, and one ordered after a read that found the lease at or past
// its expiry decides at or after that read, so it is too late and is not
// applied (Renew's rule: a renewal that arrives after expiry is not
// applied).
func (o *SandboxOps) RenewLease(ctx context.Context, r protocol.SandboxRenewalV1) (SandboxOutcome, error) {
	var decided time.Time
	outcome, err := o.leases.renew(ctx, r, func(ctx context.Context, tx *sql.Tx) (time.Time, error) {
		now, err := o.nowTx(ctx, tx)
		decided = now
		return now, err
	})
	if err != nil {
		return SandboxOutcome{}, err
	}
	outcome.ObservedAt = decided
	return outcome, nil
}

// SandboxOpLeaseState is the raw durable state of the lease an op targets.
// The store reports it when the lease cannot run ops. Mapping it to a wire
// refusal code is the caller's decision (U1).
type SandboxOpLeaseState struct {
	Status        string
	CleanupStatus *string
	ExpiresAt     time.Time
}

// RefusalCode is the U1 mapping from the raw lease state at a decision time
// to the non-fault op refusal code, or "" when the lease runs ops then:
//
//   - running and before its expiry: "" (ops proceed);
//   - running at or after its expiry: lease_expired;
//   - pending: lease_not_running;
//   - released, or cleanup towards released: released;
//   - expired, or cleanup towards expired: lease_expired;
//   - failed (including miner_restart), cleanup towards failed, or anything
//     else: lease_not_running.
//
// The codes mean "no further ops on this lease"; in cleanup the sandbox
// may still be torn down. None is proof that an exec never started, and
// miner_restart is never emitted for ops. An op that names no lease row of
// this miner, fenced or not, gets no receipt at all (ErrSandboxOpForeign).
func (s SandboxOpLeaseState) RefusalCode(at time.Time) string {
	status := s.Status
	if status == "cleanup" && s.CleanupStatus != nil {
		status = *s.CleanupStatus
	}
	switch {
	case s.Status == "running" && at.Before(s.ExpiresAt):
		return ""
	case s.Status == "running", status == "expired":
		return "lease_expired"
	case status == "released":
		return "released"
	}
	return "lease_not_running"
}

// SandboxOpAdmission is the durable decision on one op request. When
// Unavailable is set, the answer comes from the lease state, whether or not
// Replay is also set. Limited is never set together with Replay or
// Unavailable. When none of Replay, Unavailable and Limited is set, the op
// was admitted now.
type SandboxOpAdmission struct {
	// DecidedAt is the in-transaction clock reading of this decision.
	DecidedAt time.Time
	// AdmittedAt is the decision time of the first admission; zero when
	// nothing was admitted.
	AdmittedAt time.Time
	// Replay is true when this exact document was admitted before. A
	// replay never permits an effect. Its answer is the recorded admission
	// only while the lease still runs ops; otherwise Unavailable is also set.
	Replay bool
	// Start is true only on the first admission of an exec_start. Its exec
	// record is durable, and the caller may now ask the backend to start
	// it. It is never true on a replay or a refusal.
	Start bool
	// Unavailable holds the raw lease state when the lease is not running
	// or has expired at DecidedAt. Nothing was recorded.
	Unavailable *SandboxOpLeaseState
	// Limited is true when an exec_start would exceed the lease's
	// non-terminal exec cap or its session cap. Nothing was recorded.
	Limited bool
}

// AdmitOp decides one verified op request in a single transaction. The
// caller has already run VerifyBoundSandboxOpRequestV1 and the miner
// identity check. The order is:
//
//  1. lease fence (foreign);
//  2. equivocation (conflict);
//  3. exact replay, which never permits an effect and is answered from the
//     current lease state when the lease has stopped;
//  4. the request window, for unrecorded ops only;
//  5. lease state;
//  6. caps;
//  7. insert.
//
// The store re-decides the window and liveness with its own clock, so a
// window that closes between the earlier checks and this call is refused
// here.
func (o *SandboxOps) AdmitOp(ctx context.Context, req protocol.SandboxOpRequestV1) (SandboxOpAdmission, error) {
	if err := req.Validate(); err != nil {
		return SandboxOpAdmission{}, err
	}
	digest, err := protocol.SandboxOpDigestV1(req)
	if err != nil {
		return SandboxOpAdmission{}, err
	}
	opID := protocol.SandboxOpIDV1(req)
	expires := sandboxTime(req.ExpiresAt)
	tx, err := o.db.BeginTx(ctx, nil)
	if err != nil {
		return SandboxOpAdmission{}, err
	}
	defer tx.Rollback()
	// The store has one connection, so this transaction excludes every
	// other durable read and write. This reading therefore orders the
	// decision against every exec lookup.
	now, err := o.nowTx(ctx, tx)
	if err != nil {
		return SandboxOpAdmission{}, err
	}
	decision := SandboxOpAdmission{DecidedAt: now}

	state, err := sandboxOpLeaseTx(ctx, tx, req)
	if errors.Is(err, ErrSandboxOpForeign) {
		return decided(tx, SandboxOpAdmission{}, err)
	}
	if err != nil {
		return SandboxOpAdmission{}, err
	}
	var existingDigest string
	var admitted int64
	err = tx.QueryRowContext(ctx, `SELECT document_digest,admitted_at_ns FROM sandbox_ops WHERE op_id=?`, opID).Scan(&existingDigest, &admitted)
	switch {
	case err == nil && existingDigest != digest:
		return decided(tx, SandboxOpAdmission{}, ErrSandboxConflict)
	case err == nil:
		// An exact replay never permits a second effect, but it is
		// answered from the lease as it is now: once the lease stopped
		// running (release, expiry, restart), the lease state answers,
		// not the recorded admission (SC-1).
		decision.Replay, decision.AdmittedAt = true, time.Unix(0, admitted).UTC()
		if !sandboxOpLeaseLive(state, now) {
			decision.Unavailable = &state
		}
		return decision, tx.Commit()
	case !errors.Is(err, sql.ErrNoRows):
		return SandboxOpAdmission{}, err
	}
	// The request window decides only ops not recorded yet.
	if !now.Before(expires) {
		return decided(tx, SandboxOpAdmission{}, ErrSandboxOpExpired)
	}
	if !sandboxOpLeaseLive(state, now) {
		decision.Unavailable = &state
		return decision, tx.Commit()
	}
	start := req.Op == sandbox.OpExecStart
	if start {
		var live, sessions int
		if err := tx.QueryRowContext(ctx, `SELECT COALESCE(SUM(state IN ('admitted','running')),0),COUNT(*) FROM sandbox_execs WHERE lease_id=?`,
			req.LeaseID).Scan(&live, &sessions); err != nil {
			return SandboxOpAdmission{}, err
		}
		if live >= sandbox.MaxRunningExecs || sessions >= sandbox.MaxExecSessions {
			decision.Limited = true
			return decision, tx.Commit()
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO sandbox_ops(op_id,lease_id,op,document_digest,validator_hotkey,expires_at_ns,admitted_at_ns) VALUES(?,?,?,?,?,?,?)`,
		opID, req.LeaseID, req.Op, digest, sandboxValidator(req.Subnet), expires.UnixNano(), now.UnixNano()); err != nil {
		return SandboxOpAdmission{}, err
	}
	if start {
		if _, err := tx.ExecContext(ctx, `INSERT INTO sandbox_execs(exec_id,lease_id,state,admitted_at_ns,updated_at_ns) VALUES(?,?,'admitted',?,?)`,
			opID, req.LeaseID, now.UnixNano(), now.UnixNano()); err != nil {
			return SandboxOpAdmission{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return SandboxOpAdmission{}, err
	}
	decision.AdmittedAt, decision.Start = now, start
	return decision, nil
}

// nowTx is the decision time of one transaction: the later of the wall
// clock and the durable high-water time, which it raises to that time. The
// write is part of tx, so a transaction that commits also persists its
// decision time; one that rolls back decided nothing.
func (o *SandboxOps) nowTx(ctx context.Context, tx *sql.Tx) (time.Time, error) {
	wall := o.clock().UTC()
	var highWater int64
	err := tx.QueryRowContext(ctx, `SELECT high_water_ns FROM sandbox_ops_clock WHERE singleton=1`).Scan(&highWater)
	switch {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return time.Time{}, err
	case wall.UnixNano() <= highWater:
		return time.Unix(0, highWater).UTC(), nil
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO sandbox_ops_clock(singleton,high_water_ns) VALUES(1,?)
ON CONFLICT(singleton) DO UPDATE SET high_water_ns=excluded.high_water_ns`, wall.UnixNano()); err != nil {
		return time.Time{}, err
	}
	return wall, nil
}

// decided commits tx, which holds only the decision time when nothing else
// was written, and returns err: a refusal still moves the high-water time.
func decided[T any](tx *sql.Tx, value T, err error) (T, error) {
	if commitErr := tx.Commit(); commitErr != nil {
		var zero T
		return zero, commitErr
	}
	return value, err
}

// sandboxOpLeaseLive reports whether the lease runs ops at now.
func sandboxOpLeaseLive(state SandboxOpLeaseState, now time.Time) bool {
	return state.Status == "running" && now.Before(state.ExpiresAt)
}

// sandboxOpLeaseTx loads the lease req names and fences req to it.
func sandboxOpLeaseTx(ctx context.Context, tx *sql.Tx, req protocol.SandboxOpRequestV1) (SandboxOpLeaseState, error) {
	var state SandboxOpLeaseState
	var expires int64
	var payload []byte
	err := tx.QueryRowContext(ctx, `SELECT status,cleanup_status,lease_expires_at_ns,lease_json FROM sandbox_leases WHERE lease_id=?`, req.LeaseID).
		Scan(&state.Status, &state.CleanupStatus, &expires, &payload)
	if errors.Is(err, sql.ErrNoRows) {
		return state, ErrSandboxOpForeign
	}
	if err != nil {
		return state, err
	}
	var lease protocol.SandboxLeaseV1
	if err := json.Unmarshal(payload, &lease); err != nil {
		return state, fmt.Errorf("decode sandbox lease: %w", err)
	}
	if err := protocol.SandboxOpTargetsLeaseV1(req, lease); err != nil {
		return state, ErrSandboxOpForeign
	}
	state.ExpiresAt = time.Unix(0, expires).UTC()
	return state, nil
}

// SandboxExecLookup is the durable answer to an exec_read or exec_cancel.
type SandboxExecLookup struct {
	// DecidedAt is the in-transaction clock reading of this lookup. A
	// receipt that answers exec_not_found from this lookup must carry
	// exactly this observed_at, never a later time.
	DecidedAt time.Time
	// Unavailable holds the raw lease state when the lease is not running
	// or has expired at DecidedAt. The exec was not looked up.
	Unavailable *SandboxOpLeaseState
	// Found reports whether an exec_start with this exec_id was admitted
	// on the lease. It is false exactly when no such record exists.
	Found      bool
	State      string
	ErrorCode  *string
	AdmittedAt time.Time
}

// LookupExec reports whether the exec named by a verified exec_read or
// exec_cancel was admitted on its lease. Its clock reading is ordered
// against every AdmitOp, because both hold the store's only connection.
// Suppose a lookup finds nothing at DecidedAt >= expires_at plus the skew of
// the exec_start. Then no later admission of that exec_start can happen,
// because AdmitOp refuses at or after expires_at by the same clock.
func (o *SandboxOps) LookupExec(ctx context.Context, req protocol.SandboxOpRequestV1) (SandboxExecLookup, error) {
	if err := req.Validate(); err != nil {
		return SandboxExecLookup{}, err
	}
	if req.ExecID == nil {
		return SandboxExecLookup{}, errors.New("sandbox exec lookup needs an exec_read or exec_cancel request")
	}
	tx, err := o.db.BeginTx(ctx, nil)
	if err != nil {
		return SandboxExecLookup{}, err
	}
	defer tx.Rollback()
	now, err := o.nowTx(ctx, tx)
	if err != nil {
		return SandboxExecLookup{}, err
	}
	state, err := sandboxOpLeaseTx(ctx, tx, req)
	if errors.Is(err, ErrSandboxOpForeign) {
		return decided(tx, SandboxExecLookup{}, err)
	}
	if err != nil {
		return SandboxExecLookup{}, err
	}
	lookup := SandboxExecLookup{DecidedAt: now}
	if !sandboxOpLeaseLive(state, now) {
		lookup.Unavailable = &state
		return lookup, tx.Commit()
	}
	var admitted int64
	err = tx.QueryRowContext(ctx, `SELECT state,error_code,admitted_at_ns FROM sandbox_execs WHERE exec_id=? AND lease_id=?`, *req.ExecID, req.LeaseID).
		Scan(&lookup.State, &lookup.ErrorCode, &admitted)
	switch {
	case err == nil:
		lookup.Found, lookup.AdmittedAt = true, time.Unix(0, admitted).UTC()
	case !errors.Is(err, sql.ErrNoRows):
		return SandboxExecLookup{}, err
	}
	return lookup, tx.Commit()
}

// ExecState is the lane's own read of one exec row, for the start owner and
// the kill path: they act only on execs of a live lease (U3-L8-1), decided by
// the same high-water clock as admission. Found is false when no exec_start
// with execID was admitted. When the lease is not live, Unavailable holds its
// raw state and the exec must be left to sandbox destruction. LeaseExpiresAt
// is the lease's current expiry, which follows renewals.
func (o *SandboxOps) ExecState(ctx context.Context, execID string) (SandboxExecLookup, time.Time, error) {
	tx, err := o.db.BeginTx(ctx, nil)
	if err != nil {
		return SandboxExecLookup{}, time.Time{}, err
	}
	defer tx.Rollback()
	now, err := o.nowTx(ctx, tx)
	if err != nil {
		return SandboxExecLookup{}, time.Time{}, err
	}
	lookup := SandboxExecLookup{DecidedAt: now}
	var state SandboxOpLeaseState
	var admitted, expires int64
	err = tx.QueryRowContext(ctx, `SELECT e.state,e.error_code,e.admitted_at_ns,l.status,l.cleanup_status,l.lease_expires_at_ns
FROM sandbox_execs e JOIN sandbox_leases l ON l.lease_id=e.lease_id WHERE e.exec_id=?`, execID).
		Scan(&lookup.State, &lookup.ErrorCode, &admitted, &state.Status, &state.CleanupStatus, &expires)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return lookup, time.Time{}, tx.Commit()
	case err != nil:
		return SandboxExecLookup{}, time.Time{}, err
	}
	lookup.Found, lookup.AdmittedAt = true, time.Unix(0, admitted).UTC()
	state.ExpiresAt = time.Unix(0, expires).UTC()
	if !sandboxOpLeaseLive(state, now) {
		lookup.Unavailable = &state
	}
	return lookup, state.ExpiresAt, tx.Commit()
}

var sandboxExecTerminal = map[string]bool{
	sandbox.ExecStateExited: true, sandbox.ExecStateCancelled: true, sandbox.ExecStateTimedOut: true, sandbox.ExecStateFailed: true,
}

// RecordExecState stores a transition supplied by the caller. It does not
// decide when or why one happens (U4). It only guards monotonicity:
// admitted may become running or terminal, running may become terminal, a
// terminal state never changes, and repeating the current state is a
// no-op. failed carries a known op error code; no other state does.
func (o *SandboxOps) RecordExecState(ctx context.Context, execID, state string, code *string) error {
	switch {
	case state == sandbox.ExecStateFailed:
		if code == nil {
			return errors.New("a failed sandbox exec needs an error code")
		}
		if _, known := sandbox.OpErrorAttribution[*code]; !known {
			return errors.New("sandbox exec error code is unknown")
		}
	case state == sandbox.ExecStateRunning || sandboxExecTerminal[state]:
		if code != nil {
			return errors.New("only a failed sandbox exec carries an error code")
		}
	default:
		return errors.New("sandbox exec state is invalid")
	}
	tx, err := o.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now, err := o.nowTx(ctx, tx)
	if err != nil {
		return err
	}
	var current string
	var currentCode *string
	err = tx.QueryRowContext(ctx, `SELECT state,error_code FROM sandbox_execs WHERE exec_id=?`, execID).Scan(&current, &currentCode)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("sandbox exec %q is unknown", execID)
	}
	if err != nil {
		return err
	}
	switch {
	case current == state && sameCode(currentCode, code):
		return tx.Commit()
	case sandboxExecTerminal[current], state == sandbox.ExecStateRunning && current != "admitted":
		return ErrSandboxExecTransition
	}
	if _, err := tx.ExecContext(ctx, `UPDATE sandbox_execs SET state=?,error_code=?,updated_at_ns=? WHERE exec_id=?`, state, code, now.UnixNano(), execID); err != nil {
		return err
	}
	return tx.Commit()
}

// RecordAdmittedExecEnd stores the end of an exec that has not started: state
// is cancelled or timed_out. It applies only while the exec is still admitted.
// Once a start has recorded it running, or it has ended, nothing is written and
// the result is false, so a kill path that read the exec as admitted cannot end
// a running exec without signalling it: its caller then kills it through the
// helper. The check and the write are one transaction.
func (o *SandboxOps) RecordAdmittedExecEnd(ctx context.Context, execID, state string) (bool, error) {
	if state != sandbox.ExecStateCancelled && state != sandbox.ExecStateTimedOut {
		return false, errors.New("an admitted sandbox exec can only end cancelled or timed_out")
	}
	tx, err := o.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	now, err := o.nowTx(ctx, tx)
	if err != nil {
		return false, err
	}
	var current string
	err = tx.QueryRowContext(ctx, `SELECT state FROM sandbox_execs WHERE exec_id=?`, execID).Scan(&current)
	if errors.Is(err, sql.ErrNoRows) {
		return false, fmt.Errorf("sandbox exec %q is unknown", execID)
	}
	if err != nil {
		return false, err
	}
	applied := false
	if current == "admitted" {
		result, err := tx.ExecContext(ctx, `UPDATE sandbox_execs SET state=?,updated_at_ns=? WHERE exec_id=? AND state='admitted'`, state, now.UnixNano(), execID)
		if err != nil {
			return false, err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return false, err
		}
		applied = n == 1
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return applied, nil
}

func sameCode(left, right *string) bool {
	return (left == nil) == (right == nil) && (left == nil || *left == *right)
}
