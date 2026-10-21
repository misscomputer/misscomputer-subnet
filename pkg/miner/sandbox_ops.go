// SPDX-License-Identifier: AGPL-3.0-only

package miner

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/durable"
	"github.com/misscomputer/misscomputer-subnet/pkg/organic"
	"github.com/misscomputer/misscomputer-subnet/pkg/protocol"
	"github.com/misscomputer/misscomputer-subnet/pkg/sandbox"
	"github.com/misscomputer/misscomputer-subnet/pkg/sandboxops"
)

// The sandbox-ops-v1 lane (docs/sandbox-ops-v1.md, docs/sandbox-ops-v1-lane.md)
// runs bounded exec and file operations on running leases of this
// SandboxLane. It has no lifecycle of its own (OPS-U6): it shares the lease
// lane's base context, closed channel, gate and work group, so Close stops
// and joins lease and ops work together and no receipt is signed after it.
// It is off unless EnableOps is called with an ops-capable backend.

// SandboxOpsBackend is implemented by a SandboxBackend whose sandboxes carry
// the in-sandbox helper (cmd/sandbox-ops-helper).
type SandboxOpsBackend interface {
	// RunHelper runs the helper once in the running sandbox instanceID with
	// request on its stdin and returns its stdout, at most
	// sandboxops.MaxResponseBytes. It returns ErrSandboxNotRunning when the
	// engine reports that the sandbox is not running, and a
	// *SandboxEngineUnavailable only when the engine gave no answer and an
	// independent liveness check of the daemon failed as well (OPS-U3 D1).
	// Every other error is treated as originating inside the sandbox.
	RunHelper(ctx context.Context, instanceID string, request []byte) ([]byte, error)
}

// ErrSandboxNotRunning reports a sandbox the engine says is not running.
var ErrSandboxNotRunning = errors.New("sandbox is not running")

// SandboxEngineUnavailable is a miner-side engine failure: no answer, with a
// failed independent liveness check. It is the only op_runtime_failed cause.
type SandboxEngineUnavailable struct{ Err error }

func (e *SandboxEngineUnavailable) Error() string {
	return "sandbox engine unavailable: " + e.Err.Error()
}
func (e *SandboxEngineUnavailable) Unwrap() error { return e.Err }

// ErrSandboxOpsDisabled answers an op on a lane without ops.
var ErrSandboxOpsDisabled = errors.New("sandbox-ops-v1 is not enabled")

// ErrSandboxOpsBusy is a retryable answer without a receipt: the agent's
// in-flight bound is reached, or a durable step ran out of D_state while the
// lane is open (U6-L8-5). This attempt made no definitive outcome decision;
// an earlier attempt may already have started the operation.
var ErrSandboxOpsBusy = errors.New("sandbox ops are busy; retry")

// SandboxOpsInternalError is an admitted op's failure that is none of the
// lane's named answers. It may come after an effect started, so callers must
// treat the outcome as unknown, never as a refusal without effect.
type SandboxOpsInternalError struct{ Err error }

func (e *SandboxOpsInternalError) Error() string {
	return "sandbox op failed inside the miner: " + e.Err.Error()
}
func (e *SandboxOpsInternalError) Unwrap() error { return e.Err }

// SandboxOpsConfig holds the ops parameters the frozen ops section leaves
// symbolic until a reviewed measurement adopts them (OPS-U numeric and lab
// gates). None has a default: an operator who enables ops supplies each.
type SandboxOpsConfig struct {
	// StartResolution is D_start: how long the start owner waits for the
	// helper to confirm a start before the exec ends failed.
	StartResolution time.Duration
	// StateTimeout is D_state, the bound of one durable step, at most 30 s.
	StateTimeout time.Duration
	// KillGrace is the B-7 grace after ExecKillGrace before the second
	// cancel.
	KillGrace time.Duration
	// MaxInFlight and MaxInFlightBytes bound the ops in flight at once and
	// their payload and result bytes (D14).
	MaxInFlight      int
	MaxInFlightBytes int
	// MaxOutcomes bounds the retained answers of mutating file ops, which an
	// exact replay inside the request window is answered from.
	MaxOutcomes int
}

func (c SandboxOpsConfig) validate() error {
	if c.StartResolution <= 0 || c.StateTimeout <= 0 || c.StateTimeout > sandboxStateTimeout || c.KillGrace <= 0 ||
		c.MaxInFlight <= 0 || c.MaxInFlightBytes < sandbox.MaxChunkBytes || c.MaxOutcomes <= 0 {
		return errors.New("sandbox ops parameters must all be set: start resolution, state timeout (<= 30s), kill grace, in-flight ops and bytes (>= one chunk), retained outcomes")
	}
	return nil
}

// killPoll is how often the kill path re-reads an exec it signalled.
const killPoll = 250 * time.Millisecond

// durableAttempts bounds the tries of one exec-state step whose D_state ran
// out with the lane open; each try has its own D_state.
const durableAttempts = 3

type sandboxOps struct {
	store   *durable.SandboxOps
	backend SandboxOpsBackend
	config  SandboxOpsConfig

	mu       sync.Mutex
	inflight int
	bytes    int
	outcomes map[string]*opOutcome
	execs    map[string]*opExec
}

// opOutcome is the answer of one mutating file op, kept until its request
// can no longer be admitted, so an exact replay never repeats the effect.
type opOutcome struct {
	leaseID string
	done    chan struct{}
	receipt *protocol.SandboxOpReceiptV1
	timer   *time.Timer
}

// opExec is the lane's in-memory view of one admitted exec. Exec state never
// survives a restart (Recover ends every lease), so nothing here is durable.
type opExec struct {
	leaseID    string
	instance   string
	admittedAt time.Time
	timeout    time.Duration
	maxOutput  uint64

	mu       sync.Mutex
	observed sandboxops.ExecObservation
	exitCode *int
	endedAt  time.Time
	// deadlineTimer runs the kill path at the exec deadline (armDeadline);
	// resolveTimer runs a resolution (armResolve). They are separate so a
	// resolution never displaces the deadline.
	deadlineTimer *time.Timer
	resolveTimer  *time.Timer
	// killTrigger is the trigger of the first kill path that signalled the
	// exec through the helper.
	killTrigger string
	// cancelPending is set, and never cleared, once a tenant's exec_cancel
	// reached the kill path, before its first durable read. Until the exec
	// is terminal, retries, start owners and resolutions act on that cancel
	// (killPath). It lives in memory only: a restart loses it, and Recover
	// ends every lease and destroys its sandbox, so the exec ends with it.
	cancelPending bool
	// owned is set once a start owner was launched for this exec, or once
	// the lane decided no owner ever will (an orphaned admission).
	owned bool
	// requestExpires is the exec_start request's expires_at: from then on no
	// admission of this op ID can happen any more.
	requestExpires time.Time
	// gaveUp is set when the start owner could not read or record the
	// exec's state and handed it to armResolve.
	gaveUp bool
	// kill serializes the kill path of this exec.
	kill sync.Mutex
}

// EnableOps turns on sandbox-ops-v1 for this lane. It must run after the
// startup Recover and before the ops route is served (OPS-U6 startup).
func (l *SandboxLane) EnableOps(store *durable.SandboxOps, config SandboxOpsConfig) error {
	backend, ok := l.backend.(SandboxOpsBackend)
	if !ok {
		return errors.New("sandbox backend does not run the ops helper")
	}
	if store == nil {
		return errors.New("sandbox ops require their durable admission store")
	}
	if err := config.validate(); err != nil {
		return err
	}
	l.ops = &sandboxOps{store: store, backend: backend, config: config, outcomes: map[string]*opOutcome{}, execs: map[string]*opExec{}}
	return nil
}

// OpsEnabled reports whether EnableOps succeeded.
func (l *SandboxLane) OpsEnabled() bool { return l.ops != nil }

func (l *SandboxLane) isClosed() bool {
	select {
	case <-l.closed:
		return true
	default:
		return false
	}
}

// laneErr maps a failure caused by Close to ErrSandboxLaneClosed (DP-12). A
// request cancelled with the lane open keeps its own error.
func (l *SandboxLane) laneErr(err error) error {
	if err != nil && l.base.Err() != nil {
		return ErrSandboxLaneClosed
	}
	return err
}

// detached is ctx without its cancellation but still ending with the lane:
// work already decided continues when the client disconnects (U6-L8-3).
func (l *SandboxLane) detached(ctx context.Context) (context.Context, context.CancelFunc) {
	work, cancel := context.WithCancel(context.WithoutCancel(ctx))
	stop := context.AfterFunc(l.base, cancel)
	return work, func() {
		stop()
		cancel()
	}
}

// state is the context of one durable step: detached from the request and
// bounded by D_state (OPS-U6 durable_writes).
func (o *sandboxOps) state(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), o.config.StateTimeout)
}

// durableErr maps an expired D_state with the lane open to the retryable
// busy answer, never a 422.
func (l *SandboxLane) durableErr(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if l.base.Err() != nil {
		return ErrSandboxLaneClosed
	}
	if errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil {
		return ErrSandboxOpsBusy
	}
	return err
}

// reserve takes an in-flight slot for one op; it fails at the D14 bound.
func (o *sandboxOps) reserve(bytes int) (func(), bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.inflight >= o.config.MaxInFlight || o.bytes+bytes > o.config.MaxInFlightBytes {
		return nil, false
	}
	o.inflight++
	o.bytes += bytes
	var once sync.Once
	return func() {
		once.Do(func() {
			o.mu.Lock()
			o.inflight--
			o.bytes -= bytes
			o.mu.Unlock()
		})
	}, true
}

func opBytes(r protocol.SandboxOpRequestV1) int {
	bytes := int(r.PayloadBytes)
	if r.Limit != nil && r.Op != sandbox.OpFileList {
		bytes += int(*r.Limit)
	}
	return max(bytes, 1)
}

// Op runs one verified sandbox-op-request and answers with a signed receipt
// and its result bytes, or an error without a receipt.
func (l *SandboxLane) Op(ctx context.Context, r protocol.SandboxOpRequestV1, payload []byte, req SandboxRequest) (protocol.SandboxOpReceiptV1, []byte, error) {
	ops := l.ops
	if ops == nil {
		return protocol.SandboxOpReceiptV1{}, nil, ErrSandboxOpsDisabled
	}
	ctx, done, err := l.track(ctx)
	if err != nil {
		return protocol.SandboxOpReceiptV1{}, nil, err
	}
	defer done()
	now := l.now().UTC()
	if err := protocol.VerifyBoundSandboxOpRequestV1(r, req.ValidatorKey, now, req.CurrentBlock, req.Network, req.NetUID, req.CallerHotkey, req.MinerHotkey, req.MinerUID); err != nil {
		return protocol.SandboxOpReceiptV1{}, nil, err
	}
	if err := l.admit(r.Subnet, r.MinerID); err != nil {
		return protocol.SandboxOpReceiptV1{}, nil, err
	}
	if err := protocol.SandboxOpPayloadMatchesV1(r, payload); err != nil {
		return protocol.SandboxOpReceiptV1{}, nil, err
	}
	var command sandbox.ExecCommand
	if r.Op == sandbox.OpExecStart {
		if command, err = sandbox.DecodeExecCommand(payload); err != nil {
			return protocol.SandboxOpReceiptV1{}, nil, fmt.Errorf("sandbox_op_payload_invalid: %w", err)
		}
	}
	release, ok := ops.reserve(opBytes(r))
	if !ok {
		// No durable replay decision was made. Even an exec_start may be
		// a resend of an already-running exec whose receipt was lost, so
		// overload cannot prove refusal without effect. Only AdmitOp may
		// decide the lease/session limits and sign exec_limit_exceeded.
		return protocol.SandboxOpReceiptV1{}, nil, ErrSandboxOpsBusy
	}
	defer release()
	// U6-L8-1: a request tracked before Close decides nothing once Close
	// began.
	if l.isClosed() {
		return protocol.SandboxOpReceiptV1{}, nil, ErrSandboxLaneClosed
	}
	var receipt protocol.SandboxOpReceiptV1
	var result []byte
	switch r.Op {
	case sandbox.OpExecStart:
		receipt, err = l.execStart(ctx, ops, r, command)
	case sandbox.OpExecRead, sandbox.OpExecCancel:
		receipt, result, err = l.execLookup(ctx, ops, r, release)
	case sandbox.OpFileWrite, sandbox.OpFileRemove, sandbox.OpFileMkdir:
		receipt, err = l.fileMutation(ctx, ops, r, payload)
	default:
		receipt, result, err = l.fileRead(ctx, ops, r)
	}
	if err != nil {
		return protocol.SandboxOpReceiptV1{}, nil, l.opFailure(err)
	}
	return receipt, result, nil
}

// opFailure keeps the lane's named answers of an admitted op and marks every
// other failure internal: it may follow an effect, so it must never reach
// the validator as a definitive refusal.
func (l *SandboxLane) opFailure(err error) error {
	err = l.laneErr(err)
	for _, named := range []error{ErrSandboxLaneClosed, ErrSandboxOpsBusy, durable.ErrSandboxConflict, durable.ErrSandboxOpExpired, durable.ErrSandboxOpForeign} {
		if errors.Is(err, named) {
			return err
		}
	}
	return &SandboxOpsInternalError{Err: err}
}

// opReceipt is an unsigned-then-signed receipt with only a stage and code.
func (l *SandboxLane) opReceipt(r protocol.SandboxOpRequestV1, stage, code string, observed time.Time) (protocol.SandboxOpReceiptV1, error) {
	receipt, err := l.opBase(r, stage, observed)
	if err != nil {
		return receipt, err
	}
	if code != "" {
		receipt.ErrorCode = &code
	}
	return receipt, l.signOp(&receipt)
}

func (l *SandboxLane) opBase(r protocol.SandboxOpRequestV1, stage string, observed time.Time) (protocol.SandboxOpReceiptV1, error) {
	digest, err := protocol.SandboxOpDigestV1(r)
	if err != nil {
		return protocol.SandboxOpReceiptV1{}, err
	}
	return protocol.SandboxOpReceiptV1{
		DocumentDigest: digest, Generation: r.Generation, LeaseID: r.LeaseID, MinerID: l.agent.MinerID,
		ObservedAt: *protocol.StaticTime(observed), Op: r.Op, OpID: protocol.SandboxOpIDV1(r), SandboxID: r.SandboxID,
		Schema: protocol.SandboxOpReceiptSchema, SchemaVersion: protocol.SandboxOpsSchemaVersion, Stage: stage, Subnet: r.Subnet,
	}, nil
}

// signOp signs under the gate unless the lane closed (OPS-U6 publish rule):
// only local CPU work runs while the gate is held.
func (l *SandboxLane) signOp(receipt *protocol.SandboxOpReceiptV1) error {
	l.gate.Lock()
	defer l.gate.Unlock()
	if l.isClosed() {
		return ErrSandboxLaneClosed
	}
	return protocol.SignSandboxOpReceiptV1(receipt, l.agent.SigningKey)
}

// refusedStage maps a code to its receipt stage: a code naming a state that
// prevents the op is refused; a failure while performing it is failed.
func refusedStage(code string) string {
	switch code {
	case sandbox.OpCodeSandboxFailed, sandbox.OpCodeResourcesExhausted, sandbox.OpCodeRuntimeFailed:
		return sandbox.OpStageFailed
	}
	return sandbox.OpStageRefused
}

// leaseRefusal answers an op whose lease does not run ops at at.
func (l *SandboxLane) leaseRefusal(r protocol.SandboxOpRequestV1, state *durable.SandboxOpLeaseState, at time.Time) (protocol.SandboxOpReceiptV1, error) {
	code := state.RefusalCode(at)
	if code == "" {
		code = "lease_not_running"
	}
	return l.opReceipt(r, sandbox.OpStageRefused, code, at)
}

func later(times ...time.Time) time.Time {
	var latest time.Time
	for _, value := range times {
		if value.After(latest) {
			latest = value
		}
	}
	return latest
}

// call runs one helper request. code is "" on success, the helper's own
// non-fault code, or the miner's classification of a failed call (OPS-U3
// classification). deadline reports that ctx ended first.
func (o *sandboxOps) call(ctx context.Context, instance string, request sandboxops.Request) (response sandboxops.Response, code string, deadline bool) {
	request.Protocol = sandboxops.Protocol
	encoded, err := sandboxops.Encode(request)
	if err != nil {
		return sandboxops.Response{}, sandbox.OpCodeSandboxFailed, false
	}
	out, err := o.backend.RunHelper(ctx, instance, encoded)
	var unavailable *SandboxEngineUnavailable
	switch {
	case errors.Is(err, ErrSandboxNotRunning):
		return sandboxops.Response{}, "sandbox_exited", false
	case errors.As(err, &unavailable):
		return sandboxops.Response{}, sandbox.OpCodeRuntimeFailed, false
	case err != nil && ctx.Err() != nil:
		return sandboxops.Response{}, sandbox.OpCodeDeadline, true
	case err != nil:
		return sandboxops.Response{}, sandbox.OpCodeSandboxFailed, false
	}
	response, err = sandboxops.DecodeResponse(out, request)
	if err != nil {
		// A broken or impersonated helper (B-5).
		return sandboxops.Response{}, sandbox.OpCodeSandboxFailed, false
	}
	if response.Code != nil {
		return response, *response.Code, false
	}
	return response, "", false
}

// --- file operations ---

func (l *SandboxLane) fileRead(ctx context.Context, ops *sandboxOps, r protocol.SandboxOpRequestV1) (protocol.SandboxOpReceiptV1, []byte, error) {
	stateCtx, cancel := ops.state(ctx)
	admission, err := ops.store.AdmitOp(stateCtx, r)
	err = l.durableErr(stateCtx, err)
	cancel()
	if err != nil {
		return protocol.SandboxOpReceiptV1{}, nil, err
	}
	if admission.Unavailable != nil {
		receipt, err := l.leaseRefusal(r, admission.Unavailable, admission.DecidedAt)
		return receipt, nil, err
	}
	// Reads are side-effect free: a replay is recomputed.
	return l.runFileOp(ctx, ops, r, nil, admission.DecidedAt)
}

// fileMutation runs file_write, file_remove or file_mkdir at most once per
// op ID. Its answer is kept until the request window closes, so an exact
// replay is answered from it and never repeats the effect.
func (l *SandboxLane) fileMutation(ctx context.Context, ops *sandboxOps, r protocol.SandboxOpRequestV1, payload []byte) (protocol.SandboxOpReceiptV1, error) {
	opID := protocol.SandboxOpIDV1(r)
	outcome, owner, ok := ops.outcome(opID, r.LeaseID)
	if !ok {
		return protocol.SandboxOpReceiptV1{}, ErrSandboxOpsBusy
	}
	if !owner {
		// A concurrent or earlier request with this op ID owns the effect.
		select {
		case <-outcome.done:
		case <-ctx.Done():
			return protocol.SandboxOpReceiptV1{}, ctx.Err()
		}
	}
	stateCtx, cancel := ops.state(ctx)
	admission, err := ops.store.AdmitOp(stateCtx, r)
	err = l.durableErr(stateCtx, err)
	cancel()
	settle := func(receipt *protocol.SandboxOpReceiptV1) {
		if owner {
			// Kept until the request can no longer be admitted, on the
			// lane's clock: expires_at plus the issue skew.
			expires, _ := time.Parse(time.RFC3339Nano, r.ExpiresAt)
			ops.settle(opID, outcome, receipt, expires.Add(sandbox.IssueSkew).Sub(l.now()))
		}
	}
	switch {
	case err != nil:
		settle(nil)
		return protocol.SandboxOpReceiptV1{}, err
	case admission.Unavailable != nil:
		// Once the lease stopped, the lease state answers, replay or not.
		settle(nil)
		return l.leaseRefusal(r, admission.Unavailable, admission.DecidedAt)
	case !owner && admission.Replay && outcome.receipt != nil:
		return *outcome.receipt, nil
	case !owner || admission.Replay:
		// The effect's answer is not held here (its owner failed after
		// recording it, or it was recorded before this agent held answers):
		// never repeat the effect. Retrying is safe; the request window
		// bounds how long this can last.
		settle(nil)
		return protocol.SandboxOpReceiptV1{}, ErrSandboxOpsBusy
	}
	work, stop := l.detached(ctx)
	receipt, _, err := l.runFileOp(work, ops, r, payload, admission.DecidedAt)
	stop()
	if err != nil {
		settle(nil)
		return protocol.SandboxOpReceiptV1{}, err
	}
	settle(&receipt)
	return receipt, nil
}

// outcome returns the answer slot of opID and whether the caller owns it.
// ok is false when the retained-outcome bound is reached.
func (o *sandboxOps) outcome(opID, leaseID string) (*opOutcome, bool, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if existing := o.outcomes[opID]; existing != nil {
		return existing, false, true
	}
	if len(o.outcomes) >= o.config.MaxOutcomes {
		return nil, false, false
	}
	created := &opOutcome{leaseID: leaseID, done: make(chan struct{})}
	o.outcomes[opID] = created
	return created, true, true
}

// settle publishes an owner's answer. Without a receipt the slot is freed at
// once; with one it is kept for keep.
func (o *sandboxOps) settle(opID string, outcome *opOutcome, receipt *protocol.SandboxOpReceiptV1, keep time.Duration) {
	o.mu.Lock()
	outcome.receipt = receipt
	if receipt == nil {
		delete(o.outcomes, opID)
	} else {
		outcome.timer = time.AfterFunc(max(keep, 0), func() {
			o.mu.Lock()
			if o.outcomes[opID] == outcome {
				delete(o.outcomes, opID)
			}
			o.mu.Unlock()
		})
	}
	o.mu.Unlock()
	close(outcome.done)
}

// runFileOp performs one admitted file op through the helper within the 30 s
// file-op budget and signs its receipt.
func (l *SandboxLane) runFileOp(ctx context.Context, ops *sandboxOps, r protocol.SandboxOpRequestV1, payload []byte, decided time.Time) (protocol.SandboxOpReceiptV1, []byte, error) {
	request := sandboxops.Request{Op: r.Op, Path: r.Path, Offset: r.Offset, Limit: r.Limit, Mode: r.Mode, Recursive: r.Recursive}
	if r.Op == sandbox.OpFileWrite {
		request.Data = sandboxops.EncodeData(payload)
	}
	opCtx, cancel := context.WithTimeout(ctx, sandbox.SyncOpBudget)
	response, code, deadline := ops.call(opCtx, SandboxInstanceName(r.LeaseID), request)
	cancel()
	if err := l.base.Err(); err != nil {
		return protocol.SandboxOpReceiptV1{}, nil, ErrSandboxLaneClosed
	}
	observed := later(l.now().UTC(), decided)
	if deadline || code == sandbox.OpCodeDeadline {
		receipt, err := l.opReceipt(r, sandbox.OpStageTimedOut, sandbox.OpCodeDeadline, observed)
		return receipt, nil, err
	}
	if code != "" {
		receipt, err := l.opReceipt(r, refusedStage(code), code, observed)
		return receipt, nil, err
	}
	receipt, err := l.opBase(r, sandbox.OpStageCompleted, observed)
	if err != nil {
		return protocol.SandboxOpReceiptV1{}, nil, err
	}
	var result []byte
	switch r.Op {
	case sandbox.OpFileRead:
		result = response.Bytes()
		next := *r.Offset + uint64(len(result))
		receipt.NextOffset, receipt.EOF = &next, next >= *response.Size
	case sandbox.OpFileList:
		if result, err = organic.Canonical(*response.Listing); err != nil || len(result) > sandbox.MaxChunkBytes {
			receipt, err := l.opReceipt(r, sandbox.OpStageFailed, sandbox.OpCodeSandboxFailed, observed)
			return receipt, nil, err
		}
		next := *r.Offset + uint64(len(response.Listing.Entries))
		receipt.NextOffset, receipt.EOF = &next, response.EOF
	case sandbox.OpFileWrite, sandbox.OpFileStat, sandbox.OpFileMkdir:
		file := *response.File
		receipt.File = &file
	}
	if result != nil {
		digest := protocol.SandboxContentDigestV1(result)
		receipt.ResultDigest, receipt.ResultBytes = &digest, uint64(len(result))
	}
	return receipt, result, l.signOp(&receipt)
}

// --- exec operations ---

// execStart admits an exec_start. The first admission answers running at
// once (R1: admitted and not known to have ended; B_exec = 0) and hands the
// start to a background start owner; a replay answers from durable state.
func (l *SandboxLane) execStart(ctx context.Context, ops *sandboxOps, r protocol.SandboxOpRequestV1, command sandbox.ExecCommand) (protocol.SandboxOpReceiptV1, error) {
	opID := protocol.SandboxOpIDV1(r)
	// The exec is known to the lane before it can be admitted, so a read
	// that finds the durable row always finds this entry too.
	expires, _ := time.Parse(time.RFC3339Nano, r.ExpiresAt)
	exec := &opExec{leaseID: r.LeaseID, instance: SandboxInstanceName(r.LeaseID),
		timeout: time.Duration(*r.TimeoutMS) * time.Millisecond, maxOutput: *r.MaxOutputBytes, requestExpires: expires}
	ops.mu.Lock()
	if existing := ops.execs[opID]; existing != nil {
		exec = existing
	} else {
		ops.execs[opID] = exec
	}
	ops.mu.Unlock()
	stateCtx, cancel := ops.state(ctx)
	admission, err := ops.store.AdmitOp(stateCtx, r)
	err = l.durableErr(stateCtx, err)
	cancel()
	if err == nil && !admission.Start && !admission.Replay {
		// Refused: never admitted, so nothing can start under opID. A failed
		// admission may have committed, so its entry stays for the replay
		// that adopts it.
		ops.mu.Lock()
		if ops.execs[opID] == exec && !exec.isOwned() {
			delete(ops.execs, opID)
		}
		ops.mu.Unlock()
	}
	if err != nil {
		if !exec.isOwned() {
			// The admission may or may not have committed. Once its window
			// closed no admission of this op ID can happen any more, and the
			// durable row decides: none, the entry is dropped; one that no
			// owner took, it ends failed (never started).
			l.armResolve(ops, opID, exec, exec.requestExpires.Sub(l.now().UTC()))
		}
		return protocol.SandboxOpReceiptV1{}, err
	}
	switch {
	case admission.Unavailable != nil:
		return l.leaseRefusal(r, admission.Unavailable, admission.DecidedAt)
	case admission.Limited:
		return l.opReceipt(r, sandbox.OpStageRefused, "exec_limit_exceeded", admission.DecidedAt)
	case admission.Replay:
		// An admission whose answer was lost before any start owner ran
		// (its durable step failed after committing) is started now, once.
		l.launchStart(ops, opID, exec, admission.AdmittedAt, command)
		return l.execAnswer(ctx, ops, r, opID, nil)
	}
	l.launchStart(ops, opID, exec, admission.AdmittedAt, command)
	status := exec.status(sandbox.ExecStateRunning, admission.AdmittedAt, admission.AdmittedAt)
	receipt, err := l.opBase(r, sandbox.OpStageRunning, later(l.now().UTC(), admission.DecidedAt))
	if err != nil {
		return protocol.SandboxOpReceiptV1{}, err
	}
	receipt.Exec = status
	return receipt, l.signOp(&receipt)
}

// launchStart hands an admitted exec to its one start owner, unless one was
// launched already. D2: the owner is detached from the request after durable
// admission and runs under the lane's track; a Close before its backend call
// writes nothing (Recover ends the lease).
func (l *SandboxLane) launchStart(ops *sandboxOps, opID string, exec *opExec, admittedAt time.Time, command sandbox.ExecCommand) {
	exec.mu.Lock()
	if exec.owned {
		exec.mu.Unlock()
		return
	}
	exec.owned, exec.admittedAt = true, admittedAt
	if exec.resolveTimer != nil {
		// A resolution armed for a failed admission is moot: this owner
		// takes the exec.
		exec.resolveTimer.Stop()
	}
	exec.mu.Unlock()
	if work, done, err := l.track(l.base); err == nil {
		go func() {
			defer done()
			l.startOwner(work, ops, opID, exec, command)
		}()
	}
}

func (e *opExec) isOwned() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.owned
}

func (e *opExec) cancelRequested() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.cancelPending
}

// execState reads an exec's durable state, retrying a D_state expiry while
// the lane is open.
func (l *SandboxLane) execState(ctx context.Context, ops *sandboxOps, opID string) (durable.SandboxExecLookup, time.Time, error) {
	var err error
	for attempt := 0; attempt < durableAttempts && l.base.Err() == nil; attempt++ {
		stateCtx, cancel := ops.state(ctx)
		lookup, leaseExpiry, readErr := ops.store.ExecState(stateCtx, opID)
		cancel()
		if readErr == nil {
			return lookup, leaseExpiry, nil
		}
		err = readErr
	}
	if err == nil {
		err = ErrSandboxLaneClosed
	}
	return durable.SandboxExecLookup{}, time.Time{}, err
}

// armResolve schedules, after delay, the resolution of an exec whose durable
// state a step could not read or write, or whose admission answered an
// error. It reads the durable state (retrying D_state) and acts on it:
//
//   - the store still fails: try again after D_state, while the lane holds
//     the entry (lease teardown drops it with forgetOps);
//   - no durable row: the admission never committed; once its request
//     window closed the entry is dropped;
//   - admitted and no start owner took it: a replay may still adopt it
//     until the window closes; then it ends failed, never started;
//   - admitted with an owner that could not read or record (nothing was
//     started, or what started was killed by identity): it ends failed,
//     or cancelled when a tenant's cancel is pending;
//   - running: the deadline is armed; at a lease that has just reached its
//     expiry (leaseExpiring) that is the kill path at once;
//   - terminal, or the lease no longer runs ops for another reason: nothing
//     (teardown).
//
// One resolution timer per exec, separate from its deadline timer, which it
// never stops; each try runs once per D_state at most.
func (l *SandboxLane) armResolve(ops *sandboxOps, opID string, exec *opExec, delay time.Duration) {
	if l.base.Err() != nil {
		return
	}
	exec.mu.Lock()
	defer exec.mu.Unlock()
	if exec.resolveTimer != nil {
		exec.resolveTimer.Stop()
	}
	exec.resolveTimer = time.AfterFunc(max(delay, 0), func() {
		work, done, err := l.track(l.base)
		if err != nil {
			return
		}
		defer done()
		if ops.execEntry(opID) != exec {
			return
		}
		lookup, leaseExpiry, err := l.execState(work, ops, opID)
		switch {
		case err != nil:
			l.armResolve(ops, opID, exec, ops.config.StateTimeout)
			return
		case !lookup.Found:
			if lookup.DecidedAt.Before(exec.requestExpires) {
				l.armResolve(ops, opID, exec, exec.requestExpires.Sub(lookup.DecidedAt))
				return
			}
			ops.mu.Lock()
			if ops.execs[opID] == exec && !exec.isOwned() {
				delete(ops.execs, opID)
			}
			ops.mu.Unlock()
			return
		case lookup.Unavailable != nil && !leaseExpiring(lookup) || execTerminal[lookup.State]:
			return
		case lookup.State == "admitted":
			exec.mu.Lock()
			if !exec.owned && !lookup.DecidedAt.Before(exec.requestExpires) {
				// No replay can adopt it any more: claim it so none starts.
				exec.owned, exec.gaveUp, exec.admittedAt = true, true, lookup.AdmittedAt
			}
			owned, gaveUp := exec.owned, exec.gaveUp
			exec.mu.Unlock()
			switch {
			case !owned:
				l.armResolve(ops, opID, exec, exec.requestExpires.Sub(lookup.DecidedAt))
			case !gaveUp:
				// A start owner is at work and records the outcome itself.
			default:
				state, code := sandbox.ExecStateFailed, failure(sandbox.OpCodeSandboxFailed)
				if exec.cancelRequested() {
					state, code = sandbox.ExecStateCancelled, nil
				}
				if _, err := l.recordExec(work, ops, opID, exec, state, code); err != nil {
					l.armResolve(ops, opID, exec, ops.config.StateTimeout)
				}
			}
		default:
			l.armDeadline(ops, opID, exec, exec.deadline(leaseExpiry).Sub(lookup.DecidedAt))
		}
	})
}

// giveUp hands an exec whose start owner could not read or record its state
// to armResolve: once the store answers, an exec still admitted ends failed
// (it was never started, or what started was killed by identity).
func (l *SandboxLane) giveUp(ops *sandboxOps, opID string, exec *opExec) {
	exec.mu.Lock()
	exec.gaveUp = true
	exec.mu.Unlock()
	l.armResolve(ops, opID, exec, ops.config.StateTimeout)
}

// startOwner issues the one backend start of an admitted exec and records
// what it observed (OPS-U3 DP-5, D2-D4, INT-OPS-02).
func (l *SandboxLane) startOwner(ctx context.Context, ops *sandboxOps, opID string, exec *opExec, command sandbox.ExecCommand) {
	lookup, leaseExpiry, err := l.execState(ctx, ops, opID)
	if err != nil {
		// Nothing was started. The exec ends failed once the store answers
		// again; it is never started late.
		slog.Warn("sandbox exec start state", "exec_id", opID, "error", err)
		l.giveUp(ops, opID, exec)
		return
	}
	if !lookup.Found || lookup.Unavailable != nil || lookup.State != "admitted" {
		return
	}
	if exec.cancelRequested() {
		// A tenant cancelled the exec before its start: it is never started;
		// the kill path records it cancelled.
		l.killPath(ctx, ops, opID, exec, sandbox.ExecStateCancelled)
		return
	}
	deadline := exec.deadline(leaseExpiry)
	if !lookup.DecidedAt.Before(deadline) {
		// D4: the deadline passed before the call; no process.
		if _, err := l.recordExec(ctx, ops, opID, exec, sandbox.ExecStateTimedOut, nil); err != nil {
			l.giveUp(ops, opID, exec)
		}
		return
	}
	remaining := deadline.Sub(lookup.DecidedAt)
	// The helper's own timer gets the exec's own bound. The lease expiry
	// bound stays with the lane's deadline (armDeadline), which renewals
	// move; lease end destroys the sandbox in any case.
	own := exec.admittedAt.Add(exec.timeout).Sub(lookup.DecidedAt)
	startCtx, cancelStart := context.WithTimeout(ctx, min(ops.config.StartResolution, remaining))
	response, code, timedOut := ops.call(startCtx, exec.instance, sandboxops.Request{Op: sandbox.OpExecStart, ExecID: &opID,
		Exec: &sandboxops.ExecSpec{Command: command, MaxOutputBytes: exec.maxOutput, TimeoutMS: uint64(max(own.Milliseconds(), 1))}})
	cancelStart()
	if l.base.Err() != nil {
		// Close during the call: Recover ends the lease; write nothing.
		return
	}
	switch {
	case timedOut || code == sandbox.OpCodeDeadline:
		// Not confirmed by D_start: failed, and killed by identity in case
		// the start did happen.
		l.recordFailed(ctx, ops, opID, exec, sandbox.OpCodeSandboxFailed)
		l.killByIdentity(ctx, ops, opID, exec)
		return
	case code != "" && response.Exec == nil:
		if code == "exec_not_found" {
			code = sandbox.OpCodeSandboxFailed
		}
		l.recordFailed(ctx, ops, opID, exec, code)
		return
	}
	exec.observe(*response.Exec)
	state := response.Exec.State
	if state == sandbox.ExecStateFailed {
		failed := sandbox.OpCodeSandboxFailed
		if code != "" {
			failed = code
		}
		l.recordFailed(ctx, ops, opID, exec, failed)
		return
	}
	switch applied, err := l.recordExec(ctx, ops, opID, exec, sandbox.ExecStateRunning, nil); {
	case err != nil:
		// The start happened but could not be recorded: end it rather than
		// leave a process the lane does not track.
		l.killByIdentity(ctx, ops, opID, exec)
		l.recordFailed(ctx, ops, opID, exec, sandbox.OpCodeSandboxFailed)
		return
	case !applied:
		// INT-OPS-02: the exec ended (cancel, D_start) before the start
		// was confirmed; kill what may have started and never sign running.
		l.killByIdentity(ctx, ops, opID, exec)
		return
	}
	if state != sandbox.ExecStateRunning {
		l.recordExec(ctx, ops, opID, exec, state, nil)
		return
	}
	if exec.cancelRequested() {
		// The start was already under way when a tenant cancelled: end it
		// now, not at its deadline.
		l.killPath(ctx, ops, opID, exec, sandbox.ExecStateCancelled)
		return
	}
	l.armDeadline(ops, opID, exec, deadline.Sub(lookup.DecidedAt))
}

// recordFailed records a start failure; when the store stays unavailable the
// exec is resolved once it answers again (armResolve).
func (l *SandboxLane) recordFailed(ctx context.Context, ops *sandboxOps, opID string, exec *opExec, code string) {
	if _, err := l.recordExec(ctx, ops, opID, exec, sandbox.ExecStateFailed, failure(code)); err != nil {
		l.giveUp(ops, opID, exec)
	}
}

func failure(code string) *string { return &code }

// stopTimers stops the exec's deadline and resolution timers; the caller
// holds e.mu.
func (e *opExec) stopTimers() {
	for _, timer := range []*time.Timer{e.deadlineTimer, e.resolveTimer} {
		if timer != nil {
			timer.Stop()
		}
	}
}

// endState is the terminal state to record for an end the helper observed.
// The helper turns every exec_cancel into SIGTERM to its supervisor, which
// then reports cancelled, whoever asked. Once the lane's own deadline kill
// signalled the exec, that end is the deadline's: timed_out.
func (e *opExec) endState(observed string) string {
	e.mu.Lock()
	defer e.mu.Unlock()
	if observed == sandbox.ExecStateCancelled && e.killTrigger == sandbox.ExecStateTimedOut {
		return sandbox.ExecStateTimedOut
	}
	return observed
}

// deadline is min(admitted_at + timeout_ms, lease expiry) (R1).
func (e *opExec) deadline(leaseExpiry time.Time) time.Time {
	deadline := e.admittedAt.Add(e.timeout)
	if !leaseExpiry.IsZero() && leaseExpiry.Before(deadline) {
		deadline = leaseExpiry
	}
	return deadline
}

// observe keeps the latest helper observation, re-capped to the exec's
// retention bound; guest code can write the counts (B-5).
func (e *opExec) observe(observation sandboxops.ExecObservation) {
	e.mu.Lock()
	defer e.mu.Unlock()
	observation.StdoutRetained = min(observation.StdoutRetained, e.maxOutput)
	observation.StderrRetained = min(observation.StderrRetained, e.maxOutput)
	// Counts never go backwards within one exec.
	e.observed.StdoutRetained = max(e.observed.StdoutRetained, observation.StdoutRetained)
	e.observed.StderrRetained = max(e.observed.StderrRetained, observation.StderrRetained)
	e.observed.StdoutBytes = max(e.observed.StdoutBytes, observation.StdoutBytes, e.observed.StdoutRetained)
	e.observed.StderrBytes = max(e.observed.StderrBytes, observation.StderrBytes, e.observed.StderrRetained)
	if observation.State == sandbox.ExecStateExited && observation.ExitCode != nil && e.exitCode == nil {
		code := *observation.ExitCode
		e.exitCode = &code
	}
}

// status is the receipt's exec member in state, observed at observed.
// admittedAt is the durable admission time (R1: started_at).
func (e *opExec) status(state string, admittedAt, observed time.Time) *sandbox.ExecStatus {
	e.mu.Lock()
	defer e.mu.Unlock()
	status := &sandbox.ExecStatus{State: state, StartedAt: *protocol.StaticTime(admittedAt),
		StdoutBytes: e.observed.StdoutBytes, StdoutRetained: e.observed.StdoutRetained,
		StderrBytes: e.observed.StderrBytes, StderrRetained: e.observed.StderrRetained}
	if state != sandbox.ExecStateRunning {
		ended := e.endedAt
		if ended.IsZero() || ended.After(observed) {
			ended = observed
		}
		status.EndedAt = protocol.StaticTime(later(ended, admittedAt))
	}
	if state == sandbox.ExecStateExited {
		code := 0
		if e.exitCode != nil {
			code = *e.exitCode
		}
		status.ExitCode = &code
	}
	return status
}

// endAdmitted records the end of an exec that has not started, while it is
// still admitted (durable RecordAdmittedExecEnd), retrying a D_state expiry
// while the lane is open. It reports false, having written nothing, once the
// exec's row moved on.
func (l *SandboxLane) endAdmitted(ctx context.Context, ops *sandboxOps, opID string, exec *opExec, state string) (bool, error) {
	err := ErrSandboxLaneClosed
	for attempt := 0; attempt < durableAttempts && l.base.Err() == nil; attempt++ {
		stateCtx, cancel := ops.state(ctx)
		var applied bool
		applied, err = ops.store.RecordAdmittedExecEnd(stateCtx, opID, state)
		cancel()
		if err == nil {
			if applied {
				l.markEnded(exec)
			}
			return applied, nil
		}
		slog.Warn("sandbox exec state", "exec_id", opID, "state", state, "attempt", attempt+1, "error", err)
	}
	return false, err
}

// markEnded notes that an exec has ended: its end time is set once, and its
// deadline and resolution timers stop.
func (l *SandboxLane) markEnded(exec *opExec) {
	exec.mu.Lock()
	defer exec.mu.Unlock()
	if exec.endedAt.IsZero() {
		exec.endedAt = later(l.now().UTC(), exec.admittedAt)
	}
	exec.stopTimers()
}

// recordExec stores a transition and reports whether it was applied. A
// transition the store refuses (the exec is already terminal) is not an
// error: the first terminal state wins. Any other failure is retried while
// the lane is open; err reports a transition whose outcome stayed unknown.
func (l *SandboxLane) recordExec(ctx context.Context, ops *sandboxOps, opID string, exec *opExec, state string, code *string) (bool, error) {
	err := ErrSandboxLaneClosed
	for attempt := 0; attempt < durableAttempts && l.base.Err() == nil; attempt++ {
		stateCtx, cancel := ops.state(ctx)
		err = ops.store.RecordExecState(stateCtx, opID, state, code)
		cancel()
		if err == nil || errors.Is(err, durable.ErrSandboxExecTransition) {
			break
		}
		slog.Warn("sandbox exec state", "exec_id", opID, "state", state, "attempt", attempt+1, "error", err)
	}
	switch {
	case errors.Is(err, durable.ErrSandboxExecTransition):
		return false, nil
	case err != nil:
		return false, err
	}
	if state != sandbox.ExecStateRunning {
		l.markEnded(exec)
	}
	return true, nil
}

// armDeadline schedules the kill path after delay, the time from a durable
// decision to the exec deadline on the same clock. The wait itself is not
// tracked; each kill step is. While a tenant's cancel is pending the kill
// path is that cancel: it runs after D_state at most, never at the exec's
// deadline, and a renewal that moved the deadline does not re-arm it.
func (l *SandboxLane) armDeadline(ops *sandboxOps, opID string, exec *opExec, delay time.Duration) {
	exec.mu.Lock()
	defer exec.mu.Unlock()
	if exec.cancelPending {
		delay = min(delay, ops.config.StateTimeout)
	}
	if exec.deadlineTimer != nil {
		exec.deadlineTimer.Stop()
	}
	exec.deadlineTimer = time.AfterFunc(max(delay, 0), func() {
		work, done, err := l.track(l.base)
		if err != nil {
			return
		}
		defer done()
		if ops.execEntry(opID) != exec {
			return // the lease was torn down
		}
		lookup, leaseExpiry, err := l.execState(work, ops, opID)
		switch {
		case err != nil:
			// The store did not answer: the deadline stays armed and is
			// tried again after D_state.
			l.armDeadline(ops, opID, exec, ops.config.StateTimeout)
			return
		case !lookup.Found || lookup.Unavailable != nil && !leaseExpiring(lookup):
			// Released, failed or in cleanup: teardown ends the exec.
			return
		}
		// A renewal may have moved the lease expiry; the deadline never
		// passes admitted_at + timeout_ms. A lease past its expiry whose
		// teardown has not begun is the lease-expiry deadline itself.
		if next := exec.deadline(leaseExpiry); next.After(lookup.DecidedAt) && !exec.cancelRequested() {
			l.armDeadline(ops, opID, exec, next.Sub(lookup.DecidedAt))
			return
		}
		l.killPath(work, ops, opID, exec, sandbox.ExecStateTimedOut)
	})
}

// leaseExpiring reports a lookup whose lease runs ops no longer only because
// its expiry passed: still running, its teardown not begun. The exec deadline
// min(admitted_at + timeout_ms, lease expiry) has then been reached, and the
// kill path must still SIGTERM the exec rather than leave it to teardown.
func leaseExpiring(lookup durable.SandboxExecLookup) bool {
	return lookup.Unavailable != nil && lookup.Unavailable.Status == "running" && !lookup.DecidedAt.Before(lookup.Unavailable.ExpiresAt)
}

// killByIdentity ends whatever may run under opID without recording a state.
func (l *SandboxLane) killByIdentity(ctx context.Context, ops *sandboxOps, opID string, exec *opExec) {
	killCtx, cancel := context.WithTimeout(ctx, sandbox.ExecKillGrace)
	defer cancel()
	ops.call(killCtx, exec.instance, sandboxops.Request{Op: sandbox.OpExecCancel, ExecID: &opID, Force: true})
}

var execTerminal = map[string]bool{sandbox.ExecStateExited: true, sandbox.ExecStateCancelled: true, sandbox.ExecStateTimedOut: true, sandbox.ExecStateFailed: true}

// killPath is B-7 / DP-13 L2: cancel through the helper (SIGTERM to the
// group, SIGKILL after ExecKillGrace), wait ExecKillGrace plus KillGrace for
// a terminal observation, cancel once more by force if none came, then record
// the terminal state and release the cap slot whether or not the helper
// confirmed. Guest code can stop the helper (B-5), so every helper call is
// bounded: the cancel and the status polls by the grace window together, the
// forced cancel by ExecKillGrace. It acts only on execs of a live lease
// (U3-L8-1), or of a lease that has just reached its expiry, whose deadline
// it enforces (leaseExpiring).
//
// A deadline kill decides from its own read, the last one before the exec is
// signalled, and re-arms instead when that read shows a later deadline.
// Renewals decide on the same ops store clock, ordered against every read by
// its single connection (SandboxOps.RenewLease): one ordered after a read
// that found the deadline passed is decided past the expiry and not
// applied. A helper-observed cancelled after the lane's own deadline cancel
// is recorded timed_out (endState).
//
// A tenant's cancel sets the exec's pending cancel before its first read. A
// kill path that begins while a cancel is pending is that cancel, whatever
// its trigger, so a retry after a store failure (armDeadline) runs the
// cancel, not the deadline, and records cancelled. A kill path that
// signalled the exec first keeps its own cause (killTrigger).
func (l *SandboxLane) killPath(ctx context.Context, ops *sandboxOps, opID string, exec *opExec, trigger string) {
	exec.mu.Lock()
	switch {
	case trigger == sandbox.ExecStateCancelled:
		exec.cancelPending = true
	case exec.cancelPending:
		trigger = sandbox.ExecStateCancelled
	}
	exec.mu.Unlock()
	exec.kill.Lock()
	defer exec.kill.Unlock()
	lookup, leaseExpiry, err := l.execState(ctx, ops, opID)
	if err != nil {
		// The store did not answer: try again after D_state.
		l.armDeadline(ops, opID, exec, ops.config.StateTimeout)
		return
	}
	if !lookup.Found || lookup.Unavailable != nil && !leaseExpiring(lookup) || execTerminal[lookup.State] {
		return
	}
	if trigger == sandbox.ExecStateTimedOut {
		if next := exec.deadline(leaseExpiry); next.After(lookup.DecidedAt) {
			l.armDeadline(ops, opID, exec, next.Sub(lookup.DecidedAt))
			return
		}
	}
	if lookup.State == "admitted" {
		// Not started yet: the end is recorded only while the row is still
		// admitted, so the start owner sees the terminal row and kills by
		// identity if its start still succeeds (INT-OPS-02). A cancel that
		// could not be recorded is tried again after D_state; until then no
		// start owner starts the exec (startOwner).
		applied, err := l.endAdmitted(ctx, ops, opID, exec, trigger)
		switch {
		case err != nil:
			if trigger == sandbox.ExecStateCancelled {
				l.armDeadline(ops, opID, exec, ops.config.StateTimeout)
			}
			return
		case applied:
			return
		}
		// A start recorded the exec running first. It is running and signalled
		// below like any other running exec, so read it again.
		if lookup, leaseExpiry, err = l.execState(ctx, ops, opID); err != nil {
			l.armDeadline(ops, opID, exec, ops.config.StateTimeout)
			return
		}
		if !lookup.Found || lookup.Unavailable != nil && !leaseExpiring(lookup) || execTerminal[lookup.State] {
			return
		}
		if lookup.State == "admitted" {
			// Refused, yet still admitted: not expected, tried again later.
			l.armDeadline(ops, opID, exec, ops.config.StateTimeout)
			return
		}
	}
	exec.mu.Lock()
	if exec.killTrigger == "" {
		exec.killTrigger = trigger
	}
	exec.mu.Unlock()
	cancelRequest := sandboxops.Request{Op: sandbox.OpExecCancel, ExecID: &opID}
	grace, endGrace := context.WithTimeout(ctx, sandbox.ExecKillGrace+ops.config.KillGrace)
	ops.call(grace, exec.instance, cancelRequest)
	observed := ""
	for observed == "" && grace.Err() == nil {
		timer := time.NewTimer(killPoll)
		select {
		case <-grace.Done():
		case <-timer.C:
		}
		timer.Stop()
		if grace.Err() != nil {
			break
		}
		response, _, _ := ops.call(grace, exec.instance, sandboxops.Request{Op: sandboxops.OpExecStatus, ExecID: &opID})
		if response.Exec != nil && execTerminal[response.Exec.State] && response.Exec.State != sandbox.ExecStateFailed {
			exec.observe(*response.Exec)
			observed = response.Exec.State
		}
	}
	endGrace()
	if l.base.Err() != nil {
		return
	}
	if observed == "" {
		cancelRequest.Force = true
		forced, endForced := context.WithTimeout(ctx, sandbox.ExecKillGrace)
		ops.call(forced, exec.instance, cancelRequest)
		endForced()
		observed = trigger
	}
	if _, err := l.recordExec(ctx, ops, opID, exec, exec.endState(observed), nil); err != nil {
		// The store stayed unavailable: try the kill path again later.
		l.armDeadline(ops, opID, exec, ops.config.StateTimeout)
	}
}

// execLookup answers exec_read and exec_cancel. exec_not_found is signed at
// exactly the lookup's decision time, so it is definitive under
// SandboxExecNeverStartedV1 once that time passes the start's window.
func (l *SandboxLane) execLookup(ctx context.Context, ops *sandboxOps, r protocol.SandboxOpRequestV1, release func()) (protocol.SandboxOpReceiptV1, []byte, error) {
	stateCtx, cancel := ops.state(ctx)
	_, err := ops.store.AdmitOp(stateCtx, r)
	if err == nil {
		var lookup durable.SandboxExecLookup
		lookup, err = ops.store.LookupExec(stateCtx, r)
		err = l.durableErr(stateCtx, err)
		cancel()
		if err != nil {
			return protocol.SandboxOpReceiptV1{}, nil, err
		}
		switch {
		case lookup.Unavailable != nil:
			receipt, err := l.leaseRefusal(r, lookup.Unavailable, lookup.DecidedAt)
			return receipt, nil, err
		case !lookup.Found:
			receipt, err := l.opReceipt(r, sandbox.OpStageRefused, "exec_not_found", lookup.DecidedAt)
			return receipt, nil, err
		}
		if r.Op == sandbox.OpExecCancel {
			receipt, err := l.execCancel(ctx, ops, r, lookup, release)
			return receipt, nil, err
		}
		return l.execRead(ctx, ops, r, lookup)
	}
	err = l.durableErr(stateCtx, err)
	cancel()
	return protocol.SandboxOpReceiptV1{}, nil, err
}

// execEntry is the lane's view of exec opID; nil if the lane holds none.
func (o *sandboxOps) execEntry(opID string) *opExec {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.execs[opID]
}

// execCancel runs the kill path of a non-terminal exec. The kill path waits
// on the exec's own helper, which its guest code can stop, so the op's
// in-flight slot is released first: kill paths are bounded per exec, not by
// the agent-wide in-flight bound.
func (l *SandboxLane) execCancel(ctx context.Context, ops *sandboxOps, r protocol.SandboxOpRequestV1, lookup durable.SandboxExecLookup, release func()) (protocol.SandboxOpReceiptV1, error) {
	exec := ops.execEntry(*r.ExecID)
	if exec != nil && !execTerminal[lookup.State] {
		release()
		work, stop := l.detached(ctx)
		l.killPath(work, ops, *r.ExecID, exec, sandbox.ExecStateCancelled)
		stop()
		if l.base.Err() != nil {
			return protocol.SandboxOpReceiptV1{}, ErrSandboxLaneClosed
		}
	}
	return l.execAnswer(ctx, ops, r, *r.ExecID, nil)
}

// execAnswer signs an exec receipt from the exec's durable state.
func (l *SandboxLane) execAnswer(ctx context.Context, ops *sandboxOps, r protocol.SandboxOpRequestV1, execID string, result []byte) (protocol.SandboxOpReceiptV1, error) {
	stateCtx, cancel := ops.state(ctx)
	lookup, _, err := ops.store.ExecState(stateCtx, execID)
	err = l.durableErr(stateCtx, err)
	cancel()
	if err != nil {
		return protocol.SandboxOpReceiptV1{}, err
	}
	if lookup.Unavailable != nil {
		return l.leaseRefusal(r, lookup.Unavailable, lookup.DecidedAt)
	}
	exec := ops.execEntry(execID)
	if !lookup.Found || exec == nil {
		// The lane always holds an admitted exec of a live lease; without
		// one the outcome is not answerable here.
		return l.opReceipt(r, sandbox.OpStageFailed, sandbox.OpCodeSandboxFailed, later(l.now().UTC(), lookup.DecidedAt))
	}
	state := lookup.State
	if state == "admitted" {
		state = sandbox.ExecStateRunning
	}
	observed := later(l.now().UTC(), lookup.DecidedAt)
	stage := map[string]string{sandbox.ExecStateRunning: sandbox.OpStageRunning, sandbox.ExecStateExited: sandbox.OpStageExited,
		sandbox.ExecStateCancelled: sandbox.OpStageCancelled, sandbox.ExecStateTimedOut: sandbox.OpStageTimedOut,
		sandbox.ExecStateFailed: sandbox.OpStageFailed}[state]
	receipt, err := l.opBase(r, stage, observed)
	if err != nil {
		return protocol.SandboxOpReceiptV1{}, err
	}
	receipt.Exec = exec.status(state, lookup.AdmittedAt, observed)
	if state == sandbox.ExecStateFailed {
		code := sandbox.OpCodeSandboxFailed
		if lookup.ErrorCode != nil {
			code = *lookup.ErrorCode
		}
		receipt.ErrorCode = &code
	}
	// A read that raced the start owner recording a failure answers the
	// failure: a failed stage carries no read result.
	if result != nil && state != sandbox.ExecStateFailed {
		retained := receipt.Exec.StdoutRetained
		if *r.Stream == sandbox.ExecStderr {
			retained = receipt.Exec.StderrRetained
		}
		next := *r.Offset + uint64(len(result))
		digest := protocol.SandboxContentDigestV1(result)
		receipt.ResultDigest, receipt.ResultBytes, receipt.NextOffset = &digest, uint64(len(result)), &next
		receipt.EOF = state != sandbox.ExecStateRunning && next >= retained
	}
	return receipt, l.signOp(&receipt)
}

// execRead pages one stream. A helper-observed end is recorded first, so the
// receipt's state and eof agree with the bytes returned.
func (l *SandboxLane) execRead(ctx context.Context, ops *sandboxOps, r protocol.SandboxOpRequestV1, lookup durable.SandboxExecLookup) (protocol.SandboxOpReceiptV1, []byte, error) {
	execID := *r.ExecID
	exec := ops.execEntry(execID)
	if exec == nil {
		receipt, err := l.opReceipt(r, sandbox.OpStageFailed, sandbox.OpCodeSandboxFailed, later(l.now().UTC(), lookup.DecidedAt))
		return receipt, nil, err
	}
	if lookup.State == sandbox.ExecStateFailed {
		receipt, err := l.execAnswer(ctx, ops, r, execID, nil)
		return receipt, nil, err
	}
	data := []byte{}
	if lookup.State != "admitted" {
		// Bounded like a file op: guest code can stop the helper (B-5).
		readCtx, endRead := context.WithTimeout(ctx, sandbox.SyncOpBudget)
		response, code, _ := ops.call(readCtx, exec.instance, sandboxops.Request{Op: sandbox.OpExecRead, ExecID: &execID,
			Stream: r.Stream, Offset: r.Offset, Limit: r.Limit})
		endRead()
		if l.base.Err() != nil {
			return protocol.SandboxOpReceiptV1{}, nil, ErrSandboxLaneClosed
		}
		if code != "" || response.Exec == nil {
			if code == "" || code == "exec_not_found" || code == sandbox.OpCodeDeadline {
				code = sandbox.OpCodeSandboxFailed
			}
			receipt, err := l.opReceipt(r, refusedStage(code), code, later(l.now().UTC(), lookup.DecidedAt))
			return receipt, nil, err
		}
		exec.observe(*response.Exec)
		if lookup.State == sandbox.ExecStateRunning && execTerminal[response.Exec.State] && response.Exec.State != sandbox.ExecStateFailed {
			l.recordExec(ctx, ops, execID, exec, exec.endState(response.Exec.State), nil)
		}
		data = response.Bytes()
	}
	// Re-cap the bytes to the retained stream the receipt reports.
	status := exec.status(sandbox.ExecStateRunning, lookup.AdmittedAt, lookup.AdmittedAt)
	retained := status.StdoutRetained
	if *r.Stream == sandbox.ExecStderr {
		retained = status.StderrRetained
	}
	switch {
	case *r.Offset >= retained:
		data = []byte{}
	case *r.Offset+uint64(len(data)) > retained:
		data = data[:retained-*r.Offset]
	}
	receipt, err := l.execAnswer(ctx, ops, r, execID, data)
	if err != nil {
		return protocol.SandboxOpReceiptV1{}, nil, err
	}
	if receipt.ResultDigest == nil {
		return receipt, nil, nil
	}
	return receipt, data, nil
}

// forgetOps drops the in-memory ops state of a lease whose sandbox is being
// destroyed: its execs end with it, and its answers can no longer be asked
// for (the lease state answers instead).
func (l *SandboxLane) forgetOps(leaseID string) {
	ops := l.ops
	if ops == nil {
		return
	}
	ops.mu.Lock()
	defer ops.mu.Unlock()
	for id, exec := range ops.execs {
		if exec.leaseID == leaseID {
			exec.mu.Lock()
			exec.stopTimers()
			exec.mu.Unlock()
			delete(ops.execs, id)
		}
	}
	for id, outcome := range ops.outcomes {
		if outcome.leaseID == leaseID && outcome.timer != nil {
			outcome.timer.Stop()
			delete(ops.outcomes, id)
		}
	}
}
