// SPDX-License-Identifier: AGPL-3.0-only

package miner

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/durable"
	"github.com/misscomputer/misscomputer-subnet/pkg/protocol"
	deployruntime "github.com/misscomputer/misscomputer-subnet/pkg/runtime"
	"github.com/misscomputer/misscomputer-subnet/pkg/sandbox"
)

// SandboxBackend runs customer sandboxes for the sandbox-lease-v1 lane. A
// backend is an isolation adapter (pkg/sandboxbackend runs gVisor on a
// dedicated Docker daemon) selected explicitly; without one the lane cannot
// be enabled.
type SandboxBackend interface {
	// Budget reports what the backend enforces for all sandboxes together:
	// the dedicated cgroup v2 subtree every sandbox runs in, never shared
	// with deployment.v4 replicas, and its disk and sandbox-count limits.
	Budget(ctx context.Context) (SandboxBudget, error)
	// Unsupported returns the non-fault receipt error code with which the
	// backend refuses a lease it cannot enforce exactly (isolation,
	// network policy, resources), or "" when it can run it.
	Unsupported(lease protocol.SandboxLeaseV1) string
	// Create starts the sandbox of lease under instanceID, a deterministic
	// name derived from the lease ID. It must be idempotent per instanceID.
	// It must return when ctx is cancelled, even if startup is incomplete;
	// a later Destroy or replay of Create must settle that same instance.
	// A *SandboxRefusal reports a condition that is not the miner's fault.
	Create(ctx context.Context, instanceID string, lease protocol.SandboxLeaseV1) error
	// Destroy deletes the sandbox and everything it wrote. It must be
	// idempotent, return nil when the sandbox does not exist, and honor ctx.
	Destroy(ctx context.Context, instanceID string) error
	// Instances lists every sandbox the backend holds, whether or not the
	// lane still knows its lease, so that orphans can be destroyed.
	Instances(ctx context.Context) ([]SandboxInstance, error)
	// Reclaim frees backend storage no sandbox uses, such as cached images.
	// The lane calls it only while no Create can run.
	Reclaim(ctx context.Context) error
}

// SandboxInstance is one sandbox a backend holds: its instance name and the
// lease ID it was created for, or "" when the backend cannot tell.
type SandboxInstance struct {
	Name    string
	LeaseID string
}

// SandboxBudget is what a backend enforces for all sandboxes together.
type SandboxBudget struct {
	// Cgroup is the cgroup v2 path of the dedicated sandbox subtree; its
	// cpu.max and memory.max are the CPU and memory budget.
	Cgroup string
	// DiskMiB and Sandboxes are the disk and sandbox-count limits the
	// backend applies.
	DiskMiB   int
	Sandboxes int
}

// SandboxLaneConfig configures the lane.
type SandboxLaneConfig struct {
	// Budget is what holds are checked against and receipts report. Every
	// component must be positive and within what the backend enforces.
	Budget sandbox.Capacity
	// CgroupRoot is the cgroup v2 mount (DefaultCgroupRoot).
	CgroupRoot string
	// AgentCgroup is the miner agent's own cgroup. DeploymentCgroup is the
	// reserved cgroup subtree for deployment.v4 replicas. Both are required:
	// omitting either would make a finite sandbox budget look isolated when
	// it still overlaps another workload.
	AgentCgroup      string
	DeploymentCgroup string
}

// ErrSandboxCleanupPending answers a release whose fence is durable but
// whose sandbox could not be destroyed yet. No receipt is signed: a release
// receipt tells the validator the slot is free, so it is signed only once
// every sandbox of the identity is gone. The validator retries the same
// release; the sweep keeps destroying in the meantime.
var ErrSandboxCleanupPending = errors.New("sandbox release is fenced but its sandbox is not destroyed yet; retry the release")

// ErrSandboxLaneClosed answers a document that arrives after the lane was
// closed for shutdown. Nothing was written; the validator retries later.
var ErrSandboxLaneClosed = errors.New("sandbox lane is shutting down; retry later")

const (
	sandboxCreateTimeout  = 5 * time.Minute
	sandboxStateTimeout   = 30 * time.Second
	sandboxCleanupTimeout = 5 * time.Minute
	// sandboxCommitAnswer bounds how long Commit waits for a sandbox to start
	// before it answers accepted. It stays well below the shortest transport
	// hop between the validator runtime and this agent (about two minutes),
	// so a slow image pull is a pending lease the validator polls by
	// replaying the lease, never an unknown outcome.
	sandboxCommitAnswer = 60 * time.Second
)

// SandboxRefusal is a backend failure that is not attributed to the miner,
// such as an image that cannot be pulled.
type SandboxRefusal struct{ Code string }

func (r *SandboxRefusal) Error() string { return "sandbox refused: " + r.Code }

// SandboxLane is the miner side of sandbox-lease-v1: it admits validator
// documents, applies them to the durable lane, drives the backend, and
// signs receipts. It never reads or writes deployment.v4 or static state.
type SandboxLane struct {
	agent   *Agent
	store   *durable.SandboxLeases
	backend SandboxBackend
	budget  sandbox.Capacity
	now     func() time.Time
	locks   sandboxLocks
	starts  sandboxStarts
	// answerWithin is sandboxCommitAnswer.
	answerWithin time.Duration
	// base is cancelled by Close. Background starts run under it, and
	// every tracked operation's context ends with it.
	base   context.Context
	cancel context.CancelFunc
	// closed is closed by Close; gate orders tracking against it, so no
	// operation is added to work after Close began waiting.
	closed chan struct{}
	gate   sync.Mutex
	work   sync.WaitGroup
	// ops is the sandbox-ops-v1 extension; nil unless EnableOps succeeded.
	ops *sandboxOps
}

// NewSandboxLane enables the lane only with a backend that runs sandboxes
// in a dedicated cgroup v2 subtree whose finite CPU and memory limits, and
// whose disk and count limits, cover the configured budget. A miner
// advertises the sandbox-lease-v1 capability only once the lane exists.
func NewSandboxLane(ctx context.Context, agent *Agent, store *durable.SandboxLeases, backend SandboxBackend, config SandboxLaneConfig) (*SandboxLane, error) {
	if agent == nil || store == nil {
		return nil, errors.New("sandbox lane requires the miner agent and durable sandbox state")
	}
	if backend == nil {
		return nil, errors.New("sandbox lane requires an isolation backend")
	}
	budget := config.Budget
	if budget.CPUMillis <= 0 || budget.MemoryMiB <= 0 || budget.DiskMiB <= 0 || budget.Sandboxes <= 0 {
		return nil, errors.New("sandbox budget must be positive in every component")
	}
	enforced, err := backend.Budget(ctx)
	if err != nil {
		return nil, fmt.Errorf("sandbox backend budget: %w", err)
	}
	if config.AgentCgroup == "" || config.DeploymentCgroup == "" {
		return nil, errors.New("sandbox lane requires both agent and deployment replica cgroup paths")
	}
	limits, err := VerifySandboxCgroup(config.CgroupRoot, enforced.Cgroup, []string{config.AgentCgroup, config.DeploymentCgroup})
	if err != nil {
		return nil, err
	}
	limits.DiskMiB, limits.Sandboxes = enforced.DiskMiB, enforced.Sandboxes
	if !budget.Within(limits) {
		return nil, fmt.Errorf("sandbox budget %+v exceeds what the backend enforces %+v", budget, limits)
	}
	base, cancel := context.WithCancel(context.Background())
	return &SandboxLane{agent: agent, store: store, backend: backend, budget: budget, now: time.Now, answerWithin: sandboxCommitAnswer,
		base: base, cancel: cancel, closed: make(chan struct{})}, nil
}

// track registers one operation that holds lease locks or drives the
// backend, so that Close waits for it before the shutdown Recover. It
// refuses once the lane is closed. The returned context ends with ctx or
// when Close cancels the lane; done must be called when the operation ends.
func (l *SandboxLane) track(ctx context.Context) (context.Context, func(), error) {
	l.gate.Lock()
	defer l.gate.Unlock()
	select {
	case <-l.closed:
		return nil, nil, ErrSandboxLaneClosed
	default:
	}
	l.work.Add(1)
	tracked, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(l.base, cancel)
	return tracked, func() {
		stop()
		cancel()
		l.work.Done()
	}, nil
}

// Close stops the lane for shutdown, before Recover runs: documents that
// would start, sweep or release are refused, a Commit waiting for its start
// answers the lease's durable stage at once, and every tracked operation's
// context is cancelled. Close then waits for those operations until ctx
// ends; an operation still running then keeps its lease lock, so the
// shutdown Recover reports that lease busy and the next start's Recover
// destroys it. Close is idempotent.
func (l *SandboxLane) Close(ctx context.Context) error {
	l.gate.Lock()
	select {
	case <-l.closed:
	default:
		close(l.closed)
		l.cancel()
	}
	l.gate.Unlock()
	drained := make(chan struct{})
	go func() {
		l.work.Wait()
		close(drained)
	}()
	select {
	case <-drained:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("sandbox lane operations still running at shutdown: %w", ctx.Err())
	}
}

// SandboxInstanceName is the deterministic backend name of a lease.
func SandboxInstanceName(leaseID string) string { return deployruntime.InstanceName(leaseID) }

// SandboxRequest is the authenticated request context of one document.
type SandboxRequest struct {
	ValidatorKey ed25519.PublicKey
	CurrentBlock uint64
	Network      string
	NetUID       uint16
	CallerHotkey string
	MinerHotkey  string
	MinerUID     *uint16
}

// admit checks what the signature-and-binding verification leaves to the
// miner: the document names this agent and its exact transport identity.
func (l *SandboxLane) admit(subnet *protocol.StaticSubnetBindingV1, minerID string) error {
	if subnet.MinerServicePublicKey != hex.EncodeToString(l.agent.PublicKey()) {
		return errors.New("sandbox document miner service key does not match this agent")
	}
	if err := l.agent.validateTransportBinding(subnet.Binding()); err != nil {
		return err
	}
	if minerID != l.agent.MinerID {
		return fmt.Errorf("sandbox document addressed to %q, agent is %q", minerID, l.agent.MinerID)
	}
	return nil
}

func (l *SandboxLane) receipt(schema string, document any, sandboxID string, generation uint64, subnet *protocol.StaticSubnetBindingV1, outcome durable.SandboxOutcome, now time.Time) (protocol.SandboxReceiptV1, error) {
	digest, err := protocol.SandboxDigestV1(document)
	if err != nil {
		return protocol.SandboxReceiptV1{}, err
	}
	r := protocol.SandboxReceiptV1{
		CapacityActive: outcome.Active, CapacityHeld: outcome.Held, CapacityTotal: l.budget,
		DocumentDigest: digest, DocumentSchema: schema, ErrorCode: outcome.ErrorCode, Generation: generation,
		LeaseID: outcome.LeaseID, MinerID: l.agent.MinerID, ObservedAt: *protocol.StaticTime(now),
		RenewalSeq: outcome.RenewalSeq, SandboxID: sandboxID, Schema: protocol.SandboxReceiptSchema,
		SchemaVersion: protocol.SandboxSchemaVersion, Stage: outcome.Stage, Subnet: subnet,
	}
	if schema == protocol.SandboxReservationSchema {
		r.LeaseID, r.RenewalSeq = nil, 0
	}
	return r, protocol.SignSandboxReceiptV1(&r, l.agent.SigningKey)
}

// Reserve holds capacity for one verified reservation.
func (l *SandboxLane) Reserve(ctx context.Context, r protocol.SandboxReservationV1, req SandboxRequest) (protocol.SandboxReceiptV1, error) {
	now := l.now().UTC()
	if err := protocol.VerifyBoundSandboxReservationV1(r, req.ValidatorKey, now, req.CurrentBlock, req.Network, req.NetUID, req.CallerHotkey, req.MinerHotkey, req.MinerUID); err != nil {
		return protocol.SandboxReceiptV1{}, err
	}
	if err := l.admit(r.Subnet, r.MinerID); err != nil {
		return protocol.SandboxReceiptV1{}, err
	}
	outcome, err := l.store.Hold(ctx, r, l.budget, now)
	if err != nil {
		return protocol.SandboxReceiptV1{}, err
	}
	return l.receipt(protocol.SandboxReservationSchema, r, r.SandboxID, r.Generation, r.Subnet, outcome, now)
}

// ReplayReservation authenticates the original reservation exactly as Reserve
// does, but only observes an existing hold. It cannot touch the backend.
func (l *SandboxLane) ReplayReservation(ctx context.Context, r protocol.SandboxReservationV1, req SandboxRequest) (protocol.SandboxReceiptV1, error) {
	ctx, done, err := l.track(ctx)
	if err != nil {
		return protocol.SandboxReceiptV1{}, err
	}
	defer done()
	now := l.now().UTC()
	if err := protocol.VerifyBoundSandboxReservationV1(r, req.ValidatorKey, now, req.CurrentBlock, req.Network, req.NetUID, req.CallerHotkey, req.MinerHotkey, req.MinerUID); err != nil {
		return protocol.SandboxReceiptV1{}, err
	}
	if err := l.admit(r.Subnet, r.MinerID); err != nil {
		return protocol.SandboxReceiptV1{}, err
	}
	// Admission may itself take time (including signature verification).
	// Start the store's snapshot clock after it, not at request admission.
	outcome, err := l.store.ReplayHeldReservation(ctx, r, l.now().UTC())
	if err != nil {
		return protocol.SandboxReceiptV1{}, err
	}
	if err := ctx.Err(); err != nil {
		return protocol.SandboxReceiptV1{}, err
	}
	return l.receipt(protocol.SandboxReservationSchema, r, r.SandboxID, r.Generation, r.Subnet, outcome, outcome.ObservedAt)
}

// Commit commits a verified lease to its hold, starts its sandbox on the
// first acceptance, and resumes a pending lease on replay. The lease is
// durable as pending before the backend is asked to create anything. The
// start runs in the background under the lease lock and does not inherit
// the HTTP request's cancellation, so a disconnected validator cannot
// strand a lease after that durable write. Commit answers the start's
// outcome if it ends within answerWithin, and otherwise the durable stage
// (accepted while pending); an exact replay waits for the same start again
// instead of starting another.
func (l *SandboxLane) Commit(ctx context.Context, lease protocol.SandboxLeaseV1, req SandboxRequest) (protocol.SandboxReceiptV1, error) {
	now := l.now().UTC()
	if err := protocol.VerifyBoundSandboxLeaseV1(lease, req.ValidatorKey, now, req.CurrentBlock, req.Network, req.NetUID, req.CallerHotkey, req.MinerHotkey, req.MinerUID); err != nil {
		return protocol.SandboxReceiptV1{}, err
	}
	if err := l.admit(lease.Subnet, lease.MinerID); err != nil {
		return protocol.SandboxReceiptV1{}, err
	}
	leaseID := protocol.SandboxLeaseIDV1(lease)
	select {
	case <-l.closed:
		return protocol.SandboxReceiptV1{}, ErrSandboxLaneClosed
	default:
	}
	deadline := time.Now().Add(l.answerWithin)
	var unlock func()
	for {
		if started := l.starts.running(leaseID); started != nil {
			l.await(started)
			return l.answerCommit(ctx, lease)
		}
		var ok bool
		if unlock, ok = l.locks.tryLock(leaseID); ok {
			break
		}
		// The lease is being committed or torn down by another caller.
		// Once it is durable, its durable stage answers without the lock.
		if time.Now().After(deadline) {
			if _, found, err := l.store.Lease(ctx, leaseID); err != nil {
				return protocol.SandboxReceiptV1{}, err
			} else if found {
				return l.answerCommit(ctx, lease)
			}
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return protocol.SandboxReceiptV1{}, ctx.Err()
		case <-l.closed:
			timer.Stop()
			if _, found, err := l.store.Lease(ctx, leaseID); err != nil {
				return protocol.SandboxReceiptV1{}, err
			} else if found {
				return l.answerCommit(ctx, lease)
			}
			return protocol.SandboxReceiptV1{}, ErrSandboxLaneClosed
		case <-timer.C:
		}
	}
	outcome, err := l.store.CommitLease(ctx, lease, now)
	if err != nil || !(outcome.Start || outcome.Stage == sandbox.StageAccepted) {
		unlock()
		if err != nil {
			return protocol.SandboxReceiptV1{}, err
		}
		return l.receipt(protocol.SandboxLeaseSchema, lease, lease.SandboxID, lease.Generation, lease.Subnet, outcome, l.now().UTC())
	}
	// The start does not inherit the request's cancellation, only the
	// lane's: Close cancels it, and the shutdown Recover then ends the
	// pending lease as failed/miner_restart.
	workCtx, done, err := l.track(l.base)
	if err != nil {
		// Closed after the lease became durable: Recover ends it.
		unlock()
		return l.answerCommit(ctx, lease)
	}
	started := l.starts.begin(leaseID)
	go func() {
		defer done()
		defer unlock()
		if _, err := l.start(workCtx, lease, leaseID); err != nil {
			slog.Warn("sandbox start", "lease_id", leaseID, "error", err)
		}
		l.starts.end(leaseID, started)
	}()
	l.await(started)
	return l.answerCommit(ctx, lease)
}

// await waits for a start to end, at most answerWithin, and not past Close.
func (l *SandboxLane) await(started <-chan struct{}) {
	timer := time.NewTimer(l.answerWithin)
	defer timer.Stop()
	select {
	case <-started:
	case <-timer.C:
	case <-l.closed:
	}
}

// answerCommit answers a lease from its durable stage.
func (l *SandboxLane) answerCommit(ctx context.Context, lease protocol.SandboxLeaseV1) (protocol.SandboxReceiptV1, error) {
	answerCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), sandboxStateTimeout)
	defer cancel()
	now := l.now().UTC()
	outcome, err := l.store.CommitLease(answerCtx, lease, now)
	if err != nil {
		return protocol.SandboxReceiptV1{}, err
	}
	return l.receipt(protocol.SandboxLeaseSchema, lease, lease.SandboxID, lease.Generation, lease.Subnet, outcome, now)
}

// start runs the sandbox of a lease that was just written as pending and
// answers with its durable stage.
//
// ctx ends only when the lane closes for shutdown. A create it cancels is
// not recorded as a failed start: the lease stays pending, and the shutdown
// Recover destroys its sandbox and ends it as failed/miner_restart. The
// durable writes after the create do not inherit ctx.
func (l *SandboxLane) start(ctx context.Context, lease protocol.SandboxLeaseV1, leaseID string) (durable.SandboxOutcome, error) {
	instance := SandboxInstanceName(leaseID)
	code := l.unsupported(lease)
	workCtx := context.WithoutCancel(ctx)
	if code == "" {
		createCtx, cancel := context.WithTimeout(ctx, sandboxCreateTimeout)
		err := l.backend.Create(createCtx, instance, lease)
		cancel()
		if err != nil && ctx.Err() != nil {
			return durable.SandboxOutcome{}, fmt.Errorf("sandbox start stopped for shutdown: %w", err)
		}
		if err == nil {
			completedAt := l.now().UTC()
			// A release or sweep can move the lease to cleanup during
			// creation; promotion to running must then fail.
			stateCtx, stateCancel := context.WithTimeout(workCtx, sandboxStateTimeout)
			running, stateErr := l.store.MarkLeaseRunning(stateCtx, leaseID, completedAt)
			stateCancel()
			if stateErr == nil {
				if !running {
					// Expiry is already fenced in MarkLeaseRunning, or a
					// release/sweep moved the lease to cleanup first.
					cleanupCtx, cleanupCancel := context.WithTimeout(workCtx, sandboxCleanupTimeout)
					_ = l.teardown(cleanupCtx, leaseID, instance, completedAt)
					cleanupCancel()
				}
				if stateErr != nil {
					return durable.SandboxOutcome{}, stateErr
				}
				answerCtx, answerCancel := context.WithTimeout(workCtx, sandboxStateTimeout)
				outcome, err := l.store.CommitLease(answerCtx, lease, completedAt)
				answerCancel()
				return outcome, err
			}
			err = stateErr
		}
		code = "runtime_start_failed"
		var refusal *SandboxRefusal
		if errors.As(err, &refusal) {
			if attributed, known := sandbox.ReceiptErrorAttribution[refusal.Code]; known && !attributed {
				code = refusal.Code
			}
		}
	}
	cleanupCtx, cleanupCancel := context.WithTimeout(workCtx, sandboxCleanupTimeout)
	defer cleanupCancel()
	completedAt := l.now().UTC()
	if err := l.store.BeginLeaseCleanup(cleanupCtx, leaseID, "failed", &code, completedAt); err != nil {
		return durable.SandboxOutcome{}, err
	}
	_ = l.teardown(cleanupCtx, leaseID, instance, completedAt)
	// An exact replay of the lease answers from the durable row.
	return l.store.CommitLease(cleanupCtx, lease, completedAt)
}

// unsupported is the non-fault refusal of a lease the lane or backend
// cannot honour exactly. Sealed secret delivery does not exist yet, so every
// lease that declares customer environment is refused.
func (l *SandboxLane) unsupported(lease protocol.SandboxLeaseV1) string {
	if lease.SecretEnv.Delivery != sandbox.SecretDeliveryNone {
		return "secret_delivery_unsupported"
	}
	code := l.backend.Unsupported(lease)
	if code == "" {
		return ""
	}
	if attributed, known := sandbox.ReceiptErrorAttribution[code]; !known || attributed {
		// A backend cannot turn its own fault into a non-fault refusal.
		return "runtime_start_failed"
	}
	return code
}

// teardown destroys a lease's sandbox and closes its cleanup. A failed
// destroy leaves the lease in cleanup, still consuming capacity, for the
// next Sweep or Recover to retry.
func (l *SandboxLane) teardown(ctx context.Context, leaseID, instance string, now time.Time) error {
	l.forgetOps(leaseID)
	if err := l.backend.Destroy(ctx, instance); err != nil {
		return fmt.Errorf("destroy sandbox %s: %w", leaseID, err)
	}
	return l.store.CompleteLeaseCleanup(ctx, leaseID, now)
}

// Renew applies a verified renewal of a live lease.
func (l *SandboxLane) Renew(ctx context.Context, r protocol.SandboxRenewalV1, req SandboxRequest) (protocol.SandboxReceiptV1, error) {
	now := l.now().UTC()
	if err := protocol.VerifyBoundSandboxRenewalV1(r, req.ValidatorKey, now, req.CurrentBlock, req.Network, req.NetUID, req.CallerHotkey, req.MinerHotkey, req.MinerUID); err != nil {
		return protocol.SandboxReceiptV1{}, err
	}
	if err := l.admit(r.Subnet, r.MinerID); err != nil {
		return protocol.SandboxReceiptV1{}, err
	}
	outcome, err := l.store.Renew(ctx, r, now)
	if err != nil {
		return protocol.SandboxReceiptV1{}, err
	}
	return l.receipt(protocol.SandboxRenewalSchema, r, r.SandboxID, r.Generation, r.Subnet, outcome, now)
}

// Release fences the identity of a verified release, then destroys every
// sandbox of the identity that is in cleanup. The released receipt is
// signed only after every one of them is destroyed. If a destroy fails, the
// fence stays durable, the sandbox keeps consuming capacity, and Release
// returns ErrSandboxCleanupPending without a receipt; an exact replay of
// the release retries the destroy.
func (l *SandboxLane) Release(ctx context.Context, r protocol.SandboxReleaseV1, req SandboxRequest) (protocol.SandboxReceiptV1, error) {
	now := l.now().UTC()
	if err := protocol.VerifyBoundSandboxReleaseV1(r, req.ValidatorKey, now, req.CurrentBlock, req.Network, req.NetUID, req.CallerHotkey, req.MinerHotkey, req.MinerUID); err != nil {
		return protocol.SandboxReceiptV1{}, err
	}
	if err := l.admit(r.Subnet, r.MinerID); err != nil {
		return protocol.SandboxReceiptV1{}, err
	}
	ctx, done, err := l.track(ctx)
	if err != nil {
		return protocol.SandboxReceiptV1{}, err
	}
	defer done()
	// The fence and the occupancy read are short local steps that do not
	// stop when Close cancels the release, so a release admitted before
	// Close is answered cleanup_pending (fenced, destroy unfinished) or
	// released, never with a bare cancellation. Only the destroy stops at
	// Close; the shutdown Recover finishes it.
	stateCtx, cancelState := context.WithTimeout(context.WithoutCancel(ctx), sandboxStateTimeout)
	defer cancelState()
	outcome, teardown, err := l.store.Release(stateCtx, r, now)
	if err != nil {
		return protocol.SandboxReceiptV1{}, err
	}
	if len(teardown) > 0 {
		if err := l.destroyAll(ctx, teardown, now); err != nil {
			return protocol.SandboxReceiptV1{}, fmt.Errorf("%w: %v", ErrSandboxCleanupPending, err)
		}
		if outcome.Held, outcome.Active, err = l.store.Occupancy(stateCtx, now); err != nil {
			return protocol.SandboxReceiptV1{}, err
		}
	}
	return l.receipt(protocol.SandboxReleaseSchema, r, r.SandboxID, r.Generation, r.Subnet, outcome, now)
}

// Sweep expires unused holds, moves leases past expiry plus grace to
// cleanup, destroys every sandbox in cleanup, and destroys orphans. Run it
// periodically.
func (l *SandboxLane) Sweep(ctx context.Context) error {
	ctx, done, err := l.track(ctx)
	if err != nil {
		return err
	}
	defer done()
	now := l.now().UTC()
	records, err := l.store.Sweep(ctx, now)
	if err != nil {
		return err
	}
	return errors.Join(l.destroyAll(ctx, records, now), l.destroyOrphans(ctx))
}

// Recover is the restart path: before the lane serves, every sandbox that
// may exist is destroyed, its lease answers failed/miner_restart, sandboxes
// without a live lease are destroyed, and unused backend storage is freed.
func (l *SandboxLane) Recover(ctx context.Context) error {
	now := l.now().UTC()
	records, err := l.store.Recover(ctx, now)
	if err != nil {
		return err
	}
	if err := errors.Join(l.destroyAll(ctx, records, now), l.destroyOrphans(ctx)); err != nil {
		return err
	}
	return l.backend.Reclaim(ctx)
}

// destroyOrphans destroys every backend sandbox whose lease is unknown or
// terminal. Each is re-read under its lease lock, so a sandbox whose lease
// Commit is creating concurrently is never mistaken for an orphan: Commit
// writes the lease as pending under the same lock before Create runs, and
// a lease whose lock is held is skipped until the next sweep.
func (l *SandboxLane) destroyOrphans(ctx context.Context) error {
	instances, err := l.backend.Instances(ctx)
	if err != nil {
		return fmt.Errorf("list sandboxes: %w", err)
	}
	var errs []error
	for _, instance := range instances {
		key := instance.LeaseID
		if key == "" || SandboxInstanceName(key) != instance.Name {
			// A sandbox the backend cannot tie to a lease is never live.
			key = "instance:" + instance.Name
		}
		unlock, ok := l.locks.tryLock(key)
		if !ok {
			// Busy: being started or destroyed, so not an orphan now.
			continue
		}
		live := false
		if key == instance.LeaseID {
			record, found, err := l.store.Lease(ctx, instance.LeaseID)
			if err != nil {
				unlock()
				errs = append(errs, err)
				continue
			}
			live = found && (record.Status == "pending" || record.Status == "running" || record.Status == "cleanup")
		}
		if !live {
			if err := l.backend.Destroy(ctx, instance.Name); err != nil {
				errs = append(errs, fmt.Errorf("destroy orphan sandbox %s: %w", instance.Name, err))
			}
		}
		unlock()
	}
	return errors.Join(errs...)
}

// destroyAll tears down every record whose lease is not busy. A busy lease
// is being started (its start tears it down once it sees the cleanup) or
// destroyed by another caller; it is reported as pending, not waited for.
func (l *SandboxLane) destroyAll(ctx context.Context, records []durable.SandboxLeaseRecord, now time.Time) error {
	var errs []error
	for _, record := range records {
		unlock, ok := l.locks.tryLock(record.LeaseID)
		if !ok {
			errs = append(errs, fmt.Errorf("sandbox %s is busy", record.LeaseID))
			continue
		}
		if err := l.teardown(ctx, record.LeaseID, SandboxInstanceName(record.LeaseID), now); err != nil {
			errs = append(errs, err)
		}
		unlock()
	}
	return errors.Join(errs...)
}

// sandboxLocks serializes the runtime work of one lease, so a release or
// sweep destroys a sandbox only after a concurrent create has returned.
type sandboxLocks struct {
	mu    sync.Mutex
	locks map[string]*sandboxLock
}

type sandboxLock struct {
	mu   sync.Mutex
	refs int
}

func (s *sandboxLocks) lock(key string) func() {
	entry := s.acquire(key)
	entry.mu.Lock()
	return func() {
		entry.mu.Unlock()
		s.release(key, entry)
	}
}

// tryLock locks key only if no one holds it.
func (s *sandboxLocks) tryLock(key string) (func(), bool) {
	entry := s.acquire(key)
	if !entry.mu.TryLock() {
		s.release(key, entry)
		return nil, false
	}
	return func() {
		entry.mu.Unlock()
		s.release(key, entry)
	}, true
}

func (s *sandboxLocks) acquire(key string) *sandboxLock {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.locks == nil {
		s.locks = map[string]*sandboxLock{}
	}
	entry := s.locks[key]
	if entry == nil {
		entry = &sandboxLock{}
		s.locks[key] = entry
	}
	entry.refs++
	return entry
}

func (s *sandboxLocks) release(key string, entry *sandboxLock) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry.refs--
	if entry.refs == 0 {
		delete(s.locks, key)
	}
}

// sandboxStarts tracks the lease starts running in the background; each
// channel closes when its start ends.
type sandboxStarts struct {
	mu       sync.Mutex
	inflight map[string]chan struct{}
}

func (s *sandboxStarts) begin(leaseID string) chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.inflight == nil {
		s.inflight = map[string]chan struct{}{}
	}
	started := make(chan struct{})
	s.inflight[leaseID] = started
	return started
}

func (s *sandboxStarts) end(leaseID string, started chan struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.inflight, leaseID)
	close(started)
}

func (s *sandboxStarts) running(leaseID string) <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	if started, ok := s.inflight[leaseID]; ok {
		return started
	}
	return nil
}
