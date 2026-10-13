// SPDX-License-Identifier: AGPL-3.0-only

package miner

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/durable"
	"github.com/misscomputer/misscomputer-subnet/pkg/protocol"
	deployruntime "github.com/misscomputer/misscomputer-subnet/pkg/runtime"
	"github.com/misscomputer/misscomputer-subnet/pkg/sandbox"
)

// SandboxBackend runs customer sandboxes for the sandbox-lease-v1 lane. No
// implementation ships with this lane: a backend is an isolation adapter
// (gVisor, Kata or Firecracker) selected separately, and without one the
// lane cannot be enabled.
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
	// A *SandboxRefusal reports a condition that is not the miner's fault.
	Create(ctx context.Context, instanceID string, lease protocol.SandboxLeaseV1) error
	// Destroy deletes the sandbox and everything it wrote. It must be
	// idempotent and return nil when the sandbox does not exist.
	Destroy(ctx context.Context, instanceID string) error
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
	// ExclusiveOf lists cgroups the sandbox subtree must be disjoint from:
	// the miner agent's own and the one deployment.v4 replicas run in.
	ExclusiveOf []string
}

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
	limits, err := VerifySandboxCgroup(config.CgroupRoot, enforced.Cgroup, config.ExclusiveOf)
	if err != nil {
		return nil, err
	}
	limits.DiskMiB, limits.Sandboxes = enforced.DiskMiB, enforced.Sandboxes
	if !budget.Within(limits) {
		return nil, fmt.Errorf("sandbox budget %+v exceeds what the backend enforces %+v", budget, limits)
	}
	return &SandboxLane{agent: agent, store: store, backend: backend, budget: budget, now: time.Now}, nil
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

// Commit commits a verified lease to its hold, starts its sandbox on the
// first acceptance, and answers replays from durable state. The lease is
// durable as pending before the backend is asked to create anything.
func (l *SandboxLane) Commit(ctx context.Context, lease protocol.SandboxLeaseV1, req SandboxRequest) (protocol.SandboxReceiptV1, error) {
	now := l.now().UTC()
	if err := protocol.VerifyBoundSandboxLeaseV1(lease, req.ValidatorKey, now, req.CurrentBlock, req.Network, req.NetUID, req.CallerHotkey, req.MinerHotkey, req.MinerUID); err != nil {
		return protocol.SandboxReceiptV1{}, err
	}
	if err := l.admit(lease.Subnet, lease.MinerID); err != nil {
		return protocol.SandboxReceiptV1{}, err
	}
	leaseID := protocol.SandboxLeaseIDV1(lease)
	unlock := l.locks.lock(leaseID)
	outcome, err := l.store.CommitLease(ctx, lease, now)
	if err == nil && outcome.Start {
		outcome, err = l.start(ctx, lease, leaseID, now)
	}
	unlock()
	if err != nil {
		return protocol.SandboxReceiptV1{}, err
	}
	return l.receipt(protocol.SandboxLeaseSchema, lease, lease.SandboxID, lease.Generation, lease.Subnet, outcome, now)
}

// start runs the sandbox of a lease that was just written as pending and
// answers with its durable stage.
func (l *SandboxLane) start(ctx context.Context, lease protocol.SandboxLeaseV1, leaseID string, now time.Time) (durable.SandboxOutcome, error) {
	instance := SandboxInstanceName(leaseID)
	code := l.unsupported(lease)
	if code == "" {
		err := l.backend.Create(ctx, instance, lease)
		if err == nil {
			// When a release or sweep moved the lease to cleanup while the
			// sandbox started, the lease stays in cleanup: that caller is
			// waiting on this lease's lock and destroys the sandbox next.
			if _, err := l.store.MarkLeaseRunning(ctx, leaseID, now); err != nil {
				return durable.SandboxOutcome{}, err
			}
			return l.store.CommitLease(ctx, lease, now)
		}
		code = "runtime_start_failed"
		var refusal *SandboxRefusal
		if errors.As(err, &refusal) {
			if attributed, known := sandbox.ReceiptErrorAttribution[refusal.Code]; known && !attributed {
				code = refusal.Code
			}
		}
	}
	if err := l.store.BeginLeaseCleanup(ctx, leaseID, "failed", &code, now); err != nil {
		return durable.SandboxOutcome{}, err
	}
	_ = l.teardown(ctx, leaseID, instance, now)
	// An exact replay of the lease answers from the durable row.
	return l.store.CommitLease(ctx, lease, now)
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
// sandbox it moved to cleanup. The receipt is signed once the fence is
// durable; a sandbox whose destroy failed keeps consuming capacity, as the
// receipt shows, until Sweep destroys it.
func (l *SandboxLane) Release(ctx context.Context, r protocol.SandboxReleaseV1, req SandboxRequest) (protocol.SandboxReceiptV1, error) {
	now := l.now().UTC()
	if err := protocol.VerifyBoundSandboxReleaseV1(r, req.ValidatorKey, now, req.CurrentBlock, req.Network, req.NetUID, req.CallerHotkey, req.MinerHotkey, req.MinerUID); err != nil {
		return protocol.SandboxReceiptV1{}, err
	}
	if err := l.admit(r.Subnet, r.MinerID); err != nil {
		return protocol.SandboxReceiptV1{}, err
	}
	outcome, teardown, err := l.store.Release(ctx, r, now)
	if err != nil {
		return protocol.SandboxReceiptV1{}, err
	}
	if len(teardown) > 0 {
		_ = l.destroyAll(ctx, teardown, now)
		if outcome.Held, outcome.Active, err = l.store.Occupancy(ctx, now); err != nil {
			return protocol.SandboxReceiptV1{}, err
		}
	}
	return l.receipt(protocol.SandboxReleaseSchema, r, r.SandboxID, r.Generation, r.Subnet, outcome, now)
}

// Sweep expires unused holds, moves leases past expiry plus grace to
// cleanup, and destroys every sandbox in cleanup. Run it periodically.
func (l *SandboxLane) Sweep(ctx context.Context) error {
	now := l.now().UTC()
	records, err := l.store.Sweep(ctx, now)
	if err != nil {
		return err
	}
	return l.destroyAll(ctx, records, now)
}

// Recover is the restart path: before the lane serves, every sandbox that
// may exist is destroyed and its lease answers failed/miner_restart.
func (l *SandboxLane) Recover(ctx context.Context) error {
	now := l.now().UTC()
	records, err := l.store.Recover(ctx, now)
	if err != nil {
		return err
	}
	return l.destroyAll(ctx, records, now)
}

func (l *SandboxLane) destroyAll(ctx context.Context, records []durable.SandboxLeaseRecord, now time.Time) error {
	var errs []error
	for _, record := range records {
		unlock := l.locks.lock(record.LeaseID)
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
	s.mu.Lock()
	if s.locks == nil {
		s.locks = map[string]*sandboxLock{}
	}
	entry := s.locks[key]
	if entry == nil {
		entry = &sandboxLock{}
		s.locks[key] = entry
	}
	entry.refs++
	s.mu.Unlock()
	entry.mu.Lock()
	return func() {
		entry.mu.Unlock()
		s.mu.Lock()
		entry.refs--
		if entry.refs == 0 {
			delete(s.locks, key)
		}
		s.mu.Unlock()
	}
}
