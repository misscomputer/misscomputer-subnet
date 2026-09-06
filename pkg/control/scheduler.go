// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/artifact"
	"github.com/misscomputer/misscomputer-subnet/pkg/durable"
	"github.com/misscomputer/misscomputer-subnet/pkg/edge"
	"github.com/misscomputer/misscomputer-subnet/pkg/ledger"
	"github.com/misscomputer/misscomputer-subnet/pkg/miner"
	"github.com/misscomputer/misscomputer-subnet/pkg/policy"
	"github.com/misscomputer/misscomputer-subnet/pkg/protocol"
	"github.com/misscomputer/misscomputer-subnet/pkg/validator"
	"github.com/misscomputer/misscomputer-subnet/pkg/workload"
)

const (
	defaultReplicas       = 3
	defaultDeployTimeout  = 2 * time.Minute
	assignmentCleanupTime = 5 * time.Second
)

var ErrDeploymentActive = errors.New("deployment ID is already active")

// A health observation always races the scheduler: the deployment it names can
// be torn down, or its replica replaced, between the moment the observation was
// taken and the moment it is applied. These sentinels let a caller that
// generates its own observations — such as the periodic Prober — tell that
// benign staleness apart from a real policy or cleanup failure.
var (
	ErrUnknownDeployment      = errors.New("unknown deployment")
	ErrDeploymentDeactivating = errors.New("deployment is deactivating")
	ErrReplicaNotActive       = errors.New("replica is not active for miner")
	// ErrAcceptanceInconclusive reports an admission probe that did not yield a
	// complete response attributable to the candidate. The assignment still
	// fails closed, but the candidate is not economically blamed for an edge,
	// network, cancellation, or incomplete-transport failure.
	ErrAcceptanceInconclusive   = errors.New("acceptance probe was inconclusive")
	errHealthObservationChanged = errors.New("endpoint health changed after corroboration")
	errHealthObservationStale   = errors.New("health observation is replayed or out of order")
)

// ScoringDisposition makes the acceptance-observation boundary explicit.
// Ordinary customer deployments retain the historical production-eligible
// behavior. Synthetic campaign deployments use evidence_only so their probe
// results cannot silently enter validator weight preparation.
type ScoringDisposition string

const (
	ScoringProductionEligible ScoringDisposition = "production_eligible"
	ScoringEvidenceOnly       ScoringDisposition = "evidence_only"
)

type committedHealthActionError struct{ cause error }

func (err *committedHealthActionError) Error() string { return err.cause.Error() }
func (err *committedHealthActionError) Unwrap() error { return err.cause }

// HealthObservationCommitted reports that the scheduler accepted the health
// evidence and committed its policy action before a later cleanup, trust, or
// replacement step failed. Callers must still persist the accepted scoring
// sample exactly once; retrying the same health message is replay-rejected.
func HealthObservationCommitted(err error) bool {
	var committed *committedHealthActionError
	return errors.As(err, &committed)
}

// CapacityError means the scheduler cannot reach the requested replica count
// using miners that are trusted, not already active/reserved, and not
// quarantined for this deployment.
type CapacityError struct {
	DeploymentID string
	Required     int
	Available    int
}

func (e *CapacityError) Error() string {
	return fmt.Sprintf("deployment %q has insufficient eligible clean miner capacity: need %d, have %d", e.DeploymentID, e.Required, e.Available)
}

type Scheduler struct {
	SigningKey ed25519.PrivateKey
	Miners     []miner.Assigner
	Router     *edge.Router
	Ledger     *ledger.Ledger
	Validator  validator.Validator
	Health     *policy.Monitor
	Replicas   int
	Domain     string
	// HostLabelPrefix keeps development deployments in a recognizable
	// single-label namespace such as edge-dev-<deployment>.miss.computer.
	HostLabelPrefix string
	Now             func() time.Time
	// Entropy is an explicit deterministic seam for the supervised local
	// playground and tests. Production callers leave it nil so assignment
	// nonces continue to come directly from crypto/rand.Reader.
	Entropy io.Reader
	// Subnet is nil for the standalone lab. Long-running neuron control uses a
	// fresh chain snapshot here and emits only deployment.v3 bound tickets.
	Subnet             *protocol.SubnetBinding
	mu                 sync.Mutex
	publicationID      string
	publicationVersion uint64
	probeTopology      uint64
	// circuitVersions is deliberately separate from policy.Monitor revisions.
	// External observations may advance economic-health history, but they must
	// neither invalidate nor authorize the in-process prober's exact route-local
	// availability decision. Entries are scoped to nonce-bearing EndpointIDs and
	// are removed with the active incarnation.
	circuitVersions map[string]uint64
	states          map[string]*deploymentState
	candidateCursor int
	cleanupCursor   string
	deficitCursor   string

	// lifecycleMu owns every assignment/cleanup worker which may call a miner,
	// router, or durable store. Drain closes admission to new workers before it
	// waits, so Plane.Close never tears those resources out from under a late
	// cancellation-ignoring assigner.
	lifecycleMu      sync.Mutex
	lifecycleWorkers int
	lifecycleClosing bool
	lifecycleIdle    chan struct{}
	// afterReplacementObservationFailure is a deterministic concurrency seam
	// used only by package tests. Production construction leaves it nil.
	afterReplacementObservationFailure func()
}

// bumpProbeTopologyLocked advances the incarnation set observed by the
// periodic prober. At exhaustion, destructive corroboration pruning stays
// disabled (see probeCorroboration.reconcile) rather than treating two
// different topologies as the same generation.
func (s *Scheduler) bumpProbeTopologyLocked() {
	if s.probeTopology != ^uint64(0) {
		s.probeTopology++
	}
}

// retireProbeStateLocked drops every process-local observation/circuit record
// owned by an endpoint at the same boundary where active routing ownership is
// removed. Endpoint IDs include generation and nonce, so no later incarnation
// may inherit this state. Scheduler.mu must be held.
func (s *Scheduler) retireProbeStateLocked(endpointID string) {
	delete(s.circuitVersions, endpointID)
	if s.Health != nil {
		s.Health.Forget(endpointID)
	}
}

type deploymentState struct {
	request        DeployRequest
	routeHost      string
	active         map[string]activeAssignment
	reserved       map[string]*candidateReservation
	excluded       map[string]struct{}
	pendingCleanup map[string]*cleanupLease
	cleanupCursor  string
	generation     uint64
	deploying      bool
	// Deactivation keeps exact ticket ownership until route, miner, and
	// durable endpoint cleanup have all succeeded. This makes retries safe
	// without reopening placement or replacement races.
	deactivationRequested bool
	cleanupInProgress     bool
}

type activeAssignment struct {
	miner              miner.Assigner
	replicaID          string
	endpointID         string
	ticket             protocol.Ticket
	receipt            protocol.Receipt
	publicationID      string
	publicationVersion uint64
}

// cleanupLease is the scheduler's exact ownership record for a ticket whose
// route/miner/durable cleanup is not yet proven complete. assignmentPending is
// true while the original Assign call can still create the workload; cleaning
// prevents two repair triggers from acting on the same incarnation.
type cleanupLease struct {
	assignment        activeAssignment
	assignmentPending bool
	requiresRetry     bool
	preserveExclusion bool
	cleaning          bool
}

// candidateReservation binds a miner handle to the exact scheduler
// publication observed while holding Scheduler.mu. Ticket signing consumes
// this captured subnet instead of taking a second lock-window snapshot.
type candidateReservation struct {
	candidate          miner.Assigner
	subnet             *protocol.SubnetBinding
	publicationID      string
	publicationVersion uint64
}

type reservationDisposition uint8

const (
	reservationAccepted reservationDisposition = iota
	reservationDeploymentStale
	reservationCandidateIneligible
	reservationPublicationChanged
	reservationMismatch
)

type DeployRequest struct {
	DeploymentID       string
	Manifest           artifact.Manifest
	ManifestKey        string
	Workload           workload.Spec
	Timeout            time.Duration
	RequiredMiner      string
	ScoringDisposition ScoringDisposition
}

type DeployResult struct {
	DeploymentID       string                  `json:"deployment_id"`
	RouteHost          string                  `json:"route_host"`
	TicketPublishedAt  time.Time               `json:"ticket_published_at"`
	FirstReplicaAt     time.Time               `json:"first_replica_at"`
	FullRedundancyAt   time.Time               `json:"full_redundancy_at"`
	FirstReplicaTime   time.Duration           `json:"first_replica_time"`
	FullRedundancyTime time.Duration           `json:"full_redundancy_time"`
	ReadyMiners        []string                `json:"ready_miners"`
	FailedMiners       []string                `json:"failed_miners,omitempty"`
	PublicProbe        validator.ProbeResult   `json:"public_probe"`
	Observations       []AcceptanceObservation `json:"acceptance_observations"`
	RequiredMiner      string                  `json:"required_miner,omitempty"`
	ScoringDisposition ScoringDisposition      `json:"scoring_disposition"`
	// AcceptedTickets is an in-process handoff at the already verified
	// scheduler acceptance boundary. It is deliberately excluded from JSON;
	// public/status surfaces use credential-safe campaign projections instead.
	AcceptedTickets []AcceptedTicket `json:"-"`
}

type AcceptedTicket struct {
	Ticket     protocol.Ticket
	AcceptedAt time.Time
}

// AcceptanceObservation is measured at the validator control boundary. Miner
// receipt timestamps remain diagnostic and never influence weights.
type AcceptanceObservation struct {
	MinerHotkey string    `json:"miner_hotkey"`
	Success     bool      `json:"success"`
	LatencyMS   int64     `json:"latency_ms"`
	ObservedAt  time.Time `json:"observed_at"`
}

type assignmentResult struct {
	miner      miner.Assigner
	ticket     protocol.Ticket
	result     miner.Result
	err        error
	latency    time.Duration
	observedAt time.Time
}

type launchedAssignment struct {
	miner          miner.Assigner
	ticket         protocol.Ticket
	done           chan assignmentResult
	fenced         chan struct{}
	needsPostFence atomic.Bool
}

// assignmentAttempt gives every launched ticket a cleanup lease. Aborting an
// attempt immediately deactivates all known endpoint IDs, while a worker that
// returns successfully later performs the same idempotent deactivation again.
// An Assigner that ignores cancellation therefore cannot block Deploy from
// returning, and a late success cannot strand its workload.
type assignmentAttempt struct {
	scheduler *Scheduler
	state     *deploymentState
	ctx       context.Context
	results   chan assignmentResult
	aborted   atomic.Bool
	finalize  sync.Once
	finalized chan struct{}
	mu        sync.Mutex
	launched  []*launchedAssignment
}

func newAssignmentAttempt(s *Scheduler, state *deploymentState, ctx context.Context, capacity int) *assignmentAttempt {
	if capacity < 1 {
		capacity = 1
	}
	return &assignmentAttempt{
		scheduler: s, state: state, ctx: ctx, results: make(chan assignmentResult, capacity), finalized: make(chan struct{}),
	}
}

func (a *assignmentAttempt) launch(candidate miner.Assigner, ticket protocol.Ticket) error {
	// The Deploy/health/repair operation which owns this attempt has already
	// passed the lifecycle admission gate. A child must remain admissible after
	// Drain starts: otherwise shutdown can observe the parent but reject the
	// exact assignment worker which the parent is required to join.
	a.scheduler.beginOwnedLifecycleWorker()
	launched := &launchedAssignment{miner: candidate, ticket: ticket, done: make(chan assignmentResult, 1), fenced: make(chan struct{})}
	a.mu.Lock()
	a.launched = append(a.launched, launched)
	a.mu.Unlock()
	go func() {
		defer a.scheduler.endLifecycleWorker()
		now := a.scheduler.clock()
		started := now().UTC()
		assigned, err := candidate.Assign(a.ctx, ticket)
		finished := now().UTC()
		outcome := assignmentResult{
			miner: candidate, ticket: ticket, result: assigned, err: err,
			latency: max(finished.Sub(started), 0), observedAt: finished,
		}
		launched.done <- outcome
		close(launched.done)
		// results is sized for every launch. Never abandon lifecycle ownership
		// merely because the request context was cancelled.
		a.results <- outcome
		// The request owner makes an explicit terminal decision. This handshake
		// closes the race where Assign returned just before abort: the worker can
		// neither miss the abort nor leave assignmentPending stuck forever.
		<-a.finalized
		if a.aborted.Load() {
			// The assignment worker itself is already lifecycle-owned, so it can
			// finish the ownership transfer even if Plane.Drain started after the
			// request was admitted. The early fence may run before Assign returns;
			// waiting for it and then cleaning again proves that a late workload
			// cannot survive the cancellation.
			<-launched.fenced
			if launched.needsPostFence.Load() && a.scheduler.markAssignmentCompleteAndClaimCleanup(a.state, candidate.ID(), expectedEndpointID(ticket)) {
				cleanupCtx, cancel := context.WithTimeout(context.Background(), assignmentCleanupTime)
				cleanupErr := a.scheduler.deactivateTicket(cleanupCtx, candidate, ticket)
				cancel()
				a.scheduler.finishCleanupLease(a.state, candidate.ID(), expectedEndpointID(ticket), cleanupErr)
			}
		}
	}()
	return nil
}

func (a *assignmentAttempt) complete() {
	a.finalize.Do(func() { close(a.finalized) })
}

func (a *assignmentAttempt) abort() {
	if !a.aborted.CompareAndSwap(false, true) {
		return
	}
	a.mu.Lock()
	launched := append([]*launchedAssignment(nil), a.launched...)
	a.mu.Unlock()
	for _, assignment := range launched {
		assignmentPending := true
		select {
		case <-assignment.done:
			assignmentPending = false
		default:
		}
		assignment.needsPostFence.Store(assignmentPending)
		claimed := a.scheduler.retainAndClaimCleanupLease(
			a.state, assignment.miner, assignment.ticket, assignmentPending, false, false,
		)
		if !claimed {
			// Exact ownership can only already belong to another cleanup worker or
			// to a completed deployment teardown. Do not launch a second cleanup
			// for the same ticket. The late-assignment fence below will make one
			// final exact cleanup claim after Assign returns when necessary.
			close(assignment.fenced)
			continue
		}
		// Fence the exact ticket immediately, even if Assign ignores
		// cancellation or a forwarding bridge continues the operation after its
		// client disconnects. The late cleanup below runs again after Assign is
		// joined, because an early idempotent stop cannot prove that no workload
		// will subsequently appear.
		a.scheduler.beginOwnedLifecycleWorker()
		go func(assignment *launchedAssignment) {
			defer a.scheduler.endLifecycleWorker()
			defer close(assignment.fenced)
			cleanupCtx, cancel := context.WithTimeout(context.Background(), assignmentCleanupTime)
			err := a.scheduler.deactivateTicket(cleanupCtx, assignment.miner, assignment.ticket)
			cancel()
			a.scheduler.finishCleanupLease(a.state, assignment.miner.ID(), expectedEndpointID(assignment.ticket), err)
		}(assignment)
	}
	a.complete()
	timer := time.NewTimer(assignmentCleanupTime)
	defer timer.Stop()
	for _, assignment := range launched {
		select {
		case <-assignment.fenced:
		case <-timer.C:
			return
		}
	}
}

func (s *Scheduler) beginLifecycleWorker() bool {
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	if s.lifecycleClosing {
		return false
	}
	if s.lifecycleWorkers == 0 {
		s.lifecycleIdle = make(chan struct{})
	}
	s.lifecycleWorkers++
	return true
}

// beginOwnedLifecycleWorker transfers part of an already-admitted scheduler
// operation into a child goroutine. It is intentionally allowed while Drain is
// waiting: the parent is still counted, so the idle channel cannot close
// between this increment and the child's eventual completion. Callers must
// already own one lifecycle count.
func (s *Scheduler) beginOwnedLifecycleWorker() {
	s.lifecycleMu.Lock()
	if s.lifecycleWorkers == 0 {
		// This is an internal invariant rather than a recoverable configuration
		// error: admitting an unowned child could race resource closure.
		s.lifecycleMu.Unlock()
		panic("scheduler lifecycle child has no owner")
	}
	s.lifecycleWorkers++
	s.lifecycleMu.Unlock()
}

func (s *Scheduler) endLifecycleWorker() {
	s.lifecycleMu.Lock()
	s.lifecycleWorkers--
	if s.lifecycleWorkers == 0 && s.lifecycleIdle != nil {
		close(s.lifecycleIdle)
		s.lifecycleIdle = nil
	}
	s.lifecycleMu.Unlock()
}

// Drain rejects new scheduler-owned workers and waits for every already-owned
// assignment and cleanup worker. A timeout is explicit: callers must not close
// the router or durable store after a failed drain.
func (s *Scheduler) Drain(ctx context.Context) error {
	if ctx == nil {
		return errors.New("scheduler drain context is required")
	}
	s.lifecycleMu.Lock()
	s.lifecycleClosing = true
	if s.lifecycleWorkers == 0 {
		s.lifecycleMu.Unlock()
		return nil
	}
	idle := s.lifecycleIdle
	s.lifecycleMu.Unlock()
	select {
	case <-idle:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("drain scheduler lifecycle: %w", ctx.Err())
	}
}

func assignmentFromTicket(candidate miner.Assigner, ticket protocol.Ticket) activeAssignment {
	return activeAssignment{
		miner: candidate, replicaID: protocol.ReplicaID(ticket), endpointID: expectedEndpointID(ticket), ticket: ticket,
	}
}

// retainCleanupLease transfers exact ownership from a reservation/active slot
// into quarantine. It is idempotent for the same endpoint and never replaces a
// newer cleanup incarnation for the miner.
func (s *Scheduler) retainCleanupLease(state *deploymentState, candidate miner.Assigner, ticket protocol.Ticket, assignmentPending, requiresRetry bool) {
	s.retainCleanupLeaseWithDisposition(state, candidate, ticket, assignmentPending, requiresRetry, false, false)
}

// retainAndClaimCleanupLease transfers exact ticket ownership and atomically
// claims the only cleanup invocation allowed for that incarnation. No repair,
// deployment teardown, or cancellation path can observe an unclaimed lease in
// between those two operations.
func (s *Scheduler) retainAndClaimCleanupLease(state *deploymentState, candidate miner.Assigner, ticket protocol.Ticket, assignmentPending, requiresRetry, preserveExclusion bool) bool {
	return s.retainCleanupLeaseWithDisposition(state, candidate, ticket, assignmentPending, requiresRetry, preserveExclusion, true)
}

func (s *Scheduler) retainCleanupLeaseWithDisposition(state *deploymentState, candidate miner.Assigner, ticket protocol.Ticket, assignmentPending, requiresRetry, preserveExclusion, claim bool) bool {
	if state == nil || candidate == nil {
		return false
	}
	assignment := assignmentFromTicket(candidate, ticket)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.states[state.request.DeploymentID] != state {
		return false
	}
	minerID := candidate.ID()
	delete(state.reserved, minerID)
	if current, ok := state.active[minerID]; ok && current.endpointID == assignment.endpointID {
		assignment = current
		delete(state.active, minerID)
		s.retireProbeStateLocked(current.endpointID)
		s.bumpProbeTopologyLocked()
	}
	// The cleanup lease is the ownership boundary for an assignment that must
	// no longer receive ordinary traffic. Suppress the exact generation+nonce
	// incarnation while Scheduler.mu still protects that transfer; tickets that
	// never reached activation simply do not match. Router.Deactivate repeats
	// this fail-closed suppression after signed lifecycle validation so a
	// persistence failure cannot republish the route.
	s.suppressAssignmentLocked(assignment)
	state.excluded[minerID] = struct{}{}
	if current, ok := state.pendingCleanup[minerID]; ok {
		if current.assignment.endpointID != assignment.endpointID {
			// The older exact lease remains authoritative. Candidate selection is
			// already blocked, and replacing it would lose cleanup ownership.
			return false
		}
		current.assignment = assignment
		current.assignmentPending = current.assignmentPending || assignmentPending
		current.requiresRetry = current.requiresRetry || requiresRetry
		current.preserveExclusion = current.preserveExclusion || preserveExclusion
		if claim && !current.cleaning {
			current.cleaning = true
			return true
		}
		return false
	}
	state.pendingCleanup[minerID] = &cleanupLease{
		assignment: assignment, assignmentPending: assignmentPending, requiresRetry: requiresRetry,
		preserveExclusion: preserveExclusion, cleaning: claim,
	}
	return claim
}

func (s *Scheduler) suppressAssignmentLocked(assignment activeAssignment) {
	if s.Router == nil || assignment.miner == nil || len(s.SigningKey) != ed25519.PrivateKeySize {
		return
	}
	s.Router.SetTemporaryAvailability(
		assignment.ticket.RouteHost, assignment.replicaID, assignment.endpointID, assignment.miner.ID(), false, s.SigningKey,
	)
}

func (s *Scheduler) markAssignmentCompleteAndClaimCleanup(state *deploymentState, minerID, endpointID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.states[state.request.DeploymentID] == state {
		if lease := state.pendingCleanup[minerID]; lease != nil && lease.assignment.endpointID == endpointID {
			lease.assignmentPending = false
			if !lease.cleaning {
				lease.cleaning = true
				return true
			}
		}
	}
	return false
}

func (s *Scheduler) finishCleanupLease(state *deploymentState, minerID, endpointID string, cleanupErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.states[state.request.DeploymentID] != state {
		return
	}
	lease := state.pendingCleanup[minerID]
	if lease == nil || lease.assignment.endpointID != endpointID {
		return
	}
	lease.cleaning = false
	if cleanupErr == nil && !lease.assignmentPending && !lease.requiresRetry {
		delete(state.pendingCleanup, minerID)
		if !lease.preserveExclusion {
			delete(state.excluded, minerID)
		}
		s.maybeDeleteDeactivatedStateLocked(state)
	}
}

func (s *Scheduler) maybeDeleteDeactivatedStateLocked(state *deploymentState) {
	if state == nil || !state.deactivationRequested || state.deploying || state.cleanupInProgress ||
		len(state.active) != 0 || len(state.reserved) != 0 || len(state.pendingCleanup) != 0 {
		return
	}
	if s.states[state.request.DeploymentID] == state {
		delete(s.states, state.request.DeploymentID)
	}
}

func (s *Scheduler) Deploy(parent context.Context, req DeployRequest) (DeployResult, error) {
	if !ValidDeploymentID(req.DeploymentID) {
		return DeployResult{}, fmt.Errorf("deployment ID must be a lowercase DNS label")
	}
	if s.Router == nil || s.Ledger == nil {
		return DeployResult{}, fmt.Errorf("scheduler router and ledger are required")
	}
	if req.ScoringDisposition == "" {
		req.ScoringDisposition = ScoringProductionEligible
	}
	if req.ScoringDisposition != ScoringProductionEligible && req.ScoringDisposition != ScoringEvidenceOnly {
		return DeployResult{}, errors.New("deployment scoring disposition is invalid")
	}
	if len(s.SigningKey) != ed25519.PrivateKeySize {
		return DeployResult{}, fmt.Errorf("scheduler signing key is invalid")
	}
	if !s.Router.IsAuthorizedFor(s.SigningKey.Public().(ed25519.PublicKey)) {
		return DeployResult{}, fmt.Errorf("scheduler router is not bound to its authoritative service key")
	}
	replicas := s.Replicas
	if replicas == 0 {
		replicas = defaultReplicas
	}
	if replicas < 1 {
		return DeployResult{}, fmt.Errorf("replica count must be positive")
	}
	if req.Timeout <= 0 {
		req.Timeout = defaultDeployTimeout
	}
	now := s.clock()
	domain := s.Domain
	if domain == "" {
		domain = "on.miss.computer"
	}
	routeLabel := s.HostLabelPrefix + req.DeploymentID
	if !ValidDeploymentID(routeLabel) {
		return DeployResult{}, fmt.Errorf("route label prefix plus deployment ID must form one lowercase DNS label")
	}
	routeHost := routeLabel + "." + domain
	if !s.beginLifecycleWorker() {
		return DeployResult{}, errors.New("scheduler is draining")
	}
	defer s.endLifecycleWorker()
	// A redeployed deployment ID must continue its route-generation sequence:
	// the route authority (and its durable store) treats any generation at or
	// below the deployment's high-water mark as a stale replay and fails
	// closed, so a fresh incarnation restarting at one could never register.
	baseGeneration, err := s.Router.HighestGeneration(parent, req.DeploymentID)
	if err != nil {
		return DeployResult{}, fmt.Errorf("load highest edge route generation: %w", err)
	}
	firstGeneration := baseGeneration + 1
	if firstGeneration == 0 {
		return DeployResult{}, fmt.Errorf("deployment %q has exhausted its route generations", req.DeploymentID)
	}
	state, err := s.beginDeployment(req, routeHost, firstGeneration)
	if err != nil {
		return DeployResult{}, err
	}
	ctx, cancel := context.WithTimeout(parent, req.Timeout)
	// At most replicas assignments are in flight, even if a concurrent
	// publication expands Miners after this attempt is constructed. Size the
	// terminal result handoff for that invariant so cancelled workers can always
	// publish and reach their post-fence cleanup without a departed receiver.
	attempt := newAssignmentAttempt(s, state, ctx, max(s.minerCount(), replicas))
	succeeded := false
	defer func() {
		if succeeded {
			attempt.complete()
			cancel()
			return
		}
		cancel()
		attempt.abort()
		s.mu.Lock()
		if s.states[req.DeploymentID] == state {
			state.deploying = false
			state.reserved = make(map[string]*candidateReservation)
			if len(state.pendingCleanup) > 0 {
				// The caller saw a failed deployment, so this cleanup-only state
				// must never be half-opened into service. Retain exact ownership
				// and block redeploy until DeactivateDeployment tears it down.
				state.deactivationRequested = true
			} else if !state.deactivationRequested || (len(state.active) == 0 && !state.cleanupInProgress) {
				delete(s.states, req.DeploymentID)
			}
			s.bumpProbeTopologyLocked()
		}
		s.mu.Unlock()
	}()

	start := now().UTC()
	s.Ledger.Start(ledger.Deployment{ID: req.DeploymentID, RouteHost: routeHost, ImageDigest: req.Manifest.ImageDigest, TicketPublished: start})
	result := DeployResult{
		DeploymentID: req.DeploymentID, RouteHost: routeHost, TicketPublishedAt: start,
		RequiredMiner: req.RequiredMiner, ScoringDisposition: req.ScoringDisposition,
	}
	recordObservation := func(observation AcceptanceObservation) error {
		result.Observations = append(result.Observations, observation)
		if req.ScoringDisposition == ScoringEvidenceOnly {
			return nil
		}
		if err := s.recordAcceptanceObservation(observation); err != nil {
			return fmt.Errorf("persist acceptance observation: %w", err)
		}
		return nil
	}
	inFlight := 0
	reservationsByNonce := make(map[string]*candidateReservation)
	attemptedCandidates := make(map[string]struct{})
	var lastInconclusive error
	launchNext := func() error {
		reservation, available := s.reserveInitialCandidateSkipping(state, attemptedCandidates)
		if reservation == nil {
			return errors.Join(lastInconclusive, &CapacityError{DeploymentID: req.DeploymentID, Required: replicas, Available: available})
		}
		candidate := reservation.candidate
		attemptedCandidates[candidate.ID()] = struct{}{}
		ticket, ticketErr := s.ticketForReservation(req, reservation, routeHost, firstGeneration, now())
		if ticketErr != nil {
			s.releaseReservation(state, candidate.ID())
			return ticketErr
		}
		if err := s.Ledger.RecordAssignment(ticket, "published"); err != nil {
			s.releaseReservation(state, candidate.ID())
			return err
		}
		reservationsByNonce[ticket.AssignmentNonce] = reservation
		inFlight++
		if err := attempt.launch(candidate, ticket); err != nil {
			inFlight--
			delete(reservationsByNonce, ticket.AssignmentNonce)
			s.releaseReservation(state, candidate.ID())
			return err
		}
		return nil
	}
	for inFlight < replicas {
		if err := launchNext(); err != nil {
			return result, err
		}
	}

	for len(result.ReadyMiners) < replicas && inFlight > 0 {
		if err := ctx.Err(); err != nil {
			return result, fmt.Errorf("deployment timed out with %d/%d ready: %w", len(result.ReadyMiners), replicas, err)
		}
		select {
		case <-ctx.Done():
			return result, fmt.Errorf("deployment timed out with %d/%d ready: %w", len(result.ReadyMiners), replicas, ctx.Err())
		case outcome := <-attempt.results:
			inFlight--
			reservation := reservationsByNonce[outcome.ticket.AssignmentNonce]
			delete(reservationsByNonce, outcome.ticket.AssignmentNonce)
			observation := AcceptanceObservation{
				MinerHotkey: outcome.miner.ID(), Success: false,
				LatencyMS: max(outcome.latency.Milliseconds(), 0), ObservedAt: outcome.observedAt,
			}
			if err := ctx.Err(); err != nil {
				return result, fmt.Errorf("deployment timed out with %d/%d ready: %w", len(result.ReadyMiners), replicas, err)
			}
			if outcome.err != nil || !s.Ledger.Eligible(outcome.miner.ID()) {
				cleanupErr := s.cleanupReservation(ctx, state, outcome, true)
				appendUnique(&result.FailedMiners, outcome.miner.ID())
				if err := recordObservation(observation); err != nil {
					return result, errors.Join(err, cleanupErr)
				}
				if cleanupErr != nil {
					return result, fmt.Errorf("cleanup failed assignment: %w", cleanupErr)
				}
				if err := launchNext(); err != nil {
					return result, err
				}
				continue
			}
			if verifyErr := s.verifyResultForDisposition(outcome.miner, outcome.ticket, outcome.result, req.ScoringDisposition); verifyErr != nil {
				cleanupErr := s.cleanupReservation(ctx, state, outcome, true)
				appendUnique(&result.FailedMiners, outcome.miner.ID())
				observationErr := recordObservation(observation)
				var persistenceErr *trustPersistenceError
				if errors.As(verifyErr, &persistenceErr) {
					if cleanupErr != nil {
						cleanupErr = fmt.Errorf("cleanup invalid receipt: %w", cleanupErr)
					}
					return result, errors.Join(
						fmt.Errorf("reject invalid receipt: %w", verifyErr),
						cleanupErr,
						observationErr,
					)
				}
				if observationErr != nil {
					return result, observationErr
				}
				if err := launchNext(); err != nil {
					return result, err
				}
				continue
			}
			if err := s.Ledger.AddReceipt(outcome.result.Receipt); err != nil {
				return result, fmt.Errorf("persist accepted receipt: %w", err)
			}
			if err := s.Router.RegisterPending(ctx, outcome.ticket, outcome.result.Receipt, outcome.miner.PublicKey(), s.SigningKey); err != nil {
				cleanupErr := s.cleanupReservation(ctx, state, outcome, true)
				return result, errors.Join(fmt.Errorf("register authenticated pending edge route: %w", err), cleanupErr)
			}
			probe := s.Validator.ProbeReplica(ctx, routeHost, outcome.result.Receipt.ReplicaID, req.Workload.ChallengePath, req.Workload.ChallengeValue)
			if err := ctx.Err(); err != nil {
				probe.ResponseComplete = false
				probe.Error = err.Error()
				return result, errors.Join(s.rejectInconclusiveAcceptance(ctx, state, outcome, probe), err)
			}
			if !probe.Correct {
				if !attributableAcceptanceFailure(probe) {
					lastInconclusive = errors.Join(lastInconclusive, s.rejectInconclusiveAcceptance(ctx, state, outcome, probe))
					appendUnique(&result.FailedMiners, outcome.miner.ID())
					if err := launchNext(); err != nil {
						return result, err
					}
					continue
				}
				if err := s.rejectAcceptance(ctx, state, routeHost, outcome, req.ScoringDisposition); err != nil {
					return result, fmt.Errorf("persist strict acceptance rejection: %w", err)
				}
				appendUnique(&result.FailedMiners, outcome.miner.ID())
				if err := recordObservation(observation); err != nil {
					return result, err
				}
				if err := launchNext(); err != nil {
					return result, err
				}
				continue
			}
			if err := s.Router.Activate(ctx, outcome.ticket, outcome.result.Receipt, outcome.miner.PublicKey(), s.SigningKey); err != nil {
				cleanupErr := s.cleanupReservation(ctx, state, outcome, true)
				return result, errors.Join(fmt.Errorf("activate authenticated edge route: %w", err), cleanupErr)
			}
			if result.FirstReplicaAt.IsZero() {
				probe = s.Validator.Probe(ctx, routeHost, req.Workload.ChallengePath, req.Workload.ChallengeValue)
				if err := ctx.Err(); err != nil {
					probe.ResponseComplete = false
					probe.Error = err.Error()
					return result, errors.Join(s.rejectInconclusiveAcceptance(ctx, state, outcome, probe), err)
				}
				if !probe.Correct {
					if !attributableAcceptanceFailure(probe) {
						lastInconclusive = errors.Join(lastInconclusive, s.rejectInconclusiveAcceptance(ctx, state, outcome, probe))
						appendUnique(&result.FailedMiners, outcome.miner.ID())
						if err := launchNext(); err != nil {
							return result, err
						}
						continue
					}
					if err := s.rejectAcceptance(ctx, state, routeHost, outcome, req.ScoringDisposition); err != nil {
						return result, fmt.Errorf("persist public acceptance rejection: %w", err)
					}
					appendUnique(&result.FailedMiners, outcome.miner.ID())
					if err := recordObservation(observation); err != nil {
						return result, err
					}
					if err := launchNext(); err != nil {
						return result, err
					}
					continue
				}
			}
			if reservation == nil {
				cleanupErr := s.cleanupReservation(ctx, state, outcome, true)
				return result, errors.Join(fmt.Errorf("assignment %q lost its scheduler publication reservation", outcome.ticket.AssignmentNonce), cleanupErr)
			}
			assignment := activeAssignment{
				miner: outcome.miner, replicaID: outcome.result.Receipt.ReplicaID, endpointID: expectedEndpointID(outcome.ticket),
				ticket: outcome.ticket, receipt: outcome.result.Receipt,
				publicationID: reservation.publicationID, publicationVersion: reservation.publicationVersion,
			}
			// Persist the endpoint while it is still an unpublished reservation.
			// If teardown starts during this write, acceptReservation observes the
			// deactivation fence and transfers the now-durable exact ticket into
			// cleanup ownership. Publishing active first would let teardown finish
			// before this write and then recreate an orphaned active row.
			if store := s.Ledger.Durable(); store != nil {
				if err := store.PutEndpoint(ctx, durable.Endpoint{EndpointID: assignment.endpointID, DeploymentID: req.DeploymentID, MinerHotkey: outcome.miner.ID(), Active: true}); err != nil {
					cleanupErr := s.cleanupReservation(ctx, state, outcome, false)
					return result, errors.Join(err, cleanupErr)
				}
			}
			if disposition := s.acceptReservation(state, outcome.miner.ID(), assignment); disposition != reservationAccepted {
				cleanupErr := s.cleanupUnaccepted(ctx, state, outcome)
				return result, errors.Join(
					fmt.Errorf("deployment %q rejected assignment reservation (disposition %d)", req.DeploymentID, disposition),
					cleanupErr,
				)
			}
			result.ReadyMiners = append(result.ReadyMiners, outcome.miner.ID())
			result.AcceptedTickets = append(result.AcceptedTickets, AcceptedTicket{
				Ticket: outcome.ticket, AcceptedAt: outcome.observedAt,
			})
			observation.Success = true
			if err := recordObservation(observation); err != nil {
				return result, err
			}
			if result.FirstReplicaAt.IsZero() {
				result.FirstReplicaAt = now().UTC()
				result.FirstReplicaTime = result.FirstReplicaAt.Sub(start)
				result.PublicProbe = probe
				s.Ledger.MarkFirst(req.DeploymentID, result.FirstReplicaAt)
			}
		}
	}
	if len(result.ReadyMiners) != replicas {
		return result, fmt.Errorf("insufficient healthy miners: %d/%d", len(result.ReadyMiners), replicas)
	}
	if req.RequiredMiner != "" {
		found := false
		for _, minerID := range result.ReadyMiners {
			found = found || minerID == req.RequiredMiner
		}
		if !found {
			return result, fmt.Errorf("required miner %q was not accepted", req.RequiredMiner)
		}
	}
	result.FullRedundancyAt = now().UTC()
	result.FullRedundancyTime = result.FullRedundancyAt.Sub(start)
	s.Ledger.MarkFull(req.DeploymentID, result.FullRedundancyAt)
	s.mu.Lock()
	if s.states[req.DeploymentID] != state || state.deactivationRequested {
		s.mu.Unlock()
		return result, fmt.Errorf("deployment %q was deactivated before registration completed", req.DeploymentID)
	}
	state.deploying = false
	s.bumpProbeTopologyLocked()
	s.mu.Unlock()
	succeeded = true
	return result, nil
}

func (s *Scheduler) recordAcceptanceObservation(observation AcceptanceObservation) error {
	availability := 0.0
	if observation.Success {
		availability = 1
	}
	return s.Ledger.RecordObservation(durable.Observation{
		MinerHotkey: observation.MinerHotkey, Success: observation.Success,
		LatencyMS: observation.LatencyMS, Availability: availability,
		ObservedAt: observation.ObservedAt, Kind: "acceptance",
	})
}

func ValidDeploymentID(value string) bool {
	if len(value) < 1 || len(value) > 63 || value[0] == '-' || value[len(value)-1] == '-' {
		return false
	}
	for _, char := range value {
		if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' {
			return false
		}
	}
	return true
}

func (s *Scheduler) beginDeployment(req DeployRequest, routeHost string, firstGeneration uint64) (*deploymentState, error) {
	if firstGeneration == 0 {
		return nil, errors.New("deployment first generation must be positive")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.states == nil {
		s.states = make(map[string]*deploymentState)
	}
	if s.Health == nil {
		s.Health = policy.NewMonitor()
	}
	if _, exists := s.states[req.DeploymentID]; exists {
		return nil, fmt.Errorf("%w: %q", ErrDeploymentActive, req.DeploymentID)
	}
	state := &deploymentState{
		request: req, routeHost: routeHost, active: make(map[string]activeAssignment),
		reserved: make(map[string]*candidateReservation), excluded: make(map[string]struct{}),
		pendingCleanup: make(map[string]*cleanupLease), generation: firstGeneration, deploying: true,
	}
	s.states[req.DeploymentID] = state
	s.bumpProbeTopologyLocked()
	return state, nil
}

func (s *Scheduler) reserveInitialCandidate(state *deploymentState) (*candidateReservation, int) {
	return s.reserveInitialCandidateSkipping(state, nil)
}

func (s *Scheduler) reserveInitialCandidateSkipping(state *deploymentState, skip map[string]struct{}) (*candidateReservation, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.states[state.request.DeploymentID] != state || state.deactivationRequested {
		return nil, 0
	}
	if required := state.request.RequiredMiner; required != "" {
		_, active := state.active[required]
		_, reserved := state.reserved[required]
		_, excluded := state.excluded[required]
		_, skipped := skip[required]
		if !active && !reserved {
			if excluded || skipped {
				return nil, len(state.active) + len(state.reserved)
			}
			for _, candidate := range s.Miners {
				if candidate != nil && candidate.ID() == required && s.candidateCleanLocked(state, candidate) {
					reservation := s.captureReservationLocked(candidate)
					state.reserved[candidate.ID()] = reservation
					return reservation, len(state.active) + len(state.reserved)
				}
			}
			return nil, len(state.active) + len(state.reserved)
		}
	}
	for offset := 0; offset < len(s.Miners); offset++ {
		index := (s.candidateCursor + offset) % len(s.Miners)
		candidate := s.Miners[index]
		if candidate != nil {
			if _, skipped := skip[candidate.ID()]; skipped {
				continue
			}
		}
		if s.candidateCleanLocked(state, candidate) {
			reservation := s.captureReservationLocked(candidate)
			state.reserved[candidate.ID()] = reservation
			s.candidateCursor = (index + 1) % len(s.Miners)
			return reservation, len(state.active) + len(state.reserved)
		}
	}
	return nil, len(state.active) + len(state.reserved)
}

func (s *Scheduler) reserveReplacementCandidate(state *deploymentState) (*candidateReservation, uint64, int, bool) {
	return s.reserveReplacementCandidateSkipping(state, nil)
}

func (s *Scheduler) reserveReplacementCandidateSkipping(state *deploymentState, skip map[string]struct{}) (*candidateReservation, uint64, int, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.states[state.request.DeploymentID] != state || state.deactivationRequested {
		return nil, 0, 0, false
	}
	current := len(state.active) + len(state.reserved)
	if current >= s.replicaCount() {
		return nil, 0, current, false
	}
	if state.generation == ^uint64(0) {
		return nil, 0, current, true
	}
	for offset := 0; offset < len(s.Miners); offset++ {
		index := (s.candidateCursor + offset) % len(s.Miners)
		candidate := s.Miners[index]
		if candidate != nil {
			if _, skipped := skip[candidate.ID()]; skipped {
				continue
			}
		}
		if s.candidateCleanLocked(state, candidate) {
			reservation := s.captureReservationLocked(candidate)
			state.reserved[candidate.ID()] = reservation
			state.generation++
			s.candidateCursor = (index + 1) % len(s.Miners)
			return reservation, state.generation, len(state.active) + len(state.reserved), true
		}
	}
	return nil, 0, current, true
}

func (s *Scheduler) captureReservationLocked(candidate miner.Assigner) *candidateReservation {
	return &candidateReservation{
		candidate: candidate, subnet: cloneSubnetBinding(s.Subnet),
		publicationID: s.publicationID, publicationVersion: s.publicationVersion,
	}
}

func (s *Scheduler) candidateCleanLocked(state *deploymentState, candidate miner.Assigner) bool {
	if candidate == nil || !s.Ledger.Eligible(candidate.ID()) {
		return false
	}
	if _, exists := state.active[candidate.ID()]; exists {
		return false
	}
	if _, exists := state.reserved[candidate.ID()]; exists {
		return false
	}
	_, excluded := state.excluded[candidate.ID()]
	return !excluded
}

func (s *Scheduler) releaseReservation(state *deploymentState, minerID string) {
	s.mu.Lock()
	if s.states[state.request.DeploymentID] == state {
		delete(state.reserved, minerID)
		s.maybeDeleteDeactivatedStateLocked(state)
	}
	s.mu.Unlock()
}

func (s *Scheduler) failReservation(state *deploymentState, minerID string) {
	s.mu.Lock()
	if s.states[state.request.DeploymentID] == state {
		delete(state.reserved, minerID)
		state.excluded[minerID] = struct{}{}
		s.maybeDeleteDeactivatedStateLocked(state)
	}
	s.mu.Unlock()
}

func (s *Scheduler) cleanupUnaccepted(ctx context.Context, state *deploymentState, outcome assignmentResult) error {
	if !s.retainAndClaimCleanupLease(state, outcome.miner, outcome.ticket, false, false, false) {
		return errors.New("exact assignment cleanup ownership was lost")
	}
	err := s.cleanupTicket(ctx, outcome.miner, outcome.ticket)
	s.finishCleanupLease(state, outcome.miner.ID(), expectedEndpointID(outcome.ticket), err)
	return err
}

// cleanupReservation resolves a launched ticket before its reservation is
// released or failed. A cleanup error transfers the exact ticket into the
// scheduler's quarantine instead of discarding ownership. Successful cleanup
// makes an evidence-neutral candidate reusable; attributable/invalid failures
// remain excluded when exclude is true.
func (s *Scheduler) cleanupReservation(ctx context.Context, state *deploymentState, outcome assignmentResult, exclude bool) error {
	endpointID := expectedEndpointID(outcome.ticket)
	if !s.retainAndClaimCleanupLease(state, outcome.miner, outcome.ticket, false, false, exclude) {
		return errors.New("exact assignment cleanup ownership was lost")
	}
	err := s.cleanupTicket(ctx, outcome.miner, outcome.ticket)
	s.finishCleanupLease(state, outcome.miner.ID(), endpointID, err)
	return err
}

func (s *Scheduler) acceptReservation(state *deploymentState, minerID string, assignment activeAssignment) reservationDisposition {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.states[state.request.DeploymentID] != state {
		return reservationDeploymentStale
	}
	quarantine := func() {
		// This assignment has already passed edge activation. Make the exact
		// incarnation unavailable before transferring ownership to cleanup.
		s.suppressAssignmentLocked(assignment)
		state.excluded[minerID] = struct{}{}
		state.pendingCleanup[minerID] = &cleanupLease{assignment: assignment}
	}
	reservation := state.reserved[minerID]
	if reservation == nil {
		quarantine()
		return reservationMismatch
	}
	// A matching reservation is consumed exactly once even when a late
	// eligibility/publication race prevents activation. Capacity debt therefore
	// stays visible instead of being hidden by an immortal reservation.
	delete(state.reserved, minerID)
	if state.deactivationRequested {
		quarantine()
		return reservationDeploymentStale
	}
	if !s.Ledger.Eligible(minerID) {
		quarantine()
		return reservationCandidateIneligible
	}
	if assignment.publicationID != reservation.publicationID || assignment.publicationVersion != reservation.publicationVersion {
		quarantine()
		return reservationPublicationChanged
	}
	state.active[minerID] = assignment
	s.bumpProbeTopologyLocked()
	return reservationAccepted
}

func (s *Scheduler) rejectAcceptance(ctx context.Context, state *deploymentState, routeHost string, outcome assignmentResult, disposition ScoringDisposition) error {
	cleanupErr := s.cleanupReservation(ctx, state, outcome, true)
	// Only a complete response carrying the edge's upstream marker reaches this
	// function. The candidate therefore controlled the wrong response and can
	// be economically penalized without attributing an edge/network failure to
	// it. Inconclusive failures use rejectInconclusiveAcceptance instead.
	var trustErr error
	if disposition != ScoringEvidenceOnly {
		trustErr = s.Ledger.SetTrust(outcome.miner.ID(), 0)
	}
	return errors.Join(cleanupErr, trustErr)
}

func attributableAcceptanceFailure(probe validator.ProbeResult) bool {
	return probe.ServedByReplica && probe.ResponseComplete
}

func (s *Scheduler) rejectInconclusiveAcceptance(ctx context.Context, state *deploymentState, outcome assignmentResult, probe validator.ProbeResult) error {
	// Transfer the reservation to an exact, exclusively claimed cleanup lease
	// before any external cleanup begins. A successful evidence-neutral cleanup
	// releases the candidate; failure leaves the same incarnation quarantined
	// for a later bounded retry without changing economic trust.
	cleanupErr := s.cleanupReservation(ctx, state, outcome, false)
	detail := probe.Error
	if detail == "" {
		detail = "no complete replica response"
	}
	return errors.Join(
		fmt.Errorf("%w for miner %q: status=%d: %s", ErrAcceptanceInconclusive, outcome.miner.ID(), probe.Status, detail),
		cleanupErr,
	)
}

func (s *Scheduler) ticket(req DeployRequest, candidate miner.Assigner, routeHost string, generation uint64, now time.Time) (protocol.Ticket, error) {
	return s.ticketWithSubnet(req, candidate, s.subnetSnapshot(), routeHost, generation, now)
}

func (s *Scheduler) ticketForReservation(req DeployRequest, reservation *candidateReservation, routeHost string, generation uint64, now time.Time) (protocol.Ticket, error) {
	if reservation == nil || reservation.candidate == nil {
		return protocol.Ticket{}, errors.New("assignment candidate reservation is empty")
	}
	return s.ticketWithSubnet(req, reservation.candidate, cloneSubnetBinding(reservation.subnet), routeHost, generation, now)
}

func (s *Scheduler) ticketWithSubnet(req DeployRequest, candidate miner.Assigner, subnet *protocol.SubnetBinding, routeHost string, generation uint64, now time.Time) (protocol.Ticket, error) {
	if generation == 0 {
		return protocol.Ticket{}, errors.New("assignment generation must be positive")
	}
	nonce, err := s.randomID(16)
	if err != nil {
		return protocol.Ticket{}, err
	}
	t := protocol.Ticket{
		Version: protocol.Version, DeploymentID: req.DeploymentID, Generation: generation,
		ImageDigest: req.Manifest.ImageDigest, ManifestKey: req.ManifestKey, MinerID: candidate.ID(),
		RouteHost: routeHost, AssignmentNonce: nonce, ChallengePath: req.Workload.ChallengePath,
		ChallengeSHA256: protocol.ChallengeDigest(req.Workload.ChallengeValue),
		Resources:       protocol.ResourceLimits{CPUMillis: 1000, MemoryMB: 512, DiskMB: 2048},
		Health:          protocol.HealthSpec{Path: "/healthz", ExpectedStatus: 200, IntervalMillis: 1000, TimeoutMillis: 3000, ConsecutiveFailure: 2},
		IssuedAt:        now.UTC(), ExpiresAt: now.Add(5 * time.Minute).UTC(),
	}
	if subnet != nil {
		bound, ok := candidate.(miner.BoundAssigner)
		if !ok {
			return protocol.Ticket{}, fmt.Errorf("miner %q lacks Bittensor identity", candidate.ID())
		}
		identity := bound.SubnetIdentity()
		if identity.AxonURL == "" || (identity.Transport != "https" && identity.Transport != "http") {
			return protocol.Ticket{}, fmt.Errorf("miner %q lacks an assignment-time transport identity", candidate.ID())
		}
		binding := *subnet
		binding.MinerHotkey = identity.Hotkey
		binding.MinerUID = identity.UID
		binding.MinerAxonURL = identity.AxonURL
		binding.MinerTransport = identity.Transport
		if identity.TransportCertificateSHA256 != "" {
			pin := identity.TransportCertificateSHA256
			binding.MinerTLSCertificateSHA256 = &pin
		} else {
			binding.MinerTLSCertificateSHA256 = nil
		}
		binding.ValidatorServicePublicKey = hex.EncodeToString(s.SigningKey.Public().(ed25519.PublicKey))
		binding.MinerServicePublicKey = hex.EncodeToString(candidate.PublicKey())
		t.Version = protocol.BoundVersion
		t.MinerID = identity.Hotkey
		t.Subnet = &binding
	}
	return t, protocol.SignTicket(&t, s.SigningKey)
}

func (s *Scheduler) verifyResult(candidate miner.Assigner, ticket protocol.Ticket, result miner.Result) error {
	return s.verifyResultForDisposition(candidate, ticket, result, ScoringProductionEligible)
}

func (s *Scheduler) verifyResultForDisposition(candidate miner.Assigner, ticket protocol.Ticket, result miner.Result, disposition ScoringDisposition) error {
	r := result.Receipt
	if err := protocol.VerifyReceipt(r, candidate.PublicKey()); err != nil {
		return s.trustZeroForDisposition(candidate.ID(), err, disposition)
	}
	expectedReplicaID := protocol.ReplicaID(ticket)
	expectedEndpoint := expectedEndpointID(ticket)
	if r.DeploymentID != ticket.DeploymentID || r.Generation != ticket.Generation || r.AssignmentNonce != ticket.AssignmentNonce ||
		r.MinerID != ticket.MinerID || r.MinerID != candidate.ID() || r.ReplicaID != expectedReplicaID ||
		r.EndpointID != expectedEndpoint || result.EndpointID != expectedEndpoint || r.ImageDigest != ticket.ImageDigest ||
		r.ManifestKey != ticket.ManifestKey || r.RouteHost != ticket.RouteHost || r.Stage != protocol.StageReady ||
		!protocol.EqualSubnetBinding(r.Subnet, ticket.Subnet) {
		return s.trustZeroForDisposition(candidate.ID(), fmt.Errorf("receipt does not match exact assignment ticket"), disposition)
	}
	return nil
}

func (s *Scheduler) trustZeroForDisposition(minerID string, cause error, disposition ScoringDisposition) error {
	if disposition == ScoringEvidenceOnly {
		return cause
	}
	return s.trustZero(minerID, cause)
}

func (s *Scheduler) trustZero(minerID string, cause error) error {
	if err := s.Ledger.SetTrust(minerID, 0); err != nil {
		return &trustPersistenceError{minerID: minerID, cause: cause, persistence: err}
	}
	return cause
}

type trustPersistenceError struct {
	minerID     string
	cause       error
	persistence error
}

func (e *trustPersistenceError) Error() string {
	return fmt.Sprintf("invalid receipt from miner %q (%v); persist trust-zero: %v", e.minerID, e.cause, e.persistence)
}

func (e *trustPersistenceError) Unwrap() []error {
	return []error{e.cause, e.persistence}
}

func expectedEndpointID(ticket protocol.Ticket) string {
	return protocol.EndpointID(ticket)
}

func (s *Scheduler) deactivateTicket(ctx context.Context, candidate miner.Assigner, ticket protocol.Ticket) error {
	if ctx == nil {
		return errors.New("assignment cleanup context is required")
	}
	var routeErr error
	if s.Router != nil && len(s.SigningKey) == ed25519.PrivateKeySize {
		routeErr = s.Router.Deactivate(ctx, ticket, s.SigningKey)
		if routeErr != nil {
			routeErr = fmt.Errorf("deactivate edge route: %w", routeErr)
		}
	}
	if known, ok := candidate.(interface {
		DeactivateKnown(context.Context, string, string) error
	}); ok {
		if err := known.DeactivateKnown(ctx, expectedEndpointID(ticket), ticket.DeploymentID); err != nil {
			return errors.Join(routeErr, err)
		}
		if store := s.Ledger.Durable(); store != nil {
			return errors.Join(routeErr, store.DeactivateEndpoint(ctx, expectedEndpointID(ticket)))
		}
		return routeErr
	}
	return errors.Join(routeErr, s.deactivate(ctx, candidate, expectedEndpointID(ticket)))
}

func (s *Scheduler) deactivate(ctx context.Context, candidate miner.Assigner, endpointID string) error {
	if ctx == nil {
		return errors.New("endpoint cleanup context is required")
	}
	if err := candidate.Deactivate(ctx, endpointID); err != nil {
		return err
	}
	if store := s.Ledger.Durable(); store != nil {
		if err := store.DeactivateEndpoint(ctx, endpointID); err != nil {
			return err
		}
	}
	return nil
}

func cleanupBudget(parent context.Context) (context.Context, context.CancelFunc) {
	base := context.Background()
	if parent != nil {
		// Cleanup ownership survives request cancellation, but remains bounded by
		// one shared deadline across route, miner, and durable state.
		base = context.WithoutCancel(parent)
	}
	return context.WithTimeout(base, assignmentCleanupTime)
}

func (s *Scheduler) cleanupTicket(parent context.Context, candidate miner.Assigner, ticket protocol.Ticket) error {
	ctx, cancel := cleanupBudget(parent)
	defer cancel()
	return s.deactivateTicket(ctx, candidate, ticket)
}

func (s *Scheduler) cleanupEndpoint(parent context.Context, candidate miner.Assigner, endpointID string) error {
	ctx, cancel := cleanupBudget(parent)
	defer cancel()
	return s.deactivate(ctx, candidate, endpointID)
}

func (s *Scheduler) monitor() *policy.Monitor {
	s.mu.Lock()
	if s.Health == nil {
		s.Health = policy.NewMonitor()
	}
	health := s.Health
	s.mu.Unlock()
	return health
}

// ObserveHealth applies post-acceptance serving/economic policy for legacy Go
// callers. Deprecated: new integrations should submit the versioned v3 health
// contract through HandleHealth. The exact route ticket is verified before
// any policy mutation, and this compatibility seam shares the same replay
// fence as v3 so it cannot regress v3 freshness state.
func (s *Scheduler) ObserveHealth(routeHost, replicaID, endpointID, minerID, vantage string, reachable, correct, fraudulent bool, at time.Time) (policy.Action, error) {
	if !s.beginLifecycleWorker() {
		return policy.Action{}, errors.New("scheduler is draining")
	}
	defer s.endLifecycleWorker()
	ticket, exists := s.Router.TicketFor(routeHost, replicaID, endpointID, minerID)
	if !exists {
		return policy.Action{}, errors.New("health observation does not identify an exact active route incarnation")
	}
	action, applied := s.monitor().ObserveExternalIfNewer(endpointID, vantage, reachable, correct, fraudulent, at)
	if !applied {
		return policy.Action{}, errHealthObservationStale
	}
	if action.RemoveFromRouting {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), assignmentCleanupTime)
		err := s.Router.Deactivate(cleanupCtx, ticket, s.SigningKey)
		cancel()
		if err != nil {
			return action, fmt.Errorf("deactivate unhealthy edge route: %w", err)
		}
	}
	if action.TrustZero {
		if err := s.Ledger.SetTrust(minerID, 0); err != nil {
			return action, err
		}
	}
	return action, nil
}

// HandleHealth applies an authenticated external post-acceptance observation.
// EndpointID is mandatory because ReplicaID is stable across replacement
// generations. The private runtime transport authenticates the caller before
// this method, and this method repeats the exact current-incarnation check
// immediately before mutating health state.
func (s *Scheduler) HandleHealth(ctx context.Context, deploymentID, replicaID, endpointID, minerID, vantage string, reachable, correct, fraudulent bool, at time.Time) (policy.Action, error) {
	return s.HandleHealthWithCommit(ctx, deploymentID, replicaID, endpointID, minerID, vantage, reachable, correct, fraudulent, at, nil)
}

// HandleHealthWithCommit is the durable external-observation boundary. commit
// runs under exact-incarnation and replay/order serialization immediately
// before policy state changes. If it fails, no health evidence is consumed and
// the identical authenticated report remains retryable. The callback must be
// bounded and must not call back into this Scheduler or its Health monitor;
// doing so would re-enter the serialization locks. The production caller uses
// it only for the independent durable observation insert.
func (s *Scheduler) HandleHealthWithCommit(ctx context.Context, deploymentID, replicaID, endpointID, minerID, vantage string, reachable, correct, fraudulent bool, at time.Time, commit func() error) (policy.Action, error) {
	if endpointID == "" {
		return policy.Action{}, errors.New("external health observation requires an exact endpoint incarnation")
	}
	action, applied, _, err := s.handleHealth(ctx, deploymentID, replicaID, endpointID, minerID, vantage, reachable, correct, fraudulent, at, false, nil, nil, commit)
	if applied && err != nil {
		err = &committedHealthActionError{cause: err}
	}
	return action, err
}

// handleEndpointHealth applies an internal observation only if endpointID is
// still the exact active generation/nonce incarnation that was probed.
func (s *Scheduler) handleEndpointHealth(ctx context.Context, deploymentID, replicaID, endpointID, minerID, vantage string, reachable, correct, fraudulent bool, at time.Time) (policy.Action, error) {
	action, _, _, err := s.handleHealth(ctx, deploymentID, replicaID, endpointID, minerID, vantage, reachable, correct, fraudulent, at, true, nil, nil, nil)
	return action, err
}

func (s *Scheduler) handleEndpointHealthVersioned(ctx context.Context, deploymentID, replicaID, endpointID, minerID, vantage string, reachable, correct, fraudulent bool, at time.Time, expectedHealthVersion, expectedCircuitVersion uint64) (policy.Action, bool, bool, error) {
	return s.handleHealth(ctx, deploymentID, replicaID, endpointID, minerID, vantage, reachable, correct, fraudulent, at, true, &expectedHealthVersion, &expectedCircuitVersion, nil)
}

// suppressEndpointAvailabilityIfVersion opens only the process-local serving
// circuit when unreachable evidence is not yet safe to apply economically or
// durably. Its route-local CAS is independent of economic-health history: an
// external report cannot mask this validator's newer targeted result, while a
// newer local circuit decision still fences an older in-flight probe.
func (s *Scheduler) suppressEndpointAvailabilityIfVersion(ctx context.Context, deploymentID, replicaID, endpointID, minerID string, expectedCircuitVersion uint64) (bool, bool, error) {
	return s.setEndpointAvailabilityIfCircuitVersion(ctx, deploymentID, replicaID, endpointID, minerID, false, expectedCircuitVersion)
}

// setEndpointAvailabilityIfCircuitVersion changes only process-local serving
// availability for the exact active endpoint incarnation. It adds no health
// evidence and has no economic effect.
func (s *Scheduler) setEndpointAvailabilityIfCircuitVersion(ctx context.Context, deploymentID, replicaID, endpointID, minerID string, available bool, expectedCircuitVersion uint64) (bool, bool, error) {
	if err := ctx.Err(); err != nil {
		return false, false, err
	}
	if !s.beginLifecycleWorker() {
		return false, false, errors.New("scheduler is draining")
	}
	defer s.endLifecycleWorker()
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.states[deploymentID]
	if state == nil {
		return false, false, fmt.Errorf("deployment %q: %w", deploymentID, ErrUnknownDeployment)
	}
	if state.deactivationRequested {
		return false, false, fmt.Errorf("deployment %q: %w", deploymentID, ErrDeploymentDeactivating)
	}
	assignment := state.active[minerID]
	if assignment.miner == nil || assignment.replicaID != replicaID || assignment.endpointID != endpointID {
		return false, false, fmt.Errorf("replica %q of miner %q: %w", replicaID, minerID, ErrReplicaNotActive)
	}
	if err := ctx.Err(); err != nil {
		return false, false, err
	}
	if s.circuitVersionLocked(endpointID) != expectedCircuitVersion || expectedCircuitVersion == ^uint64(0) {
		return false, false, errHealthObservationChanged
	}
	matched, changed := s.Router.SetTemporaryAvailability(
		state.routeHost, replicaID, endpointID, minerID, available, s.SigningKey,
	)
	if !matched {
		return false, true, fmt.Errorf("replica %q of miner %q serving circuit: %w", replicaID, minerID, ErrReplicaNotActive)
	}
	s.advanceCircuitVersionLocked(endpointID)
	return changed, true, nil
}

func (s *Scheduler) circuitVersionLocked(endpointID string) uint64 {
	if s.circuitVersions == nil {
		return 0
	}
	return s.circuitVersions[endpointID]
}

func (s *Scheduler) advanceCircuitVersionLocked(endpointID string) bool {
	if s.circuitVersions == nil {
		s.circuitVersions = make(map[string]uint64)
	}
	if s.circuitVersions[endpointID] == ^uint64(0) {
		return false
	}
	s.circuitVersions[endpointID]++
	return true
}

// handleHealth applies post-acceptance policy and synchronously restores the
// requested replica count. Validation, monitor observation, and ownership of a
// removal are claimed under one scheduler lock, so teardown/redeploy cannot
// turn an already in-flight result into an action on a newer incarnation.
func (s *Scheduler) handleHealth(ctx context.Context, deploymentID, replicaID, endpointID, minerID, vantage string, reachable, correct, fraudulent bool, at time.Time, suppressInternalLivenessTrust bool, expectedHealthVersion, expectedCircuitVersion *uint64, externalCommit func() error) (policy.Action, bool, bool, error) {
	if err := ctx.Err(); err != nil {
		return policy.Action{}, false, false, err
	}
	if !s.beginLifecycleWorker() {
		return policy.Action{}, false, false, errors.New("scheduler is draining")
	}
	defer s.endLifecycleWorker()
	health := s.monitor()
	s.mu.Lock()
	state := s.states[deploymentID]
	deactivating := state != nil && state.deactivationRequested
	var removed activeAssignment
	if state != nil && !deactivating {
		removed = state.active[minerID]
	}
	if state == nil {
		s.mu.Unlock()
		return policy.Action{}, false, false, fmt.Errorf("deployment %q: %w", deploymentID, ErrUnknownDeployment)
	}
	if deactivating {
		s.mu.Unlock()
		return policy.Action{}, false, false, fmt.Errorf("deployment %q: %w", deploymentID, ErrDeploymentDeactivating)
	}
	if removed.miner == nil || removed.replicaID != replicaID || removed.endpointID != endpointID {
		s.mu.Unlock()
		return policy.Action{}, false, false, fmt.Errorf("replica %q of miner %q: %w", replicaID, minerID, ErrReplicaNotActive)
	}
	if err := ctx.Err(); err != nil {
		s.mu.Unlock()
		return policy.Action{}, false, false, err
	}
	definitiveFault := fraudulent || (reachable && !correct)
	currentCircuitVersion := s.circuitVersionLocked(endpointID)
	if suppressInternalLivenessTrust && currentCircuitVersion == ^uint64(0) && !definitiveFault {
		s.mu.Unlock()
		return policy.Action{}, false, false, errHealthObservationChanged
	}
	if expectedCircuitVersion != nil && currentCircuitVersion != *expectedCircuitVersion && !definitiveFault {
		s.mu.Unlock()
		return policy.Action{}, false, false, errHealthObservationChanged
	}
	var action policy.Action
	if expectedHealthVersion == nil {
		if suppressInternalLivenessTrust {
			action = health.ObserveInternal(removed.endpointID, vantage, reachable, correct, fraudulent, at)
		} else {
			var applied bool
			var commitErr error
			action, applied, commitErr = health.ObserveExternalIfNewerWithCommit(removed.endpointID, vantage, reachable, correct, fraudulent, at, externalCommit)
			if commitErr != nil {
				s.mu.Unlock()
				return policy.Action{}, false, false, commitErr
			}
			if !applied {
				s.mu.Unlock()
				return policy.Action{}, false, false, errHealthObservationStale
			}
		}
	} else {
		var applied bool
		action, applied = health.ObserveIfVersionContext(ctx, removed.endpointID, vantage, reachable, correct, fraudulent, at, *expectedHealthVersion)
		if !applied {
			if err := ctx.Err(); err != nil {
				s.mu.Unlock()
				return policy.Action{}, false, false, err
			}
			// External evidence can advance economic-health history while this
			// validator's targeted request is in flight. That must not make a
			// locally broken route remain available (or a recovered route remain
			// suppressed). Commit only the exact circuit result under its
			// independent CAS, without adding policy evidence or corroboration.
			routingChanged := false
			var routingErr error
			if suppressInternalLivenessTrust && expectedCircuitVersion != nil && *expectedCircuitVersion != ^uint64(0) && s.circuitVersionLocked(endpointID) == *expectedCircuitVersion {
				available := reachable && correct && !fraudulent
				matched, changed := s.Router.SetTemporaryAvailability(
					state.routeHost, removed.replicaID, removed.endpointID, minerID, available, s.SigningKey,
				)
				routingChanged = changed
				if !matched {
					routingErr = fmt.Errorf("replica %q of miner %q serving circuit: %w", replicaID, minerID, ErrReplicaNotActive)
				} else {
					s.advanceCircuitVersionLocked(endpointID)
				}
			}
			s.mu.Unlock()
			return policy.Action{}, false, routingChanged, errors.Join(errHealthObservationChanged, routingErr)
		}
	}
	// Commit serving availability only after the exact endpoint and expected
	// monitor version have both matched, while Scheduler.mu still prevents a
	// concurrent removal/replacement. This makes the final ordering fail-closed:
	// a stale successful probe cannot re-enable a route removed by newer fault
	// evidence, and every non-correct response is suppressed before durable
	// teardown is attempted.
	routingChanged := false
	var routingErr error
	// Only the in-process targeted prober owns temporary circuit restoration.
	// An externally authenticated healthy report cannot prove that this
	// validator's edge path recovered. External evidence may still force the
	// circuit closed when policy commits a durable removal.
	if suppressInternalLivenessTrust || action.RemoveFromRouting {
		available := suppressInternalLivenessTrust && reachable && correct && !fraudulent && !action.RemoveFromRouting
		matched, changed := s.Router.SetTemporaryAvailability(
			state.routeHost, removed.replicaID, removed.endpointID, minerID, available, s.SigningKey,
		)
		routingChanged = changed
		if !matched {
			routingErr = fmt.Errorf("replica %q of miner %q serving circuit: %w", replicaID, minerID, ErrReplicaNotActive)
		} else {
			s.advanceCircuitVersionLocked(endpointID)
		}
	}
	if action.TrustZero && (state.request.ScoringDisposition == ScoringEvidenceOnly || (suppressInternalLivenessTrust && !reachable)) {
		action.TrustZero = false
	}
	if action.RemoveFromRouting {
		delete(state.active, minerID)
		s.retireProbeStateLocked(removed.endpointID)
		state.excluded[minerID] = struct{}{}
		// Transfer exact ownership before releasing the scheduler lock. A
		// concurrent deployment teardown must see this lease and cannot delete the
		// state while route/miner/durable cleanup is in flight.
		state.pendingCleanup[minerID] = &cleanupLease{
			assignment: removed, preserveExclusion: true, cleaning: true,
		}
		s.bumpProbeTopologyLocked()
	}
	s.mu.Unlock()

	var trustErr error
	if action.TrustZero {
		if err := s.Ledger.SetTrust(minerID, 0); err != nil {
			trustErr = fmt.Errorf("persist trust-zero for miner %q: %w", minerID, err)
		}
	}
	if !action.RemoveFromRouting {
		// Inconclusive replacement probes leave clean candidates available and a
		// deficit visible in desired-active-reserved capacity. Each later correct
		// observation proves the shared path works and repairs at most one deficit.
		if reachable && correct && !fraudulent {
			return action, true, routingChanged, errors.Join(routingErr, trustErr, s.repairOneDeficitOwned(ctx))
		}
		return action, true, routingChanged, errors.Join(routingErr, trustErr)
	}
	cleanupCtx, cancelCleanup := cleanupBudget(ctx)
	routeErr := s.Router.Deactivate(cleanupCtx, removed.ticket, s.SigningKey)
	cleanupErr := s.deactivate(cleanupCtx, removed.miner, removed.endpointID)
	cancelCleanup()
	s.finishCleanupLease(state, minerID, removed.endpointID, errors.Join(routeErr, cleanupErr))
	// Only the removal owner reaches this line, and a replacement always
	// observes under a new generation/nonce endpoint key, so the removed
	// incarnation's monitor state can be released instead of accumulating
	// forever in a long-running control plane.
	if cleanupErr != nil {
		cleanupErr = fmt.Errorf("deactivate removed endpoint %q: %w", removed.endpointID, cleanupErr)
	}
	if routeErr != nil {
		routeErr = fmt.Errorf("deactivate removed edge route %q: %w", removed.endpointID, routeErr)
	}
	var replacementErr error
	if action.AssignReplacement {
		replacementErr = s.assignReplacement(ctx, state)
	}
	return action, true, routingChanged, errors.Join(routingErr, trustErr, routeErr, cleanupErr, replacementErr)
}

func (s *Scheduler) assignReplacement(ctx context.Context, state *deploymentState) error {
	repairCtx, cancel := s.replacementLifecycleContext(ctx, state)
	defer cancel()
	cleanupErr := s.retryPendingCleanup(repairCtx, state)
	return errors.Join(cleanupErr, s.assignReplacementAfterCleanup(repairCtx, state))
}

// retryPendingCleanup resolves exact inconclusive-assignment ownership before
// placement considers that miner again. Failures stay quarantined but do not
// prevent another clean candidate from restoring the deployment's capacity.
func (s *Scheduler) retryPendingCleanup(ctx context.Context, state *deploymentState) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	if s.states[state.request.DeploymentID] != state || state.deactivationRequested {
		s.mu.Unlock()
		return nil
	}
	minerIDs := make([]string, 0, len(state.pendingCleanup))
	for minerID, lease := range state.pendingCleanup {
		if !lease.assignmentPending && !lease.cleaning {
			minerIDs = append(minerIDs, minerID)
		}
	}
	sort.Strings(minerIDs)
	minerID := nextSortedID(minerIDs, state.cleanupCursor)
	var assignment activeAssignment
	if minerID != "" {
		state.cleanupCursor = minerID
		lease := state.pendingCleanup[minerID]
		lease.cleaning = true
		lease.requiresRetry = false
		assignment = lease.assignment
	}
	s.mu.Unlock()
	if minerID == "" {
		return nil
	}
	cleanupErr := s.cleanupTicket(ctx, assignment.miner, assignment.ticket)
	s.finishCleanupLease(state, minerID, assignment.endpointID, cleanupErr)
	if cleanupErr != nil {
		return fmt.Errorf("retry cleanup for endpoint %q: %w", assignment.endpointID, cleanupErr)
	}
	return nil
}

func nextSortedID(ids []string, after string) string {
	if len(ids) == 0 {
		return ""
	}
	index := sort.SearchStrings(ids, after)
	for index < len(ids) && ids[index] <= after {
		index++
	}
	if index == len(ids) {
		index = 0
	}
	return ids[index]
}

func (s *Scheduler) assignReplacementAfterCleanup(ctx context.Context, state *deploymentState) error {
	attemptedCandidates := make(map[string]struct{})
	var lastInconclusive error
	for {
		reservation, generation, available, needed := s.reserveReplacementCandidateSkipping(state, attemptedCandidates)
		if !needed {
			return nil
		}
		if reservation == nil {
			return errors.Join(lastInconclusive, &CapacityError{DeploymentID: state.request.DeploymentID, Required: s.replicaCount(), Available: available})
		}
		candidate := reservation.candidate
		attemptedCandidates[candidate.ID()] = struct{}{}
		ticket, err := s.ticketForReservation(state.request, reservation, state.routeHost, generation, s.clock()())
		if err != nil {
			s.releaseReservation(state, candidate.ID())
			return err
		}
		if err := s.Ledger.RecordAssignment(ticket, "published"); err != nil {
			s.releaseReservation(state, candidate.ID())
			return err
		}
		attempt := newAssignmentAttempt(s, state, ctx, 1)
		if err := attempt.launch(candidate, ticket); err != nil {
			s.releaseReservation(state, candidate.ID())
			return err
		}
		var outcome assignmentResult
		select {
		case <-ctx.Done():
			attempt.abort()
			return fmt.Errorf("replacement assignment to %s: %w", candidate.ID(), ctx.Err())
		case outcome = <-attempt.results:
			attempt.complete()
		}
		recordObservation := func(success bool) error {
			if state.request.ScoringDisposition == ScoringEvidenceOnly {
				return nil
			}
			availability := 0.0
			if success {
				availability = 1
			}
			return s.Ledger.RecordObservation(durable.Observation{
				MinerHotkey: candidate.ID(), Success: success,
				LatencyMS: max(outcome.latency.Milliseconds(), 0), Availability: availability,
				ObservedAt: outcome.observedAt, Kind: "acceptance",
			})
		}
		if ctx.Err() != nil {
			cleanupErr := s.cleanupReservation(ctx, state, outcome, false)
			return errors.Join(fmt.Errorf("replacement assignment to %s: %w", candidate.ID(), ctx.Err()), cleanupErr)
		}
		if outcome.err != nil || !s.Ledger.Eligible(candidate.ID()) {
			cleanupErr := s.cleanupReservation(ctx, state, outcome, true)
			if err := recordObservation(false); err != nil {
				return errors.Join(fmt.Errorf("persist replacement observation: %w", err), cleanupErr)
			}
			if cleanupErr != nil {
				return fmt.Errorf("cleanup failed replacement assignment: %w", cleanupErr)
			}
			if ctx.Err() != nil {
				return fmt.Errorf("replacement assignment to %s: %w", candidate.ID(), ctx.Err())
			}
			continue
		}
		if verifyErr := s.verifyResultForDisposition(candidate, ticket, outcome.result, state.request.ScoringDisposition); verifyErr != nil {
			cleanupErr := s.cleanupReservation(ctx, state, outcome, true)
			observationErr := recordObservation(false)
			var persistenceErr *trustPersistenceError
			if errors.As(verifyErr, &persistenceErr) {
				if cleanupErr != nil {
					cleanupErr = fmt.Errorf("cleanup invalid replacement receipt: %w", cleanupErr)
				}
				return errors.Join(
					fmt.Errorf("reject invalid replacement receipt: %w", verifyErr),
					cleanupErr,
					observationErr,
				)
			}
			if observationErr != nil {
				return fmt.Errorf("persist replacement observation: %w", observationErr)
			}
			continue
		}
		if err := s.Ledger.AddReceipt(outcome.result.Receipt); err != nil {
			cleanupErr := s.cleanupReservation(ctx, state, outcome, true)
			return errors.Join(fmt.Errorf("persist replacement receipt: %w", err), cleanupErr)
		}
		if err := s.Router.RegisterPending(ctx, ticket, outcome.result.Receipt, candidate.PublicKey(), s.SigningKey); err != nil {
			cleanupErr := s.cleanupReservation(ctx, state, outcome, true)
			return errors.Join(fmt.Errorf("register authenticated replacement edge route: %w", err), cleanupErr)
		}
		probe := s.Validator.ProbeReplica(ctx, state.routeHost, outcome.result.Receipt.ReplicaID, state.request.Workload.ChallengePath, state.request.Workload.ChallengeValue)
		if err := ctx.Err(); err != nil {
			probe.ResponseComplete = false
			probe.Error = err.Error()
			return errors.Join(
				s.rejectInconclusiveAcceptance(ctx, state, outcome, probe),
				fmt.Errorf("replacement assignment to %s: %w", candidate.ID(), err),
			)
		}
		if !probe.Correct {
			if !attributableAcceptanceFailure(probe) {
				lastInconclusive = errors.Join(lastInconclusive, s.rejectInconclusiveAcceptance(ctx, state, outcome, probe))
				if ctx.Err() != nil {
					return errors.Join(lastInconclusive, ctx.Err())
				}
				continue
			}
			if err := s.rejectAcceptance(ctx, state, state.routeHost, outcome, state.request.ScoringDisposition); err != nil {
				return fmt.Errorf("persist replacement acceptance rejection: %w", err)
			}
			if err := recordObservation(false); err != nil {
				return fmt.Errorf("persist replacement observation: %w", err)
			}
			if ctx.Err() != nil {
				return fmt.Errorf("replacement %s failed strict acceptance probe: %s", candidate.ID(), probe.Error)
			}
			continue
		}
		if err := s.Router.Activate(ctx, ticket, outcome.result.Receipt, candidate.PublicKey(), s.SigningKey); err != nil {
			cleanupErr := s.cleanupReservation(ctx, state, outcome, true)
			return errors.Join(fmt.Errorf("activate authenticated replacement edge route: %w", err), cleanupErr)
		}
		assignment := activeAssignment{
			miner: candidate, replicaID: outcome.result.Receipt.ReplicaID, endpointID: expectedEndpointID(ticket),
			ticket: ticket, receipt: outcome.result.Receipt,
			publicationID: reservation.publicationID, publicationVersion: reservation.publicationVersion,
		}
		if store := s.Ledger.Durable(); store != nil {
			if err := store.PutEndpoint(ctx, durable.Endpoint{EndpointID: assignment.endpointID, DeploymentID: state.request.DeploymentID, MinerHotkey: candidate.ID(), Active: true}); err != nil {
				cleanupErr := s.cleanupReservation(ctx, state, outcome, false)
				return errors.Join(err, cleanupErr)
			}
		}
		if disposition := s.acceptReservation(state, candidate.ID(), assignment); disposition != reservationAccepted {
			cleanupErr := s.cleanupUnaccepted(ctx, state, outcome)
			return errors.Join(
				fmt.Errorf("deployment %q rejected replacement reservation (disposition %d)", state.request.DeploymentID, disposition),
				cleanupErr,
			)
		}
		if err := recordObservation(true); err != nil {
			if s.afterReplacementObservationFailure != nil {
				s.afterReplacementObservationFailure()
			}
			// cleanupUnaccepted atomically transfers this exact active endpoint to
			// a claimed cleanup lease before doing I/O. Deleting active ownership
			// first would let concurrent deployment teardown observe neither owner
			// and leave the activated route/runtime orphaned.
			cleanupErr := s.cleanupUnaccepted(ctx, state, outcome)
			return errors.Join(fmt.Errorf("persist replacement observation: %w", err), cleanupErr)
		}
		return nil
	}
}

// repairOneDeficit claims at most one missing replica across settled
// deployments. Capacity debt is derived from active plus in-flight
// reservations instead of stored as a boolean, so concurrent removals cannot
// collapse into one retry and concurrent healthy observations cannot overfill
// a deployment.
func (s *Scheduler) repairOneDeficit(ctx context.Context) error {
	if !s.beginLifecycleWorker() {
		return errors.New("scheduler is draining")
	}
	defer s.endLifecycleWorker()
	return s.repairOneDeficitOwned(ctx)
}

func (s *Scheduler) repairOneDeficitOwned(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	// A successful health observation is also a safe bounded opportunity to
	// retry one exact cleanup lease, even when another candidate has already
	// restored capacity. This eventually returns a clean candidate to the pool
	// without ever reusing it while its prior incarnation is uncertain.
	s.mu.Lock()
	pendingIDs := make([]string, 0, len(s.states))
	for deploymentID, state := range s.states {
		if state.deploying || state.deactivationRequested || len(state.pendingCleanup) == 0 {
			continue
		}
		pendingIDs = append(pendingIDs, deploymentID)
	}
	sort.Strings(pendingIDs)
	var cleanupState *deploymentState
	if cleanupID := nextSortedID(pendingIDs, s.cleanupCursor); cleanupID != "" {
		s.cleanupCursor = cleanupID
		cleanupState = s.states[cleanupID]
	}
	s.mu.Unlock()
	var cleanupErr error
	if cleanupState != nil {
		cleanupErr = s.retryPendingCleanup(ctx, cleanupState)
	}
	if err := ctx.Err(); err != nil {
		return errors.Join(cleanupErr, err)
	}

	s.mu.Lock()
	deploymentIDs := make([]string, 0, len(s.states))
	for deploymentID, state := range s.states {
		if state.deploying || state.deactivationRequested || len(state.active)+len(state.reserved) >= s.replicaCount() {
			continue
		}
		deploymentIDs = append(deploymentIDs, deploymentID)
	}
	sort.Strings(deploymentIDs)
	var state *deploymentState
	if deploymentID := nextSortedID(deploymentIDs, s.deficitCursor); deploymentID != "" {
		s.deficitCursor = deploymentID
		state = s.states[deploymentID]
	}
	s.mu.Unlock()
	if state == nil {
		return cleanupErr
	}
	repairCtx, cancel := s.replacementLifecycleContext(ctx, state)
	defer cancel()
	return errors.Join(cleanupErr, s.assignReplacementAfterCleanup(repairCtx, state))
}

func (s *Scheduler) replacementLifecycleContext(parent context.Context, state *deploymentState) (context.Context, context.CancelFunc) {
	timeout := defaultDeployTimeout
	if state != nil && state.request.Timeout > 0 {
		timeout = state.request.Timeout
	}
	return context.WithTimeout(parent, timeout)
}

// DeactivateDeployment removes an active deployment using the endpoint IDs
// retained from its exact signed tickets. Failed assignments remain owned by
// the state so a later call retries the same route/miner/durable incarnation.
func (s *Scheduler) DeactivateDeployment(ctx context.Context, deploymentID string) error {
	if ctx == nil {
		return errors.New("deployment cleanup context is required")
	}
	if !s.beginLifecycleWorker() {
		return errors.New("scheduler is draining")
	}
	defer s.endLifecycleWorker()
	s.mu.Lock()
	state := s.states[deploymentID]
	if state == nil {
		s.mu.Unlock()
		return nil
	}
	if state.cleanupInProgress {
		s.mu.Unlock()
		return fmt.Errorf("deployment %q cleanup is already in progress", deploymentID)
	}
	if !state.deactivationRequested {
		state.deactivationRequested = true
		s.bumpProbeTopologyLocked()
	}
	state.cleanupInProgress = true
	assignments := make([]activeAssignment, 0, len(state.active)+len(state.pendingCleanup))
	seenEndpoints := make(map[string]struct{}, len(state.active)+len(state.pendingCleanup))
	pendingWorkers := len(state.reserved)
	activeChanged := false
	for minerID, assignment := range state.active {
		// Transfer serving ownership into an exclusively claimed exact cleanup
		// lease before any external teardown begins. A concurrent failed Deploy
		// abort then sees this owner instead of starting a second cleanup for an
		// already accepted ticket.
		delete(state.active, minerID)
		s.retireProbeStateLocked(assignment.endpointID)
		state.excluded[minerID] = struct{}{}
		state.pendingCleanup[minerID] = &cleanupLease{
			assignment: assignment, preserveExclusion: true, cleaning: true,
		}
		assignments = append(assignments, assignment)
		seenEndpoints[assignment.endpointID] = struct{}{}
		activeChanged = true
	}
	for _, lease := range state.pendingCleanup {
		if _, duplicate := seenEndpoints[lease.assignment.endpointID]; duplicate {
			continue
		}
		if lease.assignmentPending || lease.cleaning {
			pendingWorkers++
			continue
		}
		// Claim the exact lease under Scheduler.mu before launching cleanup.
		// Cancellation fencing and repair retries therefore cannot clean the
		// same incarnation concurrently with deployment teardown.
		lease.cleaning = true
		assignment := lease.assignment
		assignments = append(assignments, assignment)
	}
	if activeChanged {
		s.bumpProbeTopologyLocked()
	}
	s.mu.Unlock()
	type cleanupResult struct {
		assignment activeAssignment
		err        error
	}
	var cleanup sync.WaitGroup
	results := make(chan cleanupResult, len(assignments))
	for _, assignment := range assignments {
		s.beginOwnedLifecycleWorker()
		cleanup.Add(1)
		go func(assignment activeAssignment) {
			defer cleanup.Done()
			defer s.endLifecycleWorker()
			routeErr := s.Router.Deactivate(ctx, assignment.ticket, s.SigningKey)
			var minerErr error
			if known, ok := assignment.miner.(interface {
				DeactivateKnown(context.Context, string, string) error
			}); ok {
				minerErr = known.DeactivateKnown(ctx, assignment.endpointID, assignment.ticket.DeploymentID)
			} else {
				minerErr = assignment.miner.Deactivate(ctx, assignment.endpointID)
			}
			var durableErr error
			if routeErr == nil && minerErr == nil {
				if store := s.Ledger.Durable(); store != nil {
					durableErr = store.DeactivateEndpoint(ctx, assignment.endpointID)
				}
			}
			results <- cleanupResult{assignment: assignment, err: errors.Join(routeErr, minerErr, durableErr)}
		}(assignment)
	}
	completed := make(chan error, 1)
	go func() {
		cleanup.Wait()
		close(results)
		var failures []error
		if pendingWorkers > 0 {
			failures = append(failures, fmt.Errorf("%d assignment or cleanup workers still own exact tickets", pendingWorkers))
		}
		succeeded := make([]activeAssignment, 0, len(assignments))
		failed := make([]activeAssignment, 0, len(assignments))
		for result := range results {
			if result.err != nil {
				failures = append(failures, result.err)
				failed = append(failed, result.assignment)
			} else {
				succeeded = append(succeeded, result.assignment)
			}
		}
		s.mu.Lock()
		if s.states[deploymentID] == state {
			for _, assignment := range succeeded {
				if current, exists := state.pendingCleanup[assignment.miner.ID()]; exists && current.assignment.endpointID == assignment.endpointID && !current.assignmentPending {
					delete(state.pendingCleanup, assignment.miner.ID())
				}
			}
			for _, assignment := range failed {
				if current := state.pendingCleanup[assignment.miner.ID()]; current != nil && current.assignment.endpointID == assignment.endpointID {
					current.cleaning = false
					current.requiresRetry = true
				}
			}
			state.cleanupInProgress = false
			if len(state.active) == 0 && len(state.reserved) == 0 && len(state.pendingCleanup) == 0 && !state.deploying {
				delete(s.states, deploymentID)
			} else if (state.deploying || len(state.reserved) > 0) && len(failures) == 0 {
				failures = append(failures, errors.New("deployment assignments or reservations are still in flight"))
			}
		}
		s.mu.Unlock()
		completed <- errors.Join(failures...)
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-completed:
		if err != nil {
			return fmt.Errorf("deactivate deployment %q: %w", deploymentID, err)
		}
		return nil
	}
}

// PendingCleanupAssignments reports the union of exact scheduler-owned and
// durable endpoint incarnations that still need cleanup. It never reacts,
// reroutes, or delivers cleanup.
func (s *Scheduler) PendingCleanupAssignments(ctx context.Context, deploymentID string) (int, error) {
	if ctx == nil {
		return 0, errors.New("cleanup inspection context is required")
	}
	if !s.beginLifecycleWorker() {
		return 0, errors.New("scheduler is draining")
	}
	defer s.endLifecycleWorker()
	if deploymentID == "" || s.Ledger == nil {
		return 0, nil
	}
	pending := make(map[string]struct{})
	s.mu.Lock()
	if state := s.states[deploymentID]; state != nil {
		for _, assignment := range state.active {
			pending[assignment.endpointID] = struct{}{}
		}
		for _, lease := range state.pendingCleanup {
			pending[lease.assignment.endpointID] = struct{}{}
		}
	}
	s.mu.Unlock()
	if s.Ledger.Durable() == nil {
		return len(pending), nil
	}
	endpoints, err := s.Ledger.Durable().CleanupAssignments(ctx, "")
	if err != nil {
		return len(pending), err
	}
	for _, endpoint := range endpoints {
		if endpoint.DeploymentID == deploymentID {
			pending[endpoint.EndpointID] = struct{}{}
		}
	}
	return len(pending), nil
}

func (s *Scheduler) replicaCount() int {
	if s.Replicas == 0 {
		return defaultReplicas
	}
	return s.Replicas
}

func (s *Scheduler) minerCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.Miners)
}

// InstallPublication atomically installs the exact subnet/miner pair accepted
// by the control API. Reservations capture both values and this local version
// under the same lock, so a later rebound publication cannot be mixed into an
// already-reserved candidate's ticket.
func (s *Scheduler) InstallPublication(publicationID string, binding protocol.SubnetBinding, miners []miner.Assigner) error {
	if publicationID == "" {
		return errors.New("scheduler publication identity is required")
	}
	seen := make(map[string]struct{}, len(miners))
	for _, candidate := range miners {
		if candidate == nil || candidate.ID() == "" {
			return errors.New("scheduler publication contains an empty miner identity")
		}
		if _, duplicate := seen[candidate.ID()]; duplicate {
			return fmt.Errorf("scheduler publication contains duplicate miner %q", candidate.ID())
		}
		seen[candidate.ID()] = struct{}{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.publicationVersion == ^uint64(0) {
		return errors.New("scheduler publication version exhausted")
	}
	copy := binding
	s.Miners = append([]miner.Assigner(nil), miners...)
	s.Subnet = cloneSubnetBinding(&copy)
	s.publicationID = publicationID
	s.publicationVersion++
	return nil
}

// SetMiners is retained for standalone/lab construction. Network control must
// use InstallPublication so the subnet and candidate set share one version.
func (s *Scheduler) SetMiners(miners []miner.Assigner) {
	s.mu.Lock()
	s.Miners = append([]miner.Assigner(nil), miners...)
	s.publicationID = ""
	s.publicationVersion++
	s.mu.Unlock()
}

// SetSubnet is retained for standalone tests; network control uses
// InstallPublication for coherent candidate/subnet installation.
func (s *Scheduler) SetSubnet(binding protocol.SubnetBinding) {
	s.mu.Lock()
	copy := binding
	s.Subnet = cloneSubnetBinding(&copy)
	s.publicationID = ""
	s.publicationVersion++
	s.mu.Unlock()
}

func (s *Scheduler) subnetSnapshot() *protocol.SubnetBinding {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Subnet == nil {
		return nil
	}
	return cloneSubnetBinding(s.Subnet)
}

func cloneSubnetBinding(binding *protocol.SubnetBinding) *protocol.SubnetBinding {
	if binding == nil {
		return nil
	}
	copy := *binding
	if binding.MinerUID != nil {
		uid := *binding.MinerUID
		copy.MinerUID = &uid
	}
	if binding.MinerTLSCertificateSHA256 != nil {
		pin := *binding.MinerTLSCertificateSHA256
		copy.MinerTLSCertificateSHA256 = &pin
	}
	return &copy
}

type ActiveReplica struct {
	MinerID    string `json:"miner_id"`
	ReplicaID  string `json:"replica_id"`
	EndpointID string `json:"endpoint_id"`
}

func (s *Scheduler) ActiveReplicas(deploymentID string) []ActiveReplica {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.states[deploymentID]
	if state == nil {
		return nil
	}
	values := make([]ActiveReplica, 0, len(state.active))
	for minerID, assignment := range state.active {
		values = append(values, ActiveReplica{MinerID: minerID, ReplicaID: assignment.replicaID, EndpointID: assignment.endpointID})
	}
	sort.Slice(values, func(i, j int) bool { return values[i].MinerID < values[j].MinerID })
	return values
}

// activeProbePeers verifies that one endpoint incarnation is still active and
// returns the current route-local and process-global peers plus an exact health
// snapshot and the independent route-circuit revision. The periodic prober
// uses this before touching its local corroboration state, then
// handleEndpointHealthVersioned repeats the endpoint, health-version, and
// circuit-version checks at the mutation boundary.
type probePeerSet struct {
	deployment    []ActiveReplica
	global        []ActiveReplica
	targetHealth  policy.ObservationSnapshot
	targetCircuit uint64
	topologyEpoch uint64
}

func (s *Scheduler) activeProbePeers(deploymentID, replicaID, endpointID, minerID string) (probePeerSet, error) {
	health := s.monitor()
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.states[deploymentID]
	if state == nil {
		return probePeerSet{}, fmt.Errorf("deployment %q: %w", deploymentID, ErrUnknownDeployment)
	}
	if state.deactivationRequested {
		return probePeerSet{}, fmt.Errorf("deployment %q: %w", deploymentID, ErrDeploymentDeactivating)
	}
	assignment := state.active[minerID]
	if assignment.miner == nil || assignment.replicaID != replicaID || assignment.endpointID != endpointID {
		return probePeerSet{}, fmt.Errorf("replica %q of miner %q: %w", replicaID, minerID, ErrReplicaNotActive)
	}
	peers := probePeerSet{
		deployment:    make([]ActiveReplica, 0, len(state.active)),
		topologyEpoch: s.probeTopology,
	}
	peers.targetHealth = health.Snapshot(endpointID)
	peers.targetCircuit = s.circuitVersionLocked(endpointID)
	for activeMinerID, active := range state.active {
		peers.deployment = append(peers.deployment, ActiveReplica{MinerID: activeMinerID, ReplicaID: active.replicaID, EndpointID: active.endpointID})
	}
	for _, candidateState := range s.states {
		if candidateState.deploying || candidateState.deactivationRequested {
			continue
		}
		for activeMinerID, active := range candidateState.active {
			peers.global = append(peers.global, ActiveReplica{MinerID: activeMinerID, ReplicaID: active.replicaID, EndpointID: active.endpointID})
		}
	}
	sort.Slice(peers.deployment, func(i, j int) bool { return peers.deployment[i].EndpointID < peers.deployment[j].EndpointID })
	sort.Slice(peers.global, func(i, j int) bool { return peers.global[i].EndpointID < peers.global[j].EndpointID })
	return peers, nil
}

// probeTarget is the exact per-deployment input the periodic prober needs. It
// carries the hidden challenge value, so it stays unexported and is never
// projected into prober outcomes, callbacks, logs, durable endpoint records,
// or published manifests.
type probeTarget struct {
	deploymentID   string
	routeHost      string
	challengePath  string
	challengeValue string
	replicas       []ActiveReplica
}

// probeTargets snapshots every deployment that is settled enough to probe:
// deploying and deactivating deployments are skipped so a sweep can never race
// acceptance or teardown. The returned slices are copies, so the caller holds
// no scheduler state while it performs network I/O.
func (s *Scheduler) probeTargets() []probeTarget {
	targets, _ := s.probeTargetsVersioned()
	return targets
}

func (s *Scheduler) probeTargetsVersioned() ([]probeTarget, uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	targets := make([]probeTarget, 0, len(s.states))
	for deploymentID, state := range s.states {
		if state.deploying || state.deactivationRequested || len(state.active) == 0 {
			continue
		}
		replicas := make([]ActiveReplica, 0, len(state.active))
		for minerID, assignment := range state.active {
			replicas = append(replicas, ActiveReplica{MinerID: minerID, ReplicaID: assignment.replicaID, EndpointID: assignment.endpointID})
		}
		sort.Slice(replicas, func(i, j int) bool { return replicas[i].MinerID < replicas[j].MinerID })
		targets = append(targets, probeTarget{
			deploymentID:   deploymentID,
			routeHost:      state.routeHost,
			challengePath:  state.request.Workload.ChallengePath,
			challengeValue: state.request.Workload.ChallengeValue,
			replicas:       replicas,
		})
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].deploymentID < targets[j].deploymentID })
	return targets, s.probeTopology
}

func (s *Scheduler) DeploymentScoringDisposition(deploymentID string) (ScoringDisposition, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.states[deploymentID]
	if state == nil {
		return "", false
	}
	disposition := state.request.ScoringDisposition
	if disposition == "" {
		disposition = ScoringProductionEligible
	}
	return disposition, true
}

func (s *Scheduler) clock() func() time.Time {
	if s.Now != nil {
		return s.Now
	}
	return time.Now
}

func appendUnique(values *[]string, value string) {
	for _, existing := range *values {
		if existing == value {
			return
		}
	}
	*values = append(*values, value)
}

func (s *Scheduler) randomID(n int) (string, error) {
	b := make([]byte, n)
	entropy := s.Entropy
	if entropy == nil {
		entropy = rand.Reader
	}
	if _, err := io.ReadFull(entropy, b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
