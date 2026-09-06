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
	states             map[string]*deploymentState
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

type deploymentState struct {
	request        DeployRequest
	routeHost      string
	active         map[string]activeAssignment
	reserved       map[string]*candidateReservation
	excluded       map[string]struct{}
	pendingCleanup map[string]activeAssignment
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

// candidateReservation binds a miner handle to the exact scheduler
// publication observed while holding Scheduler.mu. Ticket signing consumes
// this captured subnet instead of taking a second lock-window snapshot.
type candidateReservation struct {
	candidate          miner.Assigner
	subnet             *protocol.SubnetBinding
	publicationID      string
	publicationVersion uint64
}

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
	miner  miner.Assigner
	ticket protocol.Ticket
}

// assignmentAttempt gives every launched ticket a cleanup lease. Aborting an
// attempt immediately deactivates all known endpoint IDs, while a worker that
// returns successfully later performs the same idempotent deactivation again.
// An Assigner that ignores cancellation therefore cannot block Deploy from
// returning, and a late success cannot strand its workload.
type assignmentAttempt struct {
	scheduler *Scheduler
	ctx       context.Context
	results   chan assignmentResult
	aborted   atomic.Bool
	mu        sync.Mutex
	launched  []launchedAssignment
}

func newAssignmentAttempt(s *Scheduler, ctx context.Context, capacity int) *assignmentAttempt {
	if capacity < 1 {
		capacity = 1
	}
	return &assignmentAttempt{scheduler: s, ctx: ctx, results: make(chan assignmentResult, capacity)}
}

func (a *assignmentAttempt) launch(candidate miner.Assigner, ticket protocol.Ticket) {
	a.mu.Lock()
	a.launched = append(a.launched, launchedAssignment{miner: candidate, ticket: ticket})
	a.mu.Unlock()
	go func() {
		now := a.scheduler.clock()
		started := now().UTC()
		assigned, err := candidate.Assign(a.ctx, ticket)
		finished := now().UTC()
		outcome := assignmentResult{
			miner: candidate, ticket: ticket, result: assigned, err: err,
			latency: max(finished.Sub(started), 0), observedAt: finished,
		}
		if a.aborted.Load() {
			a.scheduler.deactivateTicket(candidate, ticket)
		}
		select {
		case a.results <- outcome:
		case <-a.ctx.Done():
			if !a.aborted.Load() {
				a.scheduler.deactivateTicket(candidate, ticket)
			}
		}
	}()
}

func (a *assignmentAttempt) abort(routeHost string) {
	if !a.aborted.CompareAndSwap(false, true) {
		return
	}
	a.mu.Lock()
	launched := append([]launchedAssignment(nil), a.launched...)
	a.mu.Unlock()
	var cleanup sync.WaitGroup
	for _, assignment := range launched {
		cleanup.Add(1)
		go func(assignment launchedAssignment) {
			defer cleanup.Done()
			a.scheduler.deactivateTicket(assignment.miner, assignment.ticket)
		}(assignment)
	}
	done := make(chan struct{})
	go func() {
		cleanup.Wait()
		close(done)
	}()
	timer := time.NewTimer(assignmentCleanupTime)
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
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
	attempt := newAssignmentAttempt(s, ctx, s.minerCount())
	succeeded := false
	defer func() {
		cancel()
		if succeeded {
			return
		}
		attempt.abort(routeHost)
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
	launchNext := func() error {
		reservation, available := s.reserveInitialCandidate(state)
		if reservation == nil {
			return &CapacityError{DeploymentID: req.DeploymentID, Required: replicas, Available: available}
		}
		candidate := reservation.candidate
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
		attempt.launch(candidate, ticket)
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
				s.deactivateTicket(outcome.miner, outcome.ticket)
				s.failReservation(state, outcome.miner.ID())
				appendUnique(&result.FailedMiners, outcome.miner.ID())
				if err := recordObservation(observation); err != nil {
					return result, err
				}
				if err := launchNext(); err != nil {
					return result, err
				}
				continue
			}
			if verifyErr := s.verifyResultForDisposition(outcome.miner, outcome.ticket, outcome.result, req.ScoringDisposition); verifyErr != nil {
				cleanupErr := s.deactivateTicket(outcome.miner, outcome.ticket)
				s.failReservation(state, outcome.miner.ID())
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
				s.deactivateTicket(outcome.miner, outcome.ticket)
				s.failReservation(state, outcome.miner.ID())
				return result, fmt.Errorf("register authenticated pending edge route: %w", err)
			}
			probe := s.Validator.ProbeReplica(ctx, routeHost, outcome.result.Receipt.ReplicaID, req.Workload.ChallengePath, req.Workload.ChallengeValue)
			if err := ctx.Err(); err != nil {
				probe.ResponseComplete = false
				probe.Error = err.Error()
				return result, errors.Join(s.rejectInconclusiveAcceptance(state, outcome, probe), err)
			}
			if !probe.Correct {
				if !attributableAcceptanceFailure(probe) {
					return result, s.rejectInconclusiveAcceptance(state, outcome, probe)
				}
				if err := s.rejectAcceptance(state, routeHost, outcome, req.ScoringDisposition); err != nil {
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
				s.deactivateTicket(outcome.miner, outcome.ticket)
				s.failReservation(state, outcome.miner.ID())
				return result, fmt.Errorf("activate authenticated edge route: %w", err)
			}
			if result.FirstReplicaAt.IsZero() {
				probe = s.Validator.Probe(ctx, routeHost, req.Workload.ChallengePath, req.Workload.ChallengeValue)
				if err := ctx.Err(); err != nil {
					probe.ResponseComplete = false
					probe.Error = err.Error()
					return result, errors.Join(s.rejectInconclusiveAcceptance(state, outcome, probe), err)
				}
				if !probe.Correct {
					if !attributableAcceptanceFailure(probe) {
						return result, s.rejectInconclusiveAcceptance(state, outcome, probe)
					}
					if err := s.rejectAcceptance(state, routeHost, outcome, req.ScoringDisposition); err != nil {
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
				s.deactivateTicket(outcome.miner, outcome.ticket)
				s.failReservation(state, outcome.miner.ID())
				return result, fmt.Errorf("assignment %q lost its scheduler publication reservation", outcome.ticket.AssignmentNonce)
			}
			assignment := activeAssignment{
				miner: outcome.miner, replicaID: outcome.result.Receipt.ReplicaID, endpointID: expectedEndpointID(outcome.ticket),
				ticket: outcome.ticket, receipt: outcome.result.Receipt,
				publicationID: reservation.publicationID, publicationVersion: reservation.publicationVersion,
			}
			if !s.acceptReservation(state, outcome.miner.ID(), assignment) {
				s.deactivateTicket(outcome.miner, outcome.ticket)
				return result, fmt.Errorf("deployment %q was deactivated during assignment", req.DeploymentID)
			}
			if store := s.Ledger.Durable(); store != nil {
				if err := store.PutEndpoint(ctx, durable.Endpoint{EndpointID: assignment.endpointID, DeploymentID: req.DeploymentID, MinerHotkey: outcome.miner.ID(), Active: true}); err != nil {
					return result, err
				}
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
		pendingCleanup: make(map[string]activeAssignment), generation: firstGeneration, deploying: true,
	}
	s.states[req.DeploymentID] = state
	s.bumpProbeTopologyLocked()
	return state, nil
}

func (s *Scheduler) reserveInitialCandidate(state *deploymentState) (*candidateReservation, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.states[state.request.DeploymentID] != state || state.deactivationRequested {
		return nil, 0
	}
	if required := state.request.RequiredMiner; required != "" {
		_, active := state.active[required]
		_, reserved := state.reserved[required]
		_, excluded := state.excluded[required]
		if !active && !reserved {
			if excluded {
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
	for _, candidate := range s.Miners {
		if s.candidateCleanLocked(state, candidate) {
			reservation := s.captureReservationLocked(candidate)
			state.reserved[candidate.ID()] = reservation
			return reservation, len(state.active) + len(state.reserved)
		}
	}
	return nil, len(state.active) + len(state.reserved)
}

func (s *Scheduler) reserveReplacementCandidate(state *deploymentState) (*candidateReservation, uint64, int, bool) {
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
	for _, candidate := range s.Miners {
		if s.candidateCleanLocked(state, candidate) {
			reservation := s.captureReservationLocked(candidate)
			state.reserved[candidate.ID()] = reservation
			state.generation++
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
	}
	s.mu.Unlock()
}

func (s *Scheduler) failReservation(state *deploymentState, minerID string) {
	s.mu.Lock()
	if s.states[state.request.DeploymentID] == state {
		delete(state.reserved, minerID)
		state.excluded[minerID] = struct{}{}
	}
	s.mu.Unlock()
}

func (s *Scheduler) retainPendingCleanup(state *deploymentState, outcome assignmentResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.states[state.request.DeploymentID] != state {
		return
	}
	minerID := outcome.miner.ID()
	delete(state.reserved, minerID)
	state.excluded[minerID] = struct{}{}
	state.pendingCleanup[minerID] = activeAssignment{
		miner: outcome.miner, replicaID: protocol.ReplicaID(outcome.ticket), endpointID: expectedEndpointID(outcome.ticket), ticket: outcome.ticket,
	}
}

func (s *Scheduler) acceptReservation(state *deploymentState, minerID string, assignment activeAssignment) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	reservation := state.reserved[minerID]
	if s.states[state.request.DeploymentID] != state || state.deactivationRequested || reservation == nil || !s.Ledger.Eligible(minerID) ||
		assignment.publicationID != reservation.publicationID || assignment.publicationVersion != reservation.publicationVersion {
		return false
	}
	delete(state.reserved, minerID)
	state.active[minerID] = assignment
	s.bumpProbeTopologyLocked()
	return true
}

func (s *Scheduler) rejectAcceptance(state *deploymentState, routeHost string, outcome assignmentResult, disposition ScoringDisposition) error {
	cleanupErr := s.deactivateTicket(outcome.miner, outcome.ticket)
	// Only a complete response carrying the edge's upstream marker reaches this
	// function. The candidate therefore controlled the wrong response and can
	// be economically penalized without attributing an edge/network failure to
	// it. Inconclusive failures use rejectInconclusiveAcceptance instead.
	var trustErr error
	if disposition != ScoringEvidenceOnly {
		trustErr = s.Ledger.SetTrust(outcome.miner.ID(), 0)
	}
	s.failReservation(state, outcome.miner.ID())
	return errors.Join(cleanupErr, trustErr)
}

func attributableAcceptanceFailure(probe validator.ProbeResult) bool {
	return probe.ServedByReplica && probe.ResponseComplete
}

func (s *Scheduler) rejectInconclusiveAcceptance(state *deploymentState, outcome assignmentResult, probe validator.ProbeResult) error {
	cleanupErr := s.deactivateTicket(outcome.miner, outcome.ticket)
	if cleanupErr != nil {
		// Keep uncertain runtime/route ownership quarantined inside this
		// deployment. Releasing the reservation here would let a half-open retry
		// assign a second incarnation to the same miner while cleanup of the first
		// one is still unresolved. This is evidence-neutral (trust is unchanged),
		// but deliberately removes the candidate from this deployment's pool until
		// the exact cleanup is retried successfully or the deployment is cleaned.
		s.retainPendingCleanup(state, outcome)
	} else {
		s.releaseReservation(state, outcome.miner.ID())
	}
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

func (s *Scheduler) deactivateTicket(candidate miner.Assigner, ticket protocol.Ticket) error {
	var routeErr error
	if s.Router != nil && len(s.SigningKey) == ed25519.PrivateKeySize {
		routeCtx, routeCancel := context.WithTimeout(context.Background(), assignmentCleanupTime)
		routeErr = s.Router.Deactivate(routeCtx, ticket, s.SigningKey)
		routeCancel()
		if routeErr != nil {
			routeErr = fmt.Errorf("deactivate edge route: %w", routeErr)
		}
	}
	if known, ok := candidate.(interface {
		DeactivateKnown(context.Context, string, string) error
	}); ok {
		ctx, cancel := context.WithTimeout(context.Background(), assignmentCleanupTime)
		defer cancel()
		if err := known.DeactivateKnown(ctx, expectedEndpointID(ticket), ticket.DeploymentID); err != nil {
			return errors.Join(routeErr, err)
		}
		if store := s.Ledger.Durable(); store != nil {
			return errors.Join(routeErr, store.DeactivateEndpoint(context.Background(), expectedEndpointID(ticket)))
		}
		return routeErr
	}
	return errors.Join(routeErr, s.deactivate(candidate, expectedEndpointID(ticket)))
}

func (s *Scheduler) deactivate(candidate miner.Assigner, endpointID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), assignmentCleanupTime)
	defer cancel()
	if err := candidate.Deactivate(ctx, endpointID); err != nil {
		return err
	}
	if store := s.Ledger.Durable(); store != nil {
		if err := store.DeactivateEndpoint(context.Background(), endpointID); err != nil {
			return err
		}
	}
	return nil
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

// ObserveHealth applies post-acceptance serving/economic policy. endpointID
// must identify the exact incarnation so counters never cross generations.
func (s *Scheduler) ObserveHealth(routeHost, replicaID, endpointID, minerID, vantage string, reachable, correct, fraudulent bool, at time.Time) (policy.Action, error) {
	action := s.monitor().Observe(endpointID, vantage, reachable, correct, fraudulent, at)
	if action.RemoveFromRouting {
		ticket, exists := s.Router.TicketFor(routeHost, replicaID, endpointID, minerID)
		if !exists {
			return action, errors.New("health observation does not identify an exact active route incarnation")
		}
		if err := s.Router.Deactivate(context.Background(), ticket, s.SigningKey); err != nil {
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

// HandleHealth applies an external post-acceptance observation. External
// reports identify the currently active stable replica; the in-process prober
// uses handleEndpointHealth below to bind an observation to one exact endpoint
// incarnation.
func (s *Scheduler) HandleHealth(ctx context.Context, deploymentID, replicaID, minerID, vantage string, reachable, correct, fraudulent bool, at time.Time) (policy.Action, error) {
	action, _, err := s.handleHealth(ctx, deploymentID, replicaID, "", minerID, vantage, reachable, correct, fraudulent, at, false, nil)
	return action, err
}

// handleEndpointHealth applies an internal observation only if endpointID is
// still the exact active generation/nonce incarnation that was probed.
func (s *Scheduler) handleEndpointHealth(ctx context.Context, deploymentID, replicaID, endpointID, minerID, vantage string, reachable, correct, fraudulent bool, at time.Time) (policy.Action, error) {
	action, _, err := s.handleHealth(ctx, deploymentID, replicaID, endpointID, minerID, vantage, reachable, correct, fraudulent, at, true, nil)
	return action, err
}

func (s *Scheduler) handleEndpointHealthVersioned(ctx context.Context, deploymentID, replicaID, endpointID, minerID, vantage string, reachable, correct, fraudulent bool, at time.Time, expectedHealthVersion uint64) (policy.Action, bool, error) {
	return s.handleHealth(ctx, deploymentID, replicaID, endpointID, minerID, vantage, reachable, correct, fraudulent, at, true, &expectedHealthVersion)
}

// handleHealth applies post-acceptance policy and synchronously restores the
// requested replica count. Validation, monitor observation, and ownership of a
// removal are claimed under one scheduler lock, so teardown/redeploy cannot
// turn an already in-flight result into an action on a newer incarnation.
func (s *Scheduler) handleHealth(ctx context.Context, deploymentID, replicaID, endpointID, minerID, vantage string, reachable, correct, fraudulent bool, at time.Time, suppressInternalLivenessTrust bool, expectedHealthVersion *uint64) (policy.Action, bool, error) {
	if err := ctx.Err(); err != nil {
		return policy.Action{}, false, err
	}
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
		return policy.Action{}, false, fmt.Errorf("deployment %q: %w", deploymentID, ErrUnknownDeployment)
	}
	if deactivating {
		s.mu.Unlock()
		return policy.Action{}, false, fmt.Errorf("deployment %q: %w", deploymentID, ErrDeploymentDeactivating)
	}
	if removed.miner == nil || removed.replicaID != replicaID || (endpointID != "" && removed.endpointID != endpointID) {
		s.mu.Unlock()
		return policy.Action{}, false, fmt.Errorf("replica %q of miner %q: %w", replicaID, minerID, ErrReplicaNotActive)
	}
	if err := ctx.Err(); err != nil {
		s.mu.Unlock()
		return policy.Action{}, false, err
	}
	var action policy.Action
	if expectedHealthVersion == nil {
		if suppressInternalLivenessTrust {
			action = health.ObserveInternal(removed.endpointID, vantage, reachable, correct, fraudulent, at)
		} else {
			action = health.Observe(removed.endpointID, vantage, reachable, correct, fraudulent, at)
		}
	} else {
		var applied bool
		action, applied = health.ObserveIfVersion(removed.endpointID, vantage, reachable, correct, fraudulent, at, *expectedHealthVersion)
		if !applied {
			s.mu.Unlock()
			return policy.Action{}, false, errHealthObservationChanged
		}
	}
	if action.TrustZero && (state.request.ScoringDisposition == ScoringEvidenceOnly || (suppressInternalLivenessTrust && !reachable)) {
		action.TrustZero = false
	}
	if action.RemoveFromRouting {
		delete(state.active, minerID)
		state.excluded[minerID] = struct{}{}
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
			return action, true, errors.Join(trustErr, s.repairOneDeficit(ctx))
		}
		return action, true, trustErr
	}
	routeErr := s.Router.Deactivate(context.Background(), removed.ticket, s.SigningKey)
	cleanupErr := s.deactivate(removed.miner, removed.endpointID)
	// Only the removal owner reaches this line, and a replacement always
	// observes under a new generation/nonce endpoint key, so the removed
	// incarnation's monitor state can be released instead of accumulating
	// forever in a long-running control plane.
	s.monitor().Forget(removed.endpointID)
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
	return action, true, errors.Join(trustErr, routeErr, cleanupErr, replacementErr)
}

func (s *Scheduler) assignReplacement(ctx context.Context, state *deploymentState) error {
	cleanupErr := s.retryPendingCleanup(ctx, state)
	return errors.Join(cleanupErr, s.assignReplacementAfterCleanup(ctx, state))
}

// retryPendingCleanup resolves exact inconclusive-assignment ownership before
// placement considers that miner again. Failures stay quarantined but do not
// prevent another clean candidate from restoring the deployment's capacity.
func (s *Scheduler) retryPendingCleanup(ctx context.Context, state *deploymentState) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	minerIDs := make([]string, 0, len(state.pendingCleanup))
	for minerID := range state.pendingCleanup {
		minerIDs = append(minerIDs, minerID)
	}
	sort.Strings(minerIDs)
	assignments := make([]activeAssignment, 0, len(minerIDs))
	for _, minerID := range minerIDs {
		assignments = append(assignments, state.pendingCleanup[minerID])
	}
	s.mu.Unlock()

	var cleanupErrors []error
	for _, assignment := range assignments {
		if err := ctx.Err(); err != nil {
			cleanupErrors = append(cleanupErrors, err)
			break
		}
		if err := s.deactivateTicket(assignment.miner, assignment.ticket); err != nil {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("retry cleanup for endpoint %q: %w", assignment.endpointID, err))
			continue
		}
		s.mu.Lock()
		if s.states[state.request.DeploymentID] == state {
			if current, exists := state.pendingCleanup[assignment.miner.ID()]; exists && current.endpointID == assignment.endpointID {
				delete(state.pendingCleanup, assignment.miner.ID())
				delete(state.excluded, assignment.miner.ID())
			}
		}
		s.mu.Unlock()
	}
	return errors.Join(cleanupErrors...)
}

func (s *Scheduler) assignReplacementAfterCleanup(ctx context.Context, state *deploymentState) error {
	for {
		reservation, generation, available, needed := s.reserveReplacementCandidate(state)
		if !needed {
			return nil
		}
		if reservation == nil {
			return &CapacityError{DeploymentID: state.request.DeploymentID, Required: s.replicaCount(), Available: available}
		}
		candidate := reservation.candidate
		ticket, err := s.ticketForReservation(state.request, reservation, state.routeHost, generation, s.clock()())
		if err != nil {
			s.releaseReservation(state, candidate.ID())
			return err
		}
		if err := s.Ledger.RecordAssignment(ticket, "published"); err != nil {
			s.releaseReservation(state, candidate.ID())
			return err
		}
		attempt := newAssignmentAttempt(s, ctx, 1)
		attempt.launch(candidate, ticket)
		var outcome assignmentResult
		select {
		case <-ctx.Done():
			attempt.abort(state.routeHost)
			s.releaseReservation(state, candidate.ID())
			return fmt.Errorf("replacement assignment to %s: %w", candidate.ID(), ctx.Err())
		case outcome = <-attempt.results:
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
			s.deactivateTicket(candidate, ticket)
			s.releaseReservation(state, candidate.ID())
			return fmt.Errorf("replacement assignment to %s: %w", candidate.ID(), ctx.Err())
		}
		if outcome.err != nil || !s.Ledger.Eligible(candidate.ID()) {
			s.deactivateTicket(candidate, ticket)
			s.failReservation(state, candidate.ID())
			if err := recordObservation(false); err != nil {
				return fmt.Errorf("persist replacement observation: %w", err)
			}
			if ctx.Err() != nil {
				return fmt.Errorf("replacement assignment to %s: %w", candidate.ID(), ctx.Err())
			}
			continue
		}
		if verifyErr := s.verifyResultForDisposition(candidate, ticket, outcome.result, state.request.ScoringDisposition); verifyErr != nil {
			cleanupErr := s.deactivateTicket(candidate, ticket)
			s.failReservation(state, candidate.ID())
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
			s.deactivateTicket(candidate, ticket)
			s.failReservation(state, candidate.ID())
			return fmt.Errorf("persist replacement receipt: %w", err)
		}
		if err := s.Router.RegisterPending(ctx, ticket, outcome.result.Receipt, candidate.PublicKey(), s.SigningKey); err != nil {
			s.deactivateTicket(candidate, ticket)
			s.failReservation(state, candidate.ID())
			return fmt.Errorf("register authenticated replacement edge route: %w", err)
		}
		probe := s.Validator.ProbeReplica(ctx, state.routeHost, outcome.result.Receipt.ReplicaID, state.request.Workload.ChallengePath, state.request.Workload.ChallengeValue)
		if err := ctx.Err(); err != nil {
			probe.ResponseComplete = false
			probe.Error = err.Error()
			return errors.Join(
				s.rejectInconclusiveAcceptance(state, outcome, probe),
				fmt.Errorf("replacement assignment to %s: %w", candidate.ID(), err),
			)
		}
		if !probe.Correct {
			if !attributableAcceptanceFailure(probe) {
				return s.rejectInconclusiveAcceptance(state, outcome, probe)
			}
			if err := s.rejectAcceptance(state, state.routeHost, outcome, state.request.ScoringDisposition); err != nil {
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
			s.deactivateTicket(candidate, ticket)
			s.failReservation(state, candidate.ID())
			return fmt.Errorf("activate authenticated replacement edge route: %w", err)
		}
		assignment := activeAssignment{
			miner: candidate, replicaID: outcome.result.Receipt.ReplicaID, endpointID: expectedEndpointID(ticket),
			ticket: ticket, receipt: outcome.result.Receipt,
			publicationID: reservation.publicationID, publicationVersion: reservation.publicationVersion,
		}
		if !s.acceptReservation(state, candidate.ID(), assignment) {
			s.deactivateTicket(candidate, ticket)
			return fmt.Errorf("deployment %q was deactivated during replacement", state.request.DeploymentID)
		}
		if store := s.Ledger.Durable(); store != nil {
			if err := store.PutEndpoint(ctx, durable.Endpoint{EndpointID: assignment.endpointID, DeploymentID: state.request.DeploymentID, MinerHotkey: candidate.ID(), Active: true}); err != nil {
				s.mu.Lock()
				if current, exists := state.active[candidate.ID()]; s.states[state.request.DeploymentID] == state && exists && current.endpointID == assignment.endpointID {
					delete(state.active, candidate.ID())
					state.excluded[candidate.ID()] = struct{}{}
					s.bumpProbeTopologyLocked()
				}
				s.mu.Unlock()
				s.deactivateTicket(candidate, ticket)
				return err
			}
		}
		if err := recordObservation(true); err != nil {
			s.mu.Lock()
			if current, exists := state.active[candidate.ID()]; s.states[state.request.DeploymentID] == state && exists && current.endpointID == assignment.endpointID {
				delete(state.active, candidate.ID())
				state.excluded[candidate.ID()] = struct{}{}
				s.bumpProbeTopologyLocked()
			}
			s.mu.Unlock()
			s.deactivateTicket(candidate, ticket)
			return fmt.Errorf("persist replacement observation: %w", err)
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
	if len(pendingIDs) > 0 {
		cleanupState = s.states[pendingIDs[0]]
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
	if len(deploymentIDs) > 0 {
		state = s.states[deploymentIDs[0]]
	}
	s.mu.Unlock()
	if state == nil {
		return cleanupErr
	}
	return errors.Join(cleanupErr, s.assignReplacementAfterCleanup(ctx, state))
}

// DeactivateDeployment removes an active deployment using the endpoint IDs
// retained from its exact signed tickets. Failed assignments remain owned by
// the state so a later call retries the same route/miner/durable incarnation.
func (s *Scheduler) DeactivateDeployment(ctx context.Context, deploymentID string) error {
	if ctx == nil {
		return errors.New("deployment cleanup context is required")
	}
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
	for _, assignment := range state.active {
		assignments = append(assignments, assignment)
		seenEndpoints[assignment.endpointID] = struct{}{}
	}
	for _, assignment := range state.pendingCleanup {
		if _, duplicate := seenEndpoints[assignment.endpointID]; duplicate {
			continue
		}
		assignments = append(assignments, assignment)
	}
	s.mu.Unlock()
	type cleanupResult struct {
		assignment activeAssignment
		err        error
	}
	var cleanup sync.WaitGroup
	results := make(chan cleanupResult, len(assignments))
	for _, assignment := range assignments {
		s.monitor().Forget(assignment.endpointID)
		cleanup.Add(1)
		go func(assignment activeAssignment) {
			defer cleanup.Done()
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
		succeeded := make([]activeAssignment, 0, len(assignments))
		for result := range results {
			if result.err != nil {
				failures = append(failures, result.err)
			} else {
				succeeded = append(succeeded, result.assignment)
			}
		}
		s.mu.Lock()
		if s.states[deploymentID] == state {
			activeChanged := false
			for _, assignment := range succeeded {
				if current, exists := state.active[assignment.miner.ID()]; exists && current.endpointID == assignment.endpointID {
					delete(state.active, assignment.miner.ID())
					activeChanged = true
				}
				if current, exists := state.pendingCleanup[assignment.miner.ID()]; exists && current.endpointID == assignment.endpointID {
					delete(state.pendingCleanup, assignment.miner.ID())
					delete(state.excluded, assignment.miner.ID())
				}
			}
			if activeChanged {
				s.bumpProbeTopologyLocked()
			}
			state.cleanupInProgress = false
			if len(state.active) == 0 && len(state.pendingCleanup) == 0 && !state.deploying {
				delete(s.states, deploymentID)
			} else if state.deploying && len(failures) == 0 {
				failures = append(failures, errors.New("deployment assignments are still in flight"))
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
	if deploymentID == "" || s.Ledger == nil {
		return 0, nil
	}
	pending := make(map[string]struct{})
	s.mu.Lock()
	if state := s.states[deploymentID]; state != nil {
		for _, assignment := range state.active {
			pending[assignment.endpointID] = struct{}{}
		}
		for _, assignment := range state.pendingCleanup {
			pending[assignment.endpointID] = struct{}{}
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
// snapshot. The periodic prober uses this before touching its local
// corroboration state, then handleEndpointHealthVersioned repeats both the
// endpoint and health-version checks at the mutation boundary.
type probePeerSet struct {
	deployment    []ActiveReplica
	global        []ActiveReplica
	targetHealth  policy.ObservationSnapshot
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
