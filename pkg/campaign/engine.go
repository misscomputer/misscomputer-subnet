// SPDX-License-Identifier: AGPL-3.0-only

package campaign

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
	"sync"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/protocol"
	"github.com/misscomputer/misscomputer-subnet/pkg/workload"
)

const identityAttempts = 4

var (
	ErrEntropyUnavailable   = errors.New("campaign cryptographic entropy is unavailable")
	ErrIdentityCollision    = errors.New("campaign identity collision")
	ErrInvalidMinerSet      = errors.New("campaign miner set is invalid")
	ErrInvalidTransition    = errors.New("campaign lifecycle transition is invalid")
	ErrChallengeUnavailable = errors.New("campaign challenge is unavailable")
	ErrInvalidAssignment    = errors.New("accepted assignment does not match campaign challenge")
	ErrInvalidCompletion    = errors.New("campaign completion is invalid")
	errTrackedMinerCapacity = errors.New("campaign tracked-miner capacity is saturated")
)

type DecisionReason string

const (
	DecisionScheduled                DecisionReason = "scheduled"
	DecisionStarted                  DecisionReason = "started"
	DecisionDisabled                 DecisionReason = "disabled"
	DecisionPaused                   DecisionReason = "paused"
	DecisionDraining                 DecisionReason = "draining"
	DecisionShuttingDown             DecisionReason = "shutting_down"
	DecisionStopped                  DecisionReason = "stopped"
	DecisionNotDue                   DecisionReason = "not_due"
	DecisionNoMiners                 DecisionReason = "no_miners"
	DecisionInsufficientMiners       DecisionReason = "insufficient_miners"
	DecisionTrackedMinerBackpressure DecisionReason = "tracked_miner_backpressure"
	DecisionPendingBackpressure      DecisionReason = "pending_backpressure"
	DecisionConcurrencyBackpressure  DecisionReason = "concurrency_backpressure"
	DecisionNoPending                DecisionReason = "no_pending"
)

type ScheduleDecision struct {
	Reason    DecisionReason `json:"reason"`
	Challenge *Challenge     `json:"challenge,omitempty"`
	NextDueAt *time.Time     `json:"next_due_at,omitempty"`
}

type StartDecision struct {
	Reason    DecisionReason `json:"reason"`
	Challenge *Challenge     `json:"challenge,omitempty"`
}

// Engine is an in-memory state transition authority. Every successful
// mutation seals a complete State snapshot; callers own durable persistence.
// Its mutex makes concurrent admission honor one atomic backpressure limit.
type Engine struct {
	mu      sync.Mutex
	config  Config
	state   State
	entropy io.Reader
}

// New creates an inert engine for DefaultConfig and a running engine only for
// an explicitly enabled Config. No command or service in commit A calls it.
func New(config Config, now time.Time) (*Engine, error) {
	return NewWithEntropy(config, now, rand.Reader)
}

// NewWithEntropy is the deterministic test seam. Production callers must use
// New or pass a cryptographically secure reader.
func NewWithEntropy(config Config, now time.Time, entropy io.Reader) (*Engine, error) {
	state, err := NewState(config, now)
	if err != nil {
		return nil, err
	}
	return RestoreWithEntropy(config, state, entropy)
}

func NewState(config Config, now time.Time) (State, error) {
	if err := ValidateConfig(config); err != nil {
		return State{}, err
	}
	canonicalNow, err := canonicalNow(now)
	if err != nil {
		return State{}, err
	}
	configDigest, err := ConfigDigest(config)
	if err != nil {
		return State{}, err
	}
	mode := ModeDisabled
	var nextDue *time.Time
	if config.Enabled {
		mode = ModeRunning
		nextDue = timePointer(canonicalNow)
	}
	state := State{
		Version: StateVersion, CampaignID: config.CampaignID, ConfigDigestSHA256: configDigest,
		Mode: mode, NextSequence: 1, WindowStartedAt: canonicalNow, NextDueAt: nextDue,
		Challenges: []Challenge{}, Coverage: []MinerCoverage{}, UpdatedAt: canonicalNow,
	}
	return SealState(config, state)
}

func Restore(config Config, state State) (*Engine, error) {
	return RestoreWithEntropy(config, state, rand.Reader)
}

func RestoreWithEntropy(config Config, state State, entropy io.Reader) (*Engine, error) {
	if entropy == nil {
		return nil, ErrEntropyUnavailable
	}
	if err := VerifyState(config, state); err != nil {
		return nil, err
	}
	configCopy := config
	configCopy.Workloads = append([]WorkloadPolicy(nil), config.Workloads...)
	return &Engine{config: configCopy, state: cloneState(state), entropy: entropy}, nil
}

func (engine *Engine) Snapshot() State {
	engine.mu.Lock()
	defer engine.mu.Unlock()
	return cloneState(engine.state)
}

// Schedule admits at most one due challenge. It never catches up a backlog of
// missed cadences after downtime: the next bounded jitter is measured from the
// successful admission time.
func (engine *Engine) Schedule(now time.Time, miners []string) (ScheduleDecision, error) {
	engine.mu.Lock()
	defer engine.mu.Unlock()
	canonicalNow, err := engine.transitionTime(now)
	if err != nil {
		return ScheduleDecision{}, err
	}
	if reason := schedulingModeReason(engine.state.Mode); reason != DecisionScheduled {
		return ScheduleDecision{Reason: reason, NextDueAt: cloneTime(engine.state.NextDueAt)}, nil
	}
	if engine.state.NextDueAt == nil {
		return ScheduleDecision{}, ErrInvalidState
	}
	if canonicalNow.Before(*engine.state.NextDueAt) {
		return ScheduleDecision{Reason: DecisionNotDue, NextDueAt: cloneTime(engine.state.NextDueAt)}, nil
	}
	if countStatus(engine.state.Challenges, StatusPending) >= engine.config.Limits.MaxPending {
		return ScheduleDecision{Reason: DecisionPendingBackpressure, NextDueAt: cloneTime(engine.state.NextDueAt)}, nil
	}
	canonicalMiners, err := canonicalMinerSet(miners, engine.config.Limits.MaxTrackedMiners)
	if err != nil {
		if errors.Is(err, errTrackedMinerCapacity) {
			return ScheduleDecision{Reason: DecisionTrackedMinerBackpressure, NextDueAt: cloneTime(engine.state.NextDueAt)}, nil
		}
		return ScheduleDecision{}, err
	}
	if len(canonicalMiners) == 0 {
		return ScheduleDecision{Reason: DecisionNoMiners, NextDueAt: cloneTime(engine.state.NextDueAt)}, nil
	}
	if len(canonicalMiners) < engine.config.RequiredReplicas {
		return ScheduleDecision{Reason: DecisionInsufficientMiners, NextDueAt: cloneTime(engine.state.NextDueAt)}, nil
	}

	next := cloneState(engine.state)
	rollCoverageWindow(&next, engine.config, canonicalNow)
	if err := reconcileCoverage(&next, canonicalMiners, engine.config.Limits.MaxTrackedMiners); err != nil {
		if errors.Is(err, errTrackedMinerCapacity) {
			return ScheduleDecision{Reason: DecisionTrackedMinerBackpressure, NextDueAt: cloneTime(engine.state.NextDueAt)}, nil
		}
		return ScheduleDecision{}, err
	}
	targetIndex := selectCoverageTarget(next.Coverage, canonicalMiners)
	if targetIndex < 0 {
		return ScheduleDecision{}, ErrInvalidMinerSet
	}
	policy := selectWorkload(engine.config.Workloads, next.NextSequence)
	challenge, err := engine.generateChallenge(next, policy, targetIndex, canonicalNow)
	if err != nil {
		return ScheduleDecision{}, err
	}
	delay, err := engine.nextDelay()
	if err != nil {
		return ScheduleDecision{}, err
	}
	if next.NextSequence == ^uint64(0) {
		return ScheduleDecision{}, ErrInvalidState
	}
	next.Challenges = append(next.Challenges, challenge)
	coverage := &next.Coverage[targetIndex]
	if coverage.WindowScheduled == ^uint64(0) || coverage.LifetimeScheduled == ^uint64(0) || coverage.Outstanding == ^uint64(0) {
		return ScheduleDecision{}, ErrInvalidState
	}
	coverage.WindowScheduled++
	coverage.LifetimeScheduled++
	coverage.Outstanding++
	coverage.LastScheduledSequence = challenge.Sequence
	coverage.LastScheduledAt = timePointer(canonicalNow)
	next.NextSequence++
	nextDue := canonicalNow.Add(delay)
	if !nextDue.After(canonicalNow) {
		return ScheduleDecision{}, ErrInvalidConfig
	}
	next.NextDueAt = timePointer(nextDue)
	next.UpdatedAt = canonicalNow
	if err := engine.commit(next); err != nil {
		return ScheduleDecision{}, err
	}
	copyChallenge := cloneChallenge(challenge)
	return ScheduleDecision{Reason: DecisionScheduled, Challenge: &copyChallenge, NextDueAt: timePointer(nextDue)}, nil
}

// StartNext starts the oldest pending challenge and assigns its bounded
// deadline. Paused work remains pending; drain and shutdown cancel pending work
// before entering their transition modes.
func (engine *Engine) StartNext(now time.Time) (StartDecision, error) {
	engine.mu.Lock()
	defer engine.mu.Unlock()
	canonicalNow, err := engine.transitionTime(now)
	if err != nil {
		return StartDecision{}, err
	}
	if reason := schedulingModeReason(engine.state.Mode); reason != DecisionScheduled {
		return StartDecision{Reason: reason}, nil
	}
	if countStatus(engine.state.Challenges, StatusRunning) >= engine.config.Limits.MaxConcurrent {
		return StartDecision{Reason: DecisionConcurrencyBackpressure}, nil
	}
	index := firstStatus(engine.state.Challenges, StatusPending)
	if index < 0 {
		return StartDecision{Reason: DecisionNoPending}, nil
	}
	next := cloneState(engine.state)
	challenge := &next.Challenges[index]
	deadline := canonicalNow.Add(time.Duration(engine.config.Limits.ChallengeTimeoutMillis) * time.Millisecond)
	if !deadline.After(canonicalNow) {
		return StartDecision{}, ErrInvalidConfig
	}
	challenge.Status = StatusRunning
	challenge.StartedAt = timePointer(canonicalNow)
	challenge.DeadlineAt = timePointer(deadline)
	next.UpdatedAt = canonicalNow
	if err := engine.commit(next); err != nil {
		return StartDecision{}, err
	}
	copyChallenge := cloneChallenge(*challenge)
	return StartDecision{Reason: DecisionStarted, Challenge: &copyChallenge}, nil
}

// RecordAcceptedTicket records only the credential-safe identity projection
// of a deployment.v3 ticket after the existing scheduler has verified its
// signed receipt and strict challenge acceptance. This method does not verify
// the ticket signature and must not be called for merely attempted tickets.
func (engine *Engine) RecordAcceptedTicket(sequence uint64, ticket protocol.Ticket, acceptedAt time.Time) error {
	engine.mu.Lock()
	defer engine.mu.Unlock()
	canonicalAcceptedAt, err := engine.transitionTime(acceptedAt)
	if err != nil {
		return err
	}
	index := challengeIndex(engine.state.Challenges, sequence)
	if index < 0 || engine.state.Challenges[index].Status != StatusRunning {
		return ErrChallengeUnavailable
	}
	challenge := engine.state.Challenges[index]
	if !ticketMatchesChallenge(engine.config, challenge, ticket, canonicalAcceptedAt) {
		return ErrInvalidAssignment
	}
	if len(challenge.Assignments) >= engine.config.RequiredReplicas {
		return ErrInvalidAssignment
	}
	for _, existingChallenge := range engine.state.Challenges {
		for _, existing := range existingChallenge.Assignments {
			if existing.AssignmentNonce == ticket.AssignmentNonce ||
				(existingChallenge.Sequence == challenge.Sequence && existing.MinerHotkey == ticket.MinerID) {
				return ErrInvalidAssignment
			}
		}
	}
	if len(challenge.Assignments) > 0 &&
		(ticket.ImageDigest != challenge.Assignments[0].ImageDigest || ticket.ManifestKey != challenge.Assignments[0].ManifestKey) {
		return ErrInvalidAssignment
	}
	binding := AssignmentBinding{
		TicketVersion: ticket.Version, DeploymentID: ticket.DeploymentID, BuildID: challenge.Workload.BuildID,
		ChallengePath: ticket.ChallengePath, ChallengeSHA256: ticket.ChallengeSHA256,
		MinerHotkey: ticket.MinerID, Generation: ticket.Generation, AssignmentNonce: ticket.AssignmentNonce,
		ReplicaID: protocol.ReplicaID(ticket), EndpointID: protocol.EndpointID(ticket),
		ImageDigest: ticket.ImageDigest, ManifestKey: ticket.ManifestKey, AcceptedAt: canonicalAcceptedAt,
	}
	if ticket.Subnet != nil && ticket.Subnet.MinerUID != nil {
		uid := *ticket.Subnet.MinerUID
		binding.MinerUID = &uid
	}
	next := cloneState(engine.state)
	next.Challenges[index].Assignments = append(next.Challenges[index].Assignments, binding)
	sort.Slice(next.Challenges[index].Assignments, func(left, right int) bool {
		return assignmentSortKey(next.Challenges[index].Assignments[left]) < assignmentSortKey(next.Challenges[index].Assignments[right])
	})
	next.UpdatedAt = canonicalAcceptedAt
	return engine.commit(next)
}

// Complete accepts only a closed outcome and sanitized failure code. A
// success is fail-closed unless it is before the deadline, has three accepted
// unique replicas, and includes the selected fairness target.
func (engine *Engine) Complete(sequence uint64, now time.Time, outcome Outcome, failure FailureCode) (Evidence, error) {
	engine.mu.Lock()
	defer engine.mu.Unlock()
	canonicalNow, err := engine.transitionTime(now)
	if err != nil {
		return Evidence{}, err
	}
	index := challengeIndex(engine.state.Challenges, sequence)
	if index < 0 || engine.state.Challenges[index].Status != StatusRunning {
		return Evidence{}, ErrChallengeUnavailable
	}
	challenge := engine.state.Challenges[index]
	status := StatusFailed
	switch outcome {
	case OutcomeSucceeded:
		if failure != FailureNone || challenge.DeadlineAt == nil || !canonicalNow.Before(*challenge.DeadlineAt) ||
			len(challenge.Assignments) != engine.config.RequiredReplicas || !targetAccepted(challenge) {
			return Evidence{}, ErrInvalidCompletion
		}
		status = StatusSucceeded
	case OutcomeFailed:
		if !validFailureCode(failure) || failure == FailureOperatorDrain || failure == FailureOperatorShutdown {
			return Evidence{}, ErrInvalidCompletion
		}
		if failure == FailureDeadline && challenge.DeadlineAt != nil && canonicalNow.Before(*challenge.DeadlineAt) {
			return Evidence{}, ErrInvalidCompletion
		}
	default:
		return Evidence{}, ErrInvalidCompletion
	}

	next := cloneState(engine.state)
	terminal := &next.Challenges[index]
	terminal.Status = status
	terminal.CompletedAt = timePointer(canonicalNow)
	terminal.FailureCode = failure
	if err := completeCoverage(&next, terminal.CoverageTargetMiner, status == StatusSucceeded); err != nil {
		return Evidence{}, err
	}
	next.UpdatedAt = canonicalNow
	settleMode(&next)
	pruneTerminal(&next, engine.config.Limits.RetainedTerminalChallenges)
	if err := engine.commit(next); err != nil {
		return Evidence{}, err
	}
	return engine.evidenceLocked(sequence)
}

// Pause prevents new admissions and starts while allowing already running
// challenges to finish. Pending challenges remain restart-safe for Resume.
func (engine *Engine) Pause(now time.Time) error {
	engine.mu.Lock()
	defer engine.mu.Unlock()
	canonicalNow, err := engine.transitionTime(now)
	if err != nil {
		return err
	}
	switch engine.state.Mode {
	case ModePaused:
		return nil
	case ModeRunning:
		next := cloneState(engine.state)
		next.Mode = ModePaused
		next.UpdatedAt = canonicalNow
		return engine.commit(next)
	default:
		return ErrInvalidTransition
	}
}

// Resume reopens only a paused explicitly enabled campaign. A completed drain
// has no due time, so it resumes with one immediate due admission.
func (engine *Engine) Resume(now time.Time) error {
	engine.mu.Lock()
	defer engine.mu.Unlock()
	canonicalNow, err := engine.transitionTime(now)
	if err != nil {
		return err
	}
	if !engine.config.Enabled || engine.state.Mode != ModePaused {
		return ErrInvalidTransition
	}
	next := cloneState(engine.state)
	next.Mode = ModeRunning
	if next.NextDueAt == nil {
		next.NextDueAt = timePointer(canonicalNow)
	}
	next.UpdatedAt = canonicalNow
	return engine.commit(next)
}

// Drain cancels pending work with a closed evidence code and lets running work
// finish. It settles to Paused when the last running challenge completes.
func (engine *Engine) Drain(now time.Time) ([]Evidence, error) {
	engine.mu.Lock()
	defer engine.mu.Unlock()
	canonicalNow, err := engine.transitionTime(now)
	if err != nil {
		return nil, err
	}
	if engine.state.Mode == ModeDraining {
		return []Evidence{}, nil
	}
	if engine.state.Mode != ModeRunning && engine.state.Mode != ModePaused {
		return nil, ErrInvalidTransition
	}
	return engine.stopAdmissions(canonicalNow, FailureOperatorDrain, ModeDraining, ModePaused)
}

// Shutdown cancels pending work and enters a terminal transition. It settles
// to Stopped immediately when idle or after the final running completion.
func (engine *Engine) Shutdown(now time.Time) ([]Evidence, error) {
	engine.mu.Lock()
	defer engine.mu.Unlock()
	canonicalNow, err := engine.transitionTime(now)
	if err != nil {
		return nil, err
	}
	if engine.state.Mode == ModeShuttingDown || engine.state.Mode == ModeStopped {
		return []Evidence{}, nil
	}
	// Disabled is already fully inert; shutdown is an idempotent no-op so a
	// host can use one unconditional shutdown path without activating state.
	if engine.state.Mode == ModeDisabled {
		return []Evidence{}, nil
	}
	if engine.state.Mode != ModeRunning && engine.state.Mode != ModePaused && engine.state.Mode != ModeDraining {
		return nil, ErrInvalidTransition
	}
	return engine.stopAdmissions(canonicalNow, FailureOperatorShutdown, ModeShuttingDown, ModeStopped)
}

func (engine *Engine) Evidence(sequence uint64) (Evidence, error) {
	engine.mu.Lock()
	defer engine.mu.Unlock()
	return engine.evidenceLocked(sequence)
}

func (engine *Engine) stopAdmissions(now time.Time, code FailureCode, transitional, settled Mode) ([]Evidence, error) {
	next := cloneState(engine.state)
	cancelled := make([]uint64, 0)
	for index := range next.Challenges {
		challenge := &next.Challenges[index]
		if challenge.Status != StatusPending {
			continue
		}
		challenge.Status = StatusCancelled
		challenge.CompletedAt = timePointer(now)
		challenge.FailureCode = code
		if err := completeCoverage(&next, challenge.CoverageTargetMiner, false); err != nil {
			return nil, err
		}
		cancelled = append(cancelled, challenge.Sequence)
	}
	next.NextDueAt = nil
	if countStatus(next.Challenges, StatusRunning) == 0 {
		next.Mode = settled
	} else {
		next.Mode = transitional
	}
	next.UpdatedAt = now
	pruneTerminal(&next, engine.config.Limits.RetainedTerminalChallenges)
	if err := engine.commit(next); err != nil {
		return nil, err
	}
	evidence := make([]Evidence, 0, len(cancelled))
	for _, sequence := range cancelled {
		item, err := engine.evidenceLocked(sequence)
		if err != nil {
			return nil, err
		}
		evidence = append(evidence, item)
	}
	return evidence, nil
}

func (engine *Engine) evidenceLocked(sequence uint64) (Evidence, error) {
	index := challengeIndex(engine.state.Challenges, sequence)
	if index < 0 {
		return Evidence{}, ErrChallengeUnavailable
	}
	challenge := engine.state.Challenges[index]
	if challenge.CompletedAt == nil || (challenge.Status != StatusSucceeded && challenge.Status != StatusFailed && challenge.Status != StatusCancelled) {
		return Evidence{}, ErrChallengeUnavailable
	}
	outcome := OutcomeFailed
	if challenge.Status == StatusSucceeded {
		outcome = OutcomeSucceeded
	} else if challenge.Status == StatusCancelled {
		outcome = OutcomeCancelled
	}
	evidence := Evidence{
		Version: EvidenceVersion, CampaignID: engine.state.CampaignID,
		Network: engine.config.Network, NetUID: engine.config.NetUID,
		ConfigDigestSHA256: engine.state.ConfigDigestSHA256, StateDigestSHA256: engine.state.StateDigestSHA256,
		Sequence: challenge.Sequence, DeploymentID: challenge.DeploymentID, RouteHost: challenge.RouteHost,
		CoverageTargetMiner: challenge.CoverageTargetMiner, CoverageWindowStartedAt: challenge.CoverageWindowStartedAt,
		CoverageTargetOrdinal: challenge.CoverageTargetOrdinal, CoverageTargetRequired: challenge.CoverageTargetRequired,
		WorkloadKind: challenge.Workload.Kind, PayloadBytes: challenge.Workload.PayloadBytes,
		BuildID: challenge.Workload.BuildID, ChallengePath: challenge.Workload.ChallengePath,
		ChallengeSHA256: challenge.ChallengeSHA256, WorkloadSpecDigest: challenge.WorkloadSpecDigest,
		ScheduledAt: challenge.ScheduledAt, StartedAt: cloneTime(challenge.StartedAt), CompletedAt: *challenge.CompletedAt,
		Outcome: outcome, FailureCode: challenge.FailureCode,
		AcceptedAssignments: make([]AssignmentBinding, len(challenge.Assignments)),
		ScoringEffect:       ScoringEffectNone, AcceptanceObservationSource: ScoringSourceExisting,
	}
	for index, binding := range challenge.Assignments {
		evidence.AcceptedAssignments[index] = cloneBinding(binding)
	}
	return SealEvidence(evidence)
}

func (engine *Engine) generateChallenge(state State, policy WorkloadPolicy, targetIndex int, now time.Time) (Challenge, error) {
	for attempt := 0; attempt < identityAttempts; attempt++ {
		deploymentEntropy, err := randomHex(engine.entropy, 16)
		if err != nil {
			return Challenge{}, ErrEntropyUnavailable
		}
		spec, err := workload.GenerateSpecWithReader(policy.Kind, policy.PayloadBytes, engine.entropy)
		if err != nil {
			return Challenge{}, ErrEntropyUnavailable
		}
		deploymentID := fmt.Sprintf("%s-%016x-%s", engine.config.DeploymentPrefix, state.NextSequence, deploymentEntropy)
		challengeDigest := challengeValueDigest(spec.ChallengeValue)
		if identityExists(state.Challenges, deploymentID, spec.BuildID, challengeDigest) {
			continue
		}
		specDigest, err := workloadSpecDigest(spec)
		if err != nil {
			return Challenge{}, ErrInvalidState
		}
		coverage := state.Coverage[targetIndex]
		if coverage.WindowScheduled == ^uint64(0) {
			return Challenge{}, ErrInvalidState
		}
		ordinal := coverage.WindowScheduled + 1
		return Challenge{
			Version: ChallengeVersion, Sequence: state.NextSequence, DeploymentID: deploymentID,
			RouteHost:           deploymentID + "." + engine.config.Domain,
			CoverageTargetMiner: coverage.MinerHotkey, CoverageWindowStartedAt: state.WindowStartedAt,
			CoverageTargetOrdinal:  ordinal,
			CoverageTargetRequired: ordinal <= engine.config.Coverage.MinimumChallengesPerMiner,
			Workload:               spec, WorkloadSpecDigest: specDigest, ChallengeSHA256: challengeDigest,
			Status: StatusPending, ScheduledAt: now, Assignments: []AssignmentBinding{},
		}, nil
	}
	return Challenge{}, ErrIdentityCollision
}

func (engine *Engine) nextDelay() (time.Duration, error) {
	minimum := engine.config.Cadence.MinimumDelayMillis
	maximum := engine.config.Cadence.MaximumDelayMillis
	if minimum == maximum {
		return time.Duration(minimum) * time.Millisecond, nil
	}
	span := uint64(maximum-minimum) + 1
	offset, err := randomBelow(engine.entropy, span)
	if err != nil {
		return 0, ErrEntropyUnavailable
	}
	return time.Duration(minimum+int64(offset)) * time.Millisecond, nil
}

func (engine *Engine) transitionTime(value time.Time) (time.Time, error) {
	canonical, err := canonicalNow(value)
	if err != nil || canonical.Before(engine.state.UpdatedAt) {
		return time.Time{}, ErrInvalidTransition
	}
	return canonical, nil
}

func (engine *Engine) commit(next State) error {
	sealed, err := SealState(engine.config, next)
	if err != nil {
		return err
	}
	engine.state = sealed
	return nil
}

func ticketMatchesChallenge(config Config, challenge Challenge, ticket protocol.Ticket, acceptedAt time.Time) bool {
	if ticket.Version != protocol.BoundVersion || ticket.DeploymentID != challenge.DeploymentID || ticket.RouteHost != challenge.RouteHost ||
		ticket.Generation == 0 || !validLowerHex(ticket.AssignmentNonce, 16) || !validHotkey(ticket.MinerID) ||
		ticket.ChallengePath != challenge.Workload.ChallengePath || ticket.ChallengeSHA256 != challenge.ChallengeSHA256 ||
		!validImageDigest(ticket.ImageDigest) || ticket.ManifestKey != manifestKey(ticket.ImageDigest) ||
		ticket.Subnet == nil || ticket.Subnet.Network != config.Network || ticket.Subnet.NetUID != config.NetUID ||
		ticket.Subnet.MinerHotkey != ticket.MinerID || protocol.ValidateSubnetBinding(ticket.Subnet) != nil ||
		ticket.IssuedAt.IsZero() || ticket.ExpiresAt.IsZero() || !ticket.ExpiresAt.After(ticket.IssuedAt) ||
		acceptedAt.Before(ticket.IssuedAt.UTC()) || !acceptedAt.Before(ticket.ExpiresAt.UTC()) ||
		challenge.StartedAt == nil || challenge.DeadlineAt == nil || acceptedAt.Before(*challenge.StartedAt) || !acceptedAt.Before(*challenge.DeadlineAt) {
		return false
	}
	return true
}

func canonicalNow(value time.Time) (time.Time, error) {
	if value.IsZero() {
		return time.Time{}, ErrInvalidTransition
	}
	return value.UTC(), nil
}

func timePointer(value time.Time) *time.Time {
	copyValue := value
	return &copyValue
}

func schedulingModeReason(mode Mode) DecisionReason {
	switch mode {
	case ModeRunning:
		return DecisionScheduled
	case ModeDisabled:
		return DecisionDisabled
	case ModePaused:
		return DecisionPaused
	case ModeDraining:
		return DecisionDraining
	case ModeShuttingDown:
		return DecisionShuttingDown
	case ModeStopped:
		return DecisionStopped
	default:
		return DecisionStopped
	}
}

func canonicalMinerSet(miners []string, maximum int) ([]string, error) {
	canonical := append([]string(nil), miners...)
	for _, miner := range canonical {
		if !validHotkey(miner) {
			return nil, ErrInvalidMinerSet
		}
	}
	sort.Strings(canonical)
	for index := 1; index < len(canonical); index++ {
		if canonical[index] == canonical[index-1] {
			return nil, ErrInvalidMinerSet
		}
	}
	if len(canonical) > maximum {
		return nil, errTrackedMinerCapacity
	}
	return canonical, nil
}

func rollCoverageWindow(state *State, config Config, now time.Time) {
	window := time.Duration(config.Coverage.WindowMillis) * time.Millisecond
	if now.Before(state.WindowStartedAt.Add(window)) {
		return
	}
	state.WindowStartedAt = now
	for index := range state.Coverage {
		state.Coverage[index].WindowScheduled = 0
	}
}

func reconcileCoverage(state *State, miners []string, maximum int) error {
	active := make(map[string]struct{}, len(miners))
	known := make(map[string]struct{}, len(state.Coverage))
	for _, miner := range miners {
		active[miner] = struct{}{}
	}
	for _, coverage := range state.Coverage {
		known[coverage.MinerHotkey] = struct{}{}
	}
	missing := make([]string, 0)
	for _, miner := range miners {
		if _, exists := known[miner]; !exists {
			missing = append(missing, miner)
		}
	}
	needed := len(state.Coverage) + len(missing) - maximum
	if needed > 0 {
		candidates := make([]MinerCoverage, 0)
		for _, coverage := range state.Coverage {
			_, isActive := active[coverage.MinerHotkey]
			if !isActive && coverage.Outstanding == 0 {
				candidates = append(candidates, coverage)
			}
		}
		sort.Slice(candidates, func(left, right int) bool {
			if candidates[left].LastScheduledSequence != candidates[right].LastScheduledSequence {
				return candidates[left].LastScheduledSequence < candidates[right].LastScheduledSequence
			}
			return candidates[left].MinerHotkey < candidates[right].MinerHotkey
		})
		if len(candidates) < needed {
			return errTrackedMinerCapacity
		}
		remove := make(map[string]struct{}, needed)
		for _, candidate := range candidates[:needed] {
			remove[candidate.MinerHotkey] = struct{}{}
		}
		retained := state.Coverage[:0]
		for _, coverage := range state.Coverage {
			if _, discard := remove[coverage.MinerHotkey]; !discard {
				retained = append(retained, coverage)
			}
		}
		state.Coverage = retained
	}
	for _, miner := range missing {
		state.Coverage = append(state.Coverage, MinerCoverage{MinerHotkey: miner})
	}
	sort.Slice(state.Coverage, func(left, right int) bool {
		return state.Coverage[left].MinerHotkey < state.Coverage[right].MinerHotkey
	})
	return nil
}

func selectCoverageTarget(coverage []MinerCoverage, miners []string) int {
	active := make(map[string]struct{}, len(miners))
	for _, miner := range miners {
		active[miner] = struct{}{}
	}
	selected := -1
	for index := range coverage {
		candidate := coverage[index]
		if _, exists := active[candidate.MinerHotkey]; !exists {
			continue
		}
		if selected < 0 || coverageLess(candidate, coverage[selected]) {
			selected = index
		}
	}
	return selected
}

func coverageLess(left, right MinerCoverage) bool {
	if left.WindowScheduled != right.WindowScheduled {
		return left.WindowScheduled < right.WindowScheduled
	}
	if left.LastScheduledSequence != right.LastScheduledSequence {
		return left.LastScheduledSequence < right.LastScheduledSequence
	}
	return left.MinerHotkey < right.MinerHotkey
}

func selectWorkload(policies []WorkloadPolicy, sequence uint64) WorkloadPolicy {
	var total uint64
	for _, policy := range policies {
		total += uint64(policy.Weight)
	}
	slot := (sequence - 1) % total
	for _, policy := range policies {
		weight := uint64(policy.Weight)
		if slot < weight {
			return policy
		}
		slot -= weight
	}
	return policies[len(policies)-1]
}

func identityExists(challenges []Challenge, deploymentID, buildID, challengeDigest string) bool {
	for _, challenge := range challenges {
		if challenge.DeploymentID == deploymentID || challenge.Workload.BuildID == buildID || challenge.ChallengeSHA256 == challengeDigest {
			return true
		}
	}
	return false
}

func randomHex(entropy io.Reader, bytesCount int) (string, error) {
	if entropy == nil {
		return "", ErrEntropyUnavailable
	}
	payload := make([]byte, bytesCount)
	if _, err := io.ReadFull(entropy, payload); err != nil {
		return "", ErrEntropyUnavailable
	}
	return hex.EncodeToString(payload), nil
}

func randomBelow(entropy io.Reader, maximum uint64) (uint64, error) {
	if entropy == nil || maximum == 0 {
		return 0, ErrEntropyUnavailable
	}
	limit := ^uint64(0) - (^uint64(0) % maximum)
	buffer := make([]byte, 8)
	for {
		if _, err := io.ReadFull(entropy, buffer); err != nil {
			return 0, ErrEntropyUnavailable
		}
		value := binary.BigEndian.Uint64(buffer)
		if value < limit {
			return value % maximum, nil
		}
	}
}

func countStatus(challenges []Challenge, status ChallengeStatus) int {
	count := 0
	for _, challenge := range challenges {
		if challenge.Status == status {
			count++
		}
	}
	return count
}

func firstStatus(challenges []Challenge, status ChallengeStatus) int {
	for index := range challenges {
		if challenges[index].Status == status {
			return index
		}
	}
	return -1
}

func challengeIndex(challenges []Challenge, sequence uint64) int {
	index := sort.Search(len(challenges), func(index int) bool { return challenges[index].Sequence >= sequence })
	if index >= len(challenges) || challenges[index].Sequence != sequence {
		return -1
	}
	return index
}

func completeCoverage(state *State, miner string, succeeded bool) error {
	index := sort.Search(len(state.Coverage), func(index int) bool { return state.Coverage[index].MinerHotkey >= miner })
	if index >= len(state.Coverage) || state.Coverage[index].MinerHotkey != miner || state.Coverage[index].Outstanding == 0 {
		return ErrInvalidState
	}
	coverage := &state.Coverage[index]
	if coverage.LifetimeCompleted == ^uint64(0) ||
		(succeeded && coverage.LifetimeSucceeded == ^uint64(0)) ||
		(!succeeded && coverage.LifetimeFailed == ^uint64(0)) {
		return ErrInvalidState
	}
	coverage.Outstanding--
	coverage.LifetimeCompleted++
	if succeeded {
		coverage.LifetimeSucceeded++
	} else {
		coverage.LifetimeFailed++
	}
	return nil
}

func targetAccepted(challenge Challenge) bool {
	for _, binding := range challenge.Assignments {
		if binding.MinerHotkey == challenge.CoverageTargetMiner {
			return true
		}
	}
	return false
}

func settleMode(state *State) {
	if countStatus(state.Challenges, StatusRunning) != 0 {
		return
	}
	switch state.Mode {
	case ModeDraining:
		state.Mode = ModePaused
	case ModeShuttingDown:
		state.Mode = ModeStopped
	}
}

func pruneTerminal(state *State, maximum int) {
	terminal := 0
	for _, challenge := range state.Challenges {
		if challenge.Status == StatusSucceeded || challenge.Status == StatusFailed || challenge.Status == StatusCancelled {
			terminal++
		}
	}
	remove := terminal - maximum
	if remove <= 0 {
		return
	}
	retained := make([]Challenge, 0, len(state.Challenges)-remove)
	for _, challenge := range state.Challenges {
		isTerminal := challenge.Status == StatusSucceeded || challenge.Status == StatusFailed || challenge.Status == StatusCancelled
		if isTerminal && remove > 0 {
			remove--
			continue
		}
		retained = append(retained, challenge)
	}
	state.Challenges = retained
}
