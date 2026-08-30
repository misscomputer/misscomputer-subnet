// SPDX-License-Identifier: AGPL-3.0-only

package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/artifact"
	"github.com/misscomputer/misscomputer-subnet/pkg/campaign"
	"github.com/misscomputer/misscomputer-subnet/pkg/control"
	"github.com/misscomputer/misscomputer-subnet/pkg/workload"
)

const StatusVersion = "synthetic-campaign-status.v1"

type DeploymentScheduler interface {
	Deploy(context.Context, control.DeployRequest) (control.DeployResult, error)
	DeactivateDeployment(context.Context, string) error
	PendingCleanupAssignments(context.Context, string) (int, error)
}

type ManagedArtifactStore interface {
	artifact.Store
	artifact.ExactDeleter
}

type Dependencies struct {
	StateDirectory string
	Environment    ActivationEnvironment
	Readiness      WildcardReadinessProof
	Scheduler      DeploymentScheduler
	Artifacts      ManagedArtifactStore
	Miners         func() []string
	Now            func() time.Time
	Entropy        io.Reader
}

type Runner struct {
	mu            sync.Mutex
	config        RuntimeConfig
	runtimeDigest string
	environment   ActivationEnvironment
	readiness     WildcardReadinessProof
	engine        *campaign.Engine
	store         *StateStore
	scheduler     DeploymentScheduler
	artifacts     ManagedArtifactStore
	miners        func() []string
	now           func() time.Time
	entropy       io.Reader
	runs          []RunRecord
	workers       map[uint64]context.CancelFunc
	cleaning      map[uint64]bool
	workerContext context.Context
	cancelWorkers context.CancelFunc
	wait          sync.WaitGroup
	fatal         error
	runStarted    bool
	closed        bool
}

type synchronizedReader struct {
	mu     sync.Mutex
	reader io.Reader
}

func (reader *synchronizedReader) Read(target []byte) (int, error) {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	return reader.reader.Read(target)
}

type Status struct {
	Version               string                     `json:"version"`
	Enabled               bool                       `json:"enabled"`
	RuntimeHealthy        bool                       `json:"runtime_healthy"`
	RuntimeFailureCode    campaign.FailureCode       `json:"runtime_failure_code,omitempty"`
	CampaignID            string                     `json:"campaign_id"`
	Network               string                     `json:"network"`
	NetUID                uint16                     `json:"netuid"`
	Domain                string                     `json:"domain"`
	Mode                  campaign.Mode              `json:"mode"`
	StateRevision         uint64                     `json:"state_revision"`
	ConfigDigestSHA256    string                     `json:"config_digest_sha256"`
	StateDigestSHA256     string                     `json:"state_digest_sha256"`
	ReadinessReady        bool                       `json:"readiness_ready"`
	ReadinessProofSHA256  string                     `json:"readiness_proof_sha256"`
	ReadinessVerifiedAt   time.Time                  `json:"readiness_verified_at"`
	ReadinessExpiresAt    time.Time                  `json:"readiness_expires_at"`
	NextSequence          uint64                     `json:"next_sequence"`
	NextDueAt             *time.Time                 `json:"next_due_at,omitempty"`
	Pending               int                        `json:"pending"`
	Running               int                        `json:"running"`
	CleanupBacklog        int                        `json:"cleanup_backlog"`
	CleanupExhausted      int                        `json:"cleanup_exhausted"`
	RetainedArtifactBytes int64                      `json:"retained_artifact_bytes"`
	ScoringDisposition    control.ScoringDisposition `json:"scoring_disposition"`
	Challenges            []ChallengeView            `json:"challenges"`
	Cleanup               []CleanupView              `json:"cleanup"`
}

type ChallengeView struct {
	Sequence                 uint64                   `json:"sequence"`
	DeploymentID             string                   `json:"deployment_id"`
	RouteHost                string                   `json:"route_host"`
	CoverageTargetMiner      string                   `json:"coverage_target_miner"`
	CoverageTargetRequired   bool                     `json:"coverage_target_required"`
	WorkloadKind             string                   `json:"workload_kind"`
	PayloadBytes             int                      `json:"payload_bytes"`
	ChallengeSHA256          string                   `json:"challenge_sha256"`
	Status                   campaign.ChallengeStatus `json:"status"`
	ScheduledAt              time.Time                `json:"scheduled_at"`
	StartedAt                *time.Time               `json:"started_at,omitempty"`
	DeadlineAt               *time.Time               `json:"deadline_at,omitempty"`
	CompletedAt              *time.Time               `json:"completed_at,omitempty"`
	FailureCode              campaign.FailureCode     `json:"failure_code,omitempty"`
	AcceptedAssignments      int                      `json:"accepted_assignments"`
	DeploymentCleanupPending bool                     `json:"deployment_cleanup_pending"`
	ArtifactCleanupPending   bool                     `json:"artifact_cleanup_pending"`
}

type CleanupView struct {
	Sequence                   uint64               `json:"sequence"`
	DeploymentID               string               `json:"deployment_id"`
	Phase                      RunPhase             `json:"phase"`
	ImageDigest                string               `json:"image_digest,omitempty"`
	ArtifactBytes              int64                `json:"artifact_bytes"`
	RetainUntil                *time.Time           `json:"retain_until,omitempty"`
	DeploymentCleanupPending   bool                 `json:"deployment_cleanup_pending"`
	DeploymentCleanupAttempts  int                  `json:"deployment_cleanup_attempts"`
	DeploymentNextCleanupAt    *time.Time           `json:"deployment_next_cleanup_at,omitempty"`
	DeploymentCleanupExhausted bool                 `json:"deployment_cleanup_exhausted"`
	ArtifactCleanupPending     bool                 `json:"artifact_cleanup_pending"`
	ArtifactCleanupAttempts    int                  `json:"artifact_cleanup_attempts"`
	ArtifactNextCleanupAt      *time.Time           `json:"artifact_next_cleanup_at,omitempty"`
	ArtifactCleanupExhausted   bool                 `json:"artifact_cleanup_exhausted"`
	LastFailureCode            campaign.FailureCode `json:"last_failure_code,omitempty"`
}

func NewRunner(config RuntimeConfig, runtimeDigest string, dependencies Dependencies) (*Runner, error) {
	if dependencies.Scheduler == nil || dependencies.Artifacts == nil || dependencies.Miners == nil {
		return nil, errors.New("campaign scheduler, managed artifact store, and miner source are required")
	}
	now := dependencies.Now
	if now == nil {
		now = time.Now
	}
	startedAt := now().UTC().Round(0)
	if err := ValidateActivation(config, dependencies.Environment, dependencies.Readiness, startedAt); err != nil {
		return nil, err
	}
	entropy := dependencies.Entropy
	if entropy == nil {
		entropy = rand.Reader
	}
	entropy = &synchronizedReader{reader: entropy}
	store, state, runs, err := OpenStateStore(dependencies.StateDirectory, config, runtimeDigest, startedAt)
	if err != nil {
		return nil, err
	}
	engine, err := campaign.RestoreWithEntropy(config.Campaign, state, entropy)
	if err != nil {
		store.Close()
		return nil, err
	}
	workerContext, cancelWorkers := context.WithCancel(context.Background())
	runner := &Runner{
		config: config, runtimeDigest: runtimeDigest, environment: dependencies.Environment, readiness: dependencies.Readiness,
		engine: engine, store: store,
		scheduler: dependencies.Scheduler, artifacts: dependencies.Artifacts, miners: dependencies.Miners,
		now: now, entropy: entropy, runs: runs, workers: make(map[uint64]context.CancelFunc),
		cleaning: make(map[uint64]bool), workerContext: workerContext, cancelWorkers: cancelWorkers,
	}
	runner.mu.Lock()
	err = runner.recoverLocked(startedAt)
	runner.mu.Unlock()
	if err != nil {
		cancelWorkers()
		store.Close()
		return nil, err
	}
	return runner, nil
}

func (runner *Runner) Close() error {
	runner.mu.Lock()
	if runner.closed {
		runner.mu.Unlock()
		return nil
	}
	runner.closed = true
	runner.cancelWorkers()
	runner.mu.Unlock()
	done := make(chan struct{})
	go func() {
		runner.wait.Wait()
		close(done)
	}()
	timer := time.NewTimer(time.Duration(runner.config.Artifacts.CleanupTimeoutMillis) * time.Millisecond)
	defer timer.Stop()
	var waitErr error
	select {
	case <-done:
	case <-timer.C:
		waitErr = context.DeadlineExceeded
	}
	return errors.Join(waitErr, runner.store.Close())
}

func (runner *Runner) Run(ctx context.Context) error {
	if ctx == nil {
		return errors.New("campaign run context is required")
	}
	runner.mu.Lock()
	if runner.closed || runner.runStarted {
		runner.mu.Unlock()
		return errors.New("campaign runner lifecycle is unavailable")
	}
	runner.runStarted = true
	runner.mu.Unlock()
	if err := runner.Tick(ctx); err != nil {
		return err
	}
	ticker := time.NewTicker(time.Duration(runner.config.TickIntervalMillis) * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := runner.Tick(ctx); err != nil {
				return err
			}
		}
	}
}

// Tick performs at most one admission, starts work only within the engine's
// bounded concurrency, and processes exact cleanup retries without catch-up
// bursts.
func (runner *Runner) Tick(ctx context.Context) error {
	if ctx == nil {
		return errors.New("campaign tick context is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	now := runner.canonicalNow()
	var started []campaign.Challenge
	runner.mu.Lock()
	if runner.closed {
		runner.mu.Unlock()
		return errors.New("campaign runner is closed")
	}
	if runner.fatal != nil {
		err := runner.fatal
		runner.mu.Unlock()
		return err
	}
	if activationErr := ValidateActivation(runner.config, runner.environment, runner.readiness, now); activationErr != nil {
		if !errors.Is(activationErr, ErrInvalidReadiness) {
			runner.mu.Unlock()
			return activationErr
		}
		state := runner.engine.Snapshot()
		if state.Mode == campaign.ModeRunning {
			if pauseErr := runner.engine.Pause(runner.notBeforeStateLocked(now)); pauseErr != nil {
				runner.mu.Unlock()
				return errors.Join(activationErr, pauseErr)
			}
			if persistErr := runner.persistLocked(); persistErr != nil {
				runner.mu.Unlock()
				return errors.Join(activationErr, persistErr)
			}
		}
		runner.mu.Unlock()
		// Readiness expiry is an expected fail-closed policy state, not a
		// runtime failure. Keep the production process and cleanup loop alive
		// while admission remains durably paused.
		return runner.processCleanups(ctx, now)
	}
	decision, err := runner.engine.Schedule(now, runner.miners())
	if err == nil && decision.Reason == campaign.DecisionScheduled {
		err = runner.persistLocked()
	}
	for err == nil {
		start, startErr := runner.engine.StartNext(now)
		if startErr != nil {
			err = startErr
			break
		}
		if start.Reason != campaign.DecisionStarted || start.Challenge == nil {
			break
		}
		challenge := *start.Challenge
		if runner.runIndexLocked(challenge.Sequence) >= 0 {
			err = ErrAmbiguousState
			break
		}
		runner.runs = append(runner.runs, RunRecord{
			Sequence: challenge.Sequence, DeploymentID: challenge.DeploymentID, Phase: RunStarted,
			StartedAt: *challenge.StartedAt, ArtifactKeys: []string{},
		})
		if err = runner.persistLocked(); err != nil {
			break
		}
		started = append(started, challenge)
	}
	if err == nil {
		for _, challenge := range started {
			runner.launchLocked(challenge)
		}
	}
	runner.mu.Unlock()
	if err != nil {
		return err
	}
	return runner.processCleanups(ctx, now)
}

func (runner *Runner) Pause() error {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	if err := runner.lifecycleErrorLocked(); err != nil {
		return err
	}
	if err := runner.engine.Pause(runner.canonicalNowLocked()); err != nil {
		return err
	}
	return runner.persistLocked()
}

func (runner *Runner) Resume() error {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	return runner.resumeLocked(runner.readiness)
}

// ReloadReadinessAndResume atomically installs a freshly verified readiness
// proof while reopening a paused campaign. Callers must load the proof through
// LoadReadinessProof so the same protected file and canonicality controls used
// at startup remain authoritative.
func (runner *Runner) ReloadReadinessAndResume(readiness WildcardReadinessProof) error {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	return runner.resumeLocked(readiness)
}

func (runner *Runner) resumeLocked(readiness WildcardReadinessProof) error {
	if err := runner.lifecycleErrorLocked(); err != nil {
		return err
	}
	now := runner.canonicalNowLocked()
	if err := ValidateActivation(runner.config, runner.environment, readiness, now); err != nil {
		return err
	}
	if err := runner.engine.Resume(now); err != nil {
		return err
	}
	runner.readiness = readiness
	return runner.persistLocked()
}

func (runner *Runner) Drain() error {
	runner.mu.Lock()
	if lifecycleErr := runner.lifecycleErrorLocked(); lifecycleErr != nil {
		runner.mu.Unlock()
		return lifecycleErr
	}
	evidence, err := runner.engine.Drain(runner.canonicalNowLocked())
	if err == nil {
		err = runner.persistLocked()
	}
	runner.mu.Unlock()
	if err != nil {
		return err
	}
	err = runner.persistEvidence(evidence)
	if err != nil {
		runner.fail(err)
	}
	return err
}

func (runner *Runner) Shutdown(ctx context.Context) error {
	if ctx == nil {
		return errors.New("campaign shutdown context is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	runner.mu.Lock()
	if lifecycleErr := runner.lifecycleErrorLocked(); lifecycleErr != nil {
		runner.cancelWorkers()
		runner.mu.Unlock()
		return lifecycleErr
	}
	evidence, err := runner.engine.Shutdown(runner.canonicalNowLocked())
	if err == nil {
		err = runner.persistLocked()
	}
	for _, cancel := range runner.workers {
		cancel()
	}
	runner.mu.Unlock()
	if err != nil {
		return err
	}
	if err := runner.persistEvidence(evidence); err != nil {
		runner.fail(err)
		return err
	}
	done := make(chan struct{})
	go func() {
		runner.wait.Wait()
		close(done)
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-done:
	}
	return runner.processCleanups(ctx, runner.canonicalNow())
}

func (runner *Runner) WaitIdle(ctx context.Context) error {
	if ctx == nil {
		return errors.New("campaign wait context is required")
	}
	done := make(chan struct{})
	go func() {
		runner.wait.Wait()
		close(done)
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-done:
		return nil
	}
}

func (runner *Runner) Status() (Status, error) {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	state := runner.engine.Snapshot()
	_, _, revision, err := runner.store.Current()
	if err != nil {
		return Status{}, err
	}
	status := Status{
		Version: StatusVersion, Enabled: true, RuntimeHealthy: runner.fatal == nil, CampaignID: state.CampaignID,
		Network: runner.config.Campaign.Network, NetUID: runner.config.Campaign.NetUID, Domain: runner.config.Campaign.Domain,
		Mode: state.Mode, StateRevision: revision, ConfigDigestSHA256: state.ConfigDigestSHA256,
		StateDigestSHA256: state.StateDigestSHA256, ReadinessProofSHA256: runner.readiness.ProofDigestSHA256,
		ReadinessVerifiedAt: runner.readiness.VerifiedAt,
		ReadinessExpiresAt:  runner.readiness.ExpiresAt,
		NextSequence:        state.NextSequence, NextDueAt: cloneTime(state.NextDueAt),
		ScoringDisposition: control.ScoringEvidenceOnly, Challenges: make([]ChallengeView, 0, len(state.Challenges)),
		Cleanup: make([]CleanupView, 0),
	}
	status.ReadinessReady = ValidateActivation(runner.config, runner.environment, runner.readiness, runner.canonicalNow()) == nil
	if runner.fatal != nil {
		status.RuntimeFailureCode = campaign.FailureInternal
	}
	for _, run := range runner.runs {
		status.RetainedArtifactBytes += run.ArtifactBytes
		if run.DeploymentCleanupPending || run.ArtifactCleanupPending {
			status.CleanupBacklog++
			view := CleanupView{
				Sequence: run.Sequence, DeploymentID: run.DeploymentID, Phase: run.Phase,
				ArtifactBytes: run.ArtifactBytes, RetainUntil: cloneTime(run.RetainUntil),
				DeploymentCleanupPending: run.DeploymentCleanupPending, DeploymentCleanupAttempts: run.DeploymentCleanupAttempts,
				DeploymentNextCleanupAt: cloneTime(run.DeploymentNextCleanupAt), DeploymentCleanupExhausted: run.DeploymentCleanupExhausted,
				ArtifactCleanupPending: run.ArtifactCleanupPending, ArtifactCleanupAttempts: run.ArtifactCleanupAttempts,
				ArtifactNextCleanupAt: cloneTime(run.ArtifactNextCleanupAt), ArtifactCleanupExhausted: run.ArtifactCleanupExhausted,
				LastFailureCode: run.LastFailureCode,
			}
			if run.Manifest != nil {
				view.ImageDigest = run.Manifest.ImageDigest
			}
			status.Cleanup = append(status.Cleanup, view)
		}
		if run.DeploymentCleanupExhausted || run.ArtifactCleanupExhausted {
			status.CleanupExhausted++
		}
	}
	for _, challenge := range state.Challenges {
		view := ChallengeView{
			Sequence: challenge.Sequence, DeploymentID: challenge.DeploymentID, RouteHost: challenge.RouteHost,
			CoverageTargetMiner: challenge.CoverageTargetMiner, CoverageTargetRequired: challenge.CoverageTargetRequired,
			WorkloadKind: challenge.Workload.Kind, PayloadBytes: challenge.Workload.PayloadBytes,
			ChallengeSHA256: challenge.ChallengeSHA256, Status: challenge.Status, ScheduledAt: challenge.ScheduledAt,
			StartedAt: cloneTime(challenge.StartedAt), DeadlineAt: cloneTime(challenge.DeadlineAt),
			CompletedAt: cloneTime(challenge.CompletedAt), FailureCode: challenge.FailureCode,
			AcceptedAssignments: len(challenge.Assignments),
		}
		if index := runner.runIndexLocked(challenge.Sequence); index >= 0 {
			view.DeploymentCleanupPending = runner.runs[index].DeploymentCleanupPending
			view.ArtifactCleanupPending = runner.runs[index].ArtifactCleanupPending
		}
		status.Challenges = append(status.Challenges, view)
		switch challenge.Status {
		case campaign.StatusPending:
			status.Pending++
		case campaign.StatusRunning:
			status.Running++
		}
	}
	return status, nil
}

func (runner *Runner) Evidence(sequence uint64) (campaign.Evidence, error) {
	return runner.store.Evidence(sequence)
}

func (runner *Runner) launchLocked(challenge campaign.Challenge) {
	workerContext, cancel := context.WithCancel(runner.workerContext)
	runner.workers[challenge.Sequence] = cancel
	runner.wait.Add(1)
	go func() {
		defer runner.wait.Done()
		defer func() {
			runner.mu.Lock()
			delete(runner.workers, challenge.Sequence)
			runner.mu.Unlock()
		}()
		runner.execute(workerContext, challenge)
	}()
}

func (runner *Runner) execute(ctx context.Context, challenge campaign.Challenge) {
	runner.mu.Lock()
	preflightCapacity := runner.retainedBytesLocked()+int64(challenge.Workload.PayloadBytes) <= runner.config.Artifacts.MaxRetainedBytes
	runner.mu.Unlock()
	if !preflightCapacity {
		runner.finishFailure(challenge.Sequence, campaign.FailureCapacity)
		return
	}
	layer, err := workload.EncodeWithReader(challenge.Workload, runner.entropy)
	if err != nil || int64(len(layer)) > runner.config.Artifacts.MaxSingleBytes {
		runner.finishFailure(challenge.Sequence, campaign.FailureArtifact)
		return
	}
	createdAt := runner.canonicalNow()
	manifest, err := artifact.PrepareManifest(challenge.Workload.Kind, [][]byte{layer}, map[string]string{
		"build_id": challenge.Workload.BuildID, "campaign_id": runner.config.Campaign.CampaignID,
		"campaign_sequence": fmt.Sprintf("%d", challenge.Sequence),
	}, createdAt)
	if err != nil {
		runner.finishFailure(challenge.Sequence, campaign.FailureArtifact)
		return
	}
	keys, err := artifact.ArtifactKeys(manifest)
	if err != nil {
		runner.finishFailure(challenge.Sequence, campaign.FailureArtifact)
		return
	}
	runner.mu.Lock()
	if runner.retainedBytesLocked()+int64(len(layer)) > runner.config.Artifacts.MaxRetainedBytes {
		runner.mu.Unlock()
		runner.finishFailure(challenge.Sequence, campaign.FailureCapacity)
		return
	}
	index := runner.runIndexLocked(challenge.Sequence)
	if index < 0 {
		runner.mu.Unlock()
		return
	}
	retainUntil := createdAt.Add(time.Duration(runner.config.Artifacts.RetentionMillis) * time.Millisecond)
	run := &runner.runs[index]
	run.Phase = RunArtifactPlanned
	run.Manifest = &manifest
	run.ArtifactKeys = keys
	run.ArtifactBytes = int64(len(layer))
	run.RetainUntil = &retainUntil
	err = runner.persistLocked()
	runner.mu.Unlock()
	if err != nil {
		return
	}
	if _, err = artifact.PublishPrepared(ctx, runner.artifacts, manifest, [][]byte{layer}); err != nil {
		failure := campaign.FailureArtifact
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			failure = campaign.FailureCancelled
		}
		runner.finishFailure(challenge.Sequence, failure)
		return
	}
	if err = runner.updateRunPhase(challenge.Sequence, RunArtifactPublished); err != nil {
		return
	}
	if ctx.Err() != nil {
		runner.finishFailure(challenge.Sequence, campaign.FailureCancelled)
		return
	}
	if err = runner.updateRunPhase(challenge.Sequence, RunDeploying); err != nil {
		return
	}
	deadline := *challenge.DeadlineAt
	remaining := deadline.Sub(runner.canonicalNow())
	if remaining <= 0 {
		runner.finishFailure(challenge.Sequence, campaign.FailureDeadline)
		return
	}
	result, deployErr := runner.scheduler.Deploy(ctx, control.DeployRequest{
		DeploymentID: challenge.DeploymentID, Manifest: manifest, ManifestKey: artifact.ManifestKey(manifest.ImageDigest),
		Workload: challenge.Workload, Timeout: remaining, RequiredMiner: challenge.CoverageTargetMiner,
		ScoringDisposition: control.ScoringEvidenceOnly,
	})
	if deployErr != nil {
		failure := campaign.FailureAssignment
		var capacity *control.CapacityError
		if errors.As(deployErr, &capacity) {
			failure = campaign.FailureCapacity
		} else if errors.Is(deployErr, context.DeadlineExceeded) || !runner.canonicalNow().Before(deadline) {
			failure = campaign.FailureDeadline
		} else if errors.Is(deployErr, context.Canceled) {
			failure = campaign.FailureCancelled
		}
		runner.finishFailure(challenge.Sequence, failure)
		return
	}
	if result.DeploymentID != challenge.DeploymentID || result.RouteHost != challenge.RouteHost ||
		result.RequiredMiner != challenge.CoverageTargetMiner || result.ScoringDisposition != control.ScoringEvidenceOnly ||
		len(result.AcceptedTickets) != runner.config.Campaign.RequiredReplicas ||
		len(result.ReadyMiners) != runner.config.Campaign.RequiredReplicas {
		runner.finishFailure(challenge.Sequence, campaign.FailureAssignment)
		return
	}
	ready := make(map[string]struct{}, len(result.ReadyMiners))
	for _, minerID := range result.ReadyMiners {
		if minerID == "" {
			runner.finishFailure(challenge.Sequence, campaign.FailureAssignment)
			return
		}
		if _, duplicate := ready[minerID]; duplicate {
			runner.finishFailure(challenge.Sequence, campaign.FailureAssignment)
			return
		}
		ready[minerID] = struct{}{}
	}
	acceptedMiners := make(map[string]struct{}, len(result.AcceptedTickets))
	targetAccepted := false
	for _, accepted := range result.AcceptedTickets {
		if accepted.Ticket.ImageDigest != manifest.ImageDigest || accepted.Ticket.ManifestKey != artifact.ManifestKey(manifest.ImageDigest) {
			runner.finishFailure(challenge.Sequence, campaign.FailureAssignment)
			return
		}
		if _, exists := ready[accepted.Ticket.MinerID]; !exists {
			runner.finishFailure(challenge.Sequence, campaign.FailureAssignment)
			return
		}
		if _, duplicate := acceptedMiners[accepted.Ticket.MinerID]; duplicate {
			runner.finishFailure(challenge.Sequence, campaign.FailureAssignment)
			return
		}
		acceptedMiners[accepted.Ticket.MinerID] = struct{}{}
		targetAccepted = targetAccepted || accepted.Ticket.MinerID == challenge.CoverageTargetMiner
	}
	if !targetAccepted {
		runner.finishFailure(challenge.Sequence, campaign.FailureAssignment)
		return
	}
	sort.Slice(result.AcceptedTickets, func(left, right int) bool {
		if !result.AcceptedTickets[left].AcceptedAt.Equal(result.AcceptedTickets[right].AcceptedAt) {
			return result.AcceptedTickets[left].AcceptedAt.Before(result.AcceptedTickets[right].AcceptedAt)
		}
		return result.AcceptedTickets[left].Ticket.MinerID < result.AcceptedTickets[right].Ticket.MinerID
	})
	for _, accepted := range result.AcceptedTickets {
		runner.mu.Lock()
		err = runner.engine.RecordAcceptedTicket(challenge.Sequence, accepted.Ticket, accepted.AcceptedAt.UTC().Round(0))
		if err == nil {
			err = runner.persistLocked()
		}
		runner.mu.Unlock()
		if err != nil {
			runner.finishFailure(challenge.Sequence, campaign.FailureReceipt)
			return
		}
	}
	now := runner.canonicalNow()
	if !now.Before(deadline) {
		runner.finishFailure(challenge.Sequence, campaign.FailureDeadline)
		return
	}
	if err := runner.finish(challenge.Sequence, now, campaign.OutcomeSucceeded, campaign.FailureNone); err != nil {
		return
	}
	_ = runner.processCleanups(context.Background(), runner.canonicalNow())
}

func (runner *Runner) finishFailure(sequence uint64, failure campaign.FailureCode) {
	now := runner.canonicalNow()
	if failure == campaign.FailureDeadline {
		runner.mu.Lock()
		state := runner.engine.Snapshot()
		for _, challenge := range state.Challenges {
			if challenge.Sequence == sequence && challenge.DeadlineAt != nil && now.Before(*challenge.DeadlineAt) {
				now = *challenge.DeadlineAt
			}
		}
		runner.mu.Unlock()
	}
	_ = runner.finish(sequence, now, campaign.OutcomeFailed, failure)
}

func (runner *Runner) finish(sequence uint64, now time.Time, outcome campaign.Outcome, failure campaign.FailureCode) error {
	runner.mu.Lock()
	evidence, err := runner.engine.Complete(sequence, runner.notBeforeStateLocked(now), outcome, failure)
	if err == nil {
		index := runner.runIndexLocked(sequence)
		if index < 0 {
			err = ErrAmbiguousState
		} else {
			run := &runner.runs[index]
			if run.Manifest == nil {
				// RunStarted precedes every external side effect. Once such a run
				// is terminal, retaining a cleanup journal would invent authority
				// that does not exist and would be rejected on restart.
				if run.Phase != RunStarted {
					err = ErrAmbiguousState
				} else {
					runner.runs = append(runner.runs[:index], runner.runs[index+1:]...)
				}
			} else {
				run.Phase = RunRetained
				run.DeploymentCleanupPending = true
				run.LastFailureCode = failure
				run.ArtifactCleanupPending = true
				if run.RetainUntil == nil {
					value := now.Add(time.Duration(runner.config.Artifacts.RetentionMillis) * time.Millisecond)
					run.RetainUntil = &value
				}
			}
			if err == nil {
				err = runner.persistLocked()
			}
		}
	}
	runner.mu.Unlock()
	if err != nil {
		runner.fail(err)
		return err
	}
	err = runner.store.WriteEvidence(evidence)
	if err != nil {
		runner.fail(err)
	}
	return err
}

func (runner *Runner) updateRunPhase(sequence uint64, phase RunPhase) error {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	index := runner.runIndexLocked(sequence)
	if index < 0 {
		return ErrAmbiguousState
	}
	runner.runs[index].Phase = phase
	return runner.persistLocked()
}

func (runner *Runner) processCleanups(ctx context.Context, now time.Time) error {
	runner.mu.Lock()
	sequences := make([]uint64, 0, len(runner.runs))
	for _, run := range runner.runs {
		if !runner.cleaning[run.Sequence] && (run.DeploymentCleanupPending || run.ArtifactCleanupPending) {
			runner.cleaning[run.Sequence] = true
			sequences = append(sequences, run.Sequence)
		}
	}
	runner.mu.Unlock()
	for _, sequence := range sequences {
		if err := runner.cleanupOne(ctx, sequence, now); err != nil {
			runner.mu.Lock()
			delete(runner.cleaning, sequence)
			runner.mu.Unlock()
			return err
		}
		runner.mu.Lock()
		delete(runner.cleaning, sequence)
		runner.mu.Unlock()
	}
	return nil
}

func (runner *Runner) cleanupOne(ctx context.Context, sequence uint64, now time.Time) error {
	if err := runner.cleanupDeployment(ctx, sequence, now); err != nil {
		return err
	}
	if err := runner.cleanupArtifact(ctx, sequence, now); err != nil {
		return err
	}
	runner.mu.Lock()
	defer runner.mu.Unlock()
	index := runner.runIndexLocked(sequence)
	if index >= 0 && !runner.runs[index].DeploymentCleanupPending && !runner.runs[index].ArtifactCleanupPending {
		runner.runs = append(runner.runs[:index], runner.runs[index+1:]...)
		return runner.persistLocked()
	}
	return nil
}

func (runner *Runner) cleanupDeployment(ctx context.Context, sequence uint64, now time.Time) error {
	runner.mu.Lock()
	index := runner.runIndexLocked(sequence)
	if index < 0 || !runner.runs[index].DeploymentCleanupPending {
		runner.mu.Unlock()
		return nil
	}
	run := runner.runs[index]
	due := run.DeploymentNextCleanupAt == nil || !now.Before(*run.DeploymentNextCleanupAt)
	exhausted := run.DeploymentCleanupExhausted
	runner.mu.Unlock()
	cleanupContext, cancel := context.WithTimeout(ctx, time.Duration(runner.config.Artifacts.CleanupTimeoutMillis)*time.Millisecond)
	defer cancel()
	var actionErr error
	if due && !exhausted {
		actionErr = runner.scheduler.DeactivateDeployment(cleanupContext, run.DeploymentID)
	}
	pending, countErr := runner.scheduler.PendingCleanupAssignments(cleanupContext, run.DeploymentID)
	if countErr != nil {
		actionErr = errors.Join(actionErr, countErr)
	}
	runner.mu.Lock()
	defer runner.mu.Unlock()
	index = runner.runIndexLocked(sequence)
	if index < 0 {
		return nil
	}
	current := &runner.runs[index]
	if actionErr == nil && pending == 0 {
		current.DeploymentCleanupPending = false
		current.DeploymentCleanupAttempts = 0
		current.DeploymentCleanupExhausted = false
		current.DeploymentNextCleanupAt = nil
		return runner.persistLocked()
	}
	if !due || exhausted {
		return nil
	}
	current.DeploymentCleanupAttempts++
	current.LastFailureCode = campaign.FailureRouting
	setDeploymentRetry(current, runner.config, now)
	return runner.persistLocked()
}

func (runner *Runner) cleanupArtifact(ctx context.Context, sequence uint64, now time.Time) error {
	runner.mu.Lock()
	index := runner.runIndexLocked(sequence)
	if index < 0 || !runner.runs[index].ArtifactCleanupPending || runner.runs[index].DeploymentCleanupPending {
		runner.mu.Unlock()
		return nil
	}
	run := runner.runs[index]
	due := run.RetainUntil != nil && !now.Before(*run.RetainUntil) &&
		(run.ArtifactNextCleanupAt == nil || !now.Before(*run.ArtifactNextCleanupAt))
	if !due || run.ArtifactCleanupExhausted {
		runner.mu.Unlock()
		return nil
	}
	runner.mu.Unlock()
	cleanupContext, cancel := context.WithTimeout(ctx, time.Duration(runner.config.Artifacts.CleanupTimeoutMillis)*time.Millisecond)
	defer cancel()
	err := artifact.DeleteExact(cleanupContext, runner.artifacts, run.ArtifactKeys)
	runner.mu.Lock()
	defer runner.mu.Unlock()
	index = runner.runIndexLocked(sequence)
	if index < 0 {
		return nil
	}
	current := &runner.runs[index]
	if err == nil {
		current.ArtifactCleanupPending = false
		current.ArtifactCleanupAttempts = 0
		current.ArtifactCleanupExhausted = false
		current.ArtifactNextCleanupAt = nil
		return runner.persistLocked()
	}
	current.ArtifactCleanupAttempts++
	current.LastFailureCode = campaign.FailureArtifact
	setArtifactRetry(current, runner.config, now)
	return runner.persistLocked()
}

func (runner *Runner) recoverLocked(now time.Time) error {
	state := runner.engine.Snapshot()
	runBySequence := make(map[uint64]int, len(runner.runs))
	for index := range runner.runs {
		runBySequence[runner.runs[index].Sequence] = index
	}
	var evidence []campaign.Evidence
	mutated := false
	sideEffectFree := make(map[uint64]struct{})
	for _, challenge := range state.Challenges {
		if challenge.Status == campaign.StatusRunning {
			index, exists := runBySequence[challenge.Sequence]
			if !exists {
				return ErrAmbiguousState
			}
			terminal, err := runner.engine.Complete(challenge.Sequence, runner.notBeforeStateLocked(now), campaign.OutcomeFailed, campaign.FailureInternal)
			if err != nil {
				return err
			}
			run := &runner.runs[index]
			if run.Manifest == nil {
				if run.Phase != RunStarted {
					return ErrAmbiguousState
				}
				sideEffectFree[run.Sequence] = struct{}{}
			} else {
				run.Phase = RunRetained
				run.DeploymentCleanupPending = true
				run.LastFailureCode = campaign.FailureInternal
				run.ArtifactCleanupPending = true
				if run.RetainUntil == nil {
					value := now
					run.RetainUntil = &value
				}
			}
			evidence = append(evidence, terminal)
			mutated = true
		}
	}
	if len(sideEffectFree) > 0 {
		retained := runner.runs[:0]
		for _, run := range runner.runs {
			if _, discard := sideEffectFree[run.Sequence]; !discard {
				retained = append(retained, run)
			}
		}
		runner.runs = retained
	}
	if mutated {
		if err := runner.persistLocked(); err != nil {
			return err
		}
	}
	mutated = false
	retained := runner.runs[:0]
	for _, run := range runner.runs {
		if run.DeploymentCleanupPending || run.ArtifactCleanupPending {
			retained = append(retained, run)
		} else {
			mutated = true
		}
	}
	runner.runs = retained
	if mutated {
		if err := runner.persistLocked(); err != nil {
			return err
		}
	}
	state = runner.engine.Snapshot()
	for _, challenge := range state.Challenges {
		if challenge.Status == campaign.StatusSucceeded || challenge.Status == campaign.StatusFailed || challenge.Status == campaign.StatusCancelled {
			terminal, err := runner.engine.Evidence(challenge.Sequence)
			if err != nil {
				return err
			}
			existing, existingErr := runner.store.Evidence(challenge.Sequence)
			if existingErr == nil {
				if !sameEvidenceIdentity(existing, terminal) {
					return ErrAmbiguousState
				}
				continue
			}
			if !errors.Is(existingErr, os.ErrNotExist) {
				return existingErr
			}
			evidence = append(evidence, terminal)
		}
	}
	return runner.persistEvidence(evidence)
}

func sameEvidenceIdentity(left, right campaign.Evidence) bool {
	left.StateDigestSHA256 = ""
	left.EvidenceDigestSHA256 = ""
	right.StateDigestSHA256 = ""
	right.EvidenceDigestSHA256 = ""
	leftBytes, leftErr := json.Marshal(left)
	rightBytes, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftBytes, rightBytes)
}

func (runner *Runner) persistEvidence(values []campaign.Evidence) error {
	seen := make(map[uint64]struct{}, len(values))
	for _, evidence := range values {
		if _, exists := seen[evidence.Sequence]; exists {
			continue
		}
		seen[evidence.Sequence] = struct{}{}
		if err := runner.store.WriteEvidence(evidence); err != nil {
			return err
		}
	}
	return nil
}

func (runner *Runner) persistLocked() error {
	err := runner.store.Save(runner.engine.Snapshot(), runner.runs)
	if err != nil && runner.fatal == nil {
		runner.fatal = err
		runner.cancelWorkers()
	}
	return err
}

func (runner *Runner) fail(err error) {
	if err == nil {
		return
	}
	runner.mu.Lock()
	if runner.fatal == nil {
		runner.fatal = err
		runner.cancelWorkers()
	}
	runner.mu.Unlock()
}

func (runner *Runner) runIndexLocked(sequence uint64) int {
	for index := range runner.runs {
		if runner.runs[index].Sequence == sequence {
			return index
		}
	}
	return -1
}

func (runner *Runner) lifecycleErrorLocked() error {
	if runner.closed {
		return errors.New("campaign runner is closed")
	}
	return runner.fatal
}

func (runner *Runner) retainedBytesLocked() int64 {
	var total int64
	for _, run := range runner.runs {
		if run.Manifest != nil {
			total += run.ArtifactBytes
		}
	}
	return total
}

func (runner *Runner) canonicalNow() time.Time {
	return runner.now().UTC().Round(0)
}

func (runner *Runner) canonicalNowLocked() time.Time {
	return runner.notBeforeStateLocked(runner.canonicalNow())
}

func (runner *Runner) notBeforeStateLocked(value time.Time) time.Time {
	updatedAt := runner.engine.Snapshot().UpdatedAt
	value = value.UTC().Round(0)
	if value.Before(updatedAt) {
		return updatedAt
	}
	return value
}

func retryDelay(config RuntimeConfig, attempts int) time.Duration {
	delay := time.Duration(config.Retry.InitialBackoffMillis) * time.Millisecond
	maximum := time.Duration(config.Retry.MaximumBackoffMillis) * time.Millisecond
	for index := 1; index < attempts && delay < maximum; index++ {
		if delay > maximum/2 {
			return maximum
		}
		delay *= 2
	}
	if delay > maximum {
		return maximum
	}
	return delay
}

func setDeploymentRetry(run *RunRecord, config RuntimeConfig, now time.Time) {
	if run.DeploymentCleanupAttempts >= config.Retry.MaxAttempts {
		run.DeploymentCleanupAttempts = config.Retry.MaxAttempts
		run.DeploymentCleanupExhausted = true
		run.DeploymentNextCleanupAt = nil
		return
	}
	next := now.Add(retryDelay(config, run.DeploymentCleanupAttempts))
	run.DeploymentNextCleanupAt = &next
}

func setArtifactRetry(run *RunRecord, config RuntimeConfig, now time.Time) {
	if run.ArtifactCleanupAttempts >= config.Retry.MaxAttempts {
		run.ArtifactCleanupAttempts = config.Retry.MaxAttempts
		run.ArtifactCleanupExhausted = true
		run.ArtifactNextCleanupAt = nil
		return
	}
	next := now.Add(retryDelay(config, run.ArtifactCleanupAttempts))
	run.ArtifactNextCleanupAt = &next
}
