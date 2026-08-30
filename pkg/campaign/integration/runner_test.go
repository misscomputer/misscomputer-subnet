// SPDX-License-Identifier: AGPL-3.0-only

package integration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/artifact"
	"github.com/misscomputer/misscomputer-subnet/pkg/campaign"
	"github.com/misscomputer/misscomputer-subnet/pkg/control"
	"github.com/misscomputer/misscomputer-subnet/pkg/protocol"
	"github.com/misscomputer/misscomputer-subnet/pkg/workload"
)

func TestRunnerEndToEndUniquenessFairnessCleanupAndScoringBoundary(t *testing.T) {
	clock := newTestClock(integrationEpoch)
	artifacts := newMemoryArtifacts()
	scheduler := &fakeCampaignScheduler{now: clock.Now, miners: []string{"MinerA", "MinerB", "MinerC"}}
	runner := newTestRunner(t, integrationConfig(), clock, artifacts, scheduler, t.TempDir())
	defer runner.Close()

	seenDeployments := make(map[string]struct{})
	seenTargets := make(map[string]struct{})
	var hiddenValues []string
	for index := 0; index < 3; index++ {
		if err := runner.Tick(context.Background()); err != nil {
			t.Fatal(err)
		}
		waitRunner(t, runner)
		status, err := runner.Status()
		if err != nil || len(status.Challenges) != index+1 {
			t.Fatalf("status=%+v err=%v", status, err)
		}
		challenge := status.Challenges[len(status.Challenges)-1]
		if challenge.Status != campaign.StatusSucceeded || challenge.AcceptedAssignments != 3 {
			t.Fatalf("challenge=%+v", challenge)
		}
		if _, duplicate := seenDeployments[challenge.DeploymentID]; duplicate {
			t.Fatalf("duplicate deployment %q", challenge.DeploymentID)
		}
		seenDeployments[challenge.DeploymentID] = struct{}{}
		seenTargets[challenge.CoverageTargetMiner] = struct{}{}
		evidence, err := runner.Evidence(challenge.Sequence)
		if err != nil || evidence.ScoringEffect != campaign.ScoringEffectNone ||
			evidence.AcceptanceObservationSource != campaign.ScoringSourceExisting {
			t.Fatalf("evidence=%+v err=%v", evidence, err)
		}
		clock.Advance(time.Second)
	}
	if len(seenTargets) != 3 {
		t.Fatalf("first coverage cycle targets=%v", seenTargets)
	}
	requests := scheduler.Requests()
	if len(requests) != 3 {
		t.Fatalf("deploy requests=%d", len(requests))
	}
	for _, request := range requests {
		if request.RequiredMiner == "" || request.ScoringDisposition != control.ScoringEvidenceOnly {
			t.Fatalf("campaign request crossed target/scoring boundary: %+v", request)
		}
		hiddenValues = append(hiddenValues, request.Workload.ChallengeValue)
	}
	status, err := runner.Status()
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	for _, hidden := range hiddenValues {
		if strings.Contains(string(encoded), hidden) {
			t.Fatal("credential-safe status leaked the raw hidden challenge")
		}
	}
	clock.Advance(2 * time.Second)
	if err := runner.Pause(); err != nil {
		t.Fatal(err)
	}
	if err := runner.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	status, _ = runner.Status()
	if status.CleanupBacklog != 0 || artifacts.Count() != 0 {
		t.Fatalf("cleanup status=%+v artifact_count=%d", status, artifacts.Count())
	}
}

func TestRunnerConcurrencyPendingAndStorageBackpressure(t *testing.T) {
	clock := newTestClock(integrationEpoch)
	artifacts := newMemoryArtifacts()
	block := make(chan struct{})
	scheduler := &fakeCampaignScheduler{
		now: clock.Now, miners: []string{"MinerA", "MinerB", "MinerC", "MinerD"}, block: block,
	}
	config := integrationConfig()
	runner := newTestRunner(t, config, clock, artifacts, scheduler, t.TempDir())
	defer runner.Close()
	if err := runner.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitForRequests(t, scheduler, 1)
	clock.Advance(time.Second)
	if err := runner.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitForRequests(t, scheduler, 2)
	for range 4 {
		clock.Advance(time.Second)
		if err := runner.Tick(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	status, err := runner.Status()
	if err != nil || status.Running != 2 || status.Pending != config.Campaign.Limits.MaxPending || len(scheduler.Requests()) != 2 {
		t.Fatalf("bounded status=%+v requests=%d err=%v", status, len(scheduler.Requests()), err)
	}
	close(block)
	waitRunner(t, runner)

	capacityConfig := integrationConfig()
	capacityConfig.Artifacts.MaxSingleBytes = 1_024
	capacityConfig.Artifacts.MaxRetainedBytes = 2_048
	capacityConfig.Artifacts.RetentionMillis = int64(time.Hour / time.Millisecond)
	capacityClock := newTestClock(integrationEpoch)
	capacityArtifacts := newMemoryArtifacts()
	capacityScheduler := &fakeCampaignScheduler{now: capacityClock.Now, miners: []string{"MinerA", "MinerB", "MinerC"}}
	capacityRunner := newTestRunner(t, capacityConfig, capacityClock, capacityArtifacts, capacityScheduler, t.TempDir())
	defer capacityRunner.Close()
	for range 3 {
		if err := capacityRunner.Tick(context.Background()); err != nil {
			t.Fatal(err)
		}
		waitRunner(t, capacityRunner)
		capacityClock.Advance(time.Second)
	}
	capacityStatus, _ := capacityRunner.Status()
	last := capacityStatus.Challenges[len(capacityStatus.Challenges)-1]
	if !capacityStatus.RuntimeHealthy || last.Status != campaign.StatusFailed || last.FailureCode != campaign.FailureCapacity || len(capacityScheduler.Requests()) != 2 {
		t.Fatalf("capacity status=%+v requests=%d", capacityStatus, len(capacityScheduler.Requests()))
	}
	capacityClock.Advance(time.Second)
	if err := capacityRunner.Tick(context.Background()); err != nil {
		t.Fatalf("healthy tick after capacity failure: %v", err)
	}
	waitRunner(t, capacityRunner)
	capacityStatus, _ = capacityRunner.Status()
	if !capacityStatus.RuntimeHealthy || len(capacityScheduler.Requests()) != 2 {
		t.Fatalf("post-capacity runtime status=%+v requests=%d", capacityStatus, len(capacityScheduler.Requests()))
	}
}

func TestRunnerTrackedMinerCapacityIsNonfatalBackpressure(t *testing.T) {
	config := integrationConfig()
	config.Campaign.Limits.MaxTrackedMiners = 3
	clock := newTestClock(integrationEpoch)
	scheduler := &fakeCampaignScheduler{now: clock.Now, miners: []string{"MinerA", "MinerB", "MinerC", "MinerD"}}
	runner := newTestRunner(t, config, clock, newMemoryArtifacts(), scheduler, t.TempDir())
	defer runner.Close()

	if err := runner.Tick(context.Background()); err != nil {
		t.Fatalf("tracked-miner backpressure tick: %v", err)
	}
	status, err := runner.Status()
	if err != nil || !status.RuntimeHealthy || len(status.Challenges) != 0 || len(scheduler.Requests()) != 0 {
		t.Fatalf("tracked-miner backpressure status=%+v requests=%d err=%v", status, len(scheduler.Requests()), err)
	}

	scheduler.SetMiners([]string{"MinerA", "MinerB", "MinerC"})
	if err := runner.Tick(context.Background()); err != nil {
		t.Fatalf("healthy tick after tracked-miner backpressure: %v", err)
	}
	waitRunner(t, runner)
	status, err = runner.Status()
	if err != nil || !status.RuntimeHealthy || len(scheduler.Requests()) != 1 {
		t.Fatalf("tracked-miner recovery status=%+v requests=%d err=%v", status, len(scheduler.Requests()), err)
	}
}

func TestRunnerRestartReconcilesOrphanAndPersistsEvidence(t *testing.T) {
	config := integrationConfig()
	digest, _ := RuntimeConfigDigest(config)
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	clock := newTestClock(integrationEpoch)
	artifacts := newMemoryArtifacts()
	stateStore, state, _, err := OpenStateStore(directory, config, digest, integrationEpoch)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := campaign.Restore(config.Campaign, state)
	if err != nil {
		t.Fatal(err)
	}
	scheduled, err := engine.Schedule(integrationEpoch, []string{"MinerA", "MinerB", "MinerC"})
	if err != nil || scheduled.Challenge == nil {
		t.Fatalf("schedule=%+v err=%v", scheduled, err)
	}
	started, err := engine.StartNext(integrationEpoch)
	if err != nil || started.Challenge == nil {
		t.Fatalf("start=%+v err=%v", started, err)
	}
	layer, err := workload.Encode(started.Challenge.Workload)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := artifact.PrepareManifest(started.Challenge.Workload.Kind, [][]byte{layer}, map[string]string{
		"build_id":          started.Challenge.Workload.BuildID,
		"campaign_id":       engine.Snapshot().CampaignID,
		"campaign_sequence": strconv.FormatUint(started.Challenge.Sequence, 10),
	}, integrationEpoch)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := artifact.PublishPrepared(context.Background(), artifacts, manifest, [][]byte{layer}); err != nil {
		t.Fatal(err)
	}
	keys, _ := artifact.ArtifactKeys(manifest)
	retainUntil := integrationEpoch.Add(time.Second)
	runs := []RunRecord{{
		Sequence: started.Challenge.Sequence, DeploymentID: started.Challenge.DeploymentID,
		Phase: RunDeploying, StartedAt: *started.Challenge.StartedAt, Manifest: &manifest,
		ArtifactKeys: keys, ArtifactBytes: int64(len(layer)), RetainUntil: &retainUntil,
	}}
	if err := stateStore.Save(engine.Snapshot(), runs); err != nil {
		t.Fatal(err)
	}
	stateStore.Close()

	clock.Advance(2 * time.Second)
	scheduler := &fakeCampaignScheduler{now: clock.Now, miners: []string{"MinerA", "MinerB", "MinerC"}, pendingCleanup: 1}
	runner := newTestRunner(t, config, clock, artifacts, scheduler, directory)
	defer runner.Close()
	if err := runner.Pause(); err != nil {
		t.Fatal(err)
	}
	if err := runner.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	evidence, err := runner.Evidence(started.Challenge.Sequence)
	if err != nil || evidence.Outcome != campaign.OutcomeFailed || evidence.FailureCode != campaign.FailureInternal {
		t.Fatalf("restart evidence=%+v err=%v", evidence, err)
	}
	status, _ := runner.Status()
	if status.CleanupBacklog != 0 || artifacts.Count() != 0 || scheduler.Deactivations() == 0 {
		t.Fatalf("restart cleanup status=%+v objects=%d deactivations=%d", status, artifacts.Count(), scheduler.Deactivations())
	}
}

func TestRunnerRestartClosesPreManifestRunWithoutCleanupJournal(t *testing.T) {
	config := integrationConfig()
	digest, _ := RuntimeConfigDigest(config)
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	clock := newTestClock(integrationEpoch)
	artifacts := newMemoryArtifacts()
	stateStore, state, _, err := OpenStateStore(directory, config, digest, integrationEpoch)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := campaign.Restore(config.Campaign, state)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Schedule(integrationEpoch, []string{"MinerA", "MinerB", "MinerC"}); err != nil {
		t.Fatal(err)
	}
	started, err := engine.StartNext(integrationEpoch)
	if err != nil || started.Challenge == nil {
		t.Fatalf("start=%+v err=%v", started, err)
	}
	runs := []RunRecord{{
		Sequence: started.Challenge.Sequence, DeploymentID: started.Challenge.DeploymentID,
		Phase: RunStarted, StartedAt: *started.Challenge.StartedAt, ArtifactKeys: []string{},
	}}
	if err := stateStore.Save(engine.Snapshot(), runs); err != nil {
		t.Fatal(err)
	}
	if err := stateStore.Close(); err != nil {
		t.Fatal(err)
	}

	scheduler := &fakeCampaignScheduler{now: clock.Now, miners: []string{"MinerA", "MinerB", "MinerC"}}
	runner := newTestRunner(t, config, clock, artifacts, scheduler, directory)
	evidence, err := runner.Evidence(started.Challenge.Sequence)
	status, statusErr := runner.Status()
	_, recoveredRuns, _, currentErr := runner.store.Current()
	if err != nil || statusErr != nil || currentErr != nil || evidence.Outcome != campaign.OutcomeFailed ||
		evidence.FailureCode != campaign.FailureInternal || !status.RuntimeHealthy || status.CleanupBacklog != 0 || len(recoveredRuns) != 0 {
		t.Fatalf("pre-manifest recovery evidence=%+v status=%+v runs=%+v errors=%v/%v/%v", evidence, status, recoveredRuns, err, statusErr, currentErr)
	}
	if err := runner.Tick(context.Background()); err != nil {
		t.Fatalf("post-recovery tick: %v", err)
	}
	if err := runner.Close(); err != nil {
		t.Fatal(err)
	}

	restarted := newTestRunner(t, config, clock, artifacts, scheduler, directory)
	defer restarted.Close()
	status, statusErr = restarted.Status()
	evidence, err = restarted.Evidence(started.Challenge.Sequence)
	if err != nil || statusErr != nil || !status.RuntimeHealthy || status.CleanupBacklog != 0 ||
		evidence.FailureCode != campaign.FailureInternal {
		t.Fatalf("second restart evidence=%+v status=%+v errors=%v/%v", evidence, status, err, statusErr)
	}
}

func TestRunnerRestartPreservesEarlierTerminalEvidenceRevision(t *testing.T) {
	config := integrationConfig()
	clock := newTestClock(integrationEpoch)
	artifacts := newMemoryArtifacts()
	scheduler := &fakeCampaignScheduler{now: clock.Now, miners: []string{"MinerA", "MinerB", "MinerC"}}
	directory := t.TempDir()
	runner := newTestRunner(t, config, clock, artifacts, scheduler, directory)
	for range 2 {
		if err := runner.Tick(context.Background()); err != nil {
			t.Fatal(err)
		}
		waitRunner(t, runner)
		clock.Advance(time.Second)
	}
	before, err := runner.Evidence(1)
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.Close(); err != nil {
		t.Fatal(err)
	}
	restarted := newTestRunner(t, config, clock, artifacts, scheduler, directory)
	defer restarted.Close()
	after, err := restarted.Evidence(1)
	if err != nil || after.EvidenceDigestSHA256 != before.EvidenceDigestSHA256 || after.StateDigestSHA256 != before.StateDigestSHA256 {
		t.Fatalf("restart evidence before=%+v after=%+v err=%v", before, after, err)
	}
}

func TestRunnerCleanupRetriesAreBoundedAndRecover(t *testing.T) {
	clock := newTestClock(integrationEpoch)
	artifacts := newMemoryArtifacts()
	artifacts.failDeletes = 2
	scheduler := &fakeCampaignScheduler{
		now: clock.Now, miners: []string{"MinerA", "MinerB", "MinerC"}, deactivateFailures: 2,
	}
	runner := newTestRunner(t, integrationConfig(), clock, artifacts, scheduler, t.TempDir())
	defer runner.Close()
	if err := runner.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitRunner(t, runner)
	if err := runner.Pause(); err != nil {
		t.Fatal(err)
	}
	for _, advance := range []time.Duration{100 * time.Millisecond, 200 * time.Millisecond, time.Second, 100 * time.Millisecond} {
		clock.Advance(advance)
		if err := runner.Tick(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	status, _ := runner.Status()
	if scheduler.Deactivations() != 3 || status.CleanupBacklog != 0 || status.CleanupExhausted != 0 || artifacts.Count() != 0 {
		t.Fatalf("retry status=%+v deactivations=%d artifacts=%d", status, scheduler.Deactivations(), artifacts.Count())
	}
}

func TestRunnerCleanupExhaustionBacksOffUntilExternalReconciliation(t *testing.T) {
	clock := newTestClock(integrationEpoch)
	artifacts := newMemoryArtifacts()
	scheduler := &fakeCampaignScheduler{
		now: clock.Now, miners: []string{"MinerA", "MinerB", "MinerC"}, pendingCleanup: 1, deactivateFailures: 100,
	}
	runner := newTestRunner(t, integrationConfig(), clock, artifacts, scheduler, t.TempDir())
	defer runner.Close()
	if err := runner.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitRunner(t, runner)
	if err := runner.Pause(); err != nil {
		t.Fatal(err)
	}
	for _, advance := range []time.Duration{100 * time.Millisecond, 200 * time.Millisecond} {
		clock.Advance(advance)
		if err := runner.Tick(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	status, err := runner.Status()
	if err != nil || status.CleanupBacklog != 1 || status.CleanupExhausted != 1 || len(status.Cleanup) != 1 ||
		!status.Cleanup[0].DeploymentCleanupExhausted || scheduler.Deactivations() != 3 {
		t.Fatalf("exhausted cleanup status=%+v deactivations=%d err=%v", status, scheduler.Deactivations(), err)
	}
	clock.Advance(time.Second)
	if err := runner.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if scheduler.Deactivations() != 3 {
		t.Fatalf("exhausted cleanup retried without authority: %d", scheduler.Deactivations())
	}
	scheduler.mu.Lock()
	scheduler.pendingCleanup = 0
	scheduler.mu.Unlock()
	if err := runner.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	status, err = runner.Status()
	if err != nil || status.CleanupBacklog != 0 || status.CleanupExhausted != 0 || artifacts.Count() != 0 {
		t.Fatalf("reconciled cleanup status=%+v artifacts=%d err=%v", status, artifacts.Count(), err)
	}
}

func TestRunnerReadinessExpiryPausesWithoutStoppingLoopAndFreshProofResumes(t *testing.T) {
	clock := newTestClock(integrationEpoch)
	artifacts := newMemoryArtifacts()
	scheduler := &fakeCampaignScheduler{now: clock.Now, miners: []string{"MinerA", "MinerB", "MinerC"}}
	runner := newTestRunner(t, integrationConfig(), clock, artifacts, scheduler, t.TempDir())
	defer runner.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- runner.Run(ctx) }()
	waitForRequests(t, scheduler, 1)
	waitRunner(t, runner)
	requests := len(scheduler.Requests())
	clock.Advance(6 * time.Hour)
	deadline := time.Now().Add(5 * time.Second)
	var status Status
	var err error
	for time.Now().Before(deadline) {
		status, err = runner.Status()
		if err == nil && status.Mode == campaign.ModePaused && !status.ReadinessReady && status.CleanupBacklog == 0 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if err != nil || status.Mode != campaign.ModePaused || status.ReadinessReady || status.CleanupBacklog != 0 ||
		status.ReadinessProofSHA256 == "" || artifacts.Count() != 0 || len(scheduler.Requests()) != requests {
		t.Fatalf("expired readiness status=%+v artifacts=%d requests=%d err=%v", status, artifacts.Count(), len(scheduler.Requests()), err)
	}
	select {
	case runErr := <-done:
		t.Fatalf("campaign process loop stopped on readiness expiry: %v", runErr)
	default:
	}
	if err := runner.Resume(); !errors.Is(err, ErrInvalidReadiness) {
		t.Fatalf("expired readiness resume error=%v", err)
	}
	if err := runner.Drain(); err != nil {
		t.Fatalf("drain while readiness is expired: %v", err)
	}
	time.Sleep(3 * time.Duration(integrationConfig().TickIntervalMillis) * time.Millisecond)
	if len(scheduler.Requests()) != requests {
		t.Fatalf("expired readiness admitted work: requests=%d want=%d", len(scheduler.Requests()), requests)
	}
	fresh := readinessProof(t, clock.Now())
	if err := runner.ReloadReadinessAndResume(fresh); err != nil {
		t.Fatalf("fresh readiness resume: %v", err)
	}
	waitForRequests(t, scheduler, requests+1)
	waitRunner(t, runner)
	status, err = runner.Status()
	if err != nil || !status.RuntimeHealthy || !status.ReadinessReady || status.Mode != campaign.ModeRunning ||
		status.ReadinessProofSHA256 != fresh.ProofDigestSHA256 {
		t.Fatalf("resumed readiness status=%+v err=%v", status, err)
	}
	cancel()
	select {
	case runErr := <-done:
		if !errors.Is(runErr, context.Canceled) {
			t.Fatalf("campaign process loop exit=%v", runErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("campaign process loop did not stop after cancellation")
	}
}

func TestRunnerExternalDrainResumeAndShutdown(t *testing.T) {
	clock := newTestClock(integrationEpoch)
	runner := newTestRunner(
		t, integrationConfig(), clock, newMemoryArtifacts(),
		&fakeCampaignScheduler{now: clock.Now, miners: []string{"MinerA", "MinerB", "MinerC"}}, t.TempDir(),
	)
	defer runner.Close()
	if err := runner.Drain(); err != nil {
		t.Fatal(err)
	}
	status, err := runner.Status()
	if err != nil || status.Mode != campaign.ModePaused {
		t.Fatalf("drained status=%+v err=%v", status, err)
	}
	if err := runner.Resume(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := runner.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	status, err = runner.Status()
	if err != nil || status.Mode != campaign.ModeStopped {
		t.Fatalf("shutdown status=%+v err=%v", status, err)
	}
}

func newTestRunner(t *testing.T, config RuntimeConfig, clock *testClock, artifacts *memoryArtifacts, scheduler *fakeCampaignScheduler, directory string) *Runner {
	t.Helper()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	digest, err := RuntimeConfigDigest(config)
	if err != nil {
		t.Fatal(err)
	}
	runner, err := NewRunner(config, digest, Dependencies{
		StateDirectory: directory, Environment: validEnvironment(), Readiness: readinessProof(t, integrationEpoch),
		Scheduler: scheduler, Artifacts: artifacts, Miners: scheduler.Miners,
		Now: clock.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return runner
}

func waitRunner(t *testing.T, runner *Runner) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := runner.WaitIdle(ctx); err != nil {
		t.Fatal(err)
	}
}

func waitForRequests(t *testing.T, scheduler *fakeCampaignScheduler, count int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if len(scheduler.Requests()) >= count {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("scheduler requests=%d, want %d", len(scheduler.Requests()), count)
}

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func newTestClock(now time.Time) *testClock { return &testClock{now: now} }

func (clock *testClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.now
}

func (clock *testClock) Advance(duration time.Duration) {
	clock.mu.Lock()
	clock.now = clock.now.Add(duration)
	clock.mu.Unlock()
}

type memoryArtifacts struct {
	mu          sync.Mutex
	objects     map[string][]byte
	failDeletes int
}

func newMemoryArtifacts() *memoryArtifacts {
	return &memoryArtifacts{objects: make(map[string][]byte)}
}

func (store *memoryArtifacts) Put(ctx context.Context, key string, body []byte, _ string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	store.mu.Lock()
	store.objects[key] = append([]byte(nil), body...)
	store.mu.Unlock()
	return nil
}

func (store *memoryArtifacts) Get(ctx context.Context, key string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	body, exists := store.objects[key]
	if !exists {
		return nil, osErrNotExist
	}
	return append([]byte(nil), body...), nil
}

func (store *memoryArtifacts) Delete(ctx context.Context, key string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.failDeletes > 0 {
		store.failDeletes--
		return errors.New("injected delete failure")
	}
	delete(store.objects, key)
	return nil
}

func (store *memoryArtifacts) Count() int {
	store.mu.Lock()
	defer store.mu.Unlock()
	return len(store.objects)
}

var osErrNotExist = errors.New("object does not exist")

type fakeCampaignScheduler struct {
	mu                 sync.Mutex
	now                func() time.Time
	miners             []string
	requests           []control.DeployRequest
	block              <-chan struct{}
	pendingCleanup     int
	deactivateFailures int
	deactivations      int
}

func (scheduler *fakeCampaignScheduler) Deploy(ctx context.Context, request control.DeployRequest) (control.DeployResult, error) {
	scheduler.mu.Lock()
	scheduler.requests = append(scheduler.requests, request)
	call := len(scheduler.requests)
	block := scheduler.block
	scheduler.mu.Unlock()
	if block != nil {
		select {
		case <-ctx.Done():
			return control.DeployResult{}, ctx.Err()
		case <-block:
		}
	}
	acceptedAt := scheduler.now().UTC()
	miners := []string{request.RequiredMiner}
	for _, miner := range scheduler.miners {
		if miner != request.RequiredMiner && len(miners) < 3 {
			miners = append(miners, miner)
		}
	}
	if len(miners) < 3 {
		return control.DeployResult{}, &control.CapacityError{DeploymentID: request.DeploymentID, Required: 3, Available: len(miners)}
	}
	result := control.DeployResult{
		DeploymentID: request.DeploymentID, RouteHost: request.DeploymentID + "." + campaign.MainnetDomain,
		RequiredMiner: request.RequiredMiner, ScoringDisposition: request.ScoringDisposition,
	}
	for index, miner := range miners {
		ticket := integrationTicket(request, miner, uint64(call*100+index+1), acceptedAt)
		result.ReadyMiners = append(result.ReadyMiners, miner)
		result.AcceptedTickets = append(result.AcceptedTickets, control.AcceptedTicket{Ticket: ticket, AcceptedAt: acceptedAt})
		result.Observations = append(result.Observations, control.AcceptanceObservation{MinerHotkey: miner, Success: true, ObservedAt: acceptedAt})
	}
	return result, nil
}

func (scheduler *fakeCampaignScheduler) DeactivateDeployment(ctx context.Context, _ string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	scheduler.mu.Lock()
	defer scheduler.mu.Unlock()
	scheduler.deactivations++
	if scheduler.deactivateFailures > 0 {
		scheduler.deactivateFailures--
		return errors.New("injected deactivation failure")
	}
	scheduler.pendingCleanup = 0
	return nil
}

func (scheduler *fakeCampaignScheduler) PendingCleanupAssignments(ctx context.Context, _ string) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	scheduler.mu.Lock()
	defer scheduler.mu.Unlock()
	return scheduler.pendingCleanup, nil
}

func (scheduler *fakeCampaignScheduler) Requests() []control.DeployRequest {
	scheduler.mu.Lock()
	defer scheduler.mu.Unlock()
	return append([]control.DeployRequest(nil), scheduler.requests...)
}

func (scheduler *fakeCampaignScheduler) Miners() []string {
	scheduler.mu.Lock()
	defer scheduler.mu.Unlock()
	return append([]string(nil), scheduler.miners...)
}

func (scheduler *fakeCampaignScheduler) SetMiners(miners []string) {
	scheduler.mu.Lock()
	scheduler.miners = append([]string(nil), miners...)
	scheduler.mu.Unlock()
}

func (scheduler *fakeCampaignScheduler) Deactivations() int {
	scheduler.mu.Lock()
	defer scheduler.mu.Unlock()
	return scheduler.deactivations
}

func integrationTicket(request control.DeployRequest, miner string, nonce uint64, acceptedAt time.Time) protocol.Ticket {
	uid := uint16(nonce)
	pin := strings.Repeat("a", 64)
	return protocol.Ticket{
		Version: protocol.BoundVersion, DeploymentID: request.DeploymentID, Generation: 1,
		ImageDigest: request.Manifest.ImageDigest, ManifestKey: request.ManifestKey, MinerID: miner,
		RouteHost:       request.DeploymentID + "." + campaign.MainnetDomain,
		AssignmentNonce: fmt.Sprintf("%032x", nonce), ChallengePath: request.Workload.ChallengePath,
		ChallengeSHA256: protocol.ChallengeDigest(request.Workload.ChallengeValue),
		IssuedAt:        acceptedAt.Add(-time.Second), ExpiresAt: acceptedAt.Add(time.Minute),
		Subnet: &protocol.SubnetBinding{
			Network: campaign.MainnetNetwork, NetUID: campaign.MainnetNetUID, ValidatorHotkey: "Validator1",
			MinerHotkey: miner, MinerUID: &uid, MinerAxonURL: "https://8.8.8.8:443", MinerTransport: "https",
			MinerTLSCertificateSHA256: &pin, ChainBlock: 100, Epoch: 1, ExpiresAtBlock: 200,
			ValidatorServicePublicKey: strings.Repeat("a", 64), MinerServicePublicKey: strings.Repeat("b", 64),
		},
	}
}
