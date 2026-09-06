// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/validator"
)

// scriptedProber answers targeted probes from a per-miner script so a sweep can
// be driven deterministically without a network. Miners absent from the script
// serve correctly.
type scriptedProber struct {
	mu       sync.Mutex
	dark     map[string]bool
	wrong    map[string]bool
	requests []string
	byMiner  map[string]string
}

func newScriptedProber(replicaToMiner map[string]string) *scriptedProber {
	return &scriptedProber{dark: map[string]bool{}, wrong: map[string]bool{}, byMiner: replicaToMiner}
}

func (s *scriptedProber) ProbeReplica(_ context.Context, _, replicaID, _, _ string) validator.ProbeResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	minerID := s.byMiner[replicaID]
	s.requests = append(s.requests, replicaID)
	switch {
	case s.dark[minerID]:
		// A transport failure never reaches a status line.
		return validator.ProbeResult{Vantage: "test", Status: 0, Correct: false, Error: "connection refused"}
	case s.wrong[minerID]:
		return validator.ProbeResult{Vantage: "test", Status: 200, Correct: false, Error: "incorrect response status=200"}
	default:
		return validator.ProbeResult{Vantage: "test", Status: 200, Correct: true, Latency: 5 * time.Millisecond}
	}
}

func (s *scriptedProber) setDark(minerID string) {
	s.mu.Lock()
	s.dark[minerID] = true
	s.mu.Unlock()
}

func (s *scriptedProber) setWrong(minerID string) {
	s.mu.Lock()
	s.wrong[minerID] = true
	s.mu.Unlock()
}

func (s *scriptedProber) probed(replicaID string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for _, seen := range s.requests {
		if seen == replicaID {
			count++
		}
	}
	return count
}

// newProbedHarness deploys three replicas and returns a prober wired to a
// scripted probe seam, plus the replica ID of each active miner.
func newProbedHarness(t *testing.T) (*schedulerHarness, *scriptedProber, *Prober, map[string]string) {
	t.Helper()
	h := newSchedulerHarness(t, []string{"m1", "m2", "m3", "m4"}, 3)
	if _, err := h.scheduler.Deploy(context.Background(), h.request); err != nil {
		t.Fatal(err)
	}
	replicaOf := map[string]string{}
	byReplica := map[string]string{}
	for _, replica := range h.scheduler.ActiveReplicas(h.request.DeploymentID) {
		replicaOf[replica.MinerID] = replica.ReplicaID
		byReplica[replica.ReplicaID] = replica.MinerID
	}
	if len(replicaOf) != 3 {
		t.Fatalf("expected three active replicas, got %d", len(replicaOf))
	}
	probe := newScriptedProber(byReplica)
	// The scripted seam registers replacements lazily, so keep the shared map
	// updated as the scheduler assigns new replicas.
	prober := &Prober{Scheduler: h.scheduler, Probe: probe, Vantage: "periodic-test"}
	return h, probe, prober, replicaOf
}

func (s *scriptedProber) learn(replicas []ActiveReplica) {
	s.mu.Lock()
	for _, replica := range replicas {
		s.byMiner[replica.ReplicaID] = replica.MinerID
	}
	s.mu.Unlock()
}

func activeMinerIDs(scheduler *Scheduler, deploymentID string) []string {
	replicas := scheduler.ActiveReplicas(deploymentID)
	ids := make([]string, 0, len(replicas))
	for _, replica := range replicas {
		ids = append(ids, replica.MinerID)
	}
	return ids
}

func TestProberLeavesHealthyReplicasAlone(t *testing.T) {
	h, probe, prober, replicaOf := newProbedHarness(t)
	defer h.cleanup(t)

	result := prober.Sweep(context.Background())
	if result.Deployments != 1 || len(result.Outcomes) != 3 {
		t.Fatalf("expected one deployment and three outcomes, got %d/%d", result.Deployments, len(result.Outcomes))
	}
	if result.Removed() != 0 || result.Failed() != 0 {
		t.Fatalf("healthy sweep took action: removed=%d failed=%d", result.Removed(), result.Failed())
	}
	for _, outcome := range result.Outcomes {
		if !outcome.Reachable || !outcome.Correct || outcome.Err != nil {
			t.Fatalf("healthy replica reported unhealthy: %+v", outcome)
		}
	}
	// Every replica must be probed by its targeted replica ID; an untargeted
	// probe would let one healthy replica mask its failing peers.
	for minerID, replicaID := range replicaOf {
		if probe.probed(replicaID) != 1 {
			t.Fatalf("miner %s replica %s was not probed exactly once", minerID, replicaID)
		}
	}
	if got := len(activeMinerIDs(h.scheduler, h.request.DeploymentID)); got != 3 {
		t.Fatalf("healthy sweep changed the active set to %d replicas", got)
	}
}

func TestProberEvictsReplicaThatGoesDark(t *testing.T) {
	h, probe, prober, replicaOf := newProbedHarness(t)
	defer h.cleanup(t)
	// Fix the clock so both failures land inside policy's rapid window.
	now := time.Now().UTC()
	prober.Now = func() time.Time { return now }

	probe.setDark("m1")

	first := prober.Sweep(context.Background())
	if first.Removed() != 0 {
		t.Fatalf("a single unreachable observation must not evict: %+v", first.Outcomes)
	}
	if !contains(activeMinerIDs(h.scheduler, h.request.DeploymentID), "m1") {
		t.Fatal("m1 was evicted after one observation")
	}

	now = now.Add(time.Second)
	probe.learn(h.scheduler.ActiveReplicas(h.request.DeploymentID))
	second := prober.Sweep(context.Background())
	if second.Removed() != 1 {
		t.Fatalf("second unreachable observation inside the rapid window must evict: %+v", second.Outcomes)
	}
	var evicted ProbeOutcome
	for _, outcome := range second.Outcomes {
		if outcome.Action.RemoveFromRouting {
			evicted = outcome
		}
	}
	if evicted.MinerID != "m1" || evicted.ReplicaID != replicaOf["m1"] {
		t.Fatalf("wrong replica evicted: %+v", evicted)
	}
	if !evicted.Action.AssignReplacement {
		t.Fatalf("eviction did not request a replacement: %+v", evicted.Action)
	}
	// Unreachability alone must not zero trust: that needs corroboration from a
	// second vantage, which a single in-process driver cannot provide.
	if evicted.Action.TrustZero {
		t.Fatalf("single-vantage unreachability zeroed trust: %+v", evicted.Action)
	}

	active := activeMinerIDs(h.scheduler, h.request.DeploymentID)
	if contains(active, "m1") {
		t.Fatalf("dark miner is still assigned: %v", active)
	}
	if len(active) != 3 || !contains(active, "m4") {
		t.Fatalf("replacement was not assigned from the eligible pool: %v", active)
	}
}

func TestProberEvictsReplicaServingWrongBytes(t *testing.T) {
	h, probe, prober, _ := newProbedHarness(t)
	defer h.cleanup(t)
	probe.setWrong("m2")

	result := prober.Sweep(context.Background())
	if result.Removed() != 1 || result.Failed() != 1 {
		t.Fatalf("a reachable-but-incorrect replica must be evicted at once: %+v", result.Outcomes)
	}
	var evicted ProbeOutcome
	for _, outcome := range result.Outcomes {
		if outcome.Action.RemoveFromRouting {
			evicted = outcome
		}
	}
	if evicted.MinerID != "m2" || !evicted.Reachable || evicted.Correct {
		t.Fatalf("unexpected eviction outcome: %+v", evicted)
	}
	// Serving the wrong bytes for the hidden challenge is an economic fault,
	// so policy zeroes trust immediately.
	if !evicted.Action.TrustZero || !evicted.Action.AssignReplacement {
		t.Fatalf("incorrect serving did not trigger trust-zero and replacement: %+v", evicted.Action)
	}
	if trust := h.scheduler.Ledger.Trust("m2"); trust != 0 {
		t.Fatalf("trust for m2 was not persisted as zero: %v", trust)
	}
	if contains(activeMinerIDs(h.scheduler, h.request.DeploymentID), "m2") {
		t.Fatal("incorrectly serving miner is still assigned")
	}
}

func TestProberSkipsDeactivatingDeployment(t *testing.T) {
	h, _, prober, _ := newProbedHarness(t)
	if err := h.scheduler.DeactivateDeployment(context.Background(), h.request.DeploymentID); err != nil {
		t.Fatal(err)
	}
	result := prober.Sweep(context.Background())
	if result.Deployments != 0 || len(result.Outcomes) != 0 {
		t.Fatalf("a deactivated deployment must not be probed: %+v", result)
	}
}

func TestProberTreatsSchedulerRacesAsStale(t *testing.T) {
	h, _, prober, replicaOf := newProbedHarness(t)
	defer h.cleanup(t)
	// Apply an observation for a replica the scheduler no longer knows about,
	// exactly as a sweep would if the deployment were torn down mid-probe.
	_, err := h.scheduler.HandleHealth(
		context.Background(), "no-such-deployment", replicaOf["m1"], "m1",
		"periodic-test", false, false, false, time.Now().UTC(),
	)
	if !errors.Is(err, ErrUnknownDeployment) || !isStaleObservation(err) {
		t.Fatalf("unknown deployment is not reported as a stale observation: %v", err)
	}
	_, err = h.scheduler.HandleHealth(
		context.Background(), h.request.DeploymentID, "not-a-replica", "m1",
		"periodic-test", false, false, false, time.Now().UTC(),
	)
	if !errors.Is(err, ErrReplicaNotActive) || !isStaleObservation(err) {
		t.Fatalf("stale replica is not reported as a stale observation: %v", err)
	}
	if isStaleObservation(errors.New("cleanup failed")) {
		t.Fatal("an unrelated failure was misreported as stale churn")
	}
	// A real sweep over the untouched deployment must still be clean.
	if result := prober.Sweep(context.Background()); result.Failed() != 0 {
		t.Fatalf("sweep after simulated races reported failures: %+v", result.Outcomes)
	}
}

func TestProberRunSweepsUntilCancelled(t *testing.T) {
	h, _, prober, _ := newProbedHarness(t)
	defer h.cleanup(t)
	prober.Interval = time.Millisecond

	sweeps := make(chan SweepResult, 8)
	prober.OnSweep = func(result SweepResult) {
		select {
		case sweeps <- result:
		default:
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- prober.Run(ctx) }()

	for i := 0; i < 2; i++ {
		select {
		case result := <-sweeps:
			if result.Deployments != 1 {
				t.Errorf("sweep %d saw %d deployments", i, result.Deployments)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("prober did not complete sweep %d", i)
		}
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run returned %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop after cancellation")
	}
}

func TestProberRunRequiresScheduler(t *testing.T) {
	prober := &Prober{}
	if err := prober.Run(context.Background()); err == nil {
		t.Fatal("Run accepted a prober with no scheduler")
	}
	if result := prober.Sweep(context.Background()); result.Deployments != 0 || len(result.Outcomes) != 0 {
		t.Fatalf("Sweep without a scheduler produced work: %+v", result)
	}
}

func TestProberDefaultsAreConsistentWithHealthPolicy(t *testing.T) {
	h, _, prober, _ := newProbedHarness(t)
	defer h.cleanup(t)
	// An interval at or beyond the rapid window resets policy's failure
	// counter on every pass, so a dark replica could never be evicted.
	if window := h.scheduler.monitor().RapidWindow; DefaultProbeInterval >= window {
		t.Fatalf("default interval %v is not below the health rapid window %v", DefaultProbeInterval, window)
	}
	if DefaultProbeTimeout >= DefaultProbeInterval {
		t.Fatalf("default timeout %v does not bound a sweep within the interval %v", DefaultProbeTimeout, DefaultProbeInterval)
	}
	if prober.interval() != DefaultProbeInterval || prober.timeout() != DefaultProbeTimeout {
		t.Fatal("unset interval/timeout did not fall back to the documented defaults")
	}
	if (&Prober{Scheduler: h.scheduler}).vantage() != DefaultProbeVantage {
		t.Fatal("unset vantage did not fall back to the documented default")
	}
}
