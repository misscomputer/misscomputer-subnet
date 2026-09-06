// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/policy"
	"github.com/misscomputer/misscomputer-subnet/pkg/validator"
)

// scriptedProber answers targeted probes from a per-miner script so a sweep can
// be driven deterministically without a network. Miners absent from the script
// serve correctly.
type scriptedProber struct {
	mu         sync.Mutex
	dark       map[string]bool
	wrong      map[string]bool
	incomplete map[string]bool
	edgeStatus map[string]int
	requests   []string
	byMiner    map[string]string
}

func newScriptedProber(replicaToMiner map[string]string) *scriptedProber {
	return &scriptedProber{
		dark: map[string]bool{}, wrong: map[string]bool{}, incomplete: map[string]bool{},
		edgeStatus: map[string]int{}, byMiner: replicaToMiner,
	}
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
	case s.edgeStatus[minerID] != 0:
		// The edge answered on the replica's behalf: a status arrived, but it
		// carries no upstream marker because no replica response was proxied.
		return validator.ProbeResult{
			Vantage: "test", Status: s.edgeStatus[minerID], Correct: false, ServedByReplica: false, ResponseComplete: true, EdgeGenerated: true,
			Error: "edge-generated response",
		}
	case s.incomplete[minerID]:
		return validator.ProbeResult{
			Vantage: "test", Status: 200, Correct: false, ServedByReplica: true,
			ResponseComplete: false, Error: "unexpected EOF",
		}
	case s.wrong[minerID]:
		// A real replica response that carries the wrong bytes: the edge proxied
		// it, so the upstream marker is present.
		return validator.ProbeResult{
			Vantage: "test", Status: 200, Correct: false, ServedByReplica: true, ResponseComplete: true, Error: "incorrect response status=200",
		}
	default:
		return validator.ProbeResult{
			Vantage: "test", Status: 200, Correct: true, ServedByReplica: true, ResponseComplete: true, Latency: 5 * time.Millisecond,
		}
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

func (s *scriptedProber) setEdgeStatus(minerID string, status int) {
	s.mu.Lock()
	s.edgeStatus[minerID] = status
	s.mu.Unlock()
}

func (s *scriptedProber) setIncomplete(minerID string) {
	s.mu.Lock()
	s.incomplete[minerID] = true
	s.mu.Unlock()
}

func (s *scriptedProber) setHealthy(minerID string) {
	s.mu.Lock()
	delete(s.dark, minerID)
	delete(s.wrong, minerID)
	delete(s.incomplete, minerID)
	delete(s.edgeStatus, minerID)
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
	prober := &Prober{Scheduler: h.scheduler, probe: probe, Vantage: "periodic-test"}
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

func newSingletonProbeHarness(t *testing.T) (*schedulerHarness, *scriptedProber, *Prober, []string) {
	t.Helper()
	h := newSchedulerHarness(t, []string{"m1", "m2", "m3", "m4"}, 1)
	deploymentIDs := []string{"singleton-a", "singleton-b", "singleton-c"}
	for index, deploymentID := range deploymentIDs {
		request := h.request
		request.DeploymentID = deploymentID
		request.RequiredMiner = fmt.Sprintf("m%d", index+1)
		if _, err := h.scheduler.Deploy(context.Background(), request); err != nil {
			t.Fatalf("deploy %s: %v", deploymentID, err)
		}
	}
	byReplica := make(map[string]string)
	for _, deploymentID := range deploymentIDs {
		for _, replica := range h.scheduler.ActiveReplicas(deploymentID) {
			byReplica[replica.ReplicaID] = replica.MinerID
		}
	}
	probe := newScriptedProber(byReplica)
	return h, probe, &Prober{Scheduler: h.scheduler, probe: probe, Vantage: "periodic-test"}, deploymentIDs
}

func cleanupDeployments(t *testing.T, scheduler *Scheduler, deploymentIDs []string) {
	t.Helper()
	for _, deploymentID := range deploymentIDs {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		if err := scheduler.DeactivateDeployment(ctx, deploymentID); err != nil {
			cancel()
			t.Fatalf("cleanup %s: %v", deploymentID, err)
		}
		cancel()
	}
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

func TestSweepFailureCountExcludesLifecycleResults(t *testing.T) {
	result := SweepResult{Outcomes: []ProbeOutcome{
		{Cancelled: true},
		{Stale: true},
		{CommonModeSuppressed: true},
	}}
	if failed := result.Failed(); failed != 1 {
		t.Fatalf("failed count = %d, want only the current probe failure", failed)
	}
}

func TestProberEvictsReplicaThatGoesDark(t *testing.T) {
	h, probe, prober, replicaOf := newProbedHarness(t)
	defer h.cleanup(t)
	// Fix the clock so both failures land inside policy's rapid window.
	now := time.Now().UTC()
	prober.Now = func() time.Time { return now }

	// Seed current healthy-peer proof, as an established endpoint loop has
	// before one isolated miner goes dark.
	if baseline := prober.Sweep(context.Background()); baseline.Failed() != 0 {
		t.Fatalf("healthy baseline failed: %+v", baseline.Outcomes)
	}
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

func TestProberRunObservesEveryReplicaUntilCancelled(t *testing.T) {
	h, _, prober, replicaOf := newProbedHarness(t)
	defer h.cleanup(t)
	prober.Interval = 5 * time.Millisecond
	prober.Timeout = time.Millisecond
	prober.CadenceMargin = time.Millisecond

	observed := make(chan ProbeOutcome, 64)
	prober.OnObservation = func(outcome ProbeOutcome) {
		select {
		case observed <- outcome:
		default:
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- prober.Run(ctx) }()

	// Every active endpoint must get its own paced loop, not a share of one
	// sequential pass.
	pending := map[string]struct{}{}
	for _, replicaID := range replicaOf {
		pending[replicaID] = struct{}{}
	}
	deadline := time.After(10 * time.Second)
	for len(pending) > 0 {
		select {
		case outcome := <-observed:
			delete(pending, outcome.ReplicaID)
		case <-deadline:
			t.Fatalf("prober never observed %d of its endpoints", len(pending))
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

func TestProberRefusesCadenceThatCannotEvict(t *testing.T) {
	h, _, _, _ := newProbedHarness(t)
	defer h.cleanup(t)
	window := h.scheduler.monitor().RapidWindow

	// The shipped defaults must satisfy the real inequality, not merely
	// interval < window: a hung replica burns the whole probe timeout before it
	// fails, and the interval is measured from the end of that observation.
	if bound := ProbeCadenceBound(DefaultProbeInterval, DefaultProbeTimeout, DefaultProbeCadenceMargin); bound > window {
		t.Fatalf("default cadence bound %v exceeds the health rapid window %v", bound, window)
	}
	if err := (&Prober{Scheduler: h.scheduler}).Validate(); err != nil {
		t.Fatalf("the shipped defaults were refused: %v", err)
	}

	for name, prober := range map[string]*Prober{
		// The previously shipped pairing: interval alone is below the window, but
		// timeout + interval is not, so a hung replica's two failures always land
		// further apart than the window and it is never evicted.
		"timeout plus interval exceeds the window": {Scheduler: h.scheduler, Interval: 10 * time.Second, Timeout: 5 * time.Second},
		"interval alone exceeds the window":        {Scheduler: h.scheduler, Interval: 20 * time.Second, Timeout: time.Second},
		"timeout is not shorter than interval":     {Scheduler: h.scheduler, Interval: time.Second, Timeout: time.Second},
		// Without a deadline the prober owns, a hung replica's failure gap is
		// whatever the Validator's client allows, so nothing can be guaranteed.
		"probe deadline disabled": {Scheduler: h.scheduler, Interval: time.Second, Timeout: -time.Second},
	} {
		t.Run(name, func(t *testing.T) {
			if err := prober.Validate(); !errors.Is(err, ErrProbeCadence) {
				t.Fatalf("Validate accepted a cadence that cannot evict: %v", err)
			}
			if err := prober.Run(context.Background()); !errors.Is(err, ErrProbeCadence) {
				t.Fatalf("Run started a prober that can never evict: %v", err)
			}
		})
	}
}

func TestProbeCadenceBoundRejectsOverflowAndAcceptsExactBoundary(t *testing.T) {
	h, _, _, _ := newProbedHarness(t)
	defer h.cleanup(t)
	interval, err := time.ParseDuration("2000000h")
	if err != nil {
		t.Fatal(err)
	}
	timeout, err := time.ParseDuration("1000000h")
	if err != nil {
		t.Fatal(err)
	}
	malicious := &Prober{
		Scheduler: h.scheduler, Interval: interval, Timeout: timeout,
		CadenceMargin: 2 * time.Second,
	}
	if err := malicious.Validate(); !errors.Is(err, ErrProbeCadence) {
		t.Fatalf("overflowing cadence was not refused: bound=%v err=%v", ProbeCadenceBound(interval, timeout, 2*time.Second), err)
	}
	if bound := ProbeCadenceBound(interval, timeout, 2*time.Second); bound != time.Duration(1<<63-1) {
		t.Fatalf("overflowing public bound did not saturate safely: %v", bound)
	}

	maximum := time.Duration(1<<63 - 1)
	h.scheduler.monitor().RapidWindow = maximum
	boundary := &Prober{
		Scheduler: h.scheduler, Interval: maximum - 3, Timeout: 1,
		CadenceMargin: 2,
	}
	if bound := ProbeCadenceBound(boundary.Interval, boundary.Timeout, boundary.CadenceMargin); bound != maximum {
		t.Fatalf("exact non-overflow boundary = %v, want %v", bound, maximum)
	}
	if err := boundary.Validate(); err != nil {
		t.Fatalf("exact valid duration boundary was refused: %v", err)
	}
}

func TestProberDefaultsAreConsistentWithHealthPolicy(t *testing.T) {
	h, _, prober, _ := newProbedHarness(t)
	defer h.cleanup(t)
	if DefaultProbeTimeout >= DefaultProbeInterval {
		t.Fatalf("default timeout %v is not shorter than the interval %v", DefaultProbeTimeout, DefaultProbeInterval)
	}
	if prober.interval() != DefaultProbeInterval || prober.timeout() != DefaultProbeTimeout {
		t.Fatal("unset interval/timeout did not fall back to the documented defaults")
	}
	if prober.cadenceMargin() != DefaultProbeCadenceMargin {
		t.Fatal("unset cadence margin did not fall back to the documented default")
	}
	if (&Prober{Scheduler: h.scheduler}).vantage() != DefaultProbeVantage {
		t.Fatal("unset vantage did not fall back to the documented default")
	}
}

func TestProberTreatsEdgeGeneratedErrorsAsUnreachable(t *testing.T) {
	// Each of these statuses is produced by the edge itself when the miner is
	// the thing that is down or unroutable. Reading them as "the replica
	// answered with the wrong bytes" would hand an offline miner the permanent,
	// single-vantage trust-zero reserved for serving forged content — and a
	// probe-token misconfiguration would inflict it on every miner at once.
	for name, status := range map[string]int{
		"dead backend behind the proxy": http.StatusBadGateway,
		"replica dropped from routes":   http.StatusNotFound,
		"probe token misconfigured":     http.StatusForbidden,
		"nothing healthy on the host":   http.StatusServiceUnavailable,
	} {
		t.Run(name, func(t *testing.T) {
			h, probe, prober, _ := newProbedHarness(t)
			defer h.cleanup(t)
			now := time.Now().UTC()
			prober.Now = func() time.Time { return now }
			if baseline := prober.Sweep(context.Background()); baseline.Failed() != 0 {
				t.Fatalf("healthy baseline failed: %+v", baseline.Outcomes)
			}
			probe.setEdgeStatus("m1", status)

			first := prober.Sweep(context.Background())
			var observed ProbeOutcome
			for _, outcome := range first.Outcomes {
				if outcome.MinerID == "m1" {
					observed = outcome
				}
			}
			if observed.Status != status {
				t.Fatalf("edge status was not carried through: %+v", observed)
			}
			if observed.Reachable {
				t.Fatalf("an edge-generated status was reported as a replica response: %+v", observed)
			}
			if !observed.EdgeGenerated {
				t.Fatalf("an edge-generated status was not flagged as such: %+v", observed)
			}
			if observed.Action.TrustZero || observed.Action.RemoveFromRouting {
				t.Fatalf("one edge-generated status took immediate action: %+v", observed.Action)
			}
			if trust := h.scheduler.Ledger.Trust("m1"); trust == 0 {
				t.Fatal("an edge-generated status zeroed the miner's trust")
			}

			// It is still a liveness failure, so the ordinary two-failures-inside-
			// the-rapid-window eviction must still reach it — without trust-zero,
			// which needs corroboration this single vantage cannot give.
			now = now.Add(time.Second)
			probe.learn(h.scheduler.ActiveReplicas(h.request.DeploymentID))
			second := prober.Sweep(context.Background())
			if second.Removed() != 1 {
				t.Fatalf("a repeatedly unreachable replica was not evicted: %+v", second.Outcomes)
			}
			for _, outcome := range second.Outcomes {
				if outcome.Action.RemoveFromRouting && outcome.Action.TrustZero {
					t.Fatalf("eviction for an edge-generated status zeroed trust: %+v", outcome)
				}
			}
			if trust := h.scheduler.Ledger.Trust("m1"); trust == 0 {
				t.Fatal("eviction for an edge-generated status zeroed the miner's trust")
			}
			if contains(activeMinerIDs(h.scheduler, h.request.DeploymentID), "m1") {
				t.Fatal("unreachable miner kept its assignment")
			}
		})
	}
}

func TestProberSuppressesSubnetWideCommonModeFailureAndRecovers(t *testing.T) {
	for name, failAll := range map[string]func(*scriptedProber){
		"probe token or edge failure": func(probe *scriptedProber) {
			for _, minerID := range []string{"m1", "m2", "m3"} {
				probe.setEdgeStatus(minerID, http.StatusForbidden)
			}
		},
		"transport failure": func(probe *scriptedProber) {
			for _, minerID := range []string{"m1", "m2", "m3"} {
				probe.setDark(minerID)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			h, probe, prober, _ := newProbedHarness(t)
			deactivated := false
			defer func() {
				if !deactivated {
					h.cleanup(t)
				}
			}()
			now := time.Now().UTC()
			prober.Now = func() time.Time { return now }
			if baseline := prober.Sweep(context.Background()); baseline.Failed() != 0 {
				t.Fatalf("healthy baseline failed: %+v", baseline.Outcomes)
			}
			failAll(probe)

			suppressed := 0
			for range 3 {
				now = now.Add(time.Second)
				result := prober.Sweep(context.Background())
				if result.Removed() != 0 {
					t.Fatalf("common-mode failure evicted routes: %+v", result.Outcomes)
				}
				for _, outcome := range result.Outcomes {
					if outcome.CommonModeSuppressed {
						suppressed++
					}
				}
			}
			if suppressed == 0 {
				t.Fatal("common-mode failures were not surfaced as suppressed")
			}
			if active := activeMinerIDs(h.scheduler, h.request.DeploymentID); len(active) != 3 || !contains(active, "m1") || !contains(active, "m2") || !contains(active, "m3") {
				t.Fatalf("common-mode failure changed active routes: %v", active)
			}
			if h.miners["m4"].Assignments() != 0 {
				t.Fatalf("common-mode failure consumed replacement pool: m4 assignments=%d", h.miners["m4"].Assignments())
			}
			for _, minerID := range []string{"m1", "m2", "m3", "m4"} {
				if trust := h.scheduler.Ledger.Trust(minerID); trust == 0 {
					t.Fatalf("common-mode failure trust-zeroed %s", minerID)
				}
			}

			// The edge recovers for two peers while m1 remains genuinely down.
			// Their fresh complete responses re-arm only the ordinary isolated-
			// endpoint path; m1 is then evicted and the untouched spare replaces it.
			probe.setHealthy("m2")
			probe.setHealthy("m3")
			for attempt := 0; attempt < 3 && contains(activeMinerIDs(h.scheduler, h.request.DeploymentID), "m1"); attempt++ {
				now = now.Add(time.Second)
				probe.learn(h.scheduler.ActiveReplicas(h.request.DeploymentID))
				prober.Sweep(context.Background())
			}
			active := activeMinerIDs(h.scheduler, h.request.DeploymentID)
			if contains(active, "m1") || len(active) != 3 || !contains(active, "m4") {
				t.Fatalf("isolated failure did not recover redundancy: %v", active)
			}
			if h.scheduler.Ledger.Trust("m1") == 0 || h.scheduler.Ledger.Trust("m4") == 0 {
				t.Fatal("unattributable liveness failure changed economic trust")
			}
			h.cleanup(t)
			deactivated = true
		})
	}
}

func TestProberSuppressesCommonModeFailureWithoutHealthyBaseline(t *testing.T) {
	h, probe, prober, _ := newProbedHarness(t)
	defer h.cleanup(t)
	for _, minerID := range []string{"m1", "m2", "m3"} {
		probe.setDark(minerID)
	}
	for round := 0; round < 3; round++ {
		result := prober.Sweep(context.Background())
		if result.Removed() != 0 {
			t.Fatalf("startup common-mode outage evicted routes in round %d: %+v", round+1, result.Outcomes)
		}
		for _, outcome := range result.Outcomes {
			if !outcome.CommonModeSuppressed || outcome.Action != (policy.Action{}) {
				t.Fatalf("startup outage entered miner policy: %+v", outcome)
			}
		}
	}
	if active := activeMinerIDs(h.scheduler, h.request.DeploymentID); len(active) != 3 {
		t.Fatalf("startup outage changed active set: %v", active)
	}
	if h.miners["m4"].Assignments() != 0 {
		t.Fatal("startup outage consumed a clean replacement")
	}
}

func TestCorroborationPermitCannotBeDoubleSpentBeforeCommit(t *testing.T) {
	const deploymentID = "permit-race"
	target := ActiveReplica{MinerID: "m1", ReplicaID: "r1", EndpointID: "e1"}
	peer := ActiveReplica{MinerID: "m2", ReplicaID: "r2", EndpointID: "e2"}
	peers := probePeerSet{deployment: []ActiveReplica{target, peer}, global: []ActiveReplica{target, peer}}
	corroboration := probeCorroboration{}
	failureAt := time.Now().UTC()
	// This success postdates failure A's timestamp but arrives before A reserves
	// it, which is the interleaving that defeats a timestamp fence alone.
	corroboration.recordSuccess(deploymentID, peer.EndpointID, peers, failureAt.Add(time.Second), 1)
	permitA, allowed := corroboration.unreachablePermit(deploymentID, target.EndpointID, peers)
	if !allowed || permitA == nil {
		t.Fatal("first failure could not reserve fresh peer evidence")
	}
	peers.targetHealth = policy.ObservationSnapshot{Version: 1, LastFailure: failureAt}
	if permitB, allowed := corroboration.unreachablePermit(deploymentID, target.EndpointID, peers); allowed || permitB != nil {
		t.Fatal("concurrent failure double-spent a reserved peer success")
	}
	corroboration.releasePermit(deploymentID, target.EndpointID, permitA)
	permitB, allowed := corroboration.unreachablePermit(deploymentID, target.EndpointID, peers)
	if !allowed || permitB == nil {
		t.Fatal("rolled-back permit did not release uncommitted peer evidence")
	}
	corroboration.recordApplied(deploymentID, target.EndpointID, peers, permitB, 2)
}

func TestDelayedPeerSnapshotCannotPruneReplacementEvidence(t *testing.T) {
	const deploymentID = "replacement-race"
	a := ActiveReplica{MinerID: "ma", ReplicaID: "ra", EndpointID: "ea"}
	b := ActiveReplica{MinerID: "mb", ReplicaID: "rb", EndpointID: "eb"}
	retired := ActiveReplica{MinerID: "mc", ReplicaID: "rc", EndpointID: "ec"}
	replacement := ActiveReplica{MinerID: "md", ReplicaID: "rd", EndpointID: "ed"}
	oldPeers := probePeerSet{
		deployment:    []ActiveReplica{a, b, retired},
		global:        []ActiveReplica{a, b, retired},
		topologyEpoch: 1,
	}
	newPeers := probePeerSet{
		deployment:    []ActiveReplica{a, b, replacement},
		global:        []ActiveReplica{a, b, replacement},
		topologyEpoch: 2,
	}
	corroboration := probeCorroboration{}
	now := time.Now().UTC()
	corroboration.recordSuccess(deploymentID, a.EndpointID, oldPeers, now, 1)
	corroboration.recordSuccess(deploymentID, b.EndpointID, oldPeers, now, 1)

	permit, allowed := corroboration.unreachablePermit(deploymentID, replacement.EndpointID, newPeers)
	if !allowed || permit == nil {
		t.Fatal("replacement could not reserve fresh peer evidence")
	}
	// The retired endpoint's probe and a reconciliation were both snapshotted
	// before replacement. Neither may erase the new endpoint's pending permit.
	corroboration.recordSuccess(deploymentID, retired.EndpointID, oldPeers, now.Add(time.Second), 1)
	corroboration.reconcile([]probeTarget{{deploymentID: deploymentID, replicas: oldPeers.deployment}}, oldPeers.topologyEpoch)
	corroboration.recordApplied(deploymentID, replacement.EndpointID, newPeers, permit, 1)

	newPeers.targetHealth = policy.ObservationSnapshot{Version: 1, LastFailure: now.Add(2 * time.Second)}
	if reused, allowed := corroboration.unreachablePermit(deploymentID, replacement.EndpointID, newPeers); allowed || reused != nil {
		t.Fatal("stale peer snapshot allowed replacement to reuse already-consumed successes")
	}
}

func TestCurrentReconcilePreservesPermitAcrossWitnessReplacement(t *testing.T) {
	const deploymentID = "witness-replacement-race"
	target := ActiveReplica{MinerID: "ma", ReplicaID: "ra", EndpointID: "ea"}
	retiredWitness := ActiveReplica{MinerID: "mb", ReplicaID: "rb", EndpointID: "eb"}
	survivingWitness := ActiveReplica{MinerID: "mc", ReplicaID: "rc", EndpointID: "ec"}
	newWitness := ActiveReplica{MinerID: "md", ReplicaID: "rd", EndpointID: "ed"}
	oldPeers := probePeerSet{
		deployment:    []ActiveReplica{target, retiredWitness, survivingWitness},
		global:        []ActiveReplica{target, retiredWitness, survivingWitness},
		topologyEpoch: 1,
	}
	newPeers := probePeerSet{
		deployment:    []ActiveReplica{target, survivingWitness, newWitness},
		global:        []ActiveReplica{target, survivingWitness, newWitness},
		topologyEpoch: 2,
	}
	corroboration := probeCorroboration{}
	now := time.Now().UTC()
	corroboration.recordSuccess(deploymentID, retiredWitness.EndpointID, oldPeers, now, 1)
	corroboration.recordSuccess(deploymentID, survivingWitness.EndpointID, oldPeers, now, 1)
	permit, allowed := corroboration.unreachablePermit(deploymentID, target.EndpointID, oldPeers)
	if !allowed || permit == nil {
		t.Fatal("target could not reserve witness evidence")
	}

	// A witness is replaced while the target's health mutation is in flight.
	// Current topology GC may discard retired endpoint history, but the exact
	// target permit must survive until its eventual commit or rollback.
	corroboration.reconcile([]probeTarget{{deploymentID: deploymentID, replicas: newPeers.deployment}}, newPeers.topologyEpoch)
	corroboration.recordSuccess(deploymentID, newWitness.EndpointID, newPeers, now.Add(time.Second), 1)
	corroboration.recordApplied(deploymentID, target.EndpointID, oldPeers, permit, 1)

	newPeers.targetHealth = policy.ObservationSnapshot{Version: 1, LastFailure: now.Add(2 * time.Second)}
	if reused, allowed := corroboration.unreachablePermit(deploymentID, target.EndpointID, newPeers); allowed || reused != nil {
		t.Fatal("witness replacement allowed surviving success evidence to be reused")
	}
}

func TestCorroborationDomainChangeRequiresPostFailureSuccess(t *testing.T) {
	const deploymentID = "domain-change"
	target := ActiveReplica{MinerID: "ma", ReplicaID: "ra", EndpointID: "ea"}
	localB := ActiveReplica{MinerID: "mb", ReplicaID: "rb", EndpointID: "eb"}
	localC := ActiveReplica{MinerID: "mc", ReplicaID: "rc", EndpointID: "ec"}
	globalD := ActiveReplica{MinerID: "md", ReplicaID: "rd", EndpointID: "ed"}
	globalE := ActiveReplica{MinerID: "me", ReplicaID: "re", EndpointID: "ee"}
	oldGlobal := []ActiveReplica{target, localB, localC, globalD, globalE}
	localPeers := probePeerSet{
		deployment:    []ActiveReplica{target, localB, localC},
		global:        oldGlobal,
		topologyEpoch: 1,
	}
	otherPeers := probePeerSet{
		deployment:    []ActiveReplica{globalD, globalE},
		global:        oldGlobal,
		topologyEpoch: 1,
	}
	corroboration := probeCorroboration{}
	failureAt := time.Now().UTC()
	baselineAt := failureAt.Add(-time.Second)
	for _, peer := range []ActiveReplica{localB, localC} {
		corroboration.recordSuccess(deploymentID, peer.EndpointID, localPeers, baselineAt, 1)
	}
	for _, peer := range []ActiveReplica{globalD, globalE} {
		corroboration.recordSuccess("other", peer.EndpointID, otherPeers, baselineAt, 1)
	}
	permit, allowed := corroboration.unreachablePermit(deploymentID, target.EndpointID, localPeers)
	if !allowed || permit == nil || permit.global {
		t.Fatal("local failure could not reserve deployment evidence")
	}
	corroboration.recordApplied(deploymentID, target.EndpointID, localPeers, permit, 1)

	// The deployment becomes a singleton. Old successes from unrelated global
	// peers predate the first failure and must not be accepted as fresh evidence
	// for a destructive second failure merely because the evidence domain changed.
	singletonPeers := probePeerSet{
		deployment:    []ActiveReplica{target},
		global:        []ActiveReplica{target, globalD, globalE},
		targetHealth:  policy.ObservationSnapshot{Version: 1, LastFailure: failureAt},
		topologyEpoch: 2,
	}
	if reused, allowed := corroboration.unreachablePermit(deploymentID, target.EndpointID, singletonPeers); allowed || reused != nil {
		t.Fatal("domain change reused global successes that predated the first failure")
	}
	corroboration.recordSuccess("other", globalD.EndpointID, singletonPeers, failureAt.Add(time.Second), 2)
	corroboration.recordSuccess("other", globalE.EndpointID, singletonPeers, failureAt.Add(time.Second), 2)
	if fresh, allowed := corroboration.unreachablePermit(deploymentID, target.EndpointID, singletonPeers); !allowed || fresh == nil || !fresh.global {
		t.Fatal("fresh post-failure global evidence did not re-arm singleton eviction")
	}
}

func TestDelayedSuccessCannotRegressCorroborationVersion(t *testing.T) {
	state := &deploymentCorroboration{}
	newerAt := time.Now().UTC()
	state.recordAppliedSuccess("endpoint", newerAt, 2)
	newer := state.successes["endpoint"]
	state.recordAppliedSuccess("endpoint", newerAt.Add(-time.Second), 1)
	if state.versions["endpoint"] != 2 || state.successes["endpoint"] != newer {
		t.Fatalf("delayed success regressed corroboration: version=%d success=%+v want=%+v", state.versions["endpoint"], state.successes["endpoint"], newer)
	}
}

func TestProberCommonModeFailureCannotCombineWithNewerExternalFailures(t *testing.T) {
	h, probe, prober, _ := newProbedHarness(t)
	deactivated := false
	defer func() {
		if !deactivated {
			h.cleanup(t)
		}
	}()
	now := time.Now().UTC()
	prober.Now = func() time.Time { return now }
	if baseline := prober.Sweep(context.Background()); baseline.Failed() != 0 {
		t.Fatalf("healthy baseline failed: %+v", baseline.Outcomes)
	}

	// Seed one newer failure from a second vantage for every endpoint. If the
	// prober reused its older healthy baseline, one shared edge failure would
	// now satisfy both removal and multi-vantage trust-zero thresholds.
	now = now.Add(time.Second)
	for _, replica := range h.scheduler.ActiveReplicas(h.request.DeploymentID) {
		action, err := h.scheduler.HandleHealth(
			context.Background(), h.request.DeploymentID, replica.ReplicaID, replica.MinerID,
			"external-test", false, false, false, now,
		)
		if err != nil || action != (policy.Action{}) {
			t.Fatalf("seed external failure for %s: action=%+v err=%v", replica.MinerID, action, err)
		}
		probe.setEdgeStatus(replica.MinerID, http.StatusForbidden)
	}
	now = now.Add(time.Second)
	for round := 0; round < 2; round++ {
		result := prober.Sweep(context.Background())
		if result.Removed() != 0 {
			t.Fatalf("shared failure combined with external history in round %d: %+v", round+1, result.Outcomes)
		}
		for _, outcome := range result.Outcomes {
			if !outcome.CommonModeSuppressed || outcome.Action != (policy.Action{}) {
				t.Fatalf("stale baseline entered miner policy: %+v", outcome)
			}
		}
		now = now.Add(time.Second)
	}
	for _, minerID := range []string{"m1", "m2", "m3"} {
		if trust := h.scheduler.Ledger.Trust(minerID); trust == 0 {
			t.Fatalf("shared failure trust-zeroed %s", minerID)
		}
	}
	h.cleanup(t)
	deactivated = true
}

func TestExternalFailureCannotCompletePeriodicCommonModeCascade(t *testing.T) {
	h, probe, prober, _ := newProbedHarness(t)
	deactivated := false
	defer func() {
		if !deactivated {
			h.cleanup(t)
		}
	}()
	now := time.Now().UTC()
	prober.Now = func() time.Time { return now }
	if baseline := prober.Sweep(context.Background()); baseline.Failed() != 0 {
		t.Fatalf("healthy baseline failed: %+v", baseline.Outcomes)
	}
	for _, replica := range h.scheduler.ActiveReplicas(h.request.DeploymentID) {
		probe.setEdgeStatus(replica.MinerID, http.StatusForbidden)
	}
	now = now.Add(time.Second)
	if first := prober.Sweep(context.Background()); first.Removed() != 0 {
		t.Fatalf("first shared periodic failure removed routes: %+v", first.Outcomes)
	}

	// External ingress races the in-process loops in production. Its first
	// report must not complete the periodic source's rapid-failure pair.
	now = now.Add(time.Second)
	for _, replica := range h.scheduler.ActiveReplicas(h.request.DeploymentID) {
		action, err := h.scheduler.HandleHealth(
			context.Background(), h.request.DeploymentID, replica.ReplicaID, replica.MinerID,
			"external-test", false, false, false, now,
		)
		if err != nil || action != (policy.Action{}) {
			t.Fatalf("external failure combined with periodic history for %s: action=%+v err=%v", replica.MinerID, action, err)
		}
	}
	if active := activeMinerIDs(h.scheduler, h.request.DeploymentID); len(active) != 3 {
		t.Fatalf("cross-source shared failure changed active routes: %v", active)
	}
	if h.miners["m4"].Assignments() != 0 {
		t.Fatalf("cross-source shared failure consumed replacement pool: %d", h.miners["m4"].Assignments())
	}
	for _, minerID := range []string{"m1", "m2", "m3"} {
		if trust := h.scheduler.Ledger.Trust(minerID); trust == 0 {
			t.Fatalf("cross-source shared failure trust-zeroed %s", minerID)
		}
	}
	h.cleanup(t)
	deactivated = true
}

func TestProberSuppressesSubnetWideFailureAcrossSingletonDeployments(t *testing.T) {
	for name, failAll := range map[string]func(*scriptedProber){
		"edge": func(probe *scriptedProber) {
			for _, minerID := range []string{"m1", "m2", "m3"} {
				probe.setEdgeStatus(minerID, http.StatusForbidden)
			}
		},
		"transport": func(probe *scriptedProber) {
			for _, minerID := range []string{"m1", "m2", "m3"} {
				probe.setDark(minerID)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			h, probe, prober, deploymentIDs := newSingletonProbeHarness(t)
			deactivated := false
			defer func() {
				if !deactivated {
					cleanupDeployments(t, h.scheduler, deploymentIDs)
				}
			}()
			if baseline := prober.Sweep(context.Background()); baseline.Failed() != 0 {
				t.Fatalf("healthy baseline failed: %+v", baseline.Outcomes)
			}
			failAll(probe)
			for round := 0; round < 3; round++ {
				result := prober.Sweep(context.Background())
				if result.Removed() != 0 {
					t.Fatalf("shared singleton outage removed routes in round %d: %+v", round+1, result.Outcomes)
				}
			}
			for index, deploymentID := range deploymentIDs {
				active := activeMinerIDs(h.scheduler, deploymentID)
				want := fmt.Sprintf("m%d", index+1)
				if len(active) != 1 || active[0] != want {
					t.Fatalf("shared outage changed %s active set: %v", deploymentID, active)
				}
				if trust := h.scheduler.Ledger.Trust(want); trust == 0 {
					t.Fatalf("shared outage trust-zeroed %s", want)
				}
			}
			if h.miners["m4"].Assignments() != 0 {
				t.Fatalf("shared singleton outage consumed spare: assignments=%d", h.miners["m4"].Assignments())
			}
			cleanupDeployments(t, h.scheduler, deploymentIDs)
			deactivated = true
		})
	}
}

func TestProberEvictsIsolatedFailureAcrossSingletonDeployments(t *testing.T) {
	h, probe, prober, deploymentIDs := newSingletonProbeHarness(t)
	deactivated := false
	defer func() {
		if !deactivated {
			cleanupDeployments(t, h.scheduler, deploymentIDs)
		}
	}()
	if baseline := prober.Sweep(context.Background()); baseline.Failed() != 0 {
		t.Fatalf("healthy baseline failed: %+v", baseline.Outcomes)
	}
	probe.setDark("m1")
	for round := 0; round < 3 && contains(activeMinerIDs(h.scheduler, deploymentIDs[0]), "m1"); round++ {
		prober.Sweep(context.Background())
	}
	active := activeMinerIDs(h.scheduler, deploymentIDs[0])
	if len(active) != 1 || contains(active, "m1") {
		t.Fatalf("healthy singleton witnesses did not isolate and replace m1: %v", active)
	}
	if trust := h.scheduler.Ledger.Trust("m1"); trust == 0 {
		t.Fatal("isolated liveness eviction became economic guilt")
	}
	cleanupDeployments(t, h.scheduler, deploymentIDs)
	deactivated = true
}

func TestProberPreservesSingleEndpointEvictionContract(t *testing.T) {
	h := newSchedulerHarness(t, []string{"m1", "m2"}, 1)
	if _, err := h.scheduler.Deploy(context.Background(), h.request); err != nil {
		t.Fatal(err)
	}
	deactivated := false
	defer func() {
		if !deactivated {
			h.cleanup(t)
		}
	}()
	replica := h.scheduler.ActiveReplicas(h.request.DeploymentID)[0]
	probe := newScriptedProber(map[string]string{replica.ReplicaID: replica.MinerID})
	prober := &Prober{Scheduler: h.scheduler, probe: probe, Vantage: "periodic-test"}
	if baseline := prober.Sweep(context.Background()); baseline.Failed() != 0 {
		t.Fatalf("healthy baseline failed: %+v", baseline.Outcomes)
	}
	probe.setDark("m1")
	first := prober.Sweep(context.Background())
	second := prober.Sweep(context.Background())
	if first.Removed() != 0 || second.Removed() != 1 {
		t.Fatalf("single endpoint no longer follows two-failure eviction: first=%+v second=%+v", first.Outcomes, second.Outcomes)
	}
	active := activeMinerIDs(h.scheduler, h.request.DeploymentID)
	if len(active) != 1 || contains(active, "m1") {
		t.Fatalf("single isolated endpoint was not replaced: %v", active)
	}
	h.cleanup(t)
	deactivated = true
}

func TestSingleEndpointSharedPathFailureEvictsWithoutEconomicGuiltOrPoolLoss(t *testing.T) {
	h := newSchedulerHarness(t, []string{"m1", "m2"}, 1)
	if _, err := h.scheduler.Deploy(context.Background(), h.request); err != nil {
		t.Fatal(err)
	}
	deactivated := false
	defer func() {
		if !deactivated {
			h.cleanup(t)
		}
	}()
	replica := h.scheduler.ActiveReplicas(h.request.DeploymentID)[0]
	probe := newScriptedProber(map[string]string{replica.ReplicaID: replica.MinerID})
	prober := &Prober{Scheduler: h.scheduler, probe: probe, Vantage: "periodic-test"}
	if baseline := prober.Sweep(context.Background()); baseline.Failed() != 0 {
		t.Fatalf("healthy baseline failed: %+v", baseline.Outcomes)
	}
	if action, err := h.scheduler.HandleHealth(
		context.Background(), h.request.DeploymentID, replica.ReplicaID, replica.MinerID,
		"external-test", false, false, false, time.Now().UTC(),
	); err != nil || action != (policy.Action{}) {
		t.Fatalf("seed external failure: action=%+v err=%v", action, err)
	}
	originalURL := h.scheduler.Validator.EdgeURL
	h.scheduler.Validator.EdgeURL = "http://127.0.0.1:1"
	h.scheduler.Validator.Client = &http.Client{Timeout: 100 * time.Millisecond}
	probe.setEdgeStatus(replica.MinerID, http.StatusForbidden)
	first := prober.Sweep(context.Background())
	second := prober.Sweep(context.Background())
	if first.Removed() != 0 || second.Removed() != 1 || len(second.Outcomes) != 1 || !errors.Is(second.Outcomes[0].Err, ErrAcceptanceInconclusive) {
		t.Fatalf("single route did not fail closed through broken replacement path: first=%+v second=%+v", first.Outcomes, second.Outcomes)
	}
	if trust := h.scheduler.Ledger.Trust(replica.MinerID); trust == 0 {
		t.Fatal("single shared-path fault created economic guilt")
	}
	if trust := h.scheduler.Ledger.Trust("m2"); trust == 0 || !h.scheduler.Ledger.Eligible("m2") {
		t.Fatalf("broken replacement path burned clean spare: trust=%v eligible=%v", trust, h.scheduler.Ledger.Eligible("m2"))
	}
	if active := h.scheduler.ActiveReplicas(h.request.DeploymentID); len(active) != 0 {
		t.Fatalf("single route remained active despite repeated liveness failures: %+v", active)
	}
	h.scheduler.Validator.EdgeURL = originalURL
	h.scheduler.Validator.Client = nil
	h.cleanup(t)
	deactivated = true
}

func TestSingleEndpointExternalSuccessDoesNotFreezeLaterIsolatedEviction(t *testing.T) {
	h := newSchedulerHarness(t, []string{"m1", "m2"}, 1)
	if _, err := h.scheduler.Deploy(context.Background(), h.request); err != nil {
		t.Fatal(err)
	}
	deactivated := false
	defer func() {
		if !deactivated {
			h.cleanup(t)
		}
	}()
	replica := h.scheduler.ActiveReplicas(h.request.DeploymentID)[0]
	probe := newScriptedProber(map[string]string{replica.ReplicaID: replica.MinerID})
	prober := &Prober{Scheduler: h.scheduler, probe: probe, Vantage: "periodic-test"}
	if baseline := prober.Sweep(context.Background()); baseline.Failed() != 0 {
		t.Fatalf("healthy baseline failed: %+v", baseline.Outcomes)
	}
	if action, err := h.scheduler.HandleHealth(
		context.Background(), h.request.DeploymentID, replica.ReplicaID, replica.MinerID,
		"external-test", true, true, false, time.Now().UTC(),
	); err != nil || action != (policy.Action{}) {
		t.Fatalf("external success: action=%+v err=%v", action, err)
	}
	probe.setDark(replica.MinerID)
	first := prober.Sweep(context.Background())
	second := prober.Sweep(context.Background())
	if first.Removed() != 0 || second.Removed() != 1 {
		t.Fatalf("external success froze later isolated failure: first=%+v second=%+v", first.Outcomes, second.Outcomes)
	}
	if active := activeMinerIDs(h.scheduler, h.request.DeploymentID); len(active) != 1 || contains(active, replica.MinerID) {
		t.Fatalf("isolated failed endpoint was not replaced: %v", active)
	}
	if trust := h.scheduler.Ledger.Trust(replica.MinerID); trust == 0 {
		t.Fatal("internal liveness evidence became economic guilt")
	}
	h.cleanup(t)
	deactivated = true
}

func TestProberReconciliationHalfOpensWhenEveryRouteIsAbsent(t *testing.T) {
	h := newSchedulerHarness(t, []string{"m1", "m2"}, 1)
	if _, err := h.scheduler.Deploy(context.Background(), h.request); err != nil {
		t.Fatal(err)
	}
	deactivated := false
	defer func() {
		if !deactivated {
			h.cleanup(t)
		}
	}()
	replica := h.scheduler.ActiveReplicas(h.request.DeploymentID)[0]
	originalURL := h.scheduler.Validator.EdgeURL
	h.scheduler.Validator.EdgeURL = "http://127.0.0.1:1"
	h.scheduler.Validator.Client = &http.Client{Timeout: 100 * time.Millisecond}
	action, err := h.scheduler.HandleHealth(
		context.Background(), h.request.DeploymentID, replica.ReplicaID, replica.MinerID,
		"external-test", true, false, false, time.Now().UTC(),
	)
	if !errors.Is(err, ErrAcceptanceInconclusive) || !action.RemoveFromRouting || len(h.scheduler.ActiveReplicas(h.request.DeploymentID)) != 0 {
		t.Fatalf("zero-route setup: action=%+v active=%v err=%v", action, activeMinerIDs(h.scheduler, h.request.DeploymentID), err)
	}
	h.scheduler.Validator.EdgeURL = originalURL
	h.scheduler.Validator.Client = nil
	prober := &Prober{Scheduler: h.scheduler}
	ctx, cancel := context.WithCancel(context.Background())
	loops := make(map[string]*endpointLoop)
	prober.reconcile(ctx, loops)
	cancel()
	for _, loop := range loops {
		loop.cancel()
		<-loop.done
	}
	active := activeMinerIDs(h.scheduler, h.request.DeploymentID)
	if len(active) != 1 || contains(active, "m1") {
		t.Fatalf("half-open recovery did not restore one clean route: %v", active)
	}
	if trust := h.scheduler.Ledger.Trust(active[0]); trust == 0 {
		t.Fatal("half-open recovery trust-zeroed the clean candidate")
	}
	h.cleanup(t)
	deactivated = true
}

func TestProberTreatsMidBodyErrorAsUnreachableNotWrongContent(t *testing.T) {
	h, probe, prober, _ := newProbedHarness(t)
	defer h.cleanup(t)
	now := time.Now().UTC()
	prober.Now = func() time.Time { return now }
	if baseline := prober.Sweep(context.Background()); baseline.Failed() != 0 {
		t.Fatalf("healthy baseline failed: %+v", baseline.Outcomes)
	}
	probe.setIncomplete("m1")
	first := prober.Sweep(context.Background())
	var observed ProbeOutcome
	for _, outcome := range first.Outcomes {
		if outcome.MinerID == "m1" {
			observed = outcome
		}
	}
	if observed.Reachable || observed.ResponseComplete || observed.EdgeGenerated || observed.Action.TrustZero || observed.Action.RemoveFromRouting {
		t.Fatalf("mid-body error was attributed as wrong content: %+v", observed)
	}
	if trust := h.scheduler.Ledger.Trust("m1"); trust == 0 {
		t.Fatal("mid-body transport error immediately zeroed trust")
	}
	now = now.Add(time.Second)
	second := prober.Sweep(context.Background())
	if second.Removed() != 1 {
		t.Fatalf("repeated isolated incomplete responses did not follow liveness policy: %+v", second.Outcomes)
	}
	if trust := h.scheduler.Ledger.Trust("m1"); trust == 0 {
		t.Fatal("incomplete transport evidence zeroed trust on eviction")
	}
}

// pacedProber models real probe timing. Healthy replicas answer only after a
// deliberate delay, and a hung replica accepts the probe and then stays silent
// until the caller's own deadline fires, which is the case that makes a
// sequential sweep's duration — and therefore the gap between one endpoint's
// consecutive failures — grow without bound.
type pacedProber struct {
	mu          sync.Mutex
	byMiner     map[string]string
	hung        map[string]bool
	delay       time.Duration
	inFlight    int
	maxInFlight int
}

type staleBlockingProber struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (p *staleBlockingProber) ProbeReplica(context.Context, string, string, string, string) validator.ProbeResult {
	p.once.Do(func() { close(p.started) })
	<-p.release
	return validator.ProbeResult{
		Status: 200, ServedByReplica: true, ResponseComplete: true,
		Error: "incorrect response status=200",
	}
}

type cancellationBlockingProber struct {
	mu               sync.Mutex
	block            bool
	started          chan struct{}
	cancellationSeen chan struct{}
	release          chan struct{}
	once             sync.Once
	cancelOnce       sync.Once
}

// cancelOnSecondErrContext deterministically models cancellation after the
// prober's post-I/O check but before the scheduler's first mutation check.
// Direct observe tests disable the derived timeout so these are the only Err
// calls involved.
type cancelOnSecondErrContext struct {
	context.Context
	mu    sync.Mutex
	calls int
}

func (c *cancelOnSecondErrContext) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	if c.calls >= 2 {
		return context.Canceled
	}
	return nil
}

func (p *cancellationBlockingProber) ProbeReplica(ctx context.Context, _, _, _, _ string) validator.ProbeResult {
	p.mu.Lock()
	block := p.block
	p.mu.Unlock()
	if !block {
		return validator.ProbeResult{Status: 200, Correct: true, ServedByReplica: true, ResponseComplete: true}
	}
	p.once.Do(func() { close(p.started) })
	<-ctx.Done()
	p.cancelOnce.Do(func() { close(p.cancellationSeen) })
	<-p.release
	return validator.ProbeResult{Error: ctx.Err().Error()}
}

func (p *cancellationBlockingProber) startBlocking() {
	p.mu.Lock()
	p.block = true
	p.mu.Unlock()
}

func TestProberDiscardsResultFromReplacedEndpointIncarnation(t *testing.T) {
	h := newSchedulerHarness(t, []string{"m1", "m2", "m3", "m4"}, 3)
	if _, err := h.scheduler.Deploy(context.Background(), h.request); err != nil {
		t.Fatal(err)
	}
	targets, oldTopologyEpoch := h.scheduler.probeTargetsVersioned()
	if len(targets) != 1 {
		t.Fatalf("probe targets = %d", len(targets))
	}
	oldTarget := targets[0]
	var oldReplica ActiveReplica
	for _, replica := range oldTarget.replicas {
		if replica.MinerID == "m1" {
			oldReplica = replica
		}
	}
	if oldReplica.EndpointID == "" {
		t.Fatal("m1 old endpoint was not found")
	}
	probe := &staleBlockingProber{started: make(chan struct{}), release: make(chan struct{})}
	prober := &Prober{Scheduler: h.scheduler, probe: probe, Vantage: "periodic-test"}
	observed := make(chan ProbeOutcome, 1)
	go func() { observed <- prober.observe(context.Background(), oldTarget, oldReplica) }()
	<-probe.started

	if err := h.scheduler.DeactivateDeployment(context.Background(), h.request.DeploymentID); err != nil {
		t.Fatal(err)
	}
	if _, err := h.scheduler.Deploy(context.Background(), h.request); err != nil {
		t.Fatal(err)
	}
	var newEndpoint string
	for _, replica := range h.scheduler.ActiveReplicas(h.request.DeploymentID) {
		if replica.MinerID == "m1" {
			newEndpoint = replica.EndpointID
		}
	}
	if newEndpoint == "" || newEndpoint == oldReplica.EndpointID {
		t.Fatalf("redeploy did not create a new m1 incarnation: old=%q new=%q", oldReplica.EndpointID, newEndpoint)
	}
	if _, newTopologyEpoch := h.scheduler.probeTargetsVersioned(); newTopologyEpoch <= oldTopologyEpoch {
		t.Fatalf("redeploy did not advance probe topology: old=%d new=%d", oldTopologyEpoch, newTopologyEpoch)
	}
	close(probe.release)
	outcome := <-observed
	if !outcome.Stale || !errors.Is(outcome.Err, ErrReplicaNotActive) {
		t.Fatalf("old result was not discarded as stale: %+v", outcome)
	}
	if outcome.Action != (policy.Action{}) {
		t.Fatalf("stale result caused a policy action: %+v", outcome.Action)
	}
	if active := activeMinerIDs(h.scheduler, h.request.DeploymentID); len(active) != 3 || !contains(active, "m1") {
		t.Fatalf("stale result changed redeployed routes: %v", active)
	}
	if trust := h.scheduler.Ledger.Trust("m1"); trust == 0 {
		t.Fatal("stale old result trust-zeroed the healthy new incarnation")
	}
	h.cleanup(t)
}

func TestProberCancellationIsJoinedAndNeverCountsAsFailure(t *testing.T) {
	h := newSchedulerHarness(t, []string{"m1", "m2", "m3", "m4"}, 3)
	if _, err := h.scheduler.Deploy(context.Background(), h.request); err != nil {
		t.Fatal(err)
	}
	deactivated := false
	defer func() {
		if !deactivated {
			h.cleanup(t)
		}
	}()
	probe := &cancellationBlockingProber{
		started: make(chan struct{}), cancellationSeen: make(chan struct{}), release: make(chan struct{}),
	}
	prober := &Prober{
		Scheduler: h.scheduler, probe: probe, Vantage: "periodic-test",
		Interval: 10 * time.Millisecond, Timeout: 5 * time.Millisecond, CadenceMargin: time.Millisecond,
	}
	// Healthy peers arm the attribution guard. Combined with this pre-existing
	// first health failure, applying a cancellation result would evict m1.
	if baseline := prober.Sweep(context.Background()); baseline.Failed() != 0 {
		t.Fatalf("healthy baseline failed: %+v", baseline.Outcomes)
	}
	var m1 ActiveReplica
	for _, replica := range h.scheduler.ActiveReplicas(h.request.DeploymentID) {
		if replica.MinerID == "m1" {
			m1 = replica
		}
	}
	if action, err := h.scheduler.handleEndpointHealth(
		context.Background(), h.request.DeploymentID, m1.ReplicaID, m1.EndpointID, m1.MinerID,
		"periodic-test", false, false, false, time.Now().UTC(),
	); err != nil || action.RemoveFromRouting {
		t.Fatalf("failed to seed first liveness failure: action=%+v err=%v", action, err)
	}
	peers, err := h.scheduler.activeProbePeers(h.request.DeploymentID, m1.ReplicaID, m1.EndpointID, m1.MinerID)
	if err != nil {
		t.Fatal(err)
	}
	// The direct seed bypassed the prober; align its private version fence so a
	// second result really would enter Monitor and evict if cancellation were
	// not checked first.
	prober.corroboration.recordApplied(h.request.DeploymentID, m1.EndpointID, peers, nil, peers.targetHealth.Version)
	probe.startBlocking()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- prober.Run(ctx) }()
	<-probe.started
	cancel()
	<-probe.cancellationSeen
	select {
	case err := <-done:
		t.Fatalf("Run returned before its probe completed: %v", err)
	default:
	}
	close(probe.release)
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run returned %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not join cancelled probes")
	}
	if active := activeMinerIDs(h.scheduler, h.request.DeploymentID); len(active) != 3 || !contains(active, "m1") {
		t.Fatalf("cancellation was counted as a health failure: %v", active)
	}
	if h.miners["m4"].Assignments() != 0 {
		t.Fatal("shutdown cancellation started a replacement")
	}
	if after := h.scheduler.monitor().Snapshot(m1.EndpointID); after.Version != peers.targetHealth.Version {
		t.Fatalf("cancellation mutated health version: before=%d after=%d", peers.targetHealth.Version, after.Version)
	}
	h.cleanup(t)
	deactivated = true
}

func TestProberCancellationAtMutationBoundaryDoesNotSpendCorroboration(t *testing.T) {
	h, probe, prober, _ := newProbedHarness(t)
	deactivated := false
	defer func() {
		if !deactivated {
			h.cleanup(t)
		}
	}()
	prober.Timeout = -1
	if baseline := prober.Sweep(context.Background()); baseline.Failed() != 0 {
		t.Fatalf("healthy baseline failed: %+v", baseline.Outcomes)
	}
	targets := h.scheduler.probeTargets()
	var target probeTarget
	var replica ActiveReplica
	for _, candidateTarget := range targets {
		for _, candidateReplica := range candidateTarget.replicas {
			if candidateReplica.MinerID == "m1" {
				target, replica = candidateTarget, candidateReplica
			}
		}
	}
	if replica.EndpointID == "" {
		t.Fatal("m1 probe target was not found")
	}
	before := h.scheduler.monitor().Snapshot(replica.EndpointID)
	probe.setDark(replica.MinerID)
	cancelled := prober.observe(&cancelOnSecondErrContext{Context: context.Background()}, target, replica)
	if !cancelled.Cancelled || !errors.Is(cancelled.Err, context.Canceled) || cancelled.Action != (policy.Action{}) {
		t.Fatalf("mutation-boundary cancellation was treated as health evidence: %+v", cancelled)
	}
	if after := h.scheduler.monitor().Snapshot(replica.EndpointID); after != before {
		t.Fatalf("cancelled observation mutated health: before=%+v after=%+v", before, after)
	}

	// The cancelled observation must not consume the baseline peer evidence.
	// The next real failure enters the monitor, and a later failure backed by
	// newly refreshed peers performs the ordinary isolated eviction.
	first := prober.Sweep(context.Background())
	var firstM1 ProbeOutcome
	for _, outcome := range first.Outcomes {
		if outcome.MinerID == replica.MinerID {
			firstM1 = outcome
		}
	}
	if firstM1.CommonModeSuppressed || firstM1.Cancelled || firstM1.Action.RemoveFromRouting {
		t.Fatalf("cancelled observation spent corroboration evidence: %+v", firstM1)
	}
	second := prober.Sweep(context.Background())
	if second.Removed() != 1 {
		t.Fatalf("isolated failure did not evict after cancellation: %+v", second.Outcomes)
	}
	if trust := h.scheduler.Ledger.Trust(replica.MinerID); trust == 0 {
		t.Fatal("cancelled/internal liveness evidence became economic guilt")
	}
	h.cleanup(t)
	deactivated = true
}

func (p *pacedProber) ProbeReplica(ctx context.Context, _, replicaID, _, _ string) validator.ProbeResult {
	p.mu.Lock()
	hung := p.hung[p.byMiner[replicaID]]
	p.inFlight++
	if p.inFlight > p.maxInFlight {
		p.maxInFlight = p.inFlight
	}
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		p.inFlight--
		p.mu.Unlock()
	}()
	if hung {
		<-ctx.Done()
		return validator.ProbeResult{Vantage: "test", Status: 0, Error: "probe deadline exceeded"}
	}
	select {
	case <-time.After(p.delay):
		return validator.ProbeResult{Vantage: "test", Status: 200, Correct: true, ServedByReplica: true, ResponseComplete: true, Latency: p.delay}
	case <-ctx.Done():
		return validator.ProbeResult{Vantage: "test", Status: 0, Error: "probe deadline exceeded"}
	}
}

func (p *pacedProber) peakInFlight() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.maxInFlight
}

func TestProberEvictsHungReplicaUnderRealTiming(t *testing.T) {
	const (
		replicas = 9
		// A healthy replica answers well inside the probe timeout, so a timing
		// assertion here can only be about sweep structure, never about a slow
		// runner mistaking a healthy replica for a hung one.
		healthyDelay = 150 * time.Millisecond
		probeTimeout = 400 * time.Millisecond
		interval     = 500 * time.Millisecond
		margin       = 300 * time.Millisecond
		rapidWindow  = 1500 * time.Millisecond
	)
	// The sequential driver this replaced measured its interval from the end of
	// a whole pass, so one endpoint's consecutive failures were at least this
	// far apart. Assert the fixture really does reproduce that failure mode:
	// past the rapid window the counter resets on every pass and the hung
	// replica is never evicted, silently, forever.
	sequentialGap := time.Duration(replicas-1)*healthyDelay + probeTimeout + interval
	if sequentialGap <= rapidWindow {
		t.Fatalf("fixture does not exercise sweep duration: sequential gap %v is already inside the window %v", sequentialGap, rapidWindow)
	}
	if bound := ProbeCadenceBound(interval, probeTimeout, margin); bound > rapidWindow {
		t.Fatalf("test cadence %v does not satisfy the guarantee it is checking against window %v", bound, rapidWindow)
	}

	ids := make([]string, 0, replicas+3)
	for i := 0; i < replicas+3; i++ {
		ids = append(ids, fmt.Sprintf("m%d", i))
	}
	h := newSchedulerHarness(t, ids, replicas)
	monitor := policy.NewMonitor()
	monitor.RapidWindow = rapidWindow
	h.scheduler.Health = monitor
	if _, err := h.scheduler.Deploy(context.Background(), h.request); err != nil {
		t.Fatal(err)
	}
	byReplica := map[string]string{}
	for _, replica := range h.scheduler.ActiveReplicas(h.request.DeploymentID) {
		byReplica[replica.ReplicaID] = replica.MinerID
	}
	if len(byReplica) != replicas {
		t.Fatalf("expected %d active replicas, got %d", replicas, len(byReplica))
	}
	const hungMiner = "m0"
	probe := &pacedProber{byMiner: byReplica, hung: map[string]bool{hungMiner: true}, delay: healthyDelay}

	failures := map[string][]time.Time{}
	var failureMu sync.Mutex
	evicted := make(chan ProbeOutcome, 1)
	prober := &Prober{
		Scheduler: h.scheduler, probe: probe, Vantage: "periodic-test",
		Interval: interval, Timeout: probeTimeout, CadenceMargin: margin,
		OnObservation: func(outcome ProbeOutcome) {
			if outcome.Reachable {
				return
			}
			failureMu.Lock()
			failures[outcome.EndpointID] = append(failures[outcome.EndpointID], time.Now())
			failureMu.Unlock()
			if outcome.Action.RemoveFromRouting {
				select {
				case evicted <- outcome:
				default:
				}
			}
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- prober.Run(ctx) }()

	var removal ProbeOutcome
	select {
	case removal = <-evicted:
	case <-time.After(15 * time.Second):
		cancel()
		<-done
		t.Fatal("a hung replica was never evicted: its consecutive failures never landed inside the rapid window")
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run returned %v, want context.Canceled", err)
	}

	if removal.MinerID != hungMiner {
		t.Fatalf("the wrong replica was evicted: %+v", removal)
	}
	if removal.Action.TrustZero {
		t.Fatalf("a hung replica was trust-zeroed from one vantage: %+v", removal.Action)
	}
	if !removal.Action.AssignReplacement {
		t.Fatalf("eviction did not request a replacement: %+v", removal.Action)
	}
	failureMu.Lock()
	observed := append([]time.Time(nil), failures[removal.EndpointID]...)
	failureMu.Unlock()
	if len(observed) < 2 {
		t.Fatalf("eviction happened on %d observed failures", len(observed))
	}
	// The guarantee, measured rather than assumed: consecutive failures for one
	// endpoint stay inside the rapid window no matter how many other replicas
	// exist or how slowly they answer.
	for i := 1; i < len(observed); i++ {
		if gap := observed[i].Sub(observed[i-1]); gap > rapidWindow {
			t.Fatalf("consecutive failures %v apart exceed the rapid window %v", gap, rapidWindow)
		}
	}
	if peak := probe.peakInFlight(); peak > replicas {
		t.Fatalf("probes in flight (%d) exceeded one per active endpoint (%d)", peak, replicas)
	}
	if contains(activeMinerIDs(h.scheduler, h.request.DeploymentID), hungMiner) {
		t.Fatal("the hung miner kept its assignment")
	}
	if got := len(activeMinerIDs(h.scheduler, h.request.DeploymentID)); got != replicas {
		t.Fatalf("the evicted replica was not replaced: %d active", got)
	}
	if trust := h.scheduler.Ledger.Trust(hungMiner); trust == 0 {
		t.Fatal("a hung replica's trust was zeroed")
	}
	h.cleanup(t)
}
