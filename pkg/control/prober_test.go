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
	edgeStatus map[string]int
	requests   []string
	byMiner    map[string]string
}

func newScriptedProber(replicaToMiner map[string]string) *scriptedProber {
	return &scriptedProber{dark: map[string]bool{}, wrong: map[string]bool{}, edgeStatus: map[string]int{}, byMiner: replicaToMiner}
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
			Vantage: "test", Status: s.edgeStatus[minerID], Correct: false, ServedByReplica: false, EdgeGenerated: true,
			Error: "edge-generated response",
		}
	case s.wrong[minerID]:
		// A real replica response that carries the wrong bytes: the edge proxied
		// it, so the upstream marker is present.
		return validator.ProbeResult{
			Vantage: "test", Status: 200, Correct: false, ServedByReplica: true, Error: "incorrect response status=200",
		}
	default:
		return validator.ProbeResult{
			Vantage: "test", Status: 200, Correct: true, ServedByReplica: true, Latency: 5 * time.Millisecond,
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
		return validator.ProbeResult{Vantage: "test", Status: 200, Correct: true, ServedByReplica: true, Latency: p.delay}
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
		Scheduler: h.scheduler, Probe: probe, Vantage: "periodic-test",
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
