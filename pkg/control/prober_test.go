// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/edge"
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

func (s *scriptedProber) ProbeReplica(_ context.Context, _, replicaID, _, _ string) (result validator.ProbeResult) {
	defer func() {
		if result.At.IsZero() {
			result.At = time.Now().UTC()
		}
	}()
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

func routedHealthy(scheduler *Scheduler, deploymentID, minerID string) bool {
	for _, replica := range scheduler.Router.Replicas(scheduler.states[deploymentID].routeHost) {
		if replica.MinerID == minerID {
			return replica.Healthy
		}
	}
	return false
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

func TestTemporaryRoutingCircuitSuppressesAndRestoresWithoutEconomicPenalty(t *testing.T) {
	h, probe, prober, _ := newProbedHarness(t)
	defer h.cleanup(t)
	if baseline := prober.Sweep(context.Background()); baseline.Failed() != 0 {
		t.Fatalf("healthy baseline failed: %+v", baseline.Outcomes)
	}
	probe.setDark("m1")
	failed := prober.Sweep(context.Background())
	if failed.Removed() != 0 || routedHealthy(h.scheduler, h.request.DeploymentID, "m1") {
		t.Fatalf("first transport failure was not temporarily removed from traffic: %+v", failed.Outcomes)
	}
	if !contains(activeMinerIDs(h.scheduler, h.request.DeploymentID), "m1") || h.scheduler.Ledger.Trust("m1") == 0 {
		t.Fatal("temporary availability circuit changed scheduler eligibility or economic trust")
	}
	probe.setHealthy("m1")
	recovered := prober.Sweep(context.Background())
	if !routedHealthy(h.scheduler, h.request.DeploymentID, "m1") {
		t.Fatalf("complete correct targeted probe did not restore traffic: %+v", recovered.Outcomes)
	}
	var restored bool
	for _, outcome := range recovered.Outcomes {
		if outcome.MinerID == "m1" {
			restored = outcome.RoutingRestored
		}
	}
	if !restored {
		t.Fatal("routing restoration was not surfaced to operators")
	}
}

func TestProbeStateIsRetiredWithEveryDeploymentIncarnation(t *testing.T) {
	h := newSchedulerHarness(t, []string{"m1", "m2", "m3", "m4"}, 3)
	for cycle := 0; cycle < 3; cycle++ {
		request := h.request
		request.DeploymentID = fmt.Sprintf("probe-retirement-%d", cycle)
		if _, err := h.scheduler.Deploy(context.Background(), request); err != nil {
			t.Fatalf("deploy cycle %d: %v", cycle, err)
		}
		replicas := h.scheduler.ActiveReplicas(request.DeploymentID)
		byReplica := make(map[string]string, len(replicas))
		for _, replica := range replicas {
			byReplica[replica.ReplicaID] = replica.MinerID
		}
		prober := &Prober{Scheduler: h.scheduler, probe: newScriptedProber(byReplica), Vantage: "periodic-test"}
		if result := prober.Sweep(context.Background()); result.Failed() != 0 {
			t.Fatalf("healthy cycle %d failed: %+v", cycle, result.Outcomes)
		}
		h.scheduler.mu.Lock()
		circuitCount := len(h.scheduler.circuitVersions)
		h.scheduler.mu.Unlock()
		if circuitCount != len(replicas) {
			t.Fatalf("cycle %d circuit records=%d want=%d", cycle, circuitCount, len(replicas))
		}
		if err := h.scheduler.DeactivateDeployment(context.Background(), request.DeploymentID); err != nil {
			t.Fatalf("deactivate cycle %d: %v", cycle, err)
		}
		h.scheduler.mu.Lock()
		circuitCount = len(h.scheduler.circuitVersions)
		h.scheduler.mu.Unlock()
		if circuitCount != 0 {
			t.Fatalf("cycle %d retained %d circuit records", cycle, circuitCount)
		}
		for _, replica := range replicas {
			if snapshot := h.scheduler.monitor().Snapshot(replica.EndpointID); snapshot != (policy.ObservationSnapshot{}) {
				t.Fatalf("cycle %d retained monitor state for %s: %+v", cycle, replica.EndpointID, snapshot)
			}
		}
	}
}

func TestTemporaryCircuitCASRejectsOlderSuccessAndUnauthorizedMutation(t *testing.T) {
	h, _, _, _ := newProbedHarness(t)
	deactivated := false
	defer func() {
		if !deactivated {
			h.cleanup(t)
		}
	}()
	replica := h.scheduler.ActiveReplicas(h.request.DeploymentID)[0]
	changed, applied, err := h.scheduler.suppressEndpointAvailabilityIfVersion(
		context.Background(), h.request.DeploymentID, replica.ReplicaID, replica.EndpointID, replica.MinerID, 0,
	)
	if err != nil || !applied || !changed {
		t.Fatalf("current failure did not suppress route: changed=%v applied=%v err=%v", changed, applied, err)
	}
	if action, accepted, _, err := h.scheduler.handleEndpointHealthVersioned(
		context.Background(), h.request.DeploymentID, replica.ReplicaID, replica.EndpointID, replica.MinerID,
		"older-success", true, true, false, time.Now().UTC(), 0, 0,
	); accepted || !errors.Is(err, errHealthObservationChanged) || action != (policy.Action{}) {
		t.Fatalf("older success survived suppression revision: action=%+v accepted=%v err=%v", action, accepted, err)
	}
	claims := h.scheduler.Router.Replicas(h.scheduler.states[h.request.DeploymentID].routeHost)
	for _, claim := range claims {
		if claim.EndpointID == replica.EndpointID && claim.Healthy {
			t.Fatal("stale success restored suppressed route")
		}
	}
	if action, err := h.scheduler.HandleHealth(
		context.Background(), h.request.DeploymentID, replica.ReplicaID, replica.EndpointID, replica.MinerID,
		"external-vantage", true, true, false, time.Now().UTC(),
	); err != nil || action != (policy.Action{}) {
		t.Fatalf("external healthy evidence failed: action=%+v err=%v", action, err)
	}
	for _, claim := range h.scheduler.Router.Replicas(h.scheduler.states[h.request.DeploymentID].routeHost) {
		if claim.EndpointID == replica.EndpointID && claim.Healthy {
			t.Fatal("external report reopened the validator-owned serving circuit")
		}
	}
	current := h.scheduler.monitor().Snapshot(replica.EndpointID)
	currentPeers, err := h.scheduler.activeProbePeers(
		h.request.DeploymentID, replica.ReplicaID, replica.EndpointID, replica.MinerID,
	)
	if err != nil {
		t.Fatal(err)
	}
	if action, applied, restored, err := h.scheduler.handleEndpointHealthVersioned(
		context.Background(), h.request.DeploymentID, replica.ReplicaID, replica.EndpointID, replica.MinerID,
		"periodic-current", true, true, false, time.Now().UTC(), current.Version, currentPeers.targetCircuit,
	); err != nil || !applied || !restored || action != (policy.Action{}) {
		t.Fatalf("current internal probe did not restore route: action=%+v applied=%v restored=%v err=%v", action, applied, restored, err)
	}
	wrongKey := ed25519.PrivateKey(append([]byte(nil), h.scheduler.SigningKey...))
	wrongKey[len(wrongKey)-1] ^= 0x01
	if matched, _ := h.scheduler.Router.SetTemporaryAvailability(
		h.scheduler.states[h.request.DeploymentID].routeHost, replica.ReplicaID, replica.EndpointID, replica.MinerID, true, wrongKey,
	); matched {
		t.Fatal("unauthorized in-process caller mutated serving availability")
	}
	forged := make(ed25519.PrivateKey, ed25519.PrivateKeySize)
	copy(forged[ed25519.SeedSize:], h.scheduler.SigningKey.Public().(ed25519.PublicKey))
	if matched, _ := h.scheduler.Router.SetTemporaryAvailability(
		h.scheduler.states[h.request.DeploymentID].routeHost, replica.ReplicaID, replica.EndpointID, replica.MinerID, true, forged,
	); matched {
		t.Fatal("public-key suffix without private-key possession mutated serving availability")
	}
	h.cleanup(t)
	deactivated = true
}

func TestTemporaryCircuitCancellationCannotBecomeRoutingEvidence(t *testing.T) {
	h, _, _, _ := newProbedHarness(t)
	deactivated := false
	defer func() {
		if !deactivated {
			h.cleanup(t)
		}
	}()
	replica := h.scheduler.ActiveReplicas(h.request.DeploymentID)[0]
	h.scheduler.mu.Lock()
	ctx, cancel := context.WithCancel(context.Background())
	type result struct {
		changed bool
		applied bool
		err     error
	}
	done := make(chan result, 1)
	go func() {
		changed, applied, err := h.scheduler.suppressEndpointAvailabilityIfVersion(
			ctx, h.request.DeploymentID, replica.ReplicaID, replica.EndpointID, replica.MinerID, 0,
		)
		done <- result{changed: changed, applied: applied, err: err}
	}()
	deadline := time.Now().Add(time.Second)
	for {
		h.scheduler.lifecycleMu.Lock()
		workers := h.scheduler.lifecycleWorkers
		h.scheduler.lifecycleMu.Unlock()
		if workers > 0 {
			break
		}
		if time.Now().After(deadline) {
			h.scheduler.mu.Unlock()
			t.Fatal("suppression did not reach the mutation lock")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	h.scheduler.mu.Unlock()
	got := <-done
	if got.changed || got.applied || !errors.Is(got.err, context.Canceled) {
		t.Fatalf("cancelled suppression mutated route: %+v", got)
	}
	if snapshot := h.scheduler.monitor().Snapshot(replica.EndpointID); snapshot.Version != 0 {
		t.Fatalf("cancelled suppression advanced health revision: %+v", snapshot)
	}
	for _, claim := range h.scheduler.Router.Replicas(h.scheduler.states[h.request.DeploymentID].routeHost) {
		if claim.EndpointID == replica.EndpointID && !claim.Healthy {
			t.Fatal("cancelled suppression opened serving circuit")
		}
	}
	h.cleanup(t)
	deactivated = true
}

func TestTemporaryCircuitRevisionExhaustionFailsClosed(t *testing.T) {
	h, _, _, _ := newProbedHarness(t)
	deactivated := false
	defer func() {
		if !deactivated {
			h.cleanup(t)
		}
	}()
	replica := h.scheduler.ActiveReplicas(h.request.DeploymentID)[0]
	h.scheduler.mu.Lock()
	if h.scheduler.circuitVersions == nil {
		h.scheduler.circuitVersions = make(map[string]uint64)
	}
	h.scheduler.circuitVersions[replica.EndpointID] = ^uint64(0)
	h.scheduler.mu.Unlock()
	changed, applied, err := h.scheduler.suppressEndpointAvailabilityIfVersion(
		context.Background(), h.request.DeploymentID, replica.ReplicaID, replica.EndpointID, replica.MinerID, ^uint64(0),
	)
	if changed || applied || !errors.Is(err, errHealthObservationChanged) {
		t.Fatalf("exhausted circuit revision was not refused: changed=%v applied=%v err=%v", changed, applied, err)
	}
	if !routedHealthy(h.scheduler, h.request.DeploymentID, replica.MinerID) {
		t.Fatal("exhausted revision changed route availability")
	}
	h.cleanup(t)
	deactivated = true
}

func TestProberRemovesTwoOfThreeDeadMinersWithOneHealthyWitness(t *testing.T) {
	h := newSchedulerHarness(t, []string{"m1", "m2", "m3", "m4", "m5"}, 3)
	if _, err := h.scheduler.Deploy(context.Background(), h.request); err != nil {
		t.Fatal(err)
	}
	defer h.cleanup(t)
	byReplica := make(map[string]string)
	for _, replica := range h.scheduler.ActiveReplicas(h.request.DeploymentID) {
		byReplica[replica.ReplicaID] = replica.MinerID
	}
	probe := newScriptedProber(byReplica)
	prober := &Prober{Scheduler: h.scheduler, probe: probe, Vantage: "periodic-test"}
	now := time.Now().UTC()
	prober.Now = func() time.Time { return now }
	if baseline := prober.Sweep(context.Background()); baseline.Failed() != 0 {
		t.Fatalf("healthy baseline failed: %+v", baseline.Outcomes)
	}
	probe.setDark("m1")
	probe.setDark("m2")
	for round := 0; round < 4 && (contains(activeMinerIDs(h.scheduler, h.request.DeploymentID), "m1") || contains(activeMinerIDs(h.scheduler, h.request.DeploymentID), "m2")); round++ {
		now = now.Add(time.Second)
		probe.learn(h.scheduler.ActiveReplicas(h.request.DeploymentID))
		prober.Sweep(context.Background())
	}
	active := activeMinerIDs(h.scheduler, h.request.DeploymentID)
	if contains(active, "m1") || contains(active, "m2") || len(active) != 3 || !contains(active, "m4") || !contains(active, "m5") {
		t.Fatalf("one healthy witness did not restore two-thirds capacity: %v", active)
	}
	if h.scheduler.Ledger.Trust("m1") == 0 || h.scheduler.Ledger.Trust("m2") == 0 {
		t.Fatal("unattributable liveness failures became economic penalties")
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
	_, err := h.handleHealth(
		context.Background(), "no-such-deployment", replicaOf["m1"], "m1",
		"periodic-test", false, false, false, time.Now().UTC(),
	)
	if !errors.Is(err, ErrUnknownDeployment) || !isStaleObservation(err) {
		t.Fatalf("unknown deployment is not reported as a stale observation: %v", err)
	}
	_, err = h.handleHealth(
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

func TestPeriodicProbeHonorsSixSecondTimeoutWithoutWeakeningAdmissionBound(t *testing.T) {
	h, _, _, _ := newProbedHarness(t)
	deactivated := false
	defer func() {
		if !deactivated {
			h.cleanup(t)
		}
	}()
	target := h.scheduler.probeTargets()[0]
	replica := target.replicas[0]

	// This is the production construction: scheduler admission has a nil Client,
	// so Validator supplies its independent five-second bound. Periodic probing
	// must retain that admission behavior while allowing its own configured
	// context deadline to be authoritative.
	if h.scheduler.Validator.Client != nil {
		t.Fatal("test requires the production nil validator client")
	}
	const responseDelay = 5300 * time.Millisecond
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path != target.challengePath ||
			request.Header.Get(edge.TargetReplicaHeader) != replica.ReplicaID ||
			request.Header.Get(edge.ProbeAuthorizationHeader) != h.scheduler.Validator.InternalProbeToken {
			http.Error(w, "incorrect targeted probe", http.StatusBadRequest)
			return
		}
		timer := time.NewTimer(responseDelay)
		defer timer.Stop()
		select {
		case <-request.Context().Done():
			return
		case <-timer.C:
		}
		w.Header().Set(edge.UpstreamResponseHeader, edge.UpstreamResponseMarker)
		_, _ = w.Write([]byte(target.challengeValue))
	}))
	defer server.Close()
	h.scheduler.Validator.EdgeURL = server.URL

	prober := &Prober{Scheduler: h.scheduler, Interval: 7 * time.Second, Timeout: 6 * time.Second}
	if err := prober.Validate(); err != nil {
		t.Fatalf("valid 6s timeout / 7s interval was refused: %v", err)
	}

	// Exercise both paths concurrently so the regression crosses five real
	// seconds only once. The direct scheduler-validator call models admission and
	// must still fail at its independent five-second limit. The periodic path sees
	// the same response after that limit but before its configured six seconds and
	// must accept it.
	admissionDone := make(chan validator.ProbeResult, 1)
	periodicDone := make(chan ProbeOutcome, 1)
	go func() {
		admissionDone <- h.scheduler.Validator.ProbeReplica(
			context.Background(), target.routeHost, replica.ReplicaID, target.challengePath, target.challengeValue,
		)
	}()
	go func() {
		periodicDone <- prober.observe(context.Background(), target, replica)
	}()

	admission := <-admissionDone
	periodic := <-periodicDone
	if admission.Correct || admission.Status != 0 || admission.ResponseComplete || admission.Error == "" {
		t.Fatalf("admission probe lost its independent five-second bound: %+v", admission)
	}
	if !periodic.Correct || !periodic.Reachable || !periodic.ResponseComplete || periodic.Err != nil {
		t.Fatalf("periodic response after 5s but before configured 6s was rejected: %+v", periodic)
	}
	if periodic.Latency <= 5*time.Second {
		t.Fatalf("regression did not cross the old five-second client cap: latency=%v", periodic.Latency)
	}

	h.cleanup(t)
	deactivated = true
}

func TestProberRefusesNonpositiveRapidWindow(t *testing.T) {
	for name, window := range map[string]time.Duration{
		"zero":     0,
		"negative": -time.Nanosecond,
	} {
		t.Run(name, func(t *testing.T) {
			h, _, _, _ := newProbedHarness(t)
			defer h.cleanup(t)
			h.scheduler.monitor().RapidWindow = window
			prober := &Prober{Scheduler: h.scheduler}
			if err := prober.Validate(); !errors.Is(err, ErrProbeCadence) {
				t.Fatalf("Validate accepted rapid window %v: %v", window, err)
			}
			if err := prober.Run(context.Background()); !errors.Is(err, ErrProbeCadence) {
				t.Fatalf("Run started with rapid window %v: %v", window, err)
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
			for _, minerID := range []string{"m1", "m2", "m3"} {
				if routedHealthy(h.scheduler, h.request.DeploymentID, minerID) {
					t.Fatalf("common-mode failing endpoint %s remained in ordinary traffic", minerID)
				}
			}
			if h.miners["m4"].Assignments() != 0 {
				t.Fatalf("common-mode failure consumed replacement pool: m4 assignments=%d", h.miners["m4"].Assignments())
			}
			for _, minerID := range []string{"m1", "m2", "m3", "m4"} {
				if trust := h.scheduler.Ledger.Trust(minerID); trust == 0 {
					t.Fatalf("common-mode failure trust-zeroed %s", minerID)
				}
			}

			// The edge recovers for peers while m1 remains genuinely down. One
			// fresh complete peer response re-arms only the ordinary isolated-
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

func TestSingletonCorroborationStoresOneMonotonicWitnessPerTarget(t *testing.T) {
	const count = 64
	corroboration := probeCorroboration{}
	replicas := make([]ActiveReplica, 0, count)
	for index := 0; index < count; index++ {
		replicas = append(replicas, ActiveReplica{
			MinerID: fmt.Sprintf("m-%03d", index), ReplicaID: fmt.Sprintf("r-%03d", index), EndpointID: fmt.Sprintf("e-%03d", index),
		})
	}
	now := time.Now().UTC()
	for index, replica := range replicas {
		peers := probePeerSet{deployment: []ActiveReplica{replica}, global: replicas, topologyEpoch: 1}
		corroboration.recordSuccess(fmt.Sprintf("d-%03d", index), replica.EndpointID, peers, now.Add(time.Duration(index)*time.Millisecond), 1)
	}
	for index, target := range replicas {
		peers := probePeerSet{deployment: []ActiveReplica{target}, global: replicas, topologyEpoch: 1}
		permit, allowed := corroboration.unreachablePermit(fmt.Sprintf("d-%03d", index), target.EndpointID, peers)
		if !allowed || permit == nil || !permit.global || len(permit.sequences) != 1 {
			t.Fatalf("target %d retained more than one witness: allowed=%v permit=%+v", index, allowed, permit)
		}
		corroboration.recordApplied(fmt.Sprintf("d-%03d", index), target.EndpointID, peers, permit, 1)
	}
	if got := len(corroboration.global.consumed); got != count {
		t.Fatalf("global consumed state grew beyond one scalar per target: %d", got)
	}
	target := replicas[0]
	peers := probePeerSet{deployment: []ActiveReplica{target}, global: replicas, topologyEpoch: 1}
	if permit, allowed := corroboration.unreachablePermit("d-000", target.EndpointID, peers); allowed || permit != nil {
		t.Fatal("old alternate witness bypassed the monotonic consumption fence")
	}
	corroboration.recordSuccess("d-001", replicas[1].EndpointID, peers, now.Add(time.Minute), 2)
	if permit, allowed := corroboration.unreachablePermit("d-000", target.EndpointID, peers); !allowed || permit == nil || len(permit.sequences) != 1 {
		t.Fatal("fresh alternate witness did not re-arm the target")
	}
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

func TestCurrentReconcileAllowsFreshReplacementWitness(t *testing.T) {
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
	// The replacement witness must actually be observed after the target's
	// latest failure; a result merely recorded later but timestamped earlier is
	// not valid shared-path evidence.
	corroboration.recordSuccess(deploymentID, newWitness.EndpointID, newPeers, now.Add(3*time.Second), 1)
	corroboration.recordApplied(deploymentID, target.EndpointID, oldPeers, permit, 1)

	newPeers.targetHealth = policy.ObservationSnapshot{Version: 1, LastFailure: now.Add(2 * time.Second)}
	if fresh, allowed := corroboration.unreachablePermit(deploymentID, target.EndpointID, newPeers); !allowed || fresh == nil {
		t.Fatal("fresh replacement witness could not prove the shared path recovered")
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
	corroboration.recordSuccess("other", globalD.EndpointID, singletonPeers, failureAt, 2)
	if ambiguous, allowed := corroboration.unreachablePermit(deploymentID, target.EndpointID, singletonPeers); allowed || ambiguous != nil {
		t.Fatal("success simultaneous with failure was treated as post-failure evidence")
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
		action, err := h.handleHealth(
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
		action, err := h.handleHealth(
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
	if action, err := h.handleHealth(
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
	if action, err := h.handleHealth(
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
	action, err := h.handleHealth(
		context.Background(), h.request.DeploymentID, replica.ReplicaID, replica.MinerID,
		"external-test", true, false, false, time.Now().UTC(),
	)
	if !errors.Is(err, ErrAcceptanceInconclusive) || !action.RemoveFromRouting || len(h.scheduler.ActiveReplicas(h.request.DeploymentID)) != 0 {
		t.Fatalf("zero-route setup: action=%+v active=%v err=%v", action, activeMinerIDs(h.scheduler, h.request.DeploymentID), err)
	}
	h.scheduler.Validator.EdgeURL = originalURL
	h.scheduler.Validator.Client = nil
	// Provisioning intentionally exceeds the one-probe budget. Half-open
	// recovery must use the deployment lifecycle timeout, not this 10ms probe
	// timeout, or the clean replacement can never return.
	h.miners["m2"].SetDelay(100 * time.Millisecond)
	prober := &Prober{Scheduler: h.scheduler, Timeout: 10 * time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())
	loops := make(map[string]*endpointLoop)
	started := time.Now()
	prober.reconcile(ctx, loops)
	if elapsed := time.Since(started); elapsed < 100*time.Millisecond {
		t.Fatalf("half-open repair did not exercise delayed provisioning: %s", elapsed)
	}
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

func TestHalfOpenLifecycleOutlivesDefaultFiveSecondProbeBudget(t *testing.T) {
	h := newSchedulerHarness(t, []string{"m1", "m2"}, 1)
	h.request.Timeout = 8 * time.Second
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
	if action, err := h.handleHealth(
		context.Background(), h.request.DeploymentID, replica.ReplicaID, replica.MinerID,
		"external-test", true, false, false, time.Now().UTC(),
	); !errors.Is(err, ErrAcceptanceInconclusive) || !action.RemoveFromRouting {
		t.Fatalf("zero-route setup: action=%+v err=%v", action, err)
	}
	h.scheduler.Validator.EdgeURL = originalURL
	h.scheduler.Validator.Client = nil
	h.miners["m2"].SetDelay(5100 * time.Millisecond)
	prober := &Prober{Scheduler: h.scheduler, Timeout: DefaultProbeTimeout}
	ctx, cancel := context.WithCancel(context.Background())
	loops := make(map[string]*endpointLoop)
	started := time.Now()
	prober.reconcile(ctx, loops)
	if elapsed := time.Since(started); elapsed < 5*time.Second {
		t.Fatalf("replacement lifecycle was incorrectly bounded by probe timeout: %s", elapsed)
	}
	cancel()
	for _, loop := range loops {
		loop.cancel()
		<-loop.done
	}
	active := activeMinerIDs(h.scheduler, h.request.DeploymentID)
	if len(active) != 1 || contains(active, "m1") {
		t.Fatalf("long healthy provisioning did not recover zero-route deployment: %v", active)
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
	result  *validator.ProbeResult
}

type fixedProbeResult struct {
	result validator.ProbeResult
}

type unstampedProbeResult struct {
	result validator.ProbeResult
}

func (p unstampedProbeResult) ProbeReplica(context.Context, string, string, string, string) validator.ProbeResult {
	return p.result
}

func (p fixedProbeResult) ProbeReplica(context.Context, string, string, string, string) validator.ProbeResult {
	result := p.result
	if result.At.IsZero() {
		result.At = time.Now().UTC()
	}
	return result
}

func (p *staleBlockingProber) ProbeReplica(context.Context, string, string, string, string) (result validator.ProbeResult) {
	defer func() {
		if result.At.IsZero() {
			result.At = time.Now().UTC()
		}
	}()
	p.once.Do(func() { close(p.started) })
	<-p.release
	if p.result != nil {
		return *p.result
	}
	return validator.ProbeResult{
		Status: 200, ServedByReplica: true, ResponseComplete: true,
		Error: "incorrect response status=200",
	}
}

func TestProberBindsHealthRevisionBeforeNetworkIO(t *testing.T) {
	h, _, _, _ := newProbedHarness(t)
	deactivated := false
	defer func() {
		if !deactivated {
			h.cleanup(t)
		}
	}()
	target := h.scheduler.probeTargets()[0]
	replica := target.replicas[0]
	healthy := validator.ProbeResult{
		Status: 200, Correct: true, ServedByReplica: true, ResponseComplete: true,
	}
	probe := &staleBlockingProber{
		started: make(chan struct{}), release: make(chan struct{}), result: &healthy,
	}
	prober := &Prober{Scheduler: h.scheduler, probe: probe, Vantage: "periodic-test"}
	observed := make(chan ProbeOutcome, 1)
	go func() { observed <- prober.observe(context.Background(), target, replica) }()
	<-probe.started

	changed, applied, err := h.scheduler.suppressEndpointAvailabilityIfVersion(
		context.Background(), target.deploymentID, replica.ReplicaID, replica.EndpointID, replica.MinerID, 0,
	)
	if err != nil || !applied || !changed {
		t.Fatalf("newer failure did not suppress route: changed=%v applied=%v err=%v", changed, applied, err)
	}
	close(probe.release)
	outcome := <-observed
	if !outcome.CommonModeSuppressed || !errors.Is(outcome.Err, errHealthObservationChanged) {
		t.Fatalf("pre-failure success adopted a post-failure revision: %+v", outcome)
	}
	if outcome.RoutingRestored || outcome.Action != (policy.Action{}) {
		t.Fatalf("stale success mutated serving state: %+v", outcome)
	}
	for _, claim := range h.scheduler.Router.Replicas(h.scheduler.states[target.deploymentID].routeHost) {
		if claim.EndpointID == replica.EndpointID && claim.Healthy {
			t.Fatal("pre-failure success reopened the newer failure circuit")
		}
	}
	h.cleanup(t)
	deactivated = true
}

func TestDelayedPeerSuccessKeepsItsPreFailureCompletionTime(t *testing.T) {
	h, _, _, _ := newProbedHarness(t)
	deactivated := false
	defer func() {
		if !deactivated {
			h.cleanup(t)
		}
	}()
	target := h.scheduler.probeTargets()[0]
	var failed, peer ActiveReplica
	for _, replica := range target.replicas {
		switch replica.MinerID {
		case "m1":
			failed = replica
		case "m2":
			peer = replica
		}
	}
	if failed.EndpointID == "" || peer.EndpointID == "" {
		t.Fatal("probe fixtures did not contain m1 and m2")
	}
	failureAt := time.Now().UTC()
	completedBeforeFailure := failureAt.Add(-time.Second)
	blocked := &staleBlockingProber{
		started: make(chan struct{}), release: make(chan struct{}),
		result: &validator.ProbeResult{
			At: completedBeforeFailure, Status: 200, Correct: true,
			ServedByReplica: true, ResponseComplete: true,
		},
	}
	// If observe re-stamps after ProbeReplica returns, this processing time makes
	// the old result appear fresh. The production path must ignore it and carry
	// the validator's completion timestamp unchanged.
	prober := &Prober{
		Scheduler: h.scheduler, probe: blocked, Vantage: "periodic-test",
		Now: func() time.Time { return failureAt.Add(time.Second) },
	}
	peerObserved := make(chan ProbeOutcome, 1)
	go func() { peerObserved <- prober.observe(context.Background(), target, peer) }()
	<-blocked.started

	if action, err := h.scheduler.handleEndpointHealth(
		context.Background(), target.deploymentID, failed.ReplicaID, failed.EndpointID, failed.MinerID,
		"periodic-test", false, false, false, failureAt,
	); err != nil || action.RemoveFromRouting {
		t.Fatalf("failed to seed target failure: action=%+v err=%v", action, err)
	}
	failedPeers, err := h.scheduler.activeProbePeers(target.deploymentID, failed.ReplicaID, failed.EndpointID, failed.MinerID)
	if err != nil {
		t.Fatal(err)
	}
	prober.corroboration.recordApplied(target.deploymentID, failed.EndpointID, failedPeers, nil, failedPeers.targetHealth.Version)
	beforeSecond := h.scheduler.monitor().Snapshot(failed.EndpointID)
	close(blocked.release)
	oldPeer := <-peerObserved
	if oldPeer.Err != nil || !oldPeer.Correct {
		t.Fatalf("delayed peer success did not apply: %+v", oldPeer)
	}
	prober.corroboration.mu.Lock()
	stored := prober.corroboration.deployments[target.deploymentID].successes[peer.EndpointID]
	prober.corroboration.mu.Unlock()
	if !stored.at.Equal(completedBeforeFailure) {
		t.Fatalf("peer completion was re-stamped: stored=%v want=%v", stored.at, completedBeforeFailure)
	}

	prober.probe = fixedProbeResult{result: validator.ProbeResult{
		At: failureAt.Add(2 * time.Second), Error: "shared edge unavailable",
	}}
	suppressed := prober.observe(context.Background(), target, failed)
	if !suppressed.CommonModeSuppressed || suppressed.Action != (policy.Action{}) {
		t.Fatalf("pre-failure peer success authorized destructive action: %+v", suppressed)
	}
	if after := h.scheduler.monitor().Snapshot(failed.EndpointID); after != beforeSecond {
		t.Fatalf("suppressed shared-path failure mutated health: before=%+v after=%+v", beforeSecond, after)
	}
	if !contains(activeMinerIDs(h.scheduler, target.deploymentID), failed.MinerID) {
		t.Fatal("pre-failure peer success evicted the target")
	}

	completedAfterFailure := failureAt.Add(3 * time.Second)
	prober.probe = fixedProbeResult{result: validator.ProbeResult{
		At: completedAfterFailure, Status: 200, Correct: true,
		ServedByReplica: true, ResponseComplete: true,
	}}
	if freshPeer := prober.observe(context.Background(), target, peer); freshPeer.Err != nil || !freshPeer.Correct {
		t.Fatalf("post-failure peer success did not apply: %+v", freshPeer)
	}
	prober.probe = fixedProbeResult{result: validator.ProbeResult{
		At: failureAt.Add(4 * time.Second), Error: "isolated target unavailable",
	}}
	removed := prober.observe(context.Background(), target, failed)
	if !removed.Action.RemoveFromRouting || removed.CommonModeSuppressed {
		t.Fatalf("fresh post-failure success did not authorize isolated eviction: %+v", removed)
	}
	if h.scheduler.Ledger.Trust(failed.MinerID) == 0 {
		t.Fatal("internal liveness eviction became economic trust-zero")
	}
	h.cleanup(t)
	deactivated = true
}

func TestProbeWithoutTerminalTimestampCannotMutateHealth(t *testing.T) {
	h, _, _, _ := newProbedHarness(t)
	deactivated := false
	defer func() {
		if !deactivated {
			h.cleanup(t)
		}
	}()
	target := h.scheduler.probeTargets()[0]
	replica := target.replicas[0]
	before := h.scheduler.monitor().Snapshot(replica.EndpointID)
	prober := &Prober{
		Scheduler: h.scheduler,
		probe: unstampedProbeResult{result: validator.ProbeResult{
			Status: 200, Correct: true, ServedByReplica: true, ResponseComplete: true,
		}},
		Vantage: "periodic-test",
	}
	outcome := prober.observe(context.Background(), target, replica)
	if !errors.Is(outcome.Err, errProbeTimestampZero) || !outcome.CommonModeSuppressed || outcome.Action != (policy.Action{}) {
		t.Fatalf("unstamped result was not suppressed: %+v", outcome)
	}
	if after := h.scheduler.monitor().Snapshot(replica.EndpointID); after != before {
		t.Fatalf("unstamped result mutated health: before=%+v after=%+v", before, after)
	}
	h.cleanup(t)
	deactivated = true
}

func TestExternalHealthRevisionCannotMaskInFlightLocalSuppression(t *testing.T) {
	h, _, _, _ := newProbedHarness(t)
	deactivated := false
	defer func() {
		if !deactivated {
			h.cleanup(t)
		}
	}()
	target := h.scheduler.probeTargets()[0]
	replica := target.replicas[0]
	dark := validator.ProbeResult{Status: 0, Correct: false, ResponseComplete: false, Error: "connection refused"}
	probe := &staleBlockingProber{started: make(chan struct{}), release: make(chan struct{}), result: &dark}
	prober := &Prober{Scheduler: h.scheduler, probe: probe, Vantage: "periodic-test"}
	observed := make(chan ProbeOutcome, 1)
	go func() { observed <- prober.observe(context.Background(), target, replica) }()
	<-probe.started

	if action, err := h.scheduler.HandleHealth(
		context.Background(), target.deploymentID, replica.ReplicaID, replica.EndpointID, replica.MinerID,
		"external-health", true, true, false, time.Now().UTC(),
	); err != nil || action != (policy.Action{}) {
		t.Fatalf("external health update failed: action=%+v err=%v", action, err)
	}
	close(probe.release)
	outcome := <-observed
	if !outcome.CommonModeSuppressed || !outcome.RoutingSuppressed || !errors.Is(outcome.Err, errHealthObservationChanged) {
		t.Fatalf("external policy revision masked local route failure: %+v", outcome)
	}
	if routedHealthy(h.scheduler, target.deploymentID, replica.MinerID) {
		t.Fatal("locally unreachable endpoint remained in traffic after concurrent external report")
	}
	if !contains(activeMinerIDs(h.scheduler, target.deploymentID), replica.MinerID) || h.scheduler.Ledger.Trust(replica.MinerID) == 0 {
		t.Fatal("route-local suppression changed eligibility or economic trust")
	}
	h.cleanup(t)
	deactivated = true
}

func TestExternalHealthRevisionCannotMaskInFlightLocalRecovery(t *testing.T) {
	h, _, _, _ := newProbedHarness(t)
	deactivated := false
	defer func() {
		if !deactivated {
			h.cleanup(t)
		}
	}()
	target := h.scheduler.probeTargets()[0]
	replica := target.replicas[0]
	if changed, applied, err := h.scheduler.suppressEndpointAvailabilityIfVersion(
		context.Background(), target.deploymentID, replica.ReplicaID, replica.EndpointID, replica.MinerID, 0,
	); err != nil || !applied || !changed {
		t.Fatalf("failed to establish suppressed route: changed=%v applied=%v err=%v", changed, applied, err)
	}
	healthy := validator.ProbeResult{Status: 200, Correct: true, ServedByReplica: true, ResponseComplete: true}
	probe := &staleBlockingProber{started: make(chan struct{}), release: make(chan struct{}), result: &healthy}
	prober := &Prober{Scheduler: h.scheduler, probe: probe, Vantage: "periodic-test"}
	observed := make(chan ProbeOutcome, 1)
	go func() { observed <- prober.observe(context.Background(), target, replica) }()
	<-probe.started

	if _, err := h.scheduler.HandleHealth(
		context.Background(), target.deploymentID, replica.ReplicaID, replica.EndpointID, replica.MinerID,
		"external-health", true, true, false, time.Now().UTC(),
	); err != nil {
		t.Fatalf("external health update failed: %v", err)
	}
	close(probe.release)
	outcome := <-observed
	if !outcome.CommonModeSuppressed || !outcome.RoutingRestored || !errors.Is(outcome.Err, errHealthObservationChanged) {
		t.Fatalf("external policy revision masked local route recovery: %+v", outcome)
	}
	if !routedHealthy(h.scheduler, target.deploymentID, replica.MinerID) {
		t.Fatal("complete targeted recovery did not restore traffic")
	}
	h.cleanup(t)
	deactivated = true
}

func TestNewerNoopLocalSuccessFencesOlderFailure(t *testing.T) {
	h, _, _, _ := newProbedHarness(t)
	deactivated := false
	defer func() {
		if !deactivated {
			h.cleanup(t)
		}
	}()
	target := h.scheduler.probeTargets()[0]
	replica := target.replicas[0]
	dark := validator.ProbeResult{Status: 0, Correct: false, ResponseComplete: false, Error: "connection refused"}
	oldProbe := &staleBlockingProber{started: make(chan struct{}), release: make(chan struct{}), result: &dark}
	oldProber := &Prober{Scheduler: h.scheduler, probe: oldProbe, Vantage: "periodic-old"}
	oldObserved := make(chan ProbeOutcome, 1)
	go func() { oldObserved <- oldProber.observe(context.Background(), target, replica) }()
	<-oldProbe.started

	newProber := &Prober{Scheduler: h.scheduler, probe: fixedProbeResult{result: validator.ProbeResult{
		Status: 200, Correct: true, ServedByReplica: true, ResponseComplete: true,
	}}, Vantage: "periodic-new"}
	newOutcome := newProber.observe(context.Background(), target, replica)
	if newOutcome.Err != nil || newOutcome.RoutingRestored {
		t.Fatalf("newer already-healthy result failed or reported a state change: %+v", newOutcome)
	}
	close(oldProbe.release)
	oldOutcome := <-oldObserved
	if !oldOutcome.CommonModeSuppressed || !errors.Is(oldOutcome.Err, errHealthObservationChanged) {
		t.Fatalf("older failure was not fenced by newer no-op success: %+v", oldOutcome)
	}
	if !routedHealthy(h.scheduler, target.deploymentID, replica.MinerID) {
		t.Fatal("older failure suppressed route after newer successful probe")
	}
	h.cleanup(t)
	deactivated = true
}

func TestNewerNoopLocalFailureFencesOlderRecovery(t *testing.T) {
	h, _, _, _ := newProbedHarness(t)
	deactivated := false
	defer func() {
		if !deactivated {
			h.cleanup(t)
		}
	}()
	target := h.scheduler.probeTargets()[0]
	replica := target.replicas[0]
	if changed, applied, err := h.scheduler.suppressEndpointAvailabilityIfVersion(
		context.Background(), target.deploymentID, replica.ReplicaID, replica.EndpointID, replica.MinerID, 0,
	); err != nil || !applied || !changed {
		t.Fatalf("failed to establish suppressed route: changed=%v applied=%v err=%v", changed, applied, err)
	}
	healthy := validator.ProbeResult{Status: 200, Correct: true, ServedByReplica: true, ResponseComplete: true}
	oldProbe := &staleBlockingProber{started: make(chan struct{}), release: make(chan struct{}), result: &healthy}
	oldProber := &Prober{Scheduler: h.scheduler, probe: oldProbe, Vantage: "periodic-old"}
	oldObserved := make(chan ProbeOutcome, 1)
	go func() { oldObserved <- oldProber.observe(context.Background(), target, replica) }()
	<-oldProbe.started

	newProber := &Prober{Scheduler: h.scheduler, probe: fixedProbeResult{result: validator.ProbeResult{
		Status: 0, Correct: false, ResponseComplete: false, Error: "connection refused",
	}}, Vantage: "periodic-new"}
	newOutcome := newProber.observe(context.Background(), target, replica)
	if !newOutcome.CommonModeSuppressed || newOutcome.RoutingSuppressed {
		t.Fatalf("newer already-suppressed failure had unexpected result: %+v", newOutcome)
	}
	close(oldProbe.release)
	oldOutcome := <-oldObserved
	if !oldOutcome.CommonModeSuppressed || !errors.Is(oldOutcome.Err, errHealthObservationChanged) {
		t.Fatalf("older recovery was not fenced by newer no-op failure: %+v", oldOutcome)
	}
	if routedHealthy(h.scheduler, target.deploymentID, replica.MinerID) {
		t.Fatal("older success restored route after newer failed probe")
	}
	h.cleanup(t)
	deactivated = true
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

func (p *cancellationBlockingProber) ProbeReplica(ctx context.Context, _, _, _, _ string) (result validator.ProbeResult) {
	defer func() {
		if result.At.IsZero() {
			result.At = time.Now().UTC()
		}
	}()
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

func (p *pacedProber) ProbeReplica(ctx context.Context, _, replicaID, _, _ string) (result validator.ProbeResult) {
	defer func() {
		if result.At.IsZero() {
			result.At = time.Now().UTC()
		}
	}()
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
