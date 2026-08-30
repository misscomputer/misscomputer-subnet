// SPDX-License-Identifier: AGPL-3.0-only

package campaign

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/protocol"
)

var testEpoch = time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)

func TestDefaultConfigIsInertAndMainnetOnly(t *testing.T) {
	config := DefaultConfig()
	if config.Enabled {
		t.Fatal("default campaign is enabled")
	}
	if config.Coverage.WindowMillis != int64((24*time.Hour)/time.Millisecond) || config.Coverage.MinimumChallengesPerMiner != 3 {
		t.Fatalf("default coverage does not guarantee three targeted assignments per 24h: %#v", config.Coverage)
	}
	if err := ValidateConfig(config); err != nil {
		t.Fatal(err)
	}
	engine, err := NewWithEntropy(config, testEpoch, newDeterministicReader())
	if err != nil {
		t.Fatal(err)
	}
	decision, err := engine.Schedule(testEpoch, []string{"Miner1"})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Reason != DecisionDisabled || len(engine.Snapshot().Challenges) != 0 {
		t.Fatalf("disabled decision=%#v state=%#v", decision, engine.Snapshot())
	}
	disabledDigest := engine.Snapshot().StateDigestSHA256
	if evidence, err := engine.Shutdown(testEpoch); err != nil || len(evidence) != 0 || engine.Snapshot().StateDigestSHA256 != disabledDigest {
		t.Fatalf("disabled shutdown evidence=%#v err=%v", evidence, err)
	}

	tests := []func(*Config){
		func(value *Config) { value.Network = "test" },
		func(value *Config) { value.NetUID = 1 },
		func(value *Config) { value.Domain = "campaign.example" },
		func(value *Config) { value.RequiredReplicas = 2 },
		func(value *Config) { value.Coverage.MinimumChallengesPerMiner = 2 },
		func(value *Config) { value.Coverage.WindowMillis = int64((30 * 24 * time.Hour) / time.Millisecond) },
		func(value *Config) { value.Cadence.MinimumDelayMillis = 0 },
		func(value *Config) { value.Limits.MaxConcurrent = 0 },
		func(value *Config) { value.Workloads[0].Kind = "https://credential.invalid" },
		func(value *Config) { value.Workloads[0].PayloadBytes = maximumPayloadBytes + 1 },
	}
	for index, mutate := range tests {
		candidate := DefaultConfig()
		candidate.Workloads = append([]WorkloadPolicy(nil), candidate.Workloads...)
		mutate(&candidate)
		if err := ValidateConfig(candidate); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("case %d error=%v", index, err)
		}
	}
}

func TestDeterministicMixFairnessAndUniqueDNSIdentity(t *testing.T) {
	config := testConfig()
	engine, err := NewWithEntropy(config, testEpoch, newDeterministicReader())
	if err != nil {
		t.Fatal(err)
	}
	miners := []string{"Miner4", "Miner2", "Miner1", "Miner3"}
	wantTargets := []string{"Miner1", "Miner2", "Miner3", "Miner4", "Miner1"}
	wantKinds := []string{"static", "static", "node", "static", "static"}
	seenDeployments := make(map[string]struct{})
	seenBuilds := make(map[string]struct{})
	seenChallenges := make(map[string]struct{})
	now := testEpoch
	for index := range wantTargets {
		decision, scheduleErr := engine.Schedule(now, miners)
		if scheduleErr != nil {
			t.Fatal(scheduleErr)
		}
		if decision.Reason != DecisionScheduled || decision.Challenge == nil {
			t.Fatalf("schedule %d=%#v", index, decision)
		}
		challenge := *decision.Challenge
		if challenge.CoverageTargetMiner != wantTargets[index] || challenge.Workload.Kind != wantKinds[index] {
			t.Fatalf("challenge %d target/kind=%s/%s want=%s/%s", index, challenge.CoverageTargetMiner, challenge.Workload.Kind, wantTargets[index], wantKinds[index])
		}
		if !validDNSLabel(challenge.DeploymentID) || challenge.RouteHost != challenge.DeploymentID+"."+MainnetDomain {
			t.Fatalf("unsafe generated route: %#v", challenge)
		}
		assertNewIdentity(t, seenDeployments, challenge.DeploymentID)
		assertNewIdentity(t, seenBuilds, challenge.Workload.BuildID)
		assertNewIdentity(t, seenChallenges, challenge.ChallengeSHA256)
		startAt := now.Add(time.Millisecond)
		started, startErr := engine.StartNext(startAt)
		if startErr != nil || started.Reason != DecisionStarted || started.Challenge == nil || started.Challenge.Sequence != challenge.Sequence {
			t.Fatalf("start=%#v err=%v", started, startErr)
		}
		acceptRequired(t, engine, *started.Challenge, startAt.Add(time.Second))
		if _, completeErr := engine.Complete(challenge.Sequence, startAt.Add(2*time.Second), OutcomeSucceeded, FailureNone); completeErr != nil {
			t.Fatal(completeErr)
		}
		now = startAt.Add(2 * time.Second)
	}
	state := engine.Snapshot()
	if err := VerifyState(config, state); err != nil {
		t.Fatal(err)
	}
	for _, coverage := range state.Coverage {
		if coverage.MinerHotkey == "Miner1" {
			if coverage.LifetimeScheduled != 2 || coverage.LifetimeSucceeded != 2 {
				t.Fatalf("Miner1 coverage=%#v", coverage)
			}
		} else if coverage.LifetimeScheduled != 1 || coverage.LifetimeSucceeded != 1 {
			t.Fatalf("coverage=%#v", coverage)
		}
	}
}

func TestCadenceAndBackpressureAreBounded(t *testing.T) {
	config := testConfig()
	config.Limits.MaxConcurrent = 1
	config.Limits.MaxPending = 1
	config.Limits.RetainedTerminalChallenges = 4
	config.Cadence.MinimumDelayMillis = 1_000
	config.Cadence.MaximumDelayMillis = 2_000
	engine, err := NewWithEntropy(config, testEpoch, newDeterministicReader())
	if err != nil {
		t.Fatal(err)
	}
	before := engine.Snapshot().StateDigestSHA256
	if _, err := engine.Schedule(testEpoch.Add(24*time.Hour), []string{"Miner1", "Miner1", "Miner2"}); !errors.Is(err, ErrInvalidMinerSet) || engine.Snapshot().StateDigestSHA256 != before {
		t.Fatalf("duplicate miner error=%v", err)
	}
	insufficient, err := engine.Schedule(testEpoch.Add(24*time.Hour), []string{"Miner1", "Miner2"})
	if err != nil || insufficient.Reason != DecisionInsufficientMiners || engine.Snapshot().StateDigestSHA256 != before {
		t.Fatalf("insufficient miner decision=%#v err=%v", insufficient, err)
	}
	first, err := engine.Schedule(testEpoch.Add(24*time.Hour), []string{"Miner1", "Miner2", "Miner3"})
	if err != nil || first.Reason != DecisionScheduled {
		t.Fatalf("first=%#v err=%v", first, err)
	}
	delay := first.NextDueAt.Sub(testEpoch.Add(24 * time.Hour))
	if delay < time.Second || delay > 2*time.Second {
		t.Fatalf("jitter=%s outside configured bounds", delay)
	}
	blocked, err := engine.Schedule(*first.NextDueAt, []string{"Miner1", "Miner2", "Miner3"})
	if err != nil || blocked.Reason != DecisionPendingBackpressure {
		t.Fatalf("pending backpressure=%#v err=%v", blocked, err)
	}
	started, err := engine.StartNext(first.Challenge.ScheduledAt.Add(time.Millisecond))
	if err != nil || started.Reason != DecisionStarted {
		t.Fatalf("start=%#v err=%v", started, err)
	}
	second, err := engine.Schedule(*first.NextDueAt, []string{"Miner1", "Miner2", "Miner3"})
	if err != nil || second.Reason != DecisionScheduled {
		t.Fatalf("second=%#v err=%v", second, err)
	}
	concurrent, err := engine.StartNext(*first.NextDueAt)
	if err != nil || concurrent.Reason != DecisionConcurrencyBackpressure {
		t.Fatalf("concurrency backpressure=%#v err=%v", concurrent, err)
	}
}

func TestTrackedMinerCapacityIsExplicitBackpressure(t *testing.T) {
	config := testConfig()
	config.Limits.MaxTrackedMiners = 3
	engine, err := NewWithEntropy(config, testEpoch, newDeterministicReader())
	if err != nil {
		t.Fatal(err)
	}
	before := engine.Snapshot().StateDigestSHA256
	tooMany, err := engine.Schedule(testEpoch, []string{"Miner1", "Miner2", "Miner3", "Miner4"})
	if err != nil || tooMany.Reason != DecisionTrackedMinerBackpressure || engine.Snapshot().StateDigestSHA256 != before {
		t.Fatalf("oversized miner inventory decision=%+v err=%v", tooMany, err)
	}
	if _, err := engine.Schedule(testEpoch, []string{"Miner1", "Miner1", "Miner3", "Miner4"}); !errors.Is(err, ErrInvalidMinerSet) ||
		engine.Snapshot().StateDigestSHA256 != before {
		t.Fatalf("oversized malformed miner inventory error=%v", err)
	}

	first, err := engine.Schedule(testEpoch, []string{"Miner1", "Miner2", "Miner3"})
	if err != nil || first.Reason != DecisionScheduled || first.NextDueAt == nil {
		t.Fatalf("first decision=%+v err=%v", first, err)
	}
	afterFirst := engine.Snapshot().StateDigestSHA256
	turnover, err := engine.Schedule(*first.NextDueAt, []string{"Miner4", "Miner5", "Miner6"})
	if err != nil || turnover.Reason != DecisionTrackedMinerBackpressure || engine.Snapshot().StateDigestSHA256 != afterFirst {
		t.Fatalf("outstanding coverage turnover decision=%+v err=%v", turnover, err)
	}
}

func TestConcurrentAdmissionCannotExceedBounds(t *testing.T) {
	config := testConfig()
	config.Limits.MaxPending = 2
	config.Limits.MaxConcurrent = 1
	config.Limits.RetainedTerminalChallenges = 4
	engine, err := NewWithEntropy(config, testEpoch, newDeterministicReader())
	if err != nil {
		t.Fatal(err)
	}
	miners := []string{"Miner1", "Miner2", "Miner3"}
	var wait sync.WaitGroup
	for index := 0; index < 32; index++ {
		wait.Add(1)
		go func(offset int) {
			defer wait.Done()
			_, _ = engine.Schedule(testEpoch.Add(time.Duration(offset+1)*time.Hour), miners)
		}(index)
	}
	wait.Wait()
	state := engine.Snapshot()
	if countStatus(state.Challenges, StatusPending) > config.Limits.MaxPending {
		t.Fatalf("pending count exceeded bound: %#v", state.Challenges)
	}
	if err := VerifyState(config, state); err != nil {
		t.Fatal(err)
	}
}

func TestPauseDrainAndShutdownSemantics(t *testing.T) {
	config := testConfig()
	engine, err := NewWithEntropy(config, testEpoch, newDeterministicReader())
	if err != nil {
		t.Fatal(err)
	}
	miners := []string{"Miner1", "Miner2", "Miner3"}
	first, _ := engine.Schedule(testEpoch, miners)
	started, _ := engine.StartNext(testEpoch.Add(time.Millisecond))
	second, _ := engine.Schedule(*first.NextDueAt, miners)
	if err := engine.Pause(*first.NextDueAt); err != nil {
		t.Fatal(err)
	}
	if decision, _ := engine.Schedule(*first.NextDueAt, miners); decision.Reason != DecisionPaused {
		t.Fatalf("paused schedule=%#v", decision)
	}
	if decision, _ := engine.StartNext(*first.NextDueAt); decision.Reason != DecisionPaused {
		t.Fatalf("paused start=%#v", decision)
	}
	if err := engine.Resume(*first.NextDueAt); err != nil {
		t.Fatal(err)
	}
	cancelled, err := engine.Drain(first.NextDueAt.Add(time.Millisecond))
	if err != nil || len(cancelled) != 1 || cancelled[0].Sequence != second.Challenge.Sequence || cancelled[0].FailureCode != FailureOperatorDrain {
		t.Fatalf("drain evidence=%#v err=%v", cancelled, err)
	}
	if engine.Snapshot().Mode != ModeDraining {
		t.Fatalf("mode=%s want draining", engine.Snapshot().Mode)
	}
	if _, err := engine.Complete(started.Challenge.Sequence, first.NextDueAt.Add(2*time.Millisecond), OutcomeFailed, FailureInternal); err != nil {
		t.Fatal(err)
	}
	if engine.Snapshot().Mode != ModePaused || engine.Snapshot().NextDueAt != nil {
		t.Fatalf("drain did not settle paused: %#v", engine.Snapshot())
	}
	if err := engine.Resume(first.NextDueAt.Add(3 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	third, _ := engine.Schedule(first.NextDueAt.Add(3*time.Millisecond), miners)
	thirdStarted, _ := engine.StartNext(first.NextDueAt.Add(4 * time.Millisecond))
	if third.Challenge.Sequence != thirdStarted.Challenge.Sequence {
		t.Fatal("unexpected pending challenge started")
	}
	if _, err := engine.Shutdown(first.NextDueAt.Add(5 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if engine.Snapshot().Mode != ModeShuttingDown {
		t.Fatalf("mode=%s want shutting_down", engine.Snapshot().Mode)
	}
	if _, err := engine.Complete(third.Challenge.Sequence, first.NextDueAt.Add(6*time.Millisecond), OutcomeFailed, FailureCancelled); err != nil {
		t.Fatal(err)
	}
	if engine.Snapshot().Mode != ModeStopped {
		t.Fatalf("mode=%s want stopped", engine.Snapshot().Mode)
	}
	if decision, _ := engine.Schedule(first.NextDueAt.Add(time.Second), miners); decision.Reason != DecisionStopped {
		t.Fatalf("stopped schedule=%#v", decision)
	}
}

func TestAcceptedTicketBindingFailsClosedAndEvidenceIsCredentialSafe(t *testing.T) {
	config := testConfig()
	engine, err := NewWithEntropy(config, testEpoch, newDeterministicReader())
	if err != nil {
		t.Fatal(err)
	}
	scheduled, _ := engine.Schedule(testEpoch, []string{"Miner1", "Miner2", "Miner3", "Miner4"})
	started, _ := engine.StartNext(testEpoch.Add(time.Millisecond))
	challenge := *started.Challenge
	base := validTicket(challenge, "Other1", 1, testEpoch.Add(time.Second))
	before := engine.Snapshot().StateDigestSHA256
	if _, err := engine.Complete(challenge.Sequence, testEpoch.Add(2*time.Second), OutcomeFailed, FailureDeadline); !errors.Is(err, ErrInvalidCompletion) || engine.Snapshot().StateDigestSHA256 != before {
		t.Fatalf("early deadline completion error=%v", err)
	}

	mutations := []func(*protocol.Ticket){
		func(value *protocol.Ticket) { value.DeploymentID = "other" },
		func(value *protocol.Ticket) { value.RouteHost = "other." + MainnetDomain },
		func(value *protocol.Ticket) { value.Generation = 0 },
		func(value *protocol.Ticket) { value.AssignmentNonce = "nonce" },
		func(value *protocol.Ticket) { value.ChallengePath = "/__challenge/wrong" },
		func(value *protocol.Ticket) { value.ChallengeSHA256 = strings.Repeat("0", 64) },
		func(value *protocol.Ticket) { value.ManifestKey = "v1/manifests/wrong.json" },
		func(value *protocol.Ticket) { value.Subnet.Network = "test" },
		func(value *protocol.Ticket) { value.Subnet.MinerHotkey = "Other2" },
	}
	for index, mutate := range mutations {
		candidate := cloneTicket(base)
		mutate(&candidate)
		before := engine.Snapshot().StateDigestSHA256
		if err := engine.RecordAcceptedTicket(challenge.Sequence, candidate, testEpoch.Add(time.Second)); !errors.Is(err, ErrInvalidAssignment) {
			t.Errorf("mutation %d error=%v", index, err)
		}
		if engine.Snapshot().StateDigestSHA256 != before {
			t.Fatalf("mutation %d changed state", index)
		}
	}

	acceptedAt := testEpoch.Add(time.Second)
	for index, miner := range []string{"Other1", "Other2"} {
		ticket := validTicket(challenge, miner, uint64(index+1), acceptedAt.Add(time.Duration(index)*time.Millisecond))
		if err := engine.RecordAcceptedTicket(challenge.Sequence, ticket, ticket.IssuedAt.Add(time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	mismatchedArtifact := validTicket(challenge, "Other4", 8, testEpoch.Add(1400*time.Millisecond))
	mismatchedArtifact.ImageDigest = "sha256:" + strings.Repeat("d", 64)
	mismatchedArtifact.ManifestKey = manifestKey(mismatchedArtifact.ImageDigest)
	before = engine.Snapshot().StateDigestSHA256
	if err := engine.RecordAcceptedTicket(challenge.Sequence, mismatchedArtifact, testEpoch.Add(1400*time.Millisecond)); !errors.Is(err, ErrInvalidAssignment) || engine.Snapshot().StateDigestSHA256 != before {
		t.Fatalf("cross-artifact accepted ticket error=%v", err)
	}
	before = engine.Snapshot().StateDigestSHA256
	if _, err := engine.Complete(challenge.Sequence, testEpoch.Add(2*time.Second), OutcomeSucceeded, FailureNone); !errors.Is(err, ErrInvalidCompletion) {
		t.Fatalf("success without fairness target error=%v", err)
	}
	if engine.Snapshot().StateDigestSHA256 != before {
		t.Fatal("invalid completion changed state")
	}
	targetTicket := validTicket(challenge, challenge.CoverageTargetMiner, 9, testEpoch.Add(1500*time.Millisecond))
	if err := engine.RecordAcceptedTicket(challenge.Sequence, targetTicket, testEpoch.Add(1500*time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if err := engine.RecordAcceptedTicket(challenge.Sequence, targetTicket, testEpoch.Add(1600*time.Millisecond)); !errors.Is(err, ErrInvalidAssignment) {
		t.Fatalf("duplicate accepted ticket error=%v", err)
	}
	fourthTicket := validTicket(challenge, "Other4", 10, testEpoch.Add(1700*time.Millisecond))
	before = engine.Snapshot().StateDigestSHA256
	if err := engine.RecordAcceptedTicket(challenge.Sequence, fourthTicket, testEpoch.Add(1700*time.Millisecond)); !errors.Is(err, ErrInvalidAssignment) || engine.Snapshot().StateDigestSHA256 != before {
		t.Fatalf("fourth accepted ticket error=%v", err)
	}
	before = engine.Snapshot().StateDigestSHA256
	if _, err := engine.Complete(challenge.Sequence, *challenge.DeadlineAt, OutcomeSucceeded, FailureNone); !errors.Is(err, ErrInvalidCompletion) || engine.Snapshot().StateDigestSHA256 != before {
		t.Fatalf("late success completion error=%v", err)
	}
	evidence, err := engine.Complete(challenge.Sequence, testEpoch.Add(2*time.Second), OutcomeSucceeded, FailureNone)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyEvidence(evidence); err != nil {
		t.Fatal(err)
	}
	if evidence.EvidenceDigestSHA256 != "336b8ec94acad7eb9f5571560fe340f83e706fe7ad816fb0409e10d5ddcdb8f6" {
		t.Fatalf("campaign evidence wire digest changed: %s", evidence.EvidenceDigestSHA256)
	}
	payload, err := MarshalEvidence(evidence)
	if err != nil {
		t.Fatal(err)
	}
	parsedEvidence, err := ParseEvidence(payload)
	if err != nil || parsedEvidence.EvidenceDigestSHA256 != evidence.EvidenceDigestSHA256 {
		t.Fatalf("parse evidence digest=%s err=%v", parsedEvidence.EvidenceDigestSHA256, err)
	}
	if _, err := ParseEvidence(append([]byte{' '}, payload...)); !errors.Is(err, ErrInvalidEvidence) {
		t.Fatalf("noncanonical evidence error=%v", err)
	}
	for _, forbidden := range []string{
		challenge.Workload.ChallengeValue,
		"8.8.8.8",
		strings.Repeat("a", 64),
		strings.Repeat("b", 64),
		"validator-service",
	} {
		if bytes.Contains(payload, []byte(forbidden)) {
			t.Fatalf("evidence leaked forbidden value %q", forbidden)
		}
	}
	if evidence.ScoringEffect != ScoringEffectNone || evidence.AcceptanceObservationSource != ScoringSourceExisting {
		t.Fatalf("unexpected scoring contract: %#v", evidence)
	}
	tampered := evidence
	tampered.Outcome = OutcomeFailed
	if err := VerifyEvidence(tampered); !errors.Is(err, ErrInvalidEvidence) {
		t.Fatalf("tampered evidence error=%v", err)
	}
	if scheduled.Challenge.Sequence != evidence.Sequence {
		t.Fatal("evidence sequence mismatch")
	}
}

func TestStateRoundTripTamperAndEntropyFailures(t *testing.T) {
	config := testConfig()
	engine, err := NewWithEntropy(config, testEpoch, newDeterministicReader())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Schedule(testEpoch, []string{"Miner1", "Miner2", "Miner3"}); err != nil {
		t.Fatal(err)
	}
	state := engine.Snapshot()
	if state.StateDigestSHA256 != "c25d47c740900c8b9c91e7ff2e5c25da9efefcb389e5e9d3f5b93e6c6bd330f4" {
		t.Fatalf("campaign state wire digest changed: %s", state.StateDigestSHA256)
	}
	payload, err := MarshalState(config, state)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseState(config, payload)
	if err != nil || parsed.StateDigestSHA256 != state.StateDigestSHA256 {
		t.Fatalf("parse digest=%s err=%v", parsed.StateDigestSHA256, err)
	}
	if _, err := RestoreWithEntropy(config, parsed, newDeterministicReader()); err != nil {
		t.Fatal(err)
	}

	tampered := cloneState(state)
	tampered.Challenges[0].Workload.ChallengeValue = strings.Repeat("f", 64)
	if err := VerifyState(config, tampered); !errors.Is(err, ErrStateDigestMismatch) {
		t.Fatalf("tampered state error=%v", err)
	}
	if _, err := SealState(config, tampered); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("resealed inconsistent state error=%v", err)
	}
	nullCollections := cloneState(state)
	nullCollections.Challenges = nil
	if _, err := SealState(config, nullCollections); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("null state collection error=%v", err)
	}
	noncanonical := append([]byte{' '}, payload...)
	if _, err := ParseState(config, noncanonical); !errors.Is(err, ErrInvalidStateBytes) {
		t.Fatalf("noncanonical parse error=%v", err)
	}
	unknown := bytes.Replace(payload, []byte(`"version":`), []byte(`"unknown":1,"version":`), 1)
	if _, err := ParseState(config, unknown); !errors.Is(err, ErrInvalidStateBytes) {
		t.Fatalf("unknown field parse error=%v", err)
	}

	failing, err := NewWithEntropy(config, testEpoch, secretErrorReader{})
	if err != nil {
		t.Fatal(err)
	}
	before := failing.Snapshot().StateDigestSHA256
	_, err = failing.Schedule(testEpoch, []string{"Miner1", "Miner2", "Miner3"})
	if !errors.Is(err, ErrEntropyUnavailable) || strings.Contains(err.Error(), "super-secret") || failing.Snapshot().StateDigestSHA256 != before {
		t.Fatalf("unsafe entropy error=%q state_changed=%v", err, failing.Snapshot().StateDigestSHA256 != before)
	}

	constant, err := NewWithEntropy(config, testEpoch, zeroReader{})
	if err != nil {
		t.Fatal(err)
	}
	first, err := constant.Schedule(testEpoch, []string{"Miner1", "Miner2", "Miner3"})
	if err != nil {
		t.Fatal(err)
	}
	before = constant.Snapshot().StateDigestSHA256
	_, err = constant.Schedule(*first.NextDueAt, []string{"Miner1", "Miner2", "Miner3"})
	if !errors.Is(err, ErrIdentityCollision) || constant.Snapshot().StateDigestSHA256 != before {
		t.Fatalf("collision error=%v state_changed=%v", err, constant.Snapshot().StateDigestSHA256 != before)
	}
}

func testConfig() Config {
	config := DefaultConfig()
	config.Enabled = true
	config.Cadence = CadencePolicy{MinimumDelayMillis: 1_000, MaximumDelayMillis: 1_000}
	config.Limits = LimitPolicy{
		MaxConcurrent: 2, MaxPending: 3, MaxTrackedMiners: 16,
		ChallengeTimeoutMillis: 10_000, RetainedTerminalChallenges: 8,
	}
	config.Coverage = CoveragePolicy{WindowMillis: int64((24 * time.Hour) / time.Millisecond), MinimumChallengesPerMiner: 3}
	config.Workloads = []WorkloadPolicy{
		{Kind: "static", PayloadBytes: 1024, Weight: 2},
		{Kind: "node", PayloadBytes: 2048, Weight: 1},
	}
	return config
}

func acceptRequired(t *testing.T, engine *Engine, challenge Challenge, at time.Time) {
	t.Helper()
	miners := []string{challenge.CoverageTargetMiner}
	for _, candidate := range []string{"Miner1", "Miner2", "Miner3", "Miner4", "Miner5"} {
		if candidate != challenge.CoverageTargetMiner && len(miners) < 3 {
			miners = append(miners, candidate)
		}
	}
	for index, miner := range miners {
		acceptedAt := at.Add(time.Duration(index) * time.Millisecond)
		nonce := challenge.Sequence*100 + uint64(index+1)
		if err := engine.RecordAcceptedTicket(challenge.Sequence, validTicket(challenge, miner, nonce, acceptedAt), acceptedAt); err != nil {
			t.Fatal(err)
		}
	}
}

func validTicket(challenge Challenge, miner string, nonce uint64, at time.Time) protocol.Ticket {
	uid := uint16(nonce)
	pin := strings.Repeat("a", 64)
	imageDigest := "sha256:" + strings.Repeat("c", 64)
	return protocol.Ticket{
		Version: protocol.BoundVersion, DeploymentID: challenge.DeploymentID, Generation: 1,
		ImageDigest: imageDigest, ManifestKey: manifestKey(imageDigest), MinerID: miner,
		RouteHost: challenge.RouteHost, AssignmentNonce: fmt.Sprintf("%032x", nonce),
		ChallengePath: challenge.Workload.ChallengePath, ChallengeSHA256: challenge.ChallengeSHA256,
		IssuedAt: at.Add(-time.Second).UTC(), ExpiresAt: at.Add(time.Minute).UTC(),
		Subnet: &protocol.SubnetBinding{
			Network: MainnetNetwork, NetUID: MainnetNetUID, ValidatorHotkey: "Validator1", MinerHotkey: miner, MinerUID: &uid,
			MinerAxonURL: "https://8.8.8.8:443", MinerTransport: "https", MinerTLSCertificateSHA256: &pin,
			ChainBlock: 100, Epoch: 1, ExpiresAtBlock: 200,
			ValidatorServicePublicKey: strings.Repeat("a", 64), MinerServicePublicKey: strings.Repeat("b", 64),
		},
	}
}

func cloneTicket(ticket protocol.Ticket) protocol.Ticket {
	copyTicket := ticket
	if ticket.Subnet != nil {
		binding := *ticket.Subnet
		if ticket.Subnet.MinerUID != nil {
			uid := *ticket.Subnet.MinerUID
			binding.MinerUID = &uid
		}
		if ticket.Subnet.MinerTLSCertificateSHA256 != nil {
			pin := *ticket.Subnet.MinerTLSCertificateSHA256
			binding.MinerTLSCertificateSHA256 = &pin
		}
		copyTicket.Subnet = &binding
	}
	return copyTicket
}

func assertNewIdentity(t *testing.T, seen map[string]struct{}, value string) {
	t.Helper()
	if _, exists := seen[value]; exists {
		t.Fatalf("duplicate identity %q", value)
	}
	seen[value] = struct{}{}
}

type deterministicReader struct {
	counter uint64
	buffer  []byte
}

func newDeterministicReader() *deterministicReader { return &deterministicReader{} }

func (reader *deterministicReader) Read(target []byte) (int, error) {
	written := 0
	for written < len(target) {
		if len(reader.buffer) == 0 {
			var encoded [8]byte
			binary.BigEndian.PutUint64(encoded[:], reader.counter)
			digest := sha256.Sum256(encoded[:])
			reader.buffer = append(reader.buffer[:0], digest[:]...)
			reader.counter++
		}
		count := copy(target[written:], reader.buffer)
		written += count
		reader.buffer = reader.buffer[count:]
	}
	return written, nil
}

type zeroReader struct{}

func (zeroReader) Read(target []byte) (int, error) {
	clear(target)
	return len(target), nil
}

type secretErrorReader struct{}

func (secretErrorReader) Read([]byte) (int, error) {
	return 0, errors.New("https://user:super-secret@storage.invalid/private")
}
