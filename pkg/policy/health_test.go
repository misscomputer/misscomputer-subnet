// SPDX-License-Identifier: AGPL-3.0-only

package policy

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestHealthPolicy(t *testing.T) {
	m := NewMonitor()
	now := time.Now()
	if got := m.Observe("r1", "a", false, false, false, now); got.RemoveFromRouting {
		t.Fatal("removed after one network failure")
	}
	if got := m.Observe("r1", "a", false, false, false, now.Add(time.Second)); !got.RemoveFromRouting || got.TrustZero {
		t.Fatalf("second rapid failure action = %+v", got)
	}
	m.Observe("r1", "b", false, false, false, now.Add(2*time.Second))
	if got := m.Observe("r1", "b", false, false, false, now.Add(3*time.Second)); !got.TrustZero {
		t.Fatal("corroborated repeated failures did not zero trust")
	}
	if got := m.Observe("r2", "a", true, false, false, now); !got.TrustZero || !got.RemoveFromRouting {
		t.Fatal("incorrect challenge did not zero trust")
	}
}

func TestHealthStateDoesNotBleedAcrossEndpointIncarnations(t *testing.T) {
	m := NewMonitor()
	now := time.Now()
	if got := m.Observe("endpoint-g1-nonce-a", "a", false, false, false, now); got.RemoveFromRouting {
		t.Fatal("old incarnation removed after one failure")
	}
	if got := m.Observe("endpoint-g2-nonce-b", "a", false, false, false, now.Add(time.Second)); got.RemoveFromRouting {
		t.Fatalf("new incarnation inherited old failure counter: %+v", got)
	}
	if got := m.Observe("endpoint-g2-nonce-b", "a", false, false, false, now.Add(2*time.Second)); !got.RemoveFromRouting {
		t.Fatal("new incarnation did not count its own second failure")
	}
}

func TestForgetReleasesEndpointState(t *testing.T) {
	m := NewMonitor()
	now := time.Now()
	if got := m.Observe("e1", "a", false, false, false, now); got.RemoveFromRouting {
		t.Fatalf("first failure removed endpoint: %+v", got)
	}
	m.Forget("e1")
	if got := m.Observe("e1", "a", false, false, false, now.Add(time.Second)); got.RemoveFromRouting {
		t.Fatalf("forgotten endpoint inherited rapid-failure state: %+v", got)
	}
	m.Forget("e1")
	m.Forget("never-observed")
	m.mu.Lock()
	remaining := len(m.states)
	m.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("states retained after Forget: %d", remaining)
	}
}

func TestVersionedObservationRejectsChangedHealthHistory(t *testing.T) {
	m := NewMonitor()
	now := time.Now()
	initial := m.Snapshot("e1")
	if initial.Version != 0 || !initial.LastFailure.IsZero() {
		t.Fatalf("unexpected initial snapshot: %+v", initial)
	}
	if action, applied := m.ObserveIfVersion("e1", "internal", true, true, false, now, initial.Version); !applied || action != (Action{}) {
		t.Fatalf("initial versioned observation: action=%+v applied=%v", action, applied)
	}
	stale := m.Snapshot("e1")
	if action := m.Observe("e1", "external", false, false, false, now.Add(time.Second)); action != (Action{}) {
		t.Fatalf("external first failure action=%+v", action)
	}
	if action, applied := m.ObserveIfVersion("e1", "internal", false, false, false, now.Add(2*time.Second), stale.Version); applied || action != (Action{}) {
		t.Fatalf("stale version mutated health: action=%+v applied=%v", action, applied)
	}
	current := m.Snapshot("e1")
	if current.Version != stale.Version+1 || !current.LastFailure.Equal(now.Add(time.Second)) {
		t.Fatalf("stale observation changed snapshot: stale=%+v current=%+v", stale, current)
	}
}

func TestVersionedObservationCancelledWhileWaitingForMonitorDoesNotMutate(t *testing.T) {
	m := NewMonitor()
	now := time.Now().UTC()
	if action, applied := m.ObserveIfVersionContext(
		context.Background(), "endpoint-g1-nonce", "periodic", false, false, false, now, 0,
	); !applied || action.RemoveFromRouting {
		t.Fatalf("first internal failure: action=%+v applied=%v", action, applied)
	}
	before := m.Snapshot("endpoint-g1-nonce")

	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	result := make(chan struct {
		action  Action
		applied bool
	}, 1)
	m.mu.Lock()
	go func() {
		close(started)
		action, applied := m.ObserveIfVersionContext(
			ctx, "endpoint-g1-nonce", "periodic", false, false, false, now.Add(time.Second), before.Version,
		)
		result <- struct {
			action  Action
			applied bool
		}{action: action, applied: applied}
	}()
	<-started
	cancel()
	m.mu.Unlock()

	got := <-result
	if got.applied || got.action != (Action{}) {
		t.Fatalf("cancelled second failure produced policy action: action=%+v applied=%v", got.action, got.applied)
	}
	if after := m.Snapshot("endpoint-g1-nonce"); after != before {
		t.Fatalf("cancelled lock-wait mutated health: before=%+v after=%+v", before, after)
	}
}

func TestRapidRemovalDoesNotCombineInternalAndExternalSources(t *testing.T) {
	m := NewMonitor()
	now := time.Now()
	if action := m.ObserveInternal("e1", "periodic", false, false, false, now); action.RemoveFromRouting {
		t.Fatalf("first internal failure removed endpoint: %+v", action)
	}
	if action := m.Observe("e1", "external", false, false, false, now.Add(time.Second)); action.RemoveFromRouting {
		t.Fatalf("one internal plus one external failure removed endpoint: %+v", action)
	}
	if action := m.ObserveInternal("e1", "periodic", false, false, false, now.Add(2*time.Second)); !action.RemoveFromRouting {
		t.Fatalf("second internal failure lost routing authority: %+v", action)
	}

	m.Forget("e1")
	if action := m.Observe("e1", "external", false, false, false, now); action.RemoveFromRouting {
		t.Fatalf("first external failure removed endpoint: %+v", action)
	}
	if action := m.ObserveInternal("e1", "periodic", false, false, false, now.Add(time.Second)); action.RemoveFromRouting {
		t.Fatalf("one external plus one internal failure removed endpoint: %+v", action)
	}
	if action := m.Observe("e1", "external", false, false, false, now.Add(2*time.Second)); !action.RemoveFromRouting {
		t.Fatalf("second external failure lost routing authority: %+v", action)
	}
}

func TestExternalObservationRejectsReplayAndReorderingWithoutMutation(t *testing.T) {
	m := NewMonitor()
	now := time.Now().UTC()
	first, applied := m.ObserveExternalIfNewer("endpoint-g1-nonce", "validator-a", false, false, false, now)
	if !applied || first.RemoveFromRouting {
		t.Fatalf("first external observation: action=%+v applied=%v", first, applied)
	}
	before := m.Snapshot("endpoint-g1-nonce")
	for _, stale := range []time.Time{now, now.Add(-time.Nanosecond)} {
		if action, accepted := m.ObserveExternalIfNewer("endpoint-g1-nonce", "validator-a", false, false, false, stale); accepted || action != (Action{}) {
			t.Fatalf("replayed/reordered observation applied: at=%v action=%+v", stale, action)
		}
	}
	after := m.Snapshot("endpoint-g1-nonce")
	if after != before {
		t.Fatalf("replayed observation mutated health state: before=%+v after=%+v", before, after)
	}
	if action, accepted := m.ObserveExternalIfNewer("endpoint-g1-nonce", "validator-b", true, true, false, now.Add(-time.Nanosecond)); accepted || action != (Action{}) {
		t.Fatalf("older cross-vantage liveness report applied: action=%+v accepted=%v", action, accepted)
	}
	// An independent vantage may carry the same source timestamp; it is not a
	// replay of validator-a's report and must remain usable as corroboration.
	second, applied := m.ObserveExternalIfNewer("endpoint-g1-nonce", "validator-b", false, false, false, now)
	if !applied || !second.RemoveFromRouting {
		t.Fatalf("new external observation did not advance policy: action=%+v applied=%v", second, applied)
	}
}

func TestExternalObservationCommitFailureDoesNotConsumeReplayFence(t *testing.T) {
	m := NewMonitor()
	at := time.Now().UTC()
	injected := errors.New("injected durable failure")
	calls := 0
	action, applied, err := m.ObserveExternalIfNewerWithCommit(
		"endpoint-g1-nonce", "external", true, true, false, at,
		func() error {
			calls++
			return injected
		},
	)
	if !errors.Is(err, injected) || applied || action != (Action{}) || calls != 1 {
		t.Fatalf("failed commit mutated monitor: action=%+v applied=%v calls=%d err=%v", action, applied, calls, err)
	}
	if snapshot := m.Snapshot("endpoint-g1-nonce"); snapshot != (ObservationSnapshot{}) {
		t.Fatalf("failed commit retained state: %+v", snapshot)
	}
	action, applied, err = m.ObserveExternalIfNewerWithCommit(
		"endpoint-g1-nonce", "external", true, true, false, at,
		func() error {
			calls++
			return nil
		},
	)
	if err != nil || !applied || action != (Action{}) || calls != 2 {
		t.Fatalf("identical retry did not commit: action=%+v applied=%v calls=%d err=%v", action, applied, calls, err)
	}
	if _, applied, err := m.ObserveExternalIfNewerWithCommit(
		"endpoint-g1-nonce", "external", true, true, false, at,
		func() error {
			calls++
			return nil
		},
	); err != nil || applied || calls != 2 {
		t.Fatalf("replay reached durable callback: applied=%v calls=%d err=%v", applied, calls, err)
	}
}

func TestExternalEqualTimeVantageCapIsBoundedAndResettable(t *testing.T) {
	m := NewMonitor()
	now := time.Now().UTC()
	for index := range maxExternalVantagesAtOneInstant {
		vantage := fmt.Sprintf("validator-%03d", index)
		if action, applied := m.ObserveExternalIfNewer("endpoint-g1-nonce", vantage, false, false, false, now); !applied {
			t.Fatalf("bounded vantage %d rejected: action=%+v", index, action)
		}
	}
	before := m.Snapshot("endpoint-g1-nonce")
	if action, applied := m.ObserveExternalIfNewer("endpoint-g1-nonce", "validator-overflow", false, false, false, now); applied || action != (Action{}) {
		t.Fatalf("vantage beyond cap applied: action=%+v applied=%v", action, applied)
	}
	if after := m.Snapshot("endpoint-g1-nonce"); after != before {
		t.Fatalf("rejected vantage mutated state: before=%+v after=%+v", before, after)
	}
	if action, applied := m.ObserveExternalIfNewer("endpoint-g1-nonce", "fault-proof", true, false, false, now); !applied || !action.TrustZero {
		t.Fatalf("vantage cap masked definitive fault: action=%+v applied=%v", action, applied)
	}
	if action, applied := m.ObserveExternalIfNewer("endpoint-g1-nonce", "validator-next", true, true, false, now.Add(time.Second)); !applied || action != (Action{}) {
		t.Fatalf("later instant did not reset vantage set: action=%+v applied=%v", action, applied)
	}
	m.mu.Lock()
	state := m.states["endpoint-g1-nonce"]
	externalCount := len(state.externalVantagesAtLast)
	economicVantageCount := len(state.vantages)
	m.mu.Unlock()
	if externalCount != 1 || economicVantageCount > 2 {
		t.Fatalf("vantage state is unbounded: external=%d economic=%d", externalCount, economicVantageCount)
	}
}

func TestExternalDefinitiveFaultIsNotHiddenByNewerLiveness(t *testing.T) {
	m := NewMonitor()
	now := time.Now().UTC()
	if action, applied := m.ObserveExternalIfNewer("endpoint-g1-nonce", "validator-a", true, true, false, now); !applied || action != (Action{}) {
		t.Fatalf("newer healthy observation: action=%+v applied=%v", action, applied)
	}
	action, applied := m.ObserveExternalIfNewer(
		"endpoint-g1-nonce", "validator-a", true, false, false, now.Add(-time.Second),
	)
	if !applied || !action.RemoveFromRouting || !action.AssignReplacement || !action.TrustZero {
		t.Fatalf("older definitive fault was discarded: action=%+v applied=%v", action, applied)
	}
}

func TestOlderExternalSuccessCannotResetNewerInternalFailure(t *testing.T) {
	m := NewMonitor()
	now := time.Now().UTC()
	if action, applied := m.ObserveIfVersion("endpoint-g1-nonce", "periodic", false, false, false, now.Add(2*time.Second), 0); !applied || action.RemoveFromRouting {
		t.Fatalf("first internal failure: action=%+v applied=%v", action, applied)
	}
	before := m.Snapshot("endpoint-g1-nonce")
	if action, applied := m.ObserveExternalIfNewer("endpoint-g1-nonce", "external", true, true, false, now.Add(time.Second)); applied || action != (Action{}) {
		t.Fatalf("older external success reset newer failure: action=%+v applied=%v", action, applied)
	}
	if after := m.Snapshot("endpoint-g1-nonce"); after != before {
		t.Fatalf("rejected external success mutated state: before=%+v after=%+v", before, after)
	}
	if action, applied := m.ObserveIfVersion("endpoint-g1-nonce", "periodic", false, false, false, now.Add(3*time.Second), before.Version); !applied || !action.RemoveFromRouting {
		t.Fatalf("second internal failure was reset: action=%+v applied=%v", action, applied)
	}
}

func TestDefinitiveInternalFaultSurvivesNewerLivenessVersion(t *testing.T) {
	m := NewMonitor()
	if action := m.Observe("endpoint-g1-nonce", "external", true, true, false, time.Now().UTC()); action != (Action{}) {
		t.Fatalf("healthy report changed policy: %+v", action)
	}
	action, applied := m.ObserveIfVersion(
		"endpoint-g1-nonce", "periodic", true, false, false, time.Now().UTC(), 0,
	)
	if !applied || !action.RemoveFromRouting || !action.AssignReplacement || !action.TrustZero {
		t.Fatalf("newer liveness masked definitive internal fault: action=%+v applied=%v", action, applied)
	}
}
