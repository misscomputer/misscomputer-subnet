// SPDX-License-Identifier: AGPL-3.0-only

package policy

import (
	"context"
	"errors"
	"math"
	"sync"
	"time"
)

const maxExternalVantagesAtOneInstant = 256

type Action struct {
	RemoveFromRouting bool `json:"remove_from_routing"`
	AssignReplacement bool `json:"assign_replacement"`
	TrustZero         bool `json:"trust_zero"`
}

type state struct {
	version                uint64
	rapidFailures          [2]int
	rapidLastFailure       [2]time.Time
	lastObserved           [2]time.Time
	externalVantagesAtLast map[string]struct{}
	vantages               map[string]struct{}
	consecutive            int
	lastFailure            time.Time
}

type observationClass uint8

const (
	externalObservation observationClass = iota
	internalPeriodicObservation
)

// ObservationSnapshot binds a prospective observation to the exact health
// history it was corroborated against. LastFailure lets callers reject peer
// evidence that predates a more recent external failure.
type ObservationSnapshot struct {
	Version     uint64
	LastFailure time.Time
}

type Monitor struct {
	mu                  sync.Mutex
	states              map[string]*state
	RapidWindow         time.Duration
	UnreachableFailures int
}

func NewMonitor() *Monitor {
	return &Monitor{states: make(map[string]*state), RapidWindow: 15 * time.Second, UnreachableFailures: 4}
}

// Observe keys state by endpoint incarnation, not the stable replica label.
// Callers must pass the endpoint ID (which includes generation and nonce) so a
// replacement cannot inherit an earlier workload's failures.
func (m *Monitor) Observe(endpointID, vantage string, reachable, correct, fraudulent bool, at time.Time) Action {
	return m.observeClass(endpointID, vantage, reachable, correct, fraudulent, at, externalObservation)
}

// ObserveExternalIfNewer rejects endpoint-global reordered liveness reports
// before they can advance rapid-failure counters. Distinct bounded vantages
// may report at the same newest instant, while a duplicate vantage cannot.
// Definitive attributable fault
// evidence is never discarded merely because a newer liveness report arrived
// first; the scheduler's exact-active-incarnation check makes its replay
// idempotent after the first removal.
func (m *Monitor) ObserveExternalIfNewer(endpointID, vantage string, reachable, correct, fraudulent bool, at time.Time) (Action, bool) {
	action, applied, _ := m.ObserveExternalIfNewerWithCommit(endpointID, vantage, reachable, correct, fraudulent, at, nil)
	return action, applied
}

// ObserveExternalIfNewerWithCommit runs commit after replay/order validation
// but before changing monitor state. A failed durable scoring write therefore
// leaves the report retryable instead of consuming its replay fence and losing
// the sample permanently. The callback must not call back into this Monitor.
func (m *Monitor) ObserveExternalIfNewerWithCommit(endpointID, vantage string, reachable, correct, fraudulent bool, at time.Time, commit func() error) (Action, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.states[endpointID]
	if s == nil {
		s = &state{vantages: make(map[string]struct{}), externalVantagesAtLast: make(map[string]struct{})}
	}
	definitiveFault := fraudulent || (reachable && !correct)
	last := s.lastObserved[externalObservation]
	latestLiveness := last
	if s.lastObserved[internalPeriodicObservation].After(latestLiveness) {
		latestLiveness = s.lastObserved[internalPeriodicObservation]
	}
	if !definitiveFault {
		switch {
		case at.Before(latestLiveness):
			return Action{}, false, nil
		case at.Equal(last):
			if _, duplicate := s.externalVantagesAtLast[vantage]; duplicate || len(s.externalVantagesAtLast) >= maxExternalVantagesAtOneInstant {
				return Action{}, false, nil
			}
		}
	}
	if commit != nil {
		if err := commit(); err != nil {
			return Action{}, false, errors.Join(errors.New("commit external health observation"), err)
		}
	}
	if m.states[endpointID] == nil {
		m.states[endpointID] = s
	}
	if s.version < math.MaxUint64 {
		s.version++
	}
	if at.After(last) {
		s.lastObserved[externalObservation] = at
		s.externalVantagesAtLast = map[string]struct{}{vantage: {}}
	} else if at.Equal(last) && len(s.externalVantagesAtLast) < maxExternalVantagesAtOneInstant {
		s.externalVantagesAtLast[vantage] = struct{}{}
	}
	return m.observe(s, vantage, reachable, correct, fraudulent, at, externalObservation), true, nil
}

// ObserveInternal applies an in-process periodic-prober observation. Routing
// removal needs two rapid failures from one source class, so a shared-path
// failure cannot become destructive merely by interleaving one internal result
// with one external report. Consecutive multi-vantage evidence remains shared.
func (m *Monitor) ObserveInternal(endpointID, vantage string, reachable, correct, fraudulent bool, at time.Time) Action {
	return m.observeClass(endpointID, vantage, reachable, correct, fraudulent, at, internalPeriodicObservation)
}

func (m *Monitor) observeClass(endpointID, vantage string, reachable, correct, fraudulent bool, at time.Time, class observationClass) Action {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.state(endpointID)
	if s.version < math.MaxUint64 {
		s.version++
	}
	s.lastObserved[class] = at
	return m.observe(s, vantage, reachable, correct, fraudulent, at, class)
}

// ObserveIfVersion applies an observation only when no other internal or
// external liveness observation has changed this endpoint's health history
// since the caller took its snapshot. Definitive reachable wrong/fraud
// evidence remains actionable against the still-active exact incarnation even
// after a newer liveness report; otherwise repeated healthy posts could mask
// cryptographic fault evidence. At version exhaustion it fails closed.
func (m *Monitor) ObserveIfVersion(endpointID, vantage string, reachable, correct, fraudulent bool, at time.Time, expectedVersion uint64) (Action, bool) {
	return m.ObserveIfVersionContext(context.Background(), endpointID, vantage, reachable, correct, fraudulent, at, expectedVersion)
}

// ObserveIfVersionContext is ObserveIfVersion with lifecycle cancellation
// linearized under the monitor mutation lock. A caller cancelled while waiting
// for another observation to finish cannot subsequently advance this
// endpoint's version, failure counters, or policy action.
func (m *Monitor) ObserveIfVersionContext(ctx context.Context, endpointID, vantage string, reachable, correct, fraudulent bool, at time.Time, expectedVersion uint64) (Action, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ctx == nil || ctx.Err() != nil {
		return Action{}, false
	}
	s := m.states[endpointID]
	currentVersion := uint64(0)
	if s != nil {
		currentVersion = s.version
	}
	definitiveFault := fraudulent || (reachable && !correct)
	if (currentVersion != expectedVersion && !definitiveFault) || currentVersion == math.MaxUint64 {
		return Action{}, false
	}
	// Keep this check immediately adjacent to the first mutation while m.mu is
	// held. Checks made by callers before lock acquisition have a cancellation
	// race when another health commit owns the monitor serialization point.
	if err := ctx.Err(); err != nil {
		return Action{}, false
	}
	if s == nil {
		s = m.state(endpointID)
	}
	s.version++
	if at.After(s.lastObserved[internalPeriodicObservation]) {
		s.lastObserved[internalPeriodicObservation] = at
	}
	return m.observe(s, vantage, reachable, correct, fraudulent, at, internalPeriodicObservation), true
}

// Snapshot returns the current observation version and most recent liveness
// failure for one exact endpoint incarnation.
func (m *Monitor) Snapshot(endpointID string) ObservationSnapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s := m.states[endpointID]; s != nil {
		return ObservationSnapshot{Version: s.version, LastFailure: s.lastFailure}
	}
	return ObservationSnapshot{}
}

func (m *Monitor) state(endpointID string) *state {
	s := m.states[endpointID]
	if s == nil {
		s = &state{vantages: make(map[string]struct{}), externalVantagesAtLast: make(map[string]struct{})}
		m.states[endpointID] = s
	}
	if s.externalVantagesAtLast == nil {
		s.externalVantagesAtLast = make(map[string]struct{})
	}
	return s
}

func (m *Monitor) observe(s *state, vantage string, reachable, correct, fraudulent bool, at time.Time, class observationClass) Action {
	if fraudulent || (reachable && !correct) {
		return Action{RemoveFromRouting: true, AssignReplacement: true, TrustZero: true}
	}
	if reachable {
		s.rapidFailures, s.rapidLastFailure, s.consecutive = [2]int{}, [2]time.Time{}, 0
		s.vantages = make(map[string]struct{})
		return Action{}
	}
	if at.Sub(s.rapidLastFailure[class]) > m.RapidWindow {
		s.rapidFailures[class] = 0
	}
	s.rapidLastFailure[class] = at
	s.lastFailure = at
	s.rapidFailures[class]++
	s.consecutive++
	if len(s.vantages) < 2 {
		s.vantages[vantage] = struct{}{}
	}
	a := Action{}
	if s.rapidFailures[class] >= 2 {
		a.RemoveFromRouting = true
		a.AssignReplacement = true
	}
	if s.consecutive >= m.UnreachableFailures && len(s.vantages) >= 2 {
		a.TrustZero = true
	}
	return a
}

func (m *Monitor) Forget(endpointID string) {
	m.mu.Lock()
	delete(m.states, endpointID)
	m.mu.Unlock()
}
