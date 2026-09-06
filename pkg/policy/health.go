// SPDX-License-Identifier: AGPL-3.0-only

package policy

import (
	"math"
	"sync"
	"time"
)

type Action struct {
	RemoveFromRouting bool `json:"remove_from_routing"`
	AssignReplacement bool `json:"assign_replacement"`
	TrustZero         bool `json:"trust_zero"`
}

type state struct {
	version          uint64
	rapidFailures    [2]int
	rapidLastFailure [2]time.Time
	vantages         map[string]struct{}
	consecutive      int
	lastFailure      time.Time
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
	return m.observe(s, vantage, reachable, correct, fraudulent, at, class)
}

// ObserveIfVersion applies an observation only when no other internal or
// external observation has changed this endpoint's health history since the
// caller took its snapshot. At version exhaustion it fails closed.
func (m *Monitor) ObserveIfVersion(endpointID, vantage string, reachable, correct, fraudulent bool, at time.Time, expectedVersion uint64) (Action, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.states[endpointID]
	currentVersion := uint64(0)
	if s != nil {
		currentVersion = s.version
	}
	if currentVersion != expectedVersion || currentVersion == math.MaxUint64 {
		return Action{}, false
	}
	if s == nil {
		s = m.state(endpointID)
	}
	s.version++
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
		s = &state{vantages: make(map[string]struct{})}
		m.states[endpointID] = s
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
	s.vantages[vantage] = struct{}{}
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
