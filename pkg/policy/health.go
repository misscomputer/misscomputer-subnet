// SPDX-License-Identifier: AGPL-3.0-only

package policy

import (
	"sync"
	"time"
)

type Action struct {
	RemoveFromRouting bool `json:"remove_from_routing"`
	AssignReplacement bool `json:"assign_replacement"`
	TrustZero         bool `json:"trust_zero"`
}

type state struct {
	rapidFailures int
	vantages      map[string]struct{}
	consecutive   int
	lastFailure   time.Time
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
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.states[endpointID]
	if s == nil {
		s = &state{vantages: make(map[string]struct{})}
		m.states[endpointID] = s
	}
	if fraudulent || (reachable && !correct) {
		return Action{RemoveFromRouting: true, AssignReplacement: true, TrustZero: true}
	}
	if reachable {
		s.rapidFailures, s.consecutive = 0, 0
		s.vantages = make(map[string]struct{})
		return Action{}
	}
	if at.Sub(s.lastFailure) > m.RapidWindow {
		s.rapidFailures = 0
	}
	s.lastFailure = at
	s.rapidFailures++
	s.consecutive++
	s.vantages[vantage] = struct{}{}
	a := Action{}
	if s.rapidFailures >= 2 {
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
