// SPDX-License-Identifier: AGPL-3.0-only

package policy

import (
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
