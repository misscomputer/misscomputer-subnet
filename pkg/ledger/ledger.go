// SPDX-License-Identifier: AGPL-3.0-only

package ledger

import (
	"context"
	"sync"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/durable"
	"github.com/misscomputer/misscomputer-subnet/pkg/protocol"
)

const DefaultTrust = 1.0

type Event struct {
	At           time.Time `json:"at"`
	DeploymentID string    `json:"deployment_id"`
	MinerID      string    `json:"miner_id,omitempty"`
	Type         string    `json:"type"`
	Detail       string    `json:"detail,omitempty"`
}

type Deployment struct {
	ID               string                      `json:"id"`
	RouteHost        string                      `json:"route_host"`
	ImageDigest      string                      `json:"image_digest"`
	TicketPublished  time.Time                   `json:"ticket_published"`
	FirstPublicReady time.Time                   `json:"first_public_ready,omitempty"`
	FullRedundancy   time.Time                   `json:"full_redundancy,omitempty"`
	Receipts         map[string]protocol.Receipt `json:"receipts"`
}

type Ledger struct {
	mu          sync.RWMutex
	deployments map[string]*Deployment
	events      []Event
	trust       map[string]float64
	durable     *durable.Store
}

func New() *Ledger {
	return &Ledger{deployments: make(map[string]*Deployment), trust: make(map[string]float64)}
}

// NewDurable wraps the in-process read model with transactional persistence.
// Existing lab callers keep using New; long-running services use this form.
func NewDurable(store *durable.Store) (*Ledger, error) {
	l := New()
	l.durable = store
	if store == nil {
		return l, nil
	}
	values, err := store.TrustSnapshot(context.Background())
	if err != nil {
		return nil, err
	}
	l.trust = values
	return l, nil
}

func (l *Ledger) Start(d Deployment) {
	l.mu.Lock()
	defer l.mu.Unlock()
	d.Receipts = make(map[string]protocol.Receipt)
	l.deployments[d.ID] = &d
	l.events = append(l.events, Event{At: d.TicketPublished, DeploymentID: d.ID, Type: "ticket_published"})
}

func (l *Ledger) AddReceipt(r protocol.Receipt) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.durable != nil {
		if err := l.durable.SaveReceipt(context.Background(), r); err != nil {
			return err
		}
	}
	if d := l.deployments[r.DeploymentID]; d != nil {
		d.Receipts[r.MinerID] = r
		l.events = append(l.events, Event{At: time.Now().UTC(), DeploymentID: r.DeploymentID, MinerID: r.MinerID, Type: "receipt_" + string(r.Stage), Detail: r.Error})
	}
	return nil
}

func (l *Ledger) MarkFirst(id string, at time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if d := l.deployments[id]; d != nil && d.FirstPublicReady.IsZero() {
		d.FirstPublicReady = at
		l.events = append(l.events, Event{At: at, DeploymentID: id, Type: "first_public_ready"})
	}
}

func (l *Ledger) MarkFull(id string, at time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if d := l.deployments[id]; d != nil && d.FullRedundancy.IsZero() {
		d.FullRedundancy = at
		l.events = append(l.events, Event{At: at, DeploymentID: id, Type: "full_redundancy"})
	}
}

func (l *Ledger) SetTrust(minerID string, value float64) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	// Update the in-process gate before persistence so trust-zero remains
	// fail-closed even when the durable write itself fails.
	l.trust[minerID] = value
	if l.durable != nil {
		if err := l.durable.SetTrust(context.Background(), minerID, value); err != nil {
			return err
		}
	}
	return nil
}

func (l *Ledger) RecordAssignment(ticket protocol.Ticket, status string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.durable == nil {
		return nil
	}
	return l.durable.SaveAssignment(context.Background(), ticket, status)
}

func (l *Ledger) RecordObservation(observation durable.Observation) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.durable == nil {
		return nil
	}
	return l.durable.RecordObservation(context.Background(), observation)
}

func (l *Ledger) Durable() *durable.Store { return l.durable }

// Trust returns the current economic trust value. Miners with no ledger entry
// are eligible by default so a fresh in-memory ledger does not exclude the
// entire configured miner set.
func (l *Ledger) Trust(minerID string) float64 {
	l.mu.RLock()
	value, exists := l.trust[minerID]
	l.mu.RUnlock()
	if !exists {
		return DefaultTrust
	}
	return value
}

// Eligible reports whether a miner may receive a new assignment.
func (l *Ledger) Eligible(minerID string) bool {
	return l.Trust(minerID) > 0
}

func (l *Ledger) Snapshot(id string) (Deployment, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	d := l.deployments[id]
	if d == nil {
		return Deployment{}, false
	}
	copy := *d
	copy.Receipts = make(map[string]protocol.Receipt, len(d.Receipts))
	for k, v := range d.Receipts {
		copy.Receipts[k] = v
	}
	return copy, true
}

func (l *Ledger) Events() []Event {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return append([]Event(nil), l.events...)
}
