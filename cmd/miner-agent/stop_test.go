// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// stopPhase is one scripted shutdown phase: it records that it began and
// its deadline, and can wait for another phase to have begun. stopServer's
// Shutdown and stopLane's Close and Recover are phases.
type stopPhase struct {
	began    chan struct{}
	deadline time.Time
	// waitFor, when set, makes the phase wait for that phase to begin
	// before it returns, or for its own context to end.
	waitFor *stopPhase
	err     error
}

func newStopPhase() *stopPhase { return &stopPhase{began: make(chan struct{})} }

func (p *stopPhase) run(ctx context.Context) error {
	p.deadline, _ = ctx.Deadline()
	close(p.began)
	if p.waitFor != nil {
		select {
		case <-p.waitFor.began:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return p.err
}

type stopServer struct{ shutdown *stopPhase }

func (s stopServer) Shutdown(ctx context.Context) error { return s.shutdown.run(ctx) }

type stopLane struct{ close, recover *stopPhase }

func (l stopLane) Close(ctx context.Context) error   { return l.close.run(ctx) }
func (l stopLane) Recover(ctx context.Context) error { return l.recover.run(ctx) }

// The sandbox lane closes while the server drains, on one shared deadline,
// so its drain adds nothing to the stop time; the replica cleanup and the
// sandbox Recover then run in order, each on a budget of its own. A phase
// that fails or runs out of time does not skip the later ones.
func TestStopAgentOverlapsTheLaneCloseWithServerShutdown(t *testing.T) {
	budgets := stopBudgets{serve: 2 * time.Second, cleanup: 300 * time.Millisecond, sandbox: 5 * time.Second}
	for _, test := range []struct {
		name string
		// slowCleanup makes the replica cleanup use its whole budget.
		slowCleanup bool
		closeErr    error
		want        []string // substrings of the returned error, none when empty
	}{
		{name: "every phase succeeds"},
		{name: "cleanup uses its whole budget", slowCleanup: true, want: []string{"shutdown cleanup", "deadline exceeded"}},
		{name: "the lane does not drain in time", closeErr: errors.New("sandbox lane operations still running"),
			want: []string{"still running"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			shutdown, closing, recovering := newStopPhase(), newStopPhase(), newStopPhase()
			// Each of Shutdown and Close returns only once the other began:
			// run one after the other, the first would wait out its budget.
			shutdown.waitFor, closing.waitFor = closing, shutdown
			closing.err = test.closeErr
			cleaned := false
			cleanup := func(ctx context.Context) error {
				if test.slowCleanup {
					<-ctx.Done()
					return ctx.Err()
				}
				cleaned = true
				return nil
			}
			begun := time.Now()
			err := stopAgent(stopServer{shutdown}, cleanup, stopLane{closing, recovering}, budgets)
			if took := time.Since(begun); took >= budgets.serve {
				t.Fatalf("stop took %v: server shutdown and lane close did not overlap", took)
			}
			if !shutdown.deadline.Equal(closing.deadline) {
				t.Errorf("shutdown deadline %v, close deadline %v, want one shared deadline", shutdown.deadline, closing.deadline)
			}
			select {
			case <-recovering.began:
			default:
				t.Fatal("the sandbox Recover did not run")
			}
			if !test.slowCleanup && !cleaned {
				t.Error("the replica cleanup did not run")
			}
			// Recover's budget starts after the cleanup, not from the signal.
			if left := time.Until(recovering.deadline); left < budgets.sandbox-time.Second {
				t.Errorf("sandbox Recover had %v left, want its own %v budget", left, budgets.sandbox)
			}
			if len(test.want) == 0 && err != nil {
				t.Fatalf("stop = %v, want nil", err)
			}
			for _, want := range test.want {
				if err == nil || !strings.Contains(err.Error(), want) {
					t.Errorf("stop = %v, want it to contain %q", err, want)
				}
			}
		})
	}
}

// Without a sandbox lane only the server and the replica cleanup stop.
func TestStopAgentWithoutASandboxLane(t *testing.T) {
	shutdown := newStopPhase()
	cleaned := false
	err := stopAgent(stopServer{shutdown}, func(context.Context) error { cleaned = true; return nil }, nil, agentStopBudgets)
	if err != nil || !cleaned {
		t.Fatalf("stop = %v, cleaned = %v", err, cleaned)
	}
}
