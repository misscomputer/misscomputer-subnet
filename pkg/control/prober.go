// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/policy"
	"github.com/misscomputer/misscomputer-subnet/pkg/validator"
)

const (
	// DefaultProbeInterval is the delay between the end of one sweep and the
	// start of the next.
	//
	// It must stay below policy.Monitor.RapidWindow (15s by default). Health
	// policy evicts an unreachable endpoint on its second failure inside that
	// window and resets the counter whenever two failures are further apart,
	// so a single-vantage driver sweeping at or beyond the rapid window would
	// reset its own evidence on every pass and never evict anything. Sweeping
	// every 10s evicts a dark replica after roughly 20s.
	DefaultProbeInterval = 10 * time.Second
	// DefaultProbeTimeout bounds one replica probe. It is deliberately shorter
	// than the interval so a single hung replica cannot stall the sweep.
	DefaultProbeTimeout = 5 * time.Second
	// DefaultProbeVantage labels observations produced by this in-process
	// driver so they are distinguishable from external vantage reports posted
	// to the control plane's health endpoint.
	DefaultProbeVantage = "central-periodic"
)

// ReplicaProber is the exact probing capability the periodic prober consumes.
// validator.Validator satisfies it; tests substitute a deterministic stub the
// same way Scheduler.Entropy and Scheduler.Now are substituted.
type ReplicaProber interface {
	ProbeReplica(ctx context.Context, routeHost, replicaID, challengePath, expectedValue string) validator.ProbeResult
}

// ProbeOutcome records one replica observation and the policy action it caused.
type ProbeOutcome struct {
	DeploymentID string        `json:"deployment_id"`
	MinerID      string        `json:"miner_id"`
	ReplicaID    string        `json:"replica_id"`
	EndpointID   string        `json:"endpoint_id"`
	Reachable    bool          `json:"reachable"`
	Correct      bool          `json:"correct"`
	Status       int           `json:"status"`
	Latency      time.Duration `json:"latency"`
	Action       policy.Action `json:"action"`
	// Stale is true when the observation lost a race with the scheduler: the
	// deployment was torn down or the replica replaced before the action could
	// be applied. Such an outcome is expected churn, not a fault.
	Stale bool  `json:"stale"`
	Err   error `json:"-"`
}

// SweepResult is one complete pass over every probeable active deployment.
type SweepResult struct {
	StartedAt   time.Time      `json:"started_at"`
	Deployments int            `json:"deployments"`
	Outcomes    []ProbeOutcome `json:"outcomes"`
}

// Removed counts replicas this sweep evicted from routing.
func (r SweepResult) Removed() int {
	count := 0
	for _, outcome := range r.Outcomes {
		if outcome.Action.RemoveFromRouting {
			count++
		}
	}
	return count
}

// Failed counts replicas that did not serve the exact expected challenge.
func (r SweepResult) Failed() int {
	count := 0
	for _, outcome := range r.Outcomes {
		if !outcome.Correct {
			count++
		}
	}
	return count
}

// Prober is the periodic driver for post-acceptance serving correctness. The
// scheduler already probes each replica through the internal targeted path at
// admission time; without a driver, HandleHealth only ever runs when some
// external caller posts an observation, so a miner that goes dark after
// acceptance keeps its assignment indefinitely.
//
// The prober is intentionally in-process. Targeted probing needs the hidden
// challenge value, which lives only in the scheduler's deployment state and is
// never exported to the control API, the durable store, or a published
// manifest. It reuses the existing Validator, policy.Monitor, and HandleHealth
// path exactly; it adds no policy of its own.
//
// This is the central operator's internal eligibility decision. It is unrelated
// to, and carries no authority over, the public multi-validator probe reports
// described in docs/public-validator-live-probe.md.
type Prober struct {
	// Scheduler is required.
	Scheduler *Scheduler
	// Interval defaults to DefaultProbeInterval.
	Interval time.Duration
	// Timeout bounds a single replica probe and defaults to
	// DefaultProbeTimeout. A non-positive value disables the per-probe
	// deadline and relies on the Validator's own client timeout.
	Timeout time.Duration
	// Vantage defaults to DefaultProbeVantage. Health policy counts distinct
	// vantages, so this must not collide with an external reporter's label.
	Vantage string
	// Probe defaults to the scheduler's Validator.
	Probe ReplicaProber
	// Now defaults to time.Now.
	Now func() time.Time
	// Logger defaults to slog.Default.
	Logger *slog.Logger
	// OnSweep observes each completed sweep. Operators attach metrics here;
	// tests use it to synchronize.
	OnSweep func(SweepResult)
}

// Run sweeps until ctx is cancelled, then returns ctx.Err(). Sweeps never
// overlap: the interval is measured from the end of the previous sweep, so a
// slow sweep delays the next one instead of stacking concurrent probes and
// replacement work onto the scheduler.
func (p *Prober) Run(ctx context.Context) error {
	if p.Scheduler == nil {
		return errors.New("prober requires a scheduler")
	}
	interval := p.interval()
	p.warnOnRapidWindow(interval)
	timer := time.NewTimer(interval)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
		p.Sweep(ctx)
		timer.Reset(interval)
	}
}

// Sweep probes every active replica of every settled deployment once, applying
// each observation through HandleHealth. Deployments are visited in canonical
// order and replicas sequentially, mirroring the sequential discipline of the
// public probe CLI; bounded concurrency is a later refinement that would not
// change any contract here.
func (p *Prober) Sweep(ctx context.Context) SweepResult {
	result := SweepResult{StartedAt: p.clock()().UTC()}
	if p.Scheduler == nil {
		return result
	}
	targets := p.Scheduler.probeTargets()
	result.Deployments = len(targets)
	for _, target := range targets {
		for _, replica := range target.replicas {
			if ctx.Err() != nil {
				p.publish(result)
				return result
			}
			result.Outcomes = append(result.Outcomes, p.observe(ctx, target, replica))
		}
	}
	p.publish(result)
	return result
}

func (p *Prober) observe(ctx context.Context, target probeTarget, replica ActiveReplica) ProbeOutcome {
	probeCtx := ctx
	if timeout := p.timeout(); timeout > 0 {
		var cancel context.CancelFunc
		probeCtx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	// Targeted, not public: an untargeted request round-robins across healthy
	// replicas, so a single failing replica could hide behind its peers.
	observed := p.prober().ProbeReplica(probeCtx, target.routeHost, replica.ReplicaID, target.challengePath, target.challengeValue)
	// A completed HTTP exchange always carries a status, so a zero status is
	// exactly "the replica never answered". Answering with the wrong bytes is
	// reachable-but-incorrect, which existing policy already treats as an
	// immediate removal rather than a slow unreachability count.
	outcome := ProbeOutcome{
		DeploymentID: target.deploymentID,
		MinerID:      replica.MinerID,
		ReplicaID:    replica.ReplicaID,
		EndpointID:   replica.EndpointID,
		Reachable:    observed.Status != 0,
		Correct:      observed.Correct,
		Status:       observed.Status,
		Latency:      observed.Latency,
	}
	// Fraudulence is a claim about a miner substituting or forging content and
	// is never inferred from a transport-level or body-mismatch observation.
	// The prober reports only what it saw and lets policy decide.
	action, err := p.Scheduler.HandleHealth(
		ctx, target.deploymentID, replica.ReplicaID, replica.MinerID,
		p.vantage(), outcome.Reachable, outcome.Correct, false, p.clock()().UTC(),
	)
	outcome.Action = action
	outcome.Err = err
	outcome.Stale = isStaleObservation(err)
	p.log(outcome)
	return outcome
}

// isStaleObservation reports whether the scheduler rejected an observation
// only because it had already moved past the incarnation being described.
func isStaleObservation(err error) bool {
	return errors.Is(err, ErrUnknownDeployment) ||
		errors.Is(err, ErrDeploymentDeactivating) ||
		errors.Is(err, ErrReplicaNotActive)
}

func (p *Prober) log(outcome ProbeOutcome) {
	logger := p.Logger
	if logger == nil {
		logger = slog.Default()
	}
	attrs := []any{
		"deployment_id", outcome.DeploymentID,
		"miner_id", outcome.MinerID,
		"replica_id", outcome.ReplicaID,
		"reachable", outcome.Reachable,
		"correct", outcome.Correct,
		"status", outcome.Status,
	}
	switch {
	case outcome.Stale:
		// Ordinary churn: the scheduler replaced or removed this incarnation
		// while the probe was in flight.
		logger.Debug("periodic probe observation is stale", append(attrs, "error", outcome.Err)...)
	case outcome.Err != nil:
		logger.Error("periodic probe health action failed", append(attrs, "error", outcome.Err)...)
	case outcome.Action.RemoveFromRouting:
		logger.Warn("periodic probe evicted replica from routing", append(attrs,
			"assign_replacement", outcome.Action.AssignReplacement, "trust_zero", outcome.Action.TrustZero)...)
	case !outcome.Correct:
		logger.Warn("periodic probe observed a failing replica", attrs...)
	default:
		logger.Debug("periodic probe observed a serving replica", attrs...)
	}
}

// warnOnRapidWindow reports a configuration that cannot ever evict a dark
// replica. Unreachability is only actioned when two failures land inside
// policy.Monitor.RapidWindow, so an interval at or beyond that window resets
// the counter on every sweep. This is a misconfiguration an operator must see,
// not a reason to refuse to run: correctness probes still evict immediately.
func (p *Prober) warnOnRapidWindow(interval time.Duration) {
	window := p.Scheduler.monitor().RapidWindow
	if window <= 0 || interval < window {
		return
	}
	logger := p.Logger
	if logger == nil {
		logger = slog.Default()
	}
	logger.Warn("periodic probe interval is not below the health rapid window; unreachable replicas will not be evicted",
		"interval", interval, "rapid_window", window)
}

func (p *Prober) publish(result SweepResult) {
	if p.OnSweep != nil {
		p.OnSweep(result)
	}
}

func (p *Prober) prober() ReplicaProber {
	if p.Probe != nil {
		return p.Probe
	}
	return p.Scheduler.Validator
}

func (p *Prober) interval() time.Duration {
	if p.Interval > 0 {
		return p.Interval
	}
	return DefaultProbeInterval
}

func (p *Prober) timeout() time.Duration {
	if p.Timeout != 0 {
		return p.Timeout
	}
	return DefaultProbeTimeout
}

func (p *Prober) vantage() string {
	if p.Vantage != "" {
		return p.Vantage
	}
	return DefaultProbeVantage
}

func (p *Prober) clock() func() time.Time {
	if p.Now != nil {
		return p.Now
	}
	return time.Now
}
