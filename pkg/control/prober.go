// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/misscomputer/misscomputer-subnet/pkg/policy"
	"github.com/misscomputer/misscomputer-subnet/pkg/validator"
)

const (
	// DefaultProbeInterval is the delay between the end of one endpoint's
	// observation and the start of its next probe.
	//
	// The quantity health policy actually constrains is the wall-clock gap
	// between one endpoint's consecutive failure observations, which must not
	// exceed policy.Monitor.RapidWindow (15s by default) or the failure counter
	// resets and nothing is ever evicted. Because Run paces every endpoint on
	// its own timer, that gap is bounded by Timeout + Interval plus the cost of
	// applying one no-action observation — independent of how many other
	// replicas, deployments, or slow peers exist. The cadence margin covers the
	// apply and scheduling slack, and Prober.Validate enforces the whole
	// inequality rather than the far weaker Interval < RapidWindow.
	DefaultProbeInterval = 6 * time.Second
	// DefaultProbeTimeout bounds one replica probe. A hung replica that accepts
	// the connection and then stays silent burns this entire budget before it
	// is observed as a failure, so it is part of the cadence inequality above,
	// not a detail the interval can absorb.
	DefaultProbeTimeout = 5 * time.Second
	// DefaultProbeCadenceMargin is the slack reserved, inside the rapid window,
	// for applying an observation that takes no action and for timer scheduling.
	// Applying a first failure only updates the in-memory health monitor;
	// eviction and replacement work is unbounded but happens on the last
	// observation an endpoint ever receives, so it cannot delay that endpoint's
	// own next failure.
	DefaultProbeCadenceMargin = 2 * time.Second
	// DefaultProbeVantage labels observations produced by this in-process
	// driver so they are distinguishable from external vantage reports posted
	// to the control plane's health endpoint.
	DefaultProbeVantage = "central-periodic"
)

// ErrProbeCadence reports a configuration whose worst-case gap between one
// endpoint's consecutive failure observations exceeds the health rapid window.
// Such a prober silently never evicts an unreachable replica, so it is refused
// rather than started.
var ErrProbeCadence = errors.New("probe cadence cannot evict an unreachable replica")

// ReplicaProber is the exact probing capability the periodic prober consumes.
// validator.Validator satisfies it; tests substitute a deterministic stub the
// same way Scheduler.Entropy and Scheduler.Now are substituted.
type ReplicaProber interface {
	ProbeReplica(ctx context.Context, routeHost, replicaID, challengePath, expectedValue string) validator.ProbeResult
}

// ProbeOutcome records one replica observation and the policy action it caused.
type ProbeOutcome struct {
	DeploymentID string `json:"deployment_id"`
	MinerID      string `json:"miner_id"`
	ReplicaID    string `json:"replica_id"`
	EndpointID   string `json:"endpoint_id"`
	Reachable    bool   `json:"reachable"`
	Correct      bool   `json:"correct"`
	Status       int    `json:"status"`
	// EdgeGenerated records that a status arrived but the edge produced it on
	// the replica's behalf. Such an observation is reported as unreachable, and
	// this field keeps the distinction visible to operators: a subnet-wide burst
	// of edge-generated statuses is an edge or probe-token fault, not a
	// simultaneous outbreak of miner failures.
	EdgeGenerated bool          `json:"edge_generated"`
	Latency       time.Duration `json:"latency"`
	Action        policy.Action `json:"action"`
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
	// DefaultProbeTimeout. It must be positive and shorter than Interval:
	// without a deadline the prober itself controls, a hung replica's failure
	// gap is whatever the Validator's client happens to allow, and the cadence
	// guarantee below cannot be enforced. Validate refuses anything else.
	Timeout time.Duration
	// CadenceMargin defaults to DefaultProbeCadenceMargin. It is the slack
	// Validate reserves inside the rapid window for applying an observation and
	// for timer scheduling.
	CadenceMargin time.Duration
	// Vantage defaults to DefaultProbeVantage. Health policy counts distinct
	// vantages, so this must not collide with an external reporter's label.
	Vantage string
	// Probe defaults to the scheduler's Validator.
	Probe ReplicaProber
	// Now defaults to time.Now.
	Now func() time.Time
	// Logger defaults to slog.Default.
	Logger *slog.Logger
	// OnSweep observes each completed one-shot Sweep. Run does not sweep, so
	// continuous drivers observe individual outcomes through OnObservation.
	OnSweep func(SweepResult)
	// OnObservation observes every outcome from both Run and Sweep. Operators
	// attach metrics here; tests use it to synchronize. It is called from the
	// probing goroutine, so an implementation must be safe for concurrent use
	// and must not block.
	OnObservation func(ProbeOutcome)
}

// Run drives one independent probe loop per active endpoint until ctx is
// cancelled, then returns ctx.Err().
//
// The pacing is deliberately per endpoint rather than per sweep. Health policy
// only evicts an unreachable endpoint when two of its failures land inside
// policy.Monitor.RapidWindow, so what has to be bounded is the wall-clock gap
// between one endpoint's consecutive failures. A single sequential sweep makes
// that gap Timeout + rest-of-sweep + Interval: it grows with the number of
// deployments and replicas, and a hung replica that burns the full probe
// timeout, or a peer whose eviction triggers a replacement assignment, pushes
// every other endpoint further apart. Past the rapid window the counter resets
// on every pass and a hung replica is never evicted at all.
//
// With one loop per endpoint, the gap is Timeout + Interval plus the cost of
// applying one no-action observation, whatever any other endpoint is doing.
// Validate enforces that this stays inside the rapid window.
//
// Concurrency is bounded by construction: at most one in-flight probe per
// active endpoint, which is the least a driver that must observe every endpoint
// on a fixed cadence can do. Scheduler.HandleHealth is already written for
// concurrent callers — the control plane's health endpoint serves arbitrary
// concurrent requests through it — so applying observations from these loops
// needs no new synchronization.
func (p *Prober) Run(ctx context.Context) error {
	if err := p.Validate(); err != nil {
		return err
	}
	loops := map[string]*endpointLoop{}
	defer func() {
		for _, loop := range loops {
			loop.cancel()
		}
		for _, loop := range loops {
			<-loop.done
		}
	}()
	// Reconciliation only starts loops for endpoints that appeared (a fresh
	// deployment, or a replacement for an evicted replica) and stops loops for
	// endpoints that are gone. An established endpoint's own timer is never
	// touched by it, so reconciliation cannot perturb the cadence guarantee.
	ticker := time.NewTicker(p.interval())
	defer ticker.Stop()
	for {
		p.reconcile(ctx, loops)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// Validate reports a prober that cannot do its job. A cadence that exceeds the
// health rapid window is not a degraded mode — it silently evicts nothing — so
// it is refused at construction rather than warned about at runtime.
func (p *Prober) Validate() error {
	if p.Scheduler == nil {
		return errors.New("prober requires a scheduler")
	}
	interval, timeout := p.interval(), p.timeout()
	if timeout <= 0 {
		return fmt.Errorf("%w: timeout %v leaves a probe bounded only by the client, so no failure gap can be guaranteed", ErrProbeCadence, timeout)
	}
	if timeout >= interval {
		return fmt.Errorf("%w: timeout %v must be shorter than interval %v", ErrProbeCadence, timeout, interval)
	}
	window := p.Scheduler.monitor().RapidWindow
	if window <= 0 {
		return nil
	}
	margin := p.cadenceMargin()
	if gap := ProbeCadenceBound(interval, timeout, margin); gap > window {
		return fmt.Errorf("%w: worst-case failure gap %v (timeout %v + interval %v + margin %v) exceeds the health rapid window %v",
			ErrProbeCadence, gap, timeout, interval, margin, window)
	}
	return nil
}

// ProbeCadenceBound is the worst-case wall-clock gap between one endpoint's
// consecutive failure observations under Run: a hung replica burns the whole
// probe timeout before failing, the interval is measured from the end of the
// previous observation, and the margin covers applying that observation. It
// must not exceed policy.Monitor.RapidWindow.
func ProbeCadenceBound(interval, timeout, margin time.Duration) time.Duration {
	return timeout + interval + margin
}

// endpointLoop is one endpoint's independently paced probe goroutine.
type endpointLoop struct {
	cancel context.CancelFunc
	done   chan struct{}
}

// reconcile starts a loop for every active endpoint that lacks one and stops
// every loop whose endpoint the scheduler no longer serves. Endpoint IDs carry
// generation and nonce, so a replacement is a new key and never inherits the
// loop, timer, or health counters of the incarnation it replaced.
func (p *Prober) reconcile(ctx context.Context, loops map[string]*endpointLoop) {
	for endpointID, loop := range loops {
		select {
		case <-loop.done:
			loop.cancel()
			delete(loops, endpointID)
		default:
		}
	}
	active := make(map[string]struct{}, len(loops))
	for _, target := range p.Scheduler.probeTargets() {
		for _, replica := range target.replicas {
			active[replica.EndpointID] = struct{}{}
			if _, running := loops[replica.EndpointID]; running {
				continue
			}
			loopCtx, cancel := context.WithCancel(ctx)
			loop := &endpointLoop{cancel: cancel, done: make(chan struct{})}
			loops[replica.EndpointID] = loop
			go p.runEndpoint(loopCtx, loop.done, target, replica)
		}
	}
	for endpointID, loop := range loops {
		if _, still := active[endpointID]; still {
			continue
		}
		loop.cancel()
		<-loop.done
		delete(loops, endpointID)
	}
}

// runEndpoint probes one endpoint on its own timer until the endpoint stops
// being this prober's business: the context is cancelled, the observation lost
// a race with the scheduler, or the replica was evicted. A replacement is a
// different endpoint and gets its own loop from the next reconciliation.
func (p *Prober) runEndpoint(ctx context.Context, done chan struct{}, target probeTarget, replica ActiveReplica) {
	defer close(done)
	timer := time.NewTimer(p.interval())
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		outcome := p.observe(ctx, target, replica)
		if outcome.Stale || outcome.Action.RemoveFromRouting {
			return
		}
		timer.Reset(p.interval())
	}
}

// Sweep probes every active replica of every settled deployment once, applying
// each observation through HandleHealth. It is a one-shot diagnostic pass in
// canonical deployment order, not the continuous driver: Run paces endpoints
// individually precisely because a sequential sweep's duration, and therefore
// the failure gap it produces, grows with the size of the deployment set.
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
	// Reachability is "the replica itself answered", and the only proof of that
	// is the edge's upstream marker on a response it actually proxied back. A
	// status code is not proof: the probe traverses the edge, and the edge
	// answers with a status of its own whenever the replica is the thing that is
	// down or unroutable — 502 for a dead backend or a nil tunnel target, 404
	// for a replica dropped from the routes, 403 for a probe-token mismatch that
	// would otherwise misreport every miner in the subnet at once.
	//
	// Policy turns reachable-but-incorrect into an immediate, permanent
	// trust-zero from this single vantage, so misreading an edge-generated error
	// as a miner response would hand a merely offline miner the penalty reserved
	// for serving forged content. Absent the marker the observation is exactly
	// "the replica did not answer", which is the slow, corroborated
	// unreachability path.
	//
	// Correct is accepted as independent proof of a replica response because it
	// requires a 200 carrying the exact hidden challenge value, which no edge or
	// intermediary error page can produce. That keeps a fronting proxy that
	// strips unknown response headers from silently marking healthy replicas
	// unreachable, and its failure direction is the safe one: a stripped marker
	// can only downgrade an incorrect response to unreachable, never upgrade an
	// edge error into a trust-zero.
	replicaAnswered := observed.ServedByReplica || observed.Correct
	outcome := ProbeOutcome{
		DeploymentID:  target.deploymentID,
		MinerID:       replica.MinerID,
		ReplicaID:     replica.ReplicaID,
		EndpointID:    replica.EndpointID,
		Reachable:     replicaAnswered,
		Correct:       observed.Correct,
		Status:        observed.Status,
		EdgeGenerated: observed.Status != 0 && !replicaAnswered,
		Latency:       observed.Latency,
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
	if p.OnObservation != nil {
		p.OnObservation(outcome)
	}
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
		"edge_generated", outcome.EdgeGenerated,
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

func (p *Prober) cadenceMargin() time.Duration {
	if p.CadenceMargin > 0 {
		return p.CadenceMargin
	}
	return DefaultProbeCadenceMargin
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
