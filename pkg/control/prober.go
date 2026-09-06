// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"sync"
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

// replicaProber is deliberately private because its call carries the raw
// hidden challenge. Exporting this callback would let an external Go consumer
// inject a capture implementation and expand the trusted workload/scheduler
// boundary.
type replicaProber interface {
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
	EdgeGenerated bool `json:"edge_generated"`
	// ResponseComplete distinguishes a complete replica-controlled wrong
	// response from headers followed by a body transport failure.
	ResponseComplete bool `json:"response_complete"`
	// CommonModeSuppressed is true when the result was an unattributable
	// edge/network failure without fresh healthy-peer evidence. It remains
	// visible to operators but is not allowed to add health evidence, advance
	// failure counters, or impose an economic penalty. It may advance only the
	// route-local circuit revision used to fence older in-flight probes.
	CommonModeSuppressed bool `json:"common_mode_suppressed"`
	// RoutingSuppressed reports that this exact endpoint incarnation was
	// removed from ordinary round-robin traffic using the process-local serving
	// circuit. This is availability protection only: it is neither an economic
	// trust penalty nor a durable route deactivation.
	RoutingSuppressed bool `json:"routing_suppressed"`
	// RoutingRestored reports that a complete correct targeted response closed
	// a previously open serving circuit for this exact incarnation.
	RoutingRestored bool          `json:"routing_restored"`
	Latency         time.Duration `json:"latency"`
	Action          policy.Action `json:"action"`
	// Stale is true when the observation lost a race with the scheduler: the
	// deployment was torn down or the replica replaced before the action could
	// be applied. Such an outcome is expected churn, not a fault.
	Stale     bool  `json:"stale"`
	Cancelled bool  `json:"cancelled"`
	Err       error `json:"-"`
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

// Failed counts completed, current probes whose replica did not serve the
// exact expected challenge. Lifecycle cancellation and stale incarnation
// results are not health failures.
func (r SweepResult) Failed() int {
	count := 0
	for _, outcome := range r.Outcomes {
		if !outcome.Correct && !outcome.Cancelled && !outcome.Stale {
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
// challenge value, which is retained inside the trusted workload/scheduler
// boundary and is never emitted by the prober into outcomes, callbacks, logs,
// durable endpoint records, or published manifests. It reuses the existing
// Validator, policy.Monitor, and health path; its local corroboration fence
// prevents common infrastructure evidence from being attributed to every
// miner at once.
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
	// probe defaults to the scheduler's Validator. It remains private because
	// calls through it carry the raw hidden challenge value.
	probe replicaProber
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

	corroboration probeCorroboration
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
	gap, valid := probeCadenceBound(interval, timeout, margin)
	if !valid || gap > window {
		return fmt.Errorf("%w: worst-case failure gap %v (timeout %v + interval %v + margin %v) exceeds the health rapid window %v",
			ErrProbeCadence, ProbeCadenceBound(interval, timeout, margin), timeout, interval, margin, window)
	}
	return nil
}

// ProbeCadenceBound is the worst-case wall-clock gap between one endpoint's
// consecutive failure observations under Run: a hung replica burns the whole
// probe timeout before failing, the interval is measured from the end of the
// previous observation, and the margin covers applying that observation. It
// must not exceed policy.Monitor.RapidWindow.
func ProbeCadenceBound(interval, timeout, margin time.Duration) time.Duration {
	bound, valid := probeCadenceBound(interval, timeout, margin)
	if !valid {
		return time.Duration(math.MaxInt64)
	}
	return bound
}

func probeCadenceBound(interval, timeout, margin time.Duration) (time.Duration, bool) {
	if interval < 0 || timeout < 0 || margin < 0 || interval > time.Duration(math.MaxInt64)-timeout {
		return 0, false
	}
	bound := interval + timeout
	if bound > time.Duration(math.MaxInt64)-margin {
		return 0, false
	}
	return bound + margin, true
}

// probeCorroboration prevents an unattributable shared edge/network fault from
// accumulating the two policy failures that remove every route. Each counted
// failure must consume fresh correct evidence from a quorum of distinct peers
// in the same deployment, or from this process's global endpoint population
// when the deployment is a singleton. Complete replica-backed wrong content
// never enters this guard and remains immediately attributable.
type probeCorroboration struct {
	mu                  sync.Mutex
	deployments         map[string]*deploymentCorroboration
	global              deploymentCorroboration
	latestTopologyEpoch uint64
}

type deploymentCorroboration struct {
	nextSequence uint64
	successes    map[string]probeSuccess
	// consumed stores one monotonic domain-wide success sequence per target.
	// A permit needs only one witness, and every later usable witness must have
	// a greater sequence. Keeping a per-target map of every peer would grow
	// quadratically across many singleton deployments.
	consumed map[string]uint64
	pending  map[string]*unreachablePermit
	versions map[string]uint64
}

type probeSuccess struct {
	sequence uint64
	at       time.Time
}

// unreachablePermit records the exact peer-success sequences that justified
// one unattributable liveness observation. The sequences are consumed only
// after the version-bound monitor mutation commits, so cancellation or a stale
// endpoint race cannot spend evidence that was never applied.
type unreachablePermit struct {
	global    bool
	sequences map[string]uint64
}

func (c *probeCorroboration) recordSuccess(deploymentID, endpointID string, peers probePeerSet, at time.Time, healthVersion uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.noteTopologyLocked(peers.topologyEpoch)
	state := c.state(deploymentID)
	state.recordAppliedSuccess(endpointID, at, healthVersion)
	c.global.ensure()
	c.global.recordAppliedSuccess(endpointID, at, healthVersion)
}

func (c *probeCorroboration) recordApplied(deploymentID, endpointID string, peers probePeerSet, permit *unreachablePermit, healthVersion uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.noteTopologyLocked(peers.topologyEpoch)
	state := c.state(deploymentID)
	c.global.ensure()
	consumedState := state
	if permit != nil && permit.global {
		consumedState = &c.global
	}
	committed := permit == nil
	if permit != nil && consumedState.pending[endpointID] == permit {
		delete(consumedState.pending, endpointID)
		// A newer applied observation may have recorded its version while this
		// older call was completing downstream work. Never let the older result
		// regress the fence or consume evidence after a newer success.
		if consumedState.versions[endpointID] <= healthVersion {
			consumedState.consume(endpointID, permit.sequences)
			committed = true
		}
	}
	// Only the evidence domain that authorized this liveness mutation is now
	// synchronized with the monitor version. If topology later switches between
	// deployment-local and process-global corroboration, the other domain's
	// version mismatch forces peer successes newer than this failure instead of
	// reusing an old baseline from before it.
	if committed {
		consumedState.recordVersion(endpointID, healthVersion)
	}
}

func (c *probeCorroboration) releasePermit(deploymentID, endpointID string, permit *unreachablePermit) {
	if permit == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	state := &c.global
	if !permit.global {
		state = c.deployments[deploymentID]
		if state == nil {
			return
		}
	}
	if state.pending[endpointID] == permit {
		delete(state.pending, endpointID)
	}
}

func (s *deploymentCorroboration) recordVersion(endpointID string, healthVersion uint64) {
	s.ensure()
	if healthVersion > s.versions[endpointID] {
		s.versions[endpointID] = healthVersion
	}
}

func (s *deploymentCorroboration) recordAppliedSuccess(endpointID string, at time.Time, healthVersion uint64) {
	s.ensure()
	if healthVersion < s.versions[endpointID] {
		return
	}
	s.versions[endpointID] = healthVersion
	s.recordSuccess(endpointID, at)
}

func (s *deploymentCorroboration) recordSuccess(endpointID string, at time.Time) {
	s.ensure()
	if s.nextSequence == math.MaxUint64 {
		// Sequence exhaustion is practically unreachable, but resetting both
		// sides of the comparison together preserves fail-closed semantics.
		s.successes = make(map[string]probeSuccess)
		s.consumed = make(map[string]uint64)
		s.pending = make(map[string]*unreachablePermit)
		s.nextSequence = 0
	}
	s.nextSequence++
	s.successes[endpointID] = probeSuccess{sequence: s.nextSequence, at: at}
	delete(s.consumed, endpointID)
}

func (c *probeCorroboration) unreachablePermit(deploymentID, endpointID string, peers probePeerSet) (*unreachablePermit, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.noteTopologyLocked(peers.topologyEpoch)
	state := c.state(deploymentID)
	if len(peers.deployment) > 1 {
		return state.reserveUnreachable(endpointID, peers.deployment, corroborationCutoff(state, endpointID, peers.targetHealth), false)
	}
	// A deployment with one remaining endpoint has no route-local witness. Use
	// healthy endpoints from other settled deployments to prevent one shared
	// edge/token outage from independently evicting every singleton route.
	// With only one endpoint in the entire process there can be no mass cascade,
	// so preserve the ordinary isolated-failure eviction contract.
	if len(peers.global) <= 1 {
		// There is no peer whose success could distinguish an isolated miner
		// failure from a shared path failure. Preserve fail-closed serving by
		// retaining the ordinary two-failure eviction contract. The scheduler
		// separately suppresses trust-zero for this internal liveness evidence,
		// and an edge-broken replacement remains inconclusive and pool-safe.
		return c.global.reserveUnreachableWithoutWitness(endpointID)
	}
	return c.global.reserveUnreachable(endpointID, peers.global, corroborationCutoff(&c.global, endpointID, peers.targetHealth), true)
}

func corroborationCutoff(state *deploymentCorroboration, endpointID string, health policy.ObservationSnapshot) time.Time {
	state.ensure()
	// A sequence number describes when this process recorded a success, not
	// when that success was observed. Even when the monitor version still
	// matches, a delayed peer result that predates the target's latest failure
	// cannot corroborate destructive action against that target.
	return health.LastFailure
}

func (s *deploymentCorroboration) reserveUnreachable(endpointID string, active []ActiveReplica, after time.Time, global bool) (*unreachablePermit, bool) {
	s.ensure()
	if s.pending[endpointID] != nil {
		return nil, false
	}
	used := s.consumed[endpointID]
	var witnessID string
	var witness probeSuccess
	for _, peer := range active {
		if peer.EndpointID == endpointID {
			continue
		}
		success := s.successes[peer.EndpointID]
		if success.sequence <= used || (!after.IsZero() && success.at.Before(after)) {
			continue
		}
		if witnessID == "" || success.at.After(witness.at) || (success.at.Equal(witness.at) && peer.EndpointID < witnessID) {
			witnessID = peer.EndpointID
			witness = success
		}
	}
	// One fresh complete peer response proves that the shared edge/probe path is
	// functioning for this deployment. That is sufficient to durably remove a
	// repeatedly unreachable route without assigning economic blame. Requiring
	// a majority here deadlocks a three-replica deployment when two miners
	// genuinely fail: the sole healthy peer can never provide two successes.
	// A true common-mode outage has no successful peer and remains suppressed.
	if witnessID == "" {
		return nil, false
	}
	permit := &unreachablePermit{global: global, sequences: map[string]uint64{witnessID: witness.sequence}}
	s.pending[endpointID] = permit
	return permit, true
}

func (s *deploymentCorroboration) reserveUnreachableWithoutWitness(endpointID string) (*unreachablePermit, bool) {
	s.ensure()
	if s.pending[endpointID] != nil {
		return nil, false
	}
	permit := &unreachablePermit{global: true}
	s.pending[endpointID] = permit
	return permit, true
}

func (s *deploymentCorroboration) consume(endpointID string, sequences map[string]uint64) {
	s.ensure()
	used := s.consumed[endpointID]
	for _, sequence := range sequences {
		if sequence > used {
			used = sequence
		}
	}
	s.consumed[endpointID] = used
}

func (s *deploymentCorroboration) ensure() {
	if s.successes == nil {
		s.successes = make(map[string]probeSuccess)
	}
	if s.consumed == nil {
		s.consumed = make(map[string]uint64)
	}
	if s.pending == nil {
		s.pending = make(map[string]*unreachablePermit)
	}
	if s.versions == nil {
		s.versions = make(map[string]uint64)
	}
}

func (c *probeCorroboration) state(deploymentID string) *deploymentCorroboration {
	if c.deployments == nil {
		c.deployments = make(map[string]*deploymentCorroboration)
	}
	state := c.deployments[deploymentID]
	if state == nil {
		state = &deploymentCorroboration{
			successes: make(map[string]probeSuccess),
			consumed:  make(map[string]uint64),
			pending:   make(map[string]*unreachablePermit),
			versions:  make(map[string]uint64),
		}
		c.deployments[deploymentID] = state
	}
	return state
}

func (c *probeCorroboration) noteTopologyLocked(topologyEpoch uint64) {
	if topologyEpoch > c.latestTopologyEpoch {
		c.latestTopologyEpoch = topologyEpoch
	}
}

// reconcile is the only destructive corroboration GC path. Its scheduler
// epoch prevents a snapshot taken before a replacement from pruning evidence
// subsequently reserved or recorded for the new endpoint incarnation.
// Observation-local peer snapshots are deliberately never used for pruning:
// their network work can complete in any order.
func (c *probeCorroboration) reconcile(targets []probeTarget, topologyEpoch uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if topologyEpoch < c.latestTopologyEpoch {
		return
	}
	c.latestTopologyEpoch = topologyEpoch
	if topologyEpoch == math.MaxUint64 {
		// The scheduler can no longer issue a distinct later epoch. Retaining
		// bounded-per-incarnation evidence is safer than stale destructive GC.
		return
	}
	current := make(map[string][]ActiveReplica, len(targets))
	global := make([]ActiveReplica, 0)
	for _, target := range targets {
		current[target.deploymentID] = target.replicas
		global = append(global, target.replicas...)
	}
	for deploymentID, state := range c.deployments {
		active, exists := current[deploymentID]
		if !exists {
			delete(c.deployments, deploymentID)
			continue
		}
		state.prune(active)
	}
	c.global.prune(global)
}

func (s *deploymentCorroboration) prune(active []ActiveReplica) {
	current := make(map[string]struct{}, len(active))
	for _, replica := range active {
		current[replica.EndpointID] = struct{}{}
	}
	for endpointID := range s.successes {
		if _, ok := current[endpointID]; !ok {
			delete(s.successes, endpointID)
		}
	}
	for endpointID := range s.versions {
		if _, ok := current[endpointID]; !ok {
			delete(s.versions, endpointID)
		}
	}
	for endpointID := range s.consumed {
		if _, ok := current[endpointID]; !ok {
			delete(s.consumed, endpointID)
		}
	}
	for endpointID := range s.pending {
		if _, ok := current[endpointID]; !ok {
			delete(s.pending, endpointID)
		}
	}
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
	targets, topologyEpoch := p.Scheduler.probeTargetsVersioned()
	// If every route was removed before an infrastructure failure made
	// replacement acceptance inconclusive, no healthy endpoint remains to
	// signal recovery. Use one bounded half-open replacement attempt per
	// reconciliation as the circuit breaker's recovery canary. Candidate
	// failures remain fail-closed and inconclusive attempts release the clean
	// candidate, so this cannot drain the pool.
	if len(targets) == 0 {
		// A network probe timeout must never bound assignment/provisioning. The
		// scheduler applies the deployment's own lifecycle budget (normally two
		// minutes) around this bounded half-open repair attempt.
		err := p.Scheduler.repairOneDeficit(ctx)
		if err != nil && ctx.Err() == nil {
			logger := p.Logger
			if logger == nil {
				logger = slog.Default()
			}
			if errors.Is(err, ErrAcceptanceInconclusive) || errors.Is(err, context.DeadlineExceeded) {
				logger.Debug("deferred replacement recovery remains inconclusive", "error", err)
			} else {
				logger.Warn("deferred replacement recovery failed", "error", err)
			}
		}
		targets, topologyEpoch = p.Scheduler.probeTargetsVersioned()
	}
	p.corroboration.reconcile(targets, topologyEpoch)
	for _, target := range targets {
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
		if ctx.Err() != nil || outcome.Stale || outcome.Action.RemoveFromRouting {
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
	targets, topologyEpoch := p.Scheduler.probeTargetsVersioned()
	p.corroboration.reconcile(targets, topologyEpoch)
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
	outcome := ProbeOutcome{
		DeploymentID: target.deploymentID,
		MinerID:      replica.MinerID,
		ReplicaID:    replica.ReplicaID,
		EndpointID:   replica.EndpointID,
	}
	// Bind this network operation to the health revision that exists before
	// any bytes leave the process. Taking the snapshot after ProbeReplica would
	// let an older success adopt the revision created by a newer failure and
	// incorrectly reopen that failure's temporary routing circuit.
	started, err := p.Scheduler.activeProbePeers(target.deploymentID, replica.ReplicaID, replica.EndpointID, replica.MinerID)
	if err != nil {
		outcome.Err = err
		outcome.Stale = isStaleObservation(err)
		p.finishObservation(outcome)
		return outcome
	}
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
	responseComplete := observed.ResponseComplete || observed.Correct
	replicaAnswered := (observed.ServedByReplica && responseComplete) || observed.Correct
	outcome.Reachable = replicaAnswered
	outcome.Correct = observed.Correct
	outcome.Status = observed.Status
	outcome.EdgeGenerated = observed.EdgeGenerated && responseComplete && !replicaAnswered
	outcome.ResponseComplete = responseComplete
	outcome.Latency = observed.Latency
	// A parent cancellation is lifecycle control, never evidence about a miner.
	// Check it after the potentially blocking probe and immediately before any
	// health/corroboration mutation.
	if err := ctx.Err(); err != nil {
		outcome.Cancelled = true
		outcome.Err = err
		p.finishObservation(outcome)
		return outcome
	}
	observedAt := p.clock()().UTC()
	active, err := p.Scheduler.activeProbePeers(target.deploymentID, replica.ReplicaID, replica.EndpointID, replica.MinerID)
	if err != nil {
		outcome.Err = err
		outcome.Stale = isStaleObservation(err)
		p.finishObservation(outcome)
		return outcome
	}
	// A liveness result (success or unreachability) is valid as policy evidence
	// only when no newer health fact landed while its request was in flight. Its
	// local routing result has an independent circuit revision: external policy
	// reports may not mask a targeted local failure or recovery, while an older
	// local request may not overwrite a newer circuit decision. Complete,
	// attributable wrong content is definitive evidence about this still-active
	// exact endpoint and must not be maskable by concurrent liveness updates.
	definitiveFault := outcome.Reachable && !outcome.Correct
	if active.targetCircuit != started.targetCircuit && !definitiveFault {
		outcome.Err = errHealthObservationChanged
		outcome.CommonModeSuppressed = true
		p.finishObservation(outcome)
		return outcome
	}
	if active.targetHealth.Version != started.targetHealth.Version && !definitiveFault {
		changed, applied, circuitErr := p.Scheduler.setEndpointAvailabilityIfCircuitVersion(
			ctx, target.deploymentID, replica.ReplicaID, replica.EndpointID, replica.MinerID,
			outcome.Reachable && outcome.Correct, started.targetCircuit,
		)
		outcome.RoutingRestored = outcome.Correct && changed
		outcome.RoutingSuppressed = !outcome.Correct && changed
		outcome.CommonModeSuppressed = true
		outcome.Err = errors.Join(errHealthObservationChanged, circuitErr)
		if !applied {
			outcome.Stale = isStaleObservation(circuitErr)
			outcome.Cancelled = ctx.Err() != nil
		}
		p.finishObservation(outcome)
		return outcome
	}
	var permit *unreachablePermit
	if !outcome.Reachable {
		var allowed bool
		permit, allowed = p.corroboration.unreachablePermit(target.deploymentID, replica.EndpointID, active)
		if !allowed {
			changed, applied, suppressErr := p.Scheduler.suppressEndpointAvailabilityIfVersion(
				ctx, target.deploymentID, replica.ReplicaID, replica.EndpointID, replica.MinerID,
				started.targetCircuit,
			)
			if !applied {
				outcome.Err = suppressErr
				outcome.Stale = isStaleObservation(suppressErr)
				outcome.Cancelled = ctx.Err() != nil
				p.finishObservation(outcome)
				return outcome
			}
			outcome.RoutingSuppressed = changed
			outcome.CommonModeSuppressed = true
			outcome.Err = suppressErr
			p.finishObservation(outcome)
			return outcome
		}
		// releasePermit is a no-op after recordApplied commits this exact pointer,
		// and rolls it back on every cancellation/stale/version-race return.
		defer p.corroboration.releasePermit(target.deploymentID, replica.EndpointID, permit)
	}
	// Fraudulence is a claim about a miner substituting or forging content and
	// is never inferred from a transport-level or body-mismatch observation.
	// The prober reports only what it saw and lets policy decide.
	action, applied, routingChanged, err := p.Scheduler.handleEndpointHealthVersioned(
		ctx, target.deploymentID, replica.ReplicaID, replica.EndpointID, replica.MinerID,
		p.vantage(), outcome.Reachable, outcome.Correct, false, observedAt,
		started.targetHealth.Version, started.targetCircuit,
	)
	if !applied {
		outcome.RoutingRestored = outcome.Correct && routingChanged
		outcome.RoutingSuppressed = !outcome.Correct && routingChanged
		outcome.Err = err
		switch {
		case ctx.Err() != nil:
			outcome.Cancelled = true
			outcome.Err = ctx.Err()
		case errors.Is(err, errHealthObservationChanged):
			outcome.CommonModeSuppressed = true
		default:
			outcome.Stale = isStaleObservation(err)
		}
		p.finishObservation(outcome)
		return outcome
	}
	outcome.RoutingRestored = outcome.Correct && routingChanged
	outcome.RoutingSuppressed = !outcome.Correct && routingChanged
	outcome.Action = action
	outcome.Err = err
	outcome.Stale = isStaleObservation(err)
	// Once handleEndpointHealthVersioned passes its version check, the monitor
	// observation is committed even if a downstream trust, cleanup, or capacity
	// repair returns an error. Keep the corroboration version aligned with that
	// committed fact; otherwise a healthy response that triggered an
	// inconclusive repair would disappear from shared-path evidence.
	if !outcome.Stale && !outcome.Cancelled {
		appliedVersion := active.targetHealth.Version + 1
		if outcome.Correct {
			p.corroboration.recordSuccess(target.deploymentID, replica.EndpointID, active, observedAt, appliedVersion)
		} else {
			p.corroboration.recordApplied(target.deploymentID, replica.EndpointID, active, permit, appliedVersion)
		}
	}
	p.finishObservation(outcome)
	return outcome
}

func (p *Prober) finishObservation(outcome ProbeOutcome) {
	p.log(outcome)
	if p.OnObservation != nil {
		p.OnObservation(outcome)
	}
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
		"endpoint_id", outcome.EndpointID,
		"reachable", outcome.Reachable,
		"correct", outcome.Correct,
		"status", outcome.Status,
		"edge_generated", outcome.EdgeGenerated,
		"response_complete", outcome.ResponseComplete,
		"common_mode_suppressed", outcome.CommonModeSuppressed,
		"routing_suppressed", outcome.RoutingSuppressed,
		"routing_restored", outcome.RoutingRestored,
	}
	switch {
	case outcome.Cancelled:
		logger.Debug("periodic probe cancelled before health mutation", append(attrs, "error", outcome.Err)...)
	case outcome.Stale:
		// Ordinary churn: the scheduler replaced or removed this incarnation
		// while the probe was in flight.
		logger.Debug("periodic probe observation is stale", append(attrs, "error", outcome.Err)...)
	case outcome.CommonModeSuppressed:
		logger.Warn("periodic probe suppressed unattributable shared-path failure", attrs...)
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

func (p *Prober) prober() replicaProber {
	if p.probe != nil {
		return p.probe
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
