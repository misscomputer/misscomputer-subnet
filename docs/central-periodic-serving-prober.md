# Central periodic serving prober

## What it is

The scheduler probes every replica through the internal targeted path at
admission time, and `Scheduler.HandleHealth` applies post-acceptance policy —
eviction from routing, replacement assignment, and trust-zero. Until now
`HandleHealth` only ran when some external vantage posted an observation to
`POST /v1/health`. A miner that was accepted and then went dark, or started
serving something other than the hidden challenge, kept its assignment and kept
receiving edge traffic until a human or an external reporter noticed.

`control.Prober` is the missing driver. It re-probes every active replica of
every settled deployment on an interval and applies each observation through
the existing health-policy path. A local corroboration fence prevents a shared
edge or network failure from being attributed to every miner at once; it does
not change the action for complete wrong content or for an isolated endpoint
whose healthy peers prove that the shared path is working.

## Authority boundary

This is the **central operator's internal eligibility decision**: who is
currently fit to be assigned traffic. It is single-operator by construction,
needs no multi-validator consensus, and is entirely separate from the public
multi-validator flow in [`public-validator-live-probe.md`](public-validator-live-probe.md).
A public validator's `validator-probe-report` remains, as that document states,
"not a score, not a weight, and not an authorization to submit anything"; this
prober likewise confers no scoring authority. The two paths share nothing but
the fact that both look at whether a route serves the right bytes.

## Why it runs in-process

A targeted probe needs the **raw hidden challenge value**. For an active
deployment, that value lives inside the narrow trusted workload/scheduler
boundary (synthetic campaign recovery also retains its private workload
material). The privileged deployment ingress terminates inside that boundary;
the value is deliberately absent from outward control responses, durable
endpoint records, scheduler state export, and every published manifest — the
published contracts carry only `challenge_sha256`. An out-of-process driver
would therefore require a new export across that boundary.

So the prober lives beside the scheduler in `pkg/control`, reads its targets
through the unexported `Scheduler.probeTargetsVersioned`, and the hidden
challenge value gains no exported accessor. The probe callback and its
interface are also unexported, so an external Go consumer cannot inject an
implementation that captures the expected value. Prober outcomes, callbacks,
logs, durable endpoint records, published manifests, and outward control
responses contain observations and digests only, never the raw value.

## Behaviour

`Run` gives every active endpoint its own probe loop: probe, apply, wait
`Interval`, repeat. Endpoints are therefore paced independently of each other —
see [Cadence and the rapid window](#cadence-and-the-rapid-window) for why that
is a correctness requirement rather than a performance choice. `Sweep` remains
available as a one-shot diagnostic pass in canonical deployment order; it is not
the continuous driver.

Deployments that are `deploying` or `deactivationRequested`, and deployments
with no active replicas, are skipped, so probing can never race acceptance or
teardown. Loops are keyed by endpoint ID, which carries generation and nonce, so
a replacement never inherits the loop or the health counters of the incarnation
it replaced. Every result is checked against that exact endpoint ID before it
can update corroboration state, then checked again atomically at the scheduler
mutation boundary. A result from an older redeploy is discarded as stale even
when its deployment, replica, and miner labels are identical to the new one.

Each replica is probed with `ProbeReplica` — targeted, not public. An untargeted
request round-robins across healthy replicas, so a single failing replica could
otherwise hide behind its peers.

### Reading a probe result

A probe travels through the edge, and **the edge answers with a status of its
own whenever the miner is the thing that is down or unroutable**: `502` for a
dial failure or a nil tunnel target, `404` for a replica dropped from the
routes, `403` for a probe-token mismatch, `503` when nothing on the host is
healthy. A status code alone therefore says nothing about whether the miner
replied.

`pkg/edge` sets `X-Miss-Edge-Upstream: replica` in the reverse proxy's
`ModifyResponse`, which runs only once a real upstream response has arrived. It
is `Set`, not `Add`, so a replica cannot influence it, and no edge-generated
error response passes through that code path — absence of the marker is exact,
not a heuristic. `validator.ProbeResult` surfaces the marker as
`ServedByReplica` and flags a completed, incorrect unmarked response as
`EdgeGenerated`. Exact challenge content remains independently sufficient when
an intermediary strips unknown headers. The validator also records
`ResponseComplete`, which becomes true only after the body is read through EOF
without a transport error. Headers followed by a truncated body prove neither
complete content nor miner guilt.

The observation is mapped as follows:

| Probe result | Reported | Policy outcome |
| --- | --- | --- |
| complete status 200 with the upstream marker, body digest matches | reachable, correct | no action; supplies healthy-peer evidence |
| complete response with the upstream marker, wrong body or status | reachable, **not** correct | immediate eviction and replacement; trust-zero for production-eligible deployments |
| headers/marker arrive but the body read fails | **not** reachable, incomplete | liveness evidence only; never immediate trust-zero |
| complete status with **no** upstream marker (edge-generated 502/404/403/503) | **not** reachable | liveness evidence only |
| no status line at all (timeout, refused, TLS failure) | **not** reachable | liveness evidence only |

Classifying an edge-generated error as "reachable but incorrect" would hand a
merely offline miner the permanent, single-vantage trust-zero reserved for
serving forged content — and one probe-token misconfiguration would inflict it
on every miner in the subnet in a single pass.

A response rejected by the edge's configured upstream-size limit is deliberately
in the unreachable column: the edge diverts it to its own error response before
the marker is written to the client, so the prober has no attested view of what
the miner served and does not claim one. A smaller, complete marked body that is
already longer than the bounded challenge comparison is attributable wrong
content; the validator still drains it through EOF before making that claim.

A correct response is accepted as independent proof that the replica answered,
because it requires a 200 carrying the exact hidden challenge value that no edge
or intermediary error page can produce. If some fronting proxy ever stripped the
marker, the only possible effect is to downgrade an incorrect response to
unreachable — never to upgrade an edge error into a trust-zero.

`fraudulent` is never inferred. It is a claim about a miner substituting or
forging content, and neither a transport failure nor a body mismatch
establishes it. The prober reports only what it observed.

Unreachability from the internal prober never zeroes trust: it is ambiguous
liveness evidence from one shared path, and the scheduler strips that economic
action even if external history already supplied another vantage. The external
health path retains its existing multi-vantage policy. Complete wrong bytes
attributable to a replica do zero trust immediately for a production-eligible
deployment, which is existing policy and unchanged. `ScoringEvidenceOnly`
deployments retain eviction and replacement but suppress even that attributable
economic action.

### Common-mode protection

An edge, fronting network, or probe-token fault can make every clean endpoint
look unreachable at the same time. Counting two such rounds independently for
every route would remove all routes, and probing replacements through the same
broken path would exhaust the clean pool.

The prober therefore keeps a private, in-memory corroboration fence per
deployment and endpoint incarnation. An unattributable failure can enter
`policy.Monitor` only when it consumes fresh complete-success evidence from at
least one current endpoint other than the failing one. One healthy witness is
intentional: requiring a majority deadlocks a three-replica deployment when two
miners genuinely fail, because the sole healthy replica can never supply two
successes. Evidence is consumed independently per failed target, so that one
healthy replica can justify availability removal of both dead peers but cannot
be spent twice on consecutive failures of the same endpoint. A singleton
deployment has no route-local witness, so it falls back to the same validator
process's current endpoints in other deployments. This fallback protects a
subnet containing many one-replica deployments from the same shared edge/token
cascade; it does not coordinate with another validator.

A later failure must consume newer peer evidence. Healthy evidence must also
postdate any newer external health failure that the prober did not apply. The
monitor exposes a versioned snapshot captured before probe network I/O and
atomically rejects the prober's result if health history changes before the
mutation. During a common
outage, at most one earlier baseline-backed failure can have entered the
monitor; no peer successes advance, so the destructive second failure is
suppressed. If probing starts during the outage, even that baseline evidence is
absent. Suppressed results remain in `ProbeOutcome` with
`common_mode_suppressed=true` for alerting and diagnosis.

Independently of economic and durable policy, the first incomplete transport
or edge-generated failure opens a **process-local serving circuit** for that
exact endpoint incarnation. The router stops selecting it for ordinary
customer traffic, while targeted internal probes continue to reach it. A
complete correct targeted response from this validator's in-process prober
closes the circuit immediately. An external healthy report cannot reopen a
circuit because it did not verify recovery through this validator's own edge
path. This
separates availability from guilt: two of three genuinely dead miners stop
receiving traffic and can be replaced using the remaining healthy witness,
while a subnet-wide edge outage temporarily suppresses already-failing routes
without trust-zero, durable eviction, or consumption of the replacement pool.
Circuit state is not persisted and cannot change ledger trust.

Peer snapshots belong to individual in-flight observations and can complete
out of order, so they never prune unrelated corroboration evidence. Cleanup is
performed only from a scheduler snapshot carrying a monotonic topology epoch;
a stale snapshot cannot erase a replacement's evidence, and a permit already
reserved for a still-active target survives witness replacement until its exact
health mutation commits or rolls back. If topology changes between the
deployment-local and process-global evidence domains, successes from before the
last failure are not reusable in the new domain.

Rapid routing-removal counters are source-classed between this internal
periodic prober and external `/v1/health` reports. One ambiguous periodic result
and one external result therefore cannot become the destructive two-failure
pair in either order. Two corroborated periodic failures still evict an
isolated endpoint, and two external failures retain the external health path's
existing authority; multi-vantage consecutive evidence remains a separate
policy input.

For external reports, each `vantage` must be a stable label bound or derived by
the authenticated private gateway. The public runtime cannot infer the gateway
principal from its local socket; accepting arbitrary caller-selected vantage
labels would let one credential impersonate multiple evidence sources.

If the whole process has only one active endpoint, no independent endpoint can
distinguish a miner failure from a path failure. There is also no subnet-wide
cascade to arrest. That endpoint therefore retains the ordinary two-failure
fail-closed eviction contract, while liveness observations from the internal
prober are forbidden from setting economic trust to zero. If the shared path is
actually broken, replacement acceptance is inconclusive and preserves the
clean spare for a later half-open recovery attempt. External health successes
do not freeze this single-endpoint liveness fallback.

For one isolated failed endpoint, its healthy peers continuously refresh the
proof, so the ordinary two-failure eviction contract still applies. Complete
replica-backed wrong content is attributable and bypasses this fence entirely.
There is no exchange with another validator and no new scoring authority.

Admission remains fail-closed: an assignment is never activated without a
correct probe. A no-response, edge-generated response, cancelled probe, or
incomplete body is nevertheless inconclusive rather than miner-attributable;
the pending route/runtime is cleaned up without trust-zero, negative scoring
evidence, or permanent candidate exclusion after successful cleanup. If exact
route/runtime cleanup itself fails, the scheduler retains that ticket and
quarantines the candidate within the deployment until a later healthy signal
retries cleanup; this ownership quarantine is evidence-neutral and never
changes trust. A request cancellation transfers every launched ticket into the
same lease before returning. The candidate is not reusable until the original
assignment worker has joined and the post-join exact route/miner/durable
cleanup has succeeded. If either cleanup attempt fails, the exact lease remains
quarantined for an explicit later retry. When this happens during initial
deployment, the failed deployment remains cleanup-only and blocks redeploy of
that ID until explicit cleanup succeeds; it
can never be half-opened into service behind the failed API call. Initial and
replacement admission traverse each currently eligible clean candidate at most
once per operation after an inconclusive response, so a persistently silent
candidate cannot prevent a later clean miner from being tried. If the bounded
pool is exhausted, the remaining capacity debt stays derived from the desired,
active, and reserved counts, and successfully cleaned inconclusive candidates
become retryable on a later operation without an economic penalty. Candidate
selection also rotates globally after every reservation so separate operations
do not always begin at the same miner.
Cleanup leases and deployment deficits use separate round-robin cursors and do
at most one unit of each per trigger; one permanent low-ID failure therefore
cannot block process-wide recovery. Complete healthy observations repair one
deficit at a time, so concurrent deficits cannot collapse into one boolean. If
every route is absent, periodic reconciliation makes one bounded half-open
recovery attempt instead. The five-second probe timeout applies only to a
single HTTP probe; assignment/provisioning uses the deployment lifecycle budget
(two minutes by default). A complete marked wrong response and an invalid signed
receipt remain
economically punishable.

Observations that lose a race with the scheduler — the deployment was torn down,
or the replica replaced, while the probe was in flight — are reported as
`Stale` and logged at debug. `ErrUnknownDeployment`, `ErrDeploymentDeactivating`
and `ErrReplicaNotActive` exist so a caller can tell that benign churn apart
from a real policy or cleanup failure.

Parent cancellation is checked again after every probe and before any of these
mutations. `Run` joins all endpoint loops, `Plane.Run` joins the prober, and the
runtime joins `Plane.Run` before `Plane.Close`. The scheduler then drains every
owned assignment/cleanup worker before the gateway or store is closed. A drain
deadline is returned as a shutdown error and leaves those resources open for a
later retry; shutdown cancellation is never counted as miner-health evidence
and no late worker can use a resource that was closed underneath it.

## Cadence and the rapid window

Policy evicts an unreachable endpoint on its second failure inside
`policy.Monitor.RapidWindow` (15s by default) and resets the counter whenever
two consecutive failures are further apart. The quantity that must therefore be
bounded is **the wall-clock gap between one endpoint's consecutive failure
observations** — not the configured interval.

Under a sequential sweep those are very different numbers. The interval is
measured from the end of the previous pass, so the real gap is
`probe timeout + rest-of-sweep + interval`, and the rest of the sweep grows with
the deployment and replica count. A hung replica — one that accepts the
connection and then stays silent — burns the entire probe timeout before it
fails, and a peer being evicted drags a whole replacement assignment into the
same pass. With the old 10s interval and 5s timeout, a deployment set of any
real size pushed that gap past 15s, the counter reset on every pass, and a hung
replica was **never evicted, silently, forever**.

Per-endpoint loops remove the coupling: the gap is
`probe timeout + interval + the cost of applying one no-action observation`,
whatever every other endpoint is doing. `ProbeCadenceBound` states it and
`Prober.Validate` enforces

```
timeout + interval + cadence margin <= policy.Monitor.RapidWindow
```

refusing to start otherwise — a cadence that cannot evict is not a degraded
mode, it is a prober that does nothing. A non-positive timeout is refused for
the same reason: without a deadline the prober itself owns, a hung replica's
failure gap is whatever the HTTP client happens to allow. `controlplane.New`
performs the same checks at construction, so a library caller cannot
misconfigure it silently either. The bound uses checked duration addition;
individually parseable values whose sum would overflow `time.Duration` are
refused rather than wrapping into an apparently valid negative gap.

The shipped defaults are `DefaultProbeInterval` 6s, `DefaultProbeTimeout` 5s and
`DefaultProbeCadenceMargin` 2s: 13s inside the 15s window. An already running
endpoint loop with healthy peers evicts an isolated hung replica after roughly
22s (6s wait + 5s timeout, twice). A newly activated endpoint can first wait up
to one 6s reconciliation interval before its loop is created, so
activation-to-eviction can approach 28s. Common-mode suppression can delay an
ambiguous failure until fresh healthy-peer evidence exists. Concurrency remains
bounded by construction at one in-flight probe per active endpoint.

## Enabling it

The prober is **opt-in**. Without the flag the runtime behaves exactly as
before.

```
misscomputer-runtime \
  --periodic-probe-interval 6s \
  --periodic-probe-timeout 5s \
  ...
```

`--periodic-probe-interval 0` (the default) keeps it inert. The runtime refuses
a negative interval or timeout, and refuses a timeout that is not shorter than
the interval. `controlplane.Config.PeriodicProbeInterval` is the equivalent
library-level switch, and `controlplane.New` additionally refuses any pairing
whose cadence bound exceeds the health rapid window. `Plane.Run` supervises the
prober beside the synthetic campaign and stops it on cancellation.

## What it deliberately does not do

It does not record `durable.Observation` rows. Health actions and weight
evidence are separate concerns: the observation table feeds
`validator.PrepareWeights`, and having an internal liveness driver silently
inject scoring evidence at its own sweep rate would change weight outcomes as a
side effect of an operational setting. Routing eligibility is the stated job,
and it is the whole job. Feeding prober observations into weight preparation
would be a deliberate, separately reviewed decision.
