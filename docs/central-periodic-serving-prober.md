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
the existing `HandleHealth` path. It introduces no policy of its own.

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

A targeted probe needs the **raw hidden challenge value**. That value lives only
in the scheduler's in-memory deployment state. It is deliberately absent from
the control API, the durable store, the scheduler state export, and every
published manifest — the public contracts carry only `challenge_sha256`. An
out-of-process driver would therefore require exporting the raw challenge,
which would defeat the design that lets a manifest be published safely at all.

So the prober lives beside the scheduler in `pkg/control`, reads its targets
through the unexported `Scheduler.probeTargets`, and the hidden challenge value
gains no exported accessor.

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
it replaced.

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
not a heuristic. `validator.ProbeResult` surfaces it as `ServedByReplica` and
its complement `EdgeGenerated`.

The observation is mapped as follows:

| Probe result | Reported | Policy outcome |
| --- | --- | --- |
| status 200 with the upstream marker, body digest matches | reachable, correct | no action |
| upstream marker present, wrong body or status | reachable, **not** correct | immediate eviction, replacement, trust-zero |
| status present, **no** upstream marker (edge-generated 502/404/403/503) | **not** reachable | eviction after two failures inside the rapid window |
| no status line at all (timeout, refused, TLS failure) | **not** reachable | eviction after two failures inside the rapid window |

Classifying an edge-generated error as "reachable but incorrect" would hand a
merely offline miner the permanent, single-vantage trust-zero reserved for
serving forged content — and one probe-token misconfiguration would inflict it
on every miner in the subnet in a single pass.

An oversized upstream response is deliberately in the unreachable column: the
edge rejects it before the marker is written to the client, so the prober has no
attested view of what the miner served and does not claim one.

A correct response is accepted as independent proof that the replica answered,
because it requires a 200 carrying the exact hidden challenge value that no edge
or intermediary error page can produce. If some fronting proxy ever stripped the
marker, the only possible effect is to downgrade an incorrect response to
unreachable — never to upgrade an edge error into a trust-zero.

`fraudulent` is never inferred. It is a claim about a miner substituting or
forging content, and neither a transport failure nor a body mismatch
establishes it. The prober reports only what it observed.

Because the prober is a single vantage, unreachability alone never zeroes
trust: `policy.Monitor` requires corroboration from two distinct vantages for
that. Serving the wrong bytes does zero trust immediately, which is existing
policy and unchanged.

Observations that lose a race with the scheduler — the deployment was torn down,
or the replica replaced, while the probe was in flight — are reported as
`Stale` and logged at debug. `ErrUnknownDeployment`, `ErrDeploymentDeactivating`
and `ErrReplicaNotActive` exist so a caller can tell that benign churn apart
from a real policy or cleanup failure.

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
misconfigure it silently either.

The shipped defaults are `DefaultProbeInterval` 6s, `DefaultProbeTimeout` 5s and
`DefaultProbeCadenceMargin` 2s: 13s inside the 15s window, evicting a hung or
dark replica after roughly 22s. Concurrency is bounded by construction at one
in-flight probe per active endpoint, which is the least a driver that must
observe every endpoint on a fixed cadence can use.

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
