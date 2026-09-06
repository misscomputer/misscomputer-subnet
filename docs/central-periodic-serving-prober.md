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

One sweep visits deployments in canonical order and replicas sequentially,
mirroring the sequential discipline of the public probe CLI. Bounded
concurrency is a later refinement that would change no contract here.

Deployments that are `deploying` or `deactivationRequested`, and deployments
with no active replicas, are skipped, so a sweep can never race acceptance or
teardown.

Each replica is probed with `ProbeReplica` — targeted, not public. An untargeted
request round-robins across healthy replicas, so a single failing replica could
otherwise hide behind its peers.

The observation is mapped as follows:

| Probe result | Reported | Policy outcome |
| --- | --- | --- |
| status 200, body digest matches | reachable, correct | no action |
| any status, wrong body or status | reachable, **not** correct | immediate eviction, replacement, trust-zero |
| no status line at all (timeout, refused, TLS failure) | **not** reachable | eviction after two failures inside the rapid window |

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

## Interval and the rapid window

The interval **must stay below `policy.Monitor.RapidWindow`** (15s by default).
Policy evicts an unreachable endpoint on its second failure inside that window
and resets the counter whenever two consecutive failures are further apart. A
single-vantage driver sweeping at or beyond the rapid window would therefore
reset its own evidence on every pass and never evict anything.

`DefaultProbeInterval` is 10s for this reason, which evicts a dark replica after
roughly 20s. `Prober.Run` logs a warning if it is started with an interval that
cannot ever evict. `DefaultProbeTimeout` is 5s so one hung replica cannot stall
the sweep past its own interval.

## Enabling it

The prober is **opt-in**. Without the flag the runtime behaves exactly as
before.

```
misscomputer-runtime \
  --periodic-probe-interval 10s \
  --periodic-probe-timeout 5s \
  ...
```

`--periodic-probe-interval 0` (the default) keeps it inert. The runtime refuses
a negative interval or timeout, and refuses a timeout that is not shorter than
the interval. `controlplane.Config.PeriodicProbeInterval` is the equivalent
library-level switch; `Plane.Run` supervises the prober beside the synthetic
campaign and stops it on cancellation.

## What it deliberately does not do

It does not record `durable.Observation` rows. Health actions and weight
evidence are separate concerns: the observation table feeds
`validator.PrepareWeights`, and having an internal liveness driver silently
inject scoring evidence at its own sweep rate would change weight outcomes as a
side effect of an operational setting. Routing eligibility is the stated job,
and it is the whole job. Feeding prober observations into weight preparation
would be a deliberate, separately reviewed decision.
