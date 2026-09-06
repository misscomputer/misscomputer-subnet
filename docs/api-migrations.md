# Public API migrations

## Periodic prober hardening and health-observation v3

This release contains two intentional compatibility breaks needed to keep a
raw assignment challenge and endpoint-health evidence inside their exact
security boundaries.

### Go `control.Prober` construction

The exported `control.ReplicaProber` callback and exported `Prober.Probe` field
were removed. Both accepted the raw hidden challenge value and therefore let
an arbitrary external Go callback capture material that must remain inside the
scheduler/runtime process.

External callers must no longer inject a probe callback. Construct a
`control.Prober` with its `Scheduler`, `Interval`, `Timeout`, and optional
logger/observation callback, then call `Run` (continuous operation) or `Sweep`
(one-shot diagnostics). The scheduler creates the private targeted validator
probe internally. `ProbeOutcome` exposes only result metadata and never the
raw challenge. There is deliberately no compatibility adapter for the removed
callback seam.

`Prober.Timeout` is now the authoritative whole-request budget for periodic
probes even when it exceeds five seconds. The scheduler validator's independent
five-second default remains in force for admission; the periodic path preserves
the configured HTTP transport but prevents that admission-oriented client
timeout from silently shortening its own context deadline. An earlier parent
deadline still wins, and preserved transport-stage bounds or failures may
return sooner. This correction changes no API shape and leaves the shipped 5s
timeout default unchanged.

`Prober.Validate` now returns `ErrProbeCadence` when the scheduler health
monitor's `RapidWindow` is zero or negative. Such a policy resets rapid failure
evidence instead of accumulating the failures needed for eviction, so it is no
longer accepted as an inert configuration. The shipped 15s rapid window is
unchanged.

`control.Scheduler.HandleHealth` also intentionally adds `endpointID` between
the stable replica ID and miner ID. Go callers must retain the endpoint ID from
the active-replica snapshot and pass that exact value; there is no legacy
overload because silently substituting an empty or stable identifier would
reintroduce cross-incarnation replay.

`validator.ProbeResult.At` now identifies the terminal network observation,
not request start. For a complete response it is captured immediately after
body EOF, and `Latency` includes the complete body transfer. This causal
timestamp is required so a result completed before a peer failure cannot be
re-stamped as fresh corroboration merely because its goroutine was processed
later. Callers that need the approximate request start can subtract `Latency`
from `At`.

### `POST /v1/health`

Health reports use the message-scoped protocol
`subnet-synapse.v3`. Other neuron messages remain on
`subnet-synapse.v2`.

Version 3 adds the required `endpoint_id`. Reporters obtain it from
`GET /v1/deployments/{deployment}` and must submit the exact tuple
`deployment_id`, `replica_id`, `endpoint_id`, and `miner_hotkey` they probed.
The production private gateway authenticates requests before forwarding them
over the root-owned mode-0600 Unix runtime socket. The runtime socket itself
uses canonical JSON and filesystem access control; it does not add a second
request signature. Because `endpoint_id` is in the authenticated request body,
the gateway authentication covers the incarnation, and the runtime checks the
tuple again against current scheduler state immediately before any health
mutation. Older liveness reports are rejected endpoint-globally, including
external successes that predate this validator's latest internal probe
evidence; at the newest timestamp, each bounded vantage may contribute once
(with a fixed per-instant cap), and attributable wrong or fraudulent content
is never discarded solely because a newer liveness report
arrived first.

The private gateway must also bind `vantage` to the authenticated reporter
(derive it from the principal or reject a body value that does not match the
principal's configured stable label). The runtime bounds and deduplicates that
label but cannot recover a principal identity from its mode-0600 socket. A
gateway that lets one authenticated writer rotate arbitrary vantage strings
would invalidate the multi-vantage trust-zero threshold and is not a conforming
deployment.

External healthy reports remain valid liveness evidence, but they cannot close
the process-local serving circuit owned by this validator's targeted prober.
Only a complete correct targeted response through the same local edge path can
restore ordinary traffic after that circuit opens.

The Go server and Python model both reject impossible evidence combinations:
`correct` requires `reachable`, while `fraudulent` requires a reachable but
incorrect response. Identity and vantage strings retain the schema's explicit
size bounds before they enter scheduler or monitor state.

The HTTP boundary durably inserts the accepted scoring sample after exact
incarnation/replay validation but before mutating health or routing policy. If
that insert fails, no health evidence is consumed and the same report remains
retryable. Once it succeeds, a later cleanup or replacement error is returned
as `health_action_failed`; replaying that committed report is rejected and
never creates a duplicate sample.

The deprecated Go `Scheduler.ObserveHealth` compatibility seam now also
requires the exact endpoint ID and verifies the signed route tuple before
changing its legacy route-only policy state. Live bridge integrations must use
the v3 HTTP contract (or `HandleHealth`) so scheduler removal, cleanup, and
replacement ownership remain coordinated.

Version 2 health reports are rejected fail-closed because a stable replica ID
does not identify a generation and assignment nonce. The checked-in v1/v2
fixtures and schemas remain immutable historical artifacts and are not
reinterpreted as v3.

Operators should upgrade in this order:

1. pause the old health reporter;
2. deploy the runtime advertising the `health-observation-v3` capability;
3. upgrade the reporter to fetch and retain the exact endpoint ID and emit v3;
4. resume reporting only after the capability and endpoint tuple are present.

No migration exports the hidden challenge, changes validator scoring, submits
weights, or introduces multi-validator coordination.
