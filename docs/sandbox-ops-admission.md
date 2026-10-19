# Sandbox operations: admission at the miner neuron

Status: **default off, unactivated.** This applies only with
`--sandbox-ops on` (which requires `--sandbox-leases on`). With ops off, the
miner neuron's routes, features, request bounds, rate accounting and
scheduling are unchanged.

Tenant ops reach a miner from the same validator hotkey that also sends lease
reservations, leases, renewals and releases, the capability handshake, and
deployment work. Without the rules below, a busy or hostile tenant could
spend the validator's whole request budget, or every worker slot, on ops. The
renewals of other tenants' leases and the handshake would then fail, and
leases would expire through no fault of the miner or the tenants.

## What every request keeps

Every route keeps btauth, the operator list, the unique registration, the
validator permit, the stake minimum and the signed service binding checks
(`AuthorizationPolicy.identify`, `_verify_assignment_identity`). The rules
below only change where an authenticated request's rate is counted and
whether it may wait for a worker. Nothing is counted before btauth and the
identity checks pass, so an unauthenticated or unauthorized request can
never spend, or be exempt from, any window.

The route a handler serves fixes its rate class. The one refinement is on the
ops route: an op request is counted in the cancel reserve only when all of
the following hold, and as an ordinary op otherwise, including when it cannot
be decoded at all:

- it decodes as a `subnet-sandbox-ops-synapse.v1` request whose document has
  a valid op-request routing header;
- its `caller_hotkey` is the btauth-verified caller;
- its document's `op` is exactly the string `exec_cancel`;
- it carries no payload. The agent refuses a payload on `exec_cancel`
  (`sandbox_op_payload_unexpected`).

No request member names a class, a bucket or a bound. Every window is kept
per validator hotkey.

## Rate classes

| Class | Requests | Bound per validator hotkey |
| --- | --- | --- |
| `default` | every route except ops: sandbox lease documents and replay, capabilities, deploy, status, static, deactivate | 120 requests per 60 s, unchanged |
| `sandbox-ops` | every op request on `POST /api/v1/sandbox/ops` that is not counted as a cancel, including undecodable ones | 300 requests per 10 s |
| `sandbox-ops-cancel` | well-formed `exec_cancel` requests, as defined above | 64 requests per 10 s |

Ops are never counted in the `default` window, so an exhausted ops budget
cannot refuse a renewal or a handshake. Ordinary ops never spend the cancel
reserve and cancels never spend ordinary budget. The reserve is finite: a
cancel flood is refused exactly like an ops flood. As before, a refused
request is not counted.

## Admission to the agent

Lease lifecycle documents, deploy and static deploy keep the existing
stake-ordered gate (`--max-concurrency`). Ops never use it. They have their
own admission, which never waits:

- at most `SANDBOX_OPS_CONCURRENCY` (32) ops are forwarded to the agent at
  once;
- a cancel, as classified above, may use `SANDBOX_OPS_CANCEL_HEADROOM` (4)
  more admissions;
- beyond that an op is refused at once. A queue would add only stale work and
  hold ingress, because the agent itself refuses a full in-flight bound
  immediately.

A slot is returned when its forward ends for any reason, including
cancellation.

At startup with ops on, the neuron refuses a configuration in which ops, the
cancel headroom, `--max-concurrency` and a reserve of 16 requests exceed the
64-request ingress bound. With the defaults, `--max-concurrency` can be at
most 12. The refusal is reported as a clean startup error with that message
and the process exits, rather than with a traceback.

## Refusals

| Cause | Status | `detail` | `Retry-After` |
| --- | --- | --- | --- |
| ops or cancel window full | 429 | `sandbox_ops_rate_exceeded` | seconds until the oldest counted request of that window leaves it (1..10) |
| ops capacity (and, for a cancel, its headroom) full | 429 | `sandbox_ops_capacity_exhausted` | 1 |

Both are decided before any agent contact. Nothing is forwarded, nothing is
signed, and the op had no effect. Answers from the agent keep their own
status. `503 sandbox_ops_busy` and `500 sandbox_ops_internal` still mean
that the outcome may be unknown (lane document), and this hop never turns
them into a 429.

Across the later hops:

- **Miner neuron (public):** an agent answer that arrives after dispatch but
  does not validate (malformed JSON, an extra member, or a wrong type) is
  answered `502 sandbox_agent_answer_invalid`. The op or document may already
  have run, so this is possibly delivered and never a 400 (R23-PYGAP-01).
  This covers the op and lease-document forwarders. Each op is dispatched
  once, and its admission slot is returned. A definitive agent refusal keeps
  its status and code, and a malformed inbound request is still refused with
  a 4xx before dispatch. Other miner forwarders (deploy, static, status) use
  the earlier pattern and are not covered by this change.
- **Validator bridge (public):** the bridge sends each op to the miner
  exactly once and never resends it itself. A resend at this hop could
  return a refusal (a 429 or any other 4xx) that hides an earlier attempt
  which may have reached the miner, turning a possibly executed op into a
  definitive refusal (R23-CTRL-AR-01). Any failure after the send, whether a
  miner 5xx, a lost, cut or timed-out answer, or an unusable or oversized
  answer, is answered `502 dendrite_upstream` or `504 dendrite_timeout`.
  The runtime must treat that as possibly delivered and resolve it only by
  resending the same signed op (same `op_nonce`), never a new one. Other
  routes keep `--dendrite-retries` unchanged. A miner answer below 500 is
  never resent on any route. The bridge answers with the same status, with
  the miner's `detail` as `error.message`, and `retryable: true` for a 429.
  On the sandbox-ops route only, a miner 429 whose `detail` is exactly
  `sandbox_ops_rate_exceeded` or `sandbox_ops_capacity_exhausted` keeps that
  value as `error.code`, and keeps the miner's `Retry-After` when it is
  exactly a decimal number of seconds from 1 to 60. Any other value (a sign,
  fraction, leading zero, HTTP date, non-ASCII digit, an oversized value, a
  list, or more than one header) is dropped, not repaired. Every other answer, on
  every route, keeps the generic code for its status, and no other miner
  header is relayed.
- **Validator runtime (private):** a refusal below 500 is definitive only
  while no earlier send of the same op may have been delivered. Once one may
  have been, the outcome stays unknown (X01-RB-03). The validator bridge no
  longer hides an earlier attempt inside one bridge call. The private carrier
  sends each attempt once (`postOnce`), and the runtime's resend of the same
  signed op is the only resend. This is recorded as the composed status by the
  composition review of the frozen candidate; it is source-level, not
  executed here. See "Dependencies".

## Stopping an exec: what is and is not guaranteed

With these rules, neither a full ordinary ops window nor a full ops capacity
refuses a well-formed `exec_cancel` from a validator. That is the whole
guarantee at this hop. In particular:

- **Other tenants' cancels share the reserve.** The cancel window and the
  cancel headroom are per validator hotkey, not per tenant. One tenant's
  cancels, up to 64 per 10 s, can exhaust the reserve for everyone else, and
  four slow cancels, each held for the whole kill path, fill the headroom.
  Per-owner limits belong to the gateway and runtime (DR-08, E6) and are not
  built.
- **Shared network connections still compete.** Ingress connections are
  shared by every peer (see "Ingress"). A connection-level 503 refuses a
  cancel like any other request, and the runtime treats it as possibly
  delivered.
- **Later hops decide the tenant answer.** The private runtime and gateway
  classify a refusal as definitive or unknown. Until their dependencies below
  are fixed, a refused cancel may be reported as unknown, or as definitive
  after an earlier ambiguous attempt inside one carrier call (R23-NA-01).

## Ingress: what this hop can and cannot guarantee

Uvicorn's `limit_concurrency` (`MINER_INGRESS_CONCURRENCY`, 64) is applied
when a request's headers are complete, before the application runs. It
answers 503 to any request while the open connections, or the running
request tasks, number 64 or more. Idle keep-alive connections and connections
that have not finished their first request count too, and the keep-alive
timer only starts after a first response. Any network peer, authenticated or
not, can therefore occupy connections.

Admission in the application keeps ops from taking more than their share of
request tasks, and keeps lifecycle work from ever waiting behind ops. It
cannot reserve ingress connections against arbitrary slow peers. Reserving
them needs one of the following, neither of which is built:

- a separate validator-only listener for lease lifecycle and handshakes;
- a front proxy with per-class connection limits and header and idle
  timeouts.

## Values

These are candidate production-intended code defaults pending lab
measurement. None is adopted or measured:

- **300 per 10 s.** A sync exec polls two `exec_read` ops per pass and then
  pauses 500 ms, so it issues at most 4 ops/s, about 2.5 at a 150 ms round
  trip. 30 ops/s on average sustains several polled execs. The shared
  120 per 60 s budget (2/s) fails a single polled exec after about 50 s. The
  10 s window bounds how long one burst can hold the budget.
- **64 cancels per 10 s.** The runtime sends one `exec_cancel` per exec it
  stops and resends the same one only after an ambiguous answer. 64 lets one
  window cancel every exec of a full agent in-flight bound (the profile's
  candidate `max_in_flight` of 64) once. Resends spill into the next window,
  and `Retry-After` is at most 10 s. The reserve adds at most 6.4 ops/s,
  about a fifth of the ordinary budget, to the agent's load.
- **32 concurrent ops.** This is half the ingress bound. Each forwarded op
  holds at most one 1 MiB request and one 1 MiB answer in this process.
- **4 cancel admissions.** Cancels are rare, but each holds its admission for
  the whole kill path.
- **Reserve of 16.** This leaves room for lease lifecycle waiting for its
  gate, handshakes, status, deactivation and the runtime proxy.

The lab must measure the following:

- neuron CPU and memory per op;
- renewal latency at p99.9 with one miner saturated by ops;
- false refusals under honest polling;
- zero cancel refusals when an honest tenant cancels 64 running execs at once
  while ordinary ops hold their window full;
- the agent's kill-path cost per cancel under a sustained 6.4 cancels/s;
- how far one tenant's cancel flood delays another tenant's cancel. This
  last figure is the open per-owner fairness gap.

## Dependencies outside this hop

The statements below describe the composed candidate as recorded by the
composition review of the frozen candidate. They are source-level
observations. No build, test, runtime or lab run of the composed system is
claimed.

- **Validator runtime, sweep (private), DR-02:** recorded as repaired in the
  composed private candidate. Not executed here.
- **Validator runtime, pre-dispatch refusals (private), DR-04:** the runtime's
  accept-close and agent capacity-busy classification were not closed by the
  composition review. Treat them as open.
- **Validator runtime, carrier (private), R23-NA-01:** recorded as repaired:
  each attempt is sent once (`postOnce`). A refusal below 500 after an
  ambiguous attempt must stay unknown. Not executed here.
- **Validator runtime, refusal mapping (private), R23-COMP-03:** repaired in
  the combined private candidate. A first-attempt bridge 404 becomes the
  runtime's 503 `unavailable`, not a missing local lease. The gateway answers
  503 `upstream_unavailable` with `Retry-After: 2`. A genuinely missing local
  lease still yields 404; a refusal after possible delivery stays unknown.
  This relies on the reviewed single-attempt ops chain, where a bridge 404
  precedes agent dispatch. Real socket framing remains unqualified.
- **Gateway (private), H-P2:** a definitive neuron 429 is answered to tenants
  as 429 with a fixed `Retry-After` of 2 seconds. The neuron's validated hint
  is not relayed to tenants. The combined private gateway documentation now
  lists these op refusals and the fixed hint (H-CA-1). That documented mapping
  is not a claim of installed cross-repository runtime qualification.
- **Agent and gateway (both repositories):** per-lease shares at the agent and
  per-owner limits at the gateway and runtime, including for cancels
  (R23-C-02, R23-C-03, R23-C-04, DR-08), remain open. Ingress connection sharing
  (see "Ingress") remains open.

No rate, capacity or window in this document was changed by this revision.
All values remain candidate, unmeasured and unadopted.
