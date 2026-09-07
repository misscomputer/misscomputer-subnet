# Public API migrations

## Contract checkpoint v1

This release adds three versioned contracts and their pure verification code;
see [`contract-checkpoint-v1.md`](contract-checkpoint-v1.md). It contains one
declared contract compatibility event, makes the block-lease check mandatory
for every live manifest consumer (a breaking signature change for
`verify_active_assignment_manifest`, `anchor_manifest_chain_state`, the
`verify_manifest` boundary operation, and the `misscomputer-assignment-probe`
CLI), and otherwise leaves every existing contract, schema, fixture, and Go
API unchanged.

### `assignment-manifest-chain-state` v1 gains `last_finalized_epoch` (breaking)

The append-only chain state now carries the finalized epoch of the last
accepted manifest beside its height and block hash, so that a publication
whose finalized epoch goes backwards, or that pairs one finalized height with
two epochs, is rejected (`finalized_epoch_rollback`, `same_height_fork`). The
field is `null` exactly at genesis. Canonical chain-state bytes and their
digests change; a chain-state document persisted before this release does not
parse and must be re-anchored (re-created from genesis and caught up, or
anchored on the live head; see the checkpoint document). No validator is live
on the previous form. The `assignment-manifest-chain-state` schema and fixture,
and the `validator-probe-report` fixture that embeds a chain-state digest, are
re-pinned at their new bytes; the probe-report *schema* is unchanged.

### Manifest verification

- Manifest validity is bounded by the effective horizon
  `min(expires_at_epoch, min(ticket_expires_at_epoch))`; a manifest whose
  tickets have all expired is `manifest_expired` even if `expires_at_epoch`
  lies ahead.
- `verify_active_assignment_manifest` requires the keyword argument
  `current_finalized_height` (**breaking**): every replica's `expires_at_block`
  is enforced against it (`manifest_replica_lease_expired`), and an invalid
  value is `current_finalized_height_invalid`. A caller that cannot state its
  finalized height cannot verify live; there is no opt-out. Historical
  verification (`verify_historical_active_assignment_manifest`,
  `replay_manifest_history`) is unchanged and lease-free, because superseded
  manifests are never probed. `anchor_manifest_chain_state` requires the same
  argument.
- `misscomputer-assignment-probe` requires `--finalized-height`
  (**breaking**); `AssignmentProbeCLIConfig` gains the required field
  `current_finalized_height`, validated like `evaluation_epoch`
  (`operator_context_invalid`).
- New pure helpers: `manifest_effective_expires_at_epoch`,
  `manifest_earliest_lease_expires_at_block`, `verify_manifest_block_leases`,
  `verify_pointer_signer_set`, and
  `verify_historical_active_assignment_manifest` (catch-up semantics).

### Publication and latest pointer

- `assignment-manifest-latest-pointer` v1 carries `finalized_epoch`.
- `bind_latest_pointer_to_manifest(pointer, manifest, signatures)` now takes
  the fetched envelopes and requires them to be exactly the pointer's signer
  set (`pointer_signature_mismatch`).
- `verify_manifest_latest_pointer` checks the claimed signer set against key
  validity windows, revocations, threshold, and required roles
  (`pointer_signer_invalid`, `pointer_required_role_missing`) and mirrors the
  chain-view rules. Its verdict gains `history_depth`, which is zero for a
  direct digest link and otherwise is the maximum number of immutable history
  entries to walk, not a count inferred from possibly jumping sequence values.
- New: `pointer_object_key`, `ManifestHistoryEntry`,
  `replay_manifest_history` (catch-up), and `anchor_manifest_chain_state`
  (onboarding).

### Validator decision and weight plan

- `validator-weight-decision` v1 gains `terminal_finalized_block_hash`,
  `terminal_finalized_epoch`, `terminal_manifest_effective_expires_at_epoch`,
  `terminal_earliest_lease_expires_at_block`, `prior_assigned_baseline`,
  `prior_assigned_baseline_status`, `assigned_baseline`, the row field
  `assigned_at_close`, the row aggregation `replica_share_counts`, the policy
  field `assigned_baseline_max_age_seconds`, and the abstain reason
  `assignment_lease_expired_at_close`. Parsing re-derives every abstain reason
  and row classification from the sealed fields.
- The decision now embeds a canonical `scoring_window` and ordered
  `assignment_manifest_evidence` entries containing each unique full manifest
  and the exact sorted full reports that probed it. Parsing reconstructs the
  probe rounds and recomputes the scoring-window digest, report partition,
  observation count, serving attributions and latency, per-identity
  opportunities and replica-share buckets, terminal registered identity set,
  maximum assigned count, mass-drop guard, and successor baseline. Baselines
  now carry their canonical assigned-identity list; count and identity digest
  are derived from it.
- Parsing also enforces sealed serving evidence: a positive row needs at least
  `scoring_policy.min_attributions` attributions, no more attributions than
  opportunities, no more opportunities than the record's `observation_count`,
  no more rounds than observations, row attributions summing to at most
  `serving_observation_count`, and an exact reduced expected-attribution
  fraction recomputed from the row's canonical `replica_share_counts` buckets.
  Positive weights form one normalized distribution
  (`row_positive_weight_without_evidence`, `row_weight_below_min_attributions`,
  `row_attributions_exceed_opportunities`,
  `row_expected_attributions_inconsistent`, `observation_counts_invalid`,
  `weights_not_normalized`).
- Assigned sets are counted in registered identities only:
  `terminal_assigned_miner_count` must equal the rows sealed
  `assigned_at_close` (`assigned_counts_invalid`), and the successor
  `assigned_baseline` identity digest is always checked. A record whose
  `mass_unassignment_guard` fired must carry the largest set (the applied prior
  baseline, or a manifest of the window at a sequence below the terminal)
  rather than the reduced terminal set (`assigned_baseline_not_derived`).
  On an unavailable or rejected terminal fetch, the largest verified
  in-window set is carried unless an applied prior is strictly larger; this
  also applies to first windows and expired priors.
- `decide_weight_submission` accepts `prior_assigned_baseline` and
  `archived_manifests`. The window's manifests, the archived manifests, and
  the terminal must include every actual digest-linked transition; bounded
  sequence jumps do not imply intermediate publications. A missing actual
  predecessor is `decision_manifest_chain_gap`,
  an archived manifest that does not re-validate or lies beyond the terminal
  is `decision_archived_manifest_invalid`.
- `weight_plan.build_weight_plan_from_decision` is the only path from a
  decision to a plan; `build_weight_plan` itself is unchanged. The decision's
  rows must be exactly `weight_plan.eligible_weight_targets(snapshot,
  validator_hotkey)` (every active neuron other than the validator), so a
  decision that omits an eligible miner is refused. The builder deep-validates
  once into a private decision and immutable row snapshot, so concurrent
  mutation of a caller-owned nested row list cannot split these checks.
- `probe_scoring.accumulate_scoring_window` re-validates every round
  (`scoring_round_invalid`).
- `assignment_snapshot.verify_snapshot_succession` adds
  `snapshot_finalized_epoch_rollback` and treats a second epoch at one height
  as `snapshot_finalized_fork`.

### `misscomputer-checkpoint-boundary`

Protocol `misscomputer.checkpoint-boundary.v1` gains the operations
`build_snapshot_replica`, `build_snapshot_deployment`,
`build_assignment_snapshot`, `project_snapshot_deployments`,
`verify_snapshot_succession`, `verify_manifest_derived_from_snapshot`,
`build_manifest_latest_pointer`, `verify_manifest_latest_pointer`,
`bind_latest_pointer_to_manifest` (arguments `pointer`, `manifest`,
`signatures`), and `rebind_manifest_state_trust_policy`, and the `validate`
operation accepts the models `active_assignment_snapshot` and
`assignment_manifest_latest_pointer`. The `verify_manifest_latest_pointer`
response carries `history_depth`. The `verify_manifest` operation requires the
argument `current_finalized_height` (**breaking**; a request without it is
rejected with `current_finalized_height_required`, and the manifest's block
leases are enforced against it). Every other pre-existing operation, argument,
and response shape is unchanged; chain-state documents a producer exchanges
follow the compatibility event above.

### Go `pkg/assignment`

New package; no existing Go package changed. `Seal`, `Parse`, `Marshal`,
`Project`, `Validate`, and `CanonicalJSON` are the only exported functions.

### `contracts/negative/`

New directory convention for golden invalid documents. It is not read by
`schema_inventory` and does not affect the public contract inventory digest
of `contracts/fixtures` and `contracts/schemas`.

No migration exports the hidden challenge, changes validator scoring, submits
weights, or introduces multi-validator coordination.

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
