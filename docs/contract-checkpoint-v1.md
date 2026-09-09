# Contract checkpoint v1: snapshot, publication, and validator decision

## Purpose

This checkpoint freezes the interfaces that the remaining launch work depends
on so that the runtime snapshot endpoint, the manifest publisher, the
validator coordinator loop, and operator wiring can be built in parallel
without renegotiating a boundary. It contains contracts, pure verification
code, golden and negative fixtures, and cross-language parity tests. It
deliberately implements no runtime endpoint, no publisher daemon, no
coordinator loop, no service wiring, and no weight submission.

Four contracts are added. Every pre-existing contract is byte-pinned by the
test suite. Three compatibility events are declared, all against contracts no
consumer is live on: `assignment-manifest-chain-state` gains
`last_finalized_epoch`, `validator-weight-decision` gains `trust_policies`,
and `validator-probe-report` observations gain `trust_policy_digest_sha256`
(see "Compatibility matrix"; the supported mixed-version pairings and the
coordinated pause that upgrades each writer/reader pair are in
[`api-migrations.md`](api-migrations.md): neither the decision nor the
snapshot form is transparently mixed-version compatible).

| Contract | Version | Producer | Consumer | Module |
| --- | --- | --- | --- | --- |
| `active-assignment-snapshot` | 1 | scheduler runtime (Go, `pkg/assignment`) | manifest publisher | `assignment_snapshot.py` |
| `active-assignment-snapshot-lineage` | 1 | manifest publisher (durable, local) | manifest publisher | `assignment_snapshot.py` |
| `assignment-manifest-latest-pointer` | 1 | manifest publisher | validator fetcher | `manifest_publication.py` |
| `validator-weight-decision` | 1 | validator coordinator | validator weight plan | `validator_decision.py` |

The existing `active-assignment-manifest`, `assignment-manifest-trust-policy`,
`assignment-manifest-signature-envelope`, `assignment-manifest-chain-state`,
`miner-probe-attestation`, `validator-probe-report`, and `weight-plan`
contracts are the frozen baseline this checkpoint builds around; see
[`public-validator-live-probe.md`](public-validator-live-probe.md) and
[`probe-scoring-and-weights.md`](probe-scoring-and-weights.md).

## Canonical form shared by every contract

- JSON object with sorted keys, `,`/`:` separators, ASCII-only escaping, no
  `NaN`/`Infinity`, no duplicate keys, integers within `[0, 2^63-1]`;
- every self-authenticating document ends in a `*_digest_sha256` field equal
  to the SHA-256 of the canonical rendering of the document without that
  field; every nested digest (`assignment_digest_sha256`,
  `assignment_vector_digest_sha256`,
  `projected_assignment_vector_digest_sha256`) is computed the same way;
- the on-disk and on-wire form is the canonical rendering plus exactly one
  trailing newline; parsers accept only that exact byte string, reject unknown
  keys (`additionalProperties: false`), and re-verify every digest;
- Go producers marshal through `pkg/assignment.CanonicalJSON`, which sorts
  keys and refuses non-ASCII output, and the Go test suite proves the Python
  golden fixture round-trips byte-for-byte.

## 1. Transactional active-assignment snapshot

`active-assignment-snapshot` v1 is the runtime's credential-safe answer to
"what is route-active right now", read at one durable state revision under
one lock. The publisher derives every manifest from it; nothing else is a
valid manifest source.

### Fields

| Field | Meaning |
| --- | --- |
| `snapshot_sequence` | increases by exactly one per capture from one runtime (tightened from "strictly increasing"); a publisher's lineage treats a jump as a missed capture to replay, and a legacy history with skips is preflighted with `snapshot_history_gaps` and restarted after the last skip |
| `state_revision` | scheduler durable revision the capture was read at; two captures at one revision carry byte-identical `deployments` |
| `captured_at_epoch` | capture instant; becomes the manifest's `issued_at_epoch` |
| `finalized_height`, `finalized_block_hash`, `finalized_epoch` | finalized chain view the scheduler held at capture; copied into the manifest |
| `central_authority_fingerprint_sha256`, `network`, `netuid` | authority binding, mainnet-only (`finney`/24) |
| `route_host_suffix`, `probe_scheme`, `probe_port` | public route identity base |
| `deployments[]` | sorted by `deployment_id`; may be empty |
| `deployments[].deployment_id`, `campaign_sequence`, `route_host`, `build_id`, `challenge_path`, `image_digest`, `workload_spec_digest_sha256`, `expected_status`, `attestation_requirement` | deployment and route identity; `route_host == <deployment_id>.<route_host_suffix>`, `challenge_path == /__challenge/<build_id>` |
| `deployments[].challenge_sha256` | **digest only** of the hidden challenge body |
| `replicas[].miner_uid`, `miner_hotkey`, `miner_service_public_key` | miner identity; one UID per hotkey across the whole snapshot |
| `replicas[].generation`, `assignment_nonce`, `replica_id`, `endpoint_id` | exact endpoint incarnation, `endpoint_id == <deployment_id>-<hotkey>-g<generation>-<nonce>`, unique across the snapshot |
| `replicas[].ticket_digest_sha256`, `receipt_digest_sha256` | **digests only** of the retained signed ticket and ready receipt |
| `replicas[].chain_block`, `expires_at_block` | assignment block window; must contain `finalized_height` |
| `replicas[].ticket_issued_at_epoch`, `ticket_expires_at_epoch` | signed ticket window on the **signer's clock**; unexpired at capture; issued no more than `TICKET_MAX_FUTURE_SKEW_SECONDS` (30s) after the capture instant and no more than 30s after the replica's `route_activated_at_epoch` |
| `replicas[].route_activated_at_epoch` | runtime activation instant of this exact incarnation on the **runtime's clock**; `<= captured_at_epoch` exactly (same clock); `>= ticket_issued_at_epoch - 30` (cross-clock) |
| `replicas[].route_state` | constant `active`; pending, quarantined, and deactivated incarnations are never exported |
| `projected_assignment_vector_digest_sha256` | digest of `project_manifest_deployments(snapshot)` |
| `snapshot_digest_sha256` | self digest |

The snapshot never carries the raw challenge value, ticket or receipt bytes,
axon addresses, TLS pins, artifact or image keys, provider or tunnel
identifiers, scheduler queue state, signer seeds, wallets, or weights; the
golden fixture is scanned for each of those.

### Clock domains

A capture mixes two clocks. `ticket_issued_at_epoch` and
`ticket_expires_at_epoch` are stamped by the ticket signer;
`route_activated_at_epoch` and `captured_at_epoch` are stamped by the runtime
that activated the route and read the capture. Same-clock comparisons are
exact: a route is activated at or before the capture that exports it
(`snapshot_replica_activated_after_capture`). Cross-clock comparisons tolerate
the signer's clock leading the runtime's by at most
`TICKET_MAX_FUTURE_SKEW_SECONDS` = 30, applied identically to both runtime
instants: a ticket may be stamped as issued up to 30s after the activation it
authorised (`replica_activation_order_invalid` beyond that) and up to 30s
after the capture instant (`snapshot_replica_ticket_issued_after_capture`
beyond that). A ticket issued at `captured_at_epoch + 30` for a route activated
at the capture instant is therefore a valid capture, at `+ 31` it is not, and
an activation more than 30s before its ticket's issuance is an ordering
violation whatever the capture instant. Go (`pkg/assignment`) enforces the
same rule with the same codes; the supplementary golden
`active-assignment-snapshot-signer-skew.v1.json` (alpha's tickets at `+30`,
beta's at `+1`, every route activated at capture) is parsed and re-sealed
byte-for-byte by both suites; its replicas are fresh generation-2
incarnations with fresh nonces, endpoints, ticket and receipt digests, so it
is a valid successor of the golden capture rather than a rewrite of it. The
negative fixtures `replica-ticket-issued-beyond-capture-skew` and
`replica-activated-before-ticket-skew` pin the two rejection branches.

### Consistency semantics

`verify_snapshot_succession(previous, current)` is the transactional rule a
publisher applies between captures: `snapshot_sequence` strictly increases;
`state_revision`, `captured_at_epoch`, `finalized_height`, and
`finalized_epoch` never decrease; an unchanged `state_revision` must carry
identical `deployments`; one finalized height has one block hash and one
epoch; authority and network never change. Codes:
`snapshot_sequence_not_increasing`, `snapshot_revision_rollback`,
`snapshot_revision_content_divergence`, `snapshot_capture_rollback`,
`snapshot_finalized_rollback`, `snapshot_finalized_epoch_rollback`,
`snapshot_finalized_fork`, `snapshot_authority_mismatch`,
`snapshot_network_mismatch`.

### Incarnation lineage

`replica_id` (`<deployment_id>-<hotkey>`) is the stable lineage of one miner's
assignment to one deployment; `endpoint_id` names one incarnation of it
(generation and nonce), and the ticket and receipt digests are the signed
facts issued for that incarnation. A publisher keeps an
`active-assignment-snapshot-lineage` v1 document: the transactional position
of the last accepted capture plus, for every `replica_id` it has ever
exported, the latest accepted incarnation (`generation`, `assignment_nonce`,
`endpoint_id`, ticket and receipt digests, the digest of the complete replica
document, and the digest of the enclosing deployment's ticket-bound facts:
everything but its replicas). `advance_snapshot_lineage(lineage, snapshot)`
accepts a capture or refuses it:

- the transactional rules above, held against the last accepted capture;
- a retained `endpoint_id` must carry the identical replica document and
  identical deployment facts (`snapshot_incarnation_rewritten`): a signed
  ticket binds its own issuance and its assignment, so a retained ticket digest
  with a restamped `ticket_issued_at_epoch`, a moved activation instant, or a
  changed image digest, challenge digest, workload spec, or campaign is an
  impossible rewrite, not a re-assignment;
- a replacement (a new `endpoint_id` for a known `replica_id`) must advance
  the generation (`snapshot_generation_not_increasing`);
- every new incarnation, first appearance or replacement, must carry a nonce,
  ticket digest, and receipt digest that no incarnation of any replica ever
  carried (`snapshot_incarnation_facts_reused`): the lineage keeps every fact
  it has accepted (`used_assignment_nonces`, `used_ticket_digests`,
  `used_receipt_digests`), so A → B → A cannot recycle A's first-generation
  facts at generation three, however many captures or replacements lie
  between;
- incarnations that a capture drops stay in the lineage, so an old endpoint
  re-exported rewritten after an empty or unrelated capture is still refused;
  the identical incarnation re-exported is accepted.

`verify_snapshot_succession(previous, current)` is exactly the lineage
advanced from genesis over the two captures (so `current` must be the very
next sequence), for a caller that holds only them; a publisher that persists
its lineage (`snapshot_lineage_bytes`, `parse_snapshot_lineage`,
`build_initial_snapshot_lineage`, `replay_snapshot_lineage`) gets the same
rules across its whole history, which the two-capture form cannot: a rewrite
after an intervening capture, or a fact retired two replacements ago.

The lineage's history is anchored, contiguous, and era-scoped. Each advanced
lineage names its predecessor's digest (`previous_lineage_digest_sha256`), so
persisted lineages form a hash chain; the operator retains the head digest out
of band and `verify_snapshot_lineage_anchor` refuses a restored lineage that is
not that head (`snapshot_lineage_anchor_mismatch`), because a stale backup or
a resealed copy with retired facts removed is digest-valid but false. Captures
are accepted only in exact sequence order from
`history_start_snapshot_sequence` (`snapshot_lineage_gap`; the parser requires
`last == start + count - 1`, `lineage_history_not_contiguous`): a missed
capture is replayed, never skipped, and a legacy history with skipped values
is preflighted with `snapshot_history_gaps` and started after the last skip.
Freshness is judged across every fact role: a new incarnation's nonce, ticket
digest, and receipt digest must be absent from the union of everything the
era has accepted (`lineage_used_facts_overlap` on parse if ticket and receipt
histories overlap). `snapshot_lineage_overflow` (more than
`MAX_LINEAGE_REPLICAS` replica lineages, `MAX_LINEAGE_FACTS` retained facts of
one kind, or an era beyond `MAX_LINEAGE_ERAS`) refuses the capture and forgets
nothing; the only operation that sheds anything is `begin_snapshot_lineage_era`,
which opens `era + 1`, keeps exactly the incarnations of the last accepted
capture (every `ReplicaLineage` records `last_seen_snapshot_sequence`) with
their facts, prunes inactive lineage, and records a `LineageEraBoundary` (era,
last accepted sequence, dropped lineages and facts, predecessor digest) in
the document permanently, in range and in order. The never-reuse guarantee is
therefore exactly "no fact accepted since `history_start_snapshot_sequence`
within the current `era` is ever accepted again in any role", readable from
the document. The lineage is a Python
publisher-side rule with no Go counterpart: `pkg/assignment` produces captures
and has no succession API.

An empty snapshot is a valid state meaning "nothing is route-active". A
manifest cannot be derived from it (manifest v1 requires at least one
deployment); the publisher leaves the last manifest to expire and validators
abstain (rule 1 below).

### Manifest derivation

`project_manifest_deployments` is the only projection to manifest v1
deployments: field-for-field copy, dropping only `route_activated_at_epoch`.
`verify_manifest_derived_from_snapshot(manifest, snapshot)` binds a manifest
to its capture: same authority and network, same finalized triple,
`issued_at_epoch == captured_at_epoch`, same route suffix/scheme/port, and
`assignment_vector_digest_sha256 == projected_assignment_vector_digest_sha256`.
The publisher must refuse to sign otherwise. Manifest `sequence`,
`previous_manifest_digest_sha256`, and `expires_at_epoch` remain derived from
the publisher's chain state and trust policy exactly as today.

## 2. Signed public manifest: publication contract

`active-assignment-manifest` v1, its envelope, and the trust policy are
unchanged; the chain state gains `last_finalized_epoch`. This section freezes
what surrounds them.

| Property | Frozen behaviour |
| --- | --- |
| Canonical serialization | as above; the signed message is `miss.computer/misscomputer-subnet/active-assignment-manifest/v1/ed25519` + `NUL` + canonical manifest JSON |
| Signer and key IDs | `signer_key_id` slug (`^[a-z0-9](?:[a-z0-9_-]{0,62}[a-z0-9])?$`) resolved against `trusted_keys[].key_id`; raw Ed25519 public key (base64) plus `public_key_sha256`; small-order keys rejected |
| Threshold and trust policy | `threshold` distinct verified keys and every `required_roles` entry covered; roles are `assignment_issuer`, `assignment_auditor`, `assignment_security`; per-key validity window and `revoked_at_epoch`; purpose fixed to `active_assignment_manifest_publication_v1` |
| Sequence and linkage | `sequence` starts at 1, `previous_manifest_digest_sha256` is `null` exactly at 1 and otherwise equals the previous accepted manifest digest; each actual digest-linked transition has a positive sequence delta no greater than `max_sequence_gap` (integer values between the endpoints do not imply publications) |
| Finalized-chain binding | `finalized_height`/`finalized_block_hash`/`finalized_epoch` copied from the snapshot; height and epoch never decrease, each actual transition's height delta is no greater than `max_finalized_height_gap`, and the same height implies the same hash and epoch; the chain state carries all three (`last_finalized_height`, `last_finalized_block_hash`, `last_finalized_epoch`) |
| Issued/expiry | `issued_at_epoch == captured_at_epoch`; `expires_at_epoch - issued_at_epoch <= max_manifest_lifetime_seconds`; not future beyond `max_future_skew_seconds` (the manifest's `issued_at_epoch` may lead the validator's `evaluation_epoch` by at most that many seconds; ceiling 300); not older than `max_manifest_age_seconds` at evaluation. `ManifestVerificationResult` records the `evaluation_epoch` and `trust_policy_digest_sha256` these were applied at and under; `build_validator_probe_report` seals only that epoch and policy (`report_evaluation_epoch_mismatch`, `trust_policy_mismatch`) |
| Effective horizon | a manifest is valid only until `min(expires_at_epoch, min(replicas[].ticket_expires_at_epoch))` (`manifest_effective_expires_at_epoch`); every live verifier enforces every `replicas[].expires_at_block` against its own finalized height, which is required input (`current_finalized_height` of `verify_active_assignment_manifest`, `anchor_manifest_chain_state`, and the `verify_manifest` boundary operation; `--finalized-height` of the probe CLI) with no lease-free live path (`manifest_replica_lease_expired`); expired assignment authority is never scoreable, whatever `expires_at_epoch` claims. A publisher should set `expires_at_epoch` no later than the earliest ticket expiry; the verifier does not rely on it doing so |
| Immutable objects | `v1/manifests/<manifest_digest>.json`, `v1/manifests/<manifest_digest>.<signer_key_id>.signature.json`, and `v1/manifests/<manifest_digest>.pointer.json` (the pointer as published for that manifest); content-addressed, never modified or deleted while any validator could still need them to catch up |
| Atomic latest pointer | `v1/latest.json` is an `assignment-manifest-latest-pointer` v1 written only after every object it names, including the immutable pointer copy, is readable; replaced atomically; never rewritten to a lower sequence |
| Replay / rollback / fork | an identical re-fetch is a **re-probe** (state unchanged); a different manifest at an accepted sequence is `same_sequence_divergence`; lower sequences, broken links, height or epoch rollback, and same-height forks are rejected with stable codes; the pointer pre-check mirrors these on the pointer's copied chain fields as `pointer_equivocation`, `pointer_rollback`, `pointer_sequence_gap` |
| Signer provenance | the pointer's `signer_key_ids` are checked before any fetch exactly as the envelopes will be, minus the cryptography: pinned, purpose-bound, valid at `issued_at_epoch`, unexpired and unrevoked at evaluation, threshold met, every required role covered (`pointer_signer_untrusted`, `pointer_signer_invalid`, `pointer_threshold_not_met`, `pointer_required_role_missing`); after the fetch the envelopes must be exactly that set, in order, over that digest (`pointer_signature_mismatch`) |
| Cache behaviour | immutable objects `Cache-Control: public, max-age=31536000, immutable`; pointer `public, max-age=60, must-revalidate`; fetchers send `Cache-Control: no-cache` for the pointer; a cache can only withhold, never widen acceptance |
| Onboarding / catch-up | see below |
| Key rotation | see below |
| Compatibility | manifest v1 bytes and schema unchanged; chain state v1 gains one field (declared below); new pointer object is additive |

### Latest pointer

`assignment-manifest-latest-pointer` v1 copies `sequence`,
`previous_manifest_digest_sha256`, `manifest_digest_sha256`, finalized
height, hash, and epoch, `issued_at_epoch`, `expires_at_epoch`, authority,
trust-policy digest, and network from the manifest, adds
`manifest_object_key` (which must equal the content-addressed key of the
digest) and the sorted `signer_key_ids` published beside it, and seals itself
with `pointer_digest_sha256`. It is not independently signed: every field is
re-checked against the signed manifest and the fetched envelopes by
`bind_latest_pointer_to_manifest`, and `verify_manifest_latest_pointer`
refuses, before any object fetch, a pointer whose authority, policy, network,
signer set (identity, key validity, revocation, threshold, roles),
freshness, or chain position could not lead to an acceptable manifest.

Fetch procedure (frozen): fetch `v1/latest.json` with `no-cache`; parse
canonical bytes; `verify_manifest_latest_pointer` (the verdict's
`history_depth` is zero for a direct digest link and otherwise gives the
maximum number of historical entries the fetcher may walk; sequence jumps
make the exact count unknowable from the head alone); if `history_depth > 0`,
run the catch-up procedure below first;
fetch the named manifest object and exactly the named signature objects;
parse each as canonical bytes; `bind_latest_pointer_to_manifest(pointer,
manifest, signatures)`; `verify_active_assignment_manifest` with the
validator's current finalized height (a required argument: block leases are
always enforced live); persist the next chain state before
using the manifest. Any failure is "manifest unavailable or invalid" for the
decision rules below.

### Onboarding and catch-up

A chain state advances only through accepted digest-linked publications, whose
sequence values may make bounded positive jumps, so a validator needs a
defined, authenticated way to start and to recover from missed publications:

- **Onboarding (genesis).** Ordinary verification from a genesis state accepts
  only sequence 1. A validator joining later calls
  `anchor_manifest_chain_state(head, signatures, policy, genesis,
  evaluation_epoch, current_finalized_height)`, which performs the complete
  live verification of the head (canonical form, policy binding, threshold,
  roles, real Ed25519 verification, freshness, effective horizon, block
  leases) and yields a chain state with one accepted manifest at the head's
  sequence. It is refused from any non-genesis state
  (`anchor_state_not_genesis`), so it can never skip history a validator
  already holds; the validator's non-equivocation history begins at the
  anchor. An operator may equivalently distribute an anchored chain state
  beside the trust policy; both travel over the same out-of-band trust
  channel that already roots everything else.
- **Catch-up.** A validator whose pointer verdict has `history_depth > 0`
  walks `previous_manifest_digest_sha256` back from the head, fetching for
  each actual publication the immutable manifest object, its `.pointer.json`
  copy, and exactly the signature objects the copy names, until it reaches its own
  `last_manifest_digest_sha256` or exhausts the verdict's entry budget.
  `replay_manifest_history(state, entries,
  policy, evaluation_epoch)` verifies the span in ascending order: each entry
  is bound pointer-to-objects, its signer set checked against the policy as
  of its `issued_at_epoch`, then accepted by
  `verify_historical_active_assignment_manifest`, which differs from live
  acceptance in exactly two ways (no freshness/expiry requirement; signer
  validity and revocation judged at the manifest's own issuance) and
  additionally requires the manifest to be the next digest-linked transition,
  with a positive sequence delta no greater than `max_sequence_gap`
  (`history_sequence_gap`, `history_link_mismatch`). The head is then
  verified live from the replayed state, which authenticates the whole span
  through its `previous` links. Historical manifests are never probed. The
  number of actual history entries is bounded by the policy's `max_sequence_gap`
  (`history_depth_exceeded`, `pointer_sequence_gap`); a validator further
  behind is re-anchored by its operator, never silently resynchronised.

### Key rotation

A validator pins one trust policy; manifests and chain state name its digest.
Rotation is a re-anchoring event, never a reset:

1. The operator publishes the successor policy digest out of band. The
   successor names the same authority, network, and netuid, includes the
   new keys (and any keys kept across the rotation) with their validity
   windows, and may set `revoked_at_epoch` on retiring keys.
2. Each validator installs the successor policy and calls
   `rebind_manifest_chain_state_trust_policy(state, current, next,
   evaluation_epoch)`, which preserves `last_sequence`, all digests, and the
   chain view while re-pinning the policy digest. A coordinator may hold the
   current and successor policies together and verify each manifest under the
   policy whose digest it names, re-anchoring on the first acceptance under
   the successor.
3. The producer switches to the successor digest at one publication boundary.
   Manifests before the boundary verify under the current policy, manifests
   after it under the successor; there is no manifest that verifies under
   both, and the sequence chain is continuous across the boundary.
4. Validators that have not rotated reject successor manifests with
   `trust_policy_mismatch` and therefore abstain; they never zero anyone
   because of a rotation they have not installed.

## 3. Validator decision semantics

`validator_decision.decide_weight_submission` applies the frozen rules to one
closed scoring window and seals a `validator-weight-decision` v1 record. The
record, not the raw weight vector, is the only input to
`weight_plan.build_weight_plan_from_decision`, which is the only path to
`build_weight_plan`.

| Situation | Outcome | Reason code |
| --- | --- | --- |
| Terminal manifest fetch at window close unavailable | ABSTAIN | `manifest_unavailable` |
| Terminal manifest rejected (signature, freshness, chain, policy, pointer) | ABSTAIN | `manifest_invalid` (rejection code recorded) |
| Terminal manifest's effective horizon (own expiry or earliest ticket expiry) reached at the close evaluation instant | ABSTAIN | `manifest_expired_at_close` |
| Any terminal-manifest replica's `expires_at_block` at or below the registered set's finalized height | ABSTAIN | `assignment_lease_expired_at_close` |
| Fewer verified rounds than `min_verified_rounds` | ABSTAIN | `rounds_insufficient` |
| Any miner assigned at close and outside activation grace with expected attributions below `min_expected_attributions`, whether or not it earned positive evidence | ABSTAIN | `coverage_insufficient` |
| Registered set not bound to the terminal manifest's chain view: behind it; ahead by more than `max_registered_height_gap`; at the same height with a different block hash or epoch; or ahead with a lower epoch | ABSTAIN | `registered_set_unbound` |
| Terminal assigned *registered*-miner count below `(1000 - max_assigned_drop_permille)/1000` of the largest registered assigned set seen in the window's or archived manifests or carried in an applied prior baseline (identities outside the registered set are never counted, so padding cannot hide a drop) | ABSTAIN | `mass_unassignment_guard` |
| No registered miner has positive verified evidence | ABSTAIN | `no_positive_evidence` |
| None of the above | SUBMIT | (none) |

Inputs that are not a judgement about miners but an inconsistency in what the
coordinator supplied are refused outright rather than recorded as
abstentions: a round whose report post-dates its manifest's effective horizon
(`decision_round_after_horizon`); a manifest or report that no longer
re-validates from its canonical form, for example because a nested list was
mutated after verification (`decision_round_invalid`,
`decision_terminal_status_invalid`); window, archived, and terminal manifests
that are not one unbroken chain (`decision_manifest_chain_gap`: a sequence
between the window's first and the terminal is missing, so a terminal from a
fork can never meet rounds from another chain by omitting the divergence;
`decision_manifest_chain_incoherent`: two different manifests at one
sequence, a broken `previous` link, finalized height or epoch going backwards,
a second hash or epoch at one height, issue time going backwards); an archived
manifest that does not re-validate or lies beyond the terminal
(`decision_archived_manifest_invalid`); more than one central authority, or a
network or netuid other than the registered set's
(`decision_manifest_authority_mismatch`; several trust policies from one
authority are legitimate across a rotation and each manifest is bound to its
own); a manifest naming a trust policy the coordinator did not supply, or a
supplied policy that does not re-validate, is duplicated, or names another
network or authority (`decision_trust_policy_missing`,
`decision_trust_policy_invalid`); a verified terminal manifest issued further
ahead of its evaluation instant than its policy's `max_future_skew_seconds`
(`decision_terminal_future`), or otherwise inadmissible under that policy at
that instant (`decision_terminal_policy_rejected`); a report whose manifest
its policy could not have admitted at the report's evaluation epoch, or whose
observations that policy could not have produced
(`decision_round_policy_rejected`); and a prior
baseline that post-dates the window start, names a sequence beyond the
terminal, or names a different manifest at a sequence the window also saw
(`decision_baseline_invalid`).

Per-miner classification in the record:

| Class | Meaning | Weight |
| --- | --- | --- |
| `verified_serving` | attested serving evidence in the window | positive |
| `assigned_unverified` | assigned at close, sufficiently sampled, no evidence | zero |
| `assigned_in_grace` | assigned at close, first sighted less than `activation_grace_seconds` before close, no evidence | zero, never a reason to abstain |
| `assigned_undersampled` | assigned at close, outside grace, under-sampled | zero in the record, forces ABSTAIN |
| `unassigned` | registered but absent from the terminal manifest | zero |

Every row also seals `assigned_at_close`, and the record seals the terminal
manifest's digest, sequence, expiry, effective horizon, earliest block lease,
and finalized height/hash/epoch, the registered view's height/hash/epoch and
fingerprint, the prior baseline and how it was applied, and the successor
baseline (below).

Frozen invariants:

- **Zero for absent miners is only submitted under the safe preconditions**:
  terminal manifest verified and within its effective horizon and leases at
  close, registered set bound, coverage sufficient, mass-unassignment guard
  satisfied, positive evidence present. Otherwise the validator abstains and
  the chain keeps its previous weights.
- **The sealed record is self-enforcing.** Parsing a
  `validator-weight-decision` re-derives every abstain reason and every row
  classification from the sealed fields. It also revalidates every unique
  full manifest in `assignment_manifest_evidence`, derives each registered
  assignment set and the maximum from those manifests plus the canonical
  prior-baseline identity list, and accepts the record only if the
  `decision` and `abstain_reasons` it states are exactly the ones its own
  fields imply (`abstain_reasons_not_derived`,
  `row_classification_not_derived`, `assigned_baseline_not_derived`,
  `baseline_status_not_derived`). A digest-valid record that says `submit`
  while describing an outage, an expired horizon, too few rounds, an
  under-sampled assigned miner, a mass drop, or an unbound registered view
  is rejected before it can reach a plan; the `contracts/negative/`
  `submit-with-*` fixtures are exactly such records.
- **Positive weight needs sealed serving evidence.** The record embeds its
  canonical `scoring_window`; its digest must equal
  `scoring_window_digest_sha256`, and every sorted full report must be
  partitioned exactly under the full manifest that it names. Parsing rebuilds
  those canonical probe rounds and recomputes the observation and serving
  totals, attributions, latency, every identity's opportunity total and exact
  replica-cardinality buckets, then rebuilds the registered weight vector.
  A `verified_serving`
  row must carry at least `scoring_policy.min_attributions` attributions,
  never more attributions than opportunities nor more opportunities than the
  record's `observation_count`; `round_count` never exceeds
  `observation_count`; row attributions sum to at most
  `serving_observation_count`; and the exact reduced expected-attribution
  fraction is recomputed as `sum(opportunity_count / replica_count)` from the
  row's sorted, unique `replica_share_counts` buckets. No evidence exists
  without rounds, and the
  positive weights are one normalized distribution
  (`row_positive_weight_without_evidence`,
  `row_weight_below_min_attributions`,
  `row_attributions_exceed_opportunities`,
  `row_expected_attributions_inconsistent`, `observation_counts_invalid`,
  `weights_not_normalized`). A digest-valid record cannot weight a miner it
  never observed serving, and cannot claim weight with zero serving
  observations.
- **No positive verified evidence, no transaction**: an abstain record has
  `weight_plan_rows_digest_sha256 = null`, and
  `weight_plan_rows_for_submission` refuses it; a submit record commits to the
  exact `[{miner_hotkey, weight}]` rows by digest.
- **The decision is bound to one metagraph view.**
  `build_weight_plan_from_decision(decision, snapshot,
  finalized_block_hash, version_key)` checks the snapshot's network, netuid,
  finalized flag, block (= `registered_finalized_height`), epoch
  (= `registered_finalized_epoch`), the supplied block hash
  (= `registered_finalized_block_hash`), the validator UID/hotkey, every row's
  UID/hotkey mapping, and the complete `snapshot_identity_fingerprint`
  (= `metagraph_identity_fingerprint_sha256`) before the unchanged
  `build_weight_plan` sees a row, and the decision's rows must be exactly
  `eligible_weight_targets(snapshot, validator_hotkey)`: every active neuron
  other than the validator, which is exactly the set `build_weight_plan`
  would accept a row for. A decision cannot be replayed against a different
  chain segment, a reorganised metagraph, or a remapped UID, and a decision
  that silently left an eligible miner out of the judgement while naming the
  complete fingerprint is refused rather than submitted.
- **Mass-unassignment baseline outlives the window.** Every decision seals an
  `assigned_baseline`: the largest verified assigned set of *registered*
  miners (canonical identity list, derived count and identity digest,
  sequence, manifest digest, and the window close that established it). When the
  terminal manifest clears the guard it becomes the baseline; when the guard
  fires, the reduced terminal set never does: the applied prior baseline, or
  else the window's largest manifest, is carried instead, and the record
  re-derives this on parse (`assigned_baseline_not_derived`). A coordinator
  that holds a baseline supplies it as `prior_assigned_baseline` to the next
  window, and the record seals both the supplied value and its status:
  `applied` (widens the guard's largest-set baseline), `expired` (established
  more than `assigned_baseline_max_age_seconds` before window close and
  ignored for this comparison), or `absent` (a coordinator's first window).
  If the terminal fetch is unavailable or rejected, the successor is the
  larger of the applied prior and the largest verified in-window manifest;
  fresh in-window evidence wins a tie and is established at the current
  close. Thus a first-window outage or expired prior cannot erase an observed
  guard horizon. Assigned sets are counted in registered identities only, so
  `terminal_assigned_miner_count` is exactly the rows sealed
  `assigned_at_close` (`assigned_counts_invalid`) and a manifest padded with
  identities outside the metagraph is still a drop. A central mass-eviction
  at a window boundary therefore still abstains, a guarded drop cannot become
  the next window's baseline, and a legitimate long-term shrink is accepted
  only once the old baseline has aged out by policy or the drop policy is
  relaxed.
- **One unbroken manifest chain.** The window's manifests, every archived
  manifest the coordinator accepted between them (`archived_manifests`,
  contributing sightings and assigned-set sizes but no evidence), and the
  terminal manifest include every actual publication with every `previous`
  link verified. Sequence values may jump within the bound enforced during
  acceptance, so an unused integer is not a missing manifest; omitting an
  actual predecessor is a gap (`decision_manifest_chain_gap`), never a way to
  splice rounds from one chain onto a terminal from another.
- **Evidence is re-validated before use.** Every round's manifest and report,
  and the terminal manifest, are rebuilt from their canonical documents
  (re-running every digest and count check) before scoring, both in
  `decide_weight_submission` and in `accumulate_scoring_window`; a frozen
  model whose nested list was mutated after verification is refused.
- **Activation grace** anchors on the miner's earliest sighting across the
  window's accepted manifests, the terminal manifest, and any earlier
  archived sighting the coordinator supplies (a supplied sighting may only be
  earlier). Sightings are scoped to the exact `(uid, hotkey)` identity, never
  to the last manifest that published an endpoint: an endpoint republished
  under a new UID adds a sighting for the new identity and cannot erase the
  one recorded for the identity that earned weight in earlier rounds. An
  archived sighting is supplied per exact identity
  (`identity_first_seen_epoch`, keyed by `(uid, hotkey)`), moves only that
  identity, must not post-date that identity's earliest in-chain publication
  (`decision_first_seen_after_sighting`), and is ignored for an identity the
  chain never publishes; an archived sighting of the old UID therefore never
  pulls a republished new UID out of grace. On parse, every non-`unassigned`
  row must carry a sighting no later than the minimum `issued_at_epoch` of
  the sealed evidence manifests
  that publish its identity (`row_first_seen_not_derived`); an earlier archived
  sighting remains valid. Grace creates no weight; a miner earns weight from
  the first window in which it is attributed. `activation_grace_seconds` may
  not exceed the window length.
- **Finalized window closure**: reports are admitted with
  `window_start <= evaluation_epoch < window_end`; the terminal observation
  is taken at or after `window_end`; the registered set is a finalized view
  carrying `metagraph_identity_fingerprint_sha256`, which the weight plan
  repeats.
- **Every time bound is the verifying policy's, sealed in the record.** Live
  verification admits a manifest whose `issued_at_epoch` leads the validator's
  `evaluation_epoch` by at most the trust policy's `max_future_skew_seconds`,
  so a verified report may legitimately precede its manifest's issuance by
  that much, and a policy rotation inside a window may change the bound
  between manifests. The decision therefore carries no clock-skew number of
  its own. `decide_weight_submission` takes the approved trust-policy
  documents (`trust_policies`) the coordinator verified under; every window,
  archived, and terminal manifest must name one of them by
  `trust_policy_digest_sha256` (`decision_trust_policy_missing`), the
  documents must re-validate, be unique, and name the registered set's
  network, netuid, and one central authority (`decision_trust_policy_invalid`),
  and the record seals exactly the policies its sealed manifests name, sorted
  by digest (`trust_policies_not_canonical`, `trust_policies_not_derived`,
  `trust_policy_authority_mismatch` on parse). A round is bound to its
  manifest only if `manifest.issued_at_epoch <= report.evaluation_epoch +
  policy.max_future_skew_seconds` for *that manifest's* policy
  (`decision_round_invalid`; `scoring_window_evidence_inconsistent` on parse),
  and a verified terminal manifest may lead `terminal_evaluated_at_epoch` by at
  most its own policy's bound (`decision_terminal_future`;
  `terminal_manifest_future` on parse). Beyond the skew, every report and the
  terminal are re-admitted under their manifest's policy exactly as live
  verification admits a manifest at an instant
  (`verify_manifest_policy_admission`): the policy valid at the evaluation
  epoch (`valid_from_epoch <= evaluation < valid_until_epoch`), the manifest
  inside the policy's interval, lifetime, route-suffix, scheme, network and
  authority constraints, and not stale (`max_manifest_age_seconds`); a
  report's `probe_timeout_millis` and `max_response_bytes` are the policy's
  own scalars; and every observation must be one `evaluate_probe_response`
  could have produced under that policy
  (`verify_observation_policy_binding`: the observation names that policy's
  digest, `trust_policy_digest_sha256`; every response-derived outcome, that
  is a serving outcome or any failure other than a transport failure, has
  `latency_millis <= probe_timeout_millis`, because the transport applies the
  policy's whole-request budget and a slower response is a `timeout`; a
  serving outcome, or any failure code reached only after the pin check,
  carries a pinned edge certificate when the policy pins any; a serving
  outcome or any failure reached only after the size check has
  `response_bytes <= max_response_bytes`; and a `response_oversized` verdict
  carries size evidence above it). Producer codes are
  `decision_round_policy_rejected` and `decision_terminal_policy_rejected`;
  parser codes `report_policy_rejected` and `terminal_policy_rejected`
  (`scoring_window_evidence_inconsistent` for the probe-bound scalars).
  Signatures, block leases, and the effective horizon are not re-derived here:
  the first two are live-only facts and the horizon is governed by the
  decision's own rules (`decision_round_after_horizon`,
  `manifest_expired_at_close`). Upstream, `ManifestVerificationResult` records
  the `evaluation_epoch` and `trust_policy_digest_sha256` a manifest was
  verified at and under, and `build_validator_probe_report` refuses any other
  epoch or policy (`report_evaluation_epoch_mismatch`, `trust_policy_mismatch`)
  and any observation the policy could not have produced
  (`observation_policy_violation`), so a report never claims an instant, a
  skew, or a serving verdict its verification did not admit. The golden window
  seals one policy (5s) and one round evaluated 5s before manifest 2's
  issuance; the negatives `submit-with-report-preceding-manifest-beyond-skew`
  (that report resealed one second earlier),
  `submit-with-terminal-issued-beyond-skew` (a terminal issued 6s after the
  close, produced at close+1 and rewritten to the close),
  `submit-with-terminal-before-policy-validity` (a terminal under a successor
  policy valid from close+5, produced at close+5 and rewritten to the close),
  `submit-with-report-probe-bounds-not-policy`,
  `submit-with-observation-oversized-for-policy`, and
  `submit-without-verifying-trust-policy` (sealed policies removed) are
  digest-valid and refused.
- **Repeated probing** is how replicas are covered: expected attributions are
  `opportunities / replica_count` summed over the rounds a miner was
  published in, with opportunity counts sealed by replica cardinality so the
  fraction is re-derived on parse; a silent replica of a three-replica
  deployment cannot be zeroed before `3 * min_expected_attributions`
  observations of that deployment.
- **Determinism**: exact rational accumulation; round order does not change
  the sealed bytes; every threshold is validator-local policy recorded in the
  document, so two validators with the same policy, rounds, terminal
  observation, and registered set produce identical records.
- **Evidence outlives assignment**: a miner attested during the window keeps
  its positive weight even if the terminal manifest no longer assigns it; it
  becomes zero in the next window.

Default policy: 24 verified rounds, 3 expected attributions, 1800s grace,
500‰ drop guard, 600-block registered gap, 86400s baseline age. These are
defaults, not consensus. Clock-skew bounds are never decision policy: they
come from the sealed trust policies.

## Threat and failure semantics

| Threat or failure | Effect | Why it is safe |
| --- | --- | --- |
| Publisher or object store down; pointer unreachable | validators re-probe the last accepted manifest until its effective horizon, then abstain | no zeros are ever derived from absence of a manifest |
| Stale cache serves an old pointer | re-probe (identical) or `pointer_rollback`/`pointer_stale`; abstain after freshness bound | pointer fields are re-verified against the signed manifest, envelopes, and chain state |
| Pointer names a signer set the policy could not accept, or the fetched envelopes differ from it | `pointer_signer_invalid`/`pointer_required_role_missing`/`pointer_signature_mismatch` before verification; abstain | signer provenance is bound end to end, not just counted |
| Compromised object store serves a forged or altered manifest | `signature_invalid`/`document_not_canonical`; abstain | only pinned Ed25519 keys under threshold and roles can sign |
| Publisher equivocates (two manifests at one sequence) | `same_sequence_divergence` on validators that saw the first; `decision_manifest_chain_incoherent` if both reach one window; both are archived evidence | append-only chain state is never rewound; the decision refuses incoherent input |
| Rounds from one chain combined with a terminal from a fork by omitting the actual publication where they diverge | `decision_manifest_chain_gap`; supplying the accepted predecessor exposes the fork as `decision_manifest_chain_incoherent` | the decision demands every digest-linked transition, independent of unused sequence integers |
| Live consumer omits its finalized height, or a boundary/CLI caller skips the lease check | `TypeError`/`current_finalized_height_required`/usage error; nothing verifies | the finalized height is required input of every live path; only historical replay is lease-free and it never probes |
| Publisher rolls back sequence, finalized height, or finalized epoch, or forks a height | `sequence_rollback`/`finalized_height_rollback`/`finalized_epoch_rollback`/`same_height_fork`; abstain | monotonic rules bound by policy gaps, carried in the chain state |
| Manifest claims validity beyond its tickets or block leases | `manifest_expired`/`manifest_replica_lease_expired` at the verifier; `manifest_expired_at_close`/`assignment_lease_expired_at_close` at the decision | assignment authority, not the manifest's own claim, bounds what is scoreable |
| Validator missed publications | `history_depth > 0`; catch-up walks at most that many actual entries, replays them under per-transition historical semantics, then verifies the head live | the head's link chain authenticates the span; cumulative sequence/height movement is never mistaken for one hop |
| New validator, no history | operator anchors on the live head from genesis only | complete live verification; history starts at the anchor and cannot be reset later |
| Sealed decision rewritten or produced by a defective coordinator | `abstain_reasons_not_derived`, `assigned_counts_invalid`, `scoring_window_evidence_inconsistent`, and companions on parse; never reaches a plan | full canonical manifests and reports reconstruct the probe rounds, assignment sets, scoring-window digest, and opportunities instead of trusting resealable summaries or scalar maxima |
| Digest-valid decision assigns positive weight with impossible counts, forged expected attribution, no serving evidence, or an unnormalized vector | `row_positive_weight_without_evidence`/`row_expected_attributions_inconsistent`/`observation_counts_invalid`/`weights_not_normalized` on parse | positive weight must be backed by exactly recomputable sealed evidence consistent with the scoring policy |
| Decision applied to a different metagraph view | `build_weight_plan_from_decision` refuses | height, hash, epoch, fingerprint, and every UID/hotkey are checked |
| Decision omits an eligible miner while naming the complete snapshot fingerprint, including through concurrent nested-row mutation | `build_weight_plan_from_decision` refuses (`complete eligible miner set`) | one deep-validated private decision and row snapshot is used throughout; rows must equal `eligible_weight_targets` |
| Verified report mutated in memory after validation | `decision_round_invalid`/`scoring_round_invalid` | evidence is rebuilt from canonical form before use |
| Runtime snapshot torn or inconsistent | `snapshot_revision_content_divergence` or manifest derivation mismatch; publisher refuses to sign | one-revision read is a contract, and the projection digest binds manifest to snapshot |
| Snapshot leaks material | structurally impossible: digests only; fixture scanned for forbidden terms | private retained bytes never enter the public contract |
| Central mass-eviction or empty snapshot, including exactly at a window boundary or after a close-time outage | `mass_unassignment_guard` (within the window or against the carried baseline) or manifest expiry; abstain | central failure or terminal availability is not miner evidence; verified in-window maxima survive the outage |
| Reduced assignment repeated in the next window to make the drop the new normal | still `mass_unassignment_guard`: the guarded window carried the pre-drop baseline, not the reduced set | a guarded drop never anchors the baseline; only policy age releases it |
| Manifest drops registered miners and pads itself with unregistered identities | `mass_unassignment_guard`; the padding is not counted and never enters a baseline | assigned sets are measured in registered identities |
| Validator sampling too sparse | `rounds_insufficient`/`coverage_insufficient`; abstain | the validator's gap never becomes a miner's zero |
| Digest-valid rewrite shifts a miner's first sighting later to manufacture activation grace | `row_first_seen_not_derived` on parse; never reaches a plan | every non-unassigned row is bounded by the earliest sealed manifest publication of its identity, while a genuinely earlier archived sighting remains legal |
| Endpoint republished under a new UID while the earlier registered identity earned weight in the window | producer seals the earning identity's original sighting; the record round-trips and its rewrite is still `row_first_seen_not_derived` | sightings are keyed by exact identity, so a later UID owner never erases an earlier `(uid, hotkey)` sighting |
| Old UID's archived sighting supplied for an endpoint republished under a new UID | the new UID keeps its own republication sighting (`assigned_in_grace` if unverified); only the archived identity moves earlier; the record round-trips, and rewriting the new UID's sighting later, erasing it, or back-dating it to the old UID's epoch is refused on parse (`row_first_seen_not_derived`, `row_assigned_first_seen_missing`, `row_classification_not_derived`) | archived sightings are keyed by exact `(uid, hotkey)`, never by endpoint, so archive data cannot cross-credit identities |
| Miner newly activated late in a window | `assigned_in_grace`; window still submits | new miners cannot stall the network |
| Miner registered but never assigned | `unassigned`, zero under safe preconditions | assignment is the central authority's prerogative; weight follows serving |
| Registered set from a different chain segment (behind, too far ahead, same height with another hash or epoch, lower epoch) | `registered_set_unbound`; abstain | plan and manifest views must agree |
| Key rotation half-applied | `trust_policy_mismatch`; abstain until re-anchored | rotation never resets non-equivocation history |
| Clock skew | manifest issuance ahead of the validator bounded by the verifying trust policy's `max_future_skew_seconds` at verification and, per manifest, by the same sealed policy document at the decision (reports and terminal alike); signer-clock ticket issuance ahead of the runtime's activation and capture instants bounded at 30s by one rule in Python and Go | all time is explicit input to pure code; no stage applies a bound other than the one carried by the policy that admitted the evidence, and that policy is sealed with the evidence |
| Report or terminal claims an evaluation instant its verification never admitted, or an instant at which its policy was not yet (or no longer) valid | `report_evaluation_epoch_mismatch`/`trust_policy_mismatch` at report construction; `decision_round_invalid`/`decision_round_policy_rejected`/`decision_terminal_future`/`decision_terminal_policy_rejected` at the decision; `scoring_window_evidence_inconsistent`/`report_policy_rejected`/`terminal_manifest_future`/`terminal_policy_rejected` on parse | the verification result carries its epoch and policy digest, and the sealed policy re-derives every evaluation-time admission rule |
| Responses judged under a looser same-authority policy (longer request budget, no certificate pins, larger body ceiling) relabelled under the stricter policy that verified the manifest | `observation_policy_violation` at report construction; `decision_round_policy_rejected` at the decision; `report_policy_rejected` on parse | every observation records the certificate and body size the policy-dependent checks judged, so the named policy's constraints are re-derived from the observation itself |
| Successor capture restamps a retained incarnation's ticket instant, its receipt, its activation, or the deployment facts its ticket binds; replaces an incarnation without advancing the generation; recycles a nonce, ticket, or receipt retired by any earlier replacement (A → B → A); or re-exports a dropped incarnation rewritten after an intervening capture | `snapshot_incarnation_rewritten`/`snapshot_generation_not_increasing`/`snapshot_incarnation_facts_reused`; publisher refuses | the durable lineage remembers the latest accepted incarnation of every `replica_id` and every signed fact it ever accepted in the era; a replacement is a new generation with never-seen facts |
| Lineage restored from a stale backup, resealed with retired facts removed or with impossible boundary claims, fed a capture out of order or a duplicate/rolled-back history, spent on a capture other than the one its boundary was taken for, given a second boundary before any capture followed, or grown past its bounds | `snapshot_lineage_anchor_mismatch`/`lineage_era_invalid`/`lineage_replica_facts_duplicate`/`snapshot_lineage_gap`/`snapshot_sequence_not_increasing`/`snapshot_lineage_candidate_mismatch`/`snapshot_lineage_boundary_pending`/`snapshot_lineage_overflow`; publisher refuses and forgets nothing | the lineage is a hash chain whose head the operator anchors out of band; sequences are contiguous and a history preflight refuses rollbacks; boundary claims are bounded, unique per sequence, and tied to the document's predecessor; only an explicit, recorded era boundary sheds retired facts, at the replica cap it is taken for the capture it admits and admits only that capture, and every live history replays to itself |
| Probe request stalled anywhere inside per-operation timeouts: slow name resolution, several unreachable addresses, a partial send drained just fast enough, or a byte-by-byte header or body trickle; or many lookups blocked at once | `ProbeTransportFailure("timeout")` at the transport within a small margin of the budget, `connection_failed` fast when the process-wide resolver slots are all held; `observation_policy_violation` if an older transport reports it as a response | name resolution is waited on for the remaining budget and abandoned, each address is dialled with the remaining budget, and every TLS step, `send`, and read on the connection is clamped to the time remaining in one budget on one monotonic clock (`DeadlineNetworkBackend`); the same budget is judged before every response-derived return; the binding re-derives the same bound from the recorded latency |
| The same wire outcome sealed under a policy other than the one that judged it (a 100ms `timeout` carried into a 5000ms report, a 64-byte `response_oversized` carried into a 4096-byte report, or the reverse) | `observation_policy_violation` at report construction; `decision_round_policy_rejected`/`report_policy_rejected` downstream | every observation seals the digest of the policy that judged it and its size evidence, and every consumer requires equality with the report's policy |
| Peer answers with a wire status outside `100..599` | `ProbeTransportFailure("transport_error")` with no status at the transport; the same at `evaluate_probe_response` for a leaked `ProbeResponse` | the contract's status range is enforced before an observation exists; no raw validation error reaches the CLI |
| `tls_pin_mismatch` judged under a pinning policy carried into a report naming a policy without pins, or whose pins include the leaf | `observation_policy_violation` at report construction; `decision_round_policy_rejected`/`report_policy_rejected` downstream | every policy-dependent failure branch is bound in both directions |

## Compatibility matrix

| Artifact | Status in this checkpoint | Consumers to update |
| --- | --- | --- |
| `active-assignment-manifest.v1`, `assignment-manifest-trust-policy.v1`, `assignment-manifest-signature-envelope.v1` | unchanged; schema and fixture digest-pinned in tests | none |
| `assignment-manifest-chain-state.v1` | **declared compatibility event**: gains required `last_finalized_epoch` (`null` at genesis); schema and fixture re-pinned; previously persisted states must be re-anchored (no validator is live on the old form) | private producer and every chain-state holder re-vendor; `advance_manifest_chain_state`/`rebind_manifest_chain_state_trust_policy` produce the new form |
| `validator-probe-report.v1` | **declared compatibility event**: every observation gains `trust_policy_digest_sha256` (the policy that judged it; every consumer requires it to equal the report's policy) and an oversized verdict preserves its size evidence in `response_bytes`; schema and fixture re-pinned; neither direction is compatible (old readers refuse the new field, new readers require it), so probe CLIs and their coordinator cut over together (see `api-migrations.md`); no validator is live on the old form | probe CLI emits the new form; coordinators and parsers require it |
| `miner-probe-attestation.v1` | schema and fixture unchanged and pinned | none |
| `weight-plan.v1` | unchanged, pinned; `build_weight_plan` unchanged, `build_weight_plan_from_decision` added in front of it | validator coordinator uses the decision-aware builder |
| Manifest verification (`verify_active_assignment_manifest`, `anchor_manifest_chain_state`) | effective horizon replaces `expires_at_epoch` as the validity bound; **`current_finalized_height` is required** (breaking signature); historical variant added and lease-free | every live fetcher passes its finalized height |
| `misscomputer-assignment-probe` CLI | **`--finalized-height` required** (breaking invocation) | operators add the flag from their finalized chain view |
| `misscomputer-checkpoint-boundary` protocol `misscomputer.checkpoint-boundary.v1` | additive operations; `bind_latest_pointer_to_manifest` takes `signatures`; `verify_manifest_latest_pointer` response adds `history_depth`; **`verify_manifest` requires `current_finalized_height`** (`current_finalized_height_required`); other existing operations and response shapes unchanged | private producer passes the finalized height and may adopt the new operations |
| `active-assignment-snapshot-lineage.v1` | new; publisher-local durable document; `advance_snapshot_lineage` is the durable form of `verify_snapshot_succession`; hash-chained (`previous_lineage_digest_sha256`), contiguous (`snapshot_lineage_gap`), era-scoped (`begin_snapshot_lineage_era`, `LineageEraBoundary`), anchored (`verify_snapshot_lineage_anchor`); Python only (no Go succession API) | manifest publisher persists it write-ahead beside its chain state, retains the head digest out of band, and seeds it by replaying retained captures |
| `active-assignment-snapshot.v1` | new; Go and Python parity locked; succession adds epoch monotonicity and incarnation lineage rules (`snapshot_incarnation_rewritten`, `snapshot_generation_not_increasing`, `snapshot_incarnation_facts_reused`). **Clock-domain rule**: the replica ordering check is `ticket_issued_at_epoch <= route_activated_at_epoch + 30` (was `<=` with no tolerance), so the documented capture+30 ticket tolerance is reachable; schema and golden fixture bytes unchanged, supplementary `active-assignment-snapshot-signer-skew.v1.json` added (fresh generation-2 incarnations, a valid successor of the golden) | runtime snapshot endpoint (Go), publisher; a producer that stamped activation from the signer's clock keeps validating; a publisher must never restamp a retained incarnation |
| `assignment-manifest-latest-pointer.v1` | new; carries `finalized_epoch`; immutable `.pointer.json` copy per manifest | publisher, validator fetcher |
| `validator-weight-decision.v1` | new; self-enforcing on parse, including sealed serving evidence, registered-only assigned counts, and the guarded-baseline rule; carries terminal hash/epoch/horizon/lease, `assigned_at_close`, baselines; `decide_weight_submission` takes `archived_manifests`. **Declared compatibility event**: the record gains `trust_policies` (the approved trust-policy documents its manifests name, sorted by digest) and `decide_weight_submission` requires `trust_policies`; the schema, golden fixture, and every decision negative fixture are re-pinned, and a record sealed without the field no longer digest-verifies (no coordinator is live on the old form) | validator coordinator supplies every accepted intermediate manifest it did not probe and the approved trust-policy documents it verified under |
| `contracts/negative/` | new convention: golden invalid documents with pinned rejection reasons, including digest-valid forged `submit-with-*` decisions | contract test suites |
| Go `pkg/assignment` | new package; no existing Go API changed | runtime snapshot endpoint |

Every schema and every golden fixture of the seven pre-existing contract
families is SHA-256 pinned in `test_contract_checkpoint.py`; the four new
contracts are pinned by regeneration equality with their generators and by the
negative-fixture inventory.

Private-side note: the private producer's `central-active-assignment-snapshot`
(retained ticket and receipt bytes) remains a private, never-published input.
Its projection to the manifest is already identical to
`project_manifest_deployments`; adopting the public snapshot as the producer's
input is a private change that needs no public contract change.

## Open choices (not frozen here)

Each of these is deliberately left to the owning lane; none changes a
contract shape.

1. **Snapshot transport.** Whether the runtime serves the snapshot over the
   existing `misscomputer.runtime.v1` Unix socket or writes a file is a
   runtime/operator decision; the bytes are the same either way.
2. **Publisher cadence.** How often the publisher captures and publishes,
   within the trust policy's freshness bounds; the pointer's 60s cache ceiling
   and `max_manifest_age_seconds` bound it from both sides.
3. **Coordinator window length and probe interval.** Validator-local; the
   decision policy defaults assume roughly one probe per minute over a
   one-hour window, and the policy enforces only `grace <= window`.
4. **Archive-derived first-seen sightings.** A coordinator may or may not
   supply earlier identity sightings from its archive; both are conforming.
   What is not open is their scope: a supplied sighting names the exact
   `(uid, hotkey)` it was archived for and never applies to another identity.
   Cross-window mass-unassignment protection is not an open choice: the
   sealed baseline is part of the v1 record and a coordinator that holds one
   must supply it. Neither is chain completeness: a coordinator that did not
   probe an accepted sequence must supply that manifest as an archived
   manifest, or the window is refused as a gap.

## Files

- `src/misscomputer_subnet/contract_codec.py`, `assignment_snapshot.py`,
  `manifest_publication.py`, `validator_decision.py`;
- `pkg/assignment/snapshot.go` with fixture-parity tests;
- `contracts/schemas/*.v1.schema.json` and `contracts/fixtures/*.v1.json` for
  the four new contracts (plus the supplementary
  `active-assignment-snapshot-signer-skew.v1.json`), regenerated by
  `tests/python/contract_checkpoint_context.py`;
- `contracts/negative/<contract>.v1/*.json` golden invalid documents, each
  naming the contract, the expected rejection layer (`schema` or `model`),
  and the rejection code; the `validator-weight-decision.v1/submit-with-*`
  cases carry valid self and row digests and are rejected only by the
  derived semantics;
- `tests/python/test_contract_checkpoint.py`, `test_assignment_snapshot.py`,
  `test_manifest_publication.py`, `test_validator_decision.py`,
  `test_checkpoint_boundary_contracts.py`.
