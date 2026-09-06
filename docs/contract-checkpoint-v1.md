# Contract checkpoint v1: snapshot, publication, and validator decision

## Purpose

This checkpoint freezes the interfaces that the remaining launch work depends
on so that the runtime snapshot endpoint, the manifest publisher, the
validator coordinator loop, and operator wiring can be built in parallel
without renegotiating a boundary. It contains contracts, pure verification
code, golden and negative fixtures, and cross-language parity tests. It
deliberately implements no runtime endpoint, no publisher daemon, no
coordinator loop, no service wiring, and no weight submission.

Three contracts are added; every pre-existing contract is unchanged and
byte-pinned by the test suite:

| Contract | Version | Producer | Consumer | Module |
| --- | --- | --- | --- | --- |
| `active-assignment-snapshot` | 1 | scheduler runtime (Go, `pkg/assignment`) | manifest publisher | `assignment_snapshot.py` |
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
| `snapshot_sequence` | strictly increasing per capture from one runtime |
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
| `replicas[].ticket_issued_at_epoch`, `ticket_expires_at_epoch` | signed ticket window; unexpired at capture, issued no more than 30s after capture |
| `replicas[].route_activated_at_epoch` | edge activation instant of this exact incarnation; `>= ticket_issued_at_epoch`, `<= captured_at_epoch` |
| `replicas[].route_state` | constant `active`; pending, quarantined, and deactivated incarnations are never exported |
| `projected_assignment_vector_digest_sha256` | digest of `project_manifest_deployments(snapshot)` |
| `snapshot_digest_sha256` | self digest |

The snapshot never carries the raw challenge value, ticket or receipt bytes,
axon addresses, TLS pins, artifact or image keys, provider or tunnel
identifiers, scheduler queue state, signer seeds, wallets, or weights; the
golden fixture is scanned for each of those.

### Consistency semantics

`verify_snapshot_succession(previous, current)` is the transactional rule a
publisher applies between captures: `snapshot_sequence` strictly increases;
`state_revision`, `captured_at_epoch`, and `finalized_height` never decrease;
an unchanged `state_revision` must carry identical `deployments`; one
finalized height has one block hash; authority and network never change.
Codes: `snapshot_sequence_not_increasing`, `snapshot_revision_rollback`,
`snapshot_revision_content_divergence`, `snapshot_capture_rollback`,
`snapshot_finalized_rollback`, `snapshot_finalized_fork`,
`snapshot_authority_mismatch`, `snapshot_network_mismatch`.

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

`active-assignment-manifest` v1 and its envelope, trust policy, and chain
state are unchanged. This section freezes what surrounds them.

| Property | Frozen behaviour |
| --- | --- |
| Canonical serialization | as above; the signed message is `miss.computer/misscomputer-subnet/active-assignment-manifest/v1/ed25519` + `NUL` + canonical manifest JSON |
| Signer and key IDs | `signer_key_id` slug (`^[a-z0-9](?:[a-z0-9_-]{0,62}[a-z0-9])?$`) resolved against `trusted_keys[].key_id`; raw Ed25519 public key (base64) plus `public_key_sha256`; small-order keys rejected |
| Threshold and trust policy | `threshold` distinct verified keys and every `required_roles` entry covered; roles are `assignment_issuer`, `assignment_auditor`, `assignment_security`; per-key validity window and `revoked_at_epoch`; purpose fixed to `active_assignment_manifest_publication_v1` |
| Sequence and linkage | `sequence` starts at 1, `previous_manifest_digest_sha256` is `null` exactly at 1 and otherwise equals the previous accepted manifest digest; gaps above `max_sequence_gap` rejected |
| Finalized-chain binding | `finalized_height`/`finalized_block_hash`/`finalized_epoch` copied from the snapshot; height never decreases, gaps above `max_finalized_height_gap` rejected, same height implies same hash |
| Issued/expiry | `issued_at_epoch == captured_at_epoch`; `expires_at_epoch - issued_at_epoch <= max_manifest_lifetime_seconds`; not future beyond `max_future_skew_seconds`; not older than `max_manifest_age_seconds` at evaluation |
| Immutable objects | `v1/manifests/<manifest_digest>.json` and `v1/manifests/<manifest_digest>.<signer_key_id>.signature.json`; content-addressed, never modified or deleted while referenced |
| Atomic latest pointer | `v1/latest.json` is an `assignment-manifest-latest-pointer` v1 written only after every object it names is readable; replaced atomically; never rewritten to a lower sequence |
| Replay / rollback / fork | an identical re-fetch is a **re-probe** (state unchanged); a different manifest at an accepted sequence is `same_sequence_divergence`; lower sequences, broken links, height rollback, and same-height forks are rejected with stable codes; the pointer pre-check mirrors these as `pointer_equivocation`, `pointer_rollback`, `pointer_sequence_gap` |
| Cache behaviour | immutable objects `Cache-Control: public, max-age=31536000, immutable`; pointer `public, max-age=60, must-revalidate`; fetchers send `Cache-Control: no-cache` for the pointer; a cache can only withhold, never widen acceptance |
| Key rotation | see below |
| Compatibility | manifest v1 bytes, schema, and boundary operations unchanged; new pointer object is additive |

### Latest pointer

`assignment-manifest-latest-pointer` v1 copies `sequence`,
`previous_manifest_digest_sha256`, `manifest_digest_sha256`, finalized height
and hash, `issued_at_epoch`, `expires_at_epoch`, authority, trust-policy
digest, and network from the manifest, adds `manifest_object_key` (which must
equal the content-addressed key of the digest) and the sorted
`signer_key_ids` published beside it, and seals itself with
`pointer_digest_sha256`. It is not independently signed: every field is
re-checked against the signed manifest by `bind_latest_pointer_to_manifest`,
and `verify_manifest_latest_pointer` refuses, before any object fetch, a
pointer whose authority, policy, network, signer set, threshold, freshness,
or chain position could not lead to an acceptable manifest.

Fetch procedure (frozen): fetch `v1/latest.json` with `no-cache`; parse
canonical bytes; `verify_manifest_latest_pointer`; fetch the named manifest
object and exactly the named signature objects; parse each as canonical
bytes; `bind_latest_pointer_to_manifest`;
`verify_active_assignment_manifest`; persist the next chain state before
using the manifest. Any failure is "manifest unavailable or invalid" for the
decision rules below.

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
`weight_plan.build_weight_plan`.

| Situation | Outcome | Reason code |
| --- | --- | --- |
| Terminal manifest fetch at window close unavailable | ABSTAIN | `manifest_unavailable` |
| Terminal manifest rejected (signature, freshness, chain, policy, pointer) | ABSTAIN | `manifest_invalid` (rejection code recorded) |
| Terminal manifest expired at the close evaluation instant | ABSTAIN | `manifest_expired_at_close` |
| Fewer verified rounds than `min_verified_rounds` | ABSTAIN | `rounds_insufficient` |
| Any assigned miner outside activation grace with expected attributions below `min_expected_attributions` | ABSTAIN | `coverage_insufficient` |
| Registered set not bound to the terminal manifest's chain view (behind it, or ahead by more than `max_registered_height_gap`) | ABSTAIN | `registered_set_unbound` |
| Terminal assigned-miner count below `(1000 - max_assigned_drop_permille)/1000` of the largest assigned set seen in the window | ABSTAIN | `mass_unassignment_guard` |
| No registered miner has positive verified evidence | ABSTAIN | `no_positive_evidence` |
| None of the above | SUBMIT | (none) |

Per-miner classification in the record:

| Class | Meaning | Weight |
| --- | --- | --- |
| `verified_serving` | attested serving evidence in the window | positive |
| `assigned_unverified` | assigned at close, sufficiently sampled, no evidence | zero |
| `assigned_in_grace` | assigned at close, first sighted less than `activation_grace_seconds` before close, no evidence | zero, never a reason to abstain |
| `assigned_undersampled` | assigned at close, outside grace, under-sampled | zero in the record, forces ABSTAIN |
| `unassigned` | registered but absent from the terminal manifest | zero |

Frozen invariants:

- **Zero for absent miners is only submitted under the safe preconditions**:
  terminal manifest verified and unexpired at close, registered set bound,
  coverage sufficient, mass-unassignment guard satisfied, positive evidence
  present. Otherwise the validator abstains and the chain keeps its previous
  weights.
- **No positive verified evidence, no transaction**: an abstain record has
  `weight_plan_rows_digest_sha256 = null`, and
  `weight_plan_rows_for_submission` refuses it; a submit record commits to the
  exact `[{miner_hotkey, weight}]` rows by digest.
- **Activation grace** anchors on the miner's earliest sighting across the
  window's accepted manifests, the terminal manifest, and any earlier
  archived sighting the coordinator supplies (a supplied sighting may only be
  earlier). Grace creates no weight; a miner earns weight from the first
  window in which it is attributed. `activation_grace_seconds` may not exceed
  the window length.
- **Finalized window closure**: reports are admitted with
  `window_start <= evaluation_epoch < window_end`; the terminal observation
  is taken at or after `window_end`; the registered set is a finalized view
  carrying `metagraph_identity_fingerprint_sha256`, which the weight plan
  repeats.
- **Repeated probing** is how replicas are covered: expected attributions are
  `opportunities / replica_count` summed over the rounds a miner was
  published in; a silent replica of a three-replica deployment cannot be
  zeroed before `3 * min_expected_attributions` observations of that
  deployment.
- **Determinism**: exact rational accumulation; round order does not change
  the sealed bytes; every threshold is validator-local policy recorded in the
  document, so two validators with the same policy, rounds, terminal
  observation, and registered set produce identical records.
- **Evidence outlives assignment**: a miner attested during the window keeps
  its positive weight even if the terminal manifest no longer assigns it; it
  becomes zero in the next window.

Default policy: 24 verified rounds, 3 expected attributions, 1800s grace,
500‰ drop guard, 600-block registered gap. These are defaults, not consensus.

## Threat and failure semantics

| Threat or failure | Effect | Why it is safe |
| --- | --- | --- |
| Publisher or object store down; pointer unreachable | validators re-probe the last accepted manifest until it expires, then abstain | no zeros are ever derived from absence of a manifest |
| Stale cache serves an old pointer | re-probe (identical) or `pointer_rollback`/`pointer_stale`; abstain after freshness bound | pointer fields are re-verified against the signed manifest and chain state |
| Compromised object store serves a forged or altered manifest | `signature_invalid`/`document_not_canonical`; abstain | only pinned Ed25519 keys under threshold and roles can sign |
| Publisher equivocates (two manifests at one sequence) | `same_sequence_divergence` on validators that saw the first; both are archived evidence | append-only chain state is never rewound |
| Publisher rolls back sequence or finalized height, or forks a height | `sequence_rollback`/`finalized_height_rollback`/`same_height_fork`; abstain | monotonic rules bound by policy gaps |
| Runtime snapshot torn or inconsistent | `snapshot_revision_content_divergence` or manifest derivation mismatch; publisher refuses to sign | one-revision read is a contract, and the projection digest binds manifest to snapshot |
| Snapshot leaks material | structurally impossible: digests only; fixture scanned for forbidden terms | private retained bytes never enter the public contract |
| Central mass-eviction or empty snapshot | `mass_unassignment_guard` or manifest expiry; abstain | central failure is not miner evidence |
| Validator sampling too sparse | `rounds_insufficient`/`coverage_insufficient`; abstain | the validator's gap never becomes a miner's zero |
| Miner newly activated late in a window | `assigned_in_grace`; window still submits | new miners cannot stall the network |
| Miner registered but never assigned | `unassigned`, zero under safe preconditions | assignment is the central authority's prerogative; weight follows serving |
| Registered set from a different chain segment | `registered_set_unbound`; abstain | plan and manifest views must agree |
| Key rotation half-applied | `trust_policy_mismatch`; abstain until re-anchored | rotation never resets non-equivocation history |
| Clock skew | bounded by `max_future_skew_seconds`; capture-side ticket skew bounded at 30s | all time is explicit input to pure code |

## Compatibility matrix

| Artifact | Status in this checkpoint | Consumers to update |
| --- | --- | --- |
| `active-assignment-manifest.v1` and companions | unchanged, digest-pinned in tests | none |
| `validator-probe-report.v1`, `miner-probe-attestation.v1` | unchanged | none |
| `weight-plan.v1` | unchanged | none |
| `misscomputer-checkpoint-boundary` protocol `misscomputer.checkpoint-boundary.v1` | additive operations only; existing operations and response shapes unchanged | private producer may adopt the new operations |
| `active-assignment-snapshot.v1` | new; Go and Python parity locked | runtime snapshot endpoint (Go), publisher |
| `assignment-manifest-latest-pointer.v1` | new | publisher, validator fetcher |
| `validator-weight-decision.v1` | new | validator coordinator |
| `contracts/negative/` | new convention: golden invalid documents with pinned rejection reasons | contract test suites |
| Go `pkg/assignment` | new package; no existing Go API changed | runtime snapshot endpoint |

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
   supply earlier endpoint sightings from its archive; both are conforming.
5. **Cross-window mass-unassignment comparison.** The guard compares within
   the window; comparing against the previous window's terminal manifest is
   a coordinator refinement that would only add abstentions.

## Files

- `src/misscomputer_subnet/contract_codec.py`, `assignment_snapshot.py`,
  `manifest_publication.py`, `validator_decision.py`;
- `pkg/assignment/snapshot.go` with fixture-parity tests;
- `contracts/schemas/*.v1.schema.json` and `contracts/fixtures/*.v1.json` for
  the three new contracts, regenerated by
  `tests/python/contract_checkpoint_context.py`;
- `contracts/negative/<contract>.v1/*.json` golden invalid documents, each
  naming the contract, the expected rejection layer (`schema` or `model`),
  and the rejection code;
- `tests/python/test_contract_checkpoint.py`, `test_assignment_snapshot.py`,
  `test_manifest_publication.py`, `test_validator_decision.py`,
  `test_checkpoint_boundary_contracts.py`.
