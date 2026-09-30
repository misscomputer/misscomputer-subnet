# Static-site scoring and evidence (development)

Static scoring is a **separate, versioned path** for `static-site-v1`
endpoint incarnations. Dynamic `oci-image-v1` endpoints stay on
`organic-epoch-score` v1 and `organic-availability-score` v1; no byte, rule
or fixture of that path changes. Static admission is behind the
`static_sites` flag (off by default), and nothing here is wired into a
weight decision, a central checkpoint or a live service.

Modules: `static_scoring.py` (scoring core) and `static_evidence.py`
(durable evidence). They consume the validator's
[`static_index`/`static_probe`](static-site-validator-probe.md) types and
never re-implement index authentication or probe judgement.

## Records

| Record | Producer → consumer | Purpose |
| --- | --- | --- |
| `static-probe-observation` v1 | validator probe evaluator (`static_probe.py`) | one judged request; owned by the validator track |
| `static-evidence-record` v1 | validator → its own durable journal | hash-chained, fsynced wrapper of one observation |
| `static-epoch-score` v1 | validator → auditors / runtime | sealed epoch: targets, index states, coverage, tallies, evidence, actions, alerts, observations |
| `static-availability-score` v1 | validator → (future) decision | per-miner mean over eligible endpoint-epochs |
| `static-edge-evidence` v1 | private edge → operators / auditors | one admission-crawl or ordinary-traffic check (static-site contract §10.4) |

Schemas and golden fixtures are in `contracts/schemas` and
`contracts/fixtures`; `tests/python/static_scoring_context.py` regenerates
them from real validator probes against an independent fake replica.

## Inputs and trust boundary

`score_static_epoch(targets, indexes, abstentions, observations, …)`:

- `targets`: every static deployment of the verified manifest v3;
- for each target exactly one index state: a `VerifiedStaticIndex`
  (release-authority signature verified under the pinned static trust policy)
  or a `StaticIndexAbstention`. A target with neither, or with both, refuses
  the epoch: an unknown index state is never scored;
- `observations`: hidden probes only; admission-crawl observations are
  refused (admission gates routing, it is not a score).

Each observation is re-bound before it counts: published incarnation and
miner identity; the target's `sha256:` release digest and the index's release
trust-policy digest; the
exact `expected_static_response` of its method and path — status, length,
body and normative header digests (so expected bytes
come only from the authenticated index, never from a miner or from the
observation itself); the probe body ceiling (≤ 1 MiB GET); and the embedded
attestation, whose status (`verified`, `replayed`, `fraudulent`) is
re-derived in the evaluator's order: signature under the manifest service
key, nonce, incarnation/site/request binding (`artifact_digest` =
`site_digest`), time window, and attested = observed. A fraud cannot be relabelled as a cache replay, and
a content fault cannot be relabelled as a pass.

## Epoch rules

| Condition | Disposition / effect |
| --- | --- |
| deployment's index abstained | every endpoint `abstain_index`; never zero; alert `static_index_unavailable` or `static_index_invalid` (§11.2 record code); its observations refuse the epoch |
| more than half of sampled endpoints saw only path failures | `common_mode_unavailable`; every endpoint `excluded_common_mode` |
| ≥ 2 distinct miners of one deployment returned the same wrong status, body and header digests to the same request | deployment `excluded_index_suspect`; those faults are **not** charged to miners |
| fewer than `min_attempts` attempts | `abstain_insufficient_attempts` |
| otherwise | `eligible`, availability = successes / attempts |

| Observation | Attribution | Evidence / action | Alert |
| --- | --- | --- | --- |
| attested = observed ≠ expected status, body or normative headers (`quarantine_candidate`) | miner | content-fault evidence; remove, replace, **quarantine**; `trust_zero: false` | `static_content_fault` |
| fresh attestation naming another incarnation, ticket, site or request | miner | fraud evidence; remove, replace, quarantine, `trust_zero: true` | `static_attestation_fraud` |
| attestation for another probe (`cache_replay`) | path | none | `static_replay_observed` |
| attested ≠ observed (`content_altered_in_transit`) | path | none | `static_path_tampering` |
| missing or invalid attestation | miner | failed probe only | — |
| transport, TLS, edge-generated, forbidden header | path | failed probe only | — |

`endpoint_actions` mirror the runtime health policy's action shape so the
private runtime can apply them; wrong bytes alone never recommend
trust-zero. Every record re-derives tallies, dispositions, evidence, actions
and alerts from its embedded observations on parse, and is independent of
input order. `replay_static_epoch_score(record, indexes)` rebuilds it from
re-authenticated indexes byte for byte.

## Coverage

Each authenticated deployment has a §11.3 coverage row: routes and bytes in
total, bytes GET-eligible under the ceiling, and, for the epoch, distinct
routes probed, of them body-verified by GET, and probes of unlisted paths
(synthetic `.absent`/navigation vectors).
Responses above the ceiling rest on admission, miner verify-then-serve and
edge checks; the row states that explicitly.

## Window

`aggregate_static_window` takes the mean over a miner's eligible
endpoint-epochs and carries per-miner content-fault and fraud counts plus all
evidence references. A miner with no eligible endpoint-epoch is absent,
never zero.

## Durable evidence

`StaticEvidenceJournal(path)` is one owner-only (`0600`, single link, no
symlink) append-only file of canonical `static-evidence-record` lines. Open
verifies the whole chain and refuses a torn, edited, reordered or foreign
journal instead of repairing it; each append is one `O_APPEND` write plus
`fsync`, refuses a reused nonce, and is bounded (256 MiB, 2^20 records).
Callers serialize access under the probe CLI's state-root lock.

## Not yet integrated

- The validator probe CLI does not yet write the journal or call
  `score_static_epoch` (validator track).
- `validator_decision`, `organic-central-score-report` and the checkpoint
  relay read only organic v1. Combining static and dynamic availability, and
  whether content faults make a miner ineligible for a window, need an owner
  decision, a new scoring-policy digest, a mirrored private implementation
  and a reissued checkpoint trust policy.
- Records pin `finney`/`24` like the organic path; testnet drills of the
  public pipeline need a network/netuid decision.
- The private runtime (quarantine store, replacement, alert delivery) and
  edge (producing `static-edge-evidence`) mirror these public contracts
  across the split; nothing here links private code.
