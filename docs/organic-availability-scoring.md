# Organic availability scoring and public validator evidence

This document describes the public-validator side of the organic app
deployment contract (contract §11, §13, §17.2): what central publishes, how a
validator probes organic app replicas it cannot predict, how each probe is
attributed, and how probes become a per-miner availability score. It replaces
the synthetic campaign challenge and the retired volume-based scorer; there is
no dual-running.

## What the score measures

The availability of real organic app endpoints assigned to a miner, through
the public edge path, measured by the validator's own hidden probes. It does
**not** measure request volume, response bytes, customer identity,
popularity, app-content correctness, or proof that the miner executed the
uploaded image. No non-TEE protocol can prove the last one (contract §11.3);
that limit is stated, not disguised.

## Contracts

| Contract | Version | Producer → consumer | Owner of the document | Scoring pipeline |
| --- | --- | --- | --- | --- |
| `active-assignment-manifest` | 2 | central exporter → validators | `organic_contracts` / `pkg/organic` | `organic_manifest.py`; operator-side publisher is private |
| `organic-probe-authorization` | 1 | validator → edge | `organic_contracts` / `pkg/organic` | `organic_probe.py` |
| `miner-probe-attestation` | 2 | miner agent → validator | `organic_contracts` / `pkg/organic` | `organic_probe.py` |
| `organic-probe-observation` | 1 | validator-local evidence | `organic_probe.py` | — |
| `organic-epoch-score` | 1 | validator → auditors | `organic_scoring.py` | — |
| `organic-availability-score` | 1 | validator → decision / central report | `organic_scoring.py` | — |
| `validator-weight-decision` | 2 | validator → weight plan | `validator_decision.py` | — |
| `organic-central-score-report` | 1 | central validator → score checkpoint | `checkpoint_score_contracts.py` | — |

The first three are the canonical contract-track documents (see
[`organic-contracts.md`](organic-contracts.md)); their encoding, signing input,
timestamps and header digest are defined there. This track adds the
publication pipeline around the manifest, the validator's probe transport and
judgement, and the three scoring records. Schemas and golden fixtures live in
`contracts/schemas` and `contracts/fixtures`.

### Manifest v2

Each deployment entry carries `deployment_id` (the route label),
`route_host`, `artifact_digest`, the sanitized health predicate (`method`,
`path`, `expected_statuses`, `response_marker`) and `attestation_requirement`
(`miner_service_key_v2`). Each replica carries the exact endpoint
incarnation, miner UID/hotkey, service public key, pinned TLS leaf digest,
ticket and receipt digests, `activated_at_epoch`, and the leases
`expires_at_epoch` and `chain_block`/`expires_at_block`. There is no challenge, campaign sequence,
customer secret, private origin URL, or request data. Origin-serving
deployments and pending routes have no representation: the exporter publishes
only active miner routes after verified cutover.

The frozen `assignment-manifest-trust-policy` v1, signature envelope v1 and
chain state v1 are reused unchanged: they pin the central authority and the
publication channel and read only the header every manifest version shares.
Version 2 signs under
`miss.computer/misscomputer-subnet/active-assignment-manifest/v2/ed25519`, so
a v1 signature can never verify as v2. Replica leases are *publication*
leases the exporter refreshes on every export, never ticket values, because
an organic route outlives its acceptance ticket (contract §6.6). Validity ends
at the manifest's own expiry or the earliest `expires_at_epoch`, and never
once a block lease has ended at the validator's finalized height.
Verification also refuses one UID, hotkey or service key bound to two
identities, a reused assignment nonce, or a replica activated after issuance. A missing,
stale, or unverifiable manifest means the validator abstains. v2 objects are
published under `v2/manifests/` on the assignment publication origin, never
the artifact bucket (contract §5.2, R7).

### Probe authorization and attestation v2

The validator builds the canonical authorization (whole-second `issued_at`)
with its hotkey signer and sends base64 of the canonical document in
`X-Miss-Organic-Probe-Authorization`; the edge verifies membership,
signature, 30 s freshness and one-time nonce, and strips it before app
contact. The miner's attestation v2 returns in `X-Miss-Probe-Attestation` as
base64 of the canonical document. Headers are parsed strictly: exact base64,
exact canonical bytes, no unknown members. The miner's
`response_header_sha256` is recorded but never recomputed (the edge rewrites
headers). An `observed_at` more than 2 s before `issued_at` or more than
30 s + 2 s after it is outside the authorization window.

## Hidden schedule

`plan_hidden_probes` derives each epoch's probes from a validator-private
32-byte CSPRNG seed with HMAC-SHA256 over the manifest digest, epoch index,
endpoint incarnation, and probe index. Each endpoint gets three probes per
five-minute epoch, one uniformly placed in each third, with a 32-byte nonce.
The schedule is reproducible by the seed holder and unpredictable from the
public manifest. Probes outside the manifest horizon are omitted. The seed
must be generated per validator with a CSPRNG and never published.

## Attribution

| Outcome | Attribution | Fraud |
| --- | --- | --- |
| upstream marker + verified attestation + status in `expected_statuses` + marker in first 64 KiB | success | — |
| transport failure, certificate pin mismatch, or no upstream marker (edge 502/404/403) | `path` | no |
| replica answered; attestation missing, unparseable, signature invalid, or status/body differ from what arrived | `miner` | no |
| replica answered; attestation signature verifies but binds another endpoint, generation, ticket, artifact, validator, nonce, request, or an `observed_at` outside the authorization window | `miner` | **yes** |
| verified attestation over a response that fails the customer predicate, or an upstream body over the verifiable size bound | `application` | no |

A wrong status, a missing marker, unreachability, or bytes altered in transit
is never fraud. Fraud evidence is surfaced in the epoch and window records for
the trust policy to act on; scoring counts it only as a failed probe.

## Scoring

Per epoch (`score_organic_epoch`):

1. every observation must name this validator, a supplied manifest, an
   endpoint the manifest published with the same identity and predicate, and
   an issue time inside both the epoch and the manifest horizon; every
   embedded attestation is re-verified against the manifest's service key;
   duplicates, replays, and inconsistencies refuse the epoch;
2. an endpoint with fewer than two attempts abstains;
3. if more than half of the sampled endpoints saw only `path` failures, the
   epoch is `common_mode_unavailable` and every endpoint abstains;
4. if at least two replicas of one app saw an `application` failure, the app
   is inconclusive and all its replicas are excluded;
5. otherwise endpoint availability is `successes / attempts`.

Per window (`aggregate_organic_window`), a miner's availability is the mean of
its eligible endpoint-epochs. A miner with none is unscored: absent from the
result, never zero, never trust-zero. `organic_weight_rows` hands scored
miners to the existing `weight_plan.build_weight_plan`, which normalizes and
drops zero rows.

`organic-serving-window` counters may be attached as `ServingCorroboration`.
They are summarized per endpoint for audit and never read by the score; origin
windows are ignored.

## Determinism and audit

Arithmetic is exact. Records seal availabilities as reduced fractions, are
independent of input order, and re-derive every tally, disposition, and fraud
entry from their embedded observations on parse. `replay_organic_epoch_score`
rebuilds a record from its evidence and the public manifests, re-verifying
every miner signature, so any third party can audit a validator's score
inputs. Observation facts (latency, body marker presence) remain the
observing validator's trust boundary, as with every unsigned local report.

## Pipeline in this repository

1. `misscomputer-assignment-probe` (`assignment_probe_cli.py`) runs one epoch:
   verify manifest v2 → hidden schedule → hotkey-signed probes over HTTPS →
   sealed `organic-epoch-score` (see
   [`public-validator-live-probe-runbook.md`](public-validator-live-probe-runbook.md)).
2. At window close `misscomputer-organic-window` (`organic_window_cli.py`)
   reads the finalized head's metagraph and block hash, collects the window's
   epoch records and archived manifests, fetches and verifies the terminal
   manifest against the probe's accepted chain state (read-only, never
   locked or advanced), and calls `validator_decision.decide_weight_submission`
   to seal a `validator-weight-decision` v2. It writes the decision, and only
   for `submit` the `WeightPlan` for the one-shot executor. Rules: the terminal manifest must
   verify and be within its horizon and policy at close; at least
   `min_scored_epochs` scored epochs; the registered view must be bound to the
   manifest's chain view; rows are availability (scored), 0 (fraud evidence)
   or 0 (unscored); no positive row means no transaction. Parsing replays every
   embedded epoch against the embedded manifests.
3. Only a `submit` decision reaches `weight_plan.build_weight_plan_from_decision`.
   `public_verifier.verify_public_relay_path` lets a third party re-verify the
   live head, the decision and the plan.
4. The central validator's own window becomes an `organic-central-score-report`
   bound by the signed `central-score-checkpoint` that external validators
   relay (`misscomputer-score-checkpoint-relay`).

The synthetic volume scorer (`probe_scoring.py`), the v1 decision record, the
synthetic score report/record contracts and the v1 challenge-probe CLI flow
are deleted.

The validator neuron does not derive a weight plan from Go runtime
observations. Public weight plans come from a submitted organic-window
decision or the verified central checkpoint relay.

## Contract gaps and recommendations

These are not silently resolved by new wire formats; each names what this
track implements today and what the owning track should freeze.

1. **Replica leases (01).** The contract fixture sets `expires_at_epoch` and
   `expires_at_block` about one ticket lifetime after activation. Organic
   routes outlive tickets (§6.6), so a ticket-derived value would drop every
   entry five minutes after acceptance. *Recommendation:* document both as
   publication leases the private exporter refreshes on every export; public
   verification enforces their validity.
2. **Trust policy / envelope / chain state for v2 (01, owner).** This track
   reuses the frozen v1 documents (they pin the channel and read only shared
   header fields) with a v2 signing domain, so no v1 signature verifies as v2.
   *Recommendation:* accept this; if a distinct v2 policy set is required it
   must be a new contract-track schema, not a scoring-track invention.
3. **v2 latest pointer and history walk (01/infra).** Not defined. Today the
   CLI takes explicit manifest/signature files or URLs and onboards with
   `--trusted-state-anchor genesis`; a gap after onboarding stops the probe
   (`previous_link_mismatch`). *Recommendation:* `v2/latest.json` as an
   `assignment-manifest-latest-pointer` schema version 2 identical to v1 except
   object keys under `v2/manifests/`, plus a v2 historical replay mirroring v1
   semantics.
4. **Identity rules (01).** The canonical model does not forbid one hotkey
   under two UIDs, a reused assignment nonce, or a replica activated after
   issuance; this track's verification does. *Recommendation:* move the three
   rules into `ActiveAssignmentManifestV2`.
5. **Response header digest scope (01/05).** The canonical digest hashes every
   header it is given. *Recommendation:* state that the miner hashes the
   container's end-to-end headers only (no hop-by-hop, no `X-Miss-*`).
6. **Fraud disposition (owner).** The central report makes a miner with
   attributable attestation fraud `ineligible` (score 0) and the validator
   decision gives it weight 0, implementing §11.3 trust-zero for the window.
   *Recommendation:* confirm; a longer trust-zero memory is a trust-policy
   feature, not a score.
7. **Unscored miners on chain (owner).** Chain weights are relative, so a
   registered miner with no eligible endpoint-epoch necessarily receives no
   weight from that validator's plan (a zero row the plan drops). It carries
   no penalty classification. *Recommendation:* accept.
8. **Serving-window corroboration (06).** Volume is never scored. Any
   corroboration supplied to a verifier remains separate from the hidden-probe
   evidence and cannot replace an attested miner response.

## Publication boundary

The operator publishes v2 manifests and signed checkpoints. This public tree
defines and verifies their wire contracts; producer implementation, scheduling
and deployment wiring live in the private repository.

Validator-local scheduling of `misscomputer-assignment-probe` and
`misscomputer-organic-window` remains an operator decision, not part of the
wire contract.

## Retired contract family

- **v1 manifest family:** removed. The synthetic `active-assignment-manifest`
  v1, `active-assignment-snapshot` v1 and its lineage, the v1 latest pointer
  and history walk, `miner-probe-attestation` v1, `validator-probe-report` v1
  and the checkpoint boundary's v1 manifest/snapshot/pointer operations are
  deleted (contract section 13). The channel trust policy, signature envelope
  and chain state v1 remain frozen and verify manifest v2.
