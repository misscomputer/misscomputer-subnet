# Signed central score checkpoints and external-validator relay

## Authority and dependency model

`miss.computer` remains the sole challenge, wildcard-domain, edge, evidence,
and scoring authority. The canonical synthetic score report published under the
`canonical-synthetic-score-report` contract is the only score
input to this protocol. An external validator is a dependent verifier and
weight relay. It cannot create a challenge, select or schedule an observation,
introduce another domain, provision an edge, supply evidence, re-score a
record, or replace any UID, hotkey, eligibility decision, or score.

The checkpoint contains a compact projection of every canonical score record:
UID, hotkey, eligibility status, canonical integer score, and record digest.
It also binds the exact canonical scoring policy digest, input-snapshot digest, report
digest, full canonical-report score-vector digest, compact checkpoint-vector digest,
central authority fingerprint, finalized height/hash/epoch, trust-policy
digest, sequence, validity window, and previous-checkpoint digest. The compact
projection is not an alternate score. Verification recreates it from the
canonical score report and requires byte-for-byte semantic equality.

The flow is deliberately one-way:

```text
central evidence -> canonical score report -> deterministic producer preparation
                                                    |
                                  purpose-bound one-shot signers
                                                    |
                              committed checkpoint + signatures
                                                    |
                    external verifier -> inert integer relay plan
                                             |
                      locked local ledger + bound WeightPlan preparation
                                             |
                        separate signer/executor gate (not invoked here)
```

Production and signing are separate implementations outside this public verifier.
They only create artifacts accepted by this unchanged verifier; they do not
acquire relay, wallet, submission, or publication authority.

## Key ceremony and signing boundary

`score_checkpoint_relay.py` contains Ed25519 **public-key verification only**.
The local trust policy pins the central authority fingerprint, canonical scoring policy,
network `finney`, netuid `24`, key IDs, exact public-key bytes and digests,
roles, purpose, threshold, validity intervals, revocation epochs, freshness
bounds, and append-gap bounds. Signer IDs and public keys are unique and
canonically ordered. Threshold success also has to cover every required role.

Relay signatures are produced outside this verifier process. The
purpose-restricted signer first signs its complete canonical request under a
separate one-shot authorization domain, then produces the relay projection by
signing this unchanged domain-separated message:

```text
miss.computer/misscomputer-subnet/central-score-checkpoint/v1/ed25519
NUL
<canonical complete checkpoint JSON without a trailing newline>
```

and returns a 64-byte signature. The envelope records only that external
signature, its key ID, the checkpoint digest, and the signed-message digest.
There is no private-key type, signing method, key path, secret reference,
wallet, or signer service in the relay component. Key generation, custody,
threshold authorization, rotation, and emergency revocation remain an
operator-controlled ceremony outside the verifier.

Revoked keys fail closed at the caller-supplied evaluation epoch. A key must
already be valid when the checkpoint is issued and remain valid through the
checkpoint expiry. A known key ID with another key's signature is not a valid
signer substitution: public-key verification fails.

## Publication boundary

The implementation defines bytes that may be published, but publishes nothing.
The central publication boundary is the canonical checkpoint plus its sorted
signature envelopes and the separately distributed canonical score report.
No URL, HTTP client, socket, transport retry, discovery mechanism, object-store
credential, provider-specific object-store setting, DNS setting, or service unit is present.

Publication must not imply activation. A consumer still needs an independently
pinned trust policy and a locally supplied, finalized metagraph view. Treat a
missing, malformed, stale, future, expired, under-threshold, revoked, forked,
or partially covered publication as unusable; do not fall back to a local
score or a previously rejected branch.

## External-validator verification algorithm

All time and chain context is explicit input. The core does not read a clock or
chain endpoint. For one verification attempt it performs these deterministic
steps:

1. Revalidate every frozen, `extra=forbid`, strict model and every canonical
   self/content digest.
2. Require the approved trust-policy digest and immutable network, netuid,
   central authority, and canonical scoring-policy identities.
3. Enforce the policy, checkpoint, and key validity windows using the supplied
   evaluation epoch, including maximum age, future skew, and lifetime.
4. Recreate the checkpoint score vector from the complete canonical score
   report. Require exact report, input snapshot, report score vector, record, and
   compact-vector bindings. There is no local score input.
5. Verify every supplied signature against the domain-separated complete
   checkpoint with its pinned Ed25519 public key. Reject unknown, swapped,
   invalid, future, expired, revoked, wrong-purpose, duplicate, or
   non-canonical signers. Enforce both unique-key threshold and required roles.
6. Validate the checkpoint against the prior append-only chain state.
7. Require the exact finalized metagraph height, block hash, epoch, external
   validator identity, and complete UID-to-hotkey miner mapping. The mapping
   must have no duplicates, omissions, extras, or churn relative to the score
   vector.
8. Normalize only the central canonical integer scores. policy-ineligible or
   zero-score miners receive exactly zero. Positive scores are projected into
   the existing u16 weight domain (`65,535` total) using integer division and
   largest remainders. Remainder ties are ordered by `(UID, hotkey)`. No float,
   random value, wall clock, or locally selected tie break participates.
9. Return a sealed verification report, sealed inert relay plan, and sealed
   next chain state. The relay plan binds the checkpoint, canonical report and input
   snapshot, metagraph, validator identity, verification input/report, next
   state, purpose, expiry, normalization algorithm, and complete integer weight
   vector.

The relay plan is evidence for a later preparation step. It is not a chain
transaction, signed weight plan, or authorization to submit weights.

## Append-only and anti-equivocation response

The caller supplies the last accepted state and persists nothing in Commit A.
Genesis accepts only sequence `1` with a null previous link. Later checkpoints
must have a strictly greater sequence, remain within the configured sequence
gap, link exactly to the last checkpoint digest, keep issued/evaluation epochs
monotonic, and keep finalized height and epoch monotonic. Finalized-height
advances are bounded.

At the same finalized height, the block hash, finalized epoch, canonical input
snapshot, report, report score vector, and compact vector must all remain identical.
A different block hash is a fork; different report material is equivocation.
Rollback, replay, a broken previous link, excessive forward gap, same-height
fork, or same-height divergence returns a stable sanitized rejection code and
does not produce a next state or relay plan.

Operational response is fail closed: retain the last independently verified
state, quarantine the conflicting artifacts outside this pure module, stop
relay preparation, and require operator resolution of the central publication
history. Never choose a branch by arrival order, signer count above threshold,
or a locally recomputed score.

## Pure core and local tooling boundary

`score_checkpoint_relay.py` contains only contracts, canonical encoders/parsers, public-key
verification, append validation, deterministic integer normalization, schemas,
fixtures, documentation, and pure tests. It intentionally does **not** contain:

- file-path handling, file reads, permission checks, ledger files, or a CLI;
- a private key, signing operation, validator wallet, RPC client, chain query,
  weight submission, cloud action, DNS action, or provisioning capability;
- integration with the existing `WeightPlan` writer, signer, executor, or live
  validator lifecycle.

`score_checkpoint_relay_cli.py` is the separate local-filesystem boundary. It
adds a descriptor-pinned canonical multi-file loader, one locked append-only
ledger, crash recovery, exclusive output creation, and exact conversion of
positive u16 entries into WeightPlan v1. The conversion divides each already
allocated u16 value by `65,535`; it does not run a second score or weight
normalizer. Zero and ineligible entries do not enter WeightPlan's positive
entry list. Every generated plan uses weight protocol `version_key` `2`, the
single version supported by the existing executor. This value is a stable
protocol discriminator, not a checkpoint identifier, nonce, or anti-replay
value. The signed checkpoint and canonical relay, plan, ledger, and preparation
digests retain instance uniqueness. A preparation manifest retains the
complete checkpoint, report, policy, metagraph, validator, ledger, finalized
height/hash, and WeightPlan bindings.

The CLI is still offline and non-submitting. It cannot fetch a publication,
read a clock or environment credential, load a private key or validator wallet,
query an RPC, sign a request, submit a weight, invoke the separately gated
signer/executor, change DNS/cloud state, or apply/activate a host or service.
See [`signed-score-checkpoint-relay-runbook.md`](signed-score-checkpoint-relay-runbook.md)
for the complete operator procedure, ledger continuity rules, backup/restore,
and fork/rollback response.

## Versioned contracts

The version-1 schemas and canonical fixtures cover:

- central score checkpoint;
- checkpoint trust policy and signature envelope;
- append-only checkpoint chain state;
- relay-specific finalized metagraph snapshot;
- external-validator verification input and report;
- external-validator integer score relay plan;
- canonical report parsing and digest parity across the published boundary.

They are generated by the central producer's contract generator outside this
repository; the committed copies must match its output byte-for-byte.
