# Third-party verifier and dry-run relay runbook

## Scope and security boundary

This is the public, generic route for an independent validator to consume the
frozen checkpoint-v1 artifacts. It composes existing boundaries; it does not
change any contract or introduce another scoring policy.

The verifier can:

- authenticate published `active-assignment-manifest` v2 publications against
  a validator-pinned Ed25519 trust policy;
- enforce finalized-height assignment leases before probing;
- archive the validator's own `organic-epoch-score` records and verify a
  central score checkpoint (over an `organic-central-score-report`) with
  `misscomputer-score-checkpoint-relay`;
- re-derive a sealed `validator-weight-decision` v2 from its embedded epochs
  and manifests (replaying every miner attestation), bind its terminal
  manifest to the currently verified live head, and deterministically create
  an inert WeightPlan;
- retain restart-safe manifest state and checkpoint-ledger anchors.

It cannot create a workload, domain, route, challenge, observation, score, or
eligibility decision. It has no central-authority signing key, operator control
credential, wallet, RPC submission client, service activation, DNS/cloud
capability, or direct weight-write operation. A WeightPlan is not authorization
to submit. Any later submission requires the repository's separately supplied,
isolated signer/executor boundary and its independent live-finality checks.

## Inputs and independent anchors

Obtain these through operator-approved public or out-of-band channels:

1. assignment-manifest trust policy and its independently recorded digest;
2. the current v2 manifest and its signature envelopes (`v2/manifests/`);
3. explicit trusted evaluation epoch and the validator's own finalized height;
4. the archived `organic-epoch-score` records of the window;
5. canonical score checkpoint publication, organic central score report,
   checkpoint trust policy, signatures, and complete finalized metagraph
   artifact;
6. canonical `validator-weight-decision` v2 and a complete independently
   finalized metagraph view, including block hash and tempo.

Never take a digest, time, finalized height, trust policy, or metagraph identity
from the same untrusted artifact it is meant to authenticate. Never put wallet,
private-key, provider, DNS, deployment, or central control settings in a
verifier configuration.

## Live-head procedure

The v2 publication has no latest-pointer/history walk yet (a documented gap in
`organic-availability-scoring.md`): the durable state must already reach the
head's predecessor, or be genesis for onboarding through
`anchor_organic_manifest_chain_state`. Call
`verify_organic_assignment_manifest` with the validator's own finalized
height; only after signature, freshness, identity, effective-expiry, lease,
append-only, rollback and same-height-fork checks may the returned
`next_chain_state` replace local state.

`verify_public_relay_path` is the SDK composition. It additionally requires the
lease-check height to equal the finalized metagraph block used for planning,
reparses the decision (replaying every embedded epoch against its embedded
manifests), requires its terminal identity to match the live head, and invokes
only `build_weight_plan_from_decision`.

```python
from misscomputer_subnet.public_verifier import verify_public_relay_path

result = verify_public_relay_path(
    trust_policy=assignment_policy,
    prior_chain_state=durable_state,
    head_manifest=head_manifest,
    head_signatures=head_signatures,
    evaluation_epoch=trusted_epoch,
    current_finalized_height=metagraph.block,
    decision=sealed_decision,
    retained_epoch_records=tuple(archived_epochs),
    finalized_metagraph=metagraph,        # complete, finalized, independently read
    finalized_block_hash=finalized_hash,
)
# result.weight_plan is prepared data, never a submission.
```

The retained epoch tuple is mandatory: every record is canonically reparsed
(`decision_epoch_records_invalid`) and their digests must equal the sealed
decision's epochs exactly (`decision_epoch_records_mismatch`). A probe nonce or
attestation signature reused across epochs is rejected
(`decision_probe_evidence_replayed`), and no epoch may end after the trusted
evaluation epoch. The trusted evaluation epoch must be within five seconds
(inclusive) of both window close and terminal evaluation.

Persist the verified head under the probe CLI lock before the next probe run:

```python
from misscomputer_subnet.assignment_probe_cli import persist_verified_manifest_head

persisted = persist_verified_manifest_head(
    state_root=state_root,
    trust_policy=assignment_policy,
    head_manifest=head_manifest,
    head_signatures=head_signatures,
    evaluation_epoch=trusted_epoch,
    current_finalized_height=metagraph.block,
    expected_anchor_sha256=durable_state.state_digest_sha256,
    expected_next_state_sha256=result.manifest_verification.next_chain_state.state_digest_sha256,
)
```

The handoff verifies the head again while holding `probe.lock`, compares the
starting anchor and the expected SDK result, atomically replaces `state.json`,
and makes concurrent probe runs fail `probe_busy`. Then run
`misscomputer-assignment-probe` with `--trusted-state-anchor` equal to the
persisted digest.

## Score-checkpoint cross-check

Run the offline `misscomputer-score-checkpoint-relay` procedure in
`signed-score-checkpoint-relay-runbook.md`. It authenticates the canonical score
report, authority, signatures, score bindings, finalized metagraph, append-only
checkpoint history, and deterministic complete-u16 relay vector. Its ledger is
restart-safe and its preparation explicitly says `submission_authorized:false`.

Cross-reference the two archives by finalized height/hash, miner UID/hotkey,
and the manifest/epoch evidence sealed in the weight decision. A mismatch is
not resolved by relabelling either artifact or recomputing a local score: stop
and retain both branches for review.

The score-checkpoint relay and the decision-aware WeightPlan are independent
fail-closed evidence paths. Passing one never waives a rejection in the other.
Where an operator requires both, compare their complete miner identities and
normalized result under an explicitly documented policy outside the verifier;
do not silently select whichever gives a preferred weight.

## Restart, backup, and rollback

Persist assignment `state.json` by the hardened assignment-probe CLI and retain
its digest out of band after each accepted transition. Persist score checkpoint
history only through its locked append-only ledger and retain the emitted
`ledger_anchor_digest_sha256`. Back up each state root while its CLI is stopped,
preserving owner, mode, link count, filenames, and bytes.

On restart:

1. verify the retained out-of-band state/ledger anchor;
2. reparse every canonical object and reverify signatures and digest links;
3. allow an exact last-head reprobe or the documented one-record interrupted
   checkpoint-ledger recovery only;
4. never reset to genesis, truncate records, rewrite pointers, or restore an
   older backup to make a conflict disappear.

A stale pointer, lower sequence/height/epoch, changed object at an accepted
sequence, same-height block-hash change, broken previous link, expired ticket or
block lease, policy relabel, report/evidence relabel, or old ledger anchor is a
hard stop. Keep the last independently anchored state and quarantine the new
public artifacts without modifying either.

## Upgrade and rollback compatibility

Checkpoint-v1 contract bytes are frozen. Upgrade verifier software only after:

1. running all Python and Go suites and the repository guards;
2. regenerating schemas/fixtures twice and proving byte equality both times;
3. proving the live-head/decision/WeightPlan path is deterministic;
4. taking stopped, byte-preserving backups of both state roots and anchors.

A software rollback is permitted only when the older binary accepts the exact
current v1 contracts and can reverify the current state and ledger without
migration. Never roll back persisted state. If a release cannot read the
current state, keep the newer verifier stopped and resolve compatibility
explicitly; do not re-anchor or reset merely to fit old software.

Current wire versions and validation rules are listed in `protocol.md`,
`organic-contracts.md`, and `organic-availability-scoring.md`. Historical
operator cutovers are not part of this public verifier runbook. Unknown schema
versions or fields fail closed.

## Synthetic proof

The executable proof is:

```text
python -m pytest -q \
  tests/python/test_public_verifier.py \
  tests/python/test_organic_scoring.py \
  tests/python/test_validator_decision.py \
  tests/python/test_score_checkpoint_relay.py \
  tests/python/test_score_checkpoint_relay_cli.py
```

It covers the deterministic end-to-end path and restart reprobe, threshold
signature verification, bounded history, stale/expired publications, block
lease expiry, fork/equivocation and broken links, finalized-height and policy
relabel attempts, canonical evidence re-derivation, checkpoint replay, and
non-submitting WeightPlan preparation.
