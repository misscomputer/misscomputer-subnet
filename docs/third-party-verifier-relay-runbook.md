# Third-party verifier and dry-run relay runbook

## Scope and security boundary

This is the public, generic route for an independent validator to consume the
frozen checkpoint-v1 artifacts. It composes existing boundaries; it does not
change any contract or introduce another scoring policy.

The verifier can:

- authenticate published active-assignment manifests and their immutable
  history against a validator-pinned Ed25519 trust policy;
- enforce finalized-height assignment leases before probing;
- archive public probe reports and verify a canonical score checkpoint with
  `misscomputer-score-checkpoint-relay`;
- re-derive a sealed `validator-weight-decision` from its embedded policy and
  evidence, bind its terminal manifest to the currently verified live head,
  and deterministically create an inert WeightPlan;
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
2. `v1/latest.json`, immutable manifest/pointer/signature objects, and exact
   object digests;
3. explicit trusted evaluation epoch and the validator's own finalized height;
4. archived validator probe reports;
5. canonical score checkpoint publication, score report, checkpoint trust
   policy, signatures, and complete finalized metagraph artifact;
6. canonical `validator-weight-decision` and a complete independently finalized
   metagraph view, including block hash and tempo.

Never take a digest, time, finalized height, trust policy, or metagraph identity
from the same untrusted artifact it is meant to authenticate. Never put wallet,
private-key, provider, DNS, deployment, or central control settings in a
verifier configuration.

## Assignment history and live-head procedure

Use `verify_manifest_latest_pointer` before fetching immutable objects. Its
`history_depth` is a strict traversal budget, not a claim that every integer
sequence exists.

- `reprobe=true`: fetch and verify the exact accepted head again; supply no
  history.
- `history_depth=0`: the head directly extends local state; supply no history.
- `history_depth>0`: walk immutable `previous_manifest_digest_sha256` links
  backward to the local accepted digest. Supply those entries in ascending
  sequence order to `replay_manifest_history`. Do not infer missing objects
  from unused integer sequence values.

Then bind the latest pointer to the exact manifest and envelope set and call
`verify_active_assignment_manifest` with the validator's own finalized height.
Only after successful signature, freshness, effective-expiry, lease,
append-only, rollback, and same-height-fork checks may the returned
`next_chain_state` replace local state.

`verify_public_relay_path` is the SDK composition of those steps. It limits a
single replay to 64 historical publications and additionally requires the
lease-check height to equal the finalized metagraph block used for planning.
It reparses the decision, requires its terminal identity and evidence to match
the live head, then invokes only `build_weight_plan_from_decision`.

```python
from misscomputer_subnet.public_verifier import verify_public_relay_path

result = verify_public_relay_path(
    trust_policy=assignment_policy,
    prior_chain_state=durable_state,
    latest_pointer=latest_pointer,
    history=history_entries,              # oldest to newest; empty on direct/reprobe
    head_manifest=head_manifest,
    head_signatures=head_signatures,
    evaluation_epoch=trusted_epoch,
    current_finalized_height=metagraph.block,
    decision=sealed_decision,
    retained_probe_reports=tuple(archived_probe_reports),
    finalized_metagraph=metagraph,        # complete, finalized, independently read
    finalized_block_hash=finalized_hash,
)
# Persist catch-up (if any) through the locked handoff below before probing.
# result.weight_plan is prepared data, never a submission.
```

The retained report tuple is mandatory: its canonical report digests must equal
the complete sealed decision evidence exactly. The verifier then rechecks every
credited miner attestation signature and its deployment, replica, endpoint,
challenge, body, and probe-nonce binding. It rejects reuse of a probe nonce or
signed attestation even when unsigned report timestamps, latency, or other
envelope metadata and all enclosing digests have been relabelled. The trusted
evaluation epoch must be within five seconds (inclusive) of both window close
and terminal evaluation; one second outside either boundary is rejected.

For an online serving check, use `misscomputer-assignment-probe` as documented
in `public-validator-live-probe-runbook.md`. Its locked `state.json` and
out-of-band state anchor provide the restart-safe implementation of the
manifest state transition. When SDK verification returns a caught-up state,
compare-bind and persist it under that same lock before invoking the probe CLI:

```python
from misscomputer_subnet.assignment_probe_cli import persist_assignment_manifest_catch_up

persisted = persist_assignment_manifest_catch_up(
    state_root=state_root,
    trust_policy=assignment_policy,
    history=history_entries,
    evaluation_epoch=trusted_epoch,
    expected_anchor_sha256=durable_state.state_digest_sha256,
    expected_next_state_sha256=result.manifest_verification.next_chain_state.state_digest_sha256,
)
assert persisted.state_digest_sha256 == result.manifest_verification.next_chain_state.state_digest_sha256
```

Only then run `misscomputer-assignment-probe` for the head with
`--trusted-state-anchor` equal to the persisted digest. The handoff replays and
authenticates every history object again while holding `probe.lock`, compares
the durable starting anchor and expected SDK result, atomically replaces
`state.json`, fsyncs file and directory, safely recovers a regular owner-only
`.state.install` left before rename, and makes concurrent probe/catch-up runs
fail `probe_busy`. Historical manifests are never probed.

## Score-checkpoint cross-check

Run the offline `misscomputer-score-checkpoint-relay` procedure in
`signed-score-checkpoint-relay-runbook.md`. It authenticates the canonical score
report, authority, signatures, score bindings, finalized metagraph, append-only
checkpoint history, and deterministic complete-u16 relay vector. Its ledger is
restart-safe and its preparation explicitly says `submission_authorized:false`.

Cross-reference the two archives by finalized height/hash, miner UID/hotkey,
and the manifest/report evidence sealed in the weight decision. A mismatch is
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
3. proving the synthetic catch-up/live-head/decision/WeightPlan path is
   deterministic;
4. taking stopped, byte-preserving backups of both state roots and anchors.

A software rollback is permitted only when the older binary accepts the exact
current v1 contracts and can reverify the current state and ledger without
migration. Never roll back persisted state. If a release cannot read the
current state, keep the newer verifier stopped and resolve compatibility
explicitly; do not re-anchor or reset merely to fit old software.

Declared compatibility events and coordinated cutovers are listed in
`contract-checkpoint-v1.md` and `api-migrations.md`. Unknown schema versions or
fields fail closed.

## Synthetic proof

The executable proof is:

```text
python -m pytest -q \
  tests/python/test_public_verifier.py \
  tests/python/test_manifest_publication.py \
  tests/python/test_validator_decision.py \
  tests/python/test_score_checkpoint_relay.py \
  tests/python/test_score_checkpoint_relay_cli.py
```

It covers deterministic end-to-end catch-up and restart reprobe, threshold
signature verification, bounded history, stale/expired publications, block
lease expiry, fork/equivocation and broken links, finalized-height and policy
relabel attempts, canonical evidence re-derivation, checkpoint replay, and
non-submitting WeightPlan preparation.
