# Offline score-checkpoint verifier and relay runbook

## Security boundary

`misscomputer-score-checkpoint-relay` is an offline, one-attempt local tool.
It verifies a centrally published score checkpoint and prepares inert files for
later review. It does not download anything and it does not submit weights.

The central `miss.computer` operator remains the only challenge, domain,
provisioning, evidence, eligibility, and scoring authority. An external
validator supplies only independent trust anchors, explicit time, a finalized
UID/hotkey view, its relay identity, and local persistence. It must not replace
a missing central score, change eligibility, remap a UID or hotkey, or create
local challenge/evidence data.

The separately gated weight signer and one-shot executor are outside this
procedure. Successful CLI output is verification evidence, not authorization
to sign or submit. This tool never calls either component, opens a validator
wallet, contacts an RPC, or applies a service.

## Central out-of-band publication

The central publisher transfers these canonical newline-terminated files over
an operator-approved out-of-band channel:

1. score-checkpoint trust policy;
2. central score checkpoint;
3. every sorted Ed25519 signature envelope required by the policy;
4. the complete canonical score report;
5. the relay finalized-metagraph snapshot.

Publish the SHA-256 of the **complete file bytes** over an independent trusted
channel. The validator records one digest for every file and passes each exact
digest to the CLI. A digest copied from the same untrusted directory as the
file is not an out-of-band trust anchor. The trust policy's embedded digest,
central authority fingerprint, key roles, revocations, purpose, time bounds,
and threshold are checked again after the byte digest and canonical loader.

Do not add a URL, object-store credential, RPC endpoint, discovery setting, or
fallback score to this transfer. A partial publication is rejected; there is
no last-known-good publication fallback for a new relay attempt.

## Operator time and finalized identity

Obtain `--evaluation-epoch` from the validator's independently trusted time
procedure and record its source in the operations log. The CLI never reads the
host clock. The value is used for policy, key, revocation, checkpoint age,
future-skew, and expiry checks.

The explicit validator UID/hotkey must match the active, permitted validator in
the published relay metagraph. The metagraph height, block hash, finalized
epoch, complete miner mapping, and checkpoint must match exactly.

WeightPlan v1 also requires the subnet tempo and the complete finalized
metagraph identity fingerprint used by the separately gated executor. Supply
those as `--weight-plan-tempo` and
`--weight-plan-snapshot-identity-sha256` from the independent finalized-view
procedure. The resulting preparation manifest binds that WeightPlan to the
relay metagraph digest and exact finalized block hash. The later executor must
still match the complete live finalized snapshot before any submission gate.
The generated WeightPlan always uses protocol `version_key` `2`. Do not derive
or override it with checkpoint, relay, ledger, or snapshot hashes: those values
identify the plan instance through the signed and canonical digest bindings,
while `version_key` selects the executor-supported weight protocol.

## State root and trusted anchor

Choose a dedicated absolute normalized path for `--state-root`. Its parent must
already be root/operator-owned and not group/world writable. The CLI creates
the root as mode `0700`; it contains only:

- `ledger.lock` (mode `0600`);
- `head.json` and `anchor.json` (mode `0600`);
- contiguous mode-`0600` `record-00000000000000000001.json` files.

Use `--trusted-ledger-anchor genesis` only for a new ledger. After every
success, publish and retain `ledger_anchor_digest_sha256` from the preparation
manifest out of band. Pass that digest on the next attempt. The CLI permits an
anchor exactly one record behind only to finish or replay the same interrupted
commit; it will not append another checkpoint from a stale anchor.

Every record contains the complete verification input, public signatures,
verification report, relay plan, and WeightPlan. On every restart the CLI
re-verifies the Ed25519 signatures and state transition for every record. It
then requires contiguous record links, monotonic chain state, and redundant
head/anchor agreement.

The durable order is record, head, then anchor. Each file is built in a private
unnamed inode, fsynced, linked or renamed descriptor-relatively, and followed
by directory fsync. On Linux kernels that still require `CAP_DAC_READ_SEARCH`
for `linkat(AT_EMPTY_PATH)` (before 6.10), the unprivileged operator account
links that inode through `/proc/self/fd` instead; the installed name is always
re-identified by device and inode. Recovery advances at most one fully
canonical and fully reverified record. A valid interrupted head/anchor install
is completed by rename. Missing history, a larger forward gap, arbitrary temp
residue, extra files, symlinks, hard links, wrong owners/modes, noncanonical
JSON, tamper, or a future pointer fails closed. The tool never silently resets,
truncates, unlinks, or cleans ledger state.

## Invocation

All paths must be explicit, absolute, normalized, owner-confined, regular,
single-link files. Input files must be owner-only and readable; output parents
must already exist and be safe. Repeat `--signature` and
`--signature-sha256` in corresponding order. Signature file order does not
affect output bytes.

```text
misscomputer-score-checkpoint-relay \
  --trust-policy /secure/publication/trust-policy.json \
  --trust-policy-sha256 <file-sha256> \
  --checkpoint /secure/publication/checkpoint.json \
  --checkpoint-sha256 <file-sha256> \
  --signature /secure/publication/auditor-signature.json \
  --signature /secure/publication/issuer-signature.json \
  --signature-sha256 <auditor-file-sha256> \
  --signature-sha256 <issuer-file-sha256> \
  --score-report /secure/publication/score-report.json \
  --score-report-sha256 <file-sha256> \
  --metagraph /secure/publication/relay-metagraph.json \
  --metagraph-sha256 <file-sha256> \
  --evaluation-epoch <trusted-unix-epoch> \
  --validator-uid <uid> \
  --validator-hotkey <hotkey> \
  --state-root /secure/checkpoint-ledger \
  --trusted-ledger-anchor <genesis-or-last-anchor-digest> \
  --weight-plan-tempo <finalized-subnet-tempo> \
  --weight-plan-snapshot-identity-sha256 <full-snapshot-identity> \
  --verification-report-output /secure/out/verification.json \
  --relay-plan-output /secure/out/relay-plan.json \
  --weight-plan-output /secure/out/weight-plan.json \
  --preparation-output /secure/out/preparation.json
```

Exit `0` prints only `VERIFIED`. Exit `2` is a sanitized verification or
filesystem rejection, `64` is sanitized usage failure, `75` means another
process owns the ledger lock, and `70` is an internal failure. Errors never
echo argv, paths, JSON content, or exception text.

Outputs are linked into place exclusively as owner-only mode-`0600` files and
are never overwritten. An exact last-record replay may verify already-created
output bytes and create only missing outputs, which permits recovery after an
interrupted output sequence. Any different existing content, symlink, hard
link, unsafe mode/owner, or alias is rejected.

The four outputs are:

1. canonical external-validator verification report;
2. canonical complete-u16 relay plan (including zero entries);
3. canonical WeightPlan v1 containing positive entries only and fixed protocol
   `version_key` `2`;
4. canonical non-submission preparation manifest binding the WeightPlan to the
   checkpoint, canonical report/input/policy, metagraph, validator, verification,
   next chain state, ledger record/head/anchor, finalized height/hash, and exact
   u16 vector.

## Backup and restore

After a successful attempt, close the CLI and record the published anchor
digest. With no process holding `ledger.lock`, take an offline filesystem-level
copy of the complete state root. Preserve owner, mode `0700` on the root,
mode `0600` on every file, filenames, link counts, and bytes. Store the backup
and its anchor digest in independent protected locations. Do not copy a live
root while an append may be in progress.

Restore only into a newly provisioned safe parent. Restore the complete tree;
do not merge record subsets, omit the lock/pointers, renumber records, repair
permissions opportunistically, or delete residue. Before accepting another
checkpoint, pass the independently retained anchor digest. A restored tree
that is older than that anchor is a rollback and must remain quarantined.

If the most recent crash left one fully valid forward record or one exact
pointer install, invoke the CLI with the last trusted anchor and the same
publication. Let bounded recovery complete it. Do not manually rename, delete,
truncate, or rewrite ledger files.

## Fork, rollback, and equivocation response

On `same_height_fork`, `same_height_divergence`, sequence/height/epoch rollback,
previous-link mismatch, trusted-anchor mismatch, or ledger integrity failure:

1. stop relay preparation and do not run the signer or executor;
2. retain the state root and all received files unchanged;
3. record the last independently trusted anchor, evaluation epoch, and central
   publication digests;
4. quarantine conflicting material outside the state root without changing
   the ledger;
5. escalate to the central publication and validator security operators for an
   independently authenticated resolution.

Never choose a branch by arrival time, a larger signer count, a higher score,
or local rescoring. Never reset to genesis or restore an older backup to make a
conflict disappear. Resume only from an explicitly resolved publication whose
link extends the retained trusted ledger anchor.

## Explicit non-submission handoff

The preparation manifest sets `status` to `prepared_not_submitted` and
`submission_authorized` to `false`. Archive it with the verification report,
relay plan, WeightPlan, publication digests, evaluation-time record, and ledger
anchor. A later operator may provide the WeightPlan to the repository's
separately gated signer/executor workflow only after that workflow's own
identity, expiry, live finalized-metagraph, signing, audit, and submission
approvals. Nothing in this runbook authorizes that later action.
