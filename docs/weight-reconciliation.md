# Finalized RPC shadow and reconciliation runbook

This runbook is read-only. None of these commands loads a wallet, connects to
the signer socket, changes an audit ledger, installs a service, or submits
weights. Use two genuinely independent websocket providers; two hostnames
fronting the same upstream are correlated, not redundant. RPC endpoint values
must be credential-free `ws://` or `wss://` authorities without userinfo,
queries, or fragments.

## Shadow the next plan

Run the wallet-free executor without `--execute` under its dedicated account:

```bash
misscomputer-weight-executor \
  --plan /var/lib/misscomputer-subnet/plans/weight-plan.json \
  --subtensor-network finney \
  --rpc-endpoint wss://RPC_ONE.example.invalid \
  --rpc-endpoint wss://RPC_TWO.example.invalid \
  --rpc-max-finalized-lag 8 \
  --netuid 24 \
  --validator-hotkey VALIDATOR_SS58
```

The command opens neither audit ledger and cannot reach the signer. It succeeds
only when the providers agree on the exact metagraph at their newest common
finalized height. Record the plan digest, adjusted execution digest, block, and
target/moved/omitted counts. Alert JSON on stderr contains a stable code,
phase, RPC count, and public heights only.

## Inspect an uncertain attempt

Run the evidence tool as the OS account that owns the selected mode-0600
ledger. Inspect the executor and signer ledgers separately; agreement between
their reports is useful evidence but does not merge their histories.

```bash
misscomputer-weight-reconcile \
  --audit-state /var/lib/misscomputer-subnet/weight-executor/audit.json \
  --subtensor-network finney \
  --rpc-endpoint wss://RPC_ONE.example.invalid \
  --rpc-endpoint wss://RPC_TWO.example.invalid \
  --rpc-max-finalized-lag 8 \
  --netuid 24 \
  --validator-hotkey VALIDATOR_SS58
```

Pass `--attempt-id` to select a historical attempt; otherwise the newest
uncertain/post-boundary attempt is selected. The tool pins and revalidates the
existing audit path and reads the current validator row at an agreed finalized
height. It writes one canonical report to stdout:

- exit 0 means the durable ledger itself proves a pre-send failure, or already
  records a confirmed result;
- exit 3 means the result still needs operator reconciliation;
- exit 2 means configuration, ledger validation, or chain evidence failed.

For an ambiguous/in-progress/post-send failure, both a matching and a differing
current row remain exit 3. Matching weights may have existed before the attempt;
different weights may have overwritten a successful attempt later. Never turn
an exit-3 report into a retry by deleting, editing, copying over, or changing
the path of either ledger. Preserve both ledgers, the report bytes/digest,
supervisor logs, provider alerts, and any public extrinsic reference for the
incident review.

## Executor result versus audit/cleanup health

Executor exit 2 is an operational failure, **not** proof that no submission
occurred. Read the JSON `status` and `error_code` together:

- `submission_ambiguous` has `status: "ambiguous"`, including when recording
  that result failed. Reconcile before any further action.
- `submission_confirmed_audit_failed` has `status: "confirmed"`, the public
  `extrinsic_ref`, and `audit_error_code: "audit_persistence_failed"`. The
  signer confirmed the submission, but the executor cannot claim a durable
  final audit receipt. Preserve the reference and reconcile the ledgers.
- A definite chain rejection remains `submission_failed` / `rejected`, even
  when audit persistence separately fails. It still blocks automatic replay.

`audit_error_code` and optional `cleanup_error_codes` describe storage/resource
health independently of effect certainty. Cleanup diagnostics are
`submitter_cleanup_failed`, `audit_cleanup_failed`, and `chain_cleanup_failed`;
they never convert a confirmed/ambiguous result into definite rejection.
An otherwise confirmed execution may return exit 0 with cleanup diagnostics.

If the final write failed, the previous durable `in_progress` attempt with
`submission_started: true` may remain. This is intentionally replay-blocking;
do not clear it or infer that submission did not occur. A failed unlink may
also leave an owner-only temporary file. Preserve incident evidence and repair
the storage problem separately; the executor does not weaken inode checks or
retry writes after a potentially successful replacement.

## Alert policy

Page immediately on `rpc_finalized_rollback`, `rpc_snapshot_disagreement`,
`rpc_weight_mode_disagreement`, or `rpc_weight_row_disagreement`. Treat
availability and excessive-lag alerts as fail-closed service degradation. Do
not retry against only the surviving endpoint. Restore at least two independent
agreeing finalized views, rerun the shadow command, and investigate provider
correlation before rearming any one-shot timer.
