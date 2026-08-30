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

## Alert policy

Page immediately on `rpc_finalized_rollback`, `rpc_snapshot_disagreement`,
`rpc_weight_mode_disagreement`, or `rpc_weight_row_disagreement`. Treat
availability and excessive-lag alerts as fail-closed service degradation. Do
not retry against only the surviving endpoint. Restore at least two independent
agreeing finalized views, rerun the shadow command, and investigate provider
correlation before rearming any one-shot timer.
