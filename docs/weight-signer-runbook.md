# Weight signer runbook (independent validators)

`misscomputer-weight-signer` is the only command in this repository that loads
a validator hotkey to submit weights. It is a **one-shot** service: each run is
bound to one WeightPlan that you confirm by digest, serves exactly one request
from the wallet-free `misscomputer-weight-executor`, submits at most once, and
exits. Read [validator-quickstart.md](validator-quickstart.md) and
[weight-reconciliation.md](weight-reconciliation.md) first.

## Security boundary

```text
 executor OS user (no wallet)                  signer OS user (owns the hotkey)
 ────────────────────────────                  ─────────────────────────────────
 misscomputer-weight-executor --execute        misscomputer-weight-signer
   loads its own plan copy                       loads its own plan copy (digest-confirmed)
   finalized preflight + send check              its own finalized reads (RPC quorum)
   durable executor ledger                       durable signer ledger
        │  weight-signer-request v2 (one line) ─▶ peer UID must equal --executor-uid
        │                                        request must equal its own derivation
        │ ◀─ weight-signer-response v2 ────────  in-progress receipt, THEN wallet + client
                                                 zero-retry SDK SetWeights, one submission
```

What the signer enforces:

- **No arbitrary signing.** The socket accepts only the exact canonical
  weight-signer v2 request. The signer never submits request-supplied data: it
  reloads its own plan copy, derives the execution vector from its own
  finalized chain reads, and rejects the request unless the plan digest,
  network, netuid, validator, and the entire execution vector match. The
  derived execution digest must also equal the one you confirmed on the
  command line.
- **Peer and socket confinement.** The socket is bound under a private staging
  name, set to mode `0660` with the configured group, then published by hard
  link (the executor client waits while the link count is 2). The socket
  directory must be owned by the signer user without group write or any other
  access. Each connection's `SO_PEERCRED` UID must equal `--executor-uid`;
  other peers are dropped and counted (`signer_peer_rejected` alert on
  stderr). The signer refuses to run as root or as the executor's UID.
- **At most once.** The signer keeps its own weight-execution audit ledger
  (same format as the executor's, readable by `misscomputer-weight-reconcile`).
  It holds the ledger lock for its whole run, refuses to start when the plan
  already has a confirmed, ambiguous, in-progress, or post-send attempt, writes
  a durable `in_progress` receipt before it constructs the wallet or SDK
  client, and writes a durable `submission_started` marker before it calls the
  SDK. A crash after that marker leaves the plan permanently blocked until an
  operator reconciles it.
- **Fresh chain state.** The signer reads the finalized metagraph and weight
  mode twice: at admission, and again after the wallet is loaded. A rollback,
  a same-height identity change, a changed execution vector, or commit-reveal
  at either read ends the attempt as a pre-send failure.
- **One SDK submission.** `bt.SetWeights(...)` is executed with `retries=0`,
  `wait_for_inclusion=True`, `wait_for_finalization=True` over a pinned
  endpoint without transport fallbacks. The intent is wrapped so that a build
  that selects a timelocked commit-reveal extrinsic fails before any signing.

What it does not protect against: root on the host, the signer's own OS user,
or replacement of the installed package, unit, or configuration. It is
software isolation, not a hardware signer.

## Result classification

| SDK observation | Signer ledger | v2 response | Meaning |
| --- | --- | --- | --- |
| success with inclusion reference (`<block>-<index>`) | `confirmed` | `confirmed` + reference | Weights included and finalized |
| commit-reveal refused by the wrapped intent | `failed` / `definite_failure` | `rejected` `commit_reveal_unsupported` | Nothing was signed |
| included, dispatch failed | `failed` / `definite_failure` (reference kept) | `rejected` `chain_rejected` | Definitively not applied |
| failure without an inclusion reference (e.g. pool rejection) | `ambiguous` | `ambiguous` `submission_not_included` | Could have entered the pool; reconcile |
| success without a reference | `ambiguous` | `ambiguous` `missing_extrinsic_reference` | Reconcile |
| SDK exception (including SDK preflight errors such as rate limiting) | `ambiguous` | `ambiguous` `submission_exception` | Cannot prove the signing boundary; reconcile |
| no answer within `--submission-timeout` | `ambiguous` | `ambiguous` `submission_timeout` | Reconcile |

Failures before the `submission_started` marker (wallet unavailable, hotkey
mismatch, send-check change) are recorded as `pre_send_failure` and answered
`rejected`. Admission failures before the `in_progress` receipt (wrong request,
vector mismatch, unconfirmed execution digest, chain read failure, commit-reveal
at admission) are answered `rejected` and leave no signer ledger entry.

Every `rejected` or `ambiguous` answer is replay-blocking in the **executor**
ledger. Do not retry the same plan; reconcile, then use the next window's plan.

## One-time host setup (root)

Use two dedicated accounts and one shared socket group. Names below are
examples.

```bash
sudo groupadd --system mc-weight-socket
sudo useradd --system --create-home --home-dir /var/lib/misscomputer-weight-signer \
  --shell /usr/sbin/nologin --gid mc-weight-socket mc-weight-signer
sudo useradd --system --create-home --home-dir /var/lib/misscomputer-weight-executor \
  --shell /usr/sbin/nologin mc-weight-executor
sudo usermod -aG mc-weight-socket mc-weight-executor

sudo install -d -m 0700 -o mc-weight-signer -g mc-weight-socket \
  /var/lib/misscomputer-weight-signer/plans /var/lib/misscomputer-weight-signer/ledger
sudo install -d -m 0700 -o mc-weight-executor -g mc-weight-executor \
  /var/lib/misscomputer-weight-executor/plans /var/lib/misscomputer-weight-executor/ledger
```

The socket directory must be owned by the signer user, group
`mc-weight-socket`, mode `0750` (or `0710`). `/run` is cleared at boot, so
create it with a tmpfiles.d entry:

```bash
echo 'd /run/misscomputer-weight-signer 0750 mc-weight-signer mc-weight-socket -' |
  sudo tee /etc/tmpfiles.d/misscomputer-weight-signer.conf
sudo systemd-tmpfiles --create /etc/tmpfiles.d/misscomputer-weight-signer.conf
```

Install **only the hotkey** for the signer user (see
[keys-and-secrets.md](keys-and-secrets.md)); the executor user must not be
able to read it:

```bash
sudo install -d -m 0700 -o mc-weight-signer -g mc-weight-socket \
  /var/lib/misscomputer-weight-signer/wallets \
  /var/lib/misscomputer-weight-signer/wallets/<wallet-name> \
  /var/lib/misscomputer-weight-signer/wallets/<wallet-name>/hotkeys
sudo install -m 0600 -o mc-weight-signer -g mc-weight-socket \
  /path/to/hotkeys/<hotkey-name> /path/to/hotkeys/<hotkey-name>pub.txt \
  /var/lib/misscomputer-weight-signer/wallets/<wallet-name>/hotkeys/
```

Install the package somewhere both accounts can execute but neither can
modify (for example a root-owned virtual environment under `/opt`).

## Per-plan procedure

Every step uses values you read yourself; nothing is taken from the other
process.

1. **Preflight** the plan as the executor user (read-only; see
   [validator-quickstart.md](validator-quickstart.md#step-9-preflight-a-plan-read-only)).
   Record `plan_digest_sha256` and `execution_digest_sha256`.

2. **Copy the plan** for each account. The loaders require a regular
   single-link file owned by the running user with mode `0600`:

   ```bash
   sudo install -m 0600 -o mc-weight-executor -g mc-weight-executor \
     "$MC_BASE/plans/<window>.json" /var/lib/misscomputer-weight-executor/plans/<window>.json
   sudo install -m 0600 -o mc-weight-signer -g mc-weight-socket \
     "$MC_BASE/plans/<window>.json" /var/lib/misscomputer-weight-signer/plans/<window>.json
   ```

3. **Start the signer** (it waits up to `--accept-timeout` seconds, default
   900, for the executor):

   ```bash
   sudo -u mc-weight-signer /opt/misscomputer/bin/misscomputer-weight-signer \
     --plan /var/lib/misscomputer-weight-signer/plans/<window>.json \
     --audit-state /var/lib/misscomputer-weight-signer/ledger/audit.json \
     --socket /run/misscomputer-weight-signer/signer.sock \
     --socket-gid "$(getent group mc-weight-socket | cut -d: -f3)" \
     --executor-uid "$(id -u mc-weight-executor)" \
     --subtensor-network "$MC_NETWORK" --netuid "$MC_NETUID" \
     --validator-hotkey "$MC_HOTKEY_SS58" \
     --confirm-plan-digest '<plan_digest_sha256>' \
     --confirm-execution-digest '<execution_digest_sha256>' \
     --rpc-endpoint 'wss://<rpc-provider-one>' \
     --rpc-endpoint 'wss://<rpc-provider-two>' \
     --submit-endpoint 'wss://<rpc-provider-one>' \
     --wallet-name '<wallet-name>' --wallet-hotkey '<hotkey-name>' \
     --wallet-path /var/lib/misscomputer-weight-signer/wallets
   ```

4. **Run the executor** in a second shell. Give it a `--submission-timeout`
   at least the signer's `--submission-timeout` (default 150) plus the time
   for two finalized reads; 300 seconds is a reasonable start:

   ```bash
   sudo -u mc-weight-executor env \
     MISSCOMPUTER_WEIGHT_EXECUTION_ACK=I_ACKNOWLEDGE_THIS_SUBMITS_VALIDATOR_WEIGHTS \
     /opt/misscomputer/bin/misscomputer-weight-executor \
     --plan /var/lib/misscomputer-weight-executor/plans/<window>.json \
     --subtensor-network "$MC_NETWORK" --netuid "$MC_NETUID" \
     --rpc-endpoint 'wss://<rpc-provider-one>' \
     --rpc-endpoint 'wss://<rpc-provider-two>' \
     --validator-hotkey "$MC_HOTKEY_SS58" \
     --execute --confirm-network "$MC_NETWORK" --confirm-netuid "$MC_NETUID" \
     --confirm-plan-digest '<plan_digest_sha256>' \
     --confirm-execution-digest '<execution_digest_sha256>' \
     --audit-state /var/lib/misscomputer-weight-executor/ledger/audit.json \
     --submission-timeout 300 \
     --signer-socket /run/misscomputer-weight-signer/signer.sock \
     --signer-uid "$(id -u mc-weight-signer)"
   ```

5. **Read both results.** The signer and executor each print one JSON line.
   Both must report `confirmed` with the same `extrinsic_ref` and
   `execution_digest_sha256`.

If the chain moves between preflight and execution (a miner re-registers, a
UID changes), the derived execution digest changes and both processes refuse.
Re-run the preflight and start again with the new digest while the plan is
still unexpired.

## Signer output and exit codes

| Exit | Stream | Meaning |
| --- | --- | --- |
| `0` | stdout JSON, `"status":"confirmed"` | Submitted, finalized, and durably recorded |
| `2` | stderr JSON, `"status":"rejected"` | Nothing was submitted by this run (startup refusal, admission rejection, pre-send failure, or definite chain rejection) |
| `3` | stderr JSON `"status":"ambiguous"`, or stdout `"status":"confirmed"` with `audit_error_code` | Reconcile before any further action |

The result line carries `plan_digest_sha256`, `execution_digest_sha256`,
`request_id`, `attempt_id`, `extrinsic_ref`, `error_code`, and
`rejected_peer_count`, plus `audit_error_code`, `response_error_code`
(`response_delivery_failed` when the executor had already gone away), and
`cleanup_error_codes` when relevant. It never contains paths, key material,
or chain free text. RPC quorum alerts are the same stderr JSON alerts the
executor prints.

Common refusals:

| `error_code` | Action |
| --- | --- |
| `idempotency_blocked` | The signer ledger already has a blocking attempt for this plan. Reconcile it; never delete or edit the ledger |
| `plan_digest_confirmation_required` / `invalid_plan` | The signer's plan copy is not the confirmed plan, or not owner-only `0600` |
| `signer_socket_exists` | A socket from an earlier run remains. Confirm no signer is running, then remove the stale socket |
| `signer_socket_unsafe` | Fix owner/mode of the socket directory (signer-owned, `0750` or `0710`) |
| `signer_identity_unsafe` | The signer is running as root or as the executor UID |
| `request_timeout` | No authorized executor connected in time (check `--executor-uid` and group membership) |
| `execution_vector_mismatch` / `execution_digest_confirmation_required` | The executor's vector or your confirmation differs from the signer's own finalized derivation |
| `commit_reveal_unsupported` | The subnet uses commit-reveal; this signer does not submit timelocked commits |
| `pre_send_state_changed` | The finalized view changed between the signer's two reads |
| `signer_hotkey_mismatch` / `submission_unavailable` | Wrong `--wallet-*` values or unreadable hotkey |

## Reconciling an uncertain attempt

Run the read-only evidence tool as each ledger's owner, separately:

```bash
sudo -u mc-weight-signer /opt/misscomputer/bin/misscomputer-weight-reconcile \
  --audit-state /var/lib/misscomputer-weight-signer/ledger/audit.json \
  --subtensor-network "$MC_NETWORK" --netuid "$MC_NETUID" \
  --rpc-endpoint 'wss://<rpc-provider-one>' --rpc-endpoint 'wss://<rpc-provider-two>' \
  --validator-hotkey "$MC_HOTKEY_SS58"
```

The signer ledger is the authoritative record of what the signer did; the
executor ledger records what the executor observed. Follow
[weight-reconciliation.md](weight-reconciliation.md): preserve both ledgers,
both result lines, and any `extrinsic_ref`, and never delete, edit, or move a
ledger to make a retry possible.

Stopping the signer (Ctrl-C, `SIGTERM`, host crash) after it wrote
`submission_started` leaves that attempt `in_progress`; treat it as ambiguous.
Stopping it before that point cannot submit anything.

## Local proof (no chain, no wallet)

The signer's socket, peer-UID, ledger, and SDK-classification behavior is
exercised offline against the real executor client and the real SDK
`Client.execute`/`SetWeights` code with a transport double:

```bash
python -m pytest -q tests/python/test_weight_signer.py
```
