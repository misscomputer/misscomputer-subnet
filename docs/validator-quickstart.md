# Validator quickstart

This guide is for an **independent validator**: an operator with a registered
hotkey who wants to measure miners independently and prepare weights from
that evidence. Read [getting-started.md](getting-started.md) for installation
and [keys-and-secrets.md](keys-and-secrets.md) before handling keys.

## What a validator runs

Validation on this subnet is a pipeline of one-shot commands, not a single
daemon:

```text
every 5-minute epoch   misscomputer-assignment-probe
                         verify the signed active-assignment manifest
                         send hidden, signed probes to assigned miner endpoints
                         seal one organic-epoch-score record
                                   │
after each window      misscomputer-organic-window
(default 12 epochs)      re-verify epochs + terminal manifest against your finalized chain view
                         seal a validator-weight-decision (submit or abstain)
                         write a WeightPlan only for "submit"
                                   │
optional cross-check   misscomputer-score-checkpoint-relay
                         verify the operator's signed central score checkpoint offline
                                   │
before any submission  misscomputer-weight-executor   (no --execute: read-only preflight)
                         re-check the plan against the live finalized chain
```

None of these commands can create workloads, routes, or scores, and none of
them submits weights by itself. Background and scoring rules:
[public-validator-live-probe.md](public-validator-live-probe.md) and
[organic-availability-scoring.md](organic-availability-scoring.md).

### What this repository does not include

Be clear about these boundaries before you plan a deployment:

- **Weight submission signer.** `misscomputer-weight-executor --execute` sends
  the plan digest to a separately privileged signer over a peer-UID-pinned Unix
  socket. That signer service is not part of this repository. Without it you
  can run the full evidence pipeline and the read-only preflight, but this
  software will not set weights.
- **Validator control plane.** `misscomputer-validator` (the long-running
  neuron) is the bridge between an operator-owned Go control/scheduling
  service (`--go-control-url`, default `http://127.0.0.1:9201`) and the
  miners. That service is not in this repository, and without it the neuron
  never becomes ready. Independent validators do not need it for the pipeline
  above. See [the reference at the end](#reference-misscomputer-validator).
- **Publication inputs.** The manifest trust policy, its SHA-256 digest, and
  the manifest publication location come from the subnet operator through an
  operator-approved, out-of-band channel. They are not published here.

## Local versus live

| Step | Local only | Live network |
| --- | --- | --- |
| Install and synthetic end-to-end proof (below) | ✔ | |
| Seed generation, directory layout | ✔ | |
| Hotkey registration and staking | | ✔ transactions |
| `misscomputer-assignment-probe` | | ✔ fetches manifests, probes miners through the edge |
| `misscomputer-organic-window` | | ✔ reads the chain via RPC |
| `misscomputer-score-checkpoint-relay` | ✔ offline, given the published files | |
| `misscomputer-weight-executor` without `--execute` | | ✔ reads the chain only |

## Prerequisites

- Python 3.12 and this package installed ([getting-started.md](getting-started.md#install)).
  The Go toolchain and Docker are not needed.
- A hotkey **registered on the subnet**, with the stake needed for a validator
  permit. The window coordinator rejects a validator hotkey that is missing
  from its finalized view or not flagged `active` there
  (`validator_not_registered`), and the edge verifies validator membership
  before it accepts a probe.
- **Accurate time.** The probe schedules requests from the host clock; run
  NTP or equivalent.
- **Your own chain view.** A finalized block height for every probe run, and
  RPC access for the window coordinator and executor. For the executor, use
  two genuinely independent `ws://` or `wss://` providers (see
  [weight-reconciliation.md](weight-reconciliation.md)).
- The **trust policy file**, its **independently obtained SHA-256**, and the
  **manifest publication location** from the subnet operator.

## Step 0: prove the pipeline locally (no network)

This is the repository's synthetic end-to-end proof of the verifier path
(probe records, decisions, checkpoint relay, WeightPlan preparation):

```bash
python -m pip install -e '.[dev]'
python -m pytest -q \
  tests/python/test_public_verifier.py \
  tests/python/test_organic_scoring.py \
  tests/python/test_validator_decision.py \
  tests/python/test_score_checkpoint_relay.py \
  tests/python/test_score_checkpoint_relay_cli.py
```

All tests should pass.

## Step 1: register (live transactions)

```bash
btcli subnets register --netuid '<NETUID>' --network finney \
  --wallet-name '<wallet-name>' --hotkey '<hotkey-name>'
```

Add stake per your own policy with `btcli`, then confirm with the
[read-only chain check](getting-started.md#read-only-chain-check) that your
hotkey shows `active=True` and `validator_permit=True`. Copy only the hotkey
to the server.

## Step 2: set variables and create the layout

```bash
export MC_NETWORK=finney
export MC_NETUID='<NETUID>'
export MC_WALLET='<wallet-name>'
export MC_HOTKEY='<hotkey-name>'
export MC_HOTKEY_SS58='<hotkey-ss58-address>'
export MC_BASE=/srv/misscomputer-validator
```

Create the directories as the account that will run the CLIs. The base path
must not contain names such as `secrets` or `wallets` (see
[validator input paths](keys-and-secrets.md#validator-input-paths)), and
every parent must be owned by root or you and not group/world-writable:

```bash
sudo install -d -m 0755 -o root -g root "$MC_BASE"
sudo install -d -m 0700 -o "$(id -un)" -g "$(id -gn)" \
  "$MC_BASE/probe" "$MC_BASE/epochs" "$MC_BASE/manifests" \
  "$MC_BASE/decisions" "$MC_BASE/plans"
```

Do **not** create `$MC_BASE/probe-state`; the probe CLI creates it (mode
`0700`) on its first run.

## Step 3: probe seed

Generate a private 32-byte seed once. Anyone holding it can predict your probe
schedule; never publish it or share it with another validator:

```bash
(umask 077; head -c 32 /dev/urandom > "$MC_BASE/probe/seed.bin")
export MC_SEED_SHA256=$(sha256sum "$MC_BASE/probe/seed.bin" | awk '{print $1}')
```

## Step 4: install the trust policy

Place the policy you received out of band and check it against the digest you
obtained from an independent trusted channel. Never take the digest from the
same place as the file:

```bash
install -m 0600 /path/to/received/trust-policy.json "$MC_BASE/probe/trust-policy.json"
export MC_POLICY_SHA256='<independently-obtained-sha256>'
echo "$MC_POLICY_SHA256  $MC_BASE/probe/trust-policy.json" | sha256sum -c -
```

Expected: `.../trust-policy.json: OK`.

Record the manifest publication location you were given. The examples below
use the URL form described in the
[probe runbook](public-validator-live-probe-runbook.md#manifest-publication);
local files with `--manifest-file`/`--manifest-sha256` and
`--signature-file`/`--signature-sha256` work the same way.

```bash
export MC_MANIFEST_URL='https://<publication-host>/v2/manifests/<digest>.json'
export MC_SIG_URL_1='https://<publication-host>/v2/manifests/<digest>.auditor.signature.json'
export MC_SIG_URL_2='https://<publication-host>/v2/manifests/<digest>.issuer.signature.json'
```

## Step 5: first probe run (live)

Epochs are 300 seconds: `epoch = floor(unix_time / 300)`. The CLI probes one
epoch per invocation and stays running while it sends that epoch's scheduled
probes (up to about five minutes), so start it at an epoch boundary. Scheduled
instants that already passed by more than 10 seconds are skipped, not sent
late, and an epoch that has already ended is refused.

Take your finalized height from your own node or RPC (for example the
`block` value printed by the
[read-only chain check](getting-started.md#read-only-chain-check) when it
reports `finalized=True`):

```bash
export MC_FINALIZED_HEIGHT='<validator-finalized-block-height>'
EPOCH=$(( $(date +%s) / 300 ))

misscomputer-assignment-probe \
  --trust-policy "$MC_BASE/probe/trust-policy.json" \
  --trust-policy-sha256 "$MC_POLICY_SHA256" \
  --manifest-url "$MC_MANIFEST_URL" \
  --signature-url "$MC_SIG_URL_1" \
  --signature-url "$MC_SIG_URL_2" \
  --probe-seed-file "$MC_BASE/probe/seed.bin" \
  --probe-seed-sha256 "$MC_SEED_SHA256" \
  --epoch-index "$EPOCH" \
  --finalized-height "$MC_FINALIZED_HEIGHT" \
  --validator-hotkey "$MC_HOTKEY_SS58" \
  --wallet-name "$MC_WALLET" --wallet-hotkey "$MC_HOTKEY" \
  --state-root "$MC_BASE/probe-state" \
  --trusted-state-anchor genesis \
  --epoch-output "$MC_BASE/epochs/$EPOCH.json" \
  --manifest-archive-dir "$MC_BASE/manifests"
```

Use `--trusted-state-anchor genesis` only for this first run on an empty
state root. Expected result:

| Exit | Output | Meaning |
| --- | --- | --- |
| `0` | stdout `PROBED status=scored epoch=<n> endpoints=<n> observations=<n> skipped=<n> next_state_sha256=<digest>` | Epoch scored and record written |
| `3` | same `PROBED` line with another status | Record written but not scored (common-mode outage or no eligible endpoint) |
| `2` | stderr `REJECTED <code>` | Rejected; nothing written. See [troubleshooting](troubleshooting.md#validator) |
| `64` | stderr `REJECTED usage` | Bad or missing flags |
| `75` | stderr `REJECTED probe_busy` | Another run holds the state lock |
| `70` | stderr `ERROR internal_error` | Internal failure |

Keep the printed `next_state_sha256`; it is the anchor for the next run.

## Step 6: run every epoch

Schedule one run at the start of every epoch (a timer every 5 minutes aligned
to the clock). For each subsequent run pass the digest printed by the
previous successful run:

```bash
--trusted-state-anchor <next_state_sha256 from the previous run>
```

Retain that digest outside the state root, like a checkpoint. The runbook also
describes `current`, which trusts the on-disk state as-is; use it only where
local tampering is outside your threat model. Refresh
`--finalized-height` and, when the operator publishes a new manifest, the
manifest and signature locations on every run. Re-probing the same
last-accepted manifest is normal and leaves the state unchanged.

Full flag, state, and failure semantics:
[public-validator-live-probe-runbook.md](public-validator-live-probe-runbook.md).

## Step 7: close each window

After a window closes, and within 600 seconds of its close, seal the decision.
The window is `[end - epochs*300, end)` with `end = window_end_epoch_index * 300`,
so running at the start of epoch `E` with `--window-end-epoch-index E` covers
the preceding `--window-epochs` epochs (default 12, i.e. one hour). A window
with fewer than `--min-scored-epochs` (default 6) scored epochs seals an
abstain decision:

```bash
END=$(( $(date +%s) / 300 ))

misscomputer-organic-window \
  --trust-policy "$MC_BASE/probe/trust-policy.json" \
  --trust-policy-sha256 "$MC_POLICY_SHA256" \
  --manifest-url "$MC_MANIFEST_URL" \
  --signature-url "$MC_SIG_URL_1" \
  --signature-url "$MC_SIG_URL_2" \
  --probe-state-root "$MC_BASE/probe-state" \
  --epoch-dir "$MC_BASE/epochs" \
  --manifest-archive-dir "$MC_BASE/manifests" \
  --window-end-epoch-index "$END" \
  --validator-hotkey "$MC_HOTKEY_SS58" \
  --subtensor-network "$MC_NETWORK" \
  --netuid "$MC_NETUID" \
  --rpc-endpoint 'wss://<your-rpc-endpoint>' \
  --decision-output "$MC_BASE/decisions/$END.json" \
  --weight-plan-output "$MC_BASE/plans/$END.json"
```

`--rpc-endpoint` is optional; without it the SDK's endpoint for
`--subtensor-network` is used. The coordinator never takes the probe lock, so
it can run alongside the next epoch's probe.

| Exit | Output | Meaning |
| --- | --- | --- |
| `0` | stdout `WINDOW decision=submit reasons=none scored_epochs=<n> plan=written decision_sha256=<digest>` | Decision and WeightPlan written |
| `3` | stdout `WINDOW decision=abstain reasons=<codes> ... plan=none ...` | Decision written, no plan |
| `2` | stderr `REJECTED <code>` | Nothing written (window not closed, over 600 s late, inconsistent evidence, unregistered validator, ...) |
| `64` / `70` | `REJECTED usage` / `ERROR internal_error` | Usage or internal failure |

## Step 8 (optional): cross-check the central score checkpoint

If the operator publishes a signed score checkpoint for the same period, verify
it offline with `misscomputer-score-checkpoint-relay`. It prints only
`VERIFIED` on success and never submits anything. Procedure:
[signed-score-checkpoint-relay-runbook.md](signed-score-checkpoint-relay-runbook.md),
and how the two evidence paths relate:
[third-party-verifier-relay-runbook.md](third-party-verifier-relay-runbook.md).

## Step 9: preflight a plan (read-only)

Before anything is submitted, check the written plan against the live
finalized chain. Without `--execute` the executor loads no wallet, opens no
audit ledger, and cannot reach a signer:

```bash
misscomputer-weight-executor \
  --plan "$MC_BASE/plans/<window>.json" \
  --subtensor-network "$MC_NETWORK" \
  --netuid "$MC_NETUID" \
  --rpc-endpoint 'wss://<rpc-provider-one>' \
  --rpc-endpoint 'wss://<rpc-provider-two>' \
  --validator-hotkey "$MC_HOTKEY_SS58"
```

Pass either no `--rpc-endpoint` or at least two independent ones. Success
prints one JSON line with `"mode":"dry-run"` and `"status":"validated"`, plus
the plan digest, the adjusted execution digest, the block, and
target/moved/omitted counts. A failure exits `2` with a JSON error on stderr
(`error_code`, `status`).

Submitting (`--execute`) additionally requires exact network, netuid, plan
digest, and execution digest confirmations, an explicit environment
acknowledgement, a durable `--audit-state` path, and the external signer
(`--signer-socket`, `--signer-uid`). Treat an exit `2` after `--execute` as
"unknown", never as "not submitted": follow
[weight-reconciliation.md](weight-reconciliation.md) before any retry.

## Health, logs, and outputs

- Every CLI reports through its exit status and one stdout/stderr line;
  errors are stable codes and never echo paths, arguments, or file contents.
  Have your scheduler record exit status and output for every run.
- Outputs (epoch records, decisions, plans) are created exclusively as
  owner-only files and are never overwritten. An existing output path is a
  rejection, so give each run a fresh file name (the examples use the epoch
  index).
- State you must keep: `probe-state/` (with its last digest), `manifests/`,
  `epochs/`, decisions, and plans. Back them up while no run is active.
- On any fork, rollback, or equivocation rejection (`sequence_rollback`,
  `same_sequence_divergence`, `previous_link_mismatch`, `same_height_fork`,
  `finalized_height_rollback`, ...): stop, keep everything unchanged, and
  follow the
  [fork and rollback response](public-validator-live-probe-runbook.md#fork-rollback-and-equivocation-response).
  Never reset the state root to `genesis` to make an error disappear.

## Reference: `misscomputer-validator`

The long-running neuron is used together with the operator-owned Go control
service described above. It serves a loopback-only HTTP bridge (it refuses a
non-loopback `--bridge-host`), discovers miners from the metagraph, performs
the pinned-TLS capability handshake, and forwards signed assignment traffic.
It never prepares or submits weights; the old weight flags
(`--enable-weight-submission`, `--weight-plan-path`, `--weight-interval`,
`--version-key`) are rejected at startup.

| Flag | Default |
| --- | --- |
| `--netuid` | required |
| `--subtensor-network` | `$BT_NETWORK` or `finney` |
| `--rpc-endpoint` (repeatable) | none; give none or at least two |
| `--rpc-max-finalized-lag` | `8` |
| `--wallet-name` / `--wallet-hotkey` / `--wallet-path` | as for the miner |
| `--bridge-host` / `--bridge-port` | `127.0.0.1` / `9200` |
| `--go-control-url` | `http://127.0.0.1:9201` |
| `--bridge-secret-file` / `--state-db` | required |
| `--sync-interval` | `12.0` |
| `--dendrite-timeout` / `--dendrite-retries` | `130.0` / `1` |
| `--discovery-concurrency` / `--discovery-max-attempts-per-refresh` | `16` / `64` |
| `--discovery-attempt-timeout` / `--discovery-refresh-timeout` | `10.0` / `30.0` seconds |
| `--discovery-backoff-base-rounds` / `--discovery-backoff-max-rounds` | `1` / `16` |

`GET /healthz` on the bridge returns `204` after a complete block
synchronization (chain view, control-plane capability exchange, miner
discovery, and snapshot publication) and `503` otherwise. Logs are JSON lines;
look for `validator block synchronized` and, on failure,
`validator block loop failed` with its exception.
