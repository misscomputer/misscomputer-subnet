# Public-validator live probe runbook

## Security boundary

`misscomputer-assignment-probe` runs one five-minute epoch of hidden probes of
organic app assignments per invocation. It verifies the centrally published
`active-assignment-manifest` v2, sends one signed, bounded HTTPS request at each
privately scheduled instant, and archives one canonical `organic-epoch-score`
record. It does not choose or provision workloads, create domains, activate
routes, or submit weights, and it has no RPC, cloud, DNS, or activation
capability. Its only signing capability is the validator hotkey facade method
that signs `organic-probe-authorization` messages and refuses anything else.

Nothing is contacted unless the operator supplies the manifest source and runs
the command. Run it from a timer at each epoch start (for example
`epoch = floor(unix_time / 300)`).

Design, contracts, and scoring rules are in
[`public-validator-live-probe.md`](public-validator-live-probe.md) and
[`organic-availability-scoring.md`](organic-availability-scoring.md).

## Trust policy and out-of-band digest

Obtain `assignment-manifest-trust-policy` from an operator-approved out-of-band
channel and record the SHA-256 of the complete file bytes from an independent
trusted channel. The policy pins the central manifest signing keys, threshold
and roles, freshness and append bounds, allow-listed route-host suffixes, probe
timeout, response byte ceiling, and optional edge leaf-certificate pins. Pass
the file and the digest as `--trust-policy` / `--trust-policy-sha256`; the
policy is reloaded through the descriptor-pinned owner-only loader and its
embedded digest is checked again after the byte digest.

The trust policy is validator-local. The central authority cannot widen a
validator's route-host allow-list, byte ceiling, timeout, or key set by
publishing a manifest; a manifest that references a different trust-policy
digest is rejected.

## Manifest publication

The central publisher exposes the canonical newline-terminated manifest and
every sorted signature envelope. Provide them either as local owner-only files
with their out-of-band SHA-256 (`--manifest-file`/`--manifest-sha256`,
`--signature-file`/`--signature-sha256`, repeated in corresponding order) or as
explicit HTTPS URLs (`--manifest-url`, `--signature-url`, repeated). URL fetches
use the same TLS policy as the probes, follow no redirects, use no environment
proxies, accept only status 200, and stop at 16 MiB for the manifest and 16 KiB
per envelope. A fetched manifest is authenticated only by its signature
envelopes and the pinned policy; the transport is not a trust anchor.

## Operator time, identity, seed, and wallet

The CLI reads the host clock for the epoch schedule and for manifest freshness
at the start instant; run it on a host with disciplined time.
`--epoch-index` names the epoch to probe; an epoch that already ended is
refused (`epoch_already_elapsed`). `--finalized-height` is the validator's own
finalized chain height; every replica's `expires_at_block` is enforced against
it before any request (`manifest_replica_lease_expired`).

`--probe-seed-file`/`--probe-seed-sha256` name a 32-byte seed generated once
with a CSPRNG (for example `head -c 32 /dev/urandom`) and kept private and
owner-only. Anyone holding it can predict the schedule, so never publish or
reuse it across validators; rotate it like a key.

`--validator-hotkey` must equal the hotkey of the wallet named by
`--wallet-name`/`--wallet-hotkey`/`--wallet-path`
(`wallet_hotkey_mismatch` otherwise). The edge verifies that hotkey's sr25519
signature and the validator's membership.

## State root and anchor

Choose a dedicated absolute normalized `--state-root`. Its parent must be
root/operator-owned and not group/world writable. The CLI creates the root as
mode `0700`; it contains only `probe.lock` and the canonical mode-`0600`
`state.json` (`assignment-manifest-chain-state`). A nonblocking exclusive lock
serializes concurrent runs (`probe_busy`, exit `75`).

`--trusted-state-anchor` selects how the local acceptance state is trusted:

- `genesis` only for a new, empty root;
- `<state-digest>` to require the on-disk state to match the digest printed by
  the previous successful run (recommended for scripted operation; retain it
  out of band like the checkpoint-relay anchor);
- `current` to accept the on-disk state as-is (the root is owner-only; use
  this only where local tampering is outside the threat model).

`genesis` onboards on the current v2 head at any sequence. The state advances
only when a new manifest sequence is accepted. Re-probing the exact
last-accepted manifest is expected and leaves the state unchanged. A lower sequence, a different manifest
at the same sequence, a broken previous link, a finalized-height rollback or
fork, a finalized-epoch rollback, or an issue-time rollback is rejected before
any request is sent, and the state file is not modified.

## Invocation

```text
misscomputer-assignment-probe \
  --trust-policy /secure/probe/trust-policy.json \
  --trust-policy-sha256 <file-sha256> \
  --manifest-url https://<publication-host>/v2/manifests/<digest>.json \
  --signature-url https://<publication-host>/v2/manifests/<digest>.auditor.signature.json \
  --signature-url https://<publication-host>/v2/manifests/<digest>.issuer.signature.json \
  --probe-seed-file /secure/probe/seed.bin --probe-seed-sha256 <seed-sha256> \
  --epoch-index <floor(unix/300)> \
  --finalized-height <validator-finalized-block-height> \
  --validator-hotkey <ss58> \
  --wallet-name <name> --wallet-hotkey <hotkey> [--wallet-path ~/.bittensor/wallets] \
  --state-root /secure/probe-state \
  --trusted-state-anchor <genesis-or-last-state-digest> \
  --epoch-output /secure/probe-epochs/<epoch>.json \
  --manifest-archive-dir /secure/probe-manifests
```

`--manifest-archive-dir` (owner-only, not group/world writable) receives
`<manifest-digest>.json` for every manifest the run verified, before the
state advances. An existing entry must hold identical bytes
(`manifest_archive_conflict`); the window coordinator replays epochs from it.

`--edge-origin https://<host>[:port]` sends every probe to one explicit edge
origin with the route host as SNI and `Host`; `--tls-ca-file` replaces the
system trust store with one public PEM bundle. Local files use
`--manifest-file`/`--manifest-sha256` and `--signature-file`/`--signature-sha256`.

## Exit statuses and output

- `0` — the epoch was scored; stdout prints `PROBED status=scored epoch=<n>
  endpoints=<n> observations=<n> skipped=<n> next_state_sha256=<digest>`.
- `3` — the record was written but the epoch is `common_mode_unavailable` or
  has no eligible endpoint.
- `2` — sanitized rejection (`REJECTED <code>` on stderr); no record written.
- `64` usage, `75` busy, `70` internal.

The record is installed exclusively as an owner-only file and never
overwritten. Its observations carry the attestation of every verified or
fraudulent response, so anyone holding the public manifests can replay it with
`organic_scoring.replay_organic_epoch_score`.

## Window close: `misscomputer-organic-window`

Run once within 600 s after each scoring window closes (the window is
`[end - epochs*300, end)` with `end = window_end_epoch_index * 300`):

```text
misscomputer-organic-window \
  --trust-policy /secure/probe/trust-policy.json --trust-policy-sha256 <file-sha256> \
  --manifest-url https://<publication-host>/v2/manifests/<digest>.json \
  --signature-url https://<publication-host>/v2/manifests/<digest>.auditor.signature.json \
  --signature-url https://<publication-host>/v2/manifests/<digest>.issuer.signature.json \
  --probe-state-root /secure/probe-state \
  --epoch-dir /secure/probe-epochs \
  --manifest-archive-dir /secure/probe-manifests \
  --window-end-epoch-index <floor(unix/300)> [--window-epochs 12] [--min-scored-epochs 6] \
  --validator-hotkey <ss58> \
  [--rpc-endpoint wss://<your-rpc>] \
  --decision-output /secure/decisions/<window>.json \
  --weight-plan-output /secure/plans/<window>.json
```

1. It reads the metagraph at the finalized head and that head's block hash
   from the validator's own RPC and derives the registered miner set exactly
   as the weight plan will require it.
2. It parses every `*.json` in `--epoch-dir`: a malformed, foreign, or
   duplicated record refuses the window (no curation by omission). It loads
   each probed manifest from the archive by digest.
3. It fetches the terminal manifest and verifies it live against the probe
   state (read without the probe lock, never written): it must be the
   probe's last accepted head or its direct successor. Unreachable is
   `terminal_manifest_unavailable`, unverifiable is
   `terminal_manifest_rejected`; both are sealed abstain decisions.
4. It seals `validator-weight-decision` v2 and writes it; only a `submit`
   decision also produces the `WeightPlan`. Both files are created
   exclusively (owner-only, never overwritten).

Exit status: `0` submit (plan written), `3` abstain (decision only), `2`
rejected (nothing written: window not closed or over 600 s late, unsafe or
inconsistent evidence, missing archive entry, unregistered validator, missing
probe state), `64` usage, `70` internal. Hand only a written plan to the
separately gated `misscomputer-weight-executor`, which re-checks it against
the live chain.

## Fork, rollback, and equivocation response

On `sequence_rollback`, `same_sequence_divergence`, `previous_link_mismatch`,
`same_height_fork`, `finalized_height_rollback`, `finalized_epoch_rollback`,
`issued_at_rollback`, or a state-anchor mismatch:

1. stop; do not reset the state root to genesis to make the error disappear;
2. retain the state root, the received manifest, and its envelopes unchanged;
3. record the evaluation epoch, the last printed state digest, and the
   publication digests;
4. escalate to the central publication operators for an independently
   authenticated resolution.

Never choose a manifest by arrival order or by which one probes "better".
