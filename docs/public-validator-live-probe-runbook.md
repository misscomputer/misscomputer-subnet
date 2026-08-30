# Public-validator live probe runbook

## Security boundary

`misscomputer-assignment-probe` is an online, one-attempt local tool. It
verifies a centrally published active-assignment manifest, performs exactly one
bounded HTTPS request per published deployment route, and archives one
canonical probe report. It does not choose or provision workloads, create
domains, activate routes, rescore miners, or submit weights, and it has no
wallet, private key, RPC, signer, cloud, DNS, or activation capability.

The tool is inert by default: nothing is contacted unless the operator
supplies the manifest source (`--manifest-file` or `--manifest-url` plus the
signature envelopes) and runs the command. The Miss Computer edge is reached
only for the published routes, one request each, with the byte and time bounds
pinned in the local trust policy.

Design, contracts, and verification rules are in
[`public-validator-live-probe.md`](public-validator-live-probe.md).

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

## Operator time and identity

Obtain `--evaluation-epoch` from the validator's trusted time procedure
(`date -u +%s` on a host with disciplined time is acceptable; record its
source). The CLI never reads the host clock for verification. `--validator-uid`
and `--validator-hotkey` only label the report; they authorize nothing.

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

The state advances only when a new manifest sequence is accepted. Re-probing
the exact last-accepted manifest is expected and leaves the state unchanged
(`manifest_reprobe:true` in the report). A lower sequence, a different manifest
at the same sequence, a broken previous link, a finalized-height rollback or
fork, or an issue-time rollback is rejected before any request is sent, and
the state file is not modified.

## Invocation

```text
misscomputer-assignment-probe \
  --trust-policy /secure/probe/trust-policy.json \
  --trust-policy-sha256 <file-sha256> \
  --manifest-url https://<publication-host>/assignments/manifest.json \
  --signature-url https://<publication-host>/assignments/auditor.json \
  --signature-url https://<publication-host>/assignments/issuer.json \
  --evaluation-epoch <trusted-unix-epoch> \
  --validator-uid <uid> \
  --validator-hotkey <hotkey> \
  --state-root /secure/probe-state \
  --trusted-state-anchor <genesis-or-last-state-digest> \
  --report-output /secure/probe-reports/<epoch>.json
```

Optional flags:

- `--edge-origin https://<host>[:port]` sends every probe to one explicit
  origin with the published route host as SNI and `Host` (the central
  `https://{host}` template). Certificate hostname verification still uses the
  route host. Without it the probe connects to
  `https://<route_host>:<probe_port>` directly.
- `--tls-ca-file <bundle.pem>` replaces the system trust store with one
  explicit PEM bundle (public certificates only; a bundle containing private
  key material is rejected).

Local file sources use `--manifest-file`/`--manifest-sha256` and
`--signature-file`/`--signature-sha256`; file and URL signature sources may be
mixed.

## Exit statuses and output

- `0` — every published deployment was `serving`; stdout prints
  `PROBED status=serving deployments=<n> serving=<n> failed=0 next_state_sha256=<digest>`.
- `3` — the manifest verified and the report was written, but at least one
  deployment failed; stdout prints the same line with `status=degraded`.
- `2` — sanitized rejection before probing (`REJECTED <code>` on stderr): a
  stale, future, expired, unsigned, under-threshold, revoked, wrong-authority,
  wrong-policy, wrong-route-suffix, rolled-back, or equivocating manifest;
  unsafe or mismatched inputs; an existing report path. No report is written.
- `64` — usage failure; `75` — another process holds the state lock; `70` —
  internal failure.

Errors never echo argv, paths, URLs, JSON content, or exception text. The
report is installed exclusively as an owner-only mode-`0600` file and is never
overwritten; choose a fresh path per run (for example the evaluation epoch).

## Reading a report

Each observation records the deployment, route host, challenge path, the
published `assignment_digest_sha256`, the fresh probe nonce, latency, status,
byte count, body digest, `X-Build-ID` verification, the observed edge leaf
digest, and the attestation status. `serving` means the exact published
challenge digest and build ID were served over verified TLS within bounds.
Failure codes are deliberately specific: `body_digest_mismatch`,
`build_id_header_mismatch`, `unexpected_status`, `redirect_rejected`,
`response_oversized`, `timeout`, `connection_failed`, `tls_handshake_failed`,
`tls_certificate_invalid`, `tls_pin_mismatch`, `attestation_missing`,
`attestation_invalid`, and `transport_error`.

A single degraded run is an observation, not a verdict. Treat repeated
failures for the same deployment across manifests, or an `attestation_invalid`
result, as material for the central operators; the probe itself never changes
weights or trust.

## Archival and cross-referencing

Archive each report together with the manifest, its signature envelopes, the
trust policy, the evaluation epoch source, and the printed next-state digest.
Later, the offline checkpoint flow can be cross-referenced by
`manifest_digest_sha256`, finalized height/hash, `deployment_id`,
`assignment_digest_sha256`, and — via the manifest entry — the ticket and
receipt digests, assignment nonces, and miner UID/hotkey pairs. A verified
attestation embedded in an observation additionally attributes that response
to one miner replica.

## Fork, rollback, and equivocation response

On `sequence_rollback`, `same_sequence_divergence`, `previous_link_mismatch`,
`same_height_fork`, `finalized_height_rollback`, `issued_at_rollback`, or a
state-anchor mismatch:

1. stop; do not reset the state root to genesis to make the error disappear;
2. retain the state root, the received manifest, and its envelopes unchanged;
3. record the evaluation epoch, the last printed state digest, and the
   publication digests;
4. escalate to the central publication operators for an independently
   authenticated resolution.

Never choose a manifest by arrival order or by which one probes "better".
