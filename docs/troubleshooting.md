# Troubleshooting

Messages below are quoted from the code so you can search for them verbatim.
Start with the health checks, then find the exact message.

## Quick health checks

| Check | Command | Healthy |
| --- | --- | --- |
| Miner Go agent up | `curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:9101/healthz` | `204` |
| Miner axon synced | `curl -sk -o /dev/null -w '%{http_code}\n' https://127.0.0.1:8091/healthz` | `204` (`503` = not registered, wrong UID, or chain sync failing) |
| Miner reachable from outside | same `curl -sk` against `https://<public-ip>:<port>/healthz` from another host | `204` |
| Miner TLS pin | `sudo scripts/manage-miner-tls.sh check /etc/misscomputer-miner/tls` | `leaf sha256` equals the agent's `--tls-certificate-sha256` |
| Organic network | `docker network inspect misscomputer-organic --format '{{.Internal}}'` | `true` |
| Host isolation rule | `sudo iptables -C INPUT -i miss-organic0 -m conntrack --ctstate NEW -j DROP` | exit `0` |
| Chain registration | [read-only chain check](getting-started.md#read-only-chain-check) | your UID, `active=True`, expected `axon=` |
| Validator CLI result | exit status plus the one-line stdout/stderr | `0` (or `3` for recorded-but-not-scored) |

## Miner

### `misscomputer-miner` refuses to start

| Message | Cause and fix |
| --- | --- |
| `live miner startup requires --tls-cert-file and --tls-key-file` | Live mode always needs TLS. Issue a certificate with `scripts/manage-miner-tls.sh issue` ([miner guide, Step 4](miner-quickstart.md#step-4-issue-the-tls-certificate)). |
| `--allow-insecure-mock-http requires --mock-uri` | Plain HTTP is only for the local mock chain. Remove the flag for live use. |
| `mock HTTP cannot be combined with TLS certificate options` | Choose mock HTTP *or* TLS, not both. |
| `TLS private key permissions must not grant group or other access` | `chmod 600` the key and make sure the user running the axon owns it. |
| `TLS files must be regular non-symlink files` | Point at the files inside the release (`.../tls/current/miner.crt` works; the file itself must not be a symlink). |
| `TLS leaf certificate is expired` / `... is not yet valid` | Rotate the certificate; check the host clock. |
| `TLS leaf certificate must declare CA=false` / `... must not be a CA certificate` | Use the bundled script; it issues the required non-CA leaf. |
| `TLS certificate and private key do not match` / `... do not form a loadable pair` | Certificate and key come from different releases. Use the same `current/` directory for both. |
| `bridge secret must contain at least 32 bytes` | Regenerate: `openssl rand -hex 32` into the secret file. |
| `FileNotFoundError: keyfile at '.../hotkeys/<name>' does not exist` | Wrong `--wallet-name`, `--wallet-hotkey`, or `--wallet-path`, or the hotkey file was not copied to the server. |

### Axon runs but `/healthz` is `503`

| Log message | Cause and fix |
| --- | --- |
| `miner hotkey is not registered` | The hotkey is missing from the metagraph of `--netuid` on `--subtensor-network`, **or** the chain reports it with `active=False`; the miner treats both the same. Run the read-only chain check to see which. Fix the wallet, network, or netuid, or register. |
| `configured UID differs from metagraph` | `--uid` is stale (for example after re-registration). Set it to the UID shown by the chain check, on both processes. |
| `metagraph synchronization failed` (with exception) | The chain read failed. Check network access to the chain endpoint and the `--subtensor-network` value. |

### Validators reach you but nothing is assigned

Look at the status codes in the axon's access log (`uvicorn.access` lines):

| Response | Meaning and fix |
| --- | --- |
| `503 metagraph is not ready` | See the `503` table above. |
| `401` | btauth signature, nonce, or freshness failure. Usually the caller's problem; if every request fails, check the host clock. |
| `403 caller is not active on this subnet` / `caller lacks a validator permit` / `caller stake is below policy minimum` | Normal filtering of non-validators or low-stake callers (`--min-validator-stake`, default `1000`). |
| `429 validator request rate exceeded` | One caller exceeded 120 requests per 60 seconds. |
| `409 request block is stale or from the future` | Your chain view and the validator's differ by more than two blocks. Check sync logs and `--sync-interval`. |
| `500 local Go identity is misconfigured` | The axon and agent disagree on network, netuid, hotkey, UID, transport, or TLS pin. Compare every row of [Values that must match](miner-quickstart.md#values-that-must-match). A common cause is starting the agent without `--uid` or with the default `--network local`. |
| `403 ticket Bittensor identity mismatch` | The ticket was issued for a different UID, pin, or block window than you are serving now (for example right after a certificate rotation or re-registration). New tickets after the next handshake will match. |
| `502 runtime unavailable` | The axon cannot reach the Go agent. Check the agent process and `--go-agent-url`. |

Also check:

- The axon's published IP is public and numeric, the port is open inbound,
  and the certificate was issued for exactly that IP. Validators never
  connect to hostnames or private addresses.
- The agent started without errors; it advertises `organic-oci-v1` only after
  its Docker network and host isolation checks passed. Without that feature a
  validator treats the miner as ineligible.

### `miner-agent` refuses to start

| Message | Cause and fix |
| --- | --- |
| `network, hotkey, service-key-file, and state-db are required` | Pass `--network`, `--hotkey`, `--service-key-file`, and `--state-db`. |
| `HTTPS miner transport requires a canonical lowercase TLS certificate SHA-256` | Pass `--tls-certificate-sha256` with the 64-character lowercase `leaf sha256` printed by the TLS script. |
| `pinless HTTP miner transport requires --allow-insecure-mock-http on an explicit local/mock network` | `--miner-transport http` is for local mocks only. Use the default `https` live. |
| `refusing non-loopback bridge bind without explicit override` | Keep `--bind` on loopback. `--allow-non-loopback` is unsafe unless the bridge is isolated some other way. |
| `bridge secret must contain at least 32 bytes` | Same secret file as the axon, at least 32 bytes. |
| `service signing key file must not be group/world accessible` | `chmod 600` the service key. |
| `service signing key file is invalid` | The file is not a hex Ed25519 key written by the agent. Restore it from backup; delete it only if you accept a new service key. |
| `S3 endpoint and bucket are required` | With `--artifact-backend s3`, pass `--s3-endpoint` and `--s3-bucket`. |
| `S3 credential environment variables "S3_ACCESS_KEY_ID" and "S3_SECRET_ACCESS_KEY" must be set` | Export them in the agent's environment (or name different variables with `--s3-access-key-env` / `--s3-secret-key-env`). |
| `S3 endpoint must use HTTP or HTTPS` / `... must not contain user information, a query, or a fragment` | Use a plain origin URL; credentials never go in the URL. |
| `artifact directory is required for filesystem backend` | `--artifact-backend file` needs `--artifact-dir`. |
| `create organic network: ...` / `inspect organic network: ...` | Docker is not running or the agent lacks Docker access. Run the agent as root or with Docker access. |
| `organic network misscomputer-organic is "...", want "bridge true false false miss-organic0"` | A network with that name exists with other settings. Remove it (`docker network rm misscomputer-organic`) when no replicas use it, and restart. |
| `install host isolation rule: ...` | The agent cannot run `iptables`. Run it as root (or with `CAP_NET_ADMIN`). |
| `host isolation rule is missing (iptables -I INPUT -i miss-organic0 -m conntrack --ctstate NEW -j DROP)` | You used `--host-isolation verify` without installing the rule. Install it, or use the default `enforce`. |
| `restart cleanup: ...` | Removing replicas from the previous run failed. Check `docker ps -a` and Docker's health, then restart; failed cleanups are retried. |
| `netuid or UID exceeds uint16` | Check `--netuid` and `--uid`. |

### Bridge authentication failures

Every call between the axon and the agent is HMAC-signed. The agent answers
`401` with code `unauthorized` and one of these messages:

| Message | Fix |
| --- | --- |
| `invalid bridge signature` | The two processes read different secrets. Point both at the same file and restart both. |
| `stale bridge request` | Requests older than 10 seconds or more than 2 seconds in the future. Fix the host clock. |
| `replayed bridge request` | A nonce was reused; should not happen with the shipped client. |

### Assignments fail

The agent returns a signed `failed` receipt with one error code
(details in [miner-oci-runtime.md](miner-oci-runtime.md)):

| Code | Typical cause |
| --- | --- |
| `artifact_fetch_failed` | Artifact store unreachable or credentials wrong. |
| `artifact_verify_failed` | A digest, size, or policy check failed. Never retried with different bytes. |
| `image_load_failed` | `docker load` failed. |
| `image_identity_mismatch` | The engine reported an unexpected image ID. |
| `container_create_failed` | `docker run` or network attach failed. |
| `resource_exhausted` | Disk full (`ENOSPC`). Free space under `--docker-state-dir` and Docker's data root. |
| `deactivated` | The assignment was deactivated while it was starting. |

## Validator

The hardened CLIs print one line: `PROBED ...`, `WINDOW ...`, `VERIFIED`, or
`REJECTED <code>` / `ERROR internal_error` on stderr. Codes are stable; paths,
arguments, and file contents are never echoed.

### Setup and input problems

| Code | Cause and fix |
| --- | --- |
| `usage` (exit `64`) | A required flag is missing or malformed. `--help` also prints `REJECTED usage`; flags are listed in the [validator guide](validator-quickstart.md) and runbooks. |
| `trusted_digest_invalid` | A `--*-sha256` value is not 64 lowercase hex characters. |
| `trusted_digest_mismatch` | The file's SHA-256 differs from the digest you passed. Re-check the file and the independently obtained digest; never "fix" it by copying the digest from the file. |
| `input_path_unsafe` | Paths must be absolute and normalized. |
| `input_path_sensitive` | A path component is named like `secrets`, `wallets`, `.env`, `.ssh`, or ends in `.key`/`.pem`. Move the file (see [validator input paths](keys-and-secrets.md#validator-input-paths)). |
| `input_file_unsafe` / `input_metadata_unsafe` | The input is not a regular single-link file owned by you with mode `0600`, or a parent directory is group/world-writable. |
| `probe_seed_invalid` | The seed file must be exactly 32 bytes. |
| `wallet_hotkey_mismatch` | `--validator-hotkey` is not the SS58 address of the wallet hotkey selected by `--wallet-*`. |
| `state_root_unsafe` / `state_file_unsafe` | The state root or its parent has the wrong owner or mode, or was edited. Do not hand-edit state. |
| `state_missing` | A non-`genesis` anchor was given but there is no state yet. Use `genesis` only for the very first run on an empty root. |
| `state_anchor_invalid` | `--trusted-state-anchor` is not `genesis`, `current`, or a 64-character lowercase digest. |
| `state_anchor_stale` | The anchor digest does not match the state on disk, or `genesis` was used on a root that already has state. Pass the `next_state_sha256` from the latest successful run. |
| `output_exists` | Output files are never overwritten. Use a new file name per run. |
| `output_parent_unsafe` | The output directory must exist, be owned by you, and not be group/world-writable. |
| `manifest_archive_unsafe` / `manifest_archive_conflict` | Archive directory permissions, or an existing archived manifest with different bytes. Do not delete archive entries. |
| `probe_busy` (exit `75`) | Another probe run holds the state lock. Check for an overlapping timer. |

### Chain and publication problems

| Code | Meaning |
| --- | --- |
| `epoch_already_elapsed` | The requested `--epoch-index` has ended. Start runs at the epoch boundary. |
| `trust_policy_mismatch` / `trust_policy_invalid` / `trust_policy_expired` / `trust_policy_not_yet_valid` | Wrong or outdated trust policy, or a manifest that references a different policy. Obtain the current policy out of band. |
| `manifest_stale` / `manifest_expired` / `manifest_future` | Manifest freshness failed at the start instant. Check the host clock, then the publication. |
| `manifest_replica_lease_expired` | A replica lease ended at your `--finalized-height`. Check that the height is current; otherwise wait for a fresh manifest. |
| `signature_invalid` / `signature_count_invalid` / `signature_binding_mismatch` | Signature envelopes are missing, wrong, or for another manifest. |
| `tls_handshake_failed` / `tls_certificate_invalid` | HTTPS fetch or probe TLS failed (edge or publication host). |
| `window_not_closed` / `window_close_stale` | The window coordinator ran before the window closed, or more than 600 seconds after. |
| `validator_not_registered` | Your hotkey is missing from, or not `active` in, the finalized view read by the coordinator. |
| `finalized_view_unavailable` / `finalized_view_not_finalized` | The RPC could not provide a finalized view. Check `--rpc-endpoint`. |
| `epoch_record_invalid` / `epoch_record_duplicate` / `epoch_record_foreign_validator` | The epoch directory contains a malformed, duplicated, or foreign record. The coordinator refuses to curate by omission; investigate rather than deleting files. |

### Stop-and-escalate codes

`sequence_rollback`, `same_sequence_divergence`, `previous_link_mismatch`,
`same_height_fork`, `finalized_height_rollback`, `finalized_epoch_rollback`,
and `issued_at_rollback` indicate a conflicting or rolled-back publication or
chain view. Stop, keep the state root and received files unchanged, and follow
the [fork and rollback response](public-validator-live-probe-runbook.md#fork-rollback-and-equivocation-response).
Never reset to `genesis` or restore an older backup to make them go away.

### Weight executor

Read `status` and `error_code` together. Exit `2` after `--execute` is not
proof that nothing was submitted; see
[weight-reconciliation.md](weight-reconciliation.md). RPC alerts such as
`rpc_snapshot_disagreement` or `rpc_finalized_rollback` are printed as JSON on
stderr and should page an operator.
