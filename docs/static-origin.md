# Static temporary origin (`static-origin`)

Development status: offline and loopback-tested only. Nothing here is
deployed; static admission stays behind `static_sites=off`.

`cmd/static-origin` serves exactly one `static-site-v1` site version on one
route host with the same `pkg/static` handler the miner uses, so origin and
miner bytes are identical by construction (static-site contract §5–§6, §9).
No customer code runs. The private temporary-origin runner launches one
process per route label and stops it with SIGTERM.

## Lifecycle

1. **Verify, no socket.** Parse the trust policy and require its
   `digest_sha256` to equal `--trust-policy-digest` (the out-of-band pin).
   Parse the release, require SHA-256 of its bytes to equal
   `--release-digest`, and verify it (§7.2): it binds `--site-digest`, a
   policy key valid at `issued_at` signed it under the release domain, the
   producer policy is implemented, and it authorizes this build's
   `server_implementation_digest`, which must also equal
   `--server-implementation-digest`. Fetch `v1/static-sites/<site hex>.json`
   (≤ 1 MiB) and require it to hash to the site digest and satisfy every
   manifest rule. Fetch every blob `v1/blobs/sha256/<hex>` into the private
   cache, checking length and SHA-256 while streaming.
2. **Listen.** Only after step 1: bind `--listen`, write the READY report.
3. **Serve.** Host ≠ `--route-host` → 421. Every body is rehashed as it is
   sent and its last chunk is withheld unless it matches. The first pinned
   body observed not to match (unopenable, too long, wrong length or digest)
   aborts that response, turns later requests into the fixed 503, and stops
   the process with `FAILED` / exit 3. A client disconnect is not a fault.
4. **Stop.** SIGTERM or SIGINT: stop accepting, drain up to
   `--shutdown-timeout`, delete the verified copy, print `STOPPED`, exit 0.
   A signal during step 1 also exits 0 with `STOPPED` without serving.

## Process contract

| Stdout (exactly one line) | Exit | Meaning |
|---|---|---|
| `READY <json>` | — | verified and listening |
| `REJECTED <code>` | 2 | refused before listening |
| `FAILED static_verify_failed` | 3 | stopped after a pinned body stopped verifying |
| `STOPPED` | 0 | stopped by signal |
| — | 64 | usage error, including unsafe credentials |
| — | 70 | internal error, including listen and ready-file failures |

Diagnostics go to stderr only and never contain credential values.

`READY` JSON, also written atomically with mode 0600 to `--ready-file`:

```json
{"schema":"miss.computer/misscomputer-subnet/static-origin-ready","schema_version":1,
 "listen_address":"10.20.0.5:40000","pid":1234,"route_host":"…","site_digest":"sha256:…",
 "release_digest":"sha256:…","server_implementation_digest":"sha256:…",
 "trust_policy_digest_sha256":"…","file_count":4,"total_bytes":131}
```

`REJECTED` codes: `config_invalid`; release codes `trust_policy_invalid`,
`trust_policy_digest_mismatch`, `release_invalid`, `release_digest_mismatch`,
`release_binding_mismatch`, `signer_untrusted`, `signer_outside_validity`,
`signature_invalid`, `producer_policy_unsupported`,
`server_implementation_mismatch` (the public validator's abstention codes);
content codes `static_fetch_failed`, `static_verify_failed`,
`static_manifest_invalid`, `static_limits_exceeded`,
`static_storage_exhausted`, `internal`.

## Flags

| Flag | Default | Notes |
|---|---|---|
| `--listen` | required | `host:port`; port 0 picks one (reported in READY) |
| `--route-host` | required | lowercase hostname; the only Host served |
| `--site-digest`, `--release-digest` | required | `sha256:<hex>` |
| `--release-file`, `--trust-policy-file` | required | stored document bytes |
| `--trust-policy-digest` | required | pinned `digest_sha256` |
| `--server-implementation-digest` | required | must equal `--print-server-implementation-digest` |
| `--cache-dir` | required | private per process; `<dir>/misscomputer-static-v1` is swept on start |
| `--cache-max-bytes` | 268435456 | the cache also keeps 256 MiB of filesystem space free |
| `--ready-file` | none | optional READY copy |
| `--artifact-backend` | `file` | `file` (`--artifact-dir`) or `s3` |
| `--s3-endpoint`, `--s3-bucket`, `--s3-region` | —, —, `auto` | path-style, SigV4 (`artifact.S3Store`) |
| `--s3-credentials-file` | none | owner-only regular file (0600/0400), exactly `{"access_key_id":…,"secret_access_key":…}`; takes precedence over the env |
| `--s3-access-key-env`, `--s3-secret-key-env` | `S3_ACCESS_KEY_ID`, `S3_SECRET_ACCESS_KEY` | names of env variables, never values |
| `--prepare-timeout` | 10m | bound on step 1's fetches |
| `--shutdown-timeout` | 30s | drain bound |
| `--fetch-concurrency` | 4 | concurrent blob downloads |
| `--request-concurrency` | 64 | excess requests get the fixed 503 |
| `--print-server-implementation-digest` | — | print and exit 0 |

The origin only reads exact keys (`artifact.BlobOpener`). Give it read-only
store credentials.

## In-process use

`pkg/staticorigin` exposes the same lifecycle: `Prepare(ctx, Config, Store)`
(no socket), `Origin.Identity()`, `Origin.Serve(listener)` (returns
`http.ErrServerClosed` after `Shutdown`, `*FaultError` after a fault) and
`Origin.Shutdown(ctx)`. `staticorigin.Code(err)` maps a `Prepare` error to
its `REJECTED` code.

## Known gaps

- `net/http` answers an invalid percent escape such as `GET /100%` (V29)
  with its own `400 Bad Request` body before any handler runs; the status is
  normative, the body is not. The edge answers V29 itself (§10.3).
- Where the runner gets the release bytes is not fixed by the contract; the
  origin takes them as a file and authenticates them by digest and
  signature.
- No release revocation list exists yet (contract §14, item 7).
