# Sandbox operations (`sandbox-ops-v1`): exec and files, contract slice 1

Status: **proposed contract, standalone code only, off by default, not
customer-ready.** This slice adds the vocabulary (`pkg/sandbox/ops_v1.go`),
the two signed documents and their validation (`pkg/protocol/sandbox_ops_v1.go`),
cross-language vectors (`pkg/protocol/testdata/sandbox-ops-v1-vectors.json`)
and the helper's in-sandbox path resolver
(`cmd/sandbox-ops-helper/internal/fsroot`). No miner
route, flag, capability, durable table, backend method, helper binary or
neuron transport exists yet, and no running binary behaves differently.

`sandbox-ops-v1` is a separately versioned extension of
[`sandbox-lease-v1`](sandbox-lease-v1.md). It changes no member, digest,
signing domain, receipt stage, route, table or capability of that lane, of
`deployment.v4`, or of the static documents. Ops are score-neutral.

## What an op is

One validator-signed `sandbox-op-request` asks the miner to run one bounded
operation on one **running** lease; the miner answers with one miner-signed
`sandbox-op-receipt`. Ops are:

| Op | Effect | Payload (beside the document) | Result (beside the receipt) |
| --- | --- | --- | --- |
| `exec_start` | start a command; returns at once with the exec running or already ended | exec command JSON | none |
| `exec_read` | page one output stream of an exec by absolute byte offset | none | output chunk |
| `exec_cancel` | kill an exec's process group; idempotent | none | none |
| `file_write` | offset 0: create or atomically replace a regular file with `mode`; later: append at exactly the current size | file chunk | none |
| `file_read` | read a regular file chunk | none | file chunk |
| `file_stat` | describe a path (symlinks followed in-root) | none | none (`file` member) |
| `file_list` | page a directory's entries by entry cursor | none | listing JSON |
| `file_remove` | remove a file, symlink (itself) or directory (empty unless `recursive`) | none | none |
| `file_mkdir` | create a directory with `mode` (parents with `recursive`) | none | none (`file` member) |

Background processes are execs that outlive their `exec_start` answer; a
client polls them with `exec_read`. There is no PTY, interactive stdin,
persistent shell, server push or streaming.

## Documents

Both use schema version 1, schema IDs `miss.computer/misscomputer-subnet/<stem>`,
the static-site-v1 signing rule `<schema>/v1/ed25519 || 0x00 || canonical(document without signature)`
and the `sha256:` canonical digest. Neither verifies as any lease document
or web ticket, nor as each other.

### `sandbox-op-request` (validator service key)

Identity and window: `sandbox_id`, `generation`, `miner_id`, `lease_id`
(the derived ID of the targeted lease), `lease_digest` (digest of the
complete signed `sandbox-lease-ticket`; renewals do not change it),
`op_nonce` (32 lowercase hex), `op`, `issued_at`, `expires_at`
(`issued_at < expires_at <= issued_at + 60s`), `workload_kind: sandbox`,
and the full static-v1 `subnet` binding.

The op ID is `<lease_id>-op-<op_nonce>`. Optional members are present
**exactly** when the op uses them, and `null` otherwise:

| Member | Ops | Bounds |
| --- | --- | --- |
| `exec_id` | `exec_read`, `exec_cancel` | an op ID of this lease (prefix `<lease_id>-op-`) |
| `path` | every `file_*` | path rules below; `/` only for `file_stat`, `file_list` |
| `payload_digest`, `payload_bytes` | `exec_start`, `file_write` | `sha256:` of the payload, 1..524288 bytes; `payload_bytes` is 0 otherwise |
| `offset` | `exec_read`, `file_read`, `file_write` (bytes), `file_list` (entries) | `file_write` offset + bytes <= 256 MiB |
| `limit` | `exec_read`, `file_read` (1..524288 bytes), `file_list` (1..1000 entries) | |
| `stream` | `exec_read` | `stdout` or `stderr` |
| `timeout_ms` | `exec_start` | 1000..86400000 |
| `max_output_bytes` | `exec_start` | 1024..16777216 retained per stream |
| `mode` | `file_write` at offset 0, `file_mkdir` | permission bits 0..0777 only |
| `recursive` | `file_remove`, `file_mkdir` | boolean |

### `sandbox-op-receipt` (miner service key)

Echoes `sandbox_id`, `generation`, `miner_id`, `lease_id`, `op_id`, `op`, and
carries `document_digest`, `stage`, `error_code`, `exec`, `file`,
`result_digest`, `result_bytes`, `next_offset`, `eof`, `observed_at` and the
binding.

- Exec ops answer `running`, `exited`, `cancelled`, `timed_out` (the exec's
  state, with an `exec` member whose `state` matches and no error code),
  `refused`, or `failed`. `exec` holds `started_at`, `ended_at` (only once
  terminal), `exit_code` (only for `exited`, 0..255), and per stream the
  total bytes produced and the retained prefix.
- File ops answer `completed`, `refused`, `failed`, or `timed_out` with
  `op_deadline_exceeded` (the 30 s file-op budget; a recursive remove may
  then be partial).
- `file` (type `file|directory|symlink|other`, size, permission bits) is
  present exactly for a completed `file_write`, `file_stat` or `file_mkdir`.
- `result_digest`/`next_offset` are present exactly for a successful
  `file_read`, `file_list` or `exec_read`; `result_bytes` <= 512 KiB.

`SandboxOpReceiptAnswersV1(receipt, request, result)` is the validator's
acceptance check: the receipt names that exact request (digest, op ID,
lease, parties), the returned bytes match `result_digest` and
`result_bytes`, a read's `next_offset` is `offset + result_bytes` within
`limit`, an `exec_read` stays within the retained stream and sets `eof`
exactly when the exec is terminal and the cursor reached the retained end,
and a listing decodes strictly, sorted and unique, within `limit`. A signed
receipt that contradicts an exact request is miner fraud evidence.

## Authorization and identity fencing

1. **Admission** (`VerifyBoundSandboxOpRequestV1`): signature by the
   subnet-bound validator service key, `issued_at` skew of at most 30 s, not
   expired, and the same request-local network, netuid, caller hotkey, miner
   hotkey, UID and chain-block check as every lease document. The miner then
   requires the document to name its own service key, transport identity
   and hotkey.
2. **Lease fence** (`SandboxOpTargetsLeaseV1`): `lease_digest` is the digest
   of the stored lease, `lease_id` its derived ID, and sandbox, generation,
   miner and parties (network, netuid, validator hotkey and service key,
   miner hotkey and service key) equal the lease's. A fresh chain binding of
   the same parties still targets the lease; another validator, an older or
   newer generation, or a guessed `lease_id` does not.
3. **Liveness fence** (miner durable state, later slice): an op runs only
   while the lease is `running` and before its current expiry. A pending,
   cleanup, released, fenced or expired lease answers `lease_not_running`,
   `released` or `lease_expired` without any backend call; an exited
   container answers `sandbox_exited`.
4. **Tenants are not visible to miners.** The private gateway checks that
   the tenant owns `(sandbox_id, generation)` before it asks the validator
   runtime to sign, and never lets a tenant choose `lease_id`, `generation`
   or `op_nonce`. The public protocol guarantees validator, lease and
   generation fencing only; it is not a miner-enforced tenant boundary.

## Replay

- `op_id` is the signed replay key. The miner records `(op_id,
  document_digest)` durably before any effect.
- An exact replay never repeats an effect: `exec_start` never re-executes,
  `file_write` never rewrites, `exec_cancel` is idempotent. The receipt
  reports current state (an exec may have moved from `running` to
  `exited`). Reads are side-effect free and recomputed.
- The same `op_id` with a different document is signer equivocation:
  `409 sandbox_conflict`, no receipt.
- An op record is kept at least until `expires_at` plus the 30 s skew, after
  which the request is inadmissible, and at most until lease cleanup.
- The envelope `request_id` is transport correlation only.

### Unknown outcomes (no answer arrived)

A lost answer, a timed-out hop or a validator runtime crash leaves an op's
outcome unknown. The runtime holds `exec_start` and `file_write` payload
bytes in memory only, until it has a verified receipt or until the
request's `expires_at` plus the 30 s skew; no layer persists or logs them.

- **Inside that window**, the runtime resolves by exact replay: the same
  signed document with the same payload. The `op_id` makes the replay
  idempotent at the miner.
- **After the window** the request is inadmissible:
  - `exec_start` is resolved with `exec_read` or `exec_cancel` naming
    `exec_id = op_id`. The miner records every admitted `exec_start` before
    any effect and keeps the record until lease cleanup, so an
    `exec_not_found` receipt signed at or after the start's `expires_at`
    plus the skew is a definitive non-start
    (`SandboxExecNeverStartedV1`). An earlier `exec_not_found` is not
    definitive, because the start may still be in flight. A miner that later
    reports that exec as started has signed a contradiction.
  - `file_write` is reported to the tenant as `outcome_unknown` (a gateway
    status, not a miner code). The client re-uploads from offset 0.
    `file_stat` may hint at the size but proves nothing about the content.
- A released or expired lease answers `released` or `lease_expired`. The
  sandbox and every exec are gone, but that does not prove a non-start.

## Deadlines, cancellation and caps

- Admission window 60 s; file ops finish within 30 s or answer `timed_out`.
- An exec's deadline is `min(start + timeout_ms, current lease expiry)`. At
  the deadline or on `exec_cancel` the process group gets SIGTERM, then
  SIGKILL after 5 s. Release, expiry or restart destroys the sandbox and
  every exec.
- At most 16 running execs and 1024 exec sessions per lease
  (`exec_limit_exceeded`).
- Each stream retains its **first** `max_output_bytes`; later bytes are
  counted and dropped at the producer.
- Retained output never lives unbounded in miner-agent memory. The
  in-sandbox helper captures it inside the sandbox, so it is charged to the
  lease's own writable storage or memory. The agent holds only in-flight
  chunks of at most 512 KiB per op. An agent without in-sandbox capture
  must declare a finite per-agent retained-output budget, and refuse new
  execs beyond it with `exec_limit_exceeded`.
- Exec status and output are what the helper observed inside the
  customer's sandbox, and customer code can influence both. They are
  customer results, not evidence against the customer or the miner.
- Chunks are at most 512 KiB raw, so a base64 payload or result plus the
  document fits the unchanged 1 MiB bridge body limit. A file reaches at
  most 256 MiB through writes (sequential chunks; the file is visible
  partially until the last chunk); any size can be read in chunks.

## Exec payload

`{"argv": [...], "cwd": "/...", "env": {}, "stdin_b64": null | "<base64>"}`:
1..1024 arguments of at most 32 KiB without NUL (256 KiB total), a `cwd`
under the path rules, `env` always the empty object, and at most 256 KiB of
canonical base64 stdin. Decoding is strict: every member present, no
unknown or duplicate member at any depth, no trailing data.

Per-exec environment is not part of v1: every customer variable goes
through the lease's `secret_env`, which is refused until sealed delivery
exists, and an exec-level `env` would bypass that rule.

## Paths

- Syntax (`sandbox.ValidOpPath`): absolute, printable ASCII (signed
  documents are canonical ASCII JSON), at most 4096 bytes, components
  1..255 bytes, no empty, `.` or `..` component, no trailing slash.
  Non-ASCII names are not addressable in v1; `file_list` omits them and
  counts them in `unaddressable` rather than renaming them.
- Resolution happens **inside the sandbox isolation boundary** (in the
  gVisor sentry), never on the host: no host-side access to a container's
  overlay trees, no `docker cp`, no host-side resolver over those trees.
- Inside the sandbox, the helper's resolver
  (`cmd/sandbox-ops-helper/internal/fsroot`; only the helper can import it,
  and its `Open` takes no directory and opens `/`) resolves with
  `openat2(RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS)`: symlinks follow
  container semantics (absolute targets are relative to the sandbox root,
  `..` never rises above it), procfs magic links are refused, a final
  component that is created, replaced or removed is handled with `*at`
  calls on its parent descriptor and never followed (`file_write` refuses a
  final symlink, `file_remove` removes the link itself, recursive removal
  walks by descriptor with `O_NOFOLLOW`), and FIFOs, devices and sockets are
  refused without blocking. Without `openat2` it refuses with
  `ops_unsupported`; there is no fallback.

## In-sandbox helper (later slice, requirements)

File operations and exec run through one helper binary inside the sandbox.
Docker cannot kill an exec instance, so the helper is also what kills a
whole process group at a deadline and caps output at the producer. This
slice ships no helper and no mount. These requirements come from the
security design review, and the helper slice must meet them:

- **Delivery:** a root-owned, read-only `0555` host **directory** containing
  only the helper, bind-mounted read-only, `nosuid`, `nodev`, `rprivate`
  at `/.misscomputer`, and only when ops are enabled. A directory
  mountpoint cannot be renamed or replaced by guest root (`EBUSY`); a
  single-file bind is not acceptable without probe evidence. Before every
  create, the miner opens the source without following symlinks and checks:
  a regular file owned by uid 0 with mode exactly `0555`; ancestors that are
  root-owned and not group- or other-writable; and the configured SHA-256.
  The engine readback must equal exactly that one mount. With ops off,
  create and readback stay byte-identical (`Mounts == []`).
- **Invocation:** the image default user (never 0), not privileged, empty
  environment, no TTY, the fixed absolute helper path as `argv[0]`, never
  `sh -c`.
- **Untrusted output:** customer code with the same uid can kill, ptrace or
  replace the helper process. The miner parses helper output with bounded
  framing and a strict schema, re-applies every cap, and never logs payload
  bytes.
- **Kill path:** if the wrapper does not confirm after SIGTERM, 5 s and a
  grace period, the miner sends one more cancel. It then reports
  `timed_out` or `cancelled` and closes the stream, so no miner resource is
  left unbounded.
- **Build:** static Go, `CGO_ENABLED=0`, `-trimpath`, `-buildvcs=false`,
  pinned toolchain, published SHA-256. No network, configuration files or
  environment-driven behavior. One size-capped request on stdin.
- **Keepalive:** the helper is never PID 1 and never replaces the image
  entrypoint in v1. An implicit entrypoint override is rejected. Images
  whose own process exits answer `sandbox_exited`. A helper-init keepalive
  needs a signed lease v2 member.
- **Gate:** the resolver's `openat2` behavior, the mount's immutability
  from guest root, and process-group kill must be proven inside the pinned
  runsc release before any miner advertises `sandbox-ops-v1`. If `openat2`
  is missing inside the sandbox, ops answer `ops_unsupported`.

## Error codes

Non-fault: `lease_not_running`, `lease_expired`, `released`,
`sandbox_exited`, `exec_not_found`, `exec_limit_exceeded`, `path_not_found`,
`path_exists`, `path_not_file`, `path_not_directory`, `path_refused`,
`directory_not_empty`, `permission_denied`, `no_space`, `file_too_large`,
`offset_mismatch`, `op_deadline_exceeded`, `ops_unsupported`,
`sandbox_disabled`, `sandbox_op_failed`, `sandbox_resources_exhausted`.
Miner faults: `op_runtime_failed`, `miner_restart`.

Every failure that originates inside the sandbox is non-fault, because
guest code shares the helper's identity and can frame the miner by killing
or starving the helper. That covers a helper protocol error, exit or kill
(`sandbox_op_failed`), and pids, memory or descriptor exhaustion of the lease
(`sandbox_resources_exhausted`). `op_runtime_failed` is reserved for
miner-side engine and transport failures, such as an unreachable dedicated
daemon or an exec-create API error not caused by container state.
A malformed, unsigned or inadmissible request, or a payload that does not
match its binding, is refused with a stable code and no receipt. Ops are
score-neutral, so attribution is diagnostic only.

## Visibility

Commands, stdin, file bytes, outputs and listings travel in plaintext memory
through the validator runtime, the Python neurons and the miner agent over
pinned TLS. The miner operator can read all of them. They are not
confidential, and no secret belongs in argv, stdin or files. Protocol code
never persists or logs payload or result bytes; durable rows hold digests
and counts only. That is a logging rule, not confidentiality.

## Transport and compatibility (later slices)

- Capability feature `sandbox-ops-v1`, advertised only with
  `sandbox-lease-v1` and an ops-capable backend. A validator refuses a miner
  without it before contact (`409 sandbox_ops_capability_unsupported`).
- Flag `--sandbox-ops off|on`, default off; `on` requires
  `--sandbox-leases on` and an ops-capable backend.
- Envelope `subnet-sandbox-ops-synapse.v1`: request `{protocol, request_id,
  current_block, caller_hotkey, validator_binding, document, payload_b64}`
  (plus `binding_verified` on loopback), answer `{protocol, request_id,
  receipt, result_b64}`. Routes: validator bridge
  `POST /v1/miners/{hotkey}/sandbox-ops`, miner axon
  `POST /api/v1/sandbox/ops`, Go agent `POST /v1/sandbox/ops`. Python
  forwards without interpreting, as for `subnet-sandbox-synapse.v1`.
- Flag off means byte-identical routes, tables, capabilities and behavior.

## Not in v1

PTY or interactive stdin, persistent shells, streaming output, per-exec
environment, per-exec user selection (image default user only), signals
other than cancel, inbound ports, file watch, archives, atomic multi-chunk
upload, chmod, chown, rename, search, non-ASCII paths, ops on a lease that is
not running, and exec or file state across a miner restart. Each needs a
new schema version.
