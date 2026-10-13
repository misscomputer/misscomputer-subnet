# Sandbox leases (`sandbox-lease-v1`): contract slice 1

Status: **partial, off by default, not customer-ready.** This slice adds the
signed documents and the miner-side durable holds of a sandbox
reservation/lease lane. No miner agent route, no capability advertisement, no
runtime backend, no validator scheduling, no customer API and no scoring use
them yet. With nothing enabling the lane, every existing binary behaves
exactly as before.

Normative code: `pkg/sandbox` (vocabulary), `pkg/protocol/sandbox_v1.go`
(documents), `pkg/durable/sandbox_v1.go` (durable holds and leases).
Cross-language vectors: `pkg/protocol/testdata/sandbox-lease-v1-vectors.json`.

## What a sandbox lease is

A customer sandbox is one isolated Linux container started from a
digest-pinned OCI image, with its own filesystem, network policy and process
tree. The validator Go runtime is the only placement authority. It runs a
two-phase protocol against one miner:

1. **Reserve.** A validator-signed reservation asks the miner to hold
   capacity for one `(sandbox_id, generation, miner)` identity for at most
   two minutes. The miner checks its resource budget and records the hold in
   one transaction, or refuses.
2. **Commit.** A validator-signed lease commits exactly that hold to one
   image, isolation class, network policy and declared environment, with a hard expiry
   at most 15 minutes ahead.
3. **Renew.** Validator-signed renewals with a strictly increasing
   `renewal_seq` move the expiry forward. A customer TTL and heartbeat live
   above this protocol; the validator stops renewing at the customer TTL.
4. **Release.** A validator-signed release fences the identity permanently,
   even if it arrives before the reservation or lease it cancels.

If the validator disappears, the miner tears the sandbox down within the
lease window plus 30 seconds of grace. At expiry or release a sandbox is
deleted, not stopped. Miners are untrusted: their capacity claims are
diagnostics, and the validator places only against capacity it has observed.

## Documents

All five documents use schema version 1, schema IDs
`miss.computer/misscomputer-subnet/<stem>`, and the static-site-v1 signing
rule `<schema>/v1/ed25519 || 0x00 || canonical(document without signature)`.
A `deployment.v4` signature (no domain) or any other domain, including a
sibling sandbox domain signed by the same key, never verifies one of them.
Digests are `sha256:` + hex SHA-256 of the canonical signed document.

| Stem | Signer | Members beyond identity, window and `subnet` binding |
| --- | --- | --- |
| `sandbox-reservation-ticket` | validator service key | `reservation_nonce`, `resources`, `hold_expires_at` (at most 2 min after `issued_at`), `workload_kind: sandbox` |
| `sandbox-lease-ticket` | validator service key | `reservation_digest`, `assignment_nonce`, `image_reference` + `image_digest`, `isolation`, `network`, `env`, `secret_env`, `resources` (equal to the hold), `lease_expires_at` (at most 15 min) |
| `sandbox-lease-renewal` | validator service key | `lease_id`, `lease_digest`, `renewal_seq` (from 1, strictly increasing), new `lease_expires_at` |
| `sandbox-lease-release` | validator service key | `reason` (`customer_delete`, `ttl_expired`, `placement_aborted`, `hold_unused`, `liveness_lost`, `operator_takedown`) |
| `sandbox-lease-receipt` | miner service key | `document_schema`, `document_digest`, `stage`, `error_code`, `lease_id`, `renewal_seq`, self-reported `capacity_total/held/active` |

Identity: `sandbox_id` is `sbx-` plus 32 lowercase hex. `hold_id` and
`lease_id` are `<sandbox_id>-<miner>-g<generation>-<nonce>`, the
`deployment.v4` endpoint shape, so deterministic runtime instance naming is
reused. Every validator document carries the full static-v1 subnet binding
and is admitted with the same request-local network, hotkey, UID and chain
block check as a `deployment.v4` ticket (`VerifyBoundSandbox*V1`).

Members that decide behavior are explicit and bounded:

- `resources`: 1-16 vCPU (`cpu_millis` 1000-16000), 1-64 GiB memory, 5-100
  GiB disk, 64-32768 pids. A request is held and billed as requested; there
  is no fixed class. GPU is not part of v1.
- `image_reference` must pin `image_digest` (`repository@sha256:...`). Tags
  are resolved by the validator before signing.
- `isolation`: `gvisor`, `kata` or `firecracker`. Plain runc namespaces are
  not admissible for customer code.
- `network.mode`: `none`, `public` or `allowlist`. `allow` is always an array;
  in allowlist mode it holds 1-64 sorted unique hostnames or canonical CIDR
  prefixes. Inbound is never open in v1.
  A hostname entry matches exactly that host: there is no wildcard or
  suffix matching in v1. `*.example.com` is not a valid entry, and
  `example.com` does not admit `api.example.com`. The gateway expands a
  customer wildcard into exact hosts or CIDR prefixes, or rejects the
  request; it never widens the policy to `public`. Miner enforcement of
  hostname entries (DNS-pinned resolution) is not part of this slice, and a
  miner that cannot enforce an entry refuses with
  `network_policy_unsupported`.
- `env`: always the empty object `{}` in v1. Signed documents are persisted
  and may be logged by both sides, and a customer may pass a secret in any
  variable, so no environment value ever appears in a signed document. A
  validator-signed lease with any `env` entry fails validation, signing and
  admission.
- `secret_env`: the whole customer environment. `delivery: none` (no
  variables), or `delivery: sealed-bundle-v1` with 1-128 sorted unique
  variable names and the `bundle_digest` of a separately delivered sealed
  bundle that holds the values. The gateway declares **every** customer
  environment variable here, whether or not the customer marked it secret.
  The sealed bundle format and delivery path are not built yet, so a miner
  refuses every `sealed-bundle-v1` lease with `secret_delivery_unsupported`
  (not a miner fault). Until that path exists, only sandboxes with no
  customer environment can start.

Receipt error codes and whether they are attributed to the miner:
`runtime_start_failed` and `miner_restart` are miner faults. These are not:
`capacity_exhausted`, `resources_unsupported`,
`network_policy_unsupported`, `isolation_unsupported`,
`secret_delivery_unsupported`, `sandbox_disabled`, `released_before_use`,
`hold_expired`, `lease_expired`, `image_unavailable`.

## Durable holds and leases (miner side)

`Store.EnableSandboxLeases` creates three tables (`sandbox_holds`,
`sandbox_leases`, `sandbox_release_fences`) and is the only path that does.
`durable.Open` never creates them, and the `deployment.v4`, static and edge
table definitions are unchanged whether or not the lane is enabled. The
lane never reads or writes those tables.

Invariants (each has a test in `pkg/durable/sandbox_v1_test.go`):

- Capacity is checked and the hold inserted in one transaction. Occupancy is
  unexpired `held` holds plus every lease in `pending`, `running` or
  `cleanup`, summed per resource against the miner's budget. Twenty
  concurrent reservations against a budget of three hold exactly three.
- A lease is written as `pending` before its runtime may exist (`Start` is
  set only on that first acceptance), so a crash at any point leaves a row
  that recovery cleans.
- `cleanup` keeps capacity consumed until the caller confirms the runtime is
  gone. A failed stop never frees capacity.
- A release fence beats any later reservation or lease of the identity. A
  fence, reservation, lease or release from another validator for the same
  identity fails closed.
- An exact replay answers from durable state. A different document for an
  identity that already has one, a second lease for one hold, a lease whose
  resources or parties differ from its hold, or a different renewal with the
  same sequence is `ErrSandboxConflict` (signer equivocation, no receipt).
- An unrenewed lease is moved to cleanup at expiry plus grace, never
  before. A renewal that arrives after expiry is not applied.
- Restart recovery tears down every lease whose runtime may exist and
  answers `failed/miner_restart`, as `deployment.v4` endpoints are today.

## How the contract was reconciled with the target workload

The first customer workload is agent benchmark and data-generation traffic:
thousands of short-lived sandboxes per day, hundreds concurrently, from
public OCI images, with exec, file transfer, TTL heartbeats, egress to the
customer's model endpoint, secrets for that endpoint, and kernel isolation.
An earlier draft of this lane allowed only an `egress-deny-v1` network policy
and no environment at all. That would have made the miner-facing contract
unusable for that workload without a version bump, so v1 now carries every
network mode and a declared customer environment. A miner that cannot yet
enforce a mode or deliver the environment refuses with a non-fault code; it
never silently weakens the policy. An earlier revision of this slice also
signed plain, non-secret `env` values. The target workload passes secrets in
ordinary environment variables and requires that they are never logged or
listed, so v1 now routes the whole customer environment through
`secret_env` and fails closed until sealed delivery exists.

| Requirement | This slice | Later |
| --- | --- | --- |
| Create from a public OCI image, digest pinning | `image_reference` + `image_digest` | image cache, registry credentials, prefetch: miner backend and validator |
| Create from a Dockerfile, or from a snapshot; fork N | not in v1 | new source kinds in a later schema version |
| Resource request per sandbox, billed as requested | `resources` with bounds | usage metering |
| Egress `public` / `none` / `allowlist` at create | all three modes in the contract; exact hostnames and CIDR prefixes, no wildcards | miner enforcement; gateway wildcard expansion; runtime policy change needs a new document |
| Secrets in env, never logged or listed | every customer variable is a `secret_env` name bound to a sealed bundle digest; signed `env` must be `{}`; miners refuse sealed bundles with `secret_delivery_unsupported` | sealed bundle format and delivery path; gateway never echoing values in get or list responses |
| Kernel isolation (gVisor, Kata or Firecracker); nested Docker | `isolation` class required | backend, nested Docker conformance tests |
| TTL with heartbeat; delete at expiry, not stop | lease expiry, renewal, release, sweep | customer TTL and heartbeat in the API gateway |
| Idempotent create and delete | exact replay idempotent; release idempotent | `Idempotency-Key` handling in the API gateway |
| Quota visible; 429 with Retry-After when full | per-miner budget, `capacity_exhausted` | fleet quota and 429 in the API gateway |
| Exec with server-side timeout, files, background processes | not in this slice | validator-signed sandbox runtime request path |
| Sandbox lost on miner restart | explicit `miner_restart` | stateful resume needs backend state attestation |

## Web deployment path preservation

- No member, decoder or signing rule of `deployment.v4`,
  `subnet-synapse.v3`, `static-*-v1` or `edge-runtime-request.v1` changes.
  Tests decode the real `deployment.v4` and static fixtures against the
  sandbox types and the reverse, and both fail.
- No change to `assignments`, `endpoint_incarnations`,
  `endpoint_deactivation_fences`, `static_assignments` or any edge table; a
  test compares their definitions before and after enabling the lane and
  across a reopen.
- No flag, route, capability feature or scheduler change in this slice.
  Sandbox leases are score-neutral.

## Cross-repository parity plan

The public repository owns these miner-facing contracts. Private code may
only consume a byte-identical copy.

1. **This slice (public).** Go vocabulary, documents and durable store, with
   golden vectors that pin canonical bytes, digests and signatures from
   fixed test seeds.
2. **Private vendor sync (no behavior).** Sync the public tree byte-for-byte
   into the private vendored copy, stage the Go packages with only the module
   path rewritten, and classify the five new stems and `pkg/sandbox` as
   public protocol in the ownership map before any private code imports them.
   Gate: the existing public/private split checker, plus the Go vectors
   reproduced from the staged copy.
3. **Public Python models and schemas.** Strict Pydantic models, generated
   JSON Schemas under `contracts/schemas`, canonical fixtures under
   `contracts/fixtures`, and negative fixtures, generated from the Go vectors
   and checked to reproduce them. The vectors stay in `pkg/protocol/testdata`
   until the private ownership map classifies the stems, so the public
   contract inventory does not change before the private side can accept it.
4. **Miner agent lane (public, default off).** `--sandbox-leases off` by
   default; routes, capability feature, backend interface with isolation and
   egress enforcement, a separate resource budget from web replicas, and a
   test that the feature list and routes are unchanged when off.
5. **Validator placement and API gateway (private, default off).** Placement,
   write-ahead runtime table, renewal loop, verified capacity ledger, and the
   mapping from customer API requests to these documents.

Every step is a separate pull request with a "flag off means byte-identical
behavior" test.

## Known limits

- No TEE. Isolation from the miner operator is not provided; capacity checks
  are behavioral evidence, not proof.
- Sandbox state is not kept across a miner restart.
- Snapshots, forks, exec, file transfer and inbound exposure are not part of
  this slice.
- Customer environment cannot be delivered yet: every lease that declares
  variables is refused with `secret_delivery_unsupported` until the sealed
  bundle path lands.
- Egress allowlists match exact hostnames and CIDR prefixes only; no
  wildcard or suffix matching.
