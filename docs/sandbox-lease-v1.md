# Sandbox leases (`sandbox-lease-v1`): contract slice 1

Status: **partial, off by default, not customer-ready.** The signed
documents, the miner-side durable holds and leases, the miner agent lane
(handlers, routes and backend interface), Python neuron forwarding, and a
gVisor backend ([miner-sandbox-gvisor-backend.md](miner-sandbox-gvisor-backend.md))
exist. The backend is not wired into the agent yet. No validator
scheduling, no customer API and no scoring exist yet, so the lane cannot be
enabled: `--sandbox-leases on` refuses to start. With the default
`--sandbox-leases off`, every existing binary behaves exactly as before.

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

Validator receipt acceptance is bound to the complete signed document, not
only its digest and outer identity. A lease receipt must name that lease's
derived `lease_id`. A renewal receipt must name the renewed `lease_id`; a
`ready` or `accepted` renewal receipt must echo its `renewal_seq`. A terminal
renewal receipt may report an earlier durable sequence when the renewal was
not applied. A signed contradiction of an exact document is miner fraud.

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
  before when its runtime is already running. A renewal that arrives after
  expiry is not applied. If a pending runtime finishes creation at or after
  expiry, startup atomically fences it for cleanup and destroys it before
  answering `expired`; a concurrent renewal cannot revive that fence.
- Restart recovery tears down every lease whose runtime may exist and
  answers `failed/miner_restart`, as `deployment.v4` endpoints are today.

## Miner agent lane (`pkg/miner/sandbox.go`, `cmd/miner-agent/sandbox.go`)

`SandboxLane` admits each validator document with the matching
`VerifyBoundSandbox*V1` check against the validator service key from the
verified hotkey binding, then requires the document to name this agent's
service key, transport identity and hotkey. It applies the document to the
durable lane and signs a `sandbox-lease-receipt` with the miner service key,
including refused and failed receipts.

- **Commit:** the lease is durable as `pending` before the backend creates
  anything. A lease that declares customer environment is refused with
  `secret_delivery_unsupported`, and a lease the backend cannot enforce
  exactly with the backend's non-fault code; neither creates a sandbox. A
  failed create answers `runtime_start_failed`; a backend may answer a
  non-fault code such as `image_unavailable` but can never relabel its own
  fault. Every sandbox name is `runtime.InstanceName(lease_id)`.
- **Bounded answer:** the start runs in the background under the lease's
  lock. Commit answers its outcome if it ends within 60 seconds, otherwise
  `accepted` (the lease is `pending`), well inside the roughly two-minute
  transport hops, so a slow image pull is never an unknown outcome. The
  validator learns the outcome from its next renewal receipt (`accepted`
  while pending, then `ready` or `failed`); replaying the exact lease
  answers the same way. A replay during the start
  waits for that start again, up to the same bound, and never starts a
  second sandbox; afterwards it answers `ready`, `failed` or the lease's
  terminal stage.
- **Release, Sweep, Recover:** each moves leases to `cleanup` durably, then
  destroys their sandboxes. A failed destroy keeps the lease in `cleanup`,
  still consuming capacity, until a later sweep (every 10 seconds) destroys
  it.
- **Release acknowledgement:** a `released` receipt for a release document
  is signed only after every sandbox of the identity is destroyed. While a
  destroy fails, the fence is already durable but the miner answers the
  retryable bridge error `503 cleanup_pending` with no receipt; the
  validator keeps the identity in `cleanup_pending` and replays the same
  release. A lease or renewal receipt for a lease in `cleanup` reports the
  lease's terminal intent (for example `released`) and is not a cleanup
  acknowledgement: validators free capacity only on a release receipt or
  after the lease expiry plus grace. A release that lands while a sandbox is being created does not wait: the
  fence is durable, the release answers `503 cleanup_pending`, the start
  destroys its sandbox once it sees the fence, and a replay of the release is
  acknowledged. Sweep and orphan reconciliation likewise skip a lease whose
  start or teardown is in progress, and retry it on the next sweep. Restart recovery destroys every
  sandbox that may exist before the agent serves.
- **Shutdown:** on SIGTERM the lane closes while the API drains (15 seconds
  for both). From then on a lease commit, release or sweep is refused with
  the retryable bridge error `503 sandbox_lane_closed` and nothing written,
  a Commit waiting for its start answers the lease's durable stage, and a
  create in progress is cancelled without recording a failed start. A
  release admitted before the close still writes its fence and answers `503
  cleanup_pending` while its destroy is unfinished, or its `released`
  receipt; only its destroy is cancelled. The lane waits for its in-flight
  starts, releases and sweeps, and after the agent's replica cleanup a
  Recover with its own 60-second budget destroys every sandbox and ends
  pending and running leases as `failed/miner_restart`. A start that ignores
  cancellation keeps its lease locked; that Recover reports it busy and the
  next start's recovery destroys it.
- **Backend interface (`SandboxBackend`):** `Budget`, `Unsupported`,
  `Create` (idempotent per instance name), `Destroy` (idempotent),
  `Instances` (every sandbox the backend holds, with its lease ID) and
  `Reclaim` (free unused storage). The only implementation is the gVisor
  backend in `pkg/sandboxbackend`; the lane never falls back to plain Docker.
- **Orphans:** Sweep and Recover list the backend's sandboxes and, under each
  lease's lock, destroy every one whose lease is unknown, terminal, or not
  tied to its instance name. Recover then calls `Reclaim`.
- **Dedicated budget:** the lane can be constructed only if the backend
  reports a dedicated cgroup v2 subtree with finite `cpu.max` and
  `memory.max`, disk and count limits covering its configured budget.
  Construction requires explicit `AgentCgroup` and `DeploymentCgroup` paths;
  missing, root, malformed, or overlapping paths fail closed in
  `VerifySandboxCgroup`. The cgroup path and its `cpu.max` and `memory.max`
  files are opened without following symlinks, so symlinks cannot substitute
  limits from an unrelated subtree or ordinary file. These are trusted
  configuration values: the future backend/activation review must prove
  they are the actual agent and web replica subtrees, not merely arbitrary
  disjoint names, and verify the cgroup mount/hierarchy itself. Bind mounts
  or a substituted cgroup root are outside this check. The gVisor backend
  checks each sandbox's actual process cgroup and limits below its slice;
  the agent and deployment cgroups remain trusted configuration until the
  activation change. `--sandbox-leases on` still refuses to start and no
  isolation claim has been made live.
- **Bridge routes** (only with an enabled lane, behind the bridge HMAC):
  `POST /v1/sandbox/reservations`, `/v1/sandbox/leases`,
  `/v1/sandbox/renewals`, `/v1/sandbox/releases`. The envelope is
  `subnet-sandbox-synapse.v1`: `protocol`, `request_id`, `current_block`,
  `caller_hotkey`, `binding_verified`, `validator_binding`, `document`; the
  answer is `protocol`, `request_id`, `receipt`. Equivocation is
  `409 sandbox_conflict` with no receipt.

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
4. **Miner agent lane (public, default off).** This PR adds routes, the
   capability feature, a separate budget interface and a backend seam. No
   isolation backend or operator budget flags shipped in that step; the
   gVisor backend followed separately, and its activation flags follow the
   host-preflight package. Until then `--sandbox-leases on` refuses to
   start. Flag-off routes and features are unchanged.
5. **Neuron transport (public, default off).** Done in the separate transport
   change: `subnet-sandbox-synapse.v1` forwarding in the Python miner axon
   and validator bridge; see [Neuron transport](#neuron-transport-subnet-sandbox-synapsev1).
   Until the miner lane has a real backend and advertises the feature, the
   validator refuses every document before miner contact.
6. **Validator placement and API gateway (private, default off).** Placement,
   write-ahead runtime table, renewal loop, verified capacity ledger, and the
   mapping from customer API requests to these documents.

Every step is a separate pull request with a "flag off means byte-identical
behavior" test.

## Neuron transport (`subnet-sandbox-synapse.v1`)

Off by default in both neurons (`--sandbox-leases off`). Off, neither neuron
registers a sandbox route: the axon answers 404 for `/api/v1/sandbox/*` and
the validator bridge for `/v1/miners/{hotkey}/sandbox-*`, exactly as before.
The organic, static, deactivate and runtime routes are unchanged either way.

The Python neurons authenticate and forward; they never build, sign or choose
anything. Each route carries exactly one validator document kind:

| Validator bridge (from the Go runtime) | Miner axon (btauth) | Go miner agent (miss-bridge/1) | Document schema |
| --- | --- | --- | --- |
| `POST /v1/miners/{hotkey}/sandbox-reservations` | `POST /api/v1/sandbox/reservations` | `POST /v1/sandbox/reservations` | `sandbox-reservation-ticket` |
| `POST /v1/miners/{hotkey}/sandbox-leases` | `POST /api/v1/sandbox/leases` | `POST /v1/sandbox/leases` | `sandbox-lease-ticket` |
| `POST /v1/miners/{hotkey}/sandbox-renewals` | `POST /api/v1/sandbox/renewals` | `POST /v1/sandbox/renewals` | `sandbox-lease-renewal` |
| `POST /v1/miners/{hotkey}/sandbox-releases` | `POST /api/v1/sandbox/releases` | `POST /v1/sandbox/releases` | `sandbox-lease-release` |

Envelopes (`src/misscomputer_subnet/sandbox_transport.py`), all with
`protocol: subnet-sandbox-synapse.v1` and the document as a JSON object passed
through unchanged:

- runtime → validator: `{protocol, request_id, document}`;
- validator → miner: `{protocol, request_id, current_block, caller_hotkey, validator_binding, document}`;
- miner → Go agent: the same plus `binding_verified: true`;
- every answer: `{protocol, request_id, receipt}`, the miner-signed
  `sandbox-lease-receipt`.

The miner-agent half of this table is the contract step 4 implements; no
released agent serves it yet.

Checks before the document leaves each hop:

- **Validator.** Miss-bridge HMAC from the runtime; the document's `schema`
  matches the route; its `subnet` binding resolves to the current published
  handshake of that exact miner (axon, UID, transport, leaf pin, service
  keys, chain window), as for a static ticket; the miner advertises
  `sandbox-lease-v1`, else `409 sandbox_capability_unsupported` before any
  contact (ineligible, not a fault). Delivery is btauth over the pinned leaf.
- **Miner.** btauth caller; envelope protocol; `schema` matches the route;
  `miner_id` equals `subnet.miner_hotkey`; the static-ticket validator
  service binding and Bittensor identity checks; then the priority gate. A
  Go agent with the lane off answers `sandbox_disabled`, relayed with its
  code.
- **Both, on the way back.** The answer must be a receipt for this document
  (`schema`, `document_schema`, `sandbox_id`, `generation`, `miner_id`), else
  `502 sandbox_receipt_mismatch`. The Go runtime verifies the receipt
  signature and document digest.

Malformed documents are refused with stable codes
(`sandbox_document_kind_mismatch`, `sandbox_document_invalid`) that never
echo document members. Full document validation, signatures and
`VerifyBoundSandbox*V1` admission stay in Go.

## Existing-hold-only reservation replay (opt-in)

`--sandbox-reservation-replay on` is independently **off by default** on the
Go miner agent, Python miner, and Python validator, and requires
`--sandbox-leases on` at every hop. The miner advertises
`sandbox-reservation-replay-v1` only when its agent and neuron both enable it.
Missing capability or mixed versions fail closed; there is no ordinary
reservation fallback.

The reservation-only routes are:

- Validator loopback: `POST /v1/miners/{hotkey}/sandbox-reservations/replay`.
- Miner axon: `POST /api/v1/sandbox/reservations/replay`.
- Miner agent loopback: `POST /v1/sandbox/reservations/replay`.

They retain the existing v1 envelopes, actual-path HMAC/btauth and original
signed document. A fresh validator uses only authenticated, acknowledged,
exact publication history, plus a newly synchronized finalized chain view.
Staged, ambiguous and legacy records cannot authorize replay. Current
validator permit/UID and miner UID/axon must still match; every original
ticket and service-binding expiry remains enforced. A fresh capability
handshake verifies the same key and TLS leaf (the old leaf is checked before
sending the challenge), followed by another current-authority check.

With this feature enabled, one chain producer is independent of runtime
publication I/O. Its freshness budget is `max(5s, 3 * sync_interval)` and
configurations exceeding 30 seconds are rejected. Errors/staleness close
replay admission. Historical state never sets normal readiness or enables
scheduling: a freshly restarted validator with an unavailable runtime keeps
`/healthz` at 503. Shutdown cancels and joins replay requests and both loops.

The Go lane applies unchanged reservation admission, then reads the exact
hold, document/owner/resources/expiry, lease presence and release fence in
one consistent transaction. It never calls `Hold`, creates/renews a row,
expires state, or touches the backend. A signed `held` receipt is an
observation of that snapshot, **not** a promise the hold remains held when
the response arrives. Missing holds return `404 sandbox_replay_hold_absent`;
fenced and committed/non-held identities return typed 409 refusals. Expired
original authority is never extended. Ordinary sweeping and runtime-signed
release remain the only expiry/settlement owners.

For explicit mock chains only, both Python CLIs accept `--mock-tempo N` with
`--mock-uri`; the default remains 12, and live configuration rejects the flag.
A two-minute hold generally outlives the default mock ticket horizon. A
larger mock tempo (for example 180) is configuration, not proof of remaining
authority: outage acceptance must measure the unchanged original ticket,
both bindings and current blocks at each call. A generic 410 alone cannot
prove hold-time expiry because other expired authority can also return 410.
The local replay tests do not establish the disposable outage canary, host
isolation, nonce-store durability, or production activation.

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
