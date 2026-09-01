# Protocols and identity binding

Three deployment ticket versions coexist intentionally:

- `deployment.v1` is retained only for the standalone Go lab.
- `deployment.v2` is retained as the pre-TLS neuron identity shape and is rejected on live network paths.
- `deployment.v3` is mandatory across current neuron boundaries and adds the exact miner HTTPS identity and leaf-certificate pin.

The current neuron API is `subnet-synapse.v2`; service-key attestations are `service-binding.v2`. The immutable `.v1` schemas/fixtures remain available only to identify legacy state and are not reinterpreted as the new shape. Unknown fields are rejected by both Pydantic and Go bridge decoders. Current `.v2` fixtures are consumed by both languages, and generated schemas are regenerated and diff-checked in CI.

## Bittensor v11 transport

Bittensor v11 no longer ships the legacy Axon/Dendrite/Synapse networking classes. The semantic Synapses in this repository are strict Pydantic JSON contracts over pinned HTTPS in live mode:

- `CapabilitiesSynapse`: challenge-bearing miner capabilities and hotkey-signed Go service-key binding
- `DeploySynapse`: current block, authenticated validator identity/binding, and one exact Go-signed ticket
- `StatusSynapse`: endpoint-incarnation status owned by the assigning validator
- `DeactivateSynapse`: idempotent endpoint cleanup owned by the assigning validator

The miner capability feature list must advertise `probe-attestation-v1`: the Go
miner agent emits the mandatory per-replica `miner-probe-attestation` v1 header
for public assignment probes, and a validator refuses assignment eligibility to
any miner whose handshake omits the feature. This is a fail-closed admission
invariant, not a negotiation.

Remote requests use the SDK’s `bittensor.http_auth` btauth/1 signatures. The signed material binds the sender hotkey, receiver hotkey, nonce/timestamp, HTTP method, path, and exact body. Miners additionally require an active metagraph record, validator permit, configured minimum TAO stake, and rate/priority admission. HTTP is available only when both sides explicitly select the local/mock policy; live startup never silently downgrades.

Transport retries are bounded. A retry obtains a fresh btauth nonce while preserving the semantic request/ticket identity. Redirects and environment proxies are disabled. The Go agent returns a cached signed ready result only for the same durable endpoint incarnation; a different assignment nonce cannot reuse it.

### Permissionless TLS bootstrap

The metagraph supplies only a numeric IP and port. The transport scheme is a
local validator policy, never miner-controlled URL input. Before sending the
capability POST, the validator opens a bounded TLS connection to that exact
numeric endpoint with no workload body, captures the leaf DER certificate,
checks its validity and `CA:FALSE` constraint, and closes the socket. It then
builds a `CERT_REQUIRED` context that trusts only that exact leaf and uses it
for the capability POST. The hotkey-signed response must contain the lowercase
SHA-256 fingerprint of the same leaf. Thus a relay can forward the empty
bootstrap exchange, but its different certificate cannot satisfy the signed
pin. No public CA or operator allowlist is required. The pin is the
authorization identity; Go additionally requires the leaf's numeric IP SAN to
match the canonical axon before accepting registration, so its normal TLS
verifier and exact-pin check enforce the same identity before edge workloads.

Deploy, status, deactivate, and Go edge-to-miner runtime proxy requests rebuild
trust from the accepted public DER and verify the exact pin before writing a
request body. The non-CA leaf restriction prevents a pinned certificate from
acting as a trust anchor for attacker-selected descendants. Certificate DER is
bounded and durable but never logged; private-key material never leaves the
miner.

## Open miner snapshot admission

Miner discovery is permissionless: candidate admission uses only the configured
network/netuid and the current metagraph. Every active record other than the
configured validator's own hotkey, with a unique hotkey, UID, and normalized
valid public axon, is eligible; a chain-assigned validator permit is not a
miner-role filter. There is no allowlist, owner-selected set, or miner stake
floor in the validator discovery path. Invalid axons and peer identity conflict
groups are quarantined. Ambiguity involving the validator hotkey or UID rejects
the refresh.

Capability work runs through a deterministic rotating queue. CLI configuration
bounds workers, unique attempts per refresh, one attempt's duration, the whole
refresh duration, and deterministic exponential backoff. Claims rotate every
inspected identity; a full skipped scan preserves order and each claim leaves
the next identity at the head, preventing a slow prefix from starving later
identities. Whole-refresh cancellation is not recorded as a miner failure or
backoff, but its unresolved identity remains ineligible for new work until a
successful retry. A prior binding may carry forward only when its exact
hotkey/UID/normalized-HTTPS-axon/service-key/certificate-pin identity remains admitted and unexpired. A selected
failed identity is omitted until a later successful handshake.

Python first stages a monotonic metagraph view and Go stages the matching chain
state. Successful handshakes register exact identities, then one authoritative
miner-set message atomically commits the Go chain/miner pair; Python publishes
the same schedulable map only after that commit. Go validates duplicate hotkeys
and cross-hotkey UID/axon conflicts before changing the scheduler. New work is
resolved only from this current map and rechecked against current chain identity.
Retained handles are deactivate-only and require the exact authenticated
hotkey+UID+axon+service-key+TLS-pin identity of the issued assignment. Cleanup identity
admission does not require schedulability: it independently requires exactly
one active hotkey record, the assignment UID uniquely on chain, the unchanged
normalized assignment axon, the matching authenticated service key and leaf pin, and a
current binding. Duplicate hotkey/UID ambiguity or any rebind fails closed. A
third party duplicating the victim's axon quarantines new scheduling but does
not block cleanup to the victim's own otherwise unchanged exact record.

## Hotkey-signed service binding

A capability response signs canonical JSON with the Bittensor hotkey. The binding includes:

- role (`validator` or `miner`), network, netuid, hotkey, and current UID when known;
- the persistent Go Ed25519 service public key;
- role-specific transport identity: miners use `https` plus the canonical
  64-lowercase-hex SHA-256 leaf fingerprint; validator bindings use pinless
  `local` transport because their Go bridge is loopback;
- monotonic generation and block validity window;
- the validator’s unpredictable capability challenge; and
- the hotkey signature.

The miner capability challenge prevents replay of a captured response into a later discovery round. The validator binding uses `validator-service:<service-public-key>` as its purpose string and is refreshed with the current epoch/block. Go persists accepted bindings and exact certificate material and rejects generation rollback or same-generation service-key, transport, or certificate equivocation.

The binding does not make the Go key a Bittensor key. It proves that the registered hotkey authorizes that specific local Go service key for this subnet and block window.

## Bound assignment ticket

The validator Go service signs JSON with the `signature` field blank. The ticket contains the existing immutable deployment fields plus `subnet`:

- network and netuid;
- validator and miner hotkeys;
- miner UID when the metagraph provides it;
- normalized assignment-time HTTPS axon, transport, and exact accepted leaf pin;
- chain issuance block, derived epoch, and block expiry;
- validator Go service public key; and
- miner Go service public key learned in the hotkey-signed handshake.

It also binds deployment ID, replacement generation, image digest, manifest key, destination miner, route, unpredictable assignment nonce, hidden challenge path/hash, resource limits, health contract, and wall-clock issue/expiry.

The miner neuron checks the btauth caller and current metagraph, UID, network/netuid, epoch derivation, block window, and that the ticket pin equals the certificate it is currently serving. The Go agent then verifies the validator’s Ed25519 ticket signature, exact authenticated caller/miner identity, exact UID presence/value, current block, validator service key, its own miner service key, HTTPS axon, and configured pin before downloading anything. Network-facing paths reject `deployment.v1`, `deployment.v2`, missing pins, and pin downgrades.

Go emits RFC3339Nano timestamps. Python deliberately preserves signed ticket and receipt timestamps as strings: coercing them to Python `datetime` would truncate nanoseconds and invalidate an otherwise correct Go signature.

## Receipt

Receipts bind deployment, generation, assignment nonce, miner, replica ID, endpoint ID, image digest, manifest key, route host, lifecycle stage/timestamps, and the exact `subnet` value copied from the ticket. The miner Go service signs them with its bound service key.

The scheduler verifies the signature with the capability-bound miner key and compares every assignment field to its retained ticket. A valid signature on a stale nonce, another hotkey/UID, another generation, or a modified subnet binding is fraud and can zero trust. The returned endpoint must be the scheduler-derived endpoint incarnation. Runtime/container IDs never cross this boundary.

Miner lifecycle timestamps are diagnostic. Scoring uses validator-control elapsed time and independent health observations, so a miner cannot improve its weight by forging fast timestamps.

## Durable replay and recovery

SQLite WAL tables retain:

- btauth nonces and Python/Go loopback bridge nonces;
- assignment nonces, exact ticket JSON, status, and exact receipt JSON;
- endpoint incarnations and private runtime mappings;
- service bindings and generations;
- durable miner registrations containing the exact HTTPS axon, public leaf DER,
  signed pin, and binding generation;
- trust values and scoring observations.

Assignment nonce reservation and bridge replay reservation are transactional. Same-generation registration changes, including a different leaf pin, are rejected; a successful certificate rotation requires a higher binding generation and commits the binding, HTTPS axon, pin, and public DER together. Exact endpoint IDs cannot be overwritten with different ticket JSON. After a miner-agent restart, active private runtime mappings are loaded and cleaned before readiness. After validator-control restart, the control service captures an immutable startup recovery snapshot of all non-deactivated assignments before serving requests; miners re-register and cleanup is delivered only for a snapshot member whose exact signed identity — hotkey, UID, service key, normalized assignment-time axon, transport, and TLS pin — matches the registering miner. Assignments created by the running process never enter the snapshot, and legacy or mismatched identities fail closed and remain pending instead of being delivered to a rebound axon or falsely retired.

`GET /v1/recovery` reports `non_deactivated_assignments`, the exact count of every durable assignment not yet marked deactivated, plus `pending_startup_assignments`, the unresolved members of the immutable startup recovery snapshot. The first count deliberately includes healthy current work as well as rows retained for retry after cleanup failure; its name does not imply that every row is a restart orphan.

## Edge route lifecycle

`edge-route.v1` is an internal Go control-to-router authorization object, not a
miner or Python contract. The validator service key signs a short-lived action,
nonce, full exact ticket, and (for pending registration/activation) the full
miner-signed ready receipt. The router independently verifies both signatures,
derived replica/endpoint IDs, deployment Host policy, current ticket validity
for publication, durable replay state, generation monotonicity, and the
control-derived upstream and exact pinned leaf. Deactivation requires the exact ticket signature but
remains possible after its assignment eligibility window expires. Persisted
deactivation tombstones prevent late-success publication.

## Loopback bridge contract

The Python↔Go bridge uses headers:

```text
X-Miss-Bridge-Version: 1
X-Miss-Bridge-Timestamp: <Unix nanoseconds>
X-Miss-Bridge-Nonce: <random value>
X-Miss-Bridge-Signature: HMAC-SHA256(...)
```

The signature covers `miss-bridge/1`, timestamp, nonce, uppercase method, escaped path plus query, and SHA-256 body digest. Default freshness is 10 seconds with two seconds of future skew. Bodies and responses are capped at one MiB. Errors use a stable envelope:

```json
{"error":{"code":"identity_mismatch","message":"...","retryable":false}}
```

Secrets must be at least 32 bytes, come from external file/env configuration, and differ per host. The mock workflow mounts each miner secret only into its own container.

## Artifact layout

```text
v1/blobs/sha256/<layer digest>
v1/manifests/<image digest>.json
```

Fetch requires the manifest key to be the canonical key for the signed image
digest. It rejects unknown/trailing/non-canonical manifest JSON, unsupported
schema/media types, malformed digests, and invalid layer counts before pulling
layers. The manifest identity and every downloaded layer are rehashed, and
every layer length must equal its signed manifest size. Any mismatch fails the
assignment closed before runtime creation. The format remains intentionally
OCI-like rather than a complete registry API so the existing filesystem and
S3-compatible adapters stay shared by the validator and miners.

Cleanup accepts an explicit list of exact object keys and has no prefix/list
deletion operation. Delete is idempotent. Production miners do not need delete
permission because deletion is a separate capability used only by controlled
publication/integration workflows.
