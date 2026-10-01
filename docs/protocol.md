# Protocols and identity binding

`deployment.v4` is the only assignment ticket and receipt version. It keeps the
exact miner HTTPS identity and leaf-certificate pin of the former v3 ticket,
replaces the synthetic hidden challenge with the organic OCI workload,
`small-v1` resources and the app health predicate, and is defined in
[`organic-contracts.md`](organic-contracts.md). `deployment.v1`-`v3` and the
synthetic challenge were never live and are retired without mixed-version
support; no Go or Python decoder accepts them.

Messages that embed a ticket or receipt (`deploy`, `deploy-response`,
`status-response`, `bridge-assign`) are `subnet-synapse.v3`; the other neuron
messages (capabilities, status and deactivate requests, registration, chain
state) stay `subnet-synapse.v2`; the endpoint-incarnation-bound health
observation is the message-scoped `subnet-synapse.v3`; service-key
attestations are `service-binding.v2`. Health v3 requires the exact endpoint ID
and rejects v2 reports because a stable replica label can be replayed against a
later generation. The immutable v1/v2 schemas and fixtures remain available
only to identify legacy state and are not reinterpreted as the new shape.
Unknown fields are rejected by both Pydantic and Go bridge decoders. Current fixtures are consumed by both
languages, and generated schemas are regenerated and diff-checked in CI.

## Bittensor v11 transport

Bittensor v11 no longer ships the legacy Axon/Dendrite/Synapse networking classes. The semantic Synapses in this repository are strict Pydantic JSON contracts over pinned HTTPS in live mode:

- `CapabilitiesSynapse`: challenge-bearing miner capabilities and hotkey-signed Go service-key binding
- `DeploySynapseV3`: current block, authenticated validator identity/binding, and one exact Go-signed `deployment.v4` ticket
- `StatusSynapse`: endpoint-incarnation status owned by the assigning validator
- `DeactivateSynapse`: idempotent endpoint cleanup owned by the assigning validator

A validator assigns `deployment.v4` work only to a miner whose capability
feature list advertises `organic-oci-v1`, which the Go agent reports only when
its verified OCI runtime is configured. The retired `probe-attestation-v1`
feature is neither advertised nor required: the miner agent signs
`miner-probe-attestation` v2 for validator-authorized organic probes only.

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

New assignments require a current, unambiguous chain identity and service
binding. Deactivation remains bound to the exact signed miner identity of the
original assignment; a rebound or ambiguous identity cannot authorize new
work or redirect cleanup.

Registrations reach the Go control plane as `miner-registration.v2`, or as
`miner-registration.v3` (protocol `subnet-synapse.v3`, adding the
handshake's normalized capability `features`) when the runtime advertises
the control feature `miner-registration-v3`. Capability-gated placement (for
example `organic-static-v1`) reads only v3 features; v2 grants none.

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

It also binds deployment ID, replacement generation, artifact digest, manifest key, destination miner, route, unpredictable assignment nonce, OCI workload, `small-v1` resources, app health predicate, and wall-clock issue/expiry.

The miner neuron checks the btauth caller and current metagraph, UID, network/netuid, epoch derivation, block window, and that the ticket pin equals the certificate it is currently serving. The Go agent then verifies the validator’s Ed25519 ticket signature, exact authenticated caller/miner identity, exact UID presence/value, current block, validator service key, its own miner service key, HTTPS axon, and configured pin before downloading anything. Network-facing paths reject every non-`deployment.v4` ticket, missing pins, and pin downgrades.

Go emits RFC3339Nano timestamps. Python deliberately preserves signed ticket and receipt timestamps as strings: coercing them to Python `datetime` would truncate nanoseconds and invalidate an otherwise correct Go signature.

## Receipt

Receipts bind deployment, generation, assignment nonce, miner, replica ID, endpoint ID, image digest, manifest key, route host, lifecycle stage/timestamps, and the exact `subnet` value copied from the ticket. The miner Go service signs them with its bound service key.

The assigning validator verifies the signature with the capability-bound miner
key and compares every assignment field to its retained ticket. A valid
signature on a stale nonce, another hotkey/UID, another generation, or a
modified subnet binding is fraud and can zero trust. The returned endpoint
must match the ticket-bound incarnation. Runtime/container IDs never cross
this boundary.

Miner lifecycle timestamps are diagnostic. Scoring uses independently observed
timing and health, so a miner cannot improve its weight by forging fast timestamps.

## Miner replay and recovery

The miner agent durably binds each assignment nonce and endpoint incarnation to
the exact signed ticket and receipt. A replay with different signed identity
fails closed. After a miner-agent restart, retained local runtime mappings are
recovered or cleaned before readiness.

## Organic edge transport

The edge forwards ordinary app traffic with the section 8 semantics of the
organic deployment contract: methods `GET, HEAD, POST, PUT, PATCH, DELETE,
OPTIONS` (others `405`), byte-exact escaped path and raw query (printable
ASCII, else `400`), request bodies fully buffered up to 1 MiB (`413`), and
responses capped at 16 MiB of encoded bytes (`502`). Content-Encoding is end
to end: no hop adds `Accept-Encoding` or decodes a response. Every client
`X-Miss-*`, `CF-*`, `X-Trusted-*`, `Forwarded` and `X-Forwarded-*` header is
dropped; the app receives exactly one `X-Forwarded-For`, `X-Forwarded-Host`
and `X-Forwarded-Proto`, `Host: <route_host>` (from the signed ticket at the
miner), and every other end-to-end header. App responses keep status, cookies,
redirects and encodings; app-supplied `X-Miss-*` headers are removed. There is
no automatic retry of a failed upstream request.

Every request to a network-bound replica carries `X-Miss-Edge-Authorization`
(`edge-runtime-request.v1`, signed by the validator Go service key). The miner
agent verifies it against the addressed endpoint's retained ticket, rejects a
reused nonce inside the freshness window, and answers `401` without contacting
the container on any failure. The Python axon forwards the header verbatim and
refuses a request without exactly one such header before reading its body.
The Go agent routes the runtime prefix outside `ServeMux`, whose path
cleaning would redirect `//` or `/./` instead of forwarding them.

An authorized hidden probe addresses the exact published miner replica. An
origin response is not miner evidence and carries `X-Miss-Edge-Upstream:
origin`, never `replica`.

A validator hidden probe presents `X-Miss-Organic-Probe-Authorization` (base64
of `organic-probe-authorization.v1`). It binds the exact method and path, no
query, the named endpoint and generation, a fresh timestamp, and a one-time
nonce; the validator hotkey signature and current chain identity must verify.
The miner agent strips the verified authorization before contacting the app.

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
