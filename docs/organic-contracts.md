# Organic deployment contracts

This is the implementer's reference for the public miner and validator wire
contracts. Customer API, operator runtime, edge-backend and serving-window
implementations are maintained in the private operator repository. It lists
the public documents, their schemas and fixtures, and the rules each public
implementation must keep.

The synthetic flow was never live and has been retired without mixed-version
support. Current ticket, receipt, and verifier rules are documented here and
in [`protocol.md`](protocol.md).

## Sources of truth

| What | Where |
|---|---|
| Python models (schema source) | `src/misscomputer_subnet/organic_contracts.py` (`CONTRACT_MODELS`, public stems only) |
| JSON Schemas (generated) | `contracts/schemas/<stem>.schema.json` |
| Golden fixtures | `contracts/fixtures/<stem>.json` |
| Cross-language vectors | `contracts/fixtures/organic-contract-vectors.v1.json` |
| Negative corpus | `contracts/negative/<stem>/<case>.json` (`expect` = `schema` or `model`) |
| Generator | `python tests/python/organic_contract_context.py --write` |
| Go mirrors | `pkg/organic` (miner and validator protocol), `pkg/protocol/deployment_v4.go`, `pkg/artifact/manifest_v2.go`, `pkg/neuron/contracts_v3.go` |
| Tests | `tests/python/test_organic_contracts.py`, `pkg/organic/contracts_test.go` |

Never hand-edit a schema or fixture: change the model or the generator, run the
generator, and commit the regenerated tree. Both suites fail on any drift.
`infra` vendors `contracts/` byte-identically, as for every other contract.

## Inventory

| Stem | Producer -> consumer | Python | Go |
|---|---|---|---|
| `artifact-manifest.v2` | promoter -> artifact store -> runtime, miners, origin | `ArtifactManifest` | `artifact.ManifestV2` |
| `deployment-ticket.v4` | runtime -> miner | `DeploymentTicketV4` | `protocol.TicketV4` |
| `deployment-receipt.v4` | miner -> runtime | `DeploymentReceiptV4` | `protocol.ReceiptV4` |
| `deploy.v3`, `deploy-response.v3`, `status-response.v3`, `bridge-assign.v3` | validator <-> miner (`subnet-synapse.v3`) | `DeploySynapseV3` ... | `neuron.DeploySynapseV3` ... |
| `edge-runtime-request.v1` | edge -> miner (signed object of `X-Miss-Edge-Authorization`) | `EdgeRuntimeRequest` | `organic.EdgeRuntimeRequest` |
| `active-assignment-manifest.v2` | central exporter -> public validators | `ActiveAssignmentManifestV2` | `organic.ActiveAssignmentManifestV2` |
| `organic-probe-authorization.v1` | validator -> edge | `OrganicProbeAuthorization` | `organic.ProbeAuthorization` |
| `miner-probe-attestation.v2` | miner agent -> validator (via edge) | `MinerProbeAttestationV2` | `organic.ProbeAttestationV2` |

The miner capability feature is `organic-oci-v1` (`organic.CapabilityFeature`,
`neuron.FeatureOrganicOCIV1`).

## Conventions every implementation must keep

- **Decoding.** Go uses `organic.DecodeStrict` (HTTP bodies) or
  `organic.DecodeCanonical` (content-addressed or signed documents); Python
  uses `parse_document` / `parse_canonical_document`. Both refuse duplicate,
  unknown, case-folded or missing members, non-integral numbers, non-ASCII and
  trailing data. Plain `json.Unmarshal` is not a contract parser.
- **Timestamps** are canonical Go RFC3339Nano UTC strings: `Z` suffix and no
  trailing fractional zeros (`2026-09-26T00:14:06.12Z`, never `.120Z`).
  The public Python contract helper `organic_contracts.format_timestamp` uses
  the same form. Signed ticket and receipt timestamps are Go `time.Time`
  values and stay exact strings in Python.
- **Signed ticket/receipt bytes** are Go `json.Marshal` of `TicketV4` /
  `ReceiptV4` with an empty (omitted) signature, exactly as v3. Their struct
  field order is therefore part of the wire contract; the golden signatures
  fail if it changes.
- **Nullable members are always present.** `null` is written, never omitted,
  except `signature` on an unsigned ticket or receipt.
- **Digests.** `*_digest` members are `sha256:<hex>`; `*_sha256` members are
  bare lowercase hex. Self-digests (`window_digest_sha256`,
  `assignment_digest_sha256`, `manifest_digest_sha256`) hash the canonical
  document without that member.

## Lifecycle bridge (`protocol.Ticket` / `protocol.Receipt`)

The miner agent and public protocol use the lifecycle types
`protocol.Ticket` and `protocol.Receipt`. A lifecycle value is
exactly a `deployment.v4` `TicketV4` / `ReceiptV4`:

- JSON encodes exactly as `TicketV4` / `ReceiptV4` (same signed bytes, same
  ticket digest) and decodes strictly as them, so a document carrying
  `challenge_path`, `challenge_sha256`, a v3 health shape, any other version or
  any unknown member is rejected. deployment.v1-v3 have no Go type any more.
- The v4-only members live in `Ticket.Organic` (`Workload`, `Resources`,
  `Health`) and `Receipt.LoadedImageConfigDigest` / `Receipt.ErrorCode`.
- `Ticket.V4()` / `TicketFromV4`, `Receipt.V4()` / `ReceiptFromV4` convert
  losslessly. `SignTicket`, `VerifyTicket`, `VerifyTicketSignature`,
  `SignReceipt` and `VerifyReceipt` delegate to the `*V4` functions;
  `ReceiptMatchesTicket` and `TicketDigest` accept lifecycle values.
- `VerifyBoundTicket` verifies a `TicketV4` against the request-local network,
  hotkeys, UID and chain block; `miner.Agent.ValidateSubnetTransport` requires
  a bound `deployment.v4` row for status, deactivation and runtime ingress.
- Envelopes pin the ticket generation: `subnet-synapse.v3`
  (`neuron.LocalAssignRequestV3`, `BridgeAssignRequestV3`, `DeployResponseV3`,
  `StatusResponseV3`) carries only `deployment.v4`, and it is the only
  assignment envelope: the synthetic `subnet-synapse.v2` deploy, deploy
  response, status response and bridge-assign types are deleted.
  `cmd/miner-agent` `POST /v1/assignments` refuses any other envelope and
  answers a signed failed v4 receipt as a result so its `error_code` reaches
  the assigning validator; `POST /v1/status` always answers `StatusResponseV3`.
  The bridge sends tickets in `BridgeAssignRequestV3`.

## Signing and digest rules

| Value | Rule | Go | Python |
|---|---|---|---|
| `artifact_digest` | sha256 of the exact stored manifest bytes (canonical JSON + `\n`, <= 1 MiB) | `artifact.MarshalManifestV2`, `ParseManifestV2` | `artifact_manifest_bytes`, `artifact_digest`, `parse_artifact_manifest` |
| ticket digest | `sha256:` + sha256(canonical signed ticket) | `protocol.TicketDigestV4` | `ticket_digest` |
| edge request | Ed25519 (validator Go service key) over `.../edge-runtime-request/v1/ed25519` NUL canonical(request object); header `v1 ts=<unix-nanos>,nonce=<32 hex>,sig=<128 hex>`; fresh 10 s, future skew 2 s | `SignEdgeRuntimeRequest`, `VerifyEdgeRuntimeRequest` | `edge_runtime_request_message`, `verify_edge_runtime_request` |
| probe authorization | validator hotkey (sr25519) over `.../organic-probe/v1` NUL canonical({endpoint_id, generation, issued_at, method, nonce, path}) | `OrganicProbeMessage` (message only) | `organic_probe_message`; verify with `bittensor.sp_core.verify` |
| attestation v2 | Ed25519 (miner service key) over `.../miner-probe-attestation/v2` NUL canonical(the twelve signed members) | `SignProbeAttestationV2`, `VerifyProbeAttestationV2` | `miner_probe_attestation_v2_message`, `verify_miner_probe_attestation_v2` |
| response header digest | sha256(canonical list of `[lowercase name, value]`, stably sorted by name) | `ResponseHeaderSHA256` | `response_header_sha256` |

## Contract defaults chosen here

Where the frozen text left a detail open, these defaults are now the contract.
The owner may revise any of them deliberately; implementers must not diverge.

1. **Reserved TEE fields.** `attestation` and `encrypted_image_key` "must be
   absent in the MVP", so they are not members of `deployment.v4` at all; a
   TEE design adds them with a new ticket version.
2. **`status-response.v3.receipt`** is always present: `null` for `absent` /
   `processing`, required and stage-matched for `accepted` / `ready` /
   `failed`, either for `deactivated`.
3. **Edge request object.** `path` is the raw escaped application path after
    `/runtime/<endpoint_id>` (starting `/`), `query` the raw query without
    `?` (empty when absent), `body_sha256` bare hex of the exact body (the
    empty body included), `timestamp` Unix nanoseconds equal to the header
    `ts`.
4. **Manifest v2** keeps the v1 top-level publication fields with purpose
    `active_assignment_manifest_publication_v2`, may list zero deployments,
    and each replica publishes `miner_tls_certificate_sha256`,
    `ticket_digest`, `receipt_digest`, `activated_at_epoch`,
    `expires_at_epoch`; attestation requirement `miner_service_key_v2`.
5. **Probe authorization** `issued_at` is whole-second UTC; the header
    `X-Miss-Organic-Probe-Authorization` carries base64 of the canonical
    document (the scoring and edge tracks own the transport).
6. **Attestation v2** signs exactly the twelve members named by the contract
    (not `schema`/`schema_version`); `observed_at` is canonical Go UTC.

## Open items for the owner

- **Probe authorization.** The validator hotkey signs the public
  `organic-probe-authorization.v1` document. Miners and validators must use
  the same canonical message and verification rules; see `docs/protocol.md`,
  "Organic edge transport".
- **Response header digest scope.** The header set a miner hashes is the
  container's end-to-end response headers before any hop adds its own;
  validators cannot recompute it through the edge provider, so it is
  miner-side evidence only.
- **Trust-policy / envelope / chain-state / snapshot v2.** Only the manifest
  v2 document is defined here; the scoring track owns the v2 publication
  pipeline around it (the v1 trust policy admits only the v1 purpose).

## Integration checklist

Each item names its owning track and the contract artefact it must consume.
"Contract" items are closed by this change.

### Contracts (closed here)

- [x] Public miner and validator documents have generated schemas, golden
  fixtures and Python + Go types; both languages round-trip the public golden bytes.
- [x] Negative corpus for ticket v4, receipt v4 and artifact-manifest v2,
  including retired tickets and unknown members, is rejected by both languages.
- [x] Go and Python reproduce `artifact_digest`, the ticket
  digest, the edge request signature, the probe authorization message and the
  attestation v2 signature from `organic-contract-vectors.v1.json`.

### Miner (`pkg/miner`, `cmd/miner-agent`, `miner.py`)

- [ ] Advertise `organic-oci-v1`; accept only `subnet-synapse.v3` envelopes
  with `deployment.v4` tickets (`VerifyTicketV4`). Go side done:
  `cmd/miner-agent` accepts `neuron.LocalAssignRequestV3`; `miner.py` must
  forward `DeploySynapseV3` as it (plus `binding_verified`).
- [ ] Sign `protocol.ReceiptV4` with `error_code` from
  `organic.ReceiptErrorAttribution` and `loaded_image_config_digest`.
- [x] Verify `X-Miss-Edge-Authorization` with `VerifyEdgeRuntimeRequest` against
  the addressed ticket's validator service key and a nonce replay cache;
  answer 401 before contacting the container.
- [ ] Sign `ProbeAttestationV2` for authorized validator probes.

### Scoring / public validators

- [ ] Verify `active-assignment-manifest.v2` (miner routes after cutover
  only) against the trust policy, envelope and chain state.
- [ ] Verify `miner-probe-attestation.v2` with
  `verify_miner_probe_attestation_v2`; score per contract section 17.2; never read
  serving-window volume or synthetic data in the weight path.
