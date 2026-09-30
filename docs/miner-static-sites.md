# Miner static sites (`static-site-v1`)

Status: implementation for integration, off by default. Nothing here is live.
The normative sources are the integration contract v0 and the static-site
contract (`static-site-v1`, contract workstream); this note
describes how the public miner implements them and the interfaces other
workstreams consume. Dynamic `oci-image-v1` / `deployment.v4` behavior is
unchanged.

## Enabling

```text
miner-agent ... --static-sites on \
  --static-cache-dir /var/lib/misscomputer/static \
  --static-cache-max-bytes 8589934592 \
  --static-fetch-timeout 2m --static-request-concurrency 64
```

`--static-sites` defaults to `off`: no static route, no cache, and the
capability `organic-static-v1` is not advertised. With `on`, the cache quota
must be at least one maximal site (256 MiB). The cache lives only in
`<static-cache-dir>/misscomputer-static-v1/`; startup sweeps that directory
and nothing else. The Docker organic runtime is still required at startup
(unchanged); static endpoints never use it.

## Wire interfaces (miner-owned envelope)

| Bridge route | Request | Response |
|---|---|---|
| `POST /v1/static/assignments` | `neuron.LocalStaticAssignRequestV1` (`subnet-static-synapse.v1`: `protocol`, `request_id`, `current_block`, `caller_hotkey`, `binding_verified`, `validator_binding`, `ticket`) | `neuron.StaticDeployResponseV1` (`protocol`, `request_id`, `endpoint_id`, `receipt`, `idempotent`) |
| `POST /v1/static/status` | `neuron.StaticStatusSynapseV1` (`protocol`, `request_id`, `current_block`, `caller_hotkey`, `endpoint_id`) | `neuron.StaticStatusResponseV1` (`protocol`, `request_id`, `status`, `receipt` or `null`) |
| `POST /v1/deactivate` | existing `DeactivateSynapse` (kind-neutral) | existing `DeactivateResponse` |
| `/v1/runtime/<endpoint_id>/...` | existing edge-runtime-request v1 ingress | static-handler.v1 response |

The validator-facing synapse `neuron.StaticDeploySynapseV1` has the
`DeploySynapseV3` members with a static ticket. `POST /v1/status` answers
`409 static_endpoint` for a static endpoint; a v3 envelope never carries a
static ticket. A disabled miner answers `501 static_disabled` without
consuming the nonce.

Ticket and receipt are `protocol.StaticTicketV1` / `protocol.StaticReceiptV1`
(static-site contract §8), with domain-separated Ed25519 signatures,
`miner_uid` always present, canonical string timestamps and
`static.ReceiptErrorAttribution` codes. Endpoint identities use the v4
derivation, so runtime paths, probe authorization v1 and endpoint fences are
shared; the one-time `assignment` nonce scope is shared with v4, so a nonce
can never name both a static and a dynamic endpoint.

## Verify-then-serve

1. The bridge applies the shared validator-binding checks; the agent
   verifies the ticket (`VerifyBoundStaticTicketV1`), its miner service key
   and transport pin. Refusals return no receipt and consume no nonce.
2. Admission consumes the nonce and records the exact ticket in
   `static_assignments` (a separate table: v4 decoders and recovery never
   read a static row). A deactivation fence recorded earlier wins.
3. A ticket naming another `server_implementation_digest` fails with
   `static_server_implementation_mismatch`.
4. The manifest is read by `site_manifest_key` (at most 1 MiB), must hash to
   `site_digest` (`static_verify_failed`), and must pass every §3/§4 rule
   (`static_manifest_invalid`) and §1 limit (`static_limits_exceeded`).
5. `static.Cache.Pin` reserves the quota (`static_storage_exhausted`), then
   fetches every distinct body (4 concurrent, bounded by
   `--static-fetch-timeout`) into a temp file while hashing, checks length and
   SHA-256, fsyncs, makes it read-only and renames it into the cache. A cached
   body is re-hashed before reuse. Any failure releases everything; there is
   no partial or lazy pin.
6. Only then is `ready` signed and persisted with `verified_file_count` and
   `verified_total_bytes`, and only after that is the endpoint servable.
   Failures sign a `failed` receipt with the §8.3 code.

Serving: after edge-runtime-request verification, the raw path after
`/runtime/<endpoint_id>` (from the unparsed request-target) goes through
`static.ResolveRequest` and `static.WriteResponse`. Bodies are re-hashed while
streaming and the final chunk is withheld unless the digest matches; a
mismatch aborts the connection and removes the endpoint from serving. Each
endpoint has an in-flight bound (fixed 503 beyond it). An authorized probe
gets `miner-probe-attestation` v2 with `artifact_digest = site_digest`,
`ticket_digest` = the static ticket digest and `response_header_sha256` over
exactly the normative header set.

Restart: the cache is swept and `RecoverCleanup` fences and retires every
static endpoint, so a restarted miner never serves bytes it has not
re-verified in this process (a new ticket re-pins).

## Reusing the handler (temporary static origin)

`pkg/static` is the single `static-handler.v1` implementation. An origin
reuses it unchanged:

```go
manifest, err := static.Parse(storedManifestBytes, siteDigest) // verified site
index := static.NewIndex(manifest)
handler := static.NewHandler(index, bodies, routeHost, 64)       // routeHost enables the 421 check
```

`bodies` implements `static.BodySource` (`Open(static.File) (io.ReadCloser,
error)`); it need not be trusted, because `WriteResponse` re-hashes every
body. The origin can use `static.Cache.Pin` + `*static.Site` (which is a
`BodySource`) or its own store. For lower-level use: `static.RawRequestPath`,
`static.ResolveRequest(index, req, rawPath, routeHost)`, `Index.Resolve`,
`Response.Header`, `Response.BodySHA256`, `Response.HeaderSHA256`,
`static.WriteResponse` and `Index.Routes` (the admission crawl set).

Go's `net/http` rejects some malformed request-targets (for example a bare
`%`, V29) before any handler runs, with its own 400 body; the edge answers
those locally (§10.3), and `Index.Resolve` still returns the fixed 400.

## Server implementation digest

`static.ServerImplementationDigest` is `sha256:` of the canonical JSON
descriptor

```json
{"files":[{"path":"pkg/static/handler.go","sha256":"…"},{"path":"pkg/static/manifest.go","sha256":"…"},
          {"path":"pkg/static/path.go","sha256":"…"},{"path":"pkg/static/serve.go","sha256":"…"}],
 "handler":"static-handler.v1",
 "schema":"miss.computer/misscomputer-subnet/static-handler-implementation","schema_version":1}
```

computed at init from the embedded handler sources. Any byte change to those
files is a new digest; origin and miner builds that vendor `pkg/static`
byte-identically derive the same value. The release signer and the Deploy
API must read it from the exact public build they pin.

## Open items

- Python mirrors, generated JSON schemas and fixtures for the static ticket,
  receipt and `subnet-static-synapse.v1` envelopes, and the Python axon
  routes forwarding them to the bridge (contract workstream plus a miner
  follow-up in `miner.py`).
- The capacity 503 (`Service Unavailable\n`) is not in the contract's §5.3
  table; the contract should list it as a transport-class response.
- A zero-length body is determined by its digest and is not fetched.
- An oversize object at `site_manifest_key` is `static_verify_failed` (it
  cannot match a canonical ≤ 1 MiB manifest), not `static_limits_exceeded`.
- Release authority verification is not performed by the miner (validators
  and the edge pin it); the miner binds `release_digest` into its receipt.
