# Signed active-assignment manifests and the public-validator live probe

## Authority and dependency model

`miss.computer` remains the sole challenge, wildcard-domain, edge, assignment,
route-activation, evidence, and scoring authority. The offline
[`signed-score-checkpoint-relay`](signed-score-checkpoint-relay.md) flow lets a
public validator verify the *outcome* of central scoring. The live probe adds
an **independent, bounded liveness and serving check of the assignments that
the central scheduler currently publishes as active**. It is not an alternate
scoring system:

- a public validator does not choose triads, provision workloads, create
  domains, generate challenges, activate routes, rescore miners, or submit
  weights from a probe result;
- the central scheduler publishes which deployments are active, on which
  route host, with which replicas, and what exact response the hidden
  challenge must produce;
- the validator independently checks that the published route really serves
  that exact response right now, and archives a canonical report that can be
  cross-referenced later against central evidence and the offline checkpoint.

The flow is one-way and dependency-only:

```text
central scheduler/evidence boundary -> credential-safe active-assignment manifest
                                          |
                          purpose-bound one-shot signers
                                          |
                 published manifest + sorted signature envelopes
                                          |
   public validator: pinned trust policy + local append-only manifest chain state
                                          |
          bounded HTTPS probe of each published route (no redirects, exact bytes)
                                          |
             canonical validator probe report (archived, cross-referenceable)
```

## What the manifest publishes

`active-assignment-manifest` v1 is sealed by a canonical self-digest and signed
under the fixed domain
`miss.computer/misscomputer-subnet/active-assignment-manifest/v1/ed25519`
(`NUL`-separated from the canonical manifest JSON). It carries only public-safe
facts a validator needs to probe:

- mainnet identity (`finney`, netuid `24`), the central authority fingerprint,
  and the digest of the validator-pinned trust policy it was published for;
- the finalized chain view (height, block hash, finalized epoch) at
  publication, a monotonic publication `sequence`, the previous manifest
  digest, and an explicit `issued_at_epoch`/`expires_at_epoch` validity window;
- the public route-host suffix, probe scheme (`https`), and probe port;
- one entry per active deployment: deployment ID, campaign sequence, route
  host, hidden challenge path, build ID, the SHA-256 of the exact expected
  challenge body, the expected status, image digest, workload-spec digest, and
  the attestation requirement;
- one replica projection per accepted, route-active assignment: miner UID,
  hotkey, miner Go service public key, ticket generation, assignment nonce,
  replica/endpoint IDs, the SHA-256 of the exact retained signed ticket and
  ready receipt, block window, and wall-clock ticket window.

It deliberately omits credentials, the raw challenge value, miner axons and TLS
pins, artifact manifest keys, encrypted image keys, provider or tunnel
identifiers, scheduler queue state, signer seeds, wallet paths, and every
internal runbook detail. The manifest model rejects duplicate deployments,
duplicate route hosts, duplicate assignment nonces or endpoint IDs, a miner UID
bound to two hotkeys (or the reverse), route hosts that are not exactly
`<deployment_id>.<route_host_suffix>`, replicas whose block window or ticket
window has already expired at the published finalized height/issue time, and
challenge paths that do not equal `/__challenge/<build_id>`.

## Trust policy

`assignment-manifest-trust-policy` v1 is the validator-local pin. It fixes the
central authority fingerprint, the Ed25519 manifest signing keys (key IDs,
exact public keys and digests, roles, purpose, validity, revocation), the
threshold and required roles, the policy validity window, freshness bounds
(maximum age, future skew, lifetime), append bounds (sequence and finalized
height gaps), the allow-listed public route-host suffixes, the probe scheme,
the per-request timeout, the maximum accepted response size, and an optional
allow-list of edge leaf-certificate SHA-256 pins. Signer IDs and public keys
are unique and canonically ordered; threshold success must also cover every
required role. The purpose `active_assignment_manifest_publication_v1` is
distinct from the score-checkpoint purpose, so a checkpoint key cannot sign a
manifest and vice versa.

## Verification algorithm

All time and chain context is explicit input; the pure core never reads a
clock. For one attempt `assignment_probe.verify_active_assignment_manifest`:

1. Revalidates every strict, frozen, `extra=forbid` model and every canonical
   self/content digest, including the assignment vector digest.
2. Requires the pinned trust-policy digest, network, netuid, authority
   fingerprint, `https` probe scheme, and an allow-listed route-host suffix.
3. Enforces the policy validity window, manifest lifetime, future skew,
   expiry, and maximum age at the supplied evaluation epoch.
4. Verifies every signature envelope against the domain-separated complete
   manifest with its pinned public key; rejects unknown, swapped, invalid,
   duplicate, wrong-purpose, not-yet-valid, expired, or revoked signers; then
   enforces the unique-key threshold and the required roles.
5. Applies append-only rules against the local `assignment-manifest-chain-state`:
   genesis accepts only sequence `1` with a null link; a repeat of the exact
   last-accepted manifest is a **re-probe** and leaves the state unchanged; a
   different manifest at the same sequence is equivocation; lower sequences,
   gaps beyond the policy bound, broken previous links, finalized-height
   rollback or excessive gaps, same-height forks, and issue-time rollback are
   rejected with stable codes and produce no next state.

Only a verified manifest is probed.

## Live probe and serving proof

For each published deployment, in canonical order, the CLI issues exactly one
bounded `GET https://<route_host>:<probe_port><challenge_path>` (or the same
path against an explicit `--edge-origin` with the route host as SNI and `Host`,
mirroring the central `https://{host}` probe template). The request carries
`X-Miss-Probe-Nonce` with 32 fresh random bytes, `Accept-Encoding: identity`,
and `Cache-Control: no-cache`. The transport uses TLS 1.2+, CA-verified
hostname checking (system store or one explicit `--tls-ca-file` bundle), no
redirects, no environment proxies, no retries, one per-request deadline, and a
hard byte ceiling enforced both on the declared `Content-Length` and while
streaming.

`assignment_probe.evaluate_probe_response` then judges the observation. A
deployment is `serving` only when **all** of the following hold:

- when the trust policy pins edge leaf certificates, the observed leaf is
  allow-listed;
- the status is exactly the published expected status (`200`); any `3xx` is
  `redirect_rejected`, anything else `unexpected_status`;
- the body is within the policy byte ceiling and its SHA-256 equals the
  published `challenge_sha256` — HTTP 200 alone is never sufficient;
- exactly one `X-Build-ID` header is present and equals the published build ID;
- when the deployment requires `miner_service_key_v1`, a valid miner attestation
  is presented (below). A presented-but-invalid attestation fails the
  observation even when it was not required.

Transport failures are recorded, never raised: `timeout`, `connection_failed`,
`tls_handshake_failed`, `tls_certificate_invalid`, `response_oversized`, and
`transport_error`. Every observation records the probe nonce, latency, status,
byte count, body digest, header verification, observed leaf digest, attestation
status, and the exact published assignment digest it was judged against.

Because the central edge round-robins an untargeted public request across the
deployment's healthy replicas, an un-attested `serving` observation proves that
the **deployment route** serves the exact hidden challenge; it does not by
itself attribute the response to one replica. Attribution comes only from a
verified attestation.

## Miner attestation contract

`miner-probe-attestation` v1 is a miner Go service-key statement carried in the
`X-Miss-Probe-Attestation` response header as base64 of its canonical JSON. It
binds the probe nonce, route host, deployment ID, generation, assignment nonce,
endpoint ID, miner UID, hotkey, service public key, response status, and the
SHA-256 of the served body, and is signed under
`miss.computer/misscomputer-subnet/miner-probe-attestation/v1/ed25519`. The
verifier requires the nonce to equal the one it sent, the body digest to equal
both the observed bytes and the published challenge digest, the replica to be
exactly one of the manifest's replicas for that deployment (UID, hotkey, key,
generation, nonce, endpoint), and the Ed25519 signature to verify under the
published miner service public key. A verified attestation attributes the
observation to that miner and is archived inside the report.

Manifests select the requirement per deployment (`attestation_requirement`).
`none` keeps the route-level proof; `miner_service_key_v1` fails closed with
`attestation_missing` or `attestation_invalid` when the header is absent or
wrong.

## Report

`validator-probe-report` v1 is canonical, sealed, and archivable. It binds the
validator UID/hotkey, evaluation epoch, trust-policy digest, manifest digest,
sequence, validity window, finalized chain view, verified signer IDs and roles,
prior and next chain-state digests, whether the run was a re-probe or used an
edge-origin override, the probe parameters, counts, and the complete sorted
observation vector with its digest. Its `status` is `serving` only when every
deployment served; otherwise `degraded`. Every observation names the
deployment, route, challenge path, and `assignment_digest_sha256`, whose
manifest entry names the ticket and receipt digests and campaign sequence, so
an archived report can later be cross-referenced with central campaign evidence
and with the offline score-checkpoint flow by deployment, nonce, ticket
digest, finalized height, and miner identity. The report is not a score, not a
weight, and not an authorization to submit anything.

## Pure core and boundary split

`assignment_probe.py` contains only contracts, canonical encoders/parsers,
public-key verification, append validation, response evaluation, report
sealing, and schemas/fixtures. It imports no clock, randomness, network, file,
process, environment, wallet, chain, or signing capability, and the test suite
enforces that boundary by scanning its source.

`assignment_probe_cli.py` is the only network-capable boundary. It loads the
pinned trust policy through the descriptor-pinned owner-only loader shared with
the checkpoint relay, obtains the manifest and its signature envelopes from
explicit local files or explicit HTTPS URLs, keeps one locked owner-only state
root with a single canonical `state.json`, performs the probes, and installs
the report exclusively as a mode-`0600` file that is never overwritten. It
cannot open a wallet, sign, contact an RPC, submit weights, create routes,
provision anything, or reach a Miss Computer endpoint unless the operator
supplies the manifest source and runs it. See
[`public-validator-live-probe-runbook.md`](public-validator-live-probe-runbook.md)
for invocation, exit statuses, state handling, and archival.

## Versioned contracts

The version-1 schemas and deterministic fixtures cover:

- active assignment manifest;
- assignment-manifest trust policy and signature envelope;
- append-only assignment-manifest chain state;
- miner probe attestation;
- validator probe report.

`tests/python/assignment_probe_context.py` regenerates them from fixed labels;
the committed copies must match its output byte-for-byte, and the same builder
operations are exposed to the central producer through the
`misscomputer-checkpoint-boundary` command.

## Known limitations

- Miner agents do not yet emit `miner-probe-attestation` headers. Central
  manifests must publish `attestation_requirement: "none"` until the miner
  side implements the contract; the verifier, schema, fixtures, and local test
  server already exercise the full attested path.
- Probes run sequentially with one request per deployment; very large
  manifests take proportionally long. Bounded concurrency is a possible v2
  refinement and does not change the contracts.
- An un-attested `serving` observation is route-level evidence. It cannot
  distinguish which healthy replica answered; only the central targeted probe
  (internal, credentialed) or a verified attestation can.
- The probe verifies serving behaviour, not exact binary execution; that
  remains deferred to the TEE phase, as for the central probes.
