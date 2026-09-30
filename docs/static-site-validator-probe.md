# Static-site validator probes (`static-site-v1`, development)

Status: development baseline behind the operator's `static_sites` flag (default
off). The document shapes below are provisional until the normative static
contract lands; the validator code keeps each assumption in one place so it can
be reconciled without redesign.

## What a validator checks

A static deployment is a content-addressed file bundle served by a pinned
platform handler. No customer code runs, so every static fault is attributed
either to the **miner** or to the **path** (edge, tunnel, cache, network),
never to an application.

1. **Index ingestion** (`misscomputer_subnet.static_index`). For each static
   deployment in the verified public assignment manifest, the validator
   fetches the `static-site-manifest` v1 and the `static-site-release` v1
   itself and accepts them only if:
   - SHA-256 of the exact canonical manifest bytes equals the bound
     `site_digest`;
   - the manifest is canonical and within the v1 caps (4,096 files, 256 MiB
     total, 16 MiB per file, 1 MiB manifest, path ≤ 1,024 bytes, segment ≤ 255
     bytes, depth ≤ 32), has no case-fold path collisions, and includes `/`;
   - every URL path is canonical: no dot segments, empty segments, queries,
     fragments, backslashes, controls, or ambiguous percent-encoding;
   - the release binds the same site digest and producer policy version and
     carries a threshold of valid signatures from keys pinned in the
     validator's `static-site-trust-policy` v1;
   - the producer policy version is approved and the release's pinned server
     implementation digest has a pinned server profile (its fixed 404).

   Anything else, including a failed fetch, is an **abstention** with a
   stable code. An abstained deployment is not probed, not scored as zero, and
   never falls back to the dynamic health probe.

2. **Admission crawl** (`plan_static_admission_crawl`,
   `run_static_admission_crawl`). Before a validator treats a new endpoint
   incarnation as admitted, it requests every indexed response (every file and
   every directory index), a `HEAD /`, a never-published navigation path
   (fallback or 404), and a never-published asset path (404), in a
   seed-derived order. Budgets are explicit: requests, total bytes,
   per-response bytes (≤ 16 MiB), per-request timeout, wall-clock duration,
   and at most three incarnations at once. A crawl that does not fit its
   budget is `refused` before any request; one that runs out of time is
   `incomplete`; the first failed response makes it `rejected`. Only
   `admitted` admits. A replacement incarnation is crawled again.

3. **Hidden probes** (`plan_static_hidden_probes`). Each epoch, each
   incarnation receives probes at HMAC-derived instants from a
   validator-private seed. The request itself is also seed-derived: usually a
   GET of an indexed response within the 1 MiB per-probe ceiling, sometimes a
   HEAD of any response, or a synthetic never-published path. Neither timing
   nor target is predictable from public data. `static_probe_coverage`
   reports which responses exceed the ceiling and are therefore only
   HEAD-checked by hidden probes; their bytes rest on admission, complete
   miner verification, and edge checks.

## Request shape

Every request is addressed to one incarnation through the public route host
with a fresh `organic-probe-authorization` v1 (validator hotkey, one-time
nonce, method, path, no query), `Accept-Encoding: identity`, and
`Cache-Control: no-cache`. The miner's `miner-probe-attestation` v2 binds the
response; for a static incarnation its `artifact_digest` is
`sha256:<site_digest>`.

## Judgement and attribution

The response is compared with the release-signed expectation (status,
`Content-Type`, `Content-Length`, `X-Content-Type-Options: nosniff`,
`Cache-Control: private, no-store`, no encoding, range, redirect, or cookie,
and the body digest), not with the attestation alone.

| Observation | Code | Attribution |
| --- | --- | --- |
| Transport failure, timeout, certificate-pin mismatch | transport code | path |
| Response without the edge upstream marker | `edge_generated` | path |
| Valid attestation for another probe of this incarnation | `cache_replay` | path |
| Bytes differ from both expected and attested; attestation names the expected bytes | `content_altered_in_transit` | path |
| Missing attestation, or one not signed by the service key | `attestation_missing` / `attestation_invalid` | miner |
| Attested status or body differs from the release | `status_mismatch` / `body_mismatch` | miner, quarantine candidate |
| Normative header wrong under a valid attestation | `header_mismatch` | miner |
| Valid attestation for this nonce naming another incarnation, ticket, site, or request | `attestation_fraud` | miner (evidence) |

Wrong bytes alone are never fraud. Each attempt is sealed as a
`static-probe-observation` v1 and each crawl as a `static-admission-record` v1;
scoring consumes these records and decides common-mode faults, quarantine,
and trust.
