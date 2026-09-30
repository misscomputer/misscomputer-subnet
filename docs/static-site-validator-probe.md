# Static-site validator probes (`static-site-v1`, development)

Status: development baseline behind the operator's `static_sites` flag (default
off). The validator implements the normative static-site contract (§3 site
manifest, §4 URL paths, §5 serving semantics, §7 release authority, §10.2
crawl set and budgets, §11 static index and probes). Manifest v3 parsing,
evidence and coverage record schemas, and scoring live with their owners.

## Index ingestion

Code: `misscomputer_subnet.static_index`.

For each static deployment in the verified public assignment manifest v3
(`site_digest`, `release_digest`, `server_implementation_digest`, endpoint
incarnations), the validator fetches
`static-sites/v1/manifests/<site hex>.json` and
`static-sites/v1/releases/<release hex>.json` from the public static index
and accepts them only if:

- SHA-256 of the stored manifest bytes, prefixed `sha256:`, equals
  `site_digest`, and the stored release bytes hash to `release_digest`;
- the manifest decodes canonically as `static-site-manifest` v1
  (`fallback`, `files[{body_sha256, content_length, content_type, path}]`,
  `handler: static-handler.v1`, `schema`, `schema_version`). Files must be
  strictly ascending, use §4.2 file paths and the §3.4 content type for each
  extension, and have no ASCII case-fold or file/directory collision. `/index.html`
  must be present, and a fallback must target an HTML file. Every §1 limit applies;
- the release decodes canonically as `static-site-release` v1, names the same
  `site_digest`, is signed by a key in the pinned
  `static-site-release-trust-policy` v1 whose window contains `issued_at`
  (Ed25519 over the `static-site-release/v1/ed25519` domain, NUL, and the
  release without `signature`), uses a producer policy this validator
  implements, and names the server implementation the validator pins for
  `static-handler.v1`, which the manifest v3 deployment also names.

Anything else, including an unavailable object, is an **abstention**. The
record code is `static_index_unavailable` or `static_index_invalid`, and a
finer stable reason is also kept. An abstained deployment is not probed, not
scored as zero, and never falls back to the dynamic health probe.

## Admission crawl

Code: `plan_static_admission_crawl`, `run_static_admission_crawl`.

Before the validator treats a new incarnation as admitted, it sends the §10.2
crawl set in an unpredictable order:

- `GET` of every §4.4 route;
- `HEAD /`;
- `GET /<32 hex>.absent`;
- `GET /<32 hex>`.

Budgets are explicit. The default is at most 3 incarnations at once, 30 s per
request, 15 min per incarnation, and bytes equal to the sum of route
`content_length` plus 64 KiB, capped at 512 MiB. The outcomes are:

- `refused`: the crawl does not fit its budget, and nothing is sent;
- `incomplete`: the crawl runs out of time;
- `rejected`: the first failed response ends the crawl.

Only `admitted` admits. A replacement incarnation is crawled again.

## Hidden probes

Code: `plan_static_hidden_probes`.

Each epoch, each incarnation receives probes at instants derived from a
validator-private seed. Targets are also seed-derived: routes, plus synthetic
`/<32 hex>.absent` and `/<32 hex>` paths. A route is probed with `GET` only
when its `content_length` is at most 1 MiB, otherwise with `HEAD`.
`static_probe_coverage` reports routes total and probed, and bytes total and
GET-eligible.

## Request and judgement

Every request targets one incarnation through the public route host. It
carries a fresh `organic-probe-authorization` v1, no query,
`Accept-Encoding: identity` and `Cache-Control: no-cache`. The response is
compared with `expected(...)` (§5.5): status, the normative header digest
(`organic.ResponseHeaderSHA256` over `Cache-Control`, `Content-Length`,
`Content-Type` and `X-Content-Type-Options`), length and body SHA-256. It must
also carry none of the forbidden §5.2 headers. The miner's
`miner-probe-attestation` v2 binds `artifact_digest = site_digest` and the
static `ticket_digest`.

| Observation (§11.4) | Code | Attribution |
| --- | --- | --- |
| No response, timeout, TLS failure or pin mismatch | transport code | path |
| No `X-Miss-Edge-Upstream: replica` | `edge_generated` | path |
| Attestation `probe_nonce` differs from the sent nonce | `cache_replay` | path |
| Attested status, body or header digest differs from the observation | `content_altered_in_transit` | path |
| Forbidden header, which is outside the attested set | `forbidden_header` | path |
| Attestation missing or signature invalid | `attestation_missing` / `attestation_invalid` | miner |
| Attested = observed, but differs from expected | `status_mismatch` / `body_mismatch` / `header_mismatch` | miner, quarantine candidate |
| Fresh attestation naming another ticket, endpoint, generation, site or request | `attestation_fraud` | miner (evidence) |

Wrong bytes alone are never fraud. Each attempt is sealed as a
`static-probe-observation` v1 and each crawl as a `static-admission-record` v1.
Both are validator-local evidence for scoring.
