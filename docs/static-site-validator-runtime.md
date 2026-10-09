# Static sites in `misscomputer-assignment-probe` (development, default off)

`--static-sites` defaults to `off`. Off, the probe is exactly the organic v2
flow: same inputs, schedule, records and exit codes, and any `--static-*`
option is a usage error. The static path never writes into the organic epoch
record, the window decision, the weight plan or the checkpoint; static scores
stay separate until an explicit scoring-policy digest combines them.

## Enabling

`--static-sites on` requires every pin below (missing one is `usage`):

| Option | Meaning |
| --- | --- |
| `--static-manifest-file` + `--static-manifest-sha256`, or `--static-manifest-url` | the signed `active-assignment-manifest` v3 |
| `--static-signature-file` + `--static-signature-sha256` (repeat), or `--static-signature-url` | v3 signature envelopes (frozen envelope v1, v3 signing domain) |
| `--static-state-root`, `--static-trusted-state-anchor` | owner-only v3 chain state, separate from `--state-root` (aliasing is refused) |
| `--static-release-trust-policy` + `--static-release-trust-policy-sha256` | pinned `static-site-release-trust-policy` v1 |
| `--static-server-implementation-digest` | pinned `static-handler.v1` implementation digest (`sha256:<hex>`) |
| `--static-index-origin` | HTTPS origin of the public static index (`static-sites/v1/...`) |
| `--static-manifest-archive-dir` | write-once archive of verified v3 manifests (separate from the v2 archive) |
| `--static-epoch-output` | exclusive `static-epoch-score` output (v1; v3 under a revocation authority) |
| `--static-journal` | append-only, fsynced, hash-chained `static-evidence-record` v1 journal |

Static release revocation ([static-site-release-revocation.md](static-site-release-revocation.md))
is required on `finney`, optional elsewhere, and all-or-nothing:

| Option | Meaning |
| --- | --- |
| `--static-release-revocation-policy` + `--static-release-revocation-policy-digest` | pinned `static-site-release-revocation-trust-policy` v1 and its `digest_sha256` |
| `--static-release-revocation-snapshot` | optional operator-delivered `static-site-release-revocation` v1 offered to the durable high water |
| `--static-release-revocation-max-age-seconds` | freshness limit of the high water (default 86400, 300 to 604800) |

The v3 manifest is verified under the same pinned assignment-manifest trust
policy as v2.

## One run

1. Refuse unsafe or aliased static paths and load the release trust policy.
2. Take the organic lock, then the static lock; preflight both outputs; open
   and fully verify the journal; load the pinned revocation policy and
   re-verify the held revocation high water. A busy root, unsafe path,
   torn/edited journal, missing required revocation policy or unverifiable
   high water refuses the whole run before any state advances or probe is sent.
3. Verify, archive and advance the organic v2 manifest (unchanged).
4. Verify the v3 manifest live with `verify_assignment_manifest_v3` (policy,
   identities, leases, v3-domain threshold signatures, its own append-only
   chain). If it is unavailable or
   unverifiable, the static path **abstains** for the epoch
   (`STATIC status=abstained code=...`): no static probe, no static record, no
   v3 state change, never a zero and never a dynamic probe. Otherwise archive it
   and advance the v3 state.
5. With revocation enabled, offer the snapshot to the durable high water. A
   refused snapshot, or no fresh high water, makes the static path abstain
   for the epoch with a `static_revocation_*` code.
6. For each `static-site-v1` deployment (OCI entries of v3 are ignored here),
   fetch the stored site manifest and signed release from the index origin
   and authenticate them. An unavailable or invalid index abstains that
   deployment with `static_index_unavailable` / `static_index_invalid`; a
   revoked release or release signer abstains it with
   `static_release_revoked`.
7. Fire the organic and static hidden plans in one time-ordered schedule
   (organic first on a tie; organic observations are byte-identical to an
   organic-only run). Static probes use seed-derived instants and paths, GET
   only within the trust policy's response ceiling (≤ 1 MiB), HEAD above it.
   Every static observation is appended to the journal as it is judged.
8. Write the organic record, then the `static-epoch-score` (v1, or v3 bound
   to the revocation policy and high-water snapshot): coverage,
   content-fault and fraud evidence, quarantine recommendations
   (`endpoint_actions`, never trust-zero for wrong bytes) and alerts.

Output adds one line, e.g.
`STATIC status=scored epoch=… deployments=1 index_abstentions=0 observations=9 skipped=0 content_faults=0 quarantine=0 alerts=0`.
Exit status is `3` (degraded) when the organic epoch is not scored, the
static path abstained, or the static epoch is not scored.

## Contract points

- The v3 model, signing domain, verification and anchor are the normative
  ones in `organic_contracts.ActiveAssignmentManifestV3` and
  `organic_manifest.verify_assignment_manifest_v3` /
  `anchor_assignment_manifest_v3_chain_state`, with the generated schema,
  golden fixture and negative corpus under `contracts/*/active-assignment-manifest.v3*`.
  Static targets come only from a live verification
  (`static_index.static_deployment_targets`).
- v3 is its own publication series with its own chain state: this CLI keeps
  it in `--static-state-root`, never the v2 root.
- No v3 producer exists yet; until one publishes, the static path abstains
  (`STATIC status=abstained`) and the organic path is unaffected.
- The manifest `purpose` is `active_assignment_manifest_publication_v3`; the
  frozen signature envelope keeps the channel purpose, as for v2.
- The static v3 path accepts only `finney`/`24` or `test`/`581`, bound to its
  pinned manifest trust policy. The testnet `test`/`581` pair is carried into
  static epoch/window records; organic v2 and organic scoring stay unchanged.
