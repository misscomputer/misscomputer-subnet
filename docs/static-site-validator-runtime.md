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
| Exactly one of `--static-index-root` or `--static-index-origin` | private local spool (recommended for operator-only validation), or explicit HTTPS index origin (`static-sites/v1/...`) |
| `--static-manifest-archive-dir` | write-once archive of verified v3 manifests (separate from the v2 archive) |
| `--static-epoch-output` | exclusive `static-epoch-score` output (v1; v3 under a revocation authority) |
| `--static-journal` | append-only, fsynced, hash-chained `static-evidence-record` v1 journal |

Static release revocation ([static-site-release-revocation.md](static-site-release-revocation.md))
is required on `finney`, optional elsewhere, and all-or-nothing:

| Option | Meaning |
| --- | --- |
| `--static-release-revocation-policy` + `--static-release-revocation-policy-digest` | pinned `static-site-release-revocation-trust-policy` v1 and its `digest_sha256` |
| `--static-release-revocation-snapshot` | optional operator-delivered `static-site-release-revocation-evidence` v1 envelope, carrying the signed snapshot and release proofs, offered to the durable high water; a bare snapshot is refused |
| repeated `--static-release-revocation-proof-policy` + `--static-release-revocation-proof-policy-sha256` | independently pinned historical release policies for cumulative entry proofs only; they do not authorize current index releases |
| `--static-release-revocation-max-age-seconds` | freshness limit of the high water (default 86400, 300 to 604800) |

The v3 manifest is verified under the same pinned assignment-manifest trust
policy as v2.

## Private inventory / Null migration

Use the **local** source for the operator-controlled scoring flow. This is
inventory delivery, not a website transport change: the websites themselves
are still probed over HTTPS with the existing signed probe authorization.
Both `misscomputer-static-probe` (V3 only) and
`misscomputer-assignment-probe --static-sites on` accept the same source options.

Replace `--static-index-origin https://...` with:

```text
--static-index-root /var/lib/misscomputer/operator-inventory
```

The spool contains the existing, unchanged digest-addressed bytes:

```text
operator-inventory/
  static-sites/v1/manifests/<site-sha256-hex>.json
  static-sites/v1/releases/<release-sha256-hex>.json
```

Deliver files through an operator-private provisioning channel. The spool and
all its subdirectories must be owned by the probe service's effective UID and
mode **0700**; regular files must be **0600** or **0400**, with one hard link.
Ancestors must be root/service-owned, not writable by group/others, except
sticky ancestors such as `/tmp`. Use absolute canonical paths, no symlinks,
`..`, `file://` URLs or bind-through symlink convenience paths. The inventory
must be separate from state, archive, journal and output trees. Use a local
filesystem; deadlines are checked between bounded reads, not a cancellation
mechanism for an indefinitely stalled filesystem syscall. Root and same-UID
processes remain trusted, so run the operator service under a dedicated UID.

Copy/publish complete immutable objects atomically before advancing the signed
assignment head. Readers pin directory/file descriptors and refuse observed
replacement races or permission changes. Missing, oversized or unsafe objects
cause index abstention; malformed or mismatched objects fail the existing
signature/digest verification. **There is no fallback to the HTTPS source.**
Specifying both sources, or neither, is a usage error. File-size ceilings,
epoch load budgets, signature thresholds, release revocation, expiry and
append-only assignment sequence checks are unchanged.

Also select local `--static-manifest-file` / `--static-signature-file` inputs
with their SHA-256 pins (and local V2 equivalents for the combined command).
Keep trust policies, archives, evidence and probe seeds private. The frozen
manifest purpose string still contains `publication`; it does not require
public distribution. Do not send customer inventory to external validators.

Adoption order: privately provision and validate a current signed inventory;
run the packaged command in local mode and confirm scored output with no index
network traffic; update the service/timer configuration; then disable public
assignment/index serving and remove public R2/domain access, including cached
copies where possible. This source change does **not** itself revoke public
access, erase previously published inventory, change chain consensus, or
increase runtime capacity. Live adoption remains a separate operator rollout.

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
   read the stored site manifest and signed release from the selected local spool or HTTPS origin
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
