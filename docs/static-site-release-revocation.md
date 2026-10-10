# Static release revocation in the validator (§7.3, development)

Code: `misscomputer_subnet.static_revocation`, wired into the static path of
`misscomputer-assignment-probe --static-sites on` and `misscomputer-static-probe`.

A static release that was signed correctly can still need to be taken down
(phishing, malware, a compromised release key). The release authority cannot
undo its own signature, so a separate **revocation authority** signs one
cumulative snapshot of everything revoked so far. The edge stops serving a
revoked release. The validator must therefore stop probing it: a revoked route
answers a fixed 503, and charging that to the miners would punish them for the
takedown.

## Documents

All documents are canonical JSON plus one newline.

**`static-site-release-revocation-trust-policy` v1** has the shape of the
release trust policy (§7.2) under its own schema: `policy_id`,
`trusted_keys[]` (`key_id`, `algorithm: "ed25519"`, `public_key_hex`,
`valid_from_epoch`, `valid_until_epoch`) and `digest_sha256`, the self-digest
over the other members. The threshold is 1. The policy is pinned by its
`digest_sha256`. None of its public keys may appear in the pinned release
trust policy (`revocation_policy_key_not_dedicated`).

**`static-site-release-revocation` v1**:

```json
{
  "issued_at": "2026-10-01T00:00:00Z",
  "revoked_releases": [
    {"reason_category": "phishing", "release_digest": "sha256:<64 hex>", "site_digest": "sha256:<64 hex>"}
  ],
  "revoked_signer_keys": [
    {"key_id": "<release key id>", "public_key_hex": "<64 hex>", "reason_category": "key_compromise"}
  ],
  "schema": "miss.computer/misscomputer-subnet/static-site-release-revocation",
  "schema_version": 1,
  "sequence": 1,
  "signature": "<128 hex>",
  "signer_key_id": "<revocation key id>"
}
```

- **Signed message:** the domain
  `miss.computer/misscomputer-subnet/static-site-release-revocation/v1/ed25519`,
  a NUL byte, then the canonical document without `signature`.
- **Snapshot digest:** `"sha256:" + hex(SHA-256(stored bytes))`.
- **Order:** `revoked_releases` is strictly ascending by `release_digest`;
  `revoked_signer_keys` is strictly ascending by `key_id` with unique public
  keys. Both arrays are always present.
- **Bounds:** 4096 releases, 64 signer keys, 1 MiB stored; `sequence` is
  1 to 2^53−1.
- **Release reasons:** `phishing`, `malware`, `credential_harvesting`,
  `illegal_content`, `platform_integrity`, `key_compromise`. **Key reasons:**
  `key_compromise`, `key_retired`.
- **Verification:** canonical decode, `signer_key_id` in the pinned policy,
  `issued_at` inside that key's window, signature valid. Failures are
  `revocation_snapshot_invalid`, `revocation_signer_untrusted`,
  `revocation_signer_outside_validity` and `revocation_signature_invalid`.

**Verifier-side entry evidence.** The validator accepts an offered snapshot
only inside a canonical `static-site-release-revocation-evidence` v1 envelope:

```json
{
  "schema": "miss.computer/misscomputer-subnet/static-site-release-revocation-evidence",
  "schema_version": 1,
  "snapshot_b64": "<base64 of exact signed snapshot bytes>",
  "release_proofs": [
    {"release_digest": "sha256:<64 hex>", "signed_release_b64": "<base64 of exact signed release bytes>"}
  ]
}
```

There is exactly one proof per revoked-release entry, ordered by release
digest. For each proof the verifier checks the stored-byte digest, canonical
release, its signature and issuance window under the current or an independently
digest-pinned historical release policy,
and equality between its signed `site_digest` and the snapshot entry. Every
revoked signer-key ID/public-key pair must also occur in the pinned release
policy set. A key ID and public key must identify the same key and validity
window in every supplied policy; aliases and changed windows fail closed.
Historical policies are used only to authenticate cumulative revocation
entries, **never** to authorize a current index release. The same exact
evidence envelope, limited to 8 MiB, is persisted and
re-verified on restart; the inner signed snapshot's digest remains the
high-water and epoch-record digest. A bare signed snapshot, a missing proof,
or any mismatched entry is `revocation_entry_unbound` and cannot advance the
high water. Every historical policy needed by the cumulative snapshot must
remain pinned and available across restarts; removing one first makes the held
high water unverifiable and fails the run closed. Each v1 policy keeps its
16-key bound; the proof-only policy list is bounded by the number of possible
snapshot entries and may contain independently pinned generations. The
revocation authority's v1 signature format is
unchanged; the envelope is self-authenticating through that signature and
the signed release proofs and out-of-band policy pins.

A release is **revoked** when its `release_digest` is listed, when its site is
taken down, or when its signer is listed by `key_id` *or* by public key,
whatever the release's `issued_at`. A compromised key can backdate, and
matching either identity stops a revoked key from coming back under a new ID.
An unknown or expired release key is not a revocation: index ingestion
already abstains on it.

**Taken-down site.** A revoked-release entry whose reason is a takedown
category (`phishing`, `malware`, `credential_harvesting`, `illegal_content`,
`platform_integrity`) also denies its `site_digest`. Every release of that
site is revoked, whoever signed it and whenever, so re-signing or re-promoting
the identical site cannot evade the takedown. The edge withdraws such a
release, and the validator abstains on it instead of probing a route that
answers 503. A `key_compromise` entry judges only that release's signature:
the same site may return as a release under a trusted key and is probed
normally. Site denial matches the exact `site_digest`, so changed content is
another site. Because entries never change, a `key_compromise` entry cannot
later become a takedown; take the site down with an entry for another release
of it.

## High water

The validator keeps the highest accepted snapshot and its entry evidence as
exact envelope bytes in `static-release-revocation.json` inside the owner-only, locked
`--static-state-root`. A verified snapshot *N* replaces the high water *H* when
*N* is byte-identical to *H* (no-op), or when `N.sequence > H.sequence`,
`N.issued_at ≥ H.issued_at`, and every entry of *H* is unchanged in *N*.
Otherwise:

| Case | Code |
| --- | --- |
| Lower sequence, or earlier issuance | `revocation_rollback` |
| Different snapshot at the same sequence | `revocation_equivocation` |
| Higher snapshot that drops or changes an entry | `revocation_not_cumulative` |

The store re-reads and re-verifies its own bytes under the lock before it
advances. It installs with an fsynced temporary file, a rename, a directory
fsync and a read-back, and only then does the run rely on the new snapshot. A
revocation is final. Re-genesis of the v3 chain state keeps the high water.

## Freshness rule

The snapshot carries no expiry, so the validator sets one. A high water is
usable only while `issued_at` is at most `--static-release-revocation-max-age-seconds`
old (default 86400, allowed 300 to 604800) and not more than 300 s ahead of the
validator clock. The authority keeps a validator fresh by reissuing the same
set under a higher `sequence`. A verified snapshot that is stale but higher
still raises the high water, because it can only add revocations. A snapshot
dated more than 300 s in the future is never installed, because it would hold
back every later issuance.

## Validator behaviour

| Situation | Effect |
| --- | --- |
| `finney` without a revocation policy | Run refused before any state or probe: `static_revocation_policy_required` |
| A high water is held but no policy is configured (any network) | Same refusal; the configuration can never drop a held revocation |
| Held high water fails verification under the pinned policy (tampered, or a rotation that dropped its key) | Run refused: `static_revocation_high_water_invalid` |
| Policy is not the pinned digest, or shares a release key | Run refused: `static_revocation_policy_digest_mismatch` / `static_revocation_policy_key_not_dedicated` |
| Offered envelope is unreadable, has unbound entries, is unverifiable, a rollback, an equivocation, not cumulative, or future-dated | Static epoch **abstains** with `static_revocation_*`; the high water is unchanged |
| No high water yet, or the high water is stale | Static epoch **abstains** (`static_revocation_unavailable` / `static_revocation_stale`) |
| A deployment's release digest is revoked | Deployment abstains with `release_revoked` (record code `static_release_revoked`) before its index is fetched |
| A deployment's site is taken down (any release of it, however signed) | Deployment abstains with `release_revoked` before its index is fetched; the verified release's `site_digest` is checked again after authentication |
| A deployment's verified release was signed by a revoked key | Deployment abstains with `release_revoked` |

Every epoch scored under a revocation authority is a `static-epoch-score`
**v3** record (`contracts/schemas/static-epoch-score.v3.schema.json`). It binds
`release_revocation_policy_digest_sha256` and the exact
`release_revocation_snapshot_digest` it relied on, so an auditor can fetch that
snapshot and check every `release_revoked` row. v3 keeps either transport:
`transport_profile` is null, or `public-framing-v1` on test/581. Only v3 may
carry `release_revoked`; a v1 or v2 record with it, or a v3 record without its
binding, is refused. Runs without a revocation authority keep writing the
unchanged v1 or v2 records, and the frozen v1 and v2 schema files are
untouched.

An abstained epoch writes no static record, sends no static probe and never
scores a zero; the v3 chain state still advances, and the organic path is
unaffected. A revoked deployment's endpoints are `abstain_index`, carry no
availability, raise the `static_release_revoked` alert, and are absent from the
static availability window. Nothing here writes weights.

Revocation is enabled by pinning both
`--static-release-revocation-policy <file>` and
`--static-release-revocation-policy-digest <digest_sha256>`.
`--static-release-revocation-snapshot <file>` offers the operator-delivered
evidence envelope for this run. The signed snapshot and proofs are self-authenticating, so it is not
digest-pinned. Repeat `--static-release-revocation-proof-policy <file>` with
its matching `--static-release-revocation-proof-policy-sha256 <sha256>` for
each historical release policy needed by the cumulative snapshot. The current
`--static-release-trust-policy` is included automatically. Without an offered
envelope, the run relies on the durable high water and still re-verifies it
against those same pins.

## Vectors

`contracts/fixtures/static-release-revocation-vectors.v1.json` was produced by
the Go reference verifier used by the edge and ticket issuer. It holds the
worked example (revocation key seed `0x09` × 32, key ID `static-revocation-1`;
signature `f60c1f7b…cda01`, digest
`sha256:3e6e81bf52c93d8c4637472356a8926552e7bf3117ab1bbe976957b746e28ea9`) and
policy, verify, high-water and lookup cases with the Go outcome of each.
`takedown_index_snapshot` and `takedown_index_cases` are the same takedown
vectors the edge pins. They hold a phishing entry and a `key_compromise` entry,
and each case records whether the release, the site and the signer are
revoked.
`tests/python/test_static_revocation.py` requires the Python verifier to reach
the same outcome on every case.

## Not in this change

- Where operators publish the snapshot (an index path or URL source). The
  validator reads it from a local file.
- `static-site-release-revocation*` JSON schemas and a negative-corpus
  directory; the vectors file is the cross-language contract for now.
- Re-vendoring this verifier into the private edge repository.
