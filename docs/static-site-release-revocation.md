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

Both documents are canonical JSON plus one newline.

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

A release is **revoked** when its `release_digest` is listed, or when its
signer is listed by `key_id` *or* by public key, whatever the release's
`issued_at`. A compromised key can backdate, and matching either identity
stops a revoked key from coming back under a new ID. An unknown or expired
release key is not a revocation: index ingestion already abstains on it.

## High water

The validator keeps the highest accepted snapshot (its high water) as exact
bytes in `static-release-revocation.json` inside the owner-only, locked
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
| Offered snapshot is unreadable, unverifiable, a rollback, an equivocation, not cumulative, or future-dated | Static epoch **abstains** with `static_revocation_*`; the high water is unchanged |
| No high water yet, or the high water is stale | Static epoch **abstains** (`static_revocation_unavailable` / `static_revocation_stale`) |
| A deployment's release digest is revoked | Deployment abstains with `release_revoked` (record code `static_release_revoked`) before its index is fetched |
| A deployment's verified release was signed by a revoked key | Deployment abstains with `release_revoked` |

An abstained epoch writes no static record, sends no static probe and never
scores a zero; the v3 chain state still advances, and the organic path is
unaffected. A revoked deployment's endpoints are `abstain_index`, carry no
availability, raise the `static_release_revoked` alert, and are absent from the
static availability window. Nothing here writes weights.

Revocation is enabled by pinning both
`--static-release-revocation-policy <file>` and
`--static-release-revocation-policy-digest <digest_sha256>`.
`--static-release-revocation-snapshot <file>` offers the operator-delivered
snapshot for this run. The snapshot is self-authenticating, so it is not
digest-pinned. Without it, the run relies on the durable high water.

## Vectors

`contracts/fixtures/static-release-revocation-vectors.v1.json` was produced by
the Go reference verifier used by the edge and ticket issuer. It holds the
worked example (revocation key seed `0x09` × 32, key ID `static-revocation-1`;
signature `f60c1f7b…cda01`, digest
`sha256:3e6e81bf52c93d8c4637472356a8926552e7bf3117ab1bbe976957b746e28ea9`) and
policy, verify, high-water and lookup cases with the Go outcome of each.
`tests/python/test_static_revocation.py` requires the Python verifier to reach
the same outcome on every case.

## Not in this change

- Where operators publish the snapshot (an index path or URL source). The
  validator reads it from a local file.
- `static-site-release-revocation*` JSON schemas and a negative-corpus
  directory; the vectors file is the cross-language contract for now.
- Re-vendoring this verifier into the private edge repository.
