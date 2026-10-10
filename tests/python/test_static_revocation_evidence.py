# SPDX-License-Identifier: AGPL-3.0-only
"""The revocation install envelope binds signed entries at the verifier boundary."""

from __future__ import annotations

import base64
import json

import pytest
from static_cli_context import REVOCATION_ISSUED_EPOCH
from static_context import (
    RELEASE_KEY,
    RELEASE_KEY_ID,
    key,
    raw_public,
    release_bytes,
    release_key,
    revocation_evidence_bytes,
    revocation_policy_bytes,
    revocation_snapshot_bytes,
    sha,
    stored,
    trust_policy,
)

from misscomputer_subnet.static_revocation import (
    StaticRevocationError,
    parse_static_site_release_revocation_trust_policy,
)
from misscomputer_subnet.static_revocation_evidence import (
    verify_bound_static_site_release_revocation,
)

SITE = "sha256:" + "5a" * 32
OTHER_SITE = "sha256:" + "5b" * 32
RELEASE = release_bytes(SITE)
RELEASE_DIGEST = "sha256:" + sha(RELEASE)
RELEASE_POLICY = trust_policy()
POLICY_BYTES = revocation_policy_bytes()
POLICY = parse_static_site_release_revocation_trust_policy(
    POLICY_BYTES,
    pinned_digest_sha256=json.loads(POLICY_BYTES)["digest_sha256"],
    release_policy=RELEASE_POLICY,
)


def _envelope(*, site: str = SITE, signer_public: str | None = None) -> bytes:
    snapshot = revocation_snapshot_bytes(
        1,
        REVOCATION_ISSUED_EPOCH,
        releases=((RELEASE_DIGEST, site, "phishing"),),
        signer_keys=(
            (RELEASE_KEY_ID, signer_public or raw_public(RELEASE_KEY).hex(), "key_compromise"),
        ),
    )
    return stored(
        {
            "schema": "miss.computer/misscomputer-subnet/static-site-release-revocation-evidence",
            "schema_version": 1,
            "snapshot_b64": base64.b64encode(snapshot).decode("ascii"),
            "release_proofs": [
                {
                    "release_digest": RELEASE_DIGEST,
                    "signed_release_b64": base64.b64encode(RELEASE).decode("ascii"),
                }
            ],
        }
    )


def test_bound_revocation_accepts_matching_signed_release_and_key() -> None:
    held = verify_bound_static_site_release_revocation(_envelope(), POLICY, RELEASE_POLICY)
    assert held.verified.release_revoked(RELEASE_DIGEST)
    assert held.verified.site_revoked(SITE)


@pytest.mark.parametrize(
    "payload",
    [
        _envelope(site=OTHER_SITE),
        _envelope(signer_public="11" * 32),
    ],
    ids=["signed release/site mismatch", "signer key/public mismatch"],
)
def test_bound_revocation_rejects_signed_but_unbound_entries(payload: bytes) -> None:
    with pytest.raises(StaticRevocationError, match="revocation_entry_unbound"):
        verify_bound_static_site_release_revocation(payload, POLICY, RELEASE_POLICY)


def test_bound_revocation_accepts_maximum_signed_release_snapshot() -> None:
    """A valid cumulative 4096-release snapshot must remain installable."""

    signer_id = "h" * 64
    proof_policy = trust_policy(release_key(key_id=signer_id))
    releases = tuple(
        release_bytes(
            SITE,
            key_id=signer_id,
            producer_policy_version="p" * 64,
            issued_at=f"2026-09-30T00:00:00.{index * 10 + 11:09d}Z",
        )
        for index in range(4096)
    )
    snapshot = revocation_snapshot_bytes(
        1,
        REVOCATION_ISSUED_EPOCH,
        releases=tuple(("sha256:" + sha(item), SITE, "phishing") for item in releases),
    )
    evidence = revocation_evidence_bytes(snapshot, releases)
    assert len(snapshot) < 1 << 20
    assert len(evidence) > (4 << 20)
    assert (
        verify_bound_static_site_release_revocation(
            evidence, POLICY, proof_policy
        ).verified.snapshot.sequence
        == 1
    )


def test_bound_revocation_accepts_seventeen_retired_signers() -> None:
    """Cumulative signer revocation cannot stall at the old 16-key policy cap."""

    keys = tuple(
        release_key(
            key_id=f"history-{index:02d}",
            public_key_hex=raw_public(key(f"history-{index:02d}")).hex(),
        )
        for index in range(17)
    )
    # Each v1 release policy is independently pinned and retains its 16-key
    # bound. Historical policies jointly prove the cumulative snapshot.
    release_policies = (trust_policy(*keys[:16]), trust_policy(*keys[16:]))
    releases = tuple(
        release_bytes(SITE, private=key(entry.key_id), key_id=entry.key_id) for entry in keys
    )
    snapshot = revocation_snapshot_bytes(
        1,
        REVOCATION_ISSUED_EPOCH,
        releases=tuple(("sha256:" + sha(item), SITE, "key_compromise") for item in releases),
        signer_keys=tuple((entry.key_id, entry.public_key_hex, "key_retired") for entry in keys),
    )
    evidence = revocation_evidence_bytes(snapshot, releases)
    assert (
        verify_bound_static_site_release_revocation(
            evidence, POLICY, release_policies
        ).verified.snapshot.sequence
        == 1
    )
