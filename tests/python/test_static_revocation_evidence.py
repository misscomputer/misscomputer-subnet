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
    raw_public,
    release_bytes,
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
