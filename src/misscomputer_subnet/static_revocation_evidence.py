# SPDX-License-Identifier: AGPL-3.0-only
"""Self-authenticating evidence for every entry in a signed revocation snapshot.

The authority's v1 snapshot remains the signed high-water object. This
canonical envelope carries the exact snapshot and signed releases it names;
the verifier binds each release digest to its site and each signer-key pair
to the pinned release policy. Consumers must persist and re-check the whole
envelope, not install the inner snapshot directly.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from typing import Literal

from pydantic import Field, model_validator

from .contract_codec import StrictFrozenModel, model_bytes, parse_model, revalidate
from .organic_contracts import Digest as PrefixedDigest
from .static_index import (
    MAX_RELEASE_BYTES,
    StaticSiteRelease,
    StaticSiteReleaseTrustPolicy,
    _verify_release,
    static_site_release_bytes,
    stored_digest,
)
from .static_revocation import (
    MAX_REVOCATION_SNAPSHOT_BYTES,
    MAX_REVOKED_RELEASES,
    StaticRevocationError,
    StaticSiteReleaseRevocationTrustPolicy,
    VerifiedRevocation,
    verify_static_site_release_revocation,
)

MAX_BOUND_REVOCATION_BYTES = 4 << 20


class ReleaseProof(StrictFrozenModel):
    release_digest: PrefixedDigest
    signed_release_b64: str


class BoundRevocation(StrictFrozenModel):
    """Exact snapshot bytes and one signed-release proof per release entry."""

    contract_schema: Literal[
        "miss.computer/misscomputer-subnet/static-site-release-revocation-evidence"
    ] = Field(alias="schema")
    schema_version: Literal[1]
    snapshot_b64: str
    release_proofs: list[ReleaseProof] = Field(max_length=MAX_REVOKED_RELEASES)

    @model_validator(mode="after")
    def ordered_proofs(self) -> BoundRevocation:
        digests = [proof.release_digest for proof in self.release_proofs]
        if any(left >= right for left, right in zip(digests, digests[1:], strict=False)):
            raise ValueError("release_proofs_not_strictly_ascending")
        return self


@dataclass(frozen=True, slots=True)
class VerifiedBoundRevocation:
    verified: VerifiedRevocation
    stored: bytes


def bound_revocation_bytes(value: BoundRevocation) -> bytes:
    return model_bytes(value, BoundRevocation)


def _decoded(encoded: str, maximum: int) -> bytes:
    try:
        stored = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise StaticRevocationError("revocation_entry_unbound") from exc
    if not stored or len(stored) > maximum or base64.b64encode(stored).decode("ascii") != encoded:
        raise StaticRevocationError("revocation_entry_unbound")
    return stored


def verify_bound_static_site_release_revocation(
    stored: bytes,
    revocation_policy: StaticSiteReleaseRevocationTrustPolicy,
    release_policy: StaticSiteReleaseTrustPolicy,
) -> VerifiedBoundRevocation:
    """Verify authority, release/site bindings, and signer-key identity.

    The signed snapshot's digest and sequence remain the high-water values.
    Its enclosing evidence bytes must be retained for restart verification.
    """

    release_policy = revalidate(release_policy, StaticSiteReleaseTrustPolicy)
    try:
        envelope = parse_model(
            stored,
            BoundRevocation,
            bound_revocation_bytes,
            maximum_bytes=MAX_BOUND_REVOCATION_BYTES,
        )
    except ValueError as exc:
        raise StaticRevocationError("revocation_entry_unbound") from exc
    snapshot = _decoded(envelope.snapshot_b64, MAX_REVOCATION_SNAPSHOT_BYTES)
    verified = verify_static_site_release_revocation(snapshot, revocation_policy)
    entries = verified.snapshot.revoked_releases
    if [proof.release_digest for proof in envelope.release_proofs] != [
        entry.release_digest for entry in entries
    ]:
        raise StaticRevocationError("revocation_entry_unbound")
    for entry, proof in zip(entries, envelope.release_proofs, strict=True):
        release_bytes = _decoded(proof.signed_release_b64, MAX_RELEASE_BYTES)
        if stored_digest(release_bytes) != entry.release_digest:
            raise StaticRevocationError("revocation_entry_unbound")
        try:
            release = parse_model(
                release_bytes,
                StaticSiteRelease,
                static_site_release_bytes,
                maximum_bytes=MAX_RELEASE_BYTES,
            )
        except ValueError as exc:
            raise StaticRevocationError("revocation_entry_unbound") from exc
        if release.site_digest != entry.site_digest or _verify_release(release, release_policy):
            raise StaticRevocationError("revocation_entry_unbound")
    pinned_keys = {(key.key_id, key.public_key_hex) for key in release_policy.trusted_keys}
    if any(
        (entry.key_id, entry.public_key_hex) not in pinned_keys
        for entry in verified.snapshot.revoked_signer_keys
    ):
        raise StaticRevocationError("revocation_entry_unbound")
    return VerifiedBoundRevocation(verified=verified, stored=bytes(stored))
