# SPDX-License-Identifier: AGPL-3.0-only
"""Validator verification of the signed static release revocation snapshot.

Static-site contract §7.3 (security review SR-03, rollout drill D22).

One **revocation authority**, separate from the release authority, signs one
cumulative ``static-site-release-revocation`` v1 snapshot of every revoked
``static-site-release`` digest and every revoked release signer key. Its
``static-site-release-revocation-trust-policy`` v1 has the §7.2 shape under
its own schema, threshold 1, and is pinned out of band. None of its keys may
be a key of the pinned release trust policy, so a compromised release key can
neither sign nor undo a revocation.

A verifier keeps the highest snapshot it accepted (its **high water**) and
accepts a verified snapshot only when it is byte-identical to the high water,
or has a higher ``sequence``, an ``issued_at`` that is not earlier, and every
high-water entry unchanged. Anything else is ``revocation_rollback``,
``revocation_equivocation`` or ``revocation_not_cumulative``. A revocation is
final: nothing here lifts one.

A release is revoked when its ``release_digest`` is listed, or when its signer
is listed by ``key_id`` **or** by public key, whatever the release's
``issued_at`` (a compromised key can backdate). Unknown or expired release
keys are not revocations; :mod:`misscomputer_subnet.static_index` already
abstains on those.

The snapshot carries no expiry. A validator relies on its high water only
while ``issued_at`` is at most ``max_age_seconds`` old and not more than
:data:`MAX_FUTURE_SKEW_SECONDS` ahead of its clock
(:func:`revocation_freshness`); the authority reissues the same set under a
higher ``sequence`` to keep it fresh.

This module is pure: no clock, network, file, process, environment, wallet,
chain, randomness, or signing capability.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Literal, Self

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import Field, model_validator

from .contract_codec import (
    StrictFrozenModel,
    canonical_json,
    digest,
    model_bytes,
    model_document,
    parse_model,
    revalidate,
    verify_model_digest,
)
from .ed25519_trust import decode_ed25519_public_key_hex
from .organic_contracts import Digest as PrefixedDigest
from .organic_contracts import Hex64, HexSignature, Timestamp
from .organic_probe import timestamp_epoch_seconds
from .protocol import _rfc3339nano_instant
from .static_index import (
    MAX_RELEASE_KEYS,
    KeyID,
    StaticReleaseKey,
    StaticSiteReleaseTrustPolicy,
    VerifiedStaticIndex,
    stored_digest,
)

STATIC_SITE_RELEASE_REVOCATION_SCHEMA: Final = (
    "miss.computer/misscomputer-subnet/static-site-release-revocation"
)
STATIC_SITE_RELEASE_REVOCATION_TRUST_POLICY_SCHEMA: Final = (
    "miss.computer/misscomputer-subnet/static-site-release-revocation-trust-policy"
)
STATIC_SITE_RELEASE_REVOCATION_DOMAIN_SEPARATOR: Final = (
    b"miss.computer/misscomputer-subnet/static-site-release-revocation/v1/ed25519"
)

#: §7.3 bounds.
MAX_REVOCATION_SNAPSHOT_BYTES: Final = 1 << 20
MAX_REVOCATION_POLICY_BYTES: Final = 64 * 1_024
MAX_REVOKED_RELEASES: Final = 4_096
MAX_REVOKED_SIGNER_KEYS: Final = 64
#: Keeps ``sequence`` exact in every JSON implementation.
MAX_REVOCATION_SEQUENCE: Final = (1 << 53) - 1

#: Validator freshness rule (not a wire field).
MAX_FUTURE_SKEW_SECONDS: Final = 300
DEFAULT_MAX_AGE_SECONDS: Final = 86_400
MIN_MAX_AGE_SECONDS: Final = 300
MAX_MAX_AGE_SECONDS: Final = 7 * 86_400

#: The security review §5 takedown categories plus the issuing signer's compromise.
ReleaseReason = Literal[
    "credential_harvesting",
    "illegal_content",
    "key_compromise",
    "malware",
    "phishing",
    "platform_integrity",
]
SignerKeyReason = Literal["key_compromise", "key_retired"]

RevocationCode = Literal[
    "revocation_policy_invalid",
    "revocation_policy_digest_mismatch",
    "revocation_policy_key_not_dedicated",
    "revocation_snapshot_invalid",
    "revocation_signer_untrusted",
    "revocation_signer_outside_validity",
    "revocation_signature_invalid",
    "revocation_rollback",
    "revocation_equivocation",
    "revocation_not_cumulative",
]
FreshnessCode = Literal["revocation_stale", "revocation_issued_in_future"]


class StaticRevocationError(ValueError):
    """A refused revocation policy or snapshot, with its stable §7.3 code."""

    def __init__(self, code: RevocationCode) -> None:
        super().__init__(code)
        self.code: RevocationCode = code


class StaticSiteReleaseRevocationTrustPolicy(StrictFrozenModel):
    """``static-site-release-revocation-trust-policy`` v1; threshold is 1."""

    contract_schema: Literal[
        "miss.computer/misscomputer-subnet/static-site-release-revocation-trust-policy"
    ] = Field(alias="schema")
    schema_version: Literal[1]
    policy_id: KeyID
    trusted_keys: list[StaticReleaseKey] = Field(min_length=1, max_length=MAX_RELEASE_KEYS)
    digest_sha256: Hex64

    @model_validator(mode="after")
    def distinct_keys(self) -> Self:
        if len({item.key_id for item in self.trusted_keys}) != len(self.trusted_keys):
            raise ValueError("trusted_key_id_duplicate")
        if len({item.public_key_hex for item in self.trusted_keys}) != len(self.trusted_keys):
            raise ValueError("trusted_public_key_duplicate")
        verify_model_digest(self, "digest_sha256")
        return self


class RevokedRelease(StrictFrozenModel):
    reason_category: ReleaseReason
    release_digest: PrefixedDigest
    site_digest: PrefixedDigest


class RevokedSignerKey(StrictFrozenModel):
    key_id: KeyID
    public_key_hex: Hex64
    reason_category: SignerKeyReason


class StaticSiteReleaseRevocation(StrictFrozenModel):
    """``static-site-release-revocation`` v1: one cumulative, signed snapshot."""

    issued_at: Timestamp
    revoked_releases: list[RevokedRelease] = Field(max_length=MAX_REVOKED_RELEASES)
    revoked_signer_keys: list[RevokedSignerKey] = Field(max_length=MAX_REVOKED_SIGNER_KEYS)
    contract_schema: Literal["miss.computer/misscomputer-subnet/static-site-release-revocation"] = (
        Field(alias="schema")
    )
    schema_version: Literal[1]
    sequence: int = Field(ge=1, le=MAX_REVOCATION_SEQUENCE)
    signature: HexSignature
    signer_key_id: KeyID

    @model_validator(mode="after")
    def strictly_ordered(self) -> Self:
        releases = [item.release_digest for item in self.revoked_releases]
        if any(left >= right for left, right in zip(releases, releases[1:], strict=False)):
            raise ValueError("revoked_releases_not_strictly_ascending")
        key_ids = [item.key_id for item in self.revoked_signer_keys]
        if any(left >= right for left, right in zip(key_ids, key_ids[1:], strict=False)):
            raise ValueError("revoked_signer_keys_not_strictly_ascending")
        if len({item.public_key_hex for item in self.revoked_signer_keys}) != len(key_ids):
            raise ValueError("revoked_signer_public_key_duplicate")
        return self


def build_static_site_release_revocation_trust_policy(
    *, policy_id: str, trusted_keys: list[StaticReleaseKey]
) -> StaticSiteReleaseRevocationTrustPolicy:
    """Seal a local public-key policy; no secret key material is accepted."""

    unsigned: dict[str, object] = {
        "schema": STATIC_SITE_RELEASE_REVOCATION_TRUST_POLICY_SCHEMA,
        "schema_version": 1,
        "policy_id": policy_id,
        "trusted_keys": [
            model_document(revalidate(item, StaticReleaseKey)) for item in trusted_keys
        ],
    }
    return StaticSiteReleaseRevocationTrustPolicy.model_validate(
        {**unsigned, "digest_sha256": digest(unsigned)}
    )


def static_site_release_revocation_trust_policy_bytes(
    value: StaticSiteReleaseRevocationTrustPolicy,
) -> bytes:
    return model_bytes(value, StaticSiteReleaseRevocationTrustPolicy)


def static_site_release_revocation_bytes(value: StaticSiteReleaseRevocation) -> bytes:
    return model_bytes(value, StaticSiteReleaseRevocation)


def static_site_release_revocation_message(value: StaticSiteReleaseRevocation) -> bytes:
    """The only bytes a revocation key signs: domain, NUL, canonical unsigned snapshot."""

    unsigned = model_document(revalidate(value, StaticSiteReleaseRevocation), exclude={"signature"})
    return STATIC_SITE_RELEASE_REVOCATION_DOMAIN_SEPARATOR + b"\x00" + canonical_json(unsigned)


def parse_static_site_release_revocation_trust_policy(
    stored: bytes,
    *,
    pinned_digest_sha256: str,
    release_policy: StaticSiteReleaseTrustPolicy,
) -> StaticSiteReleaseRevocationTrustPolicy:
    """Accept exact canonical policy bytes that are the pinned, dedicated policy.

    ``pinned_digest_sha256`` is the policy's ``digest_sha256``. Every key must
    be absent from ``release_policy`` by public key.
    """

    try:
        policy = parse_model(
            stored,
            StaticSiteReleaseRevocationTrustPolicy,
            static_site_release_revocation_trust_policy_bytes,
            maximum_bytes=MAX_REVOCATION_POLICY_BYTES,
        )
    except ValueError as exc:
        raise StaticRevocationError("revocation_policy_invalid") from exc
    if policy.digest_sha256 != pinned_digest_sha256:
        raise StaticRevocationError("revocation_policy_digest_mismatch")
    release_keys = {item.public_key_hex for item in release_policy.trusted_keys}
    if any(item.public_key_hex in release_keys for item in policy.trusted_keys):
        raise StaticRevocationError("revocation_policy_key_not_dedicated")
    return policy


@dataclass(frozen=True, slots=True)
class VerifiedRevocation:
    """A snapshot whose stored bytes and authority signature verified under a pinned policy."""

    snapshot: StaticSiteReleaseRevocation
    #: ``"sha256:" + hex(SHA-256(stored))``.
    snapshot_digest: str
    stored: bytes
    policy_digest_sha256: str

    def release_revoked(self, release_digest: str) -> bool:
        return any(item.release_digest == release_digest for item in self.snapshot.revoked_releases)

    def signer_revoked(self, key_id: str, public_key_hex: str) -> bool:
        """Match either identity, so a revoked key cannot return under a new ID or vice versa."""

        return any(
            item.key_id == key_id or item.public_key_hex == public_key_hex
            for item in self.snapshot.revoked_signer_keys
        )


def verify_static_site_release_revocation(
    stored: bytes, policy: StaticSiteReleaseRevocationTrustPolicy
) -> VerifiedRevocation:
    """Verify exact stored snapshot bytes (canonical JSON plus one newline)."""

    policy = revalidate(policy, StaticSiteReleaseRevocationTrustPolicy)
    try:
        snapshot = parse_model(
            stored,
            StaticSiteReleaseRevocation,
            static_site_release_revocation_bytes,
            maximum_bytes=MAX_REVOCATION_SNAPSHOT_BYTES,
        )
    except ValueError as exc:
        raise StaticRevocationError("revocation_snapshot_invalid") from exc
    key = next(
        (item for item in policy.trusted_keys if item.key_id == snapshot.signer_key_id), None
    )
    if key is None:
        raise StaticRevocationError("revocation_signer_untrusted")
    issued = timestamp_epoch_seconds(snapshot.issued_at)
    if not key.valid_from_epoch <= issued < key.valid_until_epoch:
        raise StaticRevocationError("revocation_signer_outside_validity")
    try:
        Ed25519PublicKey.from_public_bytes(
            decode_ed25519_public_key_hex(key.public_key_hex)
        ).verify(
            bytes.fromhex(snapshot.signature), static_site_release_revocation_message(snapshot)
        )
    except (InvalidSignature, ValueError) as exc:
        raise StaticRevocationError("revocation_signature_invalid") from exc
    return VerifiedRevocation(
        snapshot=snapshot,
        snapshot_digest=stored_digest(stored),
        stored=bytes(stored),
        policy_digest_sha256=policy.digest_sha256,
    )


def advance_static_site_release_revocation(
    held: VerifiedRevocation | None, offered: VerifiedRevocation
) -> bool:
    """Whether ``offered`` replaces the high water ``held``; ``False`` for an exact replay.

    Raises :class:`StaticRevocationError` for a rollback, an equivocation or a
    snapshot that is not cumulative.
    """

    if held is None:
        return True
    old, new = held.snapshot, offered.snapshot
    if new.sequence == old.sequence:
        if offered.snapshot_digest == held.snapshot_digest:
            return False
        raise StaticRevocationError("revocation_equivocation")
    if new.sequence < old.sequence:
        raise StaticRevocationError("revocation_rollback")
    if _rfc3339nano_instant(new.issued_at) < _rfc3339nano_instant(old.issued_at):
        raise StaticRevocationError("revocation_rollback")
    if not set(old.revoked_releases) <= set(new.revoked_releases) or not set(
        old.revoked_signer_keys
    ) <= set(new.revoked_signer_keys):
        raise StaticRevocationError("revocation_not_cumulative")
    return True


def revocation_freshness(
    held: VerifiedRevocation, *, now_epoch: int, max_age_seconds: int
) -> FreshnessCode | None:
    """``None`` when a validator may rely on ``held`` at ``now_epoch``."""

    issued = timestamp_epoch_seconds(held.snapshot.issued_at)
    if issued > now_epoch + MAX_FUTURE_SKEW_SECONDS:
        return "revocation_issued_in_future"
    if now_epoch - issued > max_age_seconds:
        return "revocation_stale"
    return None


def static_index_revoked(
    held: VerifiedRevocation,
    index: VerifiedStaticIndex,
    release_policy: StaticSiteReleaseTrustPolicy,
) -> bool:
    """Whether an authenticated static index names a revoked release or signer.

    ``release_policy`` must be the policy ``index`` was authenticated under;
    otherwise the signer's public key is unknown and the release counts as
    revoked (fail closed).
    """

    if held.release_revoked(index.target.release_digest):
        return True
    signer_key_id = index.release.signer_key_id
    key = next((item for item in release_policy.trusted_keys if item.key_id == signer_key_id), None)
    if key is None or index.trust_policy_digest_sha256 != release_policy.digest_sha256:
        return True
    return held.signer_revoked(signer_key_id, key.public_key_hex)
