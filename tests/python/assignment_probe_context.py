# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic manifest trust fixtures shared by the organic manifest tests.

Keys, the pinned trust policy and the chain constants every signed
active-assignment manifest test uses. Every key is derived from a fixed label,
so the committed bytes are reproducible and contain no real secret material.
"""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Sequence
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import BaseModel

from misscomputer_subnet.assignment_probe import (
    MANIFEST_PURPOSE,
    AssignmentManifestTrustPolicy,
    ManifestRole,
    TrustedManifestKey,
    build_assignment_manifest_trust_policy,
)

ROOT = Path(__file__).resolve().parents[2]
BASE_EPOCH = 1_800_000_000
EVALUATION_EPOCH = BASE_EPOCH + 200
ROUTE_SUFFIX = "mock.local"
PROBE_PORT = 443
FINALIZED_HEIGHT = 12_345_678
CENTRAL_AUTHORITY = hashlib.sha256(b"assignment-probe-central-authority").hexdigest()
FINALIZED_BLOCK_HASH = hashlib.sha256(b"assignment-probe-finalized-block").hexdigest()
FINALIZED_EPOCH = 42
SIGNER_ROLES: dict[str, ManifestRole] = {
    "auditor": "assignment_auditor",
    "issuer": "assignment_issuer",
    "security": "assignment_security",
}
MINERS: tuple[tuple[int, str], ...] = (
    (10, "MinerA"),
    (11, "MinerB"),
    (12, "MinerC"),
    (13, "MinerD"),
)


def canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def digest(value: object) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def label_digest(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def deterministic_key(label: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(label.encode("ascii")).digest())


def raw_public(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def signer_keys() -> dict[str, Ed25519PrivateKey]:
    return {key_id: deterministic_key(f"assignment-manifest-{key_id}") for key_id in SIGNER_ROLES}


def miner_key(hotkey: str) -> Ed25519PrivateKey:
    return deterministic_key(f"miner-service-{hotkey}")


def miner_service_public_key(hotkey: str) -> str:
    return raw_public(miner_key(hotkey)).hex()


def trusted_key(
    key_id: str,
    key: Ed25519PrivateKey,
    role: ManifestRole,
    *,
    valid_from: int = BASE_EPOCH - 1_000,
    valid_until: int = BASE_EPOCH + 100_000,
    revoked_at: int | None = None,
) -> TrustedManifestKey:
    public = raw_public(key)
    return TrustedManifestKey.model_validate(
        {
            "key_id": key_id,
            "algorithm": "ed25519",
            "public_key_base64": base64.b64encode(public).decode("ascii"),
            "public_key_sha256": hashlib.sha256(public).hexdigest(),
            "roles": [role],
            "purposes": [MANIFEST_PURPOSE],
            "valid_from_epoch": valid_from,
            "valid_until_epoch": valid_until,
            "revoked_at_epoch": revoked_at,
        }
    )


def build_policy(
    keys: dict[str, Ed25519PrivateKey],
    *,
    threshold: int = 2,
    required_roles: Sequence[ManifestRole] = ("assignment_auditor", "assignment_issuer"),
    key_windows: dict[str, tuple[int, int]] | None = None,
    revoked: dict[str, int | None] | None = None,
    max_age: int = 600,
    max_future_skew: int = 5,
    valid_from: int = BASE_EPOCH - 1_000,
    max_finalized_height_gap: int = 100,
    allowed_route_host_suffixes: Sequence[str] = (ROUTE_SUFFIX,),
    probe_timeout_millis: int = 5_000,
    max_response_bytes: int = 4_096,
    pinned_edge_leaf_certificate_sha256: Sequence[str] = (),
    central_authority: str = CENTRAL_AUTHORITY,
) -> AssignmentManifestTrustPolicy:
    key_models = []
    for key_id in sorted(keys):
        start, end = (key_windows or {}).get(key_id, (BASE_EPOCH - 1_000, BASE_EPOCH + 100_000))
        key_models.append(
            trusted_key(
                key_id,
                keys[key_id],
                SIGNER_ROLES[key_id],
                valid_from=start,
                valid_until=end,
                revoked_at=(revoked or {}).get(key_id),
            )
        )
    return build_assignment_manifest_trust_policy(
        central_authority_fingerprint_sha256=central_authority,
        threshold=threshold,
        required_roles=required_roles,
        trusted_keys=key_models,
        valid_from_epoch=valid_from,
        valid_until_epoch=BASE_EPOCH + 100_000,
        max_manifest_age_seconds=max_age,
        max_future_skew_seconds=max_future_skew,
        max_manifest_lifetime_seconds=3_600,
        max_sequence_gap=4,
        max_finalized_height_gap=max_finalized_height_gap,
        allowed_route_host_suffixes=allowed_route_host_suffixes,
        probe_timeout_millis=probe_timeout_millis,
        max_response_bytes=max_response_bytes,
        pinned_edge_leaf_certificate_sha256=pinned_edge_leaf_certificate_sha256,
    )


def schema_bytes(model: type[BaseModel]) -> bytes:
    rendered = json.dumps(model.model_json_schema(), indent=2, sort_keys=True, ensure_ascii=True)
    return (rendered + "\n").encode("ascii")
