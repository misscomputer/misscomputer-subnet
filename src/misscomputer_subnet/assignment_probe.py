# SPDX-License-Identifier: AGPL-3.0-only
"""Pure trust, signature, and chain rules shared by every signed assignment manifest.

The frozen ``assignment-manifest-trust-policy`` v1, ``-signature-envelope`` v1
and ``-chain-state`` v1 documents name the central publication *channel*, not
a manifest schema version. The organic ``active-assignment-manifest`` v2
(:mod:`misscomputer_subnet.organic_manifest`) is verified under them with the
header-generic rules here: policy admission, threshold signatures over a
version's domain-separated message, and append-only chain advancement. The
synthetic ``active-assignment-manifest`` v1, its challenge probe, attestation
v1 and probe report were never live and are removed (contract section 13).

The module also defines the observed-response types the bounded HTTPS
transport hands to the organic probe evaluator. It deliberately has no file,
environment, clock, randomness, network, process, chain-client, credential,
signing, submission, scheduling, or activation capability.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Annotated, Final, Literal, NoReturn, Protocol, Self, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from .ed25519_trust import (
    Ed25519PublicKeyValidationError,
    decode_ed25519_public_key_base64,
)

MANIFEST_TRUST_POLICY_SCHEMA: Final = (
    "miss.computer/misscomputer-subnet/assignment-manifest-trust-policy"
)
MANIFEST_SIGNATURE_ENVELOPE_SCHEMA: Final = (
    "miss.computer/misscomputer-subnet/assignment-manifest-signature-envelope"
)
MANIFEST_CHAIN_STATE_SCHEMA: Final = (
    "miss.computer/misscomputer-subnet/assignment-manifest-chain-state"
)
PROBE_SCHEMA_VERSION: Final = 1
MANIFEST_PURPOSE: Final = "active_assignment_manifest_publication_v1"
MANIFEST_TRUST_POLICY_ID: Final = "miss-computer-active-assignment-manifest-trust-v1"
MAINNET_NETWORK: Final = "finney"
MAINNET_NETUID: Final = 24
MAX_KEYS: Final = 16
MAX_ROUTE_SUFFIXES: Final = 16
MAX_PINNED_CERTIFICATES: Final = 16
MAX_DOCUMENT_BYTES: Final = 64 * 1_024 * 1_024
MAX_RESPONSE_BYTES_CEILING: Final = 1_024 * 1_024
MAX_LATENCY_MILLIS: Final = 3_600_000
MAX_EPOCH: Final = (1 << 63) - 1
#: Ceiling on a trust policy's ``max_future_skew_seconds``: no policy may let a
#: manifest's ``issued_at_epoch`` lead the evaluating validator's clock by more.
MAX_FUTURE_SKEW_SECONDS: Final = 300

Digest = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
Hex64 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
Hotkey = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9]{1,128}$")]
KeyID = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=64,
        pattern=r"^[a-z0-9](?:[a-z0-9_-]{0,62}[a-z0-9])?$",
    ),
]
DeploymentID = Annotated[
    str,
    StringConstraints(max_length=63, pattern=r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"),
]
RouteHost = Annotated[
    str,
    StringConstraints(
        max_length=253,
        pattern=(
            r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
            r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$"
        ),
    ),
]
EndpointID = Annotated[str, StringConstraints(min_length=3, max_length=320)]
UID = Annotated[int, Field(ge=0, le=(1 << 16) - 1)]
Epoch = Annotated[int, Field(ge=0, le=MAX_EPOCH)]
PositiveEpoch = Annotated[int, Field(ge=1, le=MAX_EPOCH)]
ManifestRole = Literal["assignment_auditor", "assignment_issuer", "assignment_security"]
TransportFailureCode = Literal[
    "connection_failed",
    "response_oversized",
    "timeout",
    "tls_certificate_invalid",
    "tls_handshake_failed",
    "transport_error",
]

ProbeRejectionCode = Literal[
    "authority_mismatch",
    "finalized_epoch_rollback",
    "finalized_height_gap",
    "finalized_height_rollback",
    "issued_at_rollback",
    "manifest_expired",
    "manifest_future",
    "manifest_lifetime_invalid",
    "manifest_replica_lease_expired",
    "manifest_stale",
    "network_mismatch",
    "previous_link_mismatch",
    "probe_scheme_mismatch",
    "required_role_missing",
    "route_host_policy_violation",
    "same_height_fork",
    "same_sequence_divergence",
    "sequence_gap",
    "sequence_rollback",
    "signature_binding_mismatch",
    "signature_invalid",
    "signer_expired",
    "signer_key_invalid",
    "signer_not_yet_valid",
    "signer_purpose_mismatch",
    "signer_revoked",
    "signer_untrusted",
    "threshold_not_met",
    "trust_policy_expired",
    "trust_policy_mismatch",
    "trust_policy_not_yet_valid",
]


class AssignmentProbeError(ValueError):
    """Stable, sanitized fail-closed manifest rejection."""

    def __init__(self, code: ProbeRejectionCode) -> None:
        super().__init__(code)
        self.code = code


def _reject(code: ProbeRejectionCode) -> NoReturn:
    raise AssignmentProbeError(code)


class _StrictFrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class ManifestHeader(Protocol):
    """Header fields every signed active-assignment manifest version shares.

    The trust policy, signature envelope and chain state name the publication
    channel, not a manifest schema version. Policy binding, signer checks and
    chain advancement read only these fields, so every manifest version (today
    the organic ``v2``, :mod:`misscomputer_subnet.organic_manifest`) is verified
    by the same rules; each version signs under its own domain separator.
    """

    @property
    def network(self) -> str: ...
    @property
    def netuid(self) -> int: ...
    @property
    def central_authority_fingerprint_sha256(self) -> str: ...
    @property
    def trust_policy_digest_sha256(self) -> str: ...
    @property
    def finalized_height(self) -> int: ...
    @property
    def finalized_block_hash(self) -> str: ...
    @property
    def finalized_epoch(self) -> int: ...
    @property
    def sequence(self) -> int: ...
    @property
    def previous_manifest_digest_sha256(self) -> str | None: ...
    @property
    def issued_at_epoch(self) -> int: ...
    @property
    def expires_at_epoch(self) -> int: ...
    @property
    def route_host_suffix(self) -> str: ...
    @property
    def probe_scheme(self) -> str: ...
    @property
    def manifest_digest_sha256(self) -> str: ...


def _canonical_json(value: object) -> bytes:
    try:
        rendered = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError, RecursionError) as exc:
        raise ValueError("canonical_json_invalid") from exc
    return rendered.encode("ascii")


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _model_document(model: BaseModel, *, exclude: set[str] | None = None) -> dict[str, object]:
    return cast(
        dict[str, object],
        model.model_dump(mode="json", by_alias=True, exclude=exclude),
    )


def _verify_model_digest(model: BaseModel, field_name: str) -> None:
    document = _model_document(model, exclude={field_name})
    if cast(str, getattr(model, field_name)) != _digest(document):
        raise ValueError(f"{field_name}_mismatch")


def _revalidate[ModelT: BaseModel](value: ModelT, model_type: type[ModelT]) -> ModelT:
    return model_type.model_validate(value.model_dump(mode="json", by_alias=True))


def _decode_base64(value: str, *, expected_bytes: int) -> bytes:
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("base64_invalid") from exc
    if len(decoded) != expected_bytes or base64.b64encode(decoded).decode("ascii") != value:
        raise ValueError("base64_invalid")
    return decoded


class TrustedManifestKey(_StrictFrozenModel):
    key_id: KeyID
    algorithm: Literal["ed25519"]
    public_key_base64: Annotated[str, StringConstraints(min_length=44, max_length=44)]
    public_key_sha256: Digest
    roles: list[ManifestRole] = Field(min_length=1, max_length=3)
    purposes: list[Literal["active_assignment_manifest_publication_v1"]] = Field(
        min_length=1, max_length=1
    )
    valid_from_epoch: Epoch
    valid_until_epoch: Epoch
    revoked_at_epoch: Epoch | None

    @model_validator(mode="after")
    def valid_key(self) -> Self:
        public_bytes = decode_ed25519_public_key_base64(self.public_key_base64)
        if hashlib.sha256(public_bytes).hexdigest() != self.public_key_sha256:
            raise ValueError("public_key_digest_mismatch")
        if self.roles != sorted(set(self.roles)):
            raise ValueError("key_roles_not_canonical")
        if self.purposes != [MANIFEST_PURPOSE]:
            raise ValueError("key_purpose_invalid")
        if self.valid_until_epoch <= self.valid_from_epoch:
            raise ValueError("key_validity_window_invalid")
        if self.revoked_at_epoch is not None and not (
            self.valid_from_epoch <= self.revoked_at_epoch <= self.valid_until_epoch
        ):
            raise ValueError("key_revocation_epoch_invalid")
        return self


class AssignmentManifestTrustPolicy(_StrictFrozenModel):
    """Validator-local pin of the central manifest authority and probe bounds."""

    contract_schema: Literal[
        "miss.computer/misscomputer-subnet/assignment-manifest-trust-policy"
    ] = Field(alias="schema")
    schema_version: Literal[1]
    policy_id: Literal["miss-computer-active-assignment-manifest-trust-v1"]
    purpose: Literal["active_assignment_manifest_publication_v1"]
    network: Literal["finney", "test"]
    netuid: Literal[24, 581]
    central_authority_fingerprint_sha256: Digest
    threshold: int = Field(ge=1, le=MAX_KEYS)
    required_roles: list[ManifestRole] = Field(min_length=1, max_length=3)
    trusted_keys: list[TrustedManifestKey] = Field(min_length=1, max_length=MAX_KEYS)
    valid_from_epoch: Epoch
    valid_until_epoch: Epoch
    max_manifest_age_seconds: int = Field(ge=1, le=86_400)
    max_future_skew_seconds: int = Field(ge=0, le=MAX_FUTURE_SKEW_SECONDS)
    max_manifest_lifetime_seconds: int = Field(ge=1, le=86_400)
    max_sequence_gap: int = Field(ge=1, le=64)
    max_finalized_height_gap: int = Field(ge=1, le=1_000_000)
    allowed_route_host_suffixes: list[RouteHost] = Field(
        min_length=1, max_length=MAX_ROUTE_SUFFIXES
    )
    probe_scheme: Literal["https"]
    probe_timeout_millis: int = Field(ge=100, le=60_000)
    max_response_bytes: int = Field(ge=64, le=MAX_RESPONSE_BYTES_CEILING)
    pinned_edge_leaf_certificate_sha256: list[Digest] = Field(max_length=MAX_PINNED_CERTIFICATES)
    trust_policy_digest_sha256: Digest

    @model_validator(mode="after")
    def canonical_policy(self) -> Self:
        if (self.network, self.netuid) not in {("finney", 24), ("test", 581)}:
            raise ValueError("static_subnet_invalid")
        if self.valid_until_epoch <= self.valid_from_epoch:
            raise ValueError("trust_policy_validity_window_invalid")
        if self.required_roles != sorted(set(self.required_roles)):
            raise ValueError("required_roles_not_canonical")
        key_ids = [item.key_id for item in self.trusted_keys]
        if key_ids != sorted(set(key_ids)):
            raise ValueError("trusted_keys_not_canonical")
        public_keys = [item.public_key_sha256 for item in self.trusted_keys]
        if len(public_keys) != len(set(public_keys)):
            raise ValueError("trusted_public_key_duplicate")
        if self.threshold > len(self.trusted_keys):
            raise ValueError("threshold_exceeds_key_count")
        covered_roles = {role for key in self.trusted_keys for role in key.roles}
        if not set(self.required_roles) <= covered_roles:
            raise ValueError("required_role_uncovered")
        if self.allowed_route_host_suffixes != sorted(set(self.allowed_route_host_suffixes)):
            raise ValueError("route_host_suffixes_not_canonical")
        if self.pinned_edge_leaf_certificate_sha256 != sorted(
            set(self.pinned_edge_leaf_certificate_sha256)
        ):
            raise ValueError("pinned_certificates_not_canonical")
        _verify_model_digest(self, "trust_policy_digest_sha256")
        return self


class AssignmentManifestSignatureEnvelope(_StrictFrozenModel):
    contract_schema: Literal[
        "miss.computer/misscomputer-subnet/assignment-manifest-signature-envelope"
    ] = Field(alias="schema")
    schema_version: Literal[1]
    purpose: Literal["active_assignment_manifest_publication_v1"]
    algorithm: Literal["ed25519"]
    signer_key_id: KeyID
    manifest_digest_sha256: Digest
    signed_message_digest_sha256: Digest
    signature_base64: Annotated[str, StringConstraints(min_length=88, max_length=88)]

    @model_validator(mode="after")
    def canonical_signature(self) -> Self:
        _decode_base64(self.signature_base64, expected_bytes=64)
        return self


class AssignmentManifestChainState(_StrictFrozenModel):
    """Append-only acceptance state shared by the central producer and each validator."""

    contract_schema: Literal[
        "miss.computer/misscomputer-subnet/assignment-manifest-chain-state"
    ] = Field(alias="schema")
    schema_version: Literal[1]
    purpose: Literal["active_assignment_manifest_publication_v1"]
    network: Literal["finney", "test"]
    netuid: Literal[24, 581]
    central_authority_fingerprint_sha256: Digest
    trust_policy_digest_sha256: Digest
    accepted_manifest_count: Epoch
    last_sequence: Epoch
    last_finalized_height: Epoch | None
    last_finalized_block_hash: Digest | None
    #: Finalized epoch of the last accepted manifest. Carried so that a
    #: publication whose finalized epoch goes backwards, or that pairs one
    #: finalized height with two epochs, is rejected like a height fork.
    last_finalized_epoch: Epoch | None
    last_issued_at_epoch: Epoch | None
    last_expires_at_epoch: Epoch | None
    last_manifest_digest_sha256: Digest | None
    state_digest_sha256: Digest

    @model_validator(mode="after")
    def canonical_state(self) -> Self:
        if (self.network, self.netuid) not in {("finney", 24), ("test", 581)}:
            raise ValueError("static_subnet_invalid")
        tail = (
            self.last_finalized_height,
            self.last_finalized_block_hash,
            self.last_finalized_epoch,
            self.last_issued_at_epoch,
            self.last_expires_at_epoch,
            self.last_manifest_digest_sha256,
        )
        if self.accepted_manifest_count == 0:
            if self.last_sequence != 0 or any(value is not None for value in tail):
                raise ValueError("genesis_chain_state_invalid")
        elif (
            self.last_sequence == 0
            or self.accepted_manifest_count > self.last_sequence
            or any(value is None for value in tail)
        ):
            raise ValueError("nonempty_chain_state_invalid")
        _verify_model_digest(self, "state_digest_sha256")
        return self


@dataclass(frozen=True)
class ProbeResponse:
    """Bytes observed by the transport boundary for exactly one probe request."""

    status: int
    headers: tuple[tuple[str, str], ...]
    body: bytes
    latency_millis: int
    tls_leaf_certificate_sha256: str | None


@dataclass(frozen=True)
class ProbeTransportFailure:
    code: TransportFailureCode
    latency_millis: int
    response_status: int | None = None
    tls_leaf_certificate_sha256: str | None = None
    #: For ``response_oversized``: the size evidence the transport judged, the
    #: declared ``Content-Length`` or the bytes received before the ceiling
    #: was crossed (``MAX_RESPONSE_BYTES_CEILING + 1`` for an unparseable
    #: declaration). Zero for every other code.
    response_bytes: int = 0


def build_assignment_manifest_trust_policy(
    *,
    central_authority_fingerprint_sha256: str,
    threshold: int,
    required_roles: Sequence[ManifestRole],
    trusted_keys: Sequence[TrustedManifestKey],
    valid_from_epoch: int,
    valid_until_epoch: int,
    max_manifest_age_seconds: int,
    max_future_skew_seconds: int,
    max_manifest_lifetime_seconds: int,
    max_sequence_gap: int,
    max_finalized_height_gap: int,
    allowed_route_host_suffixes: Sequence[str],
    probe_timeout_millis: int,
    max_response_bytes: int,
    pinned_edge_leaf_certificate_sha256: Sequence[str] = (),
    network: Literal["finney", "test"] = MAINNET_NETWORK,
    netuid: Literal[24, 581] = MAINNET_NETUID,
) -> AssignmentManifestTrustPolicy:
    """Seal a local public-key trust policy; no secret key material is accepted."""

    keys = sorted(
        (_revalidate(item, TrustedManifestKey) for item in trusted_keys),
        key=lambda item: item.key_id,
    )
    unsigned: dict[str, object] = {
        "schema": MANIFEST_TRUST_POLICY_SCHEMA,
        "schema_version": PROBE_SCHEMA_VERSION,
        "policy_id": MANIFEST_TRUST_POLICY_ID,
        "purpose": MANIFEST_PURPOSE,
        "network": network,
        "netuid": netuid,
        "central_authority_fingerprint_sha256": central_authority_fingerprint_sha256,
        "threshold": threshold,
        "required_roles": sorted(required_roles),
        "trusted_keys": [_model_document(item) for item in keys],
        "valid_from_epoch": valid_from_epoch,
        "valid_until_epoch": valid_until_epoch,
        "max_manifest_age_seconds": max_manifest_age_seconds,
        "max_future_skew_seconds": max_future_skew_seconds,
        "max_manifest_lifetime_seconds": max_manifest_lifetime_seconds,
        "max_sequence_gap": max_sequence_gap,
        "max_finalized_height_gap": max_finalized_height_gap,
        "allowed_route_host_suffixes": sorted(set(allowed_route_host_suffixes)),
        "probe_scheme": "https",
        "probe_timeout_millis": probe_timeout_millis,
        "max_response_bytes": max_response_bytes,
        "pinned_edge_leaf_certificate_sha256": sorted(set(pinned_edge_leaf_certificate_sha256)),
    }
    return AssignmentManifestTrustPolicy.model_validate(
        {**unsigned, "trust_policy_digest_sha256": _digest(unsigned)}
    )


def build_initial_manifest_chain_state(
    trust_policy: AssignmentManifestTrustPolicy,
) -> AssignmentManifestChainState:
    policy = _revalidate(trust_policy, AssignmentManifestTrustPolicy)
    unsigned: dict[str, object] = {
        "schema": MANIFEST_CHAIN_STATE_SCHEMA,
        "schema_version": PROBE_SCHEMA_VERSION,
        "purpose": MANIFEST_PURPOSE,
        "network": policy.network,
        "netuid": policy.netuid,
        "central_authority_fingerprint_sha256": policy.central_authority_fingerprint_sha256,
        "trust_policy_digest_sha256": policy.trust_policy_digest_sha256,
        "accepted_manifest_count": 0,
        "last_sequence": 0,
        "last_finalized_height": None,
        "last_finalized_block_hash": None,
        "last_finalized_epoch": None,
        "last_issued_at_epoch": None,
        "last_expires_at_epoch": None,
        "last_manifest_digest_sha256": None,
    }
    return AssignmentManifestChainState.model_validate(
        {**unsigned, "state_digest_sha256": _digest(unsigned)}
    )


def _verify_policy_binding(
    manifest: ManifestHeader,
    policy: AssignmentManifestTrustPolicy,
    *,
    evaluation_epoch: int,
) -> None:
    """Historical acceptance: everything in ``_verify_trust_and_freshness`` except freshness."""

    if manifest.trust_policy_digest_sha256 != policy.trust_policy_digest_sha256:
        _reject("trust_policy_mismatch")
    if manifest.network != policy.network or manifest.netuid != policy.netuid:
        _reject("network_mismatch")
    if manifest.central_authority_fingerprint_sha256 != policy.central_authority_fingerprint_sha256:
        _reject("authority_mismatch")
    if manifest.probe_scheme != policy.probe_scheme:
        _reject("probe_scheme_mismatch")
    if manifest.route_host_suffix not in policy.allowed_route_host_suffixes:
        _reject("route_host_policy_violation")
    if evaluation_epoch < policy.valid_from_epoch:
        _reject("trust_policy_not_yet_valid")
    if evaluation_epoch >= policy.valid_until_epoch:
        _reject("trust_policy_expired")
    if (
        manifest.issued_at_epoch < policy.valid_from_epoch
        or manifest.expires_at_epoch > policy.valid_until_epoch
    ):
        _reject("trust_policy_mismatch")
    if manifest.expires_at_epoch - manifest.issued_at_epoch > policy.max_manifest_lifetime_seconds:
        _reject("manifest_lifetime_invalid")
    if manifest.issued_at_epoch > evaluation_epoch + policy.max_future_skew_seconds:
        _reject("manifest_future")


def verify_manifest_policy_admission(
    manifest: ManifestHeader,
    policy: AssignmentManifestTrustPolicy,
    *,
    evaluation_epoch: int,
) -> None:
    """Re-derive what live verification demands of a manifest under a policy at an instant.

    Everything live manifest verification requires that depends only on the
    manifest, the policy, and the evaluation instant: the policy-digest,
    network, authority, scheme and route-suffix binding; the
    policy's own validity window at ``evaluation_epoch``; the manifest's
    issue and expiry inside that window; the manifest lifetime; the future
    skew; and staleness. Signatures, block leases, and the effective horizon
    are the caller's own rules and are not repeated here. A decision uses this
    to refuse a report or terminal observation that its named policy could not
    have admitted at the instant it claims.
    """

    _validate_evaluation_epoch(evaluation_epoch)
    _verify_policy_binding(manifest, policy, evaluation_epoch=evaluation_epoch)
    if (
        evaluation_epoch > manifest.issued_at_epoch
        and evaluation_epoch - manifest.issued_at_epoch > policy.max_manifest_age_seconds
    ):
        _reject("manifest_stale")


def _trusted_public_keys(policy: AssignmentManifestTrustPolicy) -> dict[str, bytes]:
    try:
        return {
            item.key_id: decode_ed25519_public_key_base64(item.public_key_base64)
            for item in policy.trusted_keys
        }
    except Ed25519PublicKeyValidationError:
        _reject("signer_key_invalid")


def verify_manifest_signatures(
    manifest: ManifestHeader,
    message: bytes,
    signatures: Sequence[AssignmentManifestSignatureEnvelope],
    policy: AssignmentManifestTrustPolicy,
    *,
    evaluation_epoch: int,
) -> tuple[list[str], list[ManifestRole]]:
    """Verify threshold signatures over ``message``, the manifest's domain-separated bytes."""

    public_keys = _trusted_public_keys(policy)
    message_digest = hashlib.sha256(message).hexdigest()
    trusted = {item.key_id: item for item in policy.trusted_keys}
    signer_ids = [item.signer_key_id for item in signatures]
    if signer_ids != sorted(set(signer_ids)):
        _reject("signature_binding_mismatch")
    verified_ids: list[str] = []
    verified_roles: set[ManifestRole] = set()
    for envelope in signatures:
        key = trusted.get(envelope.signer_key_id)
        if key is None:
            _reject("signer_untrusted")
        if envelope.purpose != MANIFEST_PURPOSE or MANIFEST_PURPOSE not in key.purposes:
            _reject("signer_purpose_mismatch")
        if (
            envelope.manifest_digest_sha256 != manifest.manifest_digest_sha256
            or envelope.signed_message_digest_sha256 != message_digest
        ):
            _reject("signature_binding_mismatch")
        if manifest.issued_at_epoch < key.valid_from_epoch:
            _reject("signer_not_yet_valid")
        if manifest.expires_at_epoch > key.valid_until_epoch or (
            evaluation_epoch >= key.valid_until_epoch
        ):
            _reject("signer_expired")
        if key.revoked_at_epoch is not None and key.revoked_at_epoch <= evaluation_epoch:
            _reject("signer_revoked")
        signature_bytes = _decode_base64(envelope.signature_base64, expected_bytes=64)
        try:
            Ed25519PublicKey.from_public_bytes(public_keys[key.key_id]).verify(
                signature_bytes, message
            )
        except (InvalidSignature, ValueError):
            _reject("signature_invalid")
        verified_ids.append(key.key_id)
        verified_roles.update(key.roles)
    if len(verified_ids) < policy.threshold:
        _reject("threshold_not_met")
    if not set(policy.required_roles) <= verified_roles:
        _reject("required_role_missing")
    return sorted(verified_ids), sorted(verified_roles)


def advance_manifest_header_chain_state(
    state: AssignmentManifestChainState,
    manifest: ManifestHeader,
    policy: AssignmentManifestTrustPolicy,
) -> tuple[AssignmentManifestChainState, bool]:
    """Chain advancement over the shared header; callers revalidate their manifest version."""

    state = _revalidate(state, AssignmentManifestChainState)
    policy = _revalidate(policy, AssignmentManifestTrustPolicy)
    if (
        state.network != manifest.network
        or state.netuid != manifest.netuid
        or state.central_authority_fingerprint_sha256
        != manifest.central_authority_fingerprint_sha256
    ):
        _reject("authority_mismatch")
    if (
        state.trust_policy_digest_sha256 != manifest.trust_policy_digest_sha256
        or state.trust_policy_digest_sha256 != policy.trust_policy_digest_sha256
    ):
        _reject("trust_policy_mismatch")
    if state.accepted_manifest_count == 0:
        if manifest.sequence != 1:
            _reject("sequence_gap")
        if manifest.previous_manifest_digest_sha256 is not None:
            _reject("previous_link_mismatch")
    else:
        if manifest.sequence == state.last_sequence:
            if manifest.manifest_digest_sha256 != state.last_manifest_digest_sha256:
                _reject("same_sequence_divergence")
            return state, True
        if manifest.sequence < state.last_sequence:
            _reject("sequence_rollback")
        if manifest.sequence - state.last_sequence > policy.max_sequence_gap:
            _reject("sequence_gap")
        if manifest.previous_manifest_digest_sha256 != state.last_manifest_digest_sha256:
            _reject("previous_link_mismatch")
        last_height = cast(int, state.last_finalized_height)
        last_issued = cast(int, state.last_issued_at_epoch)
        if manifest.finalized_height < last_height:
            _reject("finalized_height_rollback")
        if manifest.finalized_height - last_height > policy.max_finalized_height_gap:
            _reject("finalized_height_gap")
        last_epoch = cast(int, state.last_finalized_epoch)
        if manifest.finalized_height == last_height and (
            manifest.finalized_block_hash != state.last_finalized_block_hash
            or manifest.finalized_epoch != last_epoch
        ):
            _reject("same_height_fork")
        if manifest.finalized_epoch < last_epoch:
            _reject("finalized_epoch_rollback")
        if manifest.issued_at_epoch < last_issued:
            _reject("issued_at_rollback")
    unsigned: dict[str, object] = {
        "schema": MANIFEST_CHAIN_STATE_SCHEMA,
        "schema_version": PROBE_SCHEMA_VERSION,
        "purpose": MANIFEST_PURPOSE,
        "network": state.network,
        "netuid": state.netuid,
        "central_authority_fingerprint_sha256": state.central_authority_fingerprint_sha256,
        "trust_policy_digest_sha256": state.trust_policy_digest_sha256,
        "accepted_manifest_count": state.accepted_manifest_count + 1,
        "last_sequence": manifest.sequence,
        "last_finalized_height": manifest.finalized_height,
        "last_finalized_block_hash": manifest.finalized_block_hash,
        "last_finalized_epoch": manifest.finalized_epoch,
        "last_issued_at_epoch": manifest.issued_at_epoch,
        "last_expires_at_epoch": manifest.expires_at_epoch,
        "last_manifest_digest_sha256": manifest.manifest_digest_sha256,
    }
    return (
        AssignmentManifestChainState.model_validate(
            {**unsigned, "state_digest_sha256": _digest(unsigned)}
        ),
        False,
    )


def _validate_evaluation_epoch(evaluation_epoch: int) -> None:
    if (
        isinstance(evaluation_epoch, bool)
        or not isinstance(evaluation_epoch, int)
        or not 0 <= evaluation_epoch <= MAX_EPOCH
    ):
        raise ValueError("evaluation_epoch_invalid")


def _model_bytes[ModelT: BaseModel](value: ModelT, model_type: type[ModelT]) -> bytes:
    value = _revalidate(value, model_type)
    return _canonical_json(_model_document(value)) + b"\n"


def assignment_manifest_trust_policy_bytes(value: AssignmentManifestTrustPolicy) -> bytes:
    return _model_bytes(value, AssignmentManifestTrustPolicy)


def assignment_manifest_signature_envelope_bytes(
    value: AssignmentManifestSignatureEnvelope,
) -> bytes:
    return _model_bytes(value, AssignmentManifestSignatureEnvelope)


def assignment_manifest_chain_state_bytes(value: AssignmentManifestChainState) -> bytes:
    return _model_bytes(value, AssignmentManifestChainState)


def _reject_nonstandard_constant(value: str) -> NoReturn:
    raise ValueError(f"nonstandard_json_constant:{value}")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate_json_key")
        value[key] = item
    return value


def _parse_model[ModelT: BaseModel](
    rendered: bytes,
    model_type: type[ModelT],
    canonicalizer: Callable[[ModelT], bytes],
    *,
    maximum_bytes: int = MAX_DOCUMENT_BYTES,
) -> ModelT:
    if not rendered or len(rendered) > maximum_bytes:
        raise ValueError("document_size_invalid")
    try:
        document = json.loads(
            rendered.decode("ascii"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_nonstandard_constant,
        )
        model = model_type.model_validate(document)
    except (UnicodeDecodeError, ValueError, TypeError, RecursionError) as exc:
        raise ValueError("document_invalid") from exc
    if rendered != canonicalizer(model):
        raise ValueError("document_not_canonical")
    return model


def parse_assignment_manifest_trust_policy(rendered: bytes) -> AssignmentManifestTrustPolicy:
    return _parse_model(
        rendered,
        AssignmentManifestTrustPolicy,
        assignment_manifest_trust_policy_bytes,
        maximum_bytes=256 * 1_024,
    )


def parse_assignment_manifest_signature_envelope(
    rendered: bytes,
) -> AssignmentManifestSignatureEnvelope:
    return _parse_model(
        rendered,
        AssignmentManifestSignatureEnvelope,
        assignment_manifest_signature_envelope_bytes,
        maximum_bytes=16 * 1_024,
    )


def parse_assignment_manifest_chain_state(rendered: bytes) -> AssignmentManifestChainState:
    return _parse_model(
        rendered,
        AssignmentManifestChainState,
        assignment_manifest_chain_state_bytes,
        maximum_bytes=64 * 1_024,
    )
