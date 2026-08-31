# SPDX-License-Identifier: AGPL-3.0-only
"""Pure signed active-assignment manifest verification and live-probe evaluation contracts.

The central ``miss.computer`` scheduler is the only source of assignment,
route, challenge, and scoring truth.  This module accepts an already-published
canonical active-assignment manifest with externally produced Ed25519
signatures, verifies it without side effects, advances a caller-supplied
append-only manifest chain state, evaluates already-observed probe responses
against the manifest's expectations, and seals one canonical probe report.  It
deliberately has no file, environment, clock, randomness, network, process,
chain-client, credential, signing, submission, scheduling, or activation
capability: the separate CLI boundary performs the bounded HTTPS probe and
hands the observed bytes to this module.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Annotated, Final, Literal, NoReturn, Self, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from .ed25519_trust import (
    Ed25519PublicKeyValidationError,
    decode_ed25519_public_key_base64,
    decode_ed25519_public_key_hex,
)

MANIFEST_SCHEMA: Final = "miss.computer/misscomputer-subnet/active-assignment-manifest"
MANIFEST_TRUST_POLICY_SCHEMA: Final = (
    "miss.computer/misscomputer-subnet/assignment-manifest-trust-policy"
)
MANIFEST_SIGNATURE_ENVELOPE_SCHEMA: Final = (
    "miss.computer/misscomputer-subnet/assignment-manifest-signature-envelope"
)
MANIFEST_CHAIN_STATE_SCHEMA: Final = (
    "miss.computer/misscomputer-subnet/assignment-manifest-chain-state"
)
PROBE_ATTESTATION_SCHEMA: Final = "miss.computer/misscomputer-subnet/miner-probe-attestation"
PROBE_REPORT_SCHEMA: Final = "miss.computer/misscomputer-subnet/validator-probe-report"
PROBE_SCHEMA_VERSION: Final = 1
MANIFEST_PURPOSE: Final = "active_assignment_manifest_publication_v1"
PROBE_PURPOSE: Final = "public_validator_assignment_probe_v1"
ATTESTATION_PURPOSE: Final = "miner_probe_response_attestation_v1"
MANIFEST_SIGNATURE_DOMAIN_SEPARATOR: Final = (
    b"miss.computer/misscomputer-subnet/active-assignment-manifest/v1/ed25519"
)
ATTESTATION_SIGNATURE_DOMAIN_SEPARATOR: Final = (
    b"miss.computer/misscomputer-subnet/miner-probe-attestation/v1/ed25519"
)
MANIFEST_TRUST_POLICY_ID: Final = "miss-computer-active-assignment-manifest-trust-v1"
PROBE_NONCE_HEADER: Final = "x-miss-probe-nonce"
PROBE_ATTESTATION_HEADER: Final = "x-miss-probe-attestation"
BUILD_ID_HEADER: Final = "x-build-id"
MAINNET_NETWORK: Final = "finney"
MAINNET_NETUID: Final = 24
MAX_DEPLOYMENTS: Final = 4_096
MAX_REPLICAS: Final = 8
MAX_KEYS: Final = 16
MAX_ROUTE_SUFFIXES: Final = 16
MAX_PINNED_CERTIFICATES: Final = 16
MAX_DOCUMENT_BYTES: Final = 64 * 1_024 * 1_024
MAX_ATTESTATION_BYTES: Final = 8 * 1_024
MAX_RESPONSE_BYTES_CEILING: Final = 1_024 * 1_024
MAX_LATENCY_MILLIS: Final = 3_600_000
MAX_EPOCH: Final = (1 << 63) - 1

Digest = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
Hex24 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{24}$")]
Hex32 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{32}$")]
Hex64 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
HexSignature = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{128}$")]
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
ChallengePath = Annotated[str, StringConstraints(pattern=r"^/__challenge/[0-9a-f]{24}$")]
ImageDigest = Annotated[str, StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$")]
ReplicaID = Annotated[str, StringConstraints(min_length=3, max_length=256)]
EndpointID = Annotated[str, StringConstraints(min_length=3, max_length=320)]
UID = Annotated[int, Field(ge=0, le=(1 << 16) - 1)]
Epoch = Annotated[int, Field(ge=0, le=MAX_EPOCH)]
PositiveEpoch = Annotated[int, Field(ge=1, le=MAX_EPOCH)]
Port = Annotated[int, Field(ge=1, le=65_535)]
ManifestRole = Literal["assignment_auditor", "assignment_issuer", "assignment_security"]
AttestationRequirement = Literal["none", "miner_service_key_v1"]
AttestationStatus = Literal["not_presented", "not_required", "rejected", "verified"]
ProbeOutcome = Literal["failed", "serving"]
ReportStatus = Literal["degraded", "serving"]
TransportFailureCode = Literal[
    "connection_failed",
    "response_oversized",
    "timeout",
    "tls_certificate_invalid",
    "tls_handshake_failed",
    "transport_error",
]
ProbeFailureCode = Literal[
    "attestation_invalid",
    "attestation_missing",
    "body_digest_mismatch",
    "build_id_header_mismatch",
    "connection_failed",
    "redirect_rejected",
    "response_oversized",
    "timeout",
    "tls_certificate_invalid",
    "tls_handshake_failed",
    "tls_pin_mismatch",
    "transport_error",
    "unexpected_status",
]

ProbeRejectionCode = Literal[
    "authority_mismatch",
    "finalized_height_gap",
    "finalized_height_rollback",
    "issued_at_rollback",
    "manifest_expired",
    "manifest_future",
    "manifest_lifetime_invalid",
    "manifest_stale",
    "network_mismatch",
    "observation_coverage_mismatch",
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
    """Stable, sanitized fail-closed manifest or report rejection."""

    def __init__(self, code: ProbeRejectionCode) -> None:
        super().__init__(code)
        self.code = code


def _reject(code: ProbeRejectionCode) -> NoReturn:
    raise AssignmentProbeError(code)


class _StrictFrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


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


def _decode_hex_signature(value: str) -> bytes:
    try:
        decoded = bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError("signature_hex_invalid") from exc
    if len(decoded) != 64 or decoded.hex() != value:
        raise ValueError("signature_hex_invalid")
    return decoded


class AssignedReplica(_StrictFrozenModel):
    """Public-safe projection of one accepted, route-active deployment.v3 assignment."""

    miner_uid: UID
    miner_hotkey: Hotkey
    miner_service_public_key: Hex64
    generation: PositiveEpoch
    assignment_nonce: Hex32
    replica_id: ReplicaID
    endpoint_id: EndpointID
    ticket_digest_sha256: Digest
    receipt_digest_sha256: Digest
    chain_block: Epoch
    expires_at_block: PositiveEpoch
    ticket_issued_at_epoch: Epoch
    ticket_expires_at_epoch: PositiveEpoch
    route_state: Literal["active"]

    @model_validator(mode="after")
    def canonical_replica(self) -> Self:
        decode_ed25519_public_key_hex(self.miner_service_public_key)
        if self.expires_at_block <= self.chain_block:
            raise ValueError("replica_block_window_invalid")
        if self.ticket_expires_at_epoch <= self.ticket_issued_at_epoch:
            raise ValueError("replica_ticket_window_invalid")
        return self


class ActiveDeploymentAssignment(_StrictFrozenModel):
    """One public route with its centrally expected challenge response and replicas."""

    deployment_id: DeploymentID
    campaign_sequence: PositiveEpoch
    route_host: RouteHost
    challenge_path: ChallengePath
    build_id: Hex24
    challenge_sha256: Digest
    expected_status: Literal[200]
    image_digest: ImageDigest
    workload_spec_digest_sha256: Digest
    attestation_requirement: AttestationRequirement
    replicas: list[AssignedReplica] = Field(min_length=1, max_length=MAX_REPLICAS)
    assignment_digest_sha256: Digest

    @model_validator(mode="after")
    def canonical_assignment(self) -> Self:
        if self.challenge_path != f"/__challenge/{self.build_id}":
            raise ValueError("assignment_challenge_path_invalid")
        keys = [(item.miner_uid, item.miner_hotkey) for item in self.replicas]
        if keys != sorted(set(keys)):
            raise ValueError("assignment_replicas_not_canonical")
        if len({item.miner_uid for item in self.replicas}) != len(self.replicas):
            raise ValueError("assignment_replica_uid_duplicate")
        if len({item.miner_hotkey for item in self.replicas}) != len(self.replicas):
            raise ValueError("assignment_replica_hotkey_duplicate")
        if len({item.assignment_nonce for item in self.replicas}) != len(self.replicas):
            raise ValueError("assignment_replica_nonce_duplicate")
        for item in self.replicas:
            expected_replica = f"{self.deployment_id}-{item.miner_hotkey}"
            expected_endpoint = f"{expected_replica}-g{item.generation}-{item.assignment_nonce}"
            if item.replica_id != expected_replica or item.endpoint_id != expected_endpoint:
                raise ValueError("assignment_replica_identity_invalid")
        _verify_model_digest(self, "assignment_digest_sha256")
        return self


class ActiveAssignmentManifest(_StrictFrozenModel):
    contract_schema: Literal["miss.computer/misscomputer-subnet/active-assignment-manifest"] = (
        Field(alias="schema")
    )
    schema_version: Literal[1]
    purpose: Literal["active_assignment_manifest_publication_v1"]
    network: Literal["finney"]
    netuid: Literal[24]
    central_authority_fingerprint_sha256: Digest
    trust_policy_digest_sha256: Digest
    finalized_height: Epoch
    finalized_block_hash: Digest
    finalized_epoch: Epoch
    sequence: PositiveEpoch
    previous_manifest_digest_sha256: Digest | None
    issued_at_epoch: Epoch
    expires_at_epoch: PositiveEpoch
    route_host_suffix: RouteHost
    probe_scheme: Literal["https"]
    probe_port: Port
    deployments: list[ActiveDeploymentAssignment] = Field(min_length=1, max_length=MAX_DEPLOYMENTS)
    assignment_vector_digest_sha256: Digest
    manifest_digest_sha256: Digest

    @model_validator(mode="after")
    def canonical_manifest(self) -> Self:
        if self.expires_at_epoch <= self.issued_at_epoch:
            raise ValueError("manifest_validity_window_invalid")
        if (self.sequence == 1) != (self.previous_manifest_digest_sha256 is None):
            raise ValueError("manifest_previous_link_invalid")
        deployment_ids = [item.deployment_id for item in self.deployments]
        if deployment_ids != sorted(set(deployment_ids)):
            raise ValueError("manifest_deployments_not_canonical")
        route_hosts = [item.route_host for item in self.deployments]
        if len(set(route_hosts)) != len(route_hosts):
            raise ValueError("manifest_route_host_duplicate")
        for item in self.deployments:
            if item.route_host != f"{item.deployment_id}.{self.route_host_suffix}":
                raise ValueError("manifest_route_host_invalid")
            for replica in item.replicas:
                if replica.expires_at_block <= self.finalized_height:
                    raise ValueError("manifest_replica_block_expired")
                if replica.ticket_expires_at_epoch <= self.issued_at_epoch:
                    raise ValueError("manifest_replica_ticket_expired")
        nonces = [
            replica.assignment_nonce for item in self.deployments for replica in item.replicas
        ]
        if len(set(nonces)) != len(nonces):
            raise ValueError("manifest_assignment_nonce_duplicate")
        endpoints = [replica.endpoint_id for item in self.deployments for replica in item.replicas]
        if len(set(endpoints)) != len(endpoints):
            raise ValueError("manifest_endpoint_duplicate")
        uid_to_hotkey: dict[int, str] = {}
        hotkey_to_uid: dict[str, int] = {}
        for item in self.deployments:
            for replica in item.replicas:
                if uid_to_hotkey.setdefault(replica.miner_uid, replica.miner_hotkey) != (
                    replica.miner_hotkey
                ) or hotkey_to_uid.setdefault(replica.miner_hotkey, replica.miner_uid) != (
                    replica.miner_uid
                ):
                    raise ValueError("manifest_miner_identity_conflict")
        vector = [_model_document(item) for item in self.deployments]
        if self.assignment_vector_digest_sha256 != _digest(vector):
            raise ValueError("assignment_vector_digest_sha256_mismatch")
        _verify_model_digest(self, "manifest_digest_sha256")
        return self


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
    network: Literal["finney"]
    netuid: Literal[24]
    central_authority_fingerprint_sha256: Digest
    threshold: int = Field(ge=1, le=MAX_KEYS)
    required_roles: list[ManifestRole] = Field(min_length=1, max_length=3)
    trusted_keys: list[TrustedManifestKey] = Field(min_length=1, max_length=MAX_KEYS)
    valid_from_epoch: Epoch
    valid_until_epoch: Epoch
    max_manifest_age_seconds: int = Field(ge=1, le=86_400)
    max_future_skew_seconds: int = Field(ge=0, le=300)
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
    network: Literal["finney"]
    netuid: Literal[24]
    central_authority_fingerprint_sha256: Digest
    trust_policy_digest_sha256: Digest
    accepted_manifest_count: Epoch
    last_sequence: Epoch
    last_finalized_height: Epoch | None
    last_finalized_block_hash: Digest | None
    last_issued_at_epoch: Epoch | None
    last_expires_at_epoch: Epoch | None
    last_manifest_digest_sha256: Digest | None
    state_digest_sha256: Digest

    @model_validator(mode="after")
    def canonical_state(self) -> Self:
        tail = (
            self.last_finalized_height,
            self.last_finalized_block_hash,
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


class MinerProbeAttestation(_StrictFrozenModel):
    """Miner service-key statement binding one probe nonce to one served payload."""

    contract_schema: Literal["miss.computer/misscomputer-subnet/miner-probe-attestation"] = Field(
        alias="schema"
    )
    schema_version: Literal[1]
    purpose: Literal["miner_probe_response_attestation_v1"]
    algorithm: Literal["ed25519"]
    probe_nonce: Hex64
    route_host: RouteHost
    deployment_id: DeploymentID
    generation: PositiveEpoch
    assignment_nonce: Hex32
    endpoint_id: EndpointID
    miner_uid: UID
    miner_hotkey: Hotkey
    miner_service_public_key: Hex64
    response_status: Literal[200]
    response_body_sha256: Digest
    signature_hex: HexSignature

    @model_validator(mode="after")
    def canonical_attestation(self) -> Self:
        expected_replica = f"{self.deployment_id}-{self.miner_hotkey}"
        expected_endpoint = f"{expected_replica}-g{self.generation}-{self.assignment_nonce}"
        if self.endpoint_id != expected_endpoint:
            raise ValueError("attestation_endpoint_invalid")
        _decode_hex_signature(self.signature_hex)
        return self


class ProbeObservation(_StrictFrozenModel):
    deployment_id: DeploymentID
    route_host: RouteHost
    challenge_path: ChallengePath
    assignment_digest_sha256: Digest
    probe_nonce: Hex64
    latency_millis: int = Field(ge=0, le=MAX_LATENCY_MILLIS)
    outcome: ProbeOutcome
    failure_code: ProbeFailureCode | None
    response_status: int | None = Field(ge=100, le=599)
    response_bytes: int = Field(ge=0, le=MAX_RESPONSE_BYTES_CEILING + 1)
    response_body_sha256: Digest | None
    build_id_header_verified: bool
    tls_leaf_certificate_sha256: Digest | None
    attestation_status: AttestationStatus
    attestation: MinerProbeAttestation | None
    observation_digest_sha256: Digest

    @model_validator(mode="after")
    def canonical_observation(self) -> Self:
        if (self.outcome == "serving") != (self.failure_code is None):
            raise ValueError("observation_outcome_invalid")
        if self.outcome == "serving" and (
            self.response_status != 200
            or self.response_body_sha256 is None
            or not self.build_id_header_verified
        ):
            raise ValueError("observation_serving_invalid")
        if (self.attestation_status == "verified") != (self.attestation is not None):
            raise ValueError("observation_attestation_invalid")
        if self.attestation is not None and (
            self.attestation.probe_nonce != self.probe_nonce
            or self.attestation.deployment_id != self.deployment_id
            or self.attestation.route_host != self.route_host
            or self.attestation.response_body_sha256 != self.response_body_sha256
        ):
            raise ValueError("observation_attestation_binding_invalid")
        _verify_model_digest(self, "observation_digest_sha256")
        return self


class ValidatorProbeReport(_StrictFrozenModel):
    contract_schema: Literal["miss.computer/misscomputer-subnet/validator-probe-report"] = Field(
        alias="schema"
    )
    schema_version: Literal[1]
    purpose: Literal["public_validator_assignment_probe_v1"]
    status: ReportStatus
    network: Literal["finney"]
    netuid: Literal[24]
    validator_uid: UID
    validator_hotkey: Hotkey
    evaluation_epoch: Epoch
    central_authority_fingerprint_sha256: Digest
    trust_policy_digest_sha256: Digest
    manifest_digest_sha256: Digest
    manifest_sequence: PositiveEpoch
    manifest_issued_at_epoch: Epoch
    manifest_expires_at_epoch: PositiveEpoch
    finalized_height: Epoch
    finalized_block_hash: Digest
    finalized_epoch: Epoch
    verified_signer_key_ids: list[KeyID] = Field(min_length=1, max_length=MAX_KEYS)
    verified_roles: list[ManifestRole] = Field(min_length=1, max_length=3)
    prior_chain_state_digest_sha256: Digest
    next_chain_state_digest_sha256: Digest
    manifest_reprobe: bool
    edge_origin_override: bool
    probe_scheme: Literal["https"]
    probe_port: Port
    probe_timeout_millis: int = Field(ge=100, le=60_000)
    max_response_bytes: int = Field(ge=64, le=MAX_RESPONSE_BYTES_CEILING)
    deployment_count: int = Field(ge=1, le=MAX_DEPLOYMENTS)
    serving_count: int = Field(ge=0, le=MAX_DEPLOYMENTS)
    failed_count: int = Field(ge=0, le=MAX_DEPLOYMENTS)
    observations: list[ProbeObservation] = Field(min_length=1, max_length=MAX_DEPLOYMENTS)
    observation_vector_digest_sha256: Digest
    report_digest_sha256: Digest

    @model_validator(mode="after")
    def canonical_report(self) -> Self:
        if self.verified_signer_key_ids != sorted(set(self.verified_signer_key_ids)):
            raise ValueError("verified_signers_not_canonical")
        if self.verified_roles != sorted(set(self.verified_roles)):
            raise ValueError("verified_roles_not_canonical")
        deployment_ids = [item.deployment_id for item in self.observations]
        if deployment_ids != sorted(set(deployment_ids)):
            raise ValueError("report_observations_not_canonical")
        serving = sum(item.outcome == "serving" for item in self.observations)
        if (
            self.deployment_count != len(self.observations)
            or self.serving_count != serving
            or self.failed_count != len(self.observations) - serving
        ):
            raise ValueError("report_counts_invalid")
        if (self.status == "serving") != (self.failed_count == 0):
            raise ValueError("report_status_invalid")
        vector = [_model_document(item) for item in self.observations]
        if self.observation_vector_digest_sha256 != _digest(vector):
            raise ValueError("observation_vector_digest_mismatch")
        _verify_model_digest(self, "report_digest_sha256")
        return self


@dataclass(frozen=True)
class ManifestVerificationResult:
    manifest: ActiveAssignmentManifest
    verified_signer_key_ids: list[str]
    verified_roles: list[ManifestRole]
    next_chain_state: AssignmentManifestChainState
    reprobe: bool


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
        "network": MAINNET_NETWORK,
        "netuid": MAINNET_NETUID,
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


def build_assigned_replica(
    *,
    miner_uid: int,
    miner_hotkey: str,
    miner_service_public_key: str,
    generation: int,
    assignment_nonce: str,
    deployment_id: str,
    ticket_digest_sha256: str,
    receipt_digest_sha256: str,
    chain_block: int,
    expires_at_block: int,
    ticket_issued_at_epoch: int,
    ticket_expires_at_epoch: int,
) -> AssignedReplica:
    replica_id = f"{deployment_id}-{miner_hotkey}"
    return AssignedReplica.model_validate(
        {
            "miner_uid": miner_uid,
            "miner_hotkey": miner_hotkey,
            "miner_service_public_key": miner_service_public_key,
            "generation": generation,
            "assignment_nonce": assignment_nonce,
            "replica_id": replica_id,
            "endpoint_id": f"{replica_id}-g{generation}-{assignment_nonce}",
            "ticket_digest_sha256": ticket_digest_sha256,
            "receipt_digest_sha256": receipt_digest_sha256,
            "chain_block": chain_block,
            "expires_at_block": expires_at_block,
            "ticket_issued_at_epoch": ticket_issued_at_epoch,
            "ticket_expires_at_epoch": ticket_expires_at_epoch,
            "route_state": "active",
        }
    )


def build_active_deployment_assignment(
    *,
    deployment_id: str,
    campaign_sequence: int,
    route_host: str,
    build_id: str,
    challenge_sha256: str,
    image_digest: str,
    workload_spec_digest_sha256: str,
    attestation_requirement: AttestationRequirement,
    replicas: Sequence[AssignedReplica],
) -> ActiveDeploymentAssignment:
    ordered = sorted(
        (_revalidate(item, AssignedReplica) for item in replicas),
        key=lambda item: (item.miner_uid, item.miner_hotkey),
    )
    unsigned: dict[str, object] = {
        "deployment_id": deployment_id,
        "campaign_sequence": campaign_sequence,
        "route_host": route_host,
        "challenge_path": f"/__challenge/{build_id}",
        "build_id": build_id,
        "challenge_sha256": challenge_sha256,
        "expected_status": 200,
        "image_digest": image_digest,
        "workload_spec_digest_sha256": workload_spec_digest_sha256,
        "attestation_requirement": attestation_requirement,
        "replicas": [_model_document(item) for item in ordered],
    }
    return ActiveDeploymentAssignment.model_validate(
        {**unsigned, "assignment_digest_sha256": _digest(unsigned)}
    )


def build_active_assignment_manifest(
    trust_policy: AssignmentManifestTrustPolicy,
    *,
    finalized_height: int,
    finalized_block_hash: str,
    finalized_epoch: int,
    sequence: int,
    previous_manifest_digest_sha256: str | None,
    issued_at_epoch: int,
    expires_at_epoch: int,
    route_host_suffix: str,
    probe_port: int,
    deployments: Sequence[ActiveDeploymentAssignment],
) -> ActiveAssignmentManifest:
    """Seal one unsigned manifest bound to the validator-pinned trust policy."""

    policy = _revalidate(trust_policy, AssignmentManifestTrustPolicy)
    ordered = sorted(
        (_revalidate(item, ActiveDeploymentAssignment) for item in deployments),
        key=lambda item: item.deployment_id,
    )
    vector = [_model_document(item) for item in ordered]
    unsigned: dict[str, object] = {
        "schema": MANIFEST_SCHEMA,
        "schema_version": PROBE_SCHEMA_VERSION,
        "purpose": MANIFEST_PURPOSE,
        "network": policy.network,
        "netuid": policy.netuid,
        "central_authority_fingerprint_sha256": policy.central_authority_fingerprint_sha256,
        "trust_policy_digest_sha256": policy.trust_policy_digest_sha256,
        "finalized_height": finalized_height,
        "finalized_block_hash": finalized_block_hash,
        "finalized_epoch": finalized_epoch,
        "sequence": sequence,
        "previous_manifest_digest_sha256": previous_manifest_digest_sha256,
        "issued_at_epoch": issued_at_epoch,
        "expires_at_epoch": expires_at_epoch,
        "route_host_suffix": route_host_suffix,
        "probe_scheme": policy.probe_scheme,
        "probe_port": probe_port,
        "deployments": vector,
        "assignment_vector_digest_sha256": _digest(vector),
    }
    return ActiveAssignmentManifest.model_validate(
        {**unsigned, "manifest_digest_sha256": _digest(unsigned)}
    )


def manifest_signature_message(manifest: ActiveAssignmentManifest) -> bytes:
    """Return the only domain-separated bytes accepted by public-key verification."""

    manifest = _revalidate(manifest, ActiveAssignmentManifest)
    return (
        MANIFEST_SIGNATURE_DOMAIN_SEPARATOR + b"\x00" + _canonical_json(_model_document(manifest))
    )


def build_manifest_signature_envelope(
    manifest: ActiveAssignmentManifest,
    *,
    signer_key_id: str,
    signature_base64: str,
) -> AssignmentManifestSignatureEnvelope:
    """Wrap externally produced signature bytes; this function never creates them."""

    manifest = _revalidate(manifest, ActiveAssignmentManifest)
    message_digest = hashlib.sha256(manifest_signature_message(manifest)).hexdigest()
    return AssignmentManifestSignatureEnvelope(
        schema=MANIFEST_SIGNATURE_ENVELOPE_SCHEMA,
        schema_version=PROBE_SCHEMA_VERSION,
        purpose=MANIFEST_PURPOSE,
        algorithm="ed25519",
        signer_key_id=signer_key_id,
        manifest_digest_sha256=manifest.manifest_digest_sha256,
        signed_message_digest_sha256=message_digest,
        signature_base64=signature_base64,
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
        "last_issued_at_epoch": None,
        "last_expires_at_epoch": None,
        "last_manifest_digest_sha256": None,
    }
    return AssignmentManifestChainState.model_validate(
        {**unsigned, "state_digest_sha256": _digest(unsigned)}
    )


def miner_probe_attestation_message(attestation: MinerProbeAttestation) -> bytes:
    """Return the domain-separated bytes a miner service key must sign."""

    attestation = _revalidate(attestation, MinerProbeAttestation)
    document = _model_document(attestation, exclude={"signature_hex"})
    return ATTESTATION_SIGNATURE_DOMAIN_SEPARATOR + b"\x00" + _canonical_json(document)


def build_miner_probe_attestation(
    *,
    probe_nonce: str,
    route_host: str,
    deployment_id: str,
    generation: int,
    assignment_nonce: str,
    miner_uid: int,
    miner_hotkey: str,
    miner_service_public_key: str,
    response_body_sha256: str,
    signature_hex: str,
) -> MinerProbeAttestation:
    """Wrap an externally produced miner signature; this function never creates one."""

    replica_id = f"{deployment_id}-{miner_hotkey}"
    return MinerProbeAttestation.model_validate(
        {
            "schema": PROBE_ATTESTATION_SCHEMA,
            "schema_version": PROBE_SCHEMA_VERSION,
            "purpose": ATTESTATION_PURPOSE,
            "algorithm": "ed25519",
            "probe_nonce": probe_nonce,
            "route_host": route_host,
            "deployment_id": deployment_id,
            "generation": generation,
            "assignment_nonce": assignment_nonce,
            "endpoint_id": f"{replica_id}-g{generation}-{assignment_nonce}",
            "miner_uid": miner_uid,
            "miner_hotkey": miner_hotkey,
            "miner_service_public_key": miner_service_public_key,
            "response_status": 200,
            "response_body_sha256": response_body_sha256,
            "signature_hex": signature_hex,
        }
    )


def _verify_trust_and_freshness(
    manifest: ActiveAssignmentManifest,
    policy: AssignmentManifestTrustPolicy,
    *,
    evaluation_epoch: int,
) -> None:
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
    if evaluation_epoch >= manifest.expires_at_epoch:
        _reject("manifest_expired")
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


def _verify_signatures(
    manifest: ActiveAssignmentManifest,
    signatures: Sequence[AssignmentManifestSignatureEnvelope],
    policy: AssignmentManifestTrustPolicy,
    public_keys: dict[str, bytes],
    *,
    evaluation_epoch: int,
) -> tuple[list[str], list[ManifestRole]]:
    message = manifest_signature_message(manifest)
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


def advance_manifest_chain_state(
    state: AssignmentManifestChainState,
    manifest: ActiveAssignmentManifest,
    policy: AssignmentManifestTrustPolicy,
) -> tuple[AssignmentManifestChainState, bool]:
    """Apply append-only non-equivocation rules; a repeated exact manifest is a re-probe.

    Returns the sealed next state and whether the manifest was already the last
    accepted publication.  A re-probe of the identical manifest leaves the state
    unchanged; any other same-sequence publication is equivocation.
    """

    state = _revalidate(state, AssignmentManifestChainState)
    manifest = _revalidate(manifest, ActiveAssignmentManifest)
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
        if (
            manifest.finalized_height == last_height
            and manifest.finalized_block_hash != state.last_finalized_block_hash
        ):
            _reject("same_height_fork")
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


def verify_active_assignment_manifest(
    manifest: ActiveAssignmentManifest,
    signatures: Sequence[AssignmentManifestSignatureEnvelope],
    approved_trust_policy: AssignmentManifestTrustPolicy,
    prior_chain_state: AssignmentManifestChainState,
    *,
    evaluation_epoch: int,
) -> ManifestVerificationResult:
    """Verify one dependency-only manifest publication and derive the next state."""

    if (
        isinstance(evaluation_epoch, bool)
        or not isinstance(evaluation_epoch, int)
        or not 0 <= evaluation_epoch <= MAX_EPOCH
    ):
        raise ValueError("evaluation_epoch_invalid")
    policy = _revalidate(approved_trust_policy, AssignmentManifestTrustPolicy)
    trusted_public_keys = _trusted_public_keys(policy)
    value = _revalidate(manifest, ActiveAssignmentManifest)
    envelopes = [_revalidate(item, AssignmentManifestSignatureEnvelope) for item in signatures]
    if not 1 <= len(envelopes) <= MAX_KEYS:
        _reject("signature_binding_mismatch")
    _verify_trust_and_freshness(value, policy, evaluation_epoch=evaluation_epoch)
    signer_ids, roles = _verify_signatures(
        value,
        envelopes,
        policy,
        trusted_public_keys,
        evaluation_epoch=evaluation_epoch,
    )
    next_state, reprobe = advance_manifest_chain_state(prior_chain_state, value, policy)
    return ManifestVerificationResult(
        manifest=value,
        verified_signer_key_ids=signer_ids,
        verified_roles=roles,
        next_chain_state=next_state,
        reprobe=reprobe,
    )


def _header_values(headers: Sequence[tuple[str, str]], name: str) -> list[str]:
    return [value for key, value in headers if key.lower() == name]


def parse_miner_probe_attestation_header(value: str) -> MinerProbeAttestation:
    """Decode one base64 canonical attestation carried in a response header."""

    if not isinstance(value, str) or not value or len(value) > MAX_ATTESTATION_BYTES * 2:
        raise ValueError("attestation_header_invalid")
    try:
        rendered = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("attestation_header_invalid") from exc
    if (
        not rendered
        or len(rendered) > MAX_ATTESTATION_BYTES
        or base64.b64encode(rendered).decode("ascii") != value
    ):
        raise ValueError("attestation_header_invalid")
    try:
        document = json.loads(
            rendered.decode("ascii"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_nonstandard_constant,
        )
        attestation = MinerProbeAttestation.model_validate(document)
    except (UnicodeDecodeError, ValueError, TypeError, RecursionError) as exc:
        raise ValueError("attestation_header_invalid") from exc
    if rendered != _canonical_json(_model_document(attestation)):
        raise ValueError("attestation_header_invalid")
    return attestation


def verify_miner_probe_attestation(
    attestation: MinerProbeAttestation,
    deployment: ActiveDeploymentAssignment,
    *,
    probe_nonce: str,
    response_body_sha256: str,
) -> AssignedReplica:
    """Bind one attestation to the probe, the manifest replica, and the served bytes."""

    attestation = _revalidate(attestation, MinerProbeAttestation)
    deployment = _revalidate(deployment, ActiveDeploymentAssignment)
    if (
        attestation.probe_nonce != probe_nonce
        or attestation.route_host != deployment.route_host
        or attestation.deployment_id != deployment.deployment_id
        or attestation.response_body_sha256 != response_body_sha256
        or attestation.response_body_sha256 != deployment.challenge_sha256
    ):
        raise ValueError("attestation_binding_mismatch")
    matches = [
        item
        for item in deployment.replicas
        if item.miner_uid == attestation.miner_uid
        and item.miner_hotkey == attestation.miner_hotkey
        and item.miner_service_public_key == attestation.miner_service_public_key
        and item.generation == attestation.generation
        and item.assignment_nonce == attestation.assignment_nonce
        and item.endpoint_id == attestation.endpoint_id
    ]
    if len(matches) != 1:
        raise ValueError("attestation_replica_unknown")
    replica = matches[0]
    signature = _decode_hex_signature(attestation.signature_hex)
    try:
        public_key = decode_ed25519_public_key_hex(replica.miner_service_public_key)
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            signature, miner_probe_attestation_message(attestation)
        )
    except (InvalidSignature, ValueError) as exc:
        raise ValueError("attestation_signature_invalid") from exc
    return replica


def _seal_observation(document: dict[str, object]) -> ProbeObservation:
    return ProbeObservation.model_validate(
        {**document, "observation_digest_sha256": _digest(document)}
    )


def evaluate_probe_response(
    deployment: ActiveDeploymentAssignment,
    trust_policy: AssignmentManifestTrustPolicy,
    *,
    probe_nonce: str,
    result: ProbeResponse | ProbeTransportFailure,
) -> ProbeObservation:
    """Judge one observed response strictly against the manifest's expectation.

    ``serving`` requires status 200, the exact expected body digest, the exact
    ``X-Build-ID`` header, an allow-listed edge leaf certificate when pins are
    configured, and a verified miner attestation when the manifest requires
    one.  Everything else fails closed with one stable failure code.
    """

    deployment = _revalidate(deployment, ActiveDeploymentAssignment)
    policy = _revalidate(trust_policy, AssignmentManifestTrustPolicy)
    if not isinstance(probe_nonce, str) or len(probe_nonce) != 64:
        raise ValueError("probe_nonce_invalid")
    required = deployment.attestation_requirement != "none"
    document: dict[str, object] = {
        "deployment_id": deployment.deployment_id,
        "route_host": deployment.route_host,
        "challenge_path": deployment.challenge_path,
        "assignment_digest_sha256": deployment.assignment_digest_sha256,
        "probe_nonce": probe_nonce,
        "latency_millis": min(max(result.latency_millis, 0), MAX_LATENCY_MILLIS),
        "outcome": "failed",
        "failure_code": None,
        "response_status": None,
        "response_bytes": 0,
        "response_body_sha256": None,
        "build_id_header_verified": False,
        "tls_leaf_certificate_sha256": result.tls_leaf_certificate_sha256,
        "attestation_status": "not_presented" if required else "not_required",
        "attestation": None,
    }
    if isinstance(result, ProbeTransportFailure):
        document["failure_code"] = result.code
        document["response_status"] = result.response_status
        return _seal_observation(document)

    document["response_status"] = result.status
    document["response_bytes"] = len(result.body)
    body_digest = hashlib.sha256(result.body).hexdigest()
    document["response_body_sha256"] = body_digest
    pins = policy.pinned_edge_leaf_certificate_sha256
    if pins and result.tls_leaf_certificate_sha256 not in pins:
        document["failure_code"] = "tls_pin_mismatch"
        return _seal_observation(document)
    if 300 <= result.status <= 399:
        document["failure_code"] = "redirect_rejected"
        return _seal_observation(document)
    if result.status != deployment.expected_status:
        document["failure_code"] = "unexpected_status"
        return _seal_observation(document)
    if len(result.body) > policy.max_response_bytes:
        document["failure_code"] = "response_oversized"
        return _seal_observation(document)
    if body_digest != deployment.challenge_sha256:
        document["failure_code"] = "body_digest_mismatch"
        return _seal_observation(document)
    if _header_values(result.headers, BUILD_ID_HEADER) != [deployment.build_id]:
        document["failure_code"] = "build_id_header_mismatch"
        return _seal_observation(document)
    document["build_id_header_verified"] = True

    presented = _header_values(result.headers, PROBE_ATTESTATION_HEADER)
    if not presented:
        if required:
            document["failure_code"] = "attestation_missing"
        else:
            document["outcome"] = "serving"
        return _seal_observation(document)
    if len(presented) != 1:
        document["attestation_status"] = "rejected"
        document["failure_code"] = "attestation_invalid"
        return _seal_observation(document)
    try:
        attestation = parse_miner_probe_attestation_header(presented[0])
        verify_miner_probe_attestation(
            attestation,
            deployment,
            probe_nonce=probe_nonce,
            response_body_sha256=body_digest,
        )
    except ValueError:
        document["attestation_status"] = "rejected"
        document["failure_code"] = "attestation_invalid"
        return _seal_observation(document)
    document["attestation_status"] = "verified"
    document["attestation"] = _model_document(attestation)
    document["outcome"] = "serving"
    return _seal_observation(document)


def build_validator_probe_report(
    verification: ManifestVerificationResult,
    trust_policy: AssignmentManifestTrustPolicy,
    prior_chain_state: AssignmentManifestChainState,
    observations: Sequence[ProbeObservation],
    *,
    validator_uid: int,
    validator_hotkey: str,
    evaluation_epoch: int,
    edge_origin_override: bool,
) -> ValidatorProbeReport:
    """Seal one archivable report covering exactly the manifest's deployments."""

    policy = _revalidate(trust_policy, AssignmentManifestTrustPolicy)
    manifest = verification.manifest
    prior = _revalidate(prior_chain_state, AssignmentManifestChainState)
    ordered = sorted(
        (_revalidate(item, ProbeObservation) for item in observations),
        key=lambda item: item.deployment_id,
    )
    expected = {item.deployment_id: item for item in manifest.deployments}
    observed = {item.deployment_id: item for item in ordered}
    if len(observed) != len(ordered) or set(observed) != set(expected):
        _reject("observation_coverage_mismatch")
    for deployment_id, observation in observed.items():
        deployment = expected[deployment_id]
        if (
            observation.assignment_digest_sha256 != deployment.assignment_digest_sha256
            or observation.route_host != deployment.route_host
            or observation.challenge_path != deployment.challenge_path
        ):
            _reject("observation_coverage_mismatch")
    vector = [_model_document(item) for item in ordered]
    serving = sum(item.outcome == "serving" for item in ordered)
    unsigned: dict[str, object] = {
        "schema": PROBE_REPORT_SCHEMA,
        "schema_version": PROBE_SCHEMA_VERSION,
        "purpose": PROBE_PURPOSE,
        "status": "serving" if serving == len(ordered) else "degraded",
        "network": manifest.network,
        "netuid": manifest.netuid,
        "validator_uid": validator_uid,
        "validator_hotkey": validator_hotkey,
        "evaluation_epoch": evaluation_epoch,
        "central_authority_fingerprint_sha256": manifest.central_authority_fingerprint_sha256,
        "trust_policy_digest_sha256": policy.trust_policy_digest_sha256,
        "manifest_digest_sha256": manifest.manifest_digest_sha256,
        "manifest_sequence": manifest.sequence,
        "manifest_issued_at_epoch": manifest.issued_at_epoch,
        "manifest_expires_at_epoch": manifest.expires_at_epoch,
        "finalized_height": manifest.finalized_height,
        "finalized_block_hash": manifest.finalized_block_hash,
        "finalized_epoch": manifest.finalized_epoch,
        "verified_signer_key_ids": list(verification.verified_signer_key_ids),
        "verified_roles": list(verification.verified_roles),
        "prior_chain_state_digest_sha256": prior.state_digest_sha256,
        "next_chain_state_digest_sha256": verification.next_chain_state.state_digest_sha256,
        "manifest_reprobe": verification.reprobe,
        "edge_origin_override": edge_origin_override,
        "probe_scheme": manifest.probe_scheme,
        "probe_port": manifest.probe_port,
        "probe_timeout_millis": policy.probe_timeout_millis,
        "max_response_bytes": policy.max_response_bytes,
        "deployment_count": len(ordered),
        "serving_count": serving,
        "failed_count": len(ordered) - serving,
        "observations": vector,
        "observation_vector_digest_sha256": _digest(vector),
    }
    return ValidatorProbeReport.model_validate(
        {**unsigned, "report_digest_sha256": _digest(unsigned)}
    )


def _model_bytes[ModelT: BaseModel](value: ModelT, model_type: type[ModelT]) -> bytes:
    value = _revalidate(value, model_type)
    return _canonical_json(_model_document(value)) + b"\n"


def active_assignment_manifest_bytes(value: ActiveAssignmentManifest) -> bytes:
    return _model_bytes(value, ActiveAssignmentManifest)


def assignment_manifest_trust_policy_bytes(value: AssignmentManifestTrustPolicy) -> bytes:
    return _model_bytes(value, AssignmentManifestTrustPolicy)


def assignment_manifest_signature_envelope_bytes(
    value: AssignmentManifestSignatureEnvelope,
) -> bytes:
    return _model_bytes(value, AssignmentManifestSignatureEnvelope)


def assignment_manifest_chain_state_bytes(value: AssignmentManifestChainState) -> bytes:
    return _model_bytes(value, AssignmentManifestChainState)


def miner_probe_attestation_bytes(value: MinerProbeAttestation) -> bytes:
    return _model_bytes(value, MinerProbeAttestation)


def validator_probe_report_bytes(value: ValidatorProbeReport) -> bytes:
    return _model_bytes(value, ValidatorProbeReport)


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


def parse_active_assignment_manifest(rendered: bytes) -> ActiveAssignmentManifest:
    return _parse_model(rendered, ActiveAssignmentManifest, active_assignment_manifest_bytes)


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


def parse_miner_probe_attestation(rendered: bytes) -> MinerProbeAttestation:
    return _parse_model(
        rendered,
        MinerProbeAttestation,
        miner_probe_attestation_bytes,
        maximum_bytes=MAX_ATTESTATION_BYTES,
    )


def parse_validator_probe_report(rendered: bytes) -> ValidatorProbeReport:
    return _parse_model(rendered, ValidatorProbeReport, validator_probe_report_bytes)
