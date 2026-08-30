# SPDX-License-Identifier: AGPL-3.0-only
"""Strict offline contracts for production release and launch authorization.

This module only validates already-supplied metadata and produces canonical
bytes.  It does not read files, recompute builds, verify signatures, invoke a
subprocess, contact a network, publish artifacts, or perform launch actions.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from collections.abc import Mapping, Sequence
from typing import Annotated, Literal, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from .ed25519_trust import decode_ed25519_public_key_base64

PRODUCTION_RELEASE_MANIFEST_SCHEMA = "miss.computer/misscomputer-subnet/production-release-manifest"
LAUNCH_AUTHORIZATION_BUNDLE_SCHEMA = "miss.computer/misscomputer-subnet/launch-authorization-bundle"
OFFLINE_SIGNATURE_ENVELOPE_SCHEMA = "miss.computer/misscomputer-subnet/offline-signature-envelope"
RELEASE_TRUST_POLICY_SCHEMA = "miss.computer/misscomputer-subnet/release-trust-policy"
PRODUCTION_RELEASE_SCHEMA_VERSION = 1

EXPECTED_TOOLCHAIN_COMPONENTS = frozenset({"container_builder", "go", "python"})
EXPECTED_GO_BINARIES = frozenset({"control-api", "miner-agent", "workload"})
EXPECTED_CONTAINER_IMAGES = frozenset({"neuron", "workload"})
REQUIRED_RELEASE_FILE_CATEGORIES = frozenset({"config", "contract_schema", "systemd_unit"})
REQUIRED_SIGNER_ROLES = frozenset({"operations_owner", "release_manager", "security_reviewer"})

Digest = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
OCIDigest = Annotated[str, StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$")]
GitObjectID = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{40}$")]
RecordID = Annotated[
    str,
    StringConstraints(pattern=r"^[a-z][a-z0-9_]{0,62}[a-z0-9]$|^[a-z]$"),
]
ReleaseID = Annotated[
    str,
    StringConstraints(pattern=r"^[a-z0-9][a-z0-9.-]{0,126}[a-z0-9]$"),
]
VersionText = Annotated[
    str,
    StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9._+:-]{0,126}[A-Za-z0-9]$"),
]
Platform = Annotated[
    str,
    StringConstraints(pattern=r"^[a-z0-9][a-z0-9_/-]{0,62}[a-z0-9]$"),
]
RelativeArtifactPath = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=512,
        pattern=r"^[A-Za-z0-9](?:[A-Za-z0-9._+/-]{0,510}[A-Za-z0-9])?$",
    ),
]
CanonicalPublicKeyBase64 = Annotated[
    str,
    StringConstraints(min_length=44, max_length=44, pattern=r"^[A-Za-z0-9+/]{43}=$"),
]
CanonicalSignatureBase64 = Annotated[
    str,
    StringConstraints(min_length=88, max_length=88, pattern=r"^[A-Za-z0-9+/]{86}==$"),
]
UnixTime = Annotated[int, Field(ge=0, le=(1 << 63) - 1)]
SignerRole = Literal["operations_owner", "release_manager", "security_reviewer"]

_SENSITIVE_PATH_COMPONENTS = frozenset(
    {
        ".env",
        "credential",
        "credentials",
        "private-key",
        "private_key",
        "secret",
        "secrets",
        "wallet",
        "wallets",
    }
)


class ProductionReleaseContractError(ValueError):
    """A stable rejection raised while constructing canonical contract bytes."""


class _StrictReleaseModel(BaseModel):
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
    except (TypeError, ValueError) as exc:
        raise ProductionReleaseContractError("document is not canonical JSON") from exc
    return rendered.encode("ascii")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _document_digest(document: object) -> str:
    return _sha256(_canonical_json(document))


def _validate_relative_path(value: str) -> str:
    if (
        not value
        or len(value) > 512
        or not value.isascii()
        or value.startswith(("/", "\\"))
        or value.endswith(("/", "\\"))
        or "//" in value
        or "\\" in value
        or any(component in {"", ".", ".."} for component in value.split("/"))
        or any(component.casefold() in _SENSITIVE_PATH_COMPONENTS for component in value.split("/"))
        or any(
            not (character.isalnum() or character in {"/", ".", "_", "-", "+"})
            for character in value
        )
    ):
        raise ValueError("artifact path is unsafe or may disclose secret material")
    return value


def _decode_canonical_base64(value: str, *, byte_length: int, field_name: str) -> bytes:
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError(f"{field_name} is not canonical base64") from exc
    if len(decoded) != byte_length or base64.b64encode(decoded).decode("ascii") != value:
        raise ValueError(f"{field_name} has the wrong length or encoding")
    return decoded


def _require_sorted_unique(values: Sequence[str], *, field_name: str) -> None:
    if values != sorted(set(values)):
        raise ValueError(f"{field_name} must be unique and sorted")


class SourceRevision(_StrictReleaseModel):
    repository: Literal["misscomputer/misscomputer-subnet"]
    object_format: Literal["sha1"]
    commit_oid: GitObjectID
    tree_oid: GitObjectID
    source_archive_sha256: Digest


class ToolchainInput(_StrictReleaseModel):
    toolchain_id: RecordID
    component: Literal["container_builder", "go", "python"]
    version: VersionText
    platform: Platform
    distribution_sha256: Digest


class DependencyInput(_StrictReleaseModel):
    dependency_id: RecordID
    ecosystem: Literal["container", "go", "python"]
    path: RelativeArtifactPath
    content_sha256: Digest
    byte_length: int = Field(gt=0, le=1 << 34)

    _safe_path = field_validator("path")(_validate_relative_path)


class PythonDistribution(_StrictReleaseModel):
    artifact_id: RecordID
    distribution_kind: Literal["sdist", "wheel"]
    path: RelativeArtifactPath
    content_sha256: Digest
    byte_length: int = Field(gt=0, le=1 << 34)
    requires_python: Literal["==3.12.*"]

    _safe_path = field_validator("path")(_validate_relative_path)

    @model_validator(mode="after")
    def matching_filename(self) -> Self:
        suffix = ".whl" if self.distribution_kind == "wheel" else ".tar.gz"
        if not self.path.startswith("dist/") or not self.path.endswith(suffix):
            raise ValueError("Python distribution path does not match its kind")
        return self


class GoBinary(_StrictReleaseModel):
    artifact_id: RecordID
    binary_name: Literal["control-api", "miner-agent", "workload"]
    path: RelativeArtifactPath
    target: Literal["linux_amd64", "linux_arm64"]
    build_mode: Literal["trimpath_cgo_disabled"]
    content_sha256: Digest
    byte_length: int = Field(gt=0, le=1 << 34)

    _safe_path = field_validator("path")(_validate_relative_path)

    @model_validator(mode="after")
    def matching_binary_path(self) -> Self:
        if self.path != f"bin/{self.target}/{self.binary_name}":
            raise ValueError("Go binary path does not match its target and name")
        return self


class OCIImage(_StrictReleaseModel):
    artifact_id: RecordID
    image_name: Literal["neuron", "workload"]
    platform: Literal["linux/amd64", "linux/arm64"]
    manifest_digest: OCIDigest
    config_digest: OCIDigest
    archive_path: RelativeArtifactPath
    content_sha256: Digest
    byte_length: int = Field(gt=0, le=1 << 36)

    _safe_archive_path = field_validator("archive_path")(_validate_relative_path)

    @model_validator(mode="after")
    def matching_archive_path(self) -> Self:
        if self.archive_path != f"oci/{self.platform.replace('/', '_')}/{self.image_name}.tar":
            raise ValueError("OCI archive path does not match its platform and name")
        return self


class WorkloadArtifact(_StrictReleaseModel):
    artifact_id: RecordID
    workload_kind: Literal["synthetic_http_v1"]
    container_artifact_id: RecordID
    descriptor_path: RelativeArtifactPath
    descriptor_sha256: Digest
    content_sha256: Digest
    byte_length: int = Field(gt=0, le=1 << 34)

    _safe_descriptor_path = field_validator("descriptor_path")(_validate_relative_path)


class ReleaseFile(_StrictReleaseModel):
    artifact_id: RecordID
    category: Literal["config", "contract_schema", "systemd_unit"]
    path: RelativeArtifactPath
    content_sha256: Digest
    byte_length: int = Field(gt=0, le=1 << 30)

    _safe_path = field_validator("path")(_validate_relative_path)

    @model_validator(mode="after")
    def matching_category_path(self) -> Self:
        if self.category == "config" and not self.path.startswith("configs/"):
            raise ValueError("config artifact must be beneath configs")
        if self.category == "systemd_unit" and not (
            self.path.startswith("deployments/systemd/")
            and self.path.endswith((".service", ".timer"))
        ):
            raise ValueError("systemd unit artifact path is invalid")
        if self.category == "contract_schema" and not (
            self.path.startswith("contracts/schemas/") and self.path.endswith(".schema.json")
        ):
            raise ValueError("contract schema artifact path is invalid")
        return self


class SupplyChainReference(_StrictReleaseModel):
    reference_id: RecordID
    format: Literal["slsa_provenance_v1", "spdx_json"]
    path: RelativeArtifactPath
    content_sha256: Digest
    byte_length: int = Field(gt=0, le=1 << 32)
    subject_artifact_ids: list[RecordID] = Field(min_length=1, max_length=256)

    _safe_path = field_validator("path")(_validate_relative_path)

    @model_validator(mode="after")
    def canonical_subjects(self) -> Self:
        _require_sorted_unique(self.subject_artifact_ids, field_name="supply-chain subjects")
        return self


class RollbackBytes(_StrictReleaseModel):
    artifact_id: RecordID
    replacement_sha256: Digest
    rollback_path: RelativeArtifactPath
    rollback_sha256: Digest
    rollback_byte_length: int = Field(gt=0, le=1 << 36)

    _safe_rollback_path = field_validator("rollback_path")(_validate_relative_path)

    @model_validator(mode="after")
    def distinct_bytes(self) -> Self:
        if not self.rollback_path.startswith("rollback/"):
            raise ValueError("rollback bytes must be beneath rollback")
        if self.rollback_sha256 == self.replacement_sha256:
            raise ValueError("rollback bytes must differ from replacement bytes")
        return self


class ProductionReleaseManifest(_StrictReleaseModel):
    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        frozen=True,
        title="Production release manifest v1",
        json_schema_extra={
            "$id": ("https://miss.computer/contracts/production-release-manifest.v1.schema.json"),
            "$comment": (
                "Offline metadata only. Parsing this document does not verify builds, "
                "artifacts, signatures, or authorize launch."
            ),
        },
    )

    contract_schema: Literal["miss.computer/misscomputer-subnet/production-release-manifest"] = (
        Field(alias="schema")
    )
    schema_version: Literal[1]
    release_id: ReleaseID
    release_version: VersionText
    release_channel: Literal["production"]
    target_network: Literal["finney"]
    netuid: Literal[24]
    source: SourceRevision
    created_at_epoch: UnixTime
    expires_at_epoch: UnixTime
    toolchains: list[ToolchainInput] = Field(min_length=3, max_length=3)
    dependency_inputs: list[DependencyInput] = Field(min_length=3, max_length=64)
    python_distributions: list[PythonDistribution] = Field(min_length=2, max_length=2)
    go_binaries: list[GoBinary] = Field(min_length=3, max_length=3)
    container_images: list[OCIImage] = Field(min_length=2, max_length=8)
    workload_artifacts: list[WorkloadArtifact] = Field(min_length=1, max_length=16)
    release_files: list[ReleaseFile] = Field(min_length=3, max_length=256)
    sbom_references: list[SupplyChainReference] = Field(min_length=1, max_length=32)
    provenance_references: list[SupplyChainReference] = Field(min_length=1, max_length=32)
    rollback_bytes: list[RollbackBytes] = Field(min_length=1, max_length=512)
    completeness_state: Literal["complete"]
    uniqueness_state: Literal["unique"]
    build_recomputation_state: Literal["not_performed", "verified"]
    artifact_verification_state: Literal["not_performed", "verified"]
    live_actions: Literal[False]
    digest_sha256: Digest

    @model_validator(mode="after")
    def complete_release(self) -> Self:
        if self.created_at_epoch >= self.expires_at_epoch:
            raise ValueError("release validity window is empty")

        ordered_ids: tuple[tuple[str, list[str]], ...] = (
            ("toolchains", [item.toolchain_id for item in self.toolchains]),
            ("dependency inputs", [item.dependency_id for item in self.dependency_inputs]),
            (
                "Python distributions",
                [item.artifact_id for item in self.python_distributions],
            ),
            ("Go binaries", [item.artifact_id for item in self.go_binaries]),
            ("container images", [item.artifact_id for item in self.container_images]),
            (
                "workload artifacts",
                [item.artifact_id for item in self.workload_artifacts],
            ),
            ("release files", [item.artifact_id for item in self.release_files]),
            ("SBOM references", [item.reference_id for item in self.sbom_references]),
            (
                "provenance references",
                [item.reference_id for item in self.provenance_references],
            ),
            ("rollback bytes", [item.artifact_id for item in self.rollback_bytes]),
        )
        for field_name, values in ordered_ids:
            _require_sorted_unique(values, field_name=field_name)

        evidence_reference_ids = [
            item.reference_id for item in (*self.sbom_references, *self.provenance_references)
        ]
        if len(evidence_reference_ids) != len(set(evidence_reference_ids)):
            raise ValueError("supply-chain reference identifiers must be globally unique")

        if {item.component for item in self.toolchains} != EXPECTED_TOOLCHAIN_COMPONENTS:
            raise ValueError("required toolchain inventory is incomplete")
        if {item.ecosystem for item in self.dependency_inputs} != {
            "container",
            "go",
            "python",
        }:
            raise ValueError("dependency ecosystems are incomplete")
        if {item.distribution_kind for item in self.python_distributions} != {"sdist", "wheel"}:
            raise ValueError("wheel and sdist are both required")
        if {item.binary_name for item in self.go_binaries} != EXPECTED_GO_BINARIES:
            raise ValueError("production Go binary inventory is incomplete")
        if {item.image_name for item in self.container_images} != EXPECTED_CONTAINER_IMAGES:
            raise ValueError("production container inventory is incomplete")
        if {item.category for item in self.release_files} != REQUIRED_RELEASE_FILE_CATEGORIES:
            raise ValueError("config, unit, and schema artifact inventory is incomplete")

        all_paths = (
            [item.path for item in self.dependency_inputs]
            + [item.path for item in self.python_distributions]
            + [item.path for item in self.go_binaries]
            + [item.archive_path for item in self.container_images]
            + [item.descriptor_path for item in self.workload_artifacts]
            + [item.path for item in self.release_files]
            + [item.path for item in self.sbom_references]
            + [item.path for item in self.provenance_references]
            + [item.rollback_path for item in self.rollback_bytes]
        )
        if len(all_paths) != len(set(all_paths)):
            raise ValueError("release paths must be globally unique")

        artifact_digests: dict[str, str] = {}
        for distribution in self.python_distributions:
            artifact_digests[distribution.artifact_id] = distribution.content_sha256
        for binary in self.go_binaries:
            artifact_digests[binary.artifact_id] = binary.content_sha256
        for image in self.container_images:
            artifact_digests[image.artifact_id] = image.content_sha256
        for workload in self.workload_artifacts:
            artifact_digests[workload.artifact_id] = workload.content_sha256
        for release_file in self.release_files:
            artifact_digests[release_file.artifact_id] = release_file.content_sha256
        expected_artifact_count = (
            len(self.python_distributions)
            + len(self.go_binaries)
            + len(self.container_images)
            + len(self.workload_artifacts)
            + len(self.release_files)
        )
        if len(artifact_digests) != expected_artifact_count:
            raise ValueError("artifact identifiers must be globally unique")

        container_ids = {item.artifact_id for item in self.container_images}
        if any(item.container_artifact_id not in container_ids for item in self.workload_artifacts):
            raise ValueError("workload artifact references an unknown container")

        expected_subjects = set(artifact_digests)
        for kind, references, expected_format in (
            ("SBOM", self.sbom_references, "spdx_json"),
            ("provenance", self.provenance_references, "slsa_provenance_v1"),
        ):
            if any(reference.format != expected_format for reference in references):
                raise ValueError(f"{kind} reference format is invalid")
            subjects = [
                subject for reference in references for subject in reference.subject_artifact_ids
            ]
            if len(subjects) != len(set(subjects)) or set(subjects) != expected_subjects:
                raise ValueError(f"{kind} subject coverage is incomplete or ambiguous")

        sdist_ids = {
            item.artifact_id
            for item in self.python_distributions
            if item.distribution_kind == "sdist"
        }
        expected_rollback_ids = expected_subjects - sdist_ids
        rollback_ids = {item.artifact_id for item in self.rollback_bytes}
        if rollback_ids != expected_rollback_ids:
            raise ValueError("rollback byte coverage is incomplete or ambiguous")
        for rollback in self.rollback_bytes:
            if rollback.replacement_sha256 != artifact_digests[rollback.artifact_id]:
                raise ValueError("rollback replacement digest does not match the release artifact")

        unsigned = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"digest_sha256"},
        )
        if self.digest_sha256 != _document_digest(unsigned):
            raise ValueError("release manifest digest does not match canonical content")
        return self


class TrustedReleaseKey(_StrictReleaseModel):
    key_id: RecordID
    algorithm: Literal["ed25519"]
    public_key_base64: CanonicalPublicKeyBase64
    public_key_sha256: Digest
    roles: list[SignerRole] = Field(min_length=1, max_length=3)
    valid_from_epoch: UnixTime
    valid_until_epoch: UnixTime

    @model_validator(mode="after")
    def canonical_public_key(self) -> Self:
        decoded = decode_ed25519_public_key_base64(self.public_key_base64)
        if self.public_key_sha256 != _sha256(decoded):
            raise ValueError("public key fingerprint does not match public key bytes")
        _require_sorted_unique(self.roles, field_name="trusted key roles")
        if self.valid_from_epoch >= self.valid_until_epoch:
            raise ValueError("trusted key validity window is empty")
        return self


class ReleaseTrustPolicy(_StrictReleaseModel):
    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        frozen=True,
        title="Release trust policy v1",
        json_schema_extra={
            "$id": "https://miss.computer/contracts/release-trust-policy.v1.schema.json",
            "$comment": "Public-key metadata only; this contract has no private-key material.",
        },
    )

    contract_schema: Literal["miss.computer/misscomputer-subnet/release-trust-policy"] = Field(
        alias="schema"
    )
    schema_version: Literal[1]
    policy_id: RecordID
    threshold: int = Field(ge=2, le=16)
    required_roles: list[SignerRole] = Field(min_length=3, max_length=3)
    trusted_keys: list[TrustedReleaseKey] = Field(min_length=3, max_length=16)
    valid_from_epoch: UnixTime
    valid_until_epoch: UnixTime
    digest_sha256: Digest

    @model_validator(mode="after")
    def complete_policy(self) -> Self:
        if self.valid_from_epoch >= self.valid_until_epoch:
            raise ValueError("trust policy validity window is empty")
        _require_sorted_unique(self.required_roles, field_name="required signer roles")
        if set(self.required_roles) != REQUIRED_SIGNER_ROLES:
            raise ValueError("required signer-role separation is incomplete")
        key_ids = [key.key_id for key in self.trusted_keys]
        _require_sorted_unique(key_ids, field_name="trusted keys")
        key_digests = [key.public_key_sha256 for key in self.trusted_keys]
        if len(key_digests) != len(set(key_digests)):
            raise ValueError("trusted public keys must be unique")
        if self.threshold > len(self.trusted_keys):
            raise ValueError("signature threshold exceeds trusted key count")
        if any(
            key.valid_from_epoch > self.valid_from_epoch
            or key.valid_until_epoch < self.valid_until_epoch
            for key in self.trusted_keys
        ):
            raise ValueError("trusted key validity does not cover the policy window")
        covered_roles = {role for key in self.trusted_keys for role in key.roles}
        if not REQUIRED_SIGNER_ROLES <= covered_roles:
            raise ValueError("trusted keys do not cover every required role")
        unsigned = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"digest_sha256"},
        )
        if self.digest_sha256 != _document_digest(unsigned):
            raise ValueError("trust policy digest does not match canonical content")
        return self


class OfflineSignatureEnvelope(_StrictReleaseModel):
    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        frozen=True,
        title="Offline signature envelope v1",
        json_schema_extra={
            "$id": ("https://miss.computer/contracts/offline-signature-envelope.v1.schema.json"),
            "$comment": (
                "Canonical signature metadata only; cryptographic verification is separate."
            ),
        },
    )

    contract_schema: Literal["miss.computer/misscomputer-subnet/offline-signature-envelope"] = (
        Field(alias="schema")
    )
    schema_version: Literal[1]
    signer_key_id: RecordID
    algorithm: Literal["ed25519"]
    payload_digest_sha256: Digest
    signature_base64: CanonicalSignatureBase64
    issued_at_epoch: UnixTime
    expires_at_epoch: UnixTime

    @model_validator(mode="after")
    def canonical_envelope(self) -> Self:
        _decode_canonical_base64(
            self.signature_base64,
            byte_length=64,
            field_name="signature",
        )
        if self.issued_at_epoch >= self.expires_at_epoch:
            raise ValueError("signature envelope validity window is empty")
        return self


class LaunchAuthorizationBundle(_StrictReleaseModel):
    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        frozen=True,
        title="Launch authorization bundle v1",
        json_schema_extra={
            "$id": ("https://miss.computer/contracts/launch-authorization-bundle.v1.schema.json"),
            "$comment": (
                "Offline envelope only. A signature_verification_state of verified must "
                "come from a separate cryptographic verifier; model validation is not proof."
            ),
        },
    )

    contract_schema: Literal["miss.computer/misscomputer-subnet/launch-authorization-bundle"] = (
        Field(alias="schema")
    )
    schema_version: Literal[1]
    bundle_id: RecordID
    release_manifest: ProductionReleaseManifest
    release_manifest_digest_sha256: Digest
    trust_policy: ReleaseTrustPolicy
    trust_policy_digest_sha256: Digest
    issued_at_epoch: UnixTime
    expires_at_epoch: UnixTime
    evaluated_at_epoch: UnixTime
    authorization_payload_digest_sha256: Digest
    signatures: list[OfflineSignatureEnvelope] = Field(min_length=2, max_length=16)
    completeness_state: Literal["complete"]
    uniqueness_state: Literal["unique"]
    signature_verification_state: Literal["failed", "not_performed", "verified"]
    authorization_state: Literal[
        "authorized",
        "expired",
        "pending_signature_verification",
        "rejected",
    ]
    launch_authorized: bool
    live_actions: Literal[False]
    digest_sha256: Digest

    @model_validator(mode="after")
    def consistent_authorization(self) -> Self:
        if self.release_manifest_digest_sha256 != self.release_manifest.digest_sha256:
            raise ValueError("release manifest digest binding is inconsistent")
        if self.trust_policy_digest_sha256 != self.trust_policy.digest_sha256:
            raise ValueError("trust policy digest binding is inconsistent")
        if not (
            self.release_manifest.created_at_epoch
            <= self.issued_at_epoch
            < self.expires_at_epoch
            <= self.release_manifest.expires_at_epoch
        ):
            raise ValueError("authorization window is outside the release window")
        if not (
            self.trust_policy.valid_from_epoch
            <= self.issued_at_epoch
            < self.expires_at_epoch
            <= self.trust_policy.valid_until_epoch
        ):
            raise ValueError("authorization window is outside the trust policy window")
        if self.evaluated_at_epoch < self.issued_at_epoch:
            raise ValueError("authorization evaluation predates issuance")

        expected_payload = authorization_payload_digest(
            bundle_id=self.bundle_id,
            manifest=self.release_manifest,
            trust_policy=self.trust_policy,
            issued_at_epoch=self.issued_at_epoch,
            expires_at_epoch=self.expires_at_epoch,
        )
        if self.authorization_payload_digest_sha256 != expected_payload:
            raise ValueError("authorization payload digest does not match canonical content")

        signer_ids = [signature.signer_key_id for signature in self.signatures]
        _require_sorted_unique(signer_ids, field_name="signature envelopes")
        if len(self.signatures) < self.trust_policy.threshold:
            raise ValueError("signature envelope count is below policy threshold")
        keys = {key.key_id: key for key in self.trust_policy.trusted_keys}
        signer_roles: set[SignerRole] = set()
        for signature in self.signatures:
            key = keys.get(signature.signer_key_id)
            if key is None:
                raise ValueError("signature envelope uses an untrusted key")
            if signature.algorithm != key.algorithm:
                raise ValueError("signature algorithm does not match trusted key")
            if signature.payload_digest_sha256 != expected_payload:
                raise ValueError("signature envelope payload digest is inconsistent")
            if (
                signature.issued_at_epoch != self.issued_at_epoch
                or signature.expires_at_epoch != self.expires_at_epoch
            ):
                raise ValueError("signature envelope validity is not bundle-bound")
            if not (
                key.valid_from_epoch
                <= signature.issued_at_epoch
                < signature.expires_at_epoch
                <= key.valid_until_epoch
            ):
                raise ValueError("signature envelope is outside trusted key validity")
            signer_roles.update(key.roles)
        if not set(self.trust_policy.required_roles) <= signer_roles:
            raise ValueError("signature envelopes do not cover every required role")

        expired = self.evaluated_at_epoch >= self.expires_at_epoch
        if expired:
            expected_state = "expired"
            expected_authorized = False
        elif self.signature_verification_state == "not_performed":
            expected_state = "pending_signature_verification"
            expected_authorized = False
        elif self.signature_verification_state == "failed":
            expected_state = "rejected"
            expected_authorized = False
        else:
            expected_state = "authorized"
            expected_authorized = True
        if (
            self.authorization_state != expected_state
            or self.launch_authorized is not expected_authorized
        ):
            raise ValueError("authorization state is inconsistent with verification and expiry")

        unsigned = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"digest_sha256"},
        )
        if self.digest_sha256 != _document_digest(unsigned):
            raise ValueError("authorization bundle digest does not match canonical content")
        return self


def _build_digested_document(
    document: Mapping[str, object],
    *,
    model: (
        type[ProductionReleaseManifest] | type[ReleaseTrustPolicy] | type[LaunchAuthorizationBundle]
    ),
) -> ProductionReleaseManifest | ReleaseTrustPolicy | LaunchAuthorizationBundle:
    if "digest_sha256" in document:
        raise ProductionReleaseContractError("unsigned document unexpectedly contains a digest")
    unsigned = dict(document)
    return model.model_validate({**unsigned, "digest_sha256": _document_digest(unsigned)})


def build_production_release_manifest(
    unsigned_document: Mapping[str, object],
) -> ProductionReleaseManifest:
    """Validate a JSON-compatible unsigned manifest and bind its canonical digest."""

    built = _build_digested_document(unsigned_document, model=ProductionReleaseManifest)
    if not isinstance(built, ProductionReleaseManifest):
        raise AssertionError("unexpected production release model")
    return built


def build_release_trust_policy(unsigned_document: Mapping[str, object]) -> ReleaseTrustPolicy:
    """Validate a JSON-compatible unsigned policy and bind its canonical digest."""

    built = _build_digested_document(unsigned_document, model=ReleaseTrustPolicy)
    if not isinstance(built, ReleaseTrustPolicy):
        raise AssertionError("unexpected release trust policy model")
    return built


def authorization_payload_digest(
    *,
    bundle_id: str,
    manifest: ProductionReleaseManifest,
    trust_policy: ReleaseTrustPolicy,
    issued_at_epoch: int,
    expires_at_epoch: int,
) -> str:
    """Digest the exact non-circular payload represented by offline signatures."""

    return _document_digest(
        {
            "bundle_id": bundle_id,
            "expires_at_epoch": expires_at_epoch,
            "issued_at_epoch": issued_at_epoch,
            "netuid": manifest.netuid,
            "release_id": manifest.release_id,
            "release_manifest_digest_sha256": manifest.digest_sha256,
            "source_commit_oid": manifest.source.commit_oid,
            "source_tree_oid": manifest.source.tree_oid,
            "target_network": manifest.target_network,
            "trust_policy_digest_sha256": trust_policy.digest_sha256,
        }
    )


def build_launch_authorization_bundle(
    unsigned_document: Mapping[str, object],
) -> LaunchAuthorizationBundle:
    """Validate an unsigned JSON-compatible bundle and bind its canonical digest."""

    built = _build_digested_document(unsigned_document, model=LaunchAuthorizationBundle)
    if not isinstance(built, LaunchAuthorizationBundle):
        raise AssertionError("unexpected launch authorization model")
    return built


def production_release_manifest_bytes(manifest: ProductionReleaseManifest) -> bytes:
    """Return the one canonical newline-terminated release-manifest encoding."""

    return _canonical_json(manifest.model_dump(mode="json", by_alias=True)) + b"\n"


def release_trust_policy_bytes(policy: ReleaseTrustPolicy) -> bytes:
    """Return the one canonical newline-terminated trust-policy encoding."""

    return _canonical_json(policy.model_dump(mode="json", by_alias=True)) + b"\n"


def offline_signature_envelope_bytes(envelope: OfflineSignatureEnvelope) -> bytes:
    """Return the one canonical newline-terminated signature-envelope encoding."""

    return _canonical_json(envelope.model_dump(mode="json", by_alias=True)) + b"\n"


def launch_authorization_bundle_bytes(bundle: LaunchAuthorizationBundle) -> bytes:
    """Return the one canonical newline-terminated authorization-bundle encoding."""

    return _canonical_json(bundle.model_dump(mode="json", by_alias=True)) + b"\n"
