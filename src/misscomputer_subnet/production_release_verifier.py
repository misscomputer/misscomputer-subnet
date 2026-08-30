# SPDX-License-Identifier: AGPL-3.0-only
"""Fail-closed, offline verification for production release authorization.

The module deliberately has no network, registry, provider, subprocess,
private-key, installation, service, cloud, DNS, wallet, RPC, chain, publish,
apply, or activation capability.  It reads owner-confined local evidence,
recomputes byte digests, verifies Ed25519 signatures with public keys, and
emits a canonical report.  The report is authorization evidence only; it does
not perform a launch.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import stat
import sys
import tarfile
from collections.abc import Mapping, Sequence
from contextlib import AbstractContextManager
from dataclasses import dataclass
from typing import Annotated, Literal, NoReturn, Self, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationError,
    model_validator,
)

from misscomputer_subnet.ed25519_trust import (
    Ed25519PublicKeyValidationError,
    decode_ed25519_public_key_base64,
)
from misscomputer_subnet.production_release import (
    Digest,
    LaunchAuthorizationBundle,
    OCIImage,
    OfflineSignatureEnvelope,
    ProductionReleaseManifest,
    RecordID,
    RelativeArtifactPath,
    SignerRole,
    SupplyChainReference,
    UnixTime,
)

RELEASE_REVOCATION_LIST_SCHEMA = "miss.computer/misscomputer-subnet/release-revocation-list"
LAUNCH_AUTHORIZATION_REPORT_SCHEMA = "miss.computer/misscomputer-subnet/launch-authorization-report"
WORKLOAD_EXPORT_DESCRIPTOR_SCHEMA = "miss.computer/misscomputer-subnet/workload-export-descriptor"
VERIFIER_SCHEMA_VERSION = 1
VERIFIER_ID = "misscomputer-release-verifier-v1"
SIGNATURE_ALGORITHM = "ed25519"
SIGNATURE_PURPOSE = "production_mainnet_launch_authorization"
SIGNATURE_DOMAIN = "miss.computer/misscomputer-subnet/launch-authorization/v1"
SIGNATURE_DOMAIN_BYTES = SIGNATURE_DOMAIN.encode("ascii") + b"\x00"

MAX_CANONICAL_DOCUMENT_BYTES = 8 * 1024 * 1024
MAX_EVIDENCE_DOCUMENT_BYTES = 32 * 1024 * 1024
MAX_WORKLOAD_DESCRIPTOR_BYTES = 1024 * 1024
MAX_OCI_METADATA_BYTES = 16 * 1024 * 1024
MAX_OCI_MEMBERS = 131_072
MAX_SOURCE_ARCHIVE_BYTES = 4 * 1024 * 1024 * 1024
MAX_RELEASE_ARTIFACT_BYTES = 64 * 1024 * 1024 * 1024
READ_CHUNK_BYTES = 1024 * 1024

EXIT_OK = 0
EXIT_REJECTED = 2
EXIT_USAGE = 64
EXIT_INTERNAL = 70

_SENSITIVE_COMPONENTS = frozenset(
    {
        ".env",
        ".ssh",
        "credential",
        "credentials",
        "id_ed25519",
        "id_rsa",
        "private-key",
        "private_key",
        "secret",
        "secrets",
        "wallet",
        "wallets",
    }
)
_SENSITIVE_SUFFIXES = (".key", ".p12", ".pem", ".pfx")
_DIGEST_PATTERN = "0123456789abcdef"


class ReleaseVerificationError(RuntimeError):
    """A credential-safe, stable verifier rejection."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class _DuplicateJSONKey(ValueError):
    pass


class _RejectedJSONConstant(ValueError):
    pass


class _VerifierModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class RevokedReleaseKey(_VerifierModel):
    key_id: RecordID
    revoked_at_epoch: UnixTime
    reason: Literal["compromise", "policy_violation", "retired", "superseded"]


class ReleaseRevocationList(_VerifierModel):
    """A locally approved, digest-pinned view of release-key revocations."""

    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        frozen=True,
        title="Release revocation list v1",
        json_schema_extra={
            "$id": "https://miss.computer/contracts/release-revocation-list.v1.schema.json",
            "$comment": (
                "Offline public-key revocation metadata. The verifier requires its exact "
                "digest as an independent local trust anchor."
            ),
        },
    )

    contract_schema: Literal["miss.computer/misscomputer-subnet/release-revocation-list"] = Field(
        alias="schema"
    )
    schema_version: Literal[1]
    policy_digest_sha256: Digest
    sequence: int = Field(ge=0, le=(1 << 63) - 1)
    issued_at_epoch: UnixTime
    expires_at_epoch: UnixTime
    revoked_keys: list[RevokedReleaseKey] = Field(max_length=16)
    live_actions: Literal[False]
    digest_sha256: Digest

    @model_validator(mode="after")
    def canonical_revocations(self) -> Self:
        if self.issued_at_epoch >= self.expires_at_epoch:
            raise ValueError("revocation-list validity window is empty")
        key_ids = [item.key_id for item in self.revoked_keys]
        if key_ids != sorted(set(key_ids)):
            raise ValueError("revoked key identifiers must be unique and sorted")
        if any(item.revoked_at_epoch > self.issued_at_epoch for item in self.revoked_keys):
            raise ValueError("revocation list contains a future revocation")
        unsigned = self.model_dump(mode="json", by_alias=True, exclude={"digest_sha256"})
        if self.digest_sha256 != _document_digest(unsigned):
            raise ValueError("revocation-list digest does not match canonical content")
        return self


class WorkloadExportDescriptor(_VerifierModel):
    """Canonical immutable descriptor accepted instead of workload export bytes."""

    contract_schema: Literal["miss.computer/misscomputer-subnet/workload-export-descriptor"] = (
        Field(alias="schema")
    )
    schema_version: Literal[1]
    artifact_id: RecordID
    workload_kind: Literal["synthetic_http_v1"]
    container_artifact_id: RecordID
    container_manifest_digest: Annotated[str, StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$")]
    content_sha256: Digest
    byte_length: int = Field(gt=0, le=1 << 34)
    mutable_tag: Literal[None] = None


InputCategory = Literal[
    "dependency_input",
    "go_binary",
    "oci_archive",
    "provenance",
    "python_distribution",
    "release_file",
    "rollback_bytes",
    "sbom",
    "source_archive",
    "workload_descriptor",
]

ReportEntryID = Annotated[
    str,
    StringConstraints(
        max_length=84,
        pattern=(
            r"^(?:source_archive|(?:dependency_input|go_binary|oci_archive|provenance|"
            r"python_distribution|release_file|rollback_bytes|sbom|workload_descriptor)_"
            r"(?:[a-z][a-z0-9_]{0,62}[a-z0-9]|[a-z]))$"
        ),
    ),
]


def _report_entry_id(category: InputCategory, source_id: str) -> str:
    """Bind a contract-valid source identifier to its report input category."""

    if category == "source_archive":
        raise ValueError("source archive has no source record identifier")
    return f"{category}_{source_id}"


class VerifiedLocalInput(_VerifierModel):
    input_id: ReportEntryID
    category: InputCategory
    relative_path: RelativeArtifactPath
    expected_sha256: Digest
    observed_sha256: Digest
    expected_byte_length: int | None = Field(default=None, gt=0, le=MAX_RELEASE_ARTIFACT_BYTES)
    observed_byte_length: int = Field(gt=0, le=MAX_RELEASE_ARTIFACT_BYTES)
    recomputed_sha256: Digest | None = None
    recomputed_byte_length: int | None = Field(
        default=None,
        gt=0,
        le=MAX_RELEASE_ARTIFACT_BYTES,
    )
    bound_content_sha256: Digest | None = None
    verification_state: Literal["verified"]

    @model_validator(mode="after")
    def exact_observations(self) -> Self:
        if self.category == "source_archive":
            if self.input_id != "source_archive":
                raise ValueError("report input identifier is not bound to its category")
        elif not self.input_id.startswith(f"{self.category}_"):
            raise ValueError("report input identifier is not bound to its category")
        if self.observed_sha256 != self.expected_sha256:
            raise ValueError("observed digest differs from expected digest")
        if (
            self.expected_byte_length is not None
            and self.observed_byte_length != self.expected_byte_length
        ):
            raise ValueError("observed length differs from expected length")
        paired = self.category not in {"dependency_input", "source_archive"}
        if paired:
            if (
                self.recomputed_sha256 != self.expected_sha256
                or self.recomputed_byte_length != self.observed_byte_length
            ):
                raise ValueError("recomputed artifact is not byte-reproducible")
        elif self.recomputed_sha256 is not None or self.recomputed_byte_length is not None:
            raise ValueError("source input unexpectedly has a recomputed observation")
        return self


class VerifiedReleaseSignature(_VerifierModel):
    signer_key_id: RecordID
    algorithm: Literal["ed25519"]
    roles: list[SignerRole] = Field(min_length=1, max_length=3)
    signature_sha256: Digest
    verification_state: Literal["verified"]

    @model_validator(mode="after")
    def canonical_roles(self) -> Self:
        if self.roles != sorted(set(self.roles)):
            raise ValueError("verified signature roles must be unique and sorted")
        return self


class LaunchAuthorizationReport(_VerifierModel):
    """Canonical output of the offline verifier; never an activation action."""

    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        frozen=True,
        title="Launch authorization report v1",
        json_schema_extra={
            "$id": "https://miss.computer/contracts/launch-authorization-report.v1.schema.json",
            "$comment": (
                "Offline verification evidence only. launch_authorized does not apply, "
                "publish, install, start, or activate anything."
            ),
        },
    )

    contract_schema: Literal["miss.computer/misscomputer-subnet/launch-authorization-report"] = (
        Field(alias="schema")
    )
    schema_version: Literal[1]
    verifier_id: Literal["misscomputer-release-verifier-v1"]
    signature_algorithm: Literal["ed25519"]
    signature_purpose: Literal["production_mainnet_launch_authorization"]
    signature_domain: Literal["miss.computer/misscomputer-subnet/launch-authorization/v1"]
    bundle_id: RecordID
    bundle_digest_sha256: Digest
    release_manifest_digest_sha256: Digest
    trust_policy_digest_sha256: Digest
    approved_trust_policy_digest_sha256: Digest
    revocation_list_digest_sha256: Digest
    approved_revocation_list_digest_sha256: Digest
    source_commit_oid: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{40}$")]
    source_tree_oid: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{40}$")]
    target_network: Literal["finney"]
    netuid: Literal[24]
    evaluated_at_epoch: UnixTime
    verified_inputs: list[VerifiedLocalInput] = Field(min_length=1, max_length=1024)
    verified_input_set_digest_sha256: Digest
    verified_signatures: list[VerifiedReleaseSignature] = Field(min_length=2, max_length=16)
    verified_signature_set_digest_sha256: Digest
    required_signature_threshold: int = Field(ge=2, le=16)
    required_roles: list[SignerRole] = Field(min_length=3, max_length=3)
    artifact_verification_state: Literal["verified"]
    build_recomputation_state: Literal["verified"]
    signature_verification_state: Literal["verified"]
    revocation_verification_state: Literal["verified"]
    authorization_state: Literal["authorized"]
    launch_authorized: Literal[True]
    live_actions: Literal[False]
    digest_sha256: Digest

    @model_validator(mode="after")
    def canonical_report(self) -> Self:
        if self.trust_policy_digest_sha256 != self.approved_trust_policy_digest_sha256:
            raise ValueError("report trust-policy approval binding is inconsistent")
        if self.revocation_list_digest_sha256 != self.approved_revocation_list_digest_sha256:
            raise ValueError("report revocation-list approval binding is inconsistent")
        input_ids = [item.input_id for item in self.verified_inputs]
        if input_ids != sorted(set(input_ids)):
            raise ValueError("verified input identifiers must be unique and sorted")
        signer_ids = [item.signer_key_id for item in self.verified_signatures]
        if signer_ids != sorted(set(signer_ids)):
            raise ValueError("verified signer identifiers must be unique and sorted")
        if self.required_roles != sorted(set(self.required_roles)):
            raise ValueError("required report roles must be unique and sorted")
        if self.required_signature_threshold > len(self.verified_signatures):
            raise ValueError("verified signature count is below threshold")
        covered_roles = {role for item in self.verified_signatures for role in item.roles}
        if not set(self.required_roles) <= covered_roles:
            raise ValueError("verified signatures do not cover required roles")
        input_documents = [item.model_dump(mode="json") for item in self.verified_inputs]
        if self.verified_input_set_digest_sha256 != _document_digest(input_documents):
            raise ValueError("verified input-set digest is inconsistent")
        signature_documents = [item.model_dump(mode="json") for item in self.verified_signatures]
        if self.verified_signature_set_digest_sha256 != _document_digest(signature_documents):
            raise ValueError("verified signature-set digest is inconsistent")
        unsigned = self.model_dump(mode="json", by_alias=True, exclude={"digest_sha256"})
        if self.digest_sha256 != _document_digest(unsigned):
            raise ValueError("authorization-report digest does not match canonical content")
        return self


@dataclass(frozen=True)
class VerificationPaths:
    """Absolute normalized local paths required for a complete verification."""

    bundle: str
    revocations: str
    source_root: str
    source_archive: str
    artifact_root: str
    recomputed_artifact_root: str


@dataclass(frozen=True)
class FileObservation:
    sha256: str
    byte_length: int


@dataclass(frozen=True)
class _FileMetadata:
    device: int
    inode: int
    mode: int
    uid: int
    gid: int
    links: int
    size: int
    modified_ns: int
    changed_ns: int


@dataclass(frozen=True)
class _DirectoryIdentity:
    device: int
    inode: int
    mode: int
    uid: int
    gid: int


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
        raise ReleaseVerificationError(
            "noncanonical_json", "document is not canonical JSON"
        ) from exc
    return rendered.encode("ascii")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _document_digest(value: object) -> str:
    return _sha256(_canonical_json(value))


def _valid_digest(value: str) -> bool:
    return len(value) == 64 and all(character in _DIGEST_PATTERN for character in value)


def _safe_label(label: str) -> str:
    if (
        not label
        or len(label) > 96
        or not label.isascii()
        or not label[0].isalnum()
        or any(not (character.isalnum() or character in {"_", "-"}) for character in label)
    ):
        return "input"
    return label


def _sensitive_component(component: str) -> bool:
    folded = component.casefold()
    return folded in _SENSITIVE_COMPONENTS or folded.endswith(_SENSITIVE_SUFFIXES)


def _normalized_absolute_path(path: str, *, label: str) -> str:
    safe_label = _safe_label(label)
    if (
        not isinstance(path, str)
        or not path
        or "\x00" in path
        or not path.startswith("/")
        or path.startswith("//")
        or path != os.path.normpath(path)
    ):
        raise ReleaseVerificationError(
            "unsafe_path", f"{safe_label} path must be absolute and normalized"
        )
    components = path.split("/")[1:]
    if not components or any(
        not component or _sensitive_component(component) for component in components
    ):
        raise ReleaseVerificationError(
            "sensitive_path", f"{safe_label} path is outside the accepted evidence boundary"
        )
    return path


def _rooted_path(root: str, relative_path: str, *, label: str) -> str:
    normalized_root = _normalized_absolute_path(root, label=label)
    if (
        not relative_path
        or relative_path.startswith("/")
        or relative_path != os.path.normpath(relative_path)
        or any(component in {"", ".", ".."} for component in relative_path.split("/"))
        or any(_sensitive_component(component) for component in relative_path.split("/"))
    ):
        raise ReleaseVerificationError("unsafe_path", f"{_safe_label(label)} path is unsafe")
    return f"{normalized_root}/{relative_path}"


def _file_metadata(value: os.stat_result) -> _FileMetadata:
    return _FileMetadata(
        device=value.st_dev,
        inode=value.st_ino,
        mode=value.st_mode,
        uid=value.st_uid,
        gid=value.st_gid,
        links=value.st_nlink,
        size=value.st_size,
        modified_ns=value.st_mtime_ns,
        changed_ns=value.st_ctime_ns,
    )


def _directory_identity(value: os.stat_result) -> _DirectoryIdentity:
    return _DirectoryIdentity(
        device=value.st_dev,
        inode=value.st_ino,
        mode=value.st_mode,
        uid=value.st_uid,
        gid=value.st_gid,
    )


def _owner_confined_regular_file(metadata: _FileMetadata) -> bool:
    return (
        stat.S_ISREG(metadata.mode)
        and metadata.uid == os.geteuid()
        and metadata.links == 1
        and metadata.mode & 0o077 == 0
        and metadata.mode & stat.S_IRUSR != 0
    )


def _safe_directory(value: os.stat_result, *, final_parent: bool) -> bool:
    if not stat.S_ISDIR(value.st_mode) or value.st_uid not in {0, os.geteuid()}:
        return False
    unsafe_write_bits = stat.S_IMODE(value.st_mode) & 0o022
    sticky_ancestor = bool(value.st_mode & stat.S_ISVTX) and not final_parent
    return not unsafe_write_bits or sticky_ancestor


class HardenedFileSet:
    """Track descriptor-confined files and reject aliases between logical inputs."""

    def __init__(self) -> None:
        self._identities: dict[tuple[int, int], str] = {}

    def open(self, path: str, *, label: str) -> _PinnedFile:
        return _PinnedFile(self, path, label=label)

    def _claim(self, metadata: _FileMetadata, *, label: str) -> None:
        identity = (metadata.device, metadata.inode)
        previous = self._identities.get(identity)
        if previous is not None and previous != label:
            raise ReleaseVerificationError(
                "duplicate_file", f"{_safe_label(label)} aliases another verifier input"
            )
        self._identities[identity] = label


class _PinnedFile(AbstractContextManager["_PinnedFile"]):
    def __init__(self, file_set: HardenedFileSet, path: str, *, label: str) -> None:
        self._file_set = file_set
        self._path = _normalized_absolute_path(path, label=label)
        self._label = _safe_label(label)
        self._directory_fds: list[int] = []
        self._directory_components: list[str] = []
        self._directory_identities: list[_DirectoryIdentity] = []
        self._file_fd = -1
        self._baseline: _FileMetadata | None = None

    @property
    def fd(self) -> int:
        if self._file_fd < 0:
            raise ReleaseVerificationError("closed_input", "verifier input is closed")
        return self._file_fd

    @property
    def baseline(self) -> _FileMetadata:
        if self._baseline is None:
            raise ReleaseVerificationError("closed_input", "verifier input is closed")
        return self._baseline

    def __enter__(self) -> _PinnedFile:
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        directory = getattr(os, "O_DIRECTORY", 0)
        cloexec = getattr(os, "O_CLOEXEC", 0)
        if nofollow == 0 or directory == 0:
            raise ReleaseVerificationError(
                "platform_boundary", "required no-follow file-descriptor controls are unavailable"
            )
        components = self._path.split("/")[1:]
        try:
            root_fd = os.open("/", os.O_RDONLY | directory | cloexec)
            self._directory_fds.append(root_fd)
            self._directory_components.append("")
            root_stat = os.fstat(root_fd)
            if not _safe_directory(root_stat, final_parent=len(components) == 1):
                raise OSError("root is not a directory")
            self._directory_identities.append(_directory_identity(root_stat))
            for component in components[:-1]:
                parent_fd = self._directory_fds[-1]
                child_fd = os.open(
                    component,
                    os.O_RDONLY | directory | nofollow | cloexec,
                    dir_fd=parent_fd,
                )
                child_stat = os.fstat(child_fd)
                if not _safe_directory(
                    child_stat,
                    final_parent=len(self._directory_fds) == len(components) - 1,
                ):
                    os.close(child_fd)
                    raise OSError("path component is not a directory")
                self._directory_fds.append(child_fd)
                self._directory_components.append(component)
                self._directory_identities.append(_directory_identity(child_stat))
            self._file_fd = os.open(
                components[-1],
                os.O_RDONLY | nofollow | cloexec,
                dir_fd=self._directory_fds[-1],
            )
            self._baseline = _file_metadata(os.fstat(self._file_fd))
        except (OSError, ValueError) as exc:
            self.close()
            raise ReleaseVerificationError(
                "unsafe_file", f"{self._label} could not be opened within the evidence boundary"
            ) from exc
        if not _owner_confined_regular_file(self.baseline):
            self.close()
            raise ReleaseVerificationError(
                "unsafe_file_metadata",
                f"{self._label} must be an owner-only regular single-link file",
            )
        self._file_set._claim(self.baseline, label=self._label)
        self._revalidate()
        return self

    def _revalidate(self) -> None:
        try:
            for index, directory_fd in enumerate(self._directory_fds):
                directory_stat = os.fstat(directory_fd)
                if not _safe_directory(
                    directory_stat,
                    final_parent=index == len(self._directory_fds) - 1,
                ):
                    raise OSError("directory became unsafe")
                observed = _directory_identity(directory_stat)
                if observed != self._directory_identities[index]:
                    raise OSError("directory descriptor changed")
                if index > 0:
                    parent_fd = self._directory_fds[index - 1]
                    component = self._directory_components[index]
                    mapped = os.stat(component, dir_fd=parent_fd, follow_symlinks=False)
                    if (
                        not _safe_directory(
                            mapped,
                            final_parent=index == len(self._directory_fds) - 1,
                        )
                        or _directory_identity(mapped) != observed
                    ):
                        raise OSError("directory mapping changed")
            observed_file = _file_metadata(os.fstat(self.fd))
            mapped_file = _file_metadata(
                os.stat(
                    self._path.rsplit("/", 1)[1],
                    dir_fd=self._directory_fds[-1],
                    follow_symlinks=False,
                )
            )
            if observed_file != self.baseline or mapped_file != self.baseline:
                raise OSError("file metadata or mapping changed")
            if not _owner_confined_regular_file(observed_file):
                raise OSError("file is no longer owner-confined")
        except OSError as exc:
            raise ReleaseVerificationError(
                "input_changed", f"{self._label} changed while it was being verified"
            ) from exc

    def _digest_pass(self) -> FileObservation:
        try:
            os.lseek(self.fd, 0, os.SEEK_SET)
            digest = hashlib.sha256()
            length = 0
            while True:
                chunk = os.read(self.fd, READ_CHUNK_BYTES)
                if not chunk:
                    break
                digest.update(chunk)
                length += len(chunk)
            return FileObservation(digest.hexdigest(), length)
        except OSError as exc:
            raise ReleaseVerificationError(
                "input_read", f"{self._label} could not be read safely"
            ) from exc

    def digest(
        self,
        *,
        max_bytes: int,
        expected_sha256: str | None = None,
        expected_byte_length: int | None = None,
    ) -> FileObservation:
        baseline = self.baseline
        if baseline.size <= 0 or baseline.size > max_bytes:
            raise ReleaseVerificationError(
                "size_limit", f"{self._label} exceeds its accepted size boundary"
            )
        if expected_byte_length is not None and baseline.size != expected_byte_length:
            raise ReleaseVerificationError(
                "length_mismatch", f"{self._label} byte length does not match the manifest"
            )
        first = self._digest_pass()
        self._revalidate()
        second = self._digest_pass()
        self._revalidate()
        if first != second or first.byte_length != baseline.size:
            raise ReleaseVerificationError(
                "input_changed", f"{self._label} bytes changed while being verified"
            )
        if expected_sha256 is not None and first.sha256 != expected_sha256:
            raise ReleaseVerificationError(
                "digest_mismatch", f"{self._label} digest does not match the manifest"
            )
        return first

    def read_bytes(self, *, max_bytes: int) -> tuple[bytes, FileObservation]:
        observation = self.digest(max_bytes=max_bytes)
        try:
            os.lseek(self.fd, 0, os.SEEK_SET)
            chunks: list[bytes] = []
            remaining = observation.byte_length
            while remaining:
                chunk = os.read(self.fd, min(READ_CHUNK_BYTES, remaining))
                if not chunk:
                    raise OSError("unexpected end of file")
                chunks.append(chunk)
                remaining -= len(chunk)
            value = b"".join(chunks)
        except OSError as exc:
            raise ReleaseVerificationError(
                "input_read", f"{self._label} could not be read safely"
            ) from exc
        self._revalidate()
        if _sha256(value) != observation.sha256:
            raise ReleaseVerificationError(
                "input_changed", f"{self._label} bytes changed while being verified"
            )
        return value, observation

    def close(self) -> None:
        if self._file_fd >= 0:
            try:
                os.close(self._file_fd)
            except OSError:
                pass
            self._file_fd = -1
        while self._directory_fds:
            descriptor = self._directory_fds.pop()
            try:
                os.close(descriptor)
            except OSError:
                pass
        self._directory_components.clear()
        self._directory_identities.clear()
        self._baseline = None

    def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> None:
        self.close()


def _reject_constant(value: str) -> NoReturn:
    del value
    raise _RejectedJSONConstant("non-finite JSON number")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJSONKey("duplicate JSON key")
        result[key] = value
    return result


def _parse_json_bytes(
    value: bytes,
    *,
    label: str,
    require_canonical: bool,
) -> object:
    try:
        text = value.decode("ascii")
        parsed = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        _DuplicateJSONKey,
        _RejectedJSONConstant,
        ValueError,
        RecursionError,
    ) as exc:
        raise ReleaseVerificationError(
            "invalid_json", f"{_safe_label(label)} is not accepted JSON"
        ) from exc
    if require_canonical and value != _canonical_json(parsed) + b"\n":
        raise ReleaseVerificationError(
            "noncanonical_json", f"{_safe_label(label)} is not canonical JSON"
        )
    return parsed


def load_canonical_json(
    file_set: HardenedFileSet,
    path: str,
    *,
    label: str,
    max_bytes: int = MAX_CANONICAL_DOCUMENT_BYTES,
) -> object:
    """Load one canonical JSON file through a pinned, revalidated descriptor chain."""

    with file_set.open(path, label=label) as source:
        value, _ = source.read_bytes(max_bytes=max_bytes)
    return _parse_json_bytes(value, label=label, require_canonical=True)


def load_canonical_model(
    file_set: HardenedFileSet,
    path: str,
    *,
    label: str,
    model: type[_VerifierModel] | type[LaunchAuthorizationBundle],
) -> _VerifierModel | LaunchAuthorizationBundle:
    parsed = load_canonical_json(file_set, path, label=label)
    try:
        return model.model_validate(parsed)
    except ValidationError as exc:
        raise ReleaseVerificationError(
            "invalid_document", f"{_safe_label(label)} failed contract validation"
        ) from exc


def build_release_revocation_list(document: Mapping[str, object]) -> ReleaseRevocationList:
    if "digest_sha256" in document:
        raise ReleaseVerificationError(
            "unexpected_digest", "unsigned revocation list unexpectedly contains a digest"
        )
    unsigned = dict(document)
    try:
        return ReleaseRevocationList.model_validate(
            {**unsigned, "digest_sha256": _document_digest(unsigned)}
        )
    except ValidationError as exc:
        raise ReleaseVerificationError(
            "invalid_document", "revocation list failed contract validation"
        ) from exc


def release_revocation_list_bytes(value: ReleaseRevocationList) -> bytes:
    return _canonical_json(value.model_dump(mode="json", by_alias=True)) + b"\n"


def launch_authorization_report_bytes(value: LaunchAuthorizationReport) -> bytes:
    return _canonical_json(value.model_dump(mode="json", by_alias=True)) + b"\n"


def authorization_signature_message(
    *,
    bundle_id: str,
    release_manifest_digest_sha256: str,
    trust_policy_digest_sha256: str,
    payload_digest_sha256: str,
    signer_key_id: str,
    issued_at_epoch: int,
    expires_at_epoch: int,
    target_network: Literal["finney"] = "finney",
    netuid: Literal[24] = 24,
) -> bytes:
    """Return the exact domain-separated bytes an approved signer must sign."""

    for field_name, value in (
        ("release manifest", release_manifest_digest_sha256),
        ("trust policy", trust_policy_digest_sha256),
        ("authorization payload", payload_digest_sha256),
    ):
        if not _valid_digest(value):
            raise ReleaseVerificationError(
                "invalid_digest", f"{field_name} digest is not canonical SHA-256"
            )
    if not bundle_id or not signer_key_id or issued_at_epoch >= expires_at_epoch:
        raise ReleaseVerificationError("invalid_signature_scope", "signature scope is incomplete")
    statement = {
        "algorithm": SIGNATURE_ALGORITHM,
        "bundle_id": bundle_id,
        "expires_at_epoch": expires_at_epoch,
        "issued_at_epoch": issued_at_epoch,
        "netuid": netuid,
        "payload_digest_sha256": payload_digest_sha256,
        "purpose": SIGNATURE_PURPOSE,
        "release_manifest_digest_sha256": release_manifest_digest_sha256,
        "signer_key_id": signer_key_id,
        "target_network": target_network,
        "trust_policy_digest_sha256": trust_policy_digest_sha256,
    }
    return SIGNATURE_DOMAIN_BYTES + _canonical_json(statement)


def _signature_message(
    bundle: LaunchAuthorizationBundle,
    envelope: OfflineSignatureEnvelope,
) -> bytes:
    return authorization_signature_message(
        bundle_id=bundle.bundle_id,
        release_manifest_digest_sha256=bundle.release_manifest.digest_sha256,
        trust_policy_digest_sha256=bundle.trust_policy.digest_sha256,
        payload_digest_sha256=bundle.authorization_payload_digest_sha256,
        signer_key_id=envelope.signer_key_id,
        issued_at_epoch=envelope.issued_at_epoch,
        expires_at_epoch=envelope.expires_at_epoch,
        target_network=bundle.release_manifest.target_network,
        netuid=bundle.release_manifest.netuid,
    )


def _decode_base64(value: str, *, label: str, expected_length: int) -> bytes:
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ReleaseVerificationError(
            "invalid_encoding", f"{_safe_label(label)} encoding is invalid"
        ) from exc
    if len(decoded) != expected_length or base64.b64encode(decoded).decode("ascii") != value:
        raise ReleaseVerificationError(
            "invalid_encoding", f"{_safe_label(label)} encoding is invalid"
        )
    return decoded


def _decode_release_public_key(value: str) -> bytes:
    try:
        return decode_ed25519_public_key_base64(value)
    except Ed25519PublicKeyValidationError as exc:
        raise ReleaseVerificationError(
            "invalid_public_key", "authorization public key is invalid"
        ) from exc


def verify_bundle_signatures(
    bundle: LaunchAuthorizationBundle,
    revocations: ReleaseRevocationList,
    *,
    approved_trust_policy_digest_sha256: str,
    approved_revocation_list_digest_sha256: str,
    evaluated_at_epoch: int,
) -> list[VerifiedReleaseSignature]:
    """Verify trust anchors, validity, revocation, threshold, roles, and Ed25519 bytes."""

    if not _valid_digest(approved_trust_policy_digest_sha256) or not _valid_digest(
        approved_revocation_list_digest_sha256
    ):
        raise ReleaseVerificationError("invalid_trust_anchor", "approved digest is invalid")
    if bundle.trust_policy.digest_sha256 != approved_trust_policy_digest_sha256:
        raise ReleaseVerificationError(
            "unapproved_policy", "bundle trust policy is not the locally approved policy"
        )
    if revocations.digest_sha256 != approved_revocation_list_digest_sha256:
        raise ReleaseVerificationError(
            "unapproved_revocations", "revocation list is not the locally approved list"
        )
    if revocations.policy_digest_sha256 != bundle.trust_policy.digest_sha256:
        raise ReleaseVerificationError(
            "revocation_policy_mismatch", "revocation list is bound to another trust policy"
        )
    manifest = bundle.release_manifest
    policy = bundle.trust_policy
    trusted_public_keys = {
        key.key_id: _decode_release_public_key(key.public_key_base64) for key in policy.trusted_keys
    }
    if not bundle.issued_at_epoch <= evaluated_at_epoch < bundle.expires_at_epoch:
        raise ReleaseVerificationError(
            "expired_bundle", "authorization bundle is not valid at the evaluation epoch"
        )
    if not manifest.created_at_epoch <= evaluated_at_epoch < manifest.expires_at_epoch:
        raise ReleaseVerificationError(
            "expired_release", "release manifest is not valid at the evaluation epoch"
        )
    if not policy.valid_from_epoch <= evaluated_at_epoch < policy.valid_until_epoch:
        raise ReleaseVerificationError(
            "expired_policy", "trust policy is not valid at the evaluation epoch"
        )
    if not revocations.issued_at_epoch <= evaluated_at_epoch < revocations.expires_at_epoch:
        raise ReleaseVerificationError(
            "stale_revocations", "revocation list is not valid at the evaluation epoch"
        )
    revoked_at = {item.key_id: item.revoked_at_epoch for item in revocations.revoked_keys}
    trusted_keys = {key.key_id: key for key in policy.trusted_keys}
    verified: list[VerifiedReleaseSignature] = []
    for envelope in bundle.signatures:
        key = trusted_keys.get(envelope.signer_key_id)
        if (
            key is None
            or envelope.algorithm != SIGNATURE_ALGORITHM
            or key.algorithm != SIGNATURE_ALGORITHM
        ):
            raise ReleaseVerificationError(
                "untrusted_signer", "signature uses an untrusted key or algorithm"
            )
        if not envelope.issued_at_epoch <= evaluated_at_epoch < envelope.expires_at_epoch:
            raise ReleaseVerificationError(
                "expired_signature", "signature is not valid at the evaluation epoch"
            )
        revocation_epoch = revoked_at.get(envelope.signer_key_id)
        if revocation_epoch is not None and revocation_epoch <= evaluated_at_epoch:
            raise ReleaseVerificationError(
                "revoked_signer", "authorization contains a revoked signer"
            )
        public_bytes = trusted_public_keys[key.key_id]
        signature_bytes = _decode_base64(
            envelope.signature_base64,
            label="signature",
            expected_length=64,
        )
        try:
            Ed25519PublicKey.from_public_bytes(public_bytes).verify(
                signature_bytes,
                _signature_message(bundle, envelope),
            )
        except (InvalidSignature, ValueError) as exc:
            raise ReleaseVerificationError(
                "invalid_signature", "authorization signature verification failed"
            ) from exc
        verified.append(
            VerifiedReleaseSignature(
                signer_key_id=envelope.signer_key_id,
                algorithm="ed25519",
                roles=sorted(key.roles),
                signature_sha256=_sha256(signature_bytes),
                verification_state="verified",
            )
        )
    verified.sort(key=lambda item: item.signer_key_id)
    if len(verified) < policy.threshold:
        raise ReleaseVerificationError(
            "threshold_not_met", "verified signature threshold was not met"
        )
    covered_roles = {role for item in verified for role in item.roles}
    if not set(policy.required_roles) <= covered_roles:
        raise ReleaseVerificationError(
            "roles_not_met", "verified signatures do not cover every required role"
        )
    return verified


def _direct_observation(
    file_set: HardenedFileSet,
    path: str,
    *,
    label: str,
    expected_sha256: str,
    expected_byte_length: int,
    max_bytes: int = MAX_RELEASE_ARTIFACT_BYTES,
) -> FileObservation:
    with file_set.open(path, label=label) as source:
        return source.digest(
            max_bytes=max_bytes,
            expected_sha256=expected_sha256,
            expected_byte_length=expected_byte_length,
        )


def _paired_input(
    file_set: HardenedFileSet,
    *,
    artifact_root: str,
    recomputed_root: str,
    input_id: str,
    category: InputCategory,
    relative_path: str,
    expected_sha256: str,
    expected_byte_length: int,
    bound_content_sha256: str | None = None,
) -> VerifiedLocalInput:
    primary = _direct_observation(
        file_set,
        _rooted_path(artifact_root, relative_path, label="artifact_root"),
        label=f"candidate_{input_id}",
        expected_sha256=expected_sha256,
        expected_byte_length=expected_byte_length,
    )
    recomputed = _direct_observation(
        file_set,
        _rooted_path(recomputed_root, relative_path, label="recomputed_root"),
        label=f"recomputed_{input_id}",
        expected_sha256=expected_sha256,
        expected_byte_length=expected_byte_length,
    )
    return VerifiedLocalInput(
        input_id=input_id,
        category=category,
        relative_path=relative_path,
        expected_sha256=expected_sha256,
        observed_sha256=primary.sha256,
        expected_byte_length=expected_byte_length,
        observed_byte_length=primary.byte_length,
        recomputed_sha256=recomputed.sha256,
        recomputed_byte_length=recomputed.byte_length,
        bound_content_sha256=bound_content_sha256,
        verification_state="verified",
    )


def _read_tar_json_member(
    archive: tarfile.TarFile,
    member: tarfile.TarInfo,
    *,
    label: str,
) -> tuple[bytes, object]:
    if member.size <= 0 or member.size > MAX_OCI_METADATA_BYTES:
        raise ReleaseVerificationError(
            "oci_metadata_size", f"{_safe_label(label)} OCI metadata exceeds its size boundary"
        )
    extracted = archive.extractfile(member)
    if extracted is None:
        raise ReleaseVerificationError(
            "invalid_oci", f"{_safe_label(label)} OCI metadata is absent"
        )
    value = extracted.read(MAX_OCI_METADATA_BYTES + 1)
    if len(value) != member.size:
        raise ReleaseVerificationError(
            "invalid_oci", f"{_safe_label(label)} OCI metadata is truncated"
        )
    return value, _parse_json_bytes(value, label=label, require_canonical=False)


def _hash_tar_member(
    archive: tarfile.TarFile,
    member: tarfile.TarInfo,
    *,
    label: str,
) -> str:
    if member.size < 0 or member.size > MAX_RELEASE_ARTIFACT_BYTES:
        raise ReleaseVerificationError(
            "invalid_oci", f"{_safe_label(label)} OCI blob exceeds its size boundary"
        )
    extracted = archive.extractfile(member)
    if extracted is None:
        raise ReleaseVerificationError("invalid_oci", f"{_safe_label(label)} OCI blob is absent")
    content_digest = hashlib.sha256()
    remaining = member.size
    while remaining:
        chunk = extracted.read(min(READ_CHUNK_BYTES, remaining))
        if not chunk:
            raise ReleaseVerificationError(
                "invalid_oci", f"{_safe_label(label)} OCI blob is truncated"
            )
        content_digest.update(chunk)
        remaining -= len(chunk)
    if extracted.read(1):
        raise ReleaseVerificationError(
            "invalid_oci", f"{_safe_label(label)} OCI blob exceeds its declared size"
        )
    return content_digest.hexdigest()


def _oci_digest_path(value: str) -> str:
    if not value.startswith("sha256:") or not _valid_digest(value[7:]):
        raise ReleaseVerificationError("invalid_oci", "OCI descriptor lacks an immutable digest")
    return f"blobs/sha256/{value[7:]}"


def _verify_oci_archive(
    file_set: HardenedFileSet,
    path: str,
    *,
    label: str,
    image: OCIImage,
) -> FileObservation:
    with file_set.open(path, label=label) as source:
        observation = source.digest(
            max_bytes=MAX_RELEASE_ARTIFACT_BYTES,
            expected_sha256=image.content_sha256,
            expected_byte_length=image.byte_length,
        )
        expected_manifest_path = _oci_digest_path(image.manifest_digest)
        expected_config_path = _oci_digest_path(image.config_digest)
        selected: dict[str, tuple[bytes, object]] = {}
        names: set[str] = set()
        blob_sizes: dict[str, int] = {}
        try:
            os.lseek(source.fd, 0, os.SEEK_SET)
            duplicate_fd = os.dup(source.fd)
            with os.fdopen(duplicate_fd, "rb", closefd=True) as stream:
                with tarfile.open(fileobj=stream, mode="r:") as archive:
                    member_count = 0
                    for member in archive:
                        member_count += 1
                        if member_count > MAX_OCI_MEMBERS:
                            raise ReleaseVerificationError(
                                "invalid_oci",
                                f"{_safe_label(label)} OCI archive has too many entries",
                            )
                        raw_name = member.name
                        name = (
                            raw_name[:-1] if member.isdir() and raw_name.endswith("/") else raw_name
                        )
                        if (
                            not name
                            or name.startswith("/")
                            or name != os.path.normpath(name)
                            or any(part in {"", ".", ".."} for part in name.split("/"))
                            or name in names
                        ):
                            raise ReleaseVerificationError(
                                "invalid_oci",
                                f"{_safe_label(label)} OCI archive has an unsafe entry",
                            )
                        names.add(name)
                        if not member.isfile() and not member.isdir():
                            raise ReleaseVerificationError(
                                "invalid_oci",
                                f"{_safe_label(label)} OCI archive has a linked entry",
                            )
                        if member.isdir():
                            if name not in {"blobs", "blobs/sha256"}:
                                raise ReleaseVerificationError(
                                    "invalid_oci",
                                    f"{_safe_label(label)} OCI archive has an unexpected directory",
                                )
                            continue
                        if name in {"index.json", "oci-layout"}:
                            selected[name] = _read_tar_json_member(archive, member, label=label)
                            continue
                        if (
                            not name.startswith("blobs/sha256/")
                            or len(name) != len("blobs/sha256/") + 64
                            or not _valid_digest(name.rsplit("/", 1)[1])
                        ):
                            raise ReleaseVerificationError(
                                "invalid_oci",
                                f"{_safe_label(label)} OCI archive has an unexpected file",
                            )
                        blob_sizes[name] = member.size
                        if name in {expected_manifest_path, expected_config_path}:
                            selected[name] = _read_tar_json_member(archive, member, label=label)
                        elif (
                            _hash_tar_member(archive, member, label=label) != name.rsplit("/", 1)[1]
                        ):
                            raise ReleaseVerificationError(
                                "invalid_oci",
                                f"{_safe_label(label)} OCI blob digest is invalid",
                            )
        except (OSError, tarfile.TarError) as exc:
            raise ReleaseVerificationError(
                "invalid_oci", f"{_safe_label(label)} is not a valid uncompressed OCI archive"
            ) from exc
        source._revalidate()
    required = {"index.json", "oci-layout", expected_manifest_path, expected_config_path}
    if set(selected) != required:
        raise ReleaseVerificationError(
            "invalid_oci", f"{_safe_label(label)} OCI archive is incomplete or ambiguous"
        )
    layout = selected["oci-layout"][1]
    if layout != {"imageLayoutVersion": "1.0.0"}:
        raise ReleaseVerificationError(
            "invalid_oci", f"{_safe_label(label)} OCI layout is unsupported"
        )
    index = selected["index.json"][1]
    if (
        not isinstance(index, dict)
        or index.get("schemaVersion") != 2
        or not isinstance(index.get("manifests"), list)
        or len(index["manifests"]) != 1
    ):
        raise ReleaseVerificationError("invalid_oci", f"{_safe_label(label)} OCI index is invalid")
    os_name, architecture = image.platform.split("/", 1)
    matches: list[dict[str, object]] = []
    for descriptor in index["manifests"]:
        if not isinstance(descriptor, dict):
            raise ReleaseVerificationError(
                "invalid_oci", f"{_safe_label(label)} OCI index is invalid"
            )
        digest = descriptor.get("digest")
        if not isinstance(digest, str):
            raise ReleaseVerificationError(
                "mutable_oci_claim", f"{_safe_label(label)} OCI index has a mutable-tag-only claim"
            )
        _oci_digest_path(digest)
        if _oci_digest_path(digest) not in names:
            raise ReleaseVerificationError(
                "invalid_oci", f"{_safe_label(label)} OCI index manifest is missing"
            )
        platform = descriptor.get("platform")
        if digest == image.manifest_digest and platform == {
            "architecture": architecture,
            "os": os_name,
        }:
            matches.append(descriptor)
    if len(matches) != 1:
        raise ReleaseVerificationError(
            "invalid_oci", f"{_safe_label(label)} OCI manifest selection is incomplete or ambiguous"
        )
    manifest_bytes, manifest = selected[expected_manifest_path]
    config_bytes, config = selected[expected_config_path]
    if (
        _sha256(manifest_bytes) != image.manifest_digest[7:]
        or _sha256(config_bytes) != image.config_digest[7:]
    ):
        raise ReleaseVerificationError(
            "invalid_oci", f"{_safe_label(label)} OCI manifest or config digest is invalid"
        )
    if (
        not isinstance(manifest, dict)
        or manifest.get("schemaVersion") != 2
        or not isinstance(config, dict)
        or config.get("os") != os_name
        or config.get("architecture") != architecture
        or matches[0].get("size") != len(manifest_bytes)
    ):
        raise ReleaseVerificationError(
            "invalid_oci", f"{_safe_label(label)} OCI metadata is invalid"
        )
    config_descriptor = manifest.get("config")
    layers = manifest.get("layers")
    if (
        not isinstance(config_descriptor, dict)
        or config_descriptor.get("digest") != image.config_digest
        or config_descriptor.get("size") != len(config_bytes)
        or not isinstance(layers, list)
    ):
        raise ReleaseVerificationError(
            "invalid_oci", f"{_safe_label(label)} OCI manifest is invalid"
        )
    referenced_blobs = {expected_manifest_path, expected_config_path}
    for layer in layers:
        if not isinstance(layer, dict) or not isinstance(layer.get("digest"), str):
            raise ReleaseVerificationError(
                "invalid_oci", f"{_safe_label(label)} OCI layer is invalid"
            )
        layer_path = _oci_digest_path(cast(str, layer["digest"]))
        if layer_path not in names or layer.get("size") != blob_sizes.get(layer_path):
            raise ReleaseVerificationError(
                "invalid_oci", f"{_safe_label(label)} OCI layer is missing"
            )
        referenced_blobs.add(layer_path)
    if set(blob_sizes) != referenced_blobs:
        raise ReleaseVerificationError(
            "invalid_oci", f"{_safe_label(label)} OCI blob inventory is ambiguous"
        )
    return observation


def _canonical_artifact_json(
    file_set: HardenedFileSet,
    path: str,
    *,
    label: str,
    expected_sha256: str,
    expected_byte_length: int | None,
    max_bytes: int,
) -> tuple[object, FileObservation]:
    with file_set.open(path, label=label) as source:
        value, observation = source.read_bytes(max_bytes=max_bytes)
    if observation.sha256 != expected_sha256:
        raise ReleaseVerificationError(
            "digest_mismatch", f"{_safe_label(label)} digest does not match the manifest"
        )
    if expected_byte_length is not None and observation.byte_length != expected_byte_length:
        raise ReleaseVerificationError(
            "length_mismatch", f"{_safe_label(label)} byte length does not match the manifest"
        )
    return _parse_json_bytes(value, label=label, require_canonical=True), observation


def _artifact_digest_map(manifest: ProductionReleaseManifest) -> dict[str, str]:
    result: dict[str, str] = {}
    for collection in (
        manifest.python_distributions,
        manifest.go_binaries,
        manifest.container_images,
        manifest.workload_artifacts,
        manifest.release_files,
    ):
        for item in collection:
            result[item.artifact_id] = item.content_sha256
    return result


def _spdx_subjects(document: object, *, label: str) -> dict[str, str]:
    if not isinstance(document, dict) or document.get("spdxVersion") != "SPDX-2.3":
        raise ReleaseVerificationError("invalid_sbom", f"{_safe_label(label)} is not SPDX 2.3 JSON")
    result: dict[str, str] = {}
    seen_names: set[str] = set()
    for collection_name in ("files", "packages"):
        collection = document.get(collection_name, [])
        if not isinstance(collection, list):
            raise ReleaseVerificationError(
                "invalid_sbom", f"{_safe_label(label)} SPDX subjects are invalid"
            )
        for subject in collection:
            if not isinstance(subject, dict) or not isinstance(subject.get("name"), str):
                raise ReleaseVerificationError(
                    "invalid_sbom", f"{_safe_label(label)} SPDX subject is invalid"
                )
            checksums = subject.get("checksums")
            name = subject["name"]
            if name in seen_names:
                raise ReleaseVerificationError(
                    "ambiguous_sbom", f"{_safe_label(label)} has duplicate SPDX subjects"
                )
            seen_names.add(name)
            if not isinstance(checksums, list):
                continue
            sha_values = [
                checksum.get("checksumValue")
                for checksum in checksums
                if isinstance(checksum, dict) and checksum.get("algorithm") == "SHA256"
            ]
            if len(sha_values) == 1 and isinstance(sha_values[0], str):
                result[name] = sha_values[0]
    return result


def _slsa_subjects(
    document: object,
    *,
    label: str,
    manifest: ProductionReleaseManifest,
) -> dict[str, str]:
    if (
        not isinstance(document, dict)
        or document.get("_type") != "https://in-toto.io/Statement/v1"
        or document.get("predicateType") != "https://slsa.dev/provenance/v1"
        or not isinstance(document.get("subject"), list)
        or not isinstance(document.get("predicate"), dict)
    ):
        raise ReleaseVerificationError(
            "invalid_provenance", f"{_safe_label(label)} is not SLSA provenance v1"
        )
    predicate = cast(dict[str, object], document["predicate"])
    build_definition = predicate.get("buildDefinition")
    if not isinstance(build_definition, dict):
        raise ReleaseVerificationError(
            "source_guard", f"{_safe_label(label)} provenance lacks a pinned source definition"
        )
    external = build_definition.get("externalParameters")
    required_source = {
        "repository": manifest.source.repository,
        "commit_oid": manifest.source.commit_oid,
        "tree_oid": manifest.source.tree_oid,
        "source_archive_sha256": manifest.source.source_archive_sha256,
    }
    if external != required_source:
        raise ReleaseVerificationError(
            "source_guard", f"{_safe_label(label)} provenance source binding is invalid"
        )
    result: dict[str, str] = {}
    for subject in cast(list[object], document["subject"]):
        if not isinstance(subject, dict) or not isinstance(subject.get("name"), str):
            raise ReleaseVerificationError(
                "invalid_provenance", f"{_safe_label(label)} provenance subject is invalid"
            )
        digest = subject.get("digest")
        if (
            not isinstance(digest, dict)
            or set(digest) != {"sha256"}
            or not isinstance(digest.get("sha256"), str)
        ):
            raise ReleaseVerificationError(
                "mutable_provenance_claim",
                f"{_safe_label(label)} provenance subject lacks an immutable SHA-256 digest",
            )
        name = cast(str, subject["name"])
        if name in result:
            raise ReleaseVerificationError(
                "ambiguous_provenance", f"{_safe_label(label)} has duplicate provenance subjects"
            )
        result[name] = cast(str, digest["sha256"])
    return result


def _verify_evidence_document(
    file_set: HardenedFileSet,
    *,
    root: str,
    root_label: str,
    label: str,
    reference: SupplyChainReference,
    manifest: ProductionReleaseManifest,
    expected_subjects: Mapping[str, str],
) -> FileObservation:
    parsed, observation = _canonical_artifact_json(
        file_set,
        _rooted_path(root, reference.path, label=root_label),
        label=label,
        expected_sha256=reference.content_sha256,
        expected_byte_length=reference.byte_length,
        max_bytes=MAX_EVIDENCE_DOCUMENT_BYTES,
    )
    if reference.format == "spdx_json":
        actual_subjects = _spdx_subjects(parsed, label=label)
    else:
        actual_subjects = _slsa_subjects(parsed, label=label, manifest=manifest)
    declared_ids = set(reference.subject_artifact_ids)
    expected = {key: expected_subjects[key] for key in declared_ids}
    if actual_subjects != expected:
        raise ReleaseVerificationError(
            "evidence_subject_mismatch",
            f"{_safe_label(label)} subject coverage or digest binding is invalid",
        )
    return observation


def _verify_workload_descriptor(
    file_set: HardenedFileSet,
    *,
    root: str,
    root_label: str,
    label: str,
    manifest: ProductionReleaseManifest,
    artifact_index: int,
) -> FileObservation:
    artifact = manifest.workload_artifacts[artifact_index]
    parsed, observation = _canonical_artifact_json(
        file_set,
        _rooted_path(root, artifact.descriptor_path, label=root_label),
        label=label,
        expected_sha256=artifact.descriptor_sha256,
        expected_byte_length=None,
        max_bytes=MAX_WORKLOAD_DESCRIPTOR_BYTES,
    )
    try:
        descriptor = WorkloadExportDescriptor.model_validate(parsed)
    except ValidationError as exc:
        raise ReleaseVerificationError(
            "invalid_workload_descriptor",
            f"{_safe_label(label)} failed workload-descriptor validation",
        ) from exc
    containers = {item.artifact_id: item for item in manifest.container_images}
    container = containers.get(artifact.container_artifact_id)
    if container is None or (
        descriptor.artifact_id != artifact.artifact_id
        or descriptor.workload_kind != artifact.workload_kind
        or descriptor.container_artifact_id != artifact.container_artifact_id
        or descriptor.container_manifest_digest != container.manifest_digest
        or descriptor.content_sha256 != artifact.content_sha256
        or descriptor.byte_length != artifact.byte_length
        or descriptor.mutable_tag is not None
    ):
        raise ReleaseVerificationError(
            "workload_binding", f"{_safe_label(label)} workload binding is invalid"
        )
    return observation


def verify_local_release_artifacts(
    file_set: HardenedFileSet,
    manifest: ProductionReleaseManifest,
    *,
    source_root: str,
    source_archive: str,
    artifact_root: str,
    recomputed_artifact_root: str,
) -> list[VerifiedLocalInput]:
    """Recompute the complete local byte inventory twice and return canonical evidence."""

    _normalized_absolute_path(source_root, label="source_root")
    _normalized_absolute_path(artifact_root, label="artifact_root")
    _normalized_absolute_path(recomputed_artifact_root, label="recomputed_root")
    source_archive_path = _normalized_absolute_path(source_archive, label="source_archive")
    verified: list[VerifiedLocalInput] = []
    with file_set.open(source_archive_path, label="source_archive") as source:
        source_observation = source.digest(
            max_bytes=MAX_SOURCE_ARCHIVE_BYTES,
            expected_sha256=manifest.source.source_archive_sha256,
        )
    verified.append(
        VerifiedLocalInput(
            input_id="source_archive",
            category="source_archive",
            relative_path="source/source-archive.tar",
            expected_sha256=manifest.source.source_archive_sha256,
            observed_sha256=source_observation.sha256,
            observed_byte_length=source_observation.byte_length,
            verification_state="verified",
        )
    )
    for dependency in manifest.dependency_inputs:
        input_id = _report_entry_id("dependency_input", dependency.dependency_id)
        observation = _direct_observation(
            file_set,
            _rooted_path(source_root, dependency.path, label="source_root"),
            label=input_id,
            expected_sha256=dependency.content_sha256,
            expected_byte_length=dependency.byte_length,
        )
        verified.append(
            VerifiedLocalInput(
                input_id=input_id,
                category="dependency_input",
                relative_path=dependency.path,
                expected_sha256=dependency.content_sha256,
                observed_sha256=observation.sha256,
                expected_byte_length=dependency.byte_length,
                observed_byte_length=observation.byte_length,
                verification_state="verified",
            )
        )
    for distribution in manifest.python_distributions:
        verified.append(
            _paired_input(
                file_set,
                artifact_root=artifact_root,
                recomputed_root=recomputed_artifact_root,
                input_id=_report_entry_id("python_distribution", distribution.artifact_id),
                category="python_distribution",
                relative_path=distribution.path,
                expected_sha256=distribution.content_sha256,
                expected_byte_length=distribution.byte_length,
            )
        )
    for binary in manifest.go_binaries:
        verified.append(
            _paired_input(
                file_set,
                artifact_root=artifact_root,
                recomputed_root=recomputed_artifact_root,
                input_id=_report_entry_id("go_binary", binary.artifact_id),
                category="go_binary",
                relative_path=binary.path,
                expected_sha256=binary.content_sha256,
                expected_byte_length=binary.byte_length,
            )
        )
    for image in manifest.container_images:
        input_id = _report_entry_id("oci_archive", image.artifact_id)
        primary = _verify_oci_archive(
            file_set,
            _rooted_path(artifact_root, image.archive_path, label="artifact_root"),
            label=f"candidate_{input_id}",
            image=image,
        )
        recomputed = _verify_oci_archive(
            file_set,
            _rooted_path(
                recomputed_artifact_root,
                image.archive_path,
                label="recomputed_root",
            ),
            label=f"recomputed_{input_id}",
            image=image,
        )
        verified.append(
            VerifiedLocalInput(
                input_id=input_id,
                category="oci_archive",
                relative_path=image.archive_path,
                expected_sha256=image.content_sha256,
                observed_sha256=primary.sha256,
                expected_byte_length=image.byte_length,
                observed_byte_length=primary.byte_length,
                recomputed_sha256=recomputed.sha256,
                recomputed_byte_length=recomputed.byte_length,
                bound_content_sha256=image.manifest_digest[7:],
                verification_state="verified",
            )
        )
    for index, workload in enumerate(manifest.workload_artifacts):
        input_id = _report_entry_id("workload_descriptor", workload.artifact_id)
        primary = _verify_workload_descriptor(
            file_set,
            root=artifact_root,
            root_label="artifact_root",
            label=f"candidate_{input_id}",
            manifest=manifest,
            artifact_index=index,
        )
        recomputed = _verify_workload_descriptor(
            file_set,
            root=recomputed_artifact_root,
            root_label="recomputed_root",
            label=f"recomputed_{input_id}",
            manifest=manifest,
            artifact_index=index,
        )
        verified.append(
            VerifiedLocalInput(
                input_id=input_id,
                category="workload_descriptor",
                relative_path=workload.descriptor_path,
                expected_sha256=workload.descriptor_sha256,
                observed_sha256=primary.sha256,
                observed_byte_length=primary.byte_length,
                recomputed_sha256=recomputed.sha256,
                recomputed_byte_length=recomputed.byte_length,
                bound_content_sha256=workload.content_sha256,
                verification_state="verified",
            )
        )
    for release_file in manifest.release_files:
        verified.append(
            _paired_input(
                file_set,
                artifact_root=artifact_root,
                recomputed_root=recomputed_artifact_root,
                input_id=_report_entry_id("release_file", release_file.artifact_id),
                category="release_file",
                relative_path=release_file.path,
                expected_sha256=release_file.content_sha256,
                expected_byte_length=release_file.byte_length,
            )
        )
    subject_digests = _artifact_digest_map(manifest)
    for category, references in (
        ("sbom", manifest.sbom_references),
        ("provenance", manifest.provenance_references),
    ):
        input_category = cast(InputCategory, category)
        for reference in references:
            input_id = _report_entry_id(input_category, reference.reference_id)
            primary = _verify_evidence_document(
                file_set,
                root=artifact_root,
                root_label="artifact_root",
                label=f"candidate_{input_id}",
                reference=reference,
                manifest=manifest,
                expected_subjects=subject_digests,
            )
            recomputed = _verify_evidence_document(
                file_set,
                root=recomputed_artifact_root,
                root_label="recomputed_root",
                label=f"recomputed_{input_id}",
                reference=reference,
                manifest=manifest,
                expected_subjects=subject_digests,
            )
            verified.append(
                VerifiedLocalInput(
                    input_id=input_id,
                    category=input_category,
                    relative_path=reference.path,
                    expected_sha256=reference.content_sha256,
                    observed_sha256=primary.sha256,
                    expected_byte_length=reference.byte_length,
                    observed_byte_length=primary.byte_length,
                    recomputed_sha256=recomputed.sha256,
                    recomputed_byte_length=recomputed.byte_length,
                    verification_state="verified",
                )
            )
    for rollback in manifest.rollback_bytes:
        verified.append(
            _paired_input(
                file_set,
                artifact_root=artifact_root,
                recomputed_root=recomputed_artifact_root,
                input_id=_report_entry_id("rollback_bytes", rollback.artifact_id),
                category="rollback_bytes",
                relative_path=rollback.rollback_path,
                expected_sha256=rollback.rollback_sha256,
                expected_byte_length=rollback.rollback_byte_length,
                bound_content_sha256=rollback.replacement_sha256,
            )
        )
    verified.sort(key=lambda item: item.input_id)
    input_ids = [item.input_id for item in verified]
    if len(input_ids) != len(set(input_ids)):
        raise ReleaseVerificationError(
            "ambiguous_inventory", "release input identifiers are ambiguous"
        )
    return verified


def _build_report(
    bundle: LaunchAuthorizationBundle,
    revocations: ReleaseRevocationList,
    *,
    approved_trust_policy_digest_sha256: str,
    approved_revocation_list_digest_sha256: str,
    evaluated_at_epoch: int,
    verified_inputs: list[VerifiedLocalInput],
    verified_signatures: list[VerifiedReleaseSignature],
) -> LaunchAuthorizationReport:
    input_documents = [item.model_dump(mode="json") for item in verified_inputs]
    signature_documents = [item.model_dump(mode="json") for item in verified_signatures]
    unsigned: dict[str, object] = {
        "schema": LAUNCH_AUTHORIZATION_REPORT_SCHEMA,
        "schema_version": VERIFIER_SCHEMA_VERSION,
        "verifier_id": VERIFIER_ID,
        "signature_algorithm": SIGNATURE_ALGORITHM,
        "signature_purpose": SIGNATURE_PURPOSE,
        "signature_domain": SIGNATURE_DOMAIN,
        "bundle_id": bundle.bundle_id,
        "bundle_digest_sha256": bundle.digest_sha256,
        "release_manifest_digest_sha256": bundle.release_manifest.digest_sha256,
        "trust_policy_digest_sha256": bundle.trust_policy.digest_sha256,
        "approved_trust_policy_digest_sha256": approved_trust_policy_digest_sha256,
        "revocation_list_digest_sha256": revocations.digest_sha256,
        "approved_revocation_list_digest_sha256": approved_revocation_list_digest_sha256,
        "source_commit_oid": bundle.release_manifest.source.commit_oid,
        "source_tree_oid": bundle.release_manifest.source.tree_oid,
        "target_network": bundle.release_manifest.target_network,
        "netuid": bundle.release_manifest.netuid,
        "evaluated_at_epoch": evaluated_at_epoch,
        "verified_inputs": input_documents,
        "verified_input_set_digest_sha256": _document_digest(input_documents),
        "verified_signatures": signature_documents,
        "verified_signature_set_digest_sha256": _document_digest(signature_documents),
        "required_signature_threshold": bundle.trust_policy.threshold,
        "required_roles": sorted(bundle.trust_policy.required_roles),
        "artifact_verification_state": "verified",
        "build_recomputation_state": "verified",
        "signature_verification_state": "verified",
        "revocation_verification_state": "verified",
        "authorization_state": "authorized",
        "launch_authorized": True,
        "live_actions": False,
    }
    try:
        return LaunchAuthorizationReport.model_validate(
            {**unsigned, "digest_sha256": _document_digest(unsigned)}
        )
    except ValidationError as exc:
        raise ReleaseVerificationError(
            "invalid_report", "verifier could not construct a canonical report"
        ) from exc


def produce_launch_authorization_report(
    paths: VerificationPaths,
    *,
    approved_trust_policy_digest_sha256: str,
    approved_revocation_list_digest_sha256: str,
    evaluated_at_epoch: int,
    file_set: HardenedFileSet | None = None,
) -> LaunchAuthorizationReport:
    """Load all inputs, verify them offline, and return canonical authorization evidence."""

    inputs = file_set if file_set is not None else HardenedFileSet()
    bundle_value = load_canonical_model(
        inputs,
        paths.bundle,
        label="authorization_bundle",
        model=LaunchAuthorizationBundle,
    )
    revocation_value = load_canonical_model(
        inputs,
        paths.revocations,
        label="revocation_list",
        model=ReleaseRevocationList,
    )
    bundle = cast(LaunchAuthorizationBundle, bundle_value)
    revocations = cast(ReleaseRevocationList, revocation_value)
    verified_signatures = verify_bundle_signatures(
        bundle,
        revocations,
        approved_trust_policy_digest_sha256=approved_trust_policy_digest_sha256,
        approved_revocation_list_digest_sha256=approved_revocation_list_digest_sha256,
        evaluated_at_epoch=evaluated_at_epoch,
    )
    verified_inputs = verify_local_release_artifacts(
        inputs,
        bundle.release_manifest,
        source_root=paths.source_root,
        source_archive=paths.source_archive,
        artifact_root=paths.artifact_root,
        recomputed_artifact_root=paths.recomputed_artifact_root,
    )
    return _build_report(
        bundle,
        revocations,
        approved_trust_policy_digest_sha256=approved_trust_policy_digest_sha256,
        approved_revocation_list_digest_sha256=approved_revocation_list_digest_sha256,
        evaluated_at_epoch=evaluated_at_epoch,
        verified_inputs=verified_inputs,
        verified_signatures=verified_signatures,
    )


def _write_new_owner_file(path: str, value: bytes, *, label: str) -> None:
    normalized = _normalized_absolute_path(path, label=label)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    cloexec = getattr(os, "O_CLOEXEC", 0)
    if nofollow == 0 or directory == 0:
        raise ReleaseVerificationError(
            "platform_boundary", "required no-follow file-descriptor controls are unavailable"
        )
    components = normalized.split("/")[1:]
    directory_fds: list[int] = []
    directory_components: list[str] = []
    directory_identities: list[_DirectoryIdentity] = []
    output_fd = -1
    try:
        root_fd = os.open("/", os.O_RDONLY | directory | cloexec)
        root_stat = os.fstat(root_fd)
        if not _safe_directory(root_stat, final_parent=len(components) == 1):
            os.close(root_fd)
            raise OSError("unsafe output root")
        directory_fds.append(root_fd)
        directory_components.append("")
        directory_identities.append(_directory_identity(root_stat))
        for index, component in enumerate(components[:-1]):
            child_fd = os.open(
                component,
                os.O_RDONLY | directory | nofollow | cloexec,
                dir_fd=directory_fds[-1],
            )
            child_stat = os.fstat(child_fd)
            if not _safe_directory(
                child_stat,
                final_parent=index == len(components) - 2,
            ):
                os.close(child_fd)
                raise OSError("unsafe output parent")
            directory_fds.append(child_fd)
            directory_components.append(component)
            directory_identities.append(_directory_identity(child_stat))
        output_fd = os.open(
            components[-1],
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow | cloexec,
            0o600,
            dir_fd=directory_fds[-1],
        )
        offset = 0
        while offset < len(value):
            written = os.write(output_fd, value[offset:])
            if written <= 0:
                raise OSError("short write")
            offset += written
        os.fsync(output_fd)
        metadata = _file_metadata(os.fstat(output_fd))
        if not _owner_confined_regular_file(metadata) or metadata.size != len(value):
            raise OSError("unsafe output metadata")
        mapped = _file_metadata(
            os.stat(components[-1], dir_fd=directory_fds[-1], follow_symlinks=False)
        )
        if mapped != metadata:
            raise OSError("output mapping changed")
        for index, directory_fd in enumerate(directory_fds):
            current = os.fstat(directory_fd)
            if (
                not _safe_directory(
                    current,
                    final_parent=index == len(directory_fds) - 1,
                )
                or _directory_identity(current) != directory_identities[index]
            ):
                raise OSError("output directory changed")
            if index > 0:
                mapped_directory = os.stat(
                    directory_components[index],
                    dir_fd=directory_fds[index - 1],
                    follow_symlinks=False,
                )
                if _directory_identity(mapped_directory) != directory_identities[index]:
                    raise OSError("output directory mapping changed")
    except OSError as exc:
        raise ReleaseVerificationError(
            "output_failure", f"{_safe_label(label)} could not be created safely"
        ) from exc
    finally:
        if output_fd >= 0:
            try:
                os.close(output_fd)
            except OSError:
                pass
        while directory_fds:
            try:
                os.close(directory_fds.pop())
            except OSError:
                pass


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        del message
        raise ReleaseVerificationError("usage", "invalid command line")


def _parser() -> argparse.ArgumentParser:
    parser = _ArgumentParser(
        prog="misscomputer-release-verify",
        description="Offline, non-activating production release verifier.",
        allow_abbrev=False,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    def add_inputs(command: argparse.ArgumentParser) -> None:
        command.add_argument("--bundle", required=True)
        command.add_argument("--revocations", required=True)
        command.add_argument("--source-root", required=True)
        command.add_argument("--source-archive", required=True)
        command.add_argument("--artifact-root", required=True)
        command.add_argument("--recomputed-artifact-root", required=True)
        command.add_argument("--approved-policy-digest", required=True)
        command.add_argument("--approved-revocations-digest", required=True)
        command.add_argument("--evaluated-at-epoch", required=True, type=int)

    authorize = subparsers.add_parser(
        "authorize",
        help="verify all local evidence and create a new canonical report",
        allow_abbrev=False,
    )
    add_inputs(authorize)
    authorize.add_argument("--report", required=True)

    verify = subparsers.add_parser(
        "verify-report",
        help="recompute all evidence and compare an existing canonical report",
        allow_abbrev=False,
    )
    add_inputs(verify)
    verify.add_argument("--report", required=True)
    return parser


def _paths(arguments: argparse.Namespace) -> VerificationPaths:
    return VerificationPaths(
        bundle=cast(str, arguments.bundle),
        revocations=cast(str, arguments.revocations),
        source_root=cast(str, arguments.source_root),
        source_archive=cast(str, arguments.source_archive),
        artifact_root=cast(str, arguments.artifact_root),
        recomputed_artifact_root=cast(str, arguments.recomputed_artifact_root),
    )


def run_cli(argv: Sequence[str]) -> int:
    """Run the deterministic CLI and return a documented process status."""

    try:
        arguments = _parser().parse_args(list(argv))
        file_set = HardenedFileSet()
        expected_report: LaunchAuthorizationReport | None = None
        if arguments.command == "verify-report":
            loaded_report = load_canonical_model(
                file_set,
                cast(str, arguments.report),
                label="authorization_report",
                model=LaunchAuthorizationReport,
            )
            expected_report = cast(LaunchAuthorizationReport, loaded_report)
        report = produce_launch_authorization_report(
            _paths(arguments),
            approved_trust_policy_digest_sha256=cast(str, arguments.approved_policy_digest),
            approved_revocation_list_digest_sha256=cast(str, arguments.approved_revocations_digest),
            evaluated_at_epoch=cast(int, arguments.evaluated_at_epoch),
            file_set=file_set,
        )
        rendered = launch_authorization_report_bytes(report)
        if arguments.command == "authorize":
            _write_new_owner_file(
                cast(str, arguments.report),
                rendered,
                label="authorization_report",
            )
            sys.stdout.write(f"AUTHORIZED report_sha256={report.digest_sha256}\n")
        else:
            if (
                expected_report is None
                or launch_authorization_report_bytes(expected_report) != rendered
            ):
                raise ReleaseVerificationError(
                    "report_mismatch", "authorization report does not match recomputed evidence"
                )
            sys.stdout.write(f"VERIFIED report_sha256={report.digest_sha256}\n")
        return EXIT_OK
    except ReleaseVerificationError as exc:
        if exc.code == "usage":
            sys.stderr.write("ERROR usage: invalid command line\n")
            return EXIT_USAGE
        sys.stderr.write(f"REJECTED {exc.code}: {exc}\n")
        return EXIT_REJECTED
    except Exception:
        sys.stderr.write("ERROR internal: verifier failed without disclosing input data\n")
        return EXIT_INTERNAL


def main() -> None:
    raise SystemExit(run_cli(sys.argv[1:]))


if __name__ == "__main__":
    main()
