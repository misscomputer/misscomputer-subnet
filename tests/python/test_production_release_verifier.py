# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import ast
import base64
import hashlib
import io
import json
import os
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jsonschema import Draft202012Validator
from pydantic import ValidationError

import misscomputer_subnet.production_release_verifier as verifier_module
from misscomputer_subnet.production_release import (
    LAUNCH_AUTHORIZATION_BUNDLE_SCHEMA,
    OFFLINE_SIGNATURE_ENVELOPE_SCHEMA,
    PRODUCTION_RELEASE_MANIFEST_SCHEMA,
    PRODUCTION_RELEASE_SCHEMA_VERSION,
    RELEASE_TRUST_POLICY_SCHEMA,
    LaunchAuthorizationBundle,
    authorization_payload_digest,
    build_launch_authorization_bundle,
    build_production_release_manifest,
    build_release_trust_policy,
    launch_authorization_bundle_bytes,
)
from misscomputer_subnet.production_release_verifier import (
    EXIT_OK,
    EXIT_REJECTED,
    EXIT_USAGE,
    RELEASE_REVOCATION_LIST_SCHEMA,
    VERIFIER_SCHEMA_VERSION,
    HardenedFileSet,
    LaunchAuthorizationReport,
    ReleaseRevocationList,
    ReleaseVerificationError,
    VerificationPaths,
    VerifiedLocalInput,
    authorization_signature_message,
    build_release_revocation_list,
    launch_authorization_report_bytes,
    load_canonical_json,
    produce_launch_authorization_report,
    release_revocation_list_bytes,
    run_cli,
    verify_bundle_signatures,
)

ROOT = Path(__file__).resolve().parents[2]


def canonical_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
        + b"\n"
    )


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def write_owner_file(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value)
    path.chmod(0o600)


def copy_owner_file(source: Path, destination: Path) -> None:
    write_owner_file(destination, source.read_bytes())


def tar_bytes(files: dict[str, bytes]) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:") as archive:
        for name, value in sorted(files.items()):
            member = tarfile.TarInfo(name)
            member.size = len(value)
            member.mode = 0o600
            member.mtime = 0
            member.uid = 0
            member.gid = 0
            member.uname = ""
            member.gname = ""
            archive.addfile(member, io.BytesIO(value))
    return output.getvalue()


def oci_archive(image_name: str) -> tuple[bytes, str, str]:
    layer = f"{image_name}-immutable-layer".encode()
    layer_digest = digest(layer)
    config = canonical_bytes(
        {
            "architecture": "amd64",
            "config": {},
            "os": "linux",
            "rootfs": {"diff_ids": [f"sha256:{layer_digest}"], "type": "layers"},
        }
    )[:-1]
    config_digest = digest(config)
    manifest = canonical_bytes(
        {
            "config": {
                "digest": f"sha256:{config_digest}",
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "size": len(config),
            },
            "layers": [
                {
                    "digest": f"sha256:{layer_digest}",
                    "mediaType": "application/vnd.oci.image.layer.v1.tar",
                    "size": len(layer),
                }
            ],
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "schemaVersion": 2,
        }
    )[:-1]
    manifest_digest = digest(manifest)
    index = canonical_bytes(
        {
            "manifests": [
                {
                    "digest": f"sha256:{manifest_digest}",
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "platform": {"architecture": "amd64", "os": "linux"},
                    "size": len(manifest),
                }
            ],
            "schemaVersion": 2,
        }
    )[:-1]
    layout = canonical_bytes({"imageLayoutVersion": "1.0.0"})[:-1]
    archive = tar_bytes(
        {
            "index.json": index,
            "oci-layout": layout,
            f"blobs/sha256/{config_digest}": config,
            f"blobs/sha256/{layer_digest}": layer,
            f"blobs/sha256/{manifest_digest}": manifest,
        }
    )
    return archive, f"sha256:{manifest_digest}", f"sha256:{config_digest}"


@dataclass
class ReleaseCase:
    paths: VerificationPaths
    bundle: LaunchAuthorizationBundle
    revocations: ReleaseRevocationList
    signing_keys: dict[str, Ed25519PrivateKey]
    evaluated_at_epoch: int


def _artifact_record(artifact_id: str, path: str, value: bytes) -> dict[str, object]:
    return {
        "artifact_id": artifact_id,
        "path": path,
        "content_sha256": digest(value),
        "byte_length": len(value),
    }


def make_release_case(
    tmp_path: Path,
    *,
    id_overrides: dict[str, str] | None = None,
) -> ReleaseCase:
    overrides = id_overrides or {}

    def source_id(default: str) -> str:
        return overrides.get(default, default)

    source_root = tmp_path / "source"
    artifact_root = tmp_path / "candidate"
    recomputed_root = tmp_path / "recomputed"
    source_archive_path = tmp_path / "source-archive.tar"
    bundle_path = tmp_path / "authorization-bundle.json"
    revocations_path = tmp_path / "revocations.json"

    source_archive = b"deterministic source archive bytes\n"
    write_owner_file(source_archive_path, source_archive)
    dependency_specs = [
        (source_id("dockerfile_neuron"), "container", "Dockerfile.neuron", b"FROM scratch\n"),
        (source_id("go_mod"), "go", "go.mod", b"module example.invalid/release\n"),
        (source_id("pyproject"), "python", "pyproject.toml", b"[project]\nname='release'\n"),
    ]
    dependency_inputs: list[dict[str, object]] = []
    for dependency_id, ecosystem, path, value in dependency_specs:
        write_owner_file(source_root / path, value)
        dependency_inputs.append(
            {
                "dependency_id": dependency_id,
                "ecosystem": ecosystem,
                "path": path,
                "content_sha256": digest(value),
                "byte_length": len(value),
            }
        )

    primary_bytes: dict[str, tuple[str, bytes]] = {
        "python_sdist": ("dist/misscomputer_subnet-0.2.0.tar.gz", b"sdist-v1\n"),
        "python_wheel": (
            "dist/misscomputer_subnet-0.2.0-py3-none-any.whl",
            b"wheel-v1\n",
        ),
        "go_control_api": ("bin/linux_amd64/control-api", b"control-api-v1\n"),
        "go_miner_agent": ("bin/linux_amd64/miner-agent", b"miner-agent-v1\n"),
        "go_workload": ("bin/linux_amd64/workload", b"workload-binary-v1\n"),
        "config_mainnet": (
            "configs/synthetic-campaign.mainnet.example.json",
            canonical_bytes({"network": "finney", "netuid": 24}),
        ),
        "schema_fixture": (
            "contracts/schemas/example.schema.json",
            canonical_bytes({"$schema": "https://json-schema.org/draft/2020-12/schema"}),
        ),
        "unit_executor": (
            "deployments/systemd/misscomputer-weight-executor.service",
            b"[Service]\nExecStart=/usr/bin/false\n",
        ),
    }
    for path, value in primary_bytes.values():
        write_owner_file(artifact_root / path, value)
        write_owner_file(recomputed_root / path, value)

    image_records: list[dict[str, object]] = []
    for image_name in ("neuron", "workload"):
        value, manifest_digest, config_digest = oci_archive(image_name)
        path = f"oci/linux_amd64/{image_name}.tar"
        write_owner_file(artifact_root / path, value)
        write_owner_file(recomputed_root / path, value)
        image_records.append(
            {
                "artifact_id": f"oci_{image_name}",
                "image_name": image_name,
                "platform": "linux/amd64",
                "manifest_digest": manifest_digest,
                "config_digest": config_digest,
                "archive_path": path,
                "content_sha256": digest(value),
                "byte_length": len(value),
            }
        )
    for image_name, record in zip(("neuron", "workload"), image_records, strict=True):
        record["artifact_id"] = source_id(f"oci_{image_name}")

    workload_artifact_id = source_id("workload_descriptor")
    workload_container_id = source_id("oci_workload")
    workload_image = next(record for record in image_records if record["image_name"] == "workload")

    workload_content = b"logical workload export bytes\n"
    workload_descriptor = canonical_bytes(
        {
            "artifact_id": workload_artifact_id,
            "byte_length": len(workload_content),
            "container_artifact_id": workload_container_id,
            "container_manifest_digest": workload_image["manifest_digest"],
            "content_sha256": digest(workload_content),
            "mutable_tag": None,
            "schema": "miss.computer/misscomputer-subnet/workload-export-descriptor",
            "schema_version": 1,
            "workload_kind": "synthetic_http_v1",
        }
    )
    workload_path = "workloads/synthetic-http-v1.json"
    write_owner_file(artifact_root / workload_path, workload_descriptor)
    write_owner_file(recomputed_root / workload_path, workload_descriptor)

    python_records = []
    for default_id in ("python_sdist", "python_wheel"):
        path, value = primary_bytes[default_id]
        python_records.append(
            {
                **_artifact_record(source_id(default_id), path, value),
                "distribution_kind": "sdist" if default_id == "python_sdist" else "wheel",
                "requires_python": "==3.12.*",
            }
        )
    python_records.sort(key=lambda item: str(item["artifact_id"]))
    go_names = {
        "go_control_api": "control-api",
        "go_miner_agent": "miner-agent",
        "go_workload": "workload",
    }
    go_records = []
    for default_id in sorted(go_names):
        path, value = primary_bytes[default_id]
        go_records.append(
            {
                **_artifact_record(source_id(default_id), path, value),
                "binary_name": go_names[default_id],
                "target": "linux_amd64",
                "build_mode": "trimpath_cgo_disabled",
            }
        )
    go_records.sort(key=lambda item: str(item["artifact_id"]))
    release_categories = {
        "config_mainnet": "config",
        "schema_fixture": "contract_schema",
        "unit_executor": "systemd_unit",
    }
    release_records = []
    for default_id in sorted(release_categories):
        path, value = primary_bytes[default_id]
        release_records.append(
            {
                **_artifact_record(source_id(default_id), path, value),
                "category": release_categories[default_id],
            }
        )
    release_records.sort(key=lambda item: str(item["artifact_id"]))
    image_records.sort(key=lambda item: str(item["artifact_id"]))
    workload_records = [
        {
            "artifact_id": workload_artifact_id,
            "workload_kind": "synthetic_http_v1",
            "container_artifact_id": workload_container_id,
            "descriptor_path": workload_path,
            "descriptor_sha256": digest(workload_descriptor),
            "content_sha256": digest(workload_content),
            "byte_length": len(workload_content),
        }
    ]
    artifact_digests = {
        str(item["artifact_id"]): str(item["content_sha256"])
        for item in python_records + go_records + image_records + workload_records + release_records
    }
    subjects = sorted(artifact_digests)
    spdx = canonical_bytes(
        {
            "SPDXID": "SPDXRef-DOCUMENT",
            "dataLicense": "CC0-1.0",
            "documentNamespace": "https://miss.computer/spdx/release-test-v1",
            "files": [
                {
                    "SPDXID": f"SPDXRef-{artifact_id}",
                    "checksums": [
                        {"algorithm": "SHA256", "checksumValue": artifact_digests[artifact_id]}
                    ],
                    "name": artifact_id,
                }
                for artifact_id in subjects
            ],
            "name": "release-test-v1",
            "spdxVersion": "SPDX-2.3",
        }
    )
    provenance = canonical_bytes(
        {
            "_type": "https://in-toto.io/Statement/v1",
            "predicate": {
                "buildDefinition": {
                    "externalParameters": {
                        "commit_oid": "a" * 40,
                        "repository": "misscomputer/misscomputer-subnet",
                        "source_archive_sha256": digest(source_archive),
                        "tree_oid": "b" * 40,
                    }
                }
            },
            "predicateType": "https://slsa.dev/provenance/v1",
            "subject": [
                {"digest": {"sha256": artifact_digests[artifact_id]}, "name": artifact_id}
                for artifact_id in subjects
            ],
        }
    )
    evidence_specs = {
        "supply-chain/release.spdx.json": spdx,
        "supply-chain/release.slsa.json": provenance,
    }
    for path, value in evidence_specs.items():
        write_owner_file(artifact_root / path, value)
        write_owner_file(recomputed_root / path, value)

    rollback_records: list[dict[str, object]] = []
    for index, artifact_id in enumerate(sorted(set(subjects) - {source_id("python_sdist")})):
        value = f"rollback:{artifact_id}:{index}\n".encode()
        path = f"rollback/0.1.0/{artifact_id}.blob"
        write_owner_file(artifact_root / path, value)
        write_owner_file(recomputed_root / path, value)
        rollback_records.append(
            {
                "artifact_id": artifact_id,
                "replacement_sha256": artifact_digests[artifact_id],
                "rollback_path": path,
                "rollback_sha256": digest(value),
                "rollback_byte_length": len(value),
            }
        )

    manifest = build_production_release_manifest(
        {
            "schema": PRODUCTION_RELEASE_MANIFEST_SCHEMA,
            "schema_version": PRODUCTION_RELEASE_SCHEMA_VERSION,
            "release_id": "release-mainnet-v1",
            "release_version": "0.2.0-mainnet.1",
            "release_channel": "production",
            "target_network": "finney",
            "netuid": 24,
            "source": {
                "repository": "misscomputer/misscomputer-subnet",
                "object_format": "sha1",
                "commit_oid": "a" * 40,
                "tree_oid": "b" * 40,
                "source_archive_sha256": digest(source_archive),
            },
            "created_at_epoch": 1_000,
            "expires_at_epoch": 10_000,
            "toolchains": [
                {
                    "toolchain_id": name,
                    "component": name,
                    "version": "1.0.0",
                    "platform": "linux_amd64",
                    "distribution_sha256": digest(f"toolchain:{name}".encode()),
                }
                for name in ("container_builder", "go", "python")
            ],
            "dependency_inputs": dependency_inputs,
            "python_distributions": python_records,
            "go_binaries": go_records,
            "container_images": image_records,
            "workload_artifacts": workload_records,
            "release_files": release_records,
            "sbom_references": [
                {
                    "reference_id": source_id("sbom_release"),
                    "format": "spdx_json",
                    "path": "supply-chain/release.spdx.json",
                    "content_sha256": digest(spdx),
                    "byte_length": len(spdx),
                    "subject_artifact_ids": subjects,
                }
            ],
            "provenance_references": [
                {
                    "reference_id": source_id("provenance_release"),
                    "format": "slsa_provenance_v1",
                    "path": "supply-chain/release.slsa.json",
                    "content_sha256": digest(provenance),
                    "byte_length": len(provenance),
                    "subject_artifact_ids": subjects,
                }
            ],
            "rollback_bytes": rollback_records,
            "completeness_state": "complete",
            "uniqueness_state": "unique",
            "build_recomputation_state": "not_performed",
            "artifact_verification_state": "not_performed",
            "live_actions": False,
        }
    )

    signing_keys = {
        key_id: Ed25519PrivateKey.generate()
        for key_id in ("key_operations", "key_release", "key_security")
    }
    roles = {
        "key_operations": "operations_owner",
        "key_release": "release_manager",
        "key_security": "security_reviewer",
    }
    trusted_keys: list[dict[str, object]] = []
    for key_id in sorted(signing_keys):
        public_bytes = (
            signing_keys[key_id]
            .public_key()
            .public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            )
        )
        trusted_keys.append(
            {
                "key_id": key_id,
                "algorithm": "ed25519",
                "public_key_base64": base64.b64encode(public_bytes).decode("ascii"),
                "public_key_sha256": digest(public_bytes),
                "roles": [roles[key_id]],
                "valid_from_epoch": 1_000,
                "valid_until_epoch": 10_000,
            }
        )
    policy = build_release_trust_policy(
        {
            "schema": RELEASE_TRUST_POLICY_SCHEMA,
            "schema_version": PRODUCTION_RELEASE_SCHEMA_VERSION,
            "policy_id": "mainnet_release_policy",
            "threshold": 3,
            "required_roles": [
                "operations_owner",
                "release_manager",
                "security_reviewer",
            ],
            "trusted_keys": trusted_keys,
            "valid_from_epoch": 1_000,
            "valid_until_epoch": 10_000,
        }
    )
    issued_at_epoch = 2_000
    expires_at_epoch = 8_000
    evaluated_at_epoch = 3_000
    payload_digest = authorization_payload_digest(
        bundle_id="mainnet_launch_v1",
        manifest=manifest,
        trust_policy=policy,
        issued_at_epoch=issued_at_epoch,
        expires_at_epoch=expires_at_epoch,
    )
    signatures: list[dict[str, object]] = []
    for key_id in sorted(signing_keys):
        message = authorization_signature_message(
            bundle_id="mainnet_launch_v1",
            release_manifest_digest_sha256=manifest.digest_sha256,
            trust_policy_digest_sha256=policy.digest_sha256,
            payload_digest_sha256=payload_digest,
            signer_key_id=key_id,
            issued_at_epoch=issued_at_epoch,
            expires_at_epoch=expires_at_epoch,
        )
        signatures.append(
            {
                "schema": OFFLINE_SIGNATURE_ENVELOPE_SCHEMA,
                "schema_version": PRODUCTION_RELEASE_SCHEMA_VERSION,
                "signer_key_id": key_id,
                "algorithm": "ed25519",
                "payload_digest_sha256": payload_digest,
                "signature_base64": base64.b64encode(signing_keys[key_id].sign(message)).decode(
                    "ascii"
                ),
                "issued_at_epoch": issued_at_epoch,
                "expires_at_epoch": expires_at_epoch,
            }
        )
    bundle = build_launch_authorization_bundle(
        {
            "schema": LAUNCH_AUTHORIZATION_BUNDLE_SCHEMA,
            "schema_version": PRODUCTION_RELEASE_SCHEMA_VERSION,
            "bundle_id": "mainnet_launch_v1",
            "release_manifest": manifest.model_dump(mode="json", by_alias=True),
            "release_manifest_digest_sha256": manifest.digest_sha256,
            "trust_policy": policy.model_dump(mode="json", by_alias=True),
            "trust_policy_digest_sha256": policy.digest_sha256,
            "issued_at_epoch": issued_at_epoch,
            "expires_at_epoch": expires_at_epoch,
            "evaluated_at_epoch": evaluated_at_epoch,
            "authorization_payload_digest_sha256": payload_digest,
            "signatures": signatures,
            "completeness_state": "complete",
            "uniqueness_state": "unique",
            "signature_verification_state": "not_performed",
            "authorization_state": "pending_signature_verification",
            "launch_authorized": False,
            "live_actions": False,
        }
    )
    revocations = build_release_revocation_list(
        {
            "schema": RELEASE_REVOCATION_LIST_SCHEMA,
            "schema_version": VERIFIER_SCHEMA_VERSION,
            "policy_digest_sha256": policy.digest_sha256,
            "sequence": 1,
            "issued_at_epoch": 2_500,
            "expires_at_epoch": 7_000,
            "revoked_keys": [],
            "live_actions": False,
        }
    )
    write_owner_file(bundle_path, launch_authorization_bundle_bytes(bundle))
    write_owner_file(revocations_path, release_revocation_list_bytes(revocations))
    return ReleaseCase(
        paths=VerificationPaths(
            bundle=str(bundle_path),
            revocations=str(revocations_path),
            source_root=str(source_root),
            source_archive=str(source_archive_path),
            artifact_root=str(artifact_root),
            recomputed_artifact_root=str(recomputed_root),
        ),
        bundle=bundle,
        revocations=revocations,
        signing_keys=signing_keys,
        evaluated_at_epoch=evaluated_at_epoch,
    )


def produce(case: ReleaseCase, **overrides: object) -> LaunchAuthorizationReport:
    arguments: dict[str, object] = {
        "approved_trust_policy_digest_sha256": case.bundle.trust_policy.digest_sha256,
        "approved_revocation_list_digest_sha256": case.revocations.digest_sha256,
        "evaluated_at_epoch": case.evaluated_at_epoch,
    }
    arguments.update(overrides)
    return produce_launch_authorization_report(case.paths, **arguments)  # type: ignore[arg-type]


def replace_bundle(case: ReleaseCase, document: dict[str, Any]) -> LaunchAuthorizationBundle:
    document.pop("digest_sha256", None)
    bundle = build_launch_authorization_bundle(document)
    write_owner_file(Path(case.paths.bundle), launch_authorization_bundle_bytes(bundle))
    case.bundle = bundle
    return bundle


def replace_revocations(
    case: ReleaseCase,
    revoked_keys: list[dict[str, object]],
) -> ReleaseRevocationList:
    revocations = build_release_revocation_list(
        {
            "schema": RELEASE_REVOCATION_LIST_SCHEMA,
            "schema_version": VERIFIER_SCHEMA_VERSION,
            "policy_digest_sha256": case.bundle.trust_policy.digest_sha256,
            "sequence": 2,
            "issued_at_epoch": 2_900,
            "expires_at_epoch": 7_000,
            "revoked_keys": revoked_keys,
            "live_actions": False,
        }
    )
    write_owner_file(Path(case.paths.revocations), release_revocation_list_bytes(revocations))
    case.revocations = revocations
    return revocations


def cli_arguments(case: ReleaseCase, report: Path, *, command: str) -> list[str]:
    return [
        command,
        "--bundle",
        case.paths.bundle,
        "--revocations",
        case.paths.revocations,
        "--source-root",
        case.paths.source_root,
        "--source-archive",
        case.paths.source_archive,
        "--artifact-root",
        case.paths.artifact_root,
        "--recomputed-artifact-root",
        case.paths.recomputed_artifact_root,
        "--approved-policy-digest",
        case.bundle.trust_policy.digest_sha256,
        "--approved-revocations-digest",
        case.revocations.digest_sha256,
        "--evaluated-at-epoch",
        str(case.evaluated_at_epoch),
        "--report",
        str(report),
    ]


def test_hardened_loader_rejects_noncanonical_duplicate_nan_and_aliases(tmp_path: Path) -> None:
    valid = tmp_path / "valid.json"
    write_owner_file(valid, canonical_bytes({"state": "valid"}))
    assert load_canonical_json(HardenedFileSet(), str(valid), label="valid") == {"state": "valid"}

    for name, value in (
        ("whitespace.json", b'{"state": "valid"}\n'),
        ("duplicate.json", b'{"state":"valid","state":"other"}\n'),
        ("nan.json", b'{"state":NaN}\n'),
        ("trailing.json", b'{"state":"valid"}\n\n'),
    ):
        path = tmp_path / name
        write_owner_file(path, value)
        with pytest.raises(ReleaseVerificationError):
            load_canonical_json(HardenedFileSet(), str(path), label="document")

    file_set = HardenedFileSet()
    load_canonical_json(file_set, str(valid), label="first")
    with pytest.raises(ReleaseVerificationError, match="aliases") as error:
        load_canonical_json(file_set, str(valid), label="second")
    assert error.value.code == "duplicate_file"


def test_hardened_loader_rejects_modes_links_symlinks_and_parent_races(tmp_path: Path) -> None:
    valid = tmp_path / "valid.json"
    write_owner_file(valid, canonical_bytes({"state": "valid"}))
    valid.chmod(0o640)
    with pytest.raises(ReleaseVerificationError) as error:
        load_canonical_json(HardenedFileSet(), str(valid), label="document")
    assert error.value.code == "unsafe_file_metadata"
    valid.chmod(0o600)

    hardlink = tmp_path / "hardlink.json"
    os.link(valid, hardlink)
    with pytest.raises(ReleaseVerificationError) as error:
        load_canonical_json(HardenedFileSet(), str(valid), label="document")
    assert error.value.code == "unsafe_file_metadata"
    hardlink.unlink()

    symlink = tmp_path / "symlink.json"
    symlink.symlink_to(valid)
    with pytest.raises(ReleaseVerificationError):
        load_canonical_json(HardenedFileSet(), str(symlink), label="document")

    safe_parent = tmp_path / "safe-parent"
    safe_parent.mkdir(mode=0o700)
    nested = safe_parent / "nested.json"
    write_owner_file(nested, canonical_bytes({"state": "valid"}))
    parent_link = tmp_path / "parent-link"
    parent_link.symlink_to(safe_parent, target_is_directory=True)
    with pytest.raises(ReleaseVerificationError):
        load_canonical_json(HardenedFileSet(), str(parent_link / nested.name), label="document")

    safe_parent.chmod(0o777)
    try:
        with pytest.raises(ReleaseVerificationError):
            load_canonical_json(HardenedFileSet(), str(nested), label="document")
    finally:
        safe_parent.chmod(0o700)


def test_hardened_loader_revalidates_path_inode_and_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "race.json"
    replacement = tmp_path / "replacement.json"
    write_owner_file(target, canonical_bytes({"state": "before"}))
    write_owner_file(replacement, canonical_bytes({"state": "after"}))
    real_read = verifier_module.os.read
    replaced = False

    def racing_read(descriptor: int, length: int) -> bytes:
        nonlocal replaced
        value = real_read(descriptor, length)
        if not value and not replaced:
            replaced = True
            os.replace(replacement, target)
        return value

    monkeypatch.setattr(verifier_module.os, "read", racing_read)
    with pytest.raises(ReleaseVerificationError) as error:
        load_canonical_json(HardenedFileSet(), str(target), label="racing_document")
    assert error.value.code == "input_changed"


def test_signature_verifier_pins_domain_purpose_trust_expiry_revocation_and_roles(
    tmp_path: Path,
) -> None:
    case = make_release_case(tmp_path)
    verified = verify_bundle_signatures(
        case.bundle,
        case.revocations,
        approved_trust_policy_digest_sha256=case.bundle.trust_policy.digest_sha256,
        approved_revocation_list_digest_sha256=case.revocations.digest_sha256,
        evaluated_at_epoch=case.evaluated_at_epoch,
    )
    assert [item.signer_key_id for item in verified] == [
        "key_operations",
        "key_release",
        "key_security",
    ]
    assert {role for item in verified for role in item.roles} == {
        "operations_owner",
        "release_manager",
        "security_reviewer",
    }

    with pytest.raises(ReleaseVerificationError) as error:
        verify_bundle_signatures(
            case.bundle,
            case.revocations,
            approved_trust_policy_digest_sha256="0" * 64,
            approved_revocation_list_digest_sha256=case.revocations.digest_sha256,
            evaluated_at_epoch=case.evaluated_at_epoch,
        )
    assert error.value.code == "unapproved_policy"

    with pytest.raises(ReleaseVerificationError) as error:
        verify_bundle_signatures(
            case.bundle,
            case.revocations,
            approved_trust_policy_digest_sha256=case.bundle.trust_policy.digest_sha256,
            approved_revocation_list_digest_sha256=case.revocations.digest_sha256,
            evaluated_at_epoch=case.bundle.expires_at_epoch,
        )
    assert error.value.code == "expired_bundle"

    revocations = replace_revocations(
        case,
        [
            {
                "key_id": "key_security",
                "revoked_at_epoch": 2_800,
                "reason": "compromise",
            }
        ],
    )
    with pytest.raises(ReleaseVerificationError) as error:
        verify_bundle_signatures(
            case.bundle,
            revocations,
            approved_trust_policy_digest_sha256=case.bundle.trust_policy.digest_sha256,
            approved_revocation_list_digest_sha256=revocations.digest_sha256,
            evaluated_at_epoch=case.evaluated_at_epoch,
        )
    assert error.value.code == "revoked_signer"


def test_release_verifier_rejects_every_small_order_ed25519_trust_key(
    tmp_path: Path,
    small_order_ed25519_public_key: bytes,
) -> None:
    case = make_release_case(tmp_path)
    trusted_keys = list(case.bundle.trust_policy.trusted_keys)
    trusted_keys[0] = trusted_keys[0].model_copy(
        update={
            "public_key_base64": base64.b64encode(small_order_ed25519_public_key).decode("ascii"),
            "public_key_sha256": hashlib.sha256(small_order_ed25519_public_key).hexdigest(),
        }
    )
    weak_policy = case.bundle.trust_policy.model_copy(update={"trusted_keys": trusted_keys})
    weak_bundle = case.bundle.model_copy(update={"trust_policy": weak_policy})

    with pytest.raises(ReleaseVerificationError) as caught:
        verify_bundle_signatures(
            weak_bundle,
            case.revocations,
            approved_trust_policy_digest_sha256=weak_policy.digest_sha256,
            approved_revocation_list_digest_sha256=case.revocations.digest_sha256,
            evaluated_at_epoch=case.evaluated_at_epoch,
        )
    assert caught.value.code == "invalid_public_key"
    assert str(caught.value) == "authorization public key is invalid"


def test_signature_verifier_rejects_wrong_domain_threshold_signer_and_replay(
    tmp_path: Path,
) -> None:
    case = make_release_case(tmp_path)
    document = case.bundle.model_dump(mode="json", by_alias=True)
    wrong_message = case.bundle.authorization_payload_digest_sha256.encode("ascii")
    document["signatures"][2]["signature_base64"] = base64.b64encode(
        case.signing_keys["key_security"].sign(wrong_message)
    ).decode("ascii")
    tampered_bundle = replace_bundle(case, document)
    with pytest.raises(ReleaseVerificationError) as error:
        verify_bundle_signatures(
            tampered_bundle,
            case.revocations,
            approved_trust_policy_digest_sha256=tampered_bundle.trust_policy.digest_sha256,
            approved_revocation_list_digest_sha256=case.revocations.digest_sha256,
            evaluated_at_epoch=case.evaluated_at_epoch,
        )
    assert error.value.code == "invalid_signature"

    replay_case = make_release_case(tmp_path / "replay")
    replay_document = replay_case.bundle.model_dump(mode="json", by_alias=True)
    replay_document["bundle_id"] = "mainnet_launch_v2"
    replay_document.pop("digest_sha256")
    new_payload = authorization_payload_digest(
        bundle_id="mainnet_launch_v2",
        manifest=replay_case.bundle.release_manifest,
        trust_policy=replay_case.bundle.trust_policy,
        issued_at_epoch=replay_case.bundle.issued_at_epoch,
        expires_at_epoch=replay_case.bundle.expires_at_epoch,
    )
    replay_document["authorization_payload_digest_sha256"] = new_payload
    for envelope in replay_document["signatures"]:
        envelope["payload_digest_sha256"] = new_payload
    replay_bundle = build_launch_authorization_bundle(replay_document)
    with pytest.raises(ReleaseVerificationError) as error:
        verify_bundle_signatures(
            replay_bundle,
            replay_case.revocations,
            approved_trust_policy_digest_sha256=replay_bundle.trust_policy.digest_sha256,
            approved_revocation_list_digest_sha256=replay_case.revocations.digest_sha256,
            evaluated_at_epoch=replay_case.evaluated_at_epoch,
        )
    assert error.value.code == "invalid_signature"


def test_end_to_end_report_is_complete_canonical_and_deterministic(tmp_path: Path) -> None:
    case = make_release_case(tmp_path)
    first = produce(case)
    second = produce(case)
    assert first == second
    assert first.launch_authorized is True
    assert first.live_actions is False
    assert first.artifact_verification_state == "verified"
    assert first.build_recomputation_state == "verified"
    assert first.signature_verification_state == "verified"
    assert {item.category for item in first.verified_inputs} == {
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
    }
    rendered = launch_authorization_report_bytes(first)
    assert rendered == launch_authorization_report_bytes(second)
    assert LaunchAuthorizationReport.model_validate(json.loads(rendered)) == first
    unsigned = first.model_dump(mode="json", by_alias=True, exclude={"digest_sha256"})
    assert first.digest_sha256 == digest(canonical_bytes(unsigned)[:-1])


def test_maximum_record_ids_are_category_bound_deterministic_and_cli_safe(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    maximum_ids = {
        "dockerfile_neuron": "d" * 64,
        "python_wheel": "p" * 64,
        "go_control_api": "g" * 64,
        "oci_neuron": "o" * 64,
        "workload_descriptor": "w" * 64,
        "config_mainnet": "c" * 64,
        "sbom_release": "s" * 64,
        "provenance_release": "v" * 64,
    }
    case = make_release_case(tmp_path, id_overrides=maximum_ids)

    first = produce(case)
    second = produce(case)
    assert launch_authorization_report_bytes(first) == launch_authorization_report_bytes(second)
    report_ids = {item.input_id for item in first.verified_inputs}
    assert {
        f"dependency_input_{maximum_ids['dockerfile_neuron']}",
        f"python_distribution_{maximum_ids['python_wheel']}",
        f"go_binary_{maximum_ids['go_control_api']}",
        f"oci_archive_{maximum_ids['oci_neuron']}",
        f"workload_descriptor_{maximum_ids['workload_descriptor']}",
        f"release_file_{maximum_ids['config_mainnet']}",
        f"sbom_{maximum_ids['sbom_release']}",
        f"provenance_{maximum_ids['provenance_release']}",
        f"rollback_bytes_{maximum_ids['python_wheel']}",
    } <= report_ids

    report_path = tmp_path / "maximum-id-report.json"
    assert run_cli(cli_arguments(case, report_path, command="authorize")) == EXIT_OK
    authorized = capsys.readouterr()
    assert authorized.err == ""
    assert authorized.out.startswith("AUTHORIZED report_sha256=")
    assert run_cli(cli_arguments(case, report_path, command="verify-report")) == EXIT_OK
    verified = capsys.readouterr()
    assert verified.err == ""
    assert verified.out.startswith("VERIFIED report_sha256=")


@pytest.mark.parametrize(
    ("input_id", "category"),
    [
        ("sbom_shared", "provenance"),
        ("go_binary_shared", "oci_archive"),
        ("source_archive", "release_file"),
    ],
)
def test_report_entry_identifiers_reject_category_spoofing(
    input_id: str,
    category: str,
) -> None:
    with pytest.raises(
        ValidationError,
        match="report input identifier is not bound to its category",
    ):
        VerifiedLocalInput.model_validate(
            {
                "input_id": input_id,
                "category": category,
                "relative_path": "release/input.bin",
                "expected_sha256": "a" * 64,
                "observed_sha256": "a" * 64,
                "expected_byte_length": 1,
                "observed_byte_length": 1,
                "recomputed_sha256": "a" * 64,
                "recomputed_byte_length": 1,
                "bound_content_sha256": None,
                "verification_state": "verified",
            }
        )


@pytest.mark.parametrize(
    ("relative_path", "expected_code"),
    [
        ("dist/misscomputer_subnet-0.2.0-py3-none-any.whl", "digest_mismatch"),
        ("rollback/0.1.0/python_wheel.blob", "digest_mismatch"),
    ],
)
def test_artifact_and_rollback_tamper_are_rejected(
    tmp_path: Path,
    relative_path: str,
    expected_code: str,
) -> None:
    case = make_release_case(tmp_path)
    path = Path(case.paths.artifact_root) / relative_path
    value = path.read_bytes()
    write_owner_file(path, bytes([value[0] ^ 1]) + value[1:])
    with pytest.raises(ReleaseVerificationError) as error:
        produce(case)
    assert error.value.code == expected_code


def test_missing_duplicate_and_nonreproducible_artifacts_are_rejected(tmp_path: Path) -> None:
    missing_case = make_release_case(tmp_path / "missing")
    Path(missing_case.paths.artifact_root, "bin/linux_amd64/control-api").unlink()
    with pytest.raises(ReleaseVerificationError) as error:
        produce(missing_case)
    assert error.value.code == "unsafe_file"

    duplicate_case = make_release_case(tmp_path / "duplicate")
    candidate = Path(
        duplicate_case.paths.artifact_root,
        "dist/misscomputer_subnet-0.2.0-py3-none-any.whl",
    )
    recomputed = Path(
        duplicate_case.paths.recomputed_artifact_root,
        "dist/misscomputer_subnet-0.2.0-py3-none-any.whl",
    )
    recomputed.unlink()
    os.link(candidate, recomputed)
    with pytest.raises(ReleaseVerificationError) as error:
        produce(duplicate_case)
    assert error.value.code == "unsafe_file_metadata"

    nonreproducible_case = make_release_case(tmp_path / "nonreproducible")
    rebuilt = Path(
        nonreproducible_case.paths.recomputed_artifact_root,
        "bin/linux_amd64/miner-agent",
    )
    value = rebuilt.read_bytes()
    write_owner_file(rebuilt, bytes([value[0] ^ 1]) + value[1:])
    with pytest.raises(ReleaseVerificationError) as error:
        produce(nonreproducible_case)
    assert error.value.code == "digest_mismatch"


def test_mutable_oci_claim_and_provenance_source_guard_are_rejected(tmp_path: Path) -> None:
    provenance_case = make_release_case(tmp_path / "provenance")
    provenance_path = Path(
        provenance_case.paths.artifact_root,
        "supply-chain/release.slsa.json",
    )
    document = json.loads(provenance_path.read_bytes())
    document["predicate"]["buildDefinition"]["externalParameters"]["commit_oid"] = "c" * 40
    write_owner_file(provenance_path, canonical_bytes(document))
    with pytest.raises(ReleaseVerificationError) as error:
        produce(provenance_case)
    assert error.value.code in {"digest_mismatch", "source_guard"}

    mutable_case = make_release_case(tmp_path / "mutable")
    descriptor_path = Path(
        mutable_case.paths.artifact_root,
        "workloads/synthetic-http-v1.json",
    )
    descriptor = json.loads(descriptor_path.read_bytes())
    descriptor["mutable_tag"] = "latest"
    write_owner_file(descriptor_path, canonical_bytes(descriptor))
    with pytest.raises(ReleaseVerificationError) as error:
        produce(mutable_case)
    assert error.value.code in {"digest_mismatch", "invalid_workload_descriptor"}


def test_cli_produces_and_reverifies_report_with_clear_exits(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    case = make_release_case(tmp_path)
    report = tmp_path / "launch-report.json"
    assert run_cli(cli_arguments(case, report, command="authorize")) == EXIT_OK
    first_output = capsys.readouterr()
    assert first_output.err == ""
    assert first_output.out.startswith("AUTHORIZED report_sha256=")
    assert report.stat().st_mode & 0o777 == 0o600
    rendered = report.read_bytes()

    assert run_cli(cli_arguments(case, report, command="verify-report")) == EXIT_OK
    second_output = capsys.readouterr()
    assert second_output.err == ""
    assert second_output.out.startswith("VERIFIED report_sha256=")
    assert report.read_bytes() == rendered

    assert run_cli(["authorize", "--unknown", "credential-marker"]) == EXIT_USAGE
    usage = capsys.readouterr()
    assert usage.out == ""
    assert usage.err == "ERROR usage: invalid command line\n"
    assert "credential-marker" not in usage.err


def test_cli_errors_do_not_leak_paths_or_document_values(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    case = make_release_case(tmp_path)
    marker = "sensitive-document-marker"
    write_owner_file(Path(case.paths.bundle), canonical_bytes({"unexpected": marker}))
    report = tmp_path / "report.json"
    assert run_cli(cli_arguments(case, report, command="authorize")) == EXIT_REJECTED
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == (
        "REJECTED invalid_document: authorization_bundle failed contract validation\n"
    )
    assert marker not in captured.err
    assert str(tmp_path) not in captured.err


def test_cli_rejects_cross_list_evidence_reference_ambiguity_early(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    case = make_release_case(tmp_path)
    marker = "sensitive_reference_marker"
    document = case.bundle.model_dump(mode="json", by_alias=True)
    document["release_manifest"]["sbom_references"][0]["reference_id"] = marker
    document["release_manifest"]["provenance_references"][0]["reference_id"] = marker
    write_owner_file(Path(case.paths.bundle), canonical_bytes(document))

    report = tmp_path / "ambiguous-report.json"
    assert run_cli(cli_arguments(case, report, command="authorize")) == EXIT_REJECTED
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == (
        "REJECTED invalid_document: authorization_bundle failed contract validation\n"
    )
    assert marker not in captured.err
    assert str(tmp_path) not in captured.err
    assert not report.exists()


def test_generated_verifier_contracts_are_valid_and_regeneration_is_clean() -> None:
    for filename in (
        "launch-authorization-report.v1.schema.json",
        "release-revocation-list.v1.schema.json",
        "workload-export-descriptor.v1.schema.json",
    ):
        schema = json.loads((ROOT / "contracts" / "schemas" / filename).read_text())
        Draft202012Validator.check_schema(schema)
        assert schema["additionalProperties"] is False
    report_schema = json.loads(
        (ROOT / "contracts/schemas/launch-authorization-report.v1.schema.json").read_text()
    )
    report_input_id = report_schema["$defs"]["VerifiedLocalInput"]["properties"]["input_id"]
    assert report_input_id["maxLength"] == 84
    assert "workload_descriptor" in report_input_id["pattern"]
    fixture = ROOT / "contracts" / "fixtures" / "release-revocation-list.v1.json"
    parsed = ReleaseRevocationList.model_validate(json.loads(fixture.read_bytes()))
    assert release_revocation_list_bytes(parsed) == fixture.read_bytes()


def test_verifier_source_has_no_live_signing_or_external_capability() -> None:
    source_path = ROOT / "src" / "misscomputer_subnet" / "production_release_verifier.py"
    tree = ast.parse(source_path.read_text())
    imported_roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_roots.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported_roots.add(node.module.split(".", 1)[0])
    assert not imported_roots & {
        "bittensor",
        "docker",
        "httpx",
        "requests",
        "socket",
        "subprocess",
        "urllib",
    }
    source = source_path.read_text()
    for forbidden in (
        "Ed25519PrivateKey",
        ".sign(",
        "os.environ",
        "os.getenv",
        "systemctl",
    ):
        assert forbidden not in source
