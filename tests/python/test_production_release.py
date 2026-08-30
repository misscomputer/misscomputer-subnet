# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import base64
import copy
import hashlib
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from pydantic import BaseModel, ValidationError

from misscomputer_subnet.production_release import (
    LaunchAuthorizationBundle,
    OfflineSignatureEnvelope,
    ProductionReleaseManifest,
    ReleaseTrustPolicy,
    build_launch_authorization_bundle,
    build_production_release_manifest,
    build_release_trust_policy,
    launch_authorization_bundle_bytes,
    offline_signature_envelope_bytes,
    production_release_manifest_bytes,
    release_trust_policy_bytes,
)

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "contracts" / "fixtures"
SCHEMAS = ROOT / "contracts" / "schemas"


def canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def fixture_document(name: str) -> dict[str, Any]:
    value = json.loads((FIXTURES / f"{name}.json").read_text())
    assert isinstance(value, dict)
    return value


def rebuild_manifest(document: dict[str, Any]) -> ProductionReleaseManifest:
    unsigned = copy.deepcopy(document)
    unsigned.pop("digest_sha256", None)
    return build_production_release_manifest(unsigned)


def rebuild_bundle(document: dict[str, Any]) -> LaunchAuthorizationBundle:
    unsigned = copy.deepcopy(document)
    unsigned.pop("digest_sha256", None)
    return build_launch_authorization_bundle(unsigned)


def test_generated_contracts_are_strict_canonical_and_digest_bound() -> None:
    models: dict[str, type[BaseModel]] = {
        "production-release-manifest.v1": ProductionReleaseManifest,
        "release-trust-policy.v1": ReleaseTrustPolicy,
        "offline-signature-envelope.v1": OfflineSignatureEnvelope,
        "launch-authorization-bundle.v1": LaunchAuthorizationBundle,
    }
    serializers: dict[str, Callable[[Any], bytes]] = {
        "production-release-manifest.v1": production_release_manifest_bytes,
        "release-trust-policy.v1": release_trust_policy_bytes,
        "offline-signature-envelope.v1": offline_signature_envelope_bytes,
        "launch-authorization-bundle.v1": launch_authorization_bundle_bytes,
    }
    for name, model_type in models.items():
        rendered = (FIXTURES / f"{name}.json").read_bytes()
        document = json.loads(rendered)
        schema = json.loads((SCHEMAS / f"{name}.schema.json").read_text())
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(document)
        parsed = model_type.model_validate(document)
        assert serializers[name](parsed) == rendered
        assert rendered.endswith(b"\n") and rendered.count(b"\n") == 1
        assert schema["additionalProperties"] is False

    for name in (
        "production-release-manifest.v1",
        "release-trust-policy.v1",
        "launch-authorization-bundle.v1",
    ):
        document = fixture_document(name)
        digest = document.pop("digest_sha256")
        assert digest == hashlib.sha256(canonical_json(document)).hexdigest()


def test_release_trust_policy_accepts_representative_valid_ed25519_keys() -> None:
    document = fixture_document("release-trust-policy.v1")
    document.pop("digest_sha256")
    policy = build_release_trust_policy(document)
    assert [key.key_id for key in policy.trusted_keys] == [
        "key_operations",
        "key_release",
        "key_security",
    ]


def test_release_trust_policy_rejects_every_small_order_ed25519_encoding(
    small_order_ed25519_public_key: bytes,
) -> None:
    document = fixture_document("release-trust-policy.v1")
    document.pop("digest_sha256")
    trusted_key = document["trusted_keys"][0]
    trusted_key["public_key_base64"] = base64.b64encode(small_order_ed25519_public_key).decode(
        "ascii"
    )
    trusted_key["public_key_sha256"] = hashlib.sha256(small_order_ed25519_public_key).hexdigest()
    with pytest.raises(ValidationError, match="ed25519_public_key_small_order"):
        build_release_trust_policy(document)


def test_manifest_models_exact_mainnet_source_build_and_artifact_inventory() -> None:
    manifest = ProductionReleaseManifest.model_validate(
        fixture_document("production-release-manifest.v1")
    )
    assert manifest.target_network == "finney"
    assert manifest.netuid == 24
    assert manifest.source.commit_oid == "20b1cb454b040c52b0dcac095e6098f22bb894de"
    assert manifest.source.tree_oid == "90139e9e084ed3f562d4a1a07c4074e09ab8fead"
    assert {item.component for item in manifest.toolchains} == {
        "container_builder",
        "go",
        "python",
    }
    assert {item.ecosystem for item in manifest.dependency_inputs} == {
        "container",
        "go",
        "python",
    }
    assert {item.distribution_kind for item in manifest.python_distributions} == {
        "sdist",
        "wheel",
    }
    assert {item.binary_name for item in manifest.go_binaries} == {
        "control-api",
        "miner-agent",
        "workload",
    }
    assert {item.image_name for item in manifest.container_images} == {"neuron", "workload"}
    assert {item.category for item in manifest.release_files} == {
        "config",
        "contract_schema",
        "systemd_unit",
    }
    assert manifest.completeness_state == "complete"
    assert manifest.uniqueness_state == "unique"
    assert manifest.build_recomputation_state == "not_performed"
    assert manifest.artifact_verification_state == "not_performed"
    assert manifest.live_actions is False


def test_manifest_rejects_extra_fields_at_every_contract_level() -> None:
    root_extra = fixture_document("production-release-manifest.v1")
    root_extra["activation_command"] = "forbidden"
    with pytest.raises(ValidationError, match="extra_forbidden"):
        ProductionReleaseManifest.model_validate(root_extra)

    nested_extra = fixture_document("production-release-manifest.v1")
    nested_extra["source"]["branch"] = "main"
    with pytest.raises(ValidationError, match="extra_forbidden"):
        ProductionReleaseManifest.model_validate(nested_extra)

    private_key = fixture_document("launch-authorization-bundle.v1")
    private_key["trust_policy"]["trusted_keys"][0]["private_key_base64"] = "forbidden"
    with pytest.raises(ValidationError, match="extra_forbidden"):
        LaunchAuthorizationBundle.model_validate(private_key)


def test_manifest_rejects_duplicate_ids_paths_and_subject_coverage() -> None:
    duplicate_id = fixture_document("production-release-manifest.v1")
    duplicate_id["release_files"][1]["artifact_id"] = duplicate_id["release_files"][0][
        "artifact_id"
    ]
    with pytest.raises(ValidationError, match="release files must be unique and sorted"):
        rebuild_manifest(duplicate_id)

    duplicate_path = fixture_document("production-release-manifest.v1")
    duplicate_path["dependency_inputs"][1]["path"] = duplicate_path["dependency_inputs"][0]["path"]
    with pytest.raises(ValidationError, match="release paths must be globally unique"):
        rebuild_manifest(duplicate_path)

    duplicate_subject = fixture_document("production-release-manifest.v1")
    subjects = duplicate_subject["sbom_references"][0]["subject_artifact_ids"]
    subjects[1] = subjects[0]
    with pytest.raises(ValidationError, match="supply-chain subjects must be unique and sorted"):
        rebuild_manifest(duplicate_subject)

    duplicate_evidence_reference = fixture_document("production-release-manifest.v1")
    duplicate_evidence_reference["provenance_references"][0]["reference_id"] = (
        duplicate_evidence_reference["sbom_references"][0]["reference_id"]
    )
    with pytest.raises(
        ValidationError,
        match="supply-chain reference identifiers must be globally unique",
    ):
        rebuild_manifest(duplicate_evidence_reference)


def test_manifest_rejects_missing_artifacts_evidence_and_rollback_bytes() -> None:
    missing_sdist = fixture_document("production-release-manifest.v1")
    missing_sdist["python_distributions"].pop(0)
    with pytest.raises(ValidationError):
        rebuild_manifest(missing_sdist)

    missing_subject = fixture_document("production-release-manifest.v1")
    missing_subject["provenance_references"][0]["subject_artifact_ids"].pop()
    with pytest.raises(ValidationError, match="provenance subject coverage is incomplete"):
        rebuild_manifest(missing_subject)

    missing_rollback = fixture_document("production-release-manifest.v1")
    missing_rollback["rollback_bytes"].pop()
    with pytest.raises(ValidationError, match="rollback byte coverage is incomplete"):
        rebuild_manifest(missing_rollback)


def test_manifest_rejects_digest_and_rollback_mismatches() -> None:
    wrong_digest = fixture_document("production-release-manifest.v1")
    wrong_digest["digest_sha256"] = "0" * 64
    with pytest.raises(ValidationError, match="release manifest digest does not match"):
        ProductionReleaseManifest.model_validate(wrong_digest)

    wrong_replacement = fixture_document("production-release-manifest.v1")
    wrong_replacement["rollback_bytes"][0]["replacement_sha256"] = "1" * 64
    with pytest.raises(ValidationError, match="rollback replacement digest does not match"):
        rebuild_manifest(wrong_replacement)

    wrong_container = fixture_document("production-release-manifest.v1")
    wrong_container["workload_artifacts"][0]["container_artifact_id"] = "missing_container"
    with pytest.raises(ValidationError, match="unknown container"):
        rebuild_manifest(wrong_container)


def test_bundle_binds_manifest_policy_payload_and_unique_signers() -> None:
    bundle = LaunchAuthorizationBundle.model_validate(
        fixture_document("launch-authorization-bundle.v1")
    )
    assert bundle.release_manifest_digest_sha256 == bundle.release_manifest.digest_sha256
    assert bundle.trust_policy_digest_sha256 == bundle.trust_policy.digest_sha256
    assert {role for key in bundle.trust_policy.trusted_keys for role in key.roles} == {
        "operations_owner",
        "release_manager",
        "security_reviewer",
    }
    assert bundle.signature_verification_state == "not_performed"
    assert bundle.authorization_state == "pending_signature_verification"
    assert bundle.launch_authorized is False
    assert bundle.live_actions is False

    wrong_manifest = fixture_document("launch-authorization-bundle.v1")
    wrong_manifest["release_manifest_digest_sha256"] = "2" * 64
    with pytest.raises(ValidationError, match="manifest digest binding is inconsistent"):
        rebuild_bundle(wrong_manifest)

    wrong_payload = fixture_document("launch-authorization-bundle.v1")
    wrong_payload["signatures"][0]["payload_digest_sha256"] = "3" * 64
    with pytest.raises(ValidationError, match="signature envelope payload digest is inconsistent"):
        rebuild_bundle(wrong_payload)

    duplicate_signer = fixture_document("launch-authorization-bundle.v1")
    duplicate_signer["signatures"][1] = copy.deepcopy(duplicate_signer["signatures"][0])
    with pytest.raises(ValidationError, match="signature envelopes must be unique and sorted"):
        rebuild_bundle(duplicate_signer)


def test_bundle_expiry_and_authorization_states_are_exact() -> None:
    expired = fixture_document("launch-authorization-bundle.v1")
    expired["evaluated_at_epoch"] = expired["expires_at_epoch"]
    expired["authorization_state"] = "expired"
    parsed_expired = rebuild_bundle(expired)
    assert parsed_expired.authorization_state == "expired"
    assert parsed_expired.launch_authorized is False

    stale_pending = fixture_document("launch-authorization-bundle.v1")
    stale_pending["evaluated_at_epoch"] = stale_pending["expires_at_epoch"]
    with pytest.raises(ValidationError, match="authorization state is inconsistent"):
        rebuild_bundle(stale_pending)

    externally_verified = fixture_document("launch-authorization-bundle.v1")
    externally_verified["signature_verification_state"] = "verified"
    externally_verified["authorization_state"] = "authorized"
    externally_verified["launch_authorized"] = True
    parsed_verified = rebuild_bundle(externally_verified)
    assert parsed_verified.launch_authorized is True

    false_claim = fixture_document("launch-authorization-bundle.v1")
    false_claim["authorization_state"] = "authorized"
    false_claim["launch_authorized"] = True
    with pytest.raises(ValidationError, match="authorization state is inconsistent"):
        rebuild_bundle(false_claim)


@pytest.mark.parametrize(
    "unsafe_path",
    [
        "/etc/misscomputer-subnet/release.json",
        "dist/../release.whl",
        "secrets/release.whl",
        "dist\\release.whl",
    ],
)
def test_contracts_reject_absolute_traversal_or_secret_paths(unsafe_path: str) -> None:
    document = fixture_document("production-release-manifest.v1")
    document["python_distributions"][1]["path"] = unsafe_path
    with pytest.raises(ValidationError, match="artifact path is unsafe|string_pattern_mismatch"):
        rebuild_manifest(document)


def test_fixture_and_source_expose_no_secret_or_live_capability() -> None:
    rendered = (FIXTURES / "launch-authorization-bundle.v1.json").read_text().casefold()
    for forbidden in (
        '"private_key',
        "/run/credentials",
        "secretref://",
        "aws_secret_access_key",
        "provider_api_token",
        "miss_bridge_secret",
    ):
        assert forbidden not in rendered

    source = (ROOT / "src/misscomputer_subnet/production_release.py").read_text()
    for forbidden in (
        "import bittensor",
        "import cryptography",
        "import httpx",
        "import os",
        "import pathlib",
        "import requests",
        "import socket",
        "import subprocess",
        "import urllib",
        "from subprocess",
        "os.environ",
        "os.getenv",
        "systemctl",
    ):
        assert forbidden not in source
