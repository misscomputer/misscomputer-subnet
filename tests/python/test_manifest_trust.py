# SPDX-License-Identifier: AGPL-3.0-only
"""Channel trust, signature and chain rules every signed assignment manifest obeys.

The frozen trust policy, signature envelope and chain state v1 documents are
consumed byte-for-byte by the central producer and name the publication
channel, not a manifest version. These rules are exercised here on the live
organic ``active-assignment-manifest`` v2; the synthetic v1 manifest they were
first written against is retired.
"""

from __future__ import annotations

import ast
import base64
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from assignment_probe_context import (
    BASE_EPOCH,
    FINALIZED_BLOCK_HASH,
    FINALIZED_EPOCH,
    FINALIZED_HEIGHT,
    PROBE_PORT,
    ROUTE_SUFFIX,
    build_policy,
    digest,
    label_digest,
    schema_bytes,
    signer_keys,
)
from document_fixtures import manifest_document, manifest_signature_envelope
from jsonschema import Draft202012Validator
from organic_context import fixture_deployments, sign_manifest
from pydantic import BaseModel

from misscomputer_subnet.assignment_probe import (
    AssignmentManifestChainState,
    AssignmentManifestSignatureEnvelope,
    AssignmentManifestTrustPolicy,
    AssignmentProbeError,
    advance_manifest_header_chain_state,
    assignment_manifest_chain_state_bytes,
    assignment_manifest_signature_envelope_bytes,
    assignment_manifest_trust_policy_bytes,
    build_initial_manifest_chain_state,
    parse_assignment_manifest_chain_state,
    parse_assignment_manifest_signature_envelope,
    parse_assignment_manifest_trust_policy,
)
from misscomputer_subnet.checkpoint_boundary import PROTOCOL as BOUNDARY_PROTOCOL
from misscomputer_subnet.checkpoint_boundary import execute
from misscomputer_subnet.organic_contracts import ActiveAssignmentManifestV2
from misscomputer_subnet.organic_manifest import (
    organic_manifest_signature_message,
    verify_organic_assignment_manifest,
)

ROOT = Path(__file__).resolve().parents[2]
EVALUATION_EPOCH = BASE_EPOCH

# The generic channel documents and the weight plan are consumed by the
# private producer byte-for-byte; any change is a compatibility event.
FROZEN_CONTRACT_DIGESTS: dict[str, str] = {
    "schemas/assignment-manifest-trust-policy.v1.schema.json": (
        "85394d7eb8efc70b16146cb4eca2ac44eafad0d6be5dbdbb1d913af459fa3ab9"
    ),
    "schemas/assignment-manifest-signature-envelope.v1.schema.json": (
        "4545017e4a018b0c8eab812d2ae1a11826eea0b72cf700ca325a8a0eb6e4c7d5"
    ),
    "schemas/assignment-manifest-chain-state.v1.schema.json": (
        "a51d5253e047831d3a2e4e1bf5b8605086aa5bb4545fe7c339ac1929a384ad99"
    ),
    "schemas/weight-plan.v1.schema.json": (
        "d4fa8861c0683a05796834952363498cbae8afd6c0a9c80b64ef3cf888445b53"
    ),
    "fixtures/assignment-manifest-trust-policy.v1.json": (
        "597cbf615201e437e375ba3284e5203b325e90d6f55dd9343e570b04c1985612"
    ),
    "fixtures/assignment-manifest-signature-envelope.v1.json": (
        "09b671d14e1a38aaf6fa5c7ceeea0fcfb2d006a312e15e95bbc1acac914cb126"
    ),
    "fixtures/assignment-manifest-chain-state.v1.json": (
        "5b081cdf1a23f0f94819f06da739120630c8729d61f2d966d557e6497b08cfa6"
    ),
    "fixtures/weight-plan.v1.json": (
        "c73297fd0c2ed35bcae2dec304d9e8e4c288d30f697026b3e43c143bc28a117c"
    ),
}

CHANNEL_CONTRACTS: dict[str, tuple[type[BaseModel], Any, Any]] = {
    "assignment-manifest-trust-policy": (
        AssignmentManifestTrustPolicy,
        parse_assignment_manifest_trust_policy,
        assignment_manifest_trust_policy_bytes,
    ),
    "assignment-manifest-signature-envelope": (
        AssignmentManifestSignatureEnvelope,
        parse_assignment_manifest_signature_envelope,
        assignment_manifest_signature_envelope_bytes,
    ),
    "assignment-manifest-chain-state": (
        AssignmentManifestChainState,
        parse_assignment_manifest_chain_state,
        assignment_manifest_chain_state_bytes,
    ),
}


def assert_rejected(code: str, function: Any, *args: object, **kwargs: object) -> None:
    with pytest.raises(AssignmentProbeError) as error:
        function(*args, **kwargs)
    assert error.value.code == code


def manifest(
    policy: AssignmentManifestTrustPolicy,
    *,
    sequence: int = 1,
    previous: str | None = None,
    issued_at: int = BASE_EPOCH - 60,
    expires_at: int = BASE_EPOCH + 1_800,
    finalized_height: int = FINALIZED_HEIGHT,
    finalized_block_hash: str = FINALIZED_BLOCK_HASH,
    finalized_epoch: int = FINALIZED_EPOCH,
    route_suffix: str = ROUTE_SUFFIX,
) -> ActiveAssignmentManifestV2:
    return manifest_document(
        policy,
        finalized_height=finalized_height,
        finalized_block_hash=finalized_block_hash,
        finalized_epoch=finalized_epoch,
        sequence=sequence,
        previous_manifest_digest_sha256=previous,
        issued_at_epoch=issued_at,
        expires_at_epoch=expires_at,
        route_host_suffix=route_suffix,
        probe_port=PROBE_PORT,
        deployments=fixture_deployments(),
    )


def reseal(value: ActiveAssignmentManifestV2, **changes: object) -> ActiveAssignmentManifestV2:
    document = value.model_dump(mode="json", by_alias=True)
    document.update(changes)
    document.pop("manifest_digest_sha256")
    document["manifest_digest_sha256"] = digest(document)
    return ActiveAssignmentManifestV2.model_validate(document)


def verify(
    value: ActiveAssignmentManifestV2,
    policy: AssignmentManifestTrustPolicy,
    signatures: list[AssignmentManifestSignatureEnvelope] | None = None,
    state: AssignmentManifestChainState | None = None,
    *,
    at: int = EVALUATION_EPOCH,
) -> Any:
    return verify_organic_assignment_manifest(
        value,
        sign_manifest(value, signer_keys()) if signatures is None else signatures,
        policy,
        state or build_initial_manifest_chain_state(policy),
        evaluation_epoch=at,
        current_finalized_height=FINALIZED_HEIGHT,
    )


@pytest.mark.parametrize("path", sorted(FROZEN_CONTRACT_DIGESTS))
def test_channel_contracts_are_frozen(path: str) -> None:
    payload = (ROOT / "contracts" / path).read_bytes()
    assert hashlib.sha256(payload).hexdigest() == FROZEN_CONTRACT_DIGESTS[path]


@pytest.mark.parametrize("stem", sorted(CHANNEL_CONTRACTS))
def test_channel_schema_is_generated_and_fixture_round_trips(stem: str) -> None:
    model, parser, serializer = CHANNEL_CONTRACTS[stem]
    schema = ROOT / "contracts" / "schemas" / f"{stem}.v1.schema.json"
    fixture = (ROOT / "contracts" / "fixtures" / f"{stem}.v1.json").read_bytes()
    assert schema.read_bytes() == schema_bytes(model)
    Draft202012Validator(json.loads(schema.read_text())).validate(json.loads(fixture))
    assert serializer(parser(fixture)) == fixture
    with pytest.raises(ValueError):
        parser(fixture.replace(b"}", b',"unknown":1}', 1))


def test_trust_policy_fixture_is_the_deterministic_test_policy() -> None:
    fixture = (ROOT / "contracts/fixtures/assignment-manifest-trust-policy.v1.json").read_bytes()
    assert assignment_manifest_trust_policy_bytes(build_policy(signer_keys())) == fixture


@pytest.mark.parametrize(
    ("at", "max_age", "code"),
    [
        (BASE_EPOCH - 100, 600, "manifest_future"),
        (BASE_EPOCH + 600, 600, "manifest_stale"),
        (BASE_EPOCH + 1_800, 3_000, "manifest_expired"),
        (BASE_EPOCH - 5_000, 600, "trust_policy_not_yet_valid"),
        (BASE_EPOCH + 100_000, 600, "trust_policy_expired"),
    ],
)
def test_freshness_and_policy_window_fail_closed(at: int, max_age: int, code: str) -> None:
    policy = build_policy(signer_keys(), max_age=max_age)
    assert_rejected(code, verify, manifest(policy), policy, at=at)


def test_lifetime_policy_binding_authority_and_route_policy_fail_closed() -> None:
    keys = signer_keys()
    policy = build_policy(keys)
    assert_rejected(
        "manifest_lifetime_invalid", verify, manifest(policy, expires_at=BASE_EPOCH + 3_600), policy
    )
    assert_rejected(
        "trust_policy_mismatch", verify, manifest(policy), build_policy(keys, threshold=1)
    )
    foreign = reseal(
        manifest(policy), central_authority_fingerprint_sha256=label_digest("other-authority")
    )
    assert_rejected("authority_mismatch", verify, foreign, policy)
    other_suffix = build_policy(keys, allowed_route_host_suffixes=("other.local",))
    assert_rejected("route_host_policy_violation", verify, manifest(other_suffix), other_suffix)


def test_signature_forgery_swap_untrusted_threshold_roles_and_key_windows() -> None:
    keys = signer_keys()
    policy = build_policy(keys)
    value = manifest(policy)
    signatures = sign_manifest(value, keys)

    def envelope(key_id: str, signature: bytes) -> AssignmentManifestSignatureEnvelope:
        return manifest_signature_envelope(
            value,
            signer_key_id=key_id,
            signature_base64=base64.b64encode(signature).decode("ascii"),
        )

    forged = bytearray(keys["auditor"].sign(organic_manifest_signature_message(value)))
    forged[0] ^= 0x01
    for code, attempt in (
        ("signature_invalid", [envelope("auditor", bytes(forged)), signatures[1]]),
        (
            "signature_invalid",
            [signatures[0], envelope("issuer", base64.b64decode(signatures[0].signature_base64))],
        ),
        (
            "signer_untrusted",
            [signatures[0], envelope("stranger", base64.b64decode(signatures[0].signature_base64))],
        ),
        (
            "signature_binding_mismatch",
            [
                signatures[0],
                signatures[1].model_copy(
                    update={"manifest_digest_sha256": label_digest("other-manifest")}
                ),
            ],
        ),
        ("signature_binding_mismatch", [signatures[0], signatures[0]]),
        ("threshold_not_met", [signatures[0]]),
    ):
        assert_rejected(code, verify, value, policy, attempt)

    def publication(key_ids: tuple[str, ...] = ("auditor", "issuer"), **changes: Any) -> Any:
        changed = build_policy(keys, **changes)
        signed = manifest(changed)
        return verify(signed, changed, sign_manifest(signed, keys, key_ids))

    assert_rejected("required_role_missing", publication, ("auditor", "security"))
    assert_rejected("signer_revoked", publication, revoked={"issuer": EVALUATION_EPOCH - 1})
    assert publication(revoked={"issuer": EVALUATION_EPOCH + 1}).verified_signer_key_ids == [
        "auditor",
        "issuer",
    ]
    assert_rejected(
        "signer_not_yet_valid",
        publication,
        key_windows={"issuer": (BASE_EPOCH - 50, BASE_EPOCH + 100_000)},
    )
    assert_rejected(
        "signer_expired",
        publication,
        key_windows={"issuer": (BASE_EPOCH - 1_000, BASE_EPOCH + 100)},
    )


def test_append_only_chain_rejects_rollback_gap_link_fork_and_divergence() -> None:
    keys = signer_keys()
    policy = build_policy(keys)
    first = manifest(policy)
    genesis = build_initial_manifest_chain_state(policy)
    state_one, reprobe = advance_manifest_header_chain_state(genesis, first, policy)
    assert reprobe is False

    def next_manifest(
        base: ActiveAssignmentManifestV2, sequence: int, **changes: Any
    ) -> ActiveAssignmentManifestV2:
        values: dict[str, Any] = {
            "sequence": sequence,
            "previous": base.manifest_digest_sha256,
            "issued_at": base.issued_at_epoch + 300,
            "expires_at": base.issued_at_epoch + 2_100,
            "finalized_height": base.finalized_height + 10,
            "finalized_block_hash": label_digest(f"block-{sequence}"),
            "finalized_epoch": base.finalized_epoch + 1,
        }
        values.update(changes)
        return manifest(policy, **values)

    second = next_manifest(first, 2)
    state_two, _ = advance_manifest_header_chain_state(state_one, second, policy)
    assert (state_two.last_sequence, state_two.accepted_manifest_count) == (2, 2)
    assert state_two.last_finalized_epoch == second.finalized_epoch

    replayed, reprobe = advance_manifest_header_chain_state(state_two, second, policy)
    assert reprobe is True and replayed == state_two
    for code, candidate, state in (
        ("sequence_rollback", first, state_two),
        (
            "same_sequence_divergence",
            next_manifest(first, 2, issued_at=BASE_EPOCH + 241),
            state_two,
        ),
        ("sequence_gap", next_manifest(second, 7), state_two),
        (
            "previous_link_mismatch",
            next_manifest(second, 3, previous=first.manifest_digest_sha256),
            state_two,
        ),
        (
            "finalized_height_rollback",
            next_manifest(second, 3, finalized_height=FINALIZED_HEIGHT + 9),
            state_two,
        ),
        (
            "same_height_fork",
            next_manifest(second, 3, finalized_height=second.finalized_height),
            state_two,
        ),
        (
            "same_height_fork",
            next_manifest(
                second,
                3,
                finalized_height=second.finalized_height,
                finalized_block_hash=second.finalized_block_hash,
                finalized_epoch=second.finalized_epoch + 1,
            ),
            state_two,
        ),
        (
            "finalized_epoch_rollback",
            next_manifest(second, 3, finalized_epoch=second.finalized_epoch - 1),
            state_two,
        ),
        (
            "issued_at_rollback",
            next_manifest(second, 3, issued_at=second.issued_at_epoch - 1),
            state_two,
        ),
        ("sequence_gap", second, genesis),
    ):
        assert_rejected(code, advance_manifest_header_chain_state, state, candidate, policy)

    gap_policy = build_policy(keys, max_finalized_height_gap=5)
    gap_first = manifest(gap_policy)
    gap_state, _ = advance_manifest_header_chain_state(
        build_initial_manifest_chain_state(gap_policy), gap_first, gap_policy
    )
    gap_second = manifest(
        gap_policy,
        sequence=2,
        previous=gap_first.manifest_digest_sha256,
        issued_at=BASE_EPOCH + 240,
        expires_at=BASE_EPOCH + 2_040,
        finalized_height=FINALIZED_HEIGHT + 6,
        finalized_block_hash=label_digest("block-gap"),
    )
    assert_rejected(
        "finalized_height_gap",
        advance_manifest_header_chain_state,
        gap_state,
        gap_second,
        gap_policy,
    )

    unsigned = genesis.model_dump(mode="json", by_alias=True, exclude={"state_digest_sha256"})
    unsigned["central_authority_fingerprint_sha256"] = label_digest("elsewhere")
    foreign_state = AssignmentManifestChainState.model_validate(
        {**unsigned, "state_digest_sha256": digest(unsigned)}
    )
    assert_rejected(
        "authority_mismatch", advance_manifest_header_chain_state, foreign_state, first, policy
    )


def boundary(operation: str, arguments: dict[str, object]) -> dict[str, object]:
    return execute({"arguments": arguments, "operation": operation, "protocol": BOUNDARY_PROTOCOL})


def test_boundary_keeps_the_channel_operations_and_refuses_retired_v1_ones() -> None:
    policy = build_policy(signer_keys())
    document = policy.model_dump(mode="json", by_alias=True)
    genesis = boundary("build_manifest_initial_state", {"trust_policy": document})["value"]
    assert genesis == build_initial_manifest_chain_state(policy).model_dump(
        mode="json", by_alias=True
    )
    for model, value in (
        ("assignment_manifest_trust_policy", document),
        ("assignment_manifest_chain_state", genesis),
    ):
        assert boundary("validate", {"model": model, "value": value})["value"] == value
    for operation in (
        "build_assigned_replica",
        "build_deployment_assignment",
        "build_assignment_manifest",
        "manifest_signature_message",
        "build_manifest_signature_envelope",
        # Producer-side operations moved to the private operator boundary.
        "build_checkpoint",
        "build_signature_envelope",
        "signature_message",
        "project_organic_route",
        "build_organic_deployment",
        "build_organic_manifest",
        "organic_manifest_signature_message",
        "build_organic_manifest_signature_envelope",
        "advance_manifest_state",
        "verify_manifest",
        "build_snapshot_replica",
        "build_snapshot_deployment",
        "build_assignment_snapshot",
        "project_snapshot_deployments",
        "verify_snapshot_succession",
        "verify_manifest_derived_from_snapshot",
        "build_manifest_latest_pointer",
        "verify_manifest_latest_pointer",
        "bind_latest_pointer_to_manifest",
        "rebind_manifest_state_trust_policy",
    ):
        with pytest.raises(ValueError, match="operation_invalid"):
            boundary(operation, {})
    for model in (
        "active_assignment_manifest",
        "active_assignment_snapshot",
        "assignment_manifest_latest_pointer",
    ):
        with pytest.raises(ValueError, match="model_invalid"):
            boundary("validate", {"model": model, "value": {}})


def _scan(module: str) -> tuple[set[str], set[str], str]:
    source = (ROOT / "src" / "misscomputer_subnet" / f"{module}.py").read_text()
    tree = ast.parse(source)
    imported_roots: set[str] = set()
    called_names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_roots.update(alias.name.split(".", maxsplit=1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            imported_roots.add(node.module.split(".", maxsplit=1)[0])
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                called_names.add(node.func.id)
            elif isinstance(node.func, ast.Attribute):
                called_names.add(node.func.attr)
    return imported_roots, called_names, source.lower()


@pytest.mark.parametrize(
    ("module", "allowed_imports"),
    [
        (
            "assignment_probe",
            {
                "__future__",
                "base64",
                "binascii",
                "collections",
                "cryptography",
                "dataclasses",
                "ed25519_trust",
                "hashlib",
                "json",
                "pydantic",
                "typing",
            },
        ),
        ("contract_codec", {"__future__", "collections", "hashlib", "json", "pydantic", "typing"}),
        (
            "validator_decision",
            {
                "__future__",
                "assignment_probe",
                "collections",
                "contract_codec",
                "dataclasses",
                "fractions",
                "organic_contracts",
                "organic_manifest",
                "organic_scoring",
                "pydantic",
                "typing",
            },
        ),
    ],
)
def test_manifest_and_decision_modules_are_pure_offline_cores(
    module: str, allowed_imports: set[str]
) -> None:
    imported_roots, called_names, lowered = _scan(module)
    assert imported_roots <= allowed_imports, imported_roots - allowed_imports
    assert not called_names & {
        "Popen",
        "connect",
        "create_subprocess_exec",
        "getenv",
        "monotonic",
        "now",
        "open",
        "request",
        "run",
        "set_weights",
        "sign",
        "submit",
        "system",
        "time",
        "urlopen",
        "write_bytes",
        "write_text",
    }
    for forbidden in (
        "ed25519privatekey",
        "import bittensor",
        "import datetime",
        "import httpx",
        "import os",
        "import random",
        "import requests",
        "import socket",
        "import subprocess",
        "import time",
        "os.environ",
        ".sign(",
        "wallet.",
        "token_hex",
    ):
        assert forbidden not in lowered, forbidden
