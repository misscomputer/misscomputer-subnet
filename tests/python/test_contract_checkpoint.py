# SPDX-License-Identifier: AGPL-3.0-only

"""Contract checkpoint v1: golden fixtures, negative fixtures, pins, and purity."""

from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from assignment_probe_context import challenge_value
from contract_checkpoint_context import (
    SCHEMA_MODELS,
    fixture_documents,
    negative_documents,
    schema_bytes,
)
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from misscomputer_subnet.assignment_snapshot import (
    LINEAGE_SCHEMA,
    SNAPSHOT_SCHEMA,
    ActiveAssignmentSnapshot,
    SnapshotLineage,
    advance_snapshot_lineage,
    build_initial_snapshot_lineage,
    parse_active_assignment_snapshot,
    parse_snapshot_lineage,
)
from misscomputer_subnet.manifest_publication import (
    LATEST_POINTER_SCHEMA,
    AssignmentManifestLatestPointer,
    parse_assignment_manifest_latest_pointer,
)
from misscomputer_subnet.validator_decision import (
    DECISION_SCHEMA,
    ValidatorWeightDecision,
    parse_validator_weight_decision,
)

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "contracts" / "fixtures"
SCHEMAS = ROOT / "contracts" / "schemas"
NEGATIVE = ROOT / "contracts" / "negative"
SOURCE = ROOT / "src" / "misscomputer_subnet"

PARSERS: dict[str, Any] = {
    "active-assignment-snapshot": parse_active_assignment_snapshot,
    "active-assignment-snapshot-lineage": parse_snapshot_lineage,
    "assignment-manifest-latest-pointer": parse_assignment_manifest_latest_pointer,
    "validator-weight-decision": parse_validator_weight_decision,
}

# The pre-existing manifest, probe, and weight-plan contracts are consumed by
# the private producer byte-for-byte. This checkpoint extends around them and
# must not move them; any change here is a compatibility event, not a fix.
# Every schema and every golden fixture of those families is pinned. The one
# declared compatibility event in this checkpoint is the chain state gaining
# ``last_finalized_epoch`` (see docs/contract-checkpoint-v1.md); its schema and
# fixture, and the probe-report fixture that carries a chain-state digest, are
# pinned at their post-change bytes.
FROZEN_CONTRACT_DIGESTS: dict[str, str] = {
    "schemas/active-assignment-manifest.v1.schema.json": (
        "9a4f4c1ebd5cf25c3ab7670579041c9b35093d5d3fc3fbd528bb13c38c4d4180"
    ),
    "schemas/assignment-manifest-trust-policy.v1.schema.json": (
        "85394d7eb8efc70b16146cb4eca2ac44eafad0d6be5dbdbb1d913af459fa3ab9"
    ),
    "schemas/assignment-manifest-signature-envelope.v1.schema.json": (
        "4545017e4a018b0c8eab812d2ae1a11826eea0b72cf700ca325a8a0eb6e4c7d5"
    ),
    "schemas/assignment-manifest-chain-state.v1.schema.json": (
        "a51d5253e047831d3a2e4e1bf5b8605086aa5bb4545fe7c339ac1929a384ad99"
    ),
    "schemas/miner-probe-attestation.v1.schema.json": (
        "a32d5fd52081ca9442fa393d3449102f852a0ebb18bd515f322377c08235b328"
    ),
    "schemas/validator-probe-report.v1.schema.json": (
        "29df0c5521ef1810339adf54e9197c522248921093d05b2e7540e7feb3f9da0b"
    ),
    "schemas/weight-plan.v1.schema.json": (
        "d4fa8861c0683a05796834952363498cbae8afd6c0a9c80b64ef3cf888445b53"
    ),
    "fixtures/active-assignment-manifest.v1.json": (
        "8d2ce1883d0081126af277266e48e38cfcabf6d4c89cd01fcc44a2eca9cb27ff"
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
    "fixtures/miner-probe-attestation.v1.json": (
        "9b6d1d70f09a1817df1acbe2c885493cd1a742ee3a0b5d0e95468e79eb5b8ce7"
    ),
    "fixtures/validator-probe-report.v1.json": (
        "b726a5ed9a160097244f669353080d53a9186ad05ce132806a02f0acd2e4f924"
    ),
    "fixtures/weight-plan.v1.json": (
        "c73297fd0c2ed35bcae2dec304d9e8e4c288d30f697026b3e43c143bc28a117c"
    ),
}


@pytest.mark.parametrize("stem", sorted(SCHEMA_MODELS))
def test_generated_schema_and_canonical_fixture_are_pinned(stem: str) -> None:
    schema = json.loads((SCHEMAS / f"{stem}.v1.schema.json").read_text())
    Draft202012Validator.check_schema(schema)
    fixture_bytes = (FIXTURES / f"{stem}.v1.json").read_bytes()
    Draft202012Validator(schema).validate(json.loads(fixture_bytes))
    parsed = PARSERS[stem](fixture_bytes)
    assert isinstance(parsed, SCHEMA_MODELS[stem])
    assert (SCHEMAS / f"{stem}.v1.schema.json").read_bytes() == schema_bytes(SCHEMA_MODELS[stem])
    assert fixture_bytes == fixture_documents()[stem]
    assert fixture_bytes.endswith(b"\n") and fixture_bytes.count(b"\n") == 1


@pytest.mark.parametrize(("path", "expected"), sorted(FROZEN_CONTRACT_DIGESTS.items()))
def test_pre_existing_contracts_are_untouched(path: str, expected: str) -> None:
    assert hashlib.sha256((ROOT / "contracts" / path).read_bytes()).hexdigest() == expected


#: Golden documents that share a contract's schema but pin a distinct scenario.
#: Each is regenerated by :func:`fixture_documents` and parsed by the primary
#: contract's parser; the Go suite round-trips the same bytes.
SUPPLEMENTARY_FIXTURES: dict[str, str] = {
    "active-assignment-snapshot-signer-skew": "active-assignment-snapshot",
}


@pytest.mark.parametrize(("stem", "contract"), sorted(SUPPLEMENTARY_FIXTURES.items()))
def test_supplementary_fixtures_are_pinned_and_schema_valid(stem: str, contract: str) -> None:
    schema = json.loads((SCHEMAS / f"{contract}.v1.schema.json").read_text())
    fixture_bytes = (FIXTURES / f"{stem}.v1.json").read_bytes()
    Draft202012Validator(schema).validate(json.loads(fixture_bytes))
    parsed = PARSERS[contract](fixture_bytes)
    assert isinstance(parsed, SCHEMA_MODELS[contract])
    assert fixture_bytes == fixture_documents()[stem]
    assert fixture_bytes.endswith(b"\n") and fixture_bytes.count(b"\n") == 1


def test_lineage_fixture_is_the_two_capture_history_of_the_snapshot_goldens() -> None:
    """The lineage golden is exactly genesis advanced over the golden and signer-skew captures."""

    golden = parse_active_assignment_snapshot(
        (FIXTURES / "active-assignment-snapshot.v1.json").read_bytes()
    )
    successor = parse_active_assignment_snapshot(
        (FIXTURES / "active-assignment-snapshot-signer-skew.v1.json").read_bytes()
    )
    lineage = parse_snapshot_lineage(
        (FIXTURES / "active-assignment-snapshot-lineage.v1.json").read_bytes()
    )
    genesis = build_initial_snapshot_lineage(
        central_authority_fingerprint_sha256=golden.central_authority_fingerprint_sha256
    )
    assert genesis.accepted_snapshot_count == 0 and genesis.replicas == []
    assert advance_snapshot_lineage(advance_snapshot_lineage(genesis, golden), successor) == lineage
    assert lineage.accepted_snapshot_count == 2
    assert (lineage.era, lineage.era_boundaries, lineage.history_start_snapshot_sequence) == (
        1,
        [],
        1,
    )
    first = advance_snapshot_lineage(genesis, golden)
    assert first.previous_lineage_digest_sha256 == genesis.lineage_digest_sha256
    assert lineage.previous_lineage_digest_sha256 == first.lineage_digest_sha256
    assert lineage.last_snapshot_digest_sha256 == successor.snapshot_digest_sha256
    assert lineage.last_snapshot_sequence == successor.snapshot_sequence
    assert {item.generation for item in lineage.replicas} == {2}
    # Both generations' facts are remembered: six retired plus six current.
    assert len(lineage.used_assignment_nonces) == 12
    assert len(lineage.used_ticket_digests) == 12 and len(lineage.used_receipt_digests) == 12
    assert all(
        item.assignment_nonce in lineage.used_assignment_nonces
        and item.ticket_digest_sha256 in lineage.used_ticket_digests
        and item.receipt_digest_sha256 in lineage.used_receipt_digests
        for item in lineage.replicas
    )
    assert all(
        replica.assignment_nonce in lineage.used_assignment_nonces
        for item in golden.deployments
        for replica in item.replicas
    )
    assert [item.replica_id for item in lineage.replicas] == sorted(
        replica.replica_id for item in golden.deployments for replica in item.replicas
    )


def test_every_checkpoint_fixture_on_disk_is_generated() -> None:
    """No stray golden document may sit beside a checkpoint contract's fixtures."""

    generated = set(fixture_documents())
    on_disk = {
        path.name.removesuffix(".v1.json")
        for stem in SCHEMA_MODELS
        for path in FIXTURES.glob(f"{stem}*.v1.json")
    }
    assert on_disk == generated
    assert set(SUPPLEMENTARY_FIXTURES) == generated - set(SCHEMA_MODELS)


def _negative_files() -> list[Path]:
    return sorted(NEGATIVE.rglob("*.json"))


EXPECTED_NEGATIVE_CASES: dict[str, set[str]] = {
    "active-assignment-snapshot": {
        "endpoint-incarnation-mismatch",
        "projected-vector-digest-mismatch",
        "replica-activated-after-capture",
        "replica-activated-before-ticket-skew",
        "replica-block-window-excludes-finalized-height",
        "replica-ticket-issued-beyond-capture-skew",
        "route-host-not-derived-from-suffix",
        "self-digest-mismatch",
        "unknown-field",
        "wrong-network",
    },
    "active-assignment-snapshot-lineage": {
        "chain-link-missing",
        "era-without-boundary",
        "genesis-with-history",
        "history-not-contiguous",
        "history-overclaimed",
        "replicas-not-canonical",
        "retired-facts-forgotten",
        "self-digest-mismatch",
        "unknown-field",
        "used-facts-not-canonical",
        "used-facts-overlap",
    },
    "assignment-manifest-latest-pointer": {
        "genesis-with-previous-link",
        "missing-signers",
        "object-key-not-content-addressed",
        "self-digest-mismatch",
        "unknown-field",
        "unsorted-signers",
    },
    "validator-weight-decision": {
        "abstain-with-plan-rows-digest",
        "guarded-drop-refreshes-baseline",
        "plan-rows-digest-mismatch",
        "prior-baseline-status-not-derived",
        "row-classification-not-derived",
        "self-digest-mismatch",
        "submit-with-epoch-behind-terminal",
        "submit-with-erased-first-seen",
        "submit-with-expired-block-lease",
        "submit-with-expired-terminal",
        "submit-with-expected-attributions-exceeding-opportunities",
        "submit-with-insufficient-rounds",
        "submit-with-late-first-seen",
        "submit-with-mass-drop",
        "submit-with-noncanonical-expected-attribution",
        "submit-with-observation-oversized-for-policy",
        "submit-with-observation-slower-than-policy-timeout",
        "submit-with-padded-terminal-count",
        "submit-with-pin-mismatch-under-unpinned-policy",
        "submit-with-positive-weight-below-min-attributions",
        "submit-with-positive-weight-without-attributions",
        "submit-with-positive-weight-without-serving-observations",
        "submit-with-registered-view-behind-terminal",
        "submit-with-rejected-terminal",
        "submit-with-replica-share-aggregation-mismatch",
        "submit-with-report-preceding-manifest-beyond-skew",
        "submit-with-report-probe-bounds-not-policy",
        "submit-with-rounds-exceeding-observations",
        "submit-with-same-height-fork",
        "submit-with-terminal-before-policy-validity",
        "submit-with-terminal-issued-beyond-skew",
        "submit-with-unavailable-terminal",
        "submit-with-undersampled-positive-row",
        "submit-with-undersampled-silent-row",
        "submit-with-unnormalized-weights",
        "submit-without-positive-evidence",
        "submit-without-verifying-trust-policy",
        "successor-baseline-not-derived",
        "terminal-before-close",
        "unknown-abstain-reason",
    },
}


def test_negative_fixture_inventory_is_complete() -> None:
    on_disk: dict[str, set[str]] = {}
    for path in _negative_files():
        on_disk.setdefault(path.parent.name.removesuffix(".v1"), set()).add(path.stem)
    assert on_disk == EXPECTED_NEGATIVE_CASES


def test_forged_submit_records_are_self_consistent_yet_rejected() -> None:
    """Every ``submit-with-*`` case carries valid digests; only the derived semantics reject it."""

    for path in _negative_files():
        if not path.stem.startswith("submit-with"):
            continue
        value = json.loads(path.read_bytes())
        document = value["document"]
        assert document["decision"] == "submit" and document["abstain_reasons"] == []
        unsigned = {k: v for k, v in document.items() if k != "decision_digest_sha256"}
        assert (
            document["decision_digest_sha256"]
            == hashlib.sha256(
                json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("ascii")
            ).hexdigest()
        )
        with pytest.raises(ValidationError, match=value["code"]):
            ValidatorWeightDecision.model_validate(document)


def test_negative_fixture_tree_is_pinned_and_canonical() -> None:
    on_disk = {
        path.relative_to(NEGATIVE).with_suffix("").as_posix(): path.read_bytes()
        for path in _negative_files()
    }
    assert on_disk == negative_documents()
    for rendered in on_disk.values():
        value = json.loads(rendered)
        assert set(value) == {"case", "code", "contract", "document", "expect", "schema_version"}
        assert value["schema_version"] == 1
        assert value["expect"] in {"model", "schema"}
        compact = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        assert rendered == compact.encode("ascii") + b"\n"


@pytest.mark.parametrize("path", _negative_files(), ids=lambda path: path.stem)
def test_negative_fixtures_are_rejected_for_the_pinned_reason(path: Path) -> None:
    value = json.loads(path.read_bytes())
    contract = value["contract"]
    assert path.parent.name == f"{contract}.v1"
    model = SCHEMA_MODELS[contract]
    schema = json.loads((SCHEMAS / f"{contract}.v1.schema.json").read_text())
    schema_valid = Draft202012Validator(schema).is_valid(value["document"])
    with pytest.raises(ValidationError) as failure:
        model.model_validate(value["document"])
    if value["expect"] == "schema":
        assert not schema_valid
        assert any(error["type"] == value["code"] for error in failure.value.errors())
    else:
        # The point of a model-level case: JSON Schema alone would accept it.
        assert schema_valid
        assert value["code"] in str(failure.value)
    rendered = json.dumps(
        value["document"], sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    with pytest.raises(ValueError):
        PARSERS[contract](rendered + b"\n")


@pytest.mark.parametrize(
    ("model", "expected_schema"),
    [
        (ActiveAssignmentSnapshot, SNAPSHOT_SCHEMA),
        (SnapshotLineage, LINEAGE_SCHEMA),
        (AssignmentManifestLatestPointer, LATEST_POINTER_SCHEMA),
        (ValidatorWeightDecision, DECISION_SCHEMA),
    ],
)
def test_checkpoint_contracts_are_extra_forbid_and_versioned(
    model: Any, expected_schema: str
) -> None:
    schema = model.model_json_schema()
    assert schema["additionalProperties"] is False
    assert schema["properties"]["schema"]["const"] == expected_schema
    assert schema["properties"]["schema_version"]["const"] == 1
    for definition in schema.get("$defs", {}).values():
        assert definition.get("additionalProperties") is False, definition.get("title")


def test_snapshot_fixture_carries_only_public_safe_facts() -> None:
    rendered = (FIXTURES / "active-assignment-snapshot.v1.json").read_bytes().decode("ascii")
    for forbidden in (
        "axon",
        "challenge_value",
        "credential",
        "encrypted_image_key",
        "manifest_key",
        "private",
        "provider",
        "receipt_json",
        "secret",
        "seed",
        "ticket_json",
        "tls",
        "token",
        "tunnel",
        "wallet",
        "weight",
    ):
        assert forbidden not in rendered.lower(), forbidden
    snapshot = parse_active_assignment_snapshot(rendered.encode("ascii"))
    for deployment in snapshot.deployments:
        assert challenge_value(deployment.deployment_id) not in rendered
        assert (
            hashlib.sha256(challenge_value(deployment.deployment_id).encode()).hexdigest()
            == deployment.challenge_sha256
        )


def _scan(module: str) -> tuple[set[str], set[str], str]:
    source = (SOURCE / f"{module}.py").read_text()
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
        ("contract_codec", {"__future__", "collections", "hashlib", "json", "pydantic", "typing"}),
        (
            "assignment_snapshot",
            {
                "__future__",
                "assignment_probe",
                "collections",
                "contract_codec",
                "ed25519_trust",
                "pydantic",
                "typing",
            },
        ),
        (
            "manifest_publication",
            {
                "__future__",
                "assignment_probe",
                "collections",
                "contract_codec",
                "dataclasses",
                "pydantic",
                "typing",
            },
        ),
        (
            "validator_decision",
            {
                "__future__",
                "assignment_probe",
                "collections",
                "contract_codec",
                "dataclasses",
                "fractions",
                "probe_scoring",
                "pydantic",
                "typing",
            },
        ),
    ],
)
def test_checkpoint_modules_are_pure_offline_cores(module: str, allowed_imports: set[str]) -> None:
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


def test_checkpoint_modules_are_discoverable_from_the_repository_root() -> None:
    for module in ("contract_codec", "assignment_snapshot", "manifest_publication"):
        assert (SOURCE / f"{module}.py").is_file()
    assert (SOURCE / "validator_decision.py").is_file()
    assert (ROOT / "docs" / "contract-checkpoint-v1.md").is_file()
