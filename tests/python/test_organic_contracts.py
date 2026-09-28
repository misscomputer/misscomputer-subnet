# SPDX-License-Identifier: AGPL-3.0-only

"""Public miner/verifier contracts: schemas, goldens, negatives and signatures."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import bittensor as bt
import pytest
from jsonschema import Draft202012Validator
from organic_contract_context import generated_tree
from pydantic import ValidationError

from misscomputer_subnet import organic_contracts as oc

CONTRACTS = Path(__file__).resolve().parents[2] / "contracts"
TREE = generated_tree()
VECTORS: dict[str, Any] = json.loads(TREE["fixtures/organic-contract-vectors.v1.json"])


def _fixture(stem: str) -> bytes:
    return (CONTRACTS / "fixtures" / f"{stem}.json").read_bytes()


def test_committed_organic_contract_tree_is_exactly_the_generated_tree() -> None:
    on_disk = {
        path.relative_to(CONTRACTS).as_posix(): path.read_bytes()
        for path in CONTRACTS.rglob("*.json")
        if path.relative_to(CONTRACTS).as_posix() in TREE
    }
    assert on_disk == TREE


@pytest.mark.parametrize("stem", sorted(oc.CONTRACT_MODELS))
def test_golden_fixture_satisfies_schema_and_model(stem: str) -> None:
    schema = json.loads((CONTRACTS / "schemas" / f"{stem}.schema.json").read_bytes())
    Draft202012Validator.check_schema(schema)
    rendered = _fixture(stem)
    Draft202012Validator(schema).validate(json.loads(rendered))
    model = oc.parse_canonical_document(rendered, oc.CONTRACT_MODELS[stem])
    assert oc.document_bytes(model) == rendered


NEGATIVE = sorted((CONTRACTS / "negative").glob("*/*.json"))
ORGANIC_NEGATIVE = [path for path in NEGATIVE if path.parent.name in oc.CONTRACT_MODELS]


@pytest.mark.parametrize(
    "path", ORGANIC_NEGATIVE, ids=lambda path: path.parent.name + "/" + path.stem
)
def test_negative_fixture_is_rejected_for_its_pinned_reason(path: Path) -> None:
    value = json.loads(path.read_bytes())
    assert value["contract"] == path.parent.name and value["case"] == path.stem
    schema = json.loads((CONTRACTS / "schemas" / f"{value['contract']}.schema.json").read_bytes())
    schema_valid = Draft202012Validator(schema).is_valid(value["document"])
    with pytest.raises(ValidationError) as failure:
        oc.CONTRACT_MODELS[value["contract"]].model_validate(value["document"])
    if value["expect"] == "schema":
        assert not schema_valid
        assert value["code"] in {error["type"] for error in failure.value.errors()}
    else:
        assert schema_valid, "a model-level case must be one JSON Schema alone accepts"
        assert value["code"] in str(failure.value)


def test_artifact_manifest_is_bound_to_its_exact_bytes() -> None:
    rendered = _fixture("artifact-manifest.v2")
    expected = VECTORS["artifact_manifest"]
    manifest = oc.parse_artifact_manifest(rendered, expected["artifact_digest"])
    assert oc.artifact_digest(oc.artifact_manifest_bytes(manifest)) == expected["artifact_digest"]
    assert oc.manifest_key(expected["artifact_digest"]) == expected["manifest_key"]
    pretty = json.dumps(json.loads(rendered), indent=1, sort_keys=True).encode("ascii") + b"\n"
    with pytest.raises(ValueError, match="document_not_canonical"):
        oc.parse_artifact_manifest(pretty)
    with pytest.raises(ValueError, match="artifact_digest_mismatch"):
        oc.parse_artifact_manifest(rendered, "sha256:" + "0" * 64)


def _edge_request(**changes: object) -> oc.EdgeRuntimeRequest:
    document = json.loads(_fixture("edge-runtime-request.v1"))
    return oc.EdgeRuntimeRequest.model_validate({**document, **changes})


def test_edge_runtime_signature_verifies_only_fresh_unmodified_requests() -> None:
    vector = VECTORS["edge_runtime_request"]
    key = VECTORS["keys"]["validator_service"]["public_key_hex"]
    request = _edge_request()
    header = vector["header_value"]
    assert header == oc.edge_authorization_header_value(request, vector["signature_hex"])
    oc.verify_edge_runtime_request(request, header, key, request.timestamp + 10_000_000_000)
    oc.verify_edge_runtime_request(request, header, key, request.timestamp - 2_000_000_000)
    for now in (request.timestamp + 10_000_000_001, request.timestamp - 2_000_000_001):
        with pytest.raises(ValueError, match="edge_authorization_stale"):
            oc.verify_edge_runtime_request(request, header, key, now)
    for changed in (
        _edge_request(query="page=3&sort=desc"),
        _edge_request(method="PUT"),
        _edge_request(body_sha256="0" * 64),
        _edge_request(path="/api/items/other"),
    ):
        with pytest.raises(ValueError, match="edge_authorization_invalid"):
            oc.verify_edge_runtime_request(changed, header, key, request.timestamp)


def test_probe_authorization_is_signed_by_the_validator_hotkey() -> None:
    authorization = oc.OrganicProbeAuthorization.model_validate_json(
        _fixture("organic-probe-authorization.v1")
    )
    message = oc.organic_probe_message(authorization)
    assert message.hex() == VECTORS["organic_probe_authorization"]["message_hex"]
    signature = bytes.fromhex(authorization.signature)
    assert bt.sp_core.verify(message, signature, authorization.validator_hotkey)
    moved = authorization.model_copy(update={"path": "/admin"})
    assert not bt.sp_core.verify(
        oc.organic_probe_message(moved), signature, VECTORS["keys"]["validator_hotkey_ss58"]
    )


def test_probe_attestation_v2_verifies_only_under_the_miner_service_key() -> None:
    attestation = oc.MinerProbeAttestationV2.model_validate_json(
        _fixture("miner-probe-attestation.v2")
    )
    keys = VECTORS["keys"]
    oc.verify_miner_probe_attestation_v2(attestation, keys["miner_service"]["public_key_hex"])
    with pytest.raises(ValueError, match="attestation_signature_invalid"):
        oc.verify_miner_probe_attestation_v2(
            attestation, keys["validator_service"]["public_key_hex"]
        )
    with pytest.raises(ValueError, match="attestation_signature_invalid"):
        oc.verify_miner_probe_attestation_v2(
            attestation.model_copy(update={"response_status": 503}),
            keys["miner_service"]["public_key_hex"],
        )
    ticket = oc.DeploymentTicketV4.model_validate_json(_fixture("deployment-ticket.v4"))
    assert (
        attestation.ticket_digest == oc.ticket_digest(ticket) == VECTORS["ticket"]["ticket_digest"]
    )


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (datetime(2026, 9, 26, 0, 14, 6, 120000, tzinfo=UTC), "2026-09-26T00:14:06.12Z"),
        (datetime(2026, 9, 26, 0, 14, 6, tzinfo=UTC), "2026-09-26T00:14:06Z"),
        (
            datetime(2026, 9, 26, 2, 14, 6, 1, tzinfo=timezone(timedelta(hours=2))),
            "2026-09-26T00:14:06.000001Z",
        ),
    ],
)
def test_public_timestamp_rendering_matches_go(value: datetime, expected: str) -> None:
    rendered = oc.format_timestamp(value)
    assert rendered == expected
