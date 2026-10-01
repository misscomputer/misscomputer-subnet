# SPDX-License-Identifier: AGPL-3.0-only

"""Public static-site-v1 contracts: schemas, goldens, negatives and signatures."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jsonschema import Draft202012Validator
from pydantic import ValidationError
from static_contract_context import generated_tree

from misscomputer_subnet import organic_contracts as oc
from misscomputer_subnet import static_contracts as sc
from misscomputer_subnet.contract_codec import canonical_json, model_document

CONTRACTS = Path(__file__).resolve().parents[2] / "contracts"
TREE = generated_tree()
VECTORS: dict[str, Any] = json.loads(TREE["fixtures/static-contract-vectors.v1.json"])


def _fixture(stem: str) -> bytes:
    return (CONTRACTS / "fixtures" / f"{stem}.json").read_bytes()


def test_committed_static_contract_tree_is_exactly_the_generated_tree() -> None:
    on_disk = {
        path.relative_to(CONTRACTS).as_posix(): path.read_bytes()
        for path in CONTRACTS.rglob("*.json")
        if path.relative_to(CONTRACTS).as_posix() in TREE
    }
    assert on_disk == TREE
    committed_negatives = {
        path.relative_to(CONTRACTS).as_posix()
        for path in CONTRACTS.glob("negative/static-*/*.json")
    }
    assert committed_negatives == {name for name in TREE if name.startswith("negative/")}


@pytest.mark.parametrize("stem", sorted(sc.STATIC_CONTRACT_MODELS))
def test_static_golden_satisfies_schema_and_model(stem: str) -> None:
    schema = json.loads((CONTRACTS / "schemas" / f"{stem}.schema.json").read_bytes())
    Draft202012Validator.check_schema(schema)
    rendered = _fixture(stem)
    Draft202012Validator(schema).validate(json.loads(rendered))
    model = oc.parse_canonical_document(rendered, sc.STATIC_CONTRACT_MODELS[stem])
    assert oc.document_bytes(model) == rendered
    # Every wire dump (bridge and dendrite bodies) keeps the ``schema`` name.
    assert json.loads(rendered) == model.model_dump(mode="json")


STATIC_NEGATIVE = sorted(CONTRACTS.glob("negative/static-*/*.json"))


@pytest.mark.parametrize(
    "path", STATIC_NEGATIVE, ids=lambda path: path.parent.name + "/" + path.stem
)
def test_static_negative_is_rejected_for_its_pinned_reason(path: Path) -> None:
    value = json.loads(path.read_bytes())
    schema = json.loads((CONTRACTS / "schemas" / f"{value['contract']}.schema.json").read_bytes())
    schema_valid = Draft202012Validator(schema).is_valid(value["document"])
    with pytest.raises(ValidationError) as failure:
        sc.STATIC_CONTRACT_MODELS[value["contract"]].model_validate(value["document"])
    if value["expect"] == "schema":
        assert not schema_valid
        assert value["code"] in {error["type"] for error in failure.value.errors()}
    else:
        assert schema_valid, "a model-level case must be one JSON Schema alone accepts"
        assert value["code"] in str(failure.value)


def test_site_manifest_identity_is_the_contract_worked_example() -> None:
    rendered = _fixture("static-site-manifest.v1")
    # Static-site contract §3.5 publishes these exact values.
    assert len(rendered) == 861
    expected = "sha256:9db3b2a4b3f18c1d31fd7d3348f83e1dfde21163d5aca540fd2f63d6b88ab77f"
    assert VECTORS["site_manifest"]["site_digest"] == expected
    manifest = sc.parse_static_site_manifest(rendered, expected)
    assert sc.static_site_manifest_bytes(manifest) == rendered
    with pytest.raises(ValueError, match="static_verify_failed"):
        sc.parse_static_site_manifest(rendered, "sha256:" + "0" * 64)
    pretty = json.dumps(json.loads(rendered), indent=1, sort_keys=True).encode("ascii") + b"\n"
    with pytest.raises(ValueError):
        sc.parse_static_site_manifest(pretty, sc.site_digest(pretty))


@pytest.mark.parametrize(
    ("raw", "valid"),
    [
        ("/", True),
        ("/docs/", True),
        ("/caf%C3%A9", True),
        ("/index.html/", True),
        ("/%69ndex.html", False),
        ("/a%2Fb", False),
        ("/a%2fb", False),
        ("/../index.html", False),
        ("/./index.html", False),
        ("/%2E%2E/", False),
        ("//index.html", False),
        ("/a%5Cb", False),
        ("/%00", False),
        ("/%7F", False),
        ("/a|b", False),
        ("/caf%c3%a9", False),
        ("/100%", False),
        ("/" + "/".join(["a" * 204] * 5), False),
        ("/" + "/".join(["a" * 204] * 5)[:-1], True),
        ("/a" * 33, False),
    ],
)
def test_request_path_normalization_matches_the_contract_vectors(raw: str, valid: bool) -> None:
    assert sc.valid_request_path(raw) is valid


def _sign(seed_hex: str, message: bytes) -> str:
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex)).sign(message).hex()


def test_static_signatures_are_domain_separated_and_bound_to_the_ticket() -> None:
    ticket = sc.StaticDeploymentTicketV1.model_validate_json(
        _fixture("static-deployment-ticket.v1")
    )
    receipt = sc.StaticDeploymentReceiptV1.model_validate_json(
        _fixture("static-deployment-receipt.v1")
    )
    sc.verify_static_ticket_signature(ticket)
    sc.verify_static_receipt_signature(receipt)
    sc.static_receipt_answers_ticket(ticket, receipt)
    assert sc.static_ticket_digest(ticket) == VECTORS["ticket"]["ticket_digest"]
    assert sc.static_receipt_digest(receipt) == VECTORS["receipt"]["receipt_digest"]
    validator_seed = VECTORS["keys"]["validator_service"]["seed_hex"]
    unsigned = canonical_json(model_document(ticket, exclude={"signature"}))
    for message in (unsigned, sc.RECEIPT_SIGNING_DOMAIN + b"\x00" + unsigned):
        forged = ticket.model_copy(update={"signature": _sign(validator_seed, message)})
        with pytest.raises(ValueError, match="static_ticket_signature_invalid"):
            sc.verify_static_ticket_signature(forged)
    moved = ticket.model_copy(update={"site_digest": "sha256:" + "0" * 64})
    with pytest.raises(ValueError, match="static_ticket_signature_invalid"):
        sc.verify_static_ticket_signature(moved)
    other = receipt.model_copy(update={"ticket_digest": "sha256:" + "0" * 64})
    with pytest.raises(ValueError, match="static_receipt_does_not_answer_ticket"):
        sc.static_receipt_answers_ticket(ticket, other)


def test_deployment_v4_decoders_reject_static_documents() -> None:
    # Old peers reject static work neutrally: no v3/v4 decoder accepts it.
    with pytest.raises(ValueError):
        oc.parse_document(_fixture("static-deployment-ticket.v1"), oc.DeploymentTicketV4)
    with pytest.raises(ValueError):
        oc.parse_document(_fixture("static-deploy.v1"), oc.DeploySynapseV3)
    with pytest.raises(ValueError):
        oc.parse_document(_fixture("static-bridge-assign.v1"), oc.BridgeAssignRequestV3)
