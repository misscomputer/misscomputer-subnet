# SPDX-License-Identifier: AGPL-3.0-only
"""Verifier-side boundary operations over retained ``deployment.v4`` routes.

The producer that turns a retained ticket and ready receipt into a public v2
route lives with the private operator boundary; its golden projection over
the Go-signed fixture ticket and receipt is committed under
``tests/python/fixtures/`` so the public boundary's verification operations
are still exercised against Go-signed inputs.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

import pytest
from assignment_probe_context import BASE_EPOCH, FINALIZED_HEIGHT, build_policy, signer_keys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from document_fixtures import (
    deployment_document,
    golden_route_projection,
    manifest_document,
    manifest_signature_envelope,
)

from misscomputer_subnet import checkpoint_boundary
from misscomputer_subnet import organic_contracts as oc
from misscomputer_subnet.contract_codec import model_document
from misscomputer_subnet.organic_manifest import organic_manifest_signature_message

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "contracts" / "fixtures"
VECTORS = json.loads((FIXTURES / "organic-contract-vectors.v1.json").read_bytes())
# Pinned by the Go ReceiptDigestV4 test over the same golden receipt.
GOLDEN_RECEIPT_DIGEST = "sha256:a0f5a1fd445a49c6709e64210ed618df211549c52562f0bf302258b05ef92e27"
LEASES = {
    "chain_block": FINALIZED_HEIGHT,
    "expires_at_block": FINALIZED_HEIGHT + 25,
    "activated_at_epoch": BASE_EPOCH - 120,
    "expires_at_epoch": BASE_EPOCH + 600,
}


def _key(name: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(VECTORS["keys"][name]["seed_hex"]))


def _golden() -> tuple[dict[str, Any], dict[str, Any]]:
    return (
        json.loads((FIXTURES / "deployment-ticket.v4.json").read_bytes()),
        json.loads((FIXTURES / "deployment-receipt.v4.json").read_bytes()),
    )


def _signed_ticket(document: dict[str, Any]) -> oc.DeploymentTicketV4:
    ticket = oc.DeploymentTicketV4.model_validate({**document, "signature": "0" * 128})
    signature = _key("validator_service").sign(oc.ticket_v4_signed_bytes(ticket)).hex()
    return ticket.model_copy(update={"signature": signature})


def _signed_receipt(document: dict[str, Any]) -> oc.DeploymentReceiptV4:
    receipt = oc.DeploymentReceiptV4.model_validate({**document, "signature": "0" * 128})
    signature = _key("miner_service").sign(oc.receipt_v4_signed_bytes(receipt)).hex()
    return receipt.model_copy(update={"signature": signature})


def _call(operation: str, **arguments: object) -> dict[str, Any]:
    request = {
        "arguments": arguments,
        "operation": operation,
        "protocol": checkpoint_boundary.PROTOCOL,
    }
    return checkpoint_boundary.execute(json.loads(json.dumps(request)))


def test_go_signed_ticket_and_receipt_verify_in_python() -> None:
    ticket_doc, receipt_doc = _golden()
    ticket = oc.DeploymentTicketV4.model_validate(ticket_doc)
    receipt = oc.DeploymentReceiptV4.model_validate(receipt_doc)
    oc.verify_ticket_v4_signature(ticket)
    oc.verify_receipt_v4_signature(receipt)
    assert oc.ticket_digest(ticket) == VECTORS["ticket"]["ticket_digest"]
    assert oc.receipt_digest(receipt) == GOLDEN_RECEIPT_DIGEST
    tampered = ticket.model_copy(update={"generation": 2})
    with pytest.raises(ValueError, match="ticket_signature_invalid"):
        oc.verify_ticket_v4_signature(tampered)
    with pytest.raises(ValueError, match="receipt_signature_invalid"):
        oc.verify_receipt_v4_signature(receipt.model_copy(update={"error": "x"}))


def test_go_html_escaping_is_reproduced() -> None:
    ticket_doc, _ = _golden()
    ticket_doc["health"]["response_marker"] = "<ok & ready>"
    rendered = oc.ticket_v4_signed_bytes(_signed_ticket(ticket_doc))
    assert b"\\u003cok \\u0026 ready\\u003e" in rendered
    assert b'"signature"' not in rendered


def test_boundary_verifies_a_v2_manifest_authored_from_golden_routes() -> None:
    ticket_doc, receipt_doc = _golden()
    keys = signer_keys()
    policy_model = build_policy(keys, allowed_route_host_suffixes=("on.miss.computer",))
    policy = model_document(policy_model)
    projection = golden_route_projection()
    replica = oc.OrganicAssignedReplica.model_validate(projection["replica"])
    assert replica.ticket_digest == oc.ticket_digest(
        oc.DeploymentTicketV4.model_validate(ticket_doc)
    )
    assert replica.receipt_digest == oc.receipt_digest(
        oc.DeploymentReceiptV4.model_validate(receipt_doc)
    )
    assert (replica.chain_block, replica.expires_at_block) == (
        LEASES["chain_block"],
        LEASES["expires_at_block"],
    )
    deployment = deployment_document(
        deployment_id=str(projection["deployment_id"]),
        route_host=str(projection["route_host"]),
        artifact_digest=str(projection["artifact_digest"]),
        health=oc.OrganicHealthProbe.model_validate(projection["health"]),
        replicas=[replica],
    )
    manifest_model = manifest_document(
        policy_model,
        finalized_height=FINALIZED_HEIGHT,
        finalized_block_hash="ab" * 32,
        finalized_epoch=42,
        sequence=1,
        previous_manifest_digest_sha256=None,
        issued_at_epoch=BASE_EPOCH - 60,
        expires_at_epoch=BASE_EPOCH + 300,
        route_host_suffix="on.miss.computer",
        probe_port=443,
        deployments=[deployment],
    )
    manifest = model_document(manifest_model)
    assert (
        _call("validate", model="active_assignment_manifest_v2", value=manifest)["value"]
        == manifest
    )
    message = organic_manifest_signature_message(manifest_model)
    assert message.startswith(
        b"miss.computer/misscomputer-subnet/active-assignment-manifest/v2/ed25519\x00"
    )
    envelopes = [
        model_document(
            manifest_signature_envelope(
                manifest_model,
                signer_key_id=key_id,
                signature_base64=base64.b64encode(keys[key_id].sign(message)).decode("ascii"),
            )
        )
        for key_id in ("auditor", "issuer")
    ]
    genesis = _call("build_manifest_initial_state", trust_policy=policy)["value"]
    verdict = _call(
        "verify_organic_manifest",
        manifest=manifest,
        signatures=envelopes,
        trust_policy=policy,
        prior_chain_state=genesis,
        evaluation_epoch=BASE_EPOCH,
        current_finalized_height=FINALIZED_HEIGHT,
    )
    assert verdict["verified_signer_key_ids"] == ["auditor", "issuer"]
    assert (
        verdict["next_chain_state"]["last_manifest_digest_sha256"]
        == manifest["manifest_digest_sha256"]
    )
    with pytest.raises(Exception, match="manifest_replica_lease_expired"):
        _call(
            "verify_organic_manifest",
            manifest=manifest,
            signatures=envelopes,
            trust_policy=policy,
            prior_chain_state=genesis,
            evaluation_epoch=BASE_EPOCH,
            current_finalized_height=LEASES["expires_at_block"],
        )
    v1_message = message.replace(b"/v2/", b"/v1/")
    with pytest.raises(Exception, match="signature"):
        _call(
            "verify_organic_manifest",
            manifest=manifest,
            signatures=[
                model_document(
                    manifest_signature_envelope(
                        manifest_model,
                        signer_key_id=key_id,
                        signature_base64=base64.b64encode(keys[key_id].sign(v1_message)).decode(
                            "ascii"
                        ),
                    )
                )
                for key_id in ("auditor", "issuer")
            ],
            trust_policy=policy,
            prior_chain_state=genesis,
            evaluation_epoch=BASE_EPOCH,
            current_finalized_height=FINALIZED_HEIGHT,
        )
