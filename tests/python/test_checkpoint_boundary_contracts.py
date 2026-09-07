# SPDX-License-Identifier: AGPL-3.0-only

"""Contract-checkpoint operations exposed through the canonical-file boundary."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from assignment_probe_context import EVALUATION_EPOCH, build_policy, make_context, signer_keys
from contract_checkpoint_context import build_snapshot

from misscomputer_subnet.checkpoint_boundary import PROTOCOL, execute

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "contracts" / "fixtures"


def document(value: Any) -> dict[str, Any]:
    return json.loads(json.dumps(value.model_dump(mode="json", by_alias=True)))


def call(operation: str, **arguments: Any) -> dict[str, Any]:
    return execute({"protocol": PROTOCOL, "operation": operation, "arguments": arguments})


def test_snapshot_operations_round_trip_through_the_boundary() -> None:
    snapshot = build_snapshot()
    fixture = json.loads((FIXTURES / "active-assignment-snapshot.v1.json").read_bytes())
    deployments = [
        call("build_snapshot_deployment", **_deployment_arguments(item))["value"]
        for item in fixture["deployments"]
    ]
    rebuilt = call(
        "build_assignment_snapshot",
        central_authority_fingerprint_sha256=fixture["central_authority_fingerprint_sha256"],
        snapshot_sequence=fixture["snapshot_sequence"],
        state_revision=fixture["state_revision"],
        captured_at_epoch=fixture["captured_at_epoch"],
        finalized_height=fixture["finalized_height"],
        finalized_block_hash=fixture["finalized_block_hash"],
        finalized_epoch=fixture["finalized_epoch"],
        route_host_suffix=fixture["route_host_suffix"],
        probe_port=fixture["probe_port"],
        deployments=deployments,
    )["value"]
    assert rebuilt == fixture == document(snapshot)
    manifest = make_context().manifest
    projected = call("project_snapshot_deployments", snapshot=fixture)["value"]
    assert projected == [document(item) for item in manifest.deployments]
    assert call(
        "verify_manifest_derived_from_snapshot", manifest=document(manifest), snapshot=fixture
    ) == {"value": True}
    successor = document(build_snapshot(snapshot_sequence=2, state_revision=8))
    assert call("verify_snapshot_succession", previous=fixture, current=successor) == {
        "value": True
    }
    with pytest.raises(ValueError, match="snapshot_sequence_not_increasing"):
        call("verify_snapshot_succession", previous=successor, current=fixture)
    assert call("validate", model="active_assignment_snapshot", value=fixture)["value"] == fixture


def _deployment_arguments(item: dict[str, Any]) -> dict[str, Any]:
    replicas = [
        call(
            "build_snapshot_replica",
            deployment_id=item["deployment_id"],
            **{
                key: replica[key]
                for key in (
                    "miner_uid",
                    "miner_hotkey",
                    "miner_service_public_key",
                    "generation",
                    "assignment_nonce",
                    "ticket_digest_sha256",
                    "receipt_digest_sha256",
                    "chain_block",
                    "expires_at_block",
                    "ticket_issued_at_epoch",
                    "ticket_expires_at_epoch",
                    "route_activated_at_epoch",
                )
            },
        )["value"]
        for replica in item["replicas"]
    ]
    return {
        "deployment_id": item["deployment_id"],
        "campaign_sequence": item["campaign_sequence"],
        "route_host": item["route_host"],
        "build_id": item["build_id"],
        "challenge_sha256": item["challenge_sha256"],
        "image_digest": item["image_digest"],
        "workload_spec_digest_sha256": item["workload_spec_digest_sha256"],
        "attestation_requirement": item["attestation_requirement"],
        "replicas": replicas,
    }


def test_publication_operations_round_trip_through_the_boundary() -> None:
    context = make_context()
    manifest = document(context.manifest)
    signatures = [document(item) for item in context.signatures]
    pointer = call("build_manifest_latest_pointer", manifest=manifest, signatures=signatures)[
        "value"
    ]
    assert pointer == json.loads(
        (FIXTURES / "assignment-manifest-latest-pointer.v1.json").read_bytes()
    )
    genesis = call("build_manifest_initial_state", trust_policy=document(context.policy))["value"]
    verdict = call(
        "verify_manifest_latest_pointer",
        pointer=pointer,
        trust_policy=document(context.policy),
        prior_chain_state=genesis,
        evaluation_epoch=EVALUATION_EPOCH,
    )
    assert verdict == {
        "history_depth": 0,
        "manifest_object_key": pointer["manifest_object_key"],
        "reprobe": False,
        "signature_object_keys": [
            f"v1/manifests/{pointer['manifest_digest_sha256']}.auditor.signature.json",
            f"v1/manifests/{pointer['manifest_digest_sha256']}.issuer.signature.json",
        ],
    }
    assert call(
        "bind_latest_pointer_to_manifest",
        pointer=pointer,
        manifest=manifest,
        signatures=signatures,
    ) == {"value": True}
    with pytest.raises(ValueError, match="pointer_signature_mismatch"):
        call(
            "bind_latest_pointer_to_manifest",
            pointer=pointer,
            manifest=manifest,
            signatures=signatures[:1],
        )
    accepted = document(context.verification.next_chain_state)
    successor = build_policy(signer_keys(), threshold=1)
    rebound = call(
        "rebind_manifest_state_trust_policy",
        state=accepted,
        current_trust_policy=document(context.policy),
        next_trust_policy=document(successor),
        evaluation_epoch=EVALUATION_EPOCH,
    )["value"]
    assert rebound["trust_policy_digest_sha256"] == successor.trust_policy_digest_sha256
    assert rebound["last_sequence"] == 1
    assert (
        call("validate", model="assignment_manifest_latest_pointer", value=pointer)["value"]
        == pointer
    )
    with pytest.raises(ValueError, match="operation_invalid"):
        call("decide_weight_submission")


def test_verify_manifest_boundary_requires_and_enforces_the_finalized_height() -> None:
    """The shipped boundary cannot omit or ignore the block-lease check."""

    context = make_context()
    manifest = document(context.manifest)
    signatures = [document(item) for item in context.signatures]
    genesis = call("build_manifest_initial_state", trust_policy=document(context.policy))["value"]
    earliest = min(
        replica["expires_at_block"]
        for item in manifest["deployments"]
        for replica in item["replicas"]
    )
    arguments = {
        "manifest": manifest,
        "signatures": signatures,
        "trust_policy": document(context.policy),
        "prior_chain_state": genesis,
        "evaluation_epoch": EVALUATION_EPOCH,
    }
    with pytest.raises(ValueError, match="current_finalized_height_required"):
        call("verify_manifest", **arguments)
    verified = call("verify_manifest", **arguments, current_finalized_height=earliest - 1)
    assert verified["next_chain_state"]["last_sequence"] == 1
    assert verified["reprobe"] is False
    with pytest.raises(ValueError, match="manifest_replica_lease_expired"):
        call("verify_manifest", **arguments, current_finalized_height=earliest)
    with pytest.raises(ValueError, match="current_finalized_height_invalid"):
        call("verify_manifest", **arguments, current_finalized_height="soon")
    with pytest.raises(ValueError, match="current_finalized_height_invalid"):
        call("verify_manifest", **arguments, current_finalized_height=None)
