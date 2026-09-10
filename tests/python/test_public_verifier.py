# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import ast
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from assignment_probe_context import sign_manifest
from contract_checkpoint_context import (
    REGISTERED_HEIGHT,
    WINDOW_END,
    make_window_context,
    metagraph_view,
)
from pydantic import ValidationError

from misscomputer_subnet.assignment_probe import ActiveAssignmentManifest, AssignmentProbeError
from misscomputer_subnet.contract_codec import digest
from misscomputer_subnet.manifest_publication import (
    ManifestHistoryEntry,
    ManifestPublicationError,
    build_manifest_latest_pointer,
)
from misscomputer_subnet.public_verifier import (
    MAX_PUBLIC_HISTORY_ENTRIES,
    PublicVerifierError,
    verify_public_relay_path,
)
from misscomputer_subnet.validator_decision import ValidatorWeightDecision
from misscomputer_subnet.weight_plan import WEIGHT_PLAN_PROTOCOL_VERSION_KEY

ROOT = Path(__file__).resolve().parents[2]


def integration_inputs() -> dict[str, Any]:
    context = make_window_context()
    one, two, three = context.manifests
    signatures_two = tuple(sign_manifest(two, context.keys))
    signatures_three = tuple(sign_manifest(three, context.keys))
    return {
        "trust_policy": context.policy,
        "prior_chain_state": context.states[1],
        "latest_pointer": build_manifest_latest_pointer(three, signatures_three),
        "history": (
            ManifestHistoryEntry(
                pointer=build_manifest_latest_pointer(two, signatures_two),
                manifest=two,
                signatures=signatures_two,
            ),
        ),
        "head_manifest": three,
        "head_signatures": signatures_three,
        "evaluation_epoch": WINDOW_END,
        "current_finalized_height": REGISTERED_HEIGHT,
        "decision": context.decision,
        "finalized_metagraph": metagraph_view(),
        "finalized_block_hash": context.registered.finalized_block_hash,
    }


def test_synthetic_end_to_end_catch_up_verification_and_dry_run_plan() -> None:
    values = integration_inputs()
    first = verify_public_relay_path(**values)
    second = verify_public_relay_path(**values)

    assert first == second
    assert first.history_entries_replayed == 1
    assert first.manifest_verification.next_chain_state.last_sequence == 3
    assert first.manifest_verification.next_chain_state.last_manifest_digest_sha256 == (
        first.decision.terminal_manifest_digest_sha256
    )
    assert first.decision.decision == "submit"
    assert first.weight_plan.version_key == WEIGHT_PLAN_PROTOCOL_VERSION_KEY
    assert first.weight_plan.snapshot.block == REGISTERED_HEIGHT
    assert first.weight_plan.snapshot.finalized is True
    assert first.weight_plan.validator_hotkey == first.decision.validator_hotkey
    assert {entry.hotkey for entry in first.weight_plan.weights} == {
        "MinerA",
        "MinerB",
        "MinerC",
        "MinerD",
        "MinerE",
    }
    # A WeightPlan is inert data: the integrated result exposes no executor,
    # signer, wallet, RPC, submission, domain, or workload operation.
    assert not {
        "execute",
        "sign",
        "submit",
        "wallet",
        "rpc",
        "create_domain",
        "create_workload",
    } & set(dir(first))


def test_restart_from_caught_up_state_is_an_exact_reprobe() -> None:
    values = integration_inputs()
    first = verify_public_relay_path(**values)
    values["prior_chain_state"] = first.manifest_verification.next_chain_state
    values["history"] = ()

    restarted = verify_public_relay_path(**values)
    assert restarted.history_entries_replayed == 0
    assert restarted.manifest_verification.reprobe is True
    assert restarted.manifest_verification.next_chain_state == (
        first.manifest_verification.next_chain_state
    )
    assert restarted.weight_plan.digest_sha256 == first.weight_plan.digest_sha256


def test_history_is_required_bounded_and_cannot_be_replayed_on_direct_head() -> None:
    values = integration_inputs()
    values["history"] = ()
    with pytest.raises(PublicVerifierError, match="^history_required$"):
        verify_public_relay_path(**values)

    values = integration_inputs()
    values["history"] = values["history"] * (MAX_PUBLIC_HISTORY_ENTRIES + 1)
    with pytest.raises(PublicVerifierError, match="^history_resource_limit$"):
        verify_public_relay_path(**values)

    values = integration_inputs()
    context = make_window_context()
    values["prior_chain_state"] = context.states[2]
    with pytest.raises(PublicVerifierError, match="^history_unexpected$"):
        verify_public_relay_path(**values)


def test_fork_equivocation_and_broken_history_fail_before_plan() -> None:
    values = integration_inputs()
    history = values["history"][0]
    manifest_document = history.manifest.model_dump(mode="json", by_alias=True)
    manifest_document["finalized_block_hash"] = "f" * 64
    manifest_document.pop("manifest_digest_sha256")
    manifest_document["manifest_digest_sha256"] = digest(manifest_document)
    fork = ActiveAssignmentManifest.model_validate(manifest_document)
    values["history"] = (
        ManifestHistoryEntry(
            pointer=history.pointer,
            manifest=fork,
            signatures=history.signatures,
        ),
    )
    with pytest.raises(ManifestPublicationError, match="^history_pointer_mismatch$"):
        verify_public_relay_path(**values)

    values = integration_inputs()
    head = values["head_manifest"]
    head_document = head.model_dump(mode="json", by_alias=True)
    head_document["previous_manifest_digest_sha256"] = "e" * 64
    head_document.pop("manifest_digest_sha256")
    head_document["manifest_digest_sha256"] = digest(head_document)
    relinked = ActiveAssignmentManifest.model_validate(head_document)
    values["head_manifest"] = relinked
    with pytest.raises(ManifestPublicationError, match="^pointer_manifest_mismatch$"):
        verify_public_relay_path(**values)


def test_stale_expired_lease_and_finalized_height_relabel_fail_closed() -> None:
    values = integration_inputs()
    values["evaluation_epoch"] = values["head_manifest"].expires_at_epoch
    with pytest.raises(ManifestPublicationError, match="^pointer_expired$"):
        verify_public_relay_path(**values)

    values = integration_inputs()
    lease_expiry = min(
        replica.expires_at_block
        for deployment in values["head_manifest"].deployments
        for replica in deployment.replicas
    )
    values["current_finalized_height"] = lease_expiry
    values["finalized_metagraph"] = replace(metagraph_view(), block=lease_expiry)
    with pytest.raises(AssignmentProbeError, match="^manifest_replica_lease_expired$"):
        verify_public_relay_path(**values)

    values = integration_inputs()
    values["current_finalized_height"] = REGISTERED_HEIGHT - 1
    with pytest.raises(PublicVerifierError, match="^finalized_height_mismatch$"):
        verify_public_relay_path(**values)


def test_decision_relabel_and_terminal_substitution_are_rejected() -> None:
    values = integration_inputs()
    decision = values["decision"]
    document = decision.model_dump(mode="json", by_alias=True)
    document["terminal_manifest_digest_sha256"] = "f" * 64
    document.pop("decision_digest_sha256")
    document["decision_digest_sha256"] = digest(document)
    with pytest.raises(ValidationError):
        ValidatorWeightDecision.model_validate(document)

    context = make_window_context()
    values["decision"] = context.decision.model_copy(
        update={"terminal_manifest_digest_sha256": context.manifests[1].manifest_digest_sha256}
    )
    with pytest.raises(ValidationError):
        verify_public_relay_path(**values)


def test_public_verifier_source_has_no_mutating_or_secret_capability() -> None:
    source = (ROOT / "src/misscomputer_subnet/public_verifier.py").read_text()
    tree = ast.parse(source)
    imported = {
        node.module.split(".")[-1]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    }
    called = {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    assert not imported & {
        "bittensor",
        "chain",
        "os",
        "socket",
        "subprocess",
        "weight_executor",
    }
    assert not called & {"connect", "execute", "sign", "set_weights", "submit", "write_bytes"}
    lowered = source.lower()
    for forbidden in (
        "privatekey",
        "os.environ",
        "import bittensor",
        "import socket",
        "import subprocess",
        ".sign(",
        "set_weights",
    ):
        assert forbidden not in lowered
