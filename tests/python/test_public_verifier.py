# SPDX-License-Identifier: AGPL-3.0-only
"""Third-party verification of an organic validator's weight preparation."""

from __future__ import annotations

import ast
import copy
from pathlib import Path
from typing import Any

import pytest
from assignment_probe_context import signer_keys
from organic_context import (
    EPOCH,
    EPOCH_SECONDS,
    EPOCH_START,
    REGISTERED_HEIGHT,
    SHOP,
    WINDOW_END,
    decide,
    endpoint,
    epoch_probes,
    make_window_context,
    metagraph_snapshot,
    probe,
    sign_manifest,
)

from misscomputer_subnet.assignment_probe import (
    AssignmentProbeError,
    build_initial_manifest_chain_state,
)
from misscomputer_subnet.organic_scoring import score_organic_epoch
from misscomputer_subnet.public_verifier import (
    PUBLIC_EVALUATION_TOLERANCE_SECONDS,
    PublicVerifierError,
    verify_public_relay_path,
)
from misscomputer_subnet.weight_plan import WEIGHT_PLAN_PROTOCOL_VERSION_KEY

ROOT = Path(__file__).resolve().parents[2]


def integration_inputs() -> dict[str, Any]:
    context = make_window_context()
    return {
        "trust_policy": context.policy,
        "prior_chain_state": build_initial_manifest_chain_state(context.policy),
        "head_manifest": context.manifest,
        "head_signatures": tuple(sign_manifest(context.manifest, signer_keys())),
        "evaluation_epoch": WINDOW_END,
        "current_finalized_height": REGISTERED_HEIGHT,
        "decision": context.decision,
        "retained_epoch_records": tuple(context.epochs),
        "finalized_metagraph": metagraph_snapshot(),
        "finalized_block_hash": context.registered.finalized_block_hash,
    }


def test_end_to_end_verification_yields_a_dry_run_plan_and_the_next_state() -> None:
    values = integration_inputs()
    result = verify_public_relay_path(**values)
    assert result.decision.decision == "submit"
    assert result.weight_plan.version_key == WEIGHT_PLAN_PROTOCOL_VERSION_KEY
    assert {entry.hotkey for entry in result.weight_plan.weights} == {"MinerA", "MinerB", "MinerC"}
    state = result.manifest_verification.next_chain_state
    assert state.last_manifest_digest_sha256 == values["head_manifest"].manifest_digest_sha256
    # Restarting from the accepted state is an exact re-probe of the same head.
    values["prior_chain_state"] = state
    again = verify_public_relay_path(**values)
    assert again.manifest_verification.reprobe is True
    assert again.weight_plan == result.weight_plan


@pytest.mark.parametrize(
    ("change", "code"),
    [
        ("retained_archive_missing_epoch", "decision_epoch_records_mismatch"),
        ("terminal_substituted", "decision_terminal_mismatch"),
        ("finalized_height_relabel", "finalized_height_mismatch"),
    ],
)
def test_archive_terminal_and_height_substitution_fail_before_a_plan(
    change: str, code: str
) -> None:
    values = integration_inputs()
    if change == "retained_archive_missing_epoch":
        values["retained_epoch_records"] = values["retained_epoch_records"][:1]
    elif change == "terminal_substituted":
        context = make_window_context()
        from organic_context import build_manifest, fixture_deployments

        other = build_manifest(context.policy, fixture_deployments()[:1])
        values["head_manifest"] = other
        values["head_signatures"] = tuple(sign_manifest(other, signer_keys()))
    else:
        values["current_finalized_height"] = REGISTERED_HEIGHT - 1
    with pytest.raises(PublicVerifierError, match=f"^{code}$"):
        verify_public_relay_path(**values)


def test_a_tampered_retained_archive_is_invalid() -> None:
    values = integration_inputs()
    epochs = copy.deepcopy(values["retained_epoch_records"])
    epochs[0].observations.pop()
    values["retained_epoch_records"] = epochs
    with pytest.raises(PublicVerifierError, match="^decision_epoch_records_invalid$"):
        verify_public_relay_path(**values)


def test_an_unverifiable_head_fails_closed() -> None:
    values = integration_inputs()
    values["head_signatures"] = values["head_signatures"][:1]
    with pytest.raises(AssignmentProbeError, match="threshold_not_met"):
        verify_public_relay_path(**values)


def test_probe_evidence_replayed_across_epochs_is_rejected() -> None:
    """Each epoch is self-consistent; only the cross-epoch nonce check can catch a replay."""

    context = make_window_context()
    shop_a = endpoint(context.manifest, SHOP, "MinerA")
    healthy = {
        replica.endpoint_id: ("success",) * 3
        for deployment in context.manifest.deployments
        for replica in deployment.replicas
    }
    epochs = []
    for index in range(2):
        start = EPOCH_START + index * EPOCH_SECONDS
        observations = epoch_probes(
            context.policy, context.manifest, {**healthy, shop_a: ()}, epoch_start=start
        )
        observations += [
            probe(
                context.policy, context.manifest, shop_a, offset_seconds=offset, epoch_start=start
            )
            for offset in (20, 120)
        ]
        # The same nonce label in both epochs: an archived probe re-used later.
        observations.append(
            probe(
                context.policy,
                context.manifest,
                shop_a,
                offset_seconds=200,
                epoch_start=start,
                label="replayed",
            )
        )
        epochs.append(
            score_organic_epoch(
                [context.manifest],
                observations,
                validator_hotkey=context.decision.validator_hotkey,
                epoch_index=EPOCH + index,
            )
        )
    decision = decide(context.policy, context.manifest, epochs)
    values = integration_inputs()
    values["decision"] = decision
    values["retained_epoch_records"] = tuple(epochs)
    with pytest.raises(PublicVerifierError, match="^decision_probe_evidence_replayed$"):
        verify_public_relay_path(**values)


def test_trusted_evaluation_time_tolerance_has_exact_boundaries() -> None:
    for offset in (-PUBLIC_EVALUATION_TOLERANCE_SECONDS, 0, PUBLIC_EVALUATION_TOLERANCE_SECONDS):
        values = integration_inputs()
        values["evaluation_epoch"] = WINDOW_END + offset
        assert verify_public_relay_path(**values).decision.decision == "submit"
    for offset in (
        -PUBLIC_EVALUATION_TOLERANCE_SECONDS - 1,
        PUBLIC_EVALUATION_TOLERANCE_SECONDS + 1,
    ):
        values = integration_inputs()
        values["evaluation_epoch"] = WINDOW_END + offset
        with pytest.raises(PublicVerifierError, match="^decision_time_mismatch$"):
            verify_public_relay_path(**values)


def test_minimal_public_metagraph_protocol_derives_epoch_without_attribute() -> None:
    values = integration_inputs()
    complete = metagraph_snapshot()

    class MinimalMetagraph:
        network = complete.network
        netuid = complete.netuid
        block = complete.block
        tempo = complete.tempo
        neurons = complete.neurons
        finalized = complete.finalized

    values["finalized_metagraph"] = MinimalMetagraph()
    assert verify_public_relay_path(**values).weight_plan.snapshot.epoch == (
        complete.block // complete.tempo
    )


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
    assert not imported & {"bittensor", "chain", "os", "socket", "subprocess", "weight_executor"}
    assert not called & {"connect", "execute", "sign", "set_weights", "submit", "write_bytes"}
