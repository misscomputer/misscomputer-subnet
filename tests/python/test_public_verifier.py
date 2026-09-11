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
    reseal_decision,
    reseal_observation,
    reseal_report,
)
from pydantic import ValidationError

from misscomputer_subnet.assignment_probe import (
    ActiveAssignmentManifest,
    AssignmentProbeError,
    ValidatorProbeReport,
)
from misscomputer_subnet.contract_codec import digest
from misscomputer_subnet.manifest_publication import (
    ManifestHistoryEntry,
    ManifestPublicationError,
    build_manifest_latest_pointer,
)
from misscomputer_subnet.probe_scoring import ProbeRound
from misscomputer_subnet.public_verifier import (
    MAX_PUBLIC_HISTORY_ENTRIES,
    PUBLIC_EVALUATION_TOLERANCE_SECONDS,
    PublicVerifierError,
    verify_public_relay_path,
)
from misscomputer_subnet.validator_decision import (
    ValidatorWeightDecision,
    decide_weight_submission,
)
from misscomputer_subnet.weight_plan import WEIGHT_PLAN_PROTOCOL_VERSION_KEY

ROOT = Path(__file__).resolve().parents[2]


def _decision_reports(decision: ValidatorWeightDecision) -> tuple[ValidatorProbeReport, ...]:
    return tuple(
        report
        for evidence in decision.assignment_manifest_evidence
        for report in evidence.scoring_reports
    )


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
        "retained_probe_reports": _decision_reports(context.decision),
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
    values["retained_probe_reports"] = _decision_reports(values["decision"])
    with pytest.raises(ValidationError):
        verify_public_relay_path(**values)


def _reseal_decision_report_dependencies(document: dict[str, Any]) -> dict[str, Any]:
    report_digests: list[str] = []
    for evidence in document["assignment_manifest_evidence"]:
        for report in evidence["scoring_reports"]:
            report["observation_vector_digest_sha256"] = digest(report["observations"])
            report["report_digest_sha256"] = digest(
                {key: value for key, value in report.items() if key != "report_digest_sha256"}
            )
            report_digests.append(report["report_digest_sha256"])
        evidence["scoring_reports"].sort(key=lambda item: item["report_digest_sha256"])
    document["scoring_window"]["report_digests"] = sorted(report_digests)
    document["scoring_window_digest_sha256"] = digest(document["scoring_window"])
    return reseal_decision(document)


def test_decision_reports_must_match_independently_retained_archive() -> None:
    values = integration_inputs()
    values["retained_probe_reports"] = values["retained_probe_reports"][:-1]
    with pytest.raises(PublicVerifierError, match="^decision_probe_records_mismatch$"):
        verify_public_relay_path(**values)


def test_resealed_zero_signatures_fail_before_weight_credit() -> None:
    values = integration_inputs()
    document = values["decision"].model_dump(mode="json", by_alias=True)
    rewritten = 0
    for evidence in document["assignment_manifest_evidence"]:
        for report in evidence["scoring_reports"]:
            observations = []
            for observation in report["observations"]:
                if observation["attestation"] is not None:
                    observation["attestation"]["signature_hex"] = "0" * 128
                    rewritten += 1
                observations.append(reseal_observation(observation))
            report["observations"] = observations
    assert rewritten == 111
    values["decision"] = ValidatorWeightDecision.model_validate(
        _reseal_decision_report_dependencies(document)
    )
    values["retained_probe_reports"] = _decision_reports(values["decision"])
    with pytest.raises(PublicVerifierError, match="^decision_attestation_invalid$"):
        verify_public_relay_path(**values)


@pytest.mark.parametrize("relabel", ["evaluation_epoch", "latency_millis"])
def test_resealed_underlying_probe_replay_is_rejected_across_unsigned_relabels(
    relabel: str,
) -> None:
    values = integration_inputs()
    context = make_window_context()
    source_rounds = (context.rounds[0], context.rounds[24], context.rounds[36])
    replayed_rounds: list[ProbeRound] = []
    for copy_index in range(8):
        for source_index, source in enumerate(source_rounds):
            report = source.report.model_dump(mode="json", by_alias=True)
            if relabel == "evaluation_epoch":
                report["evaluation_epoch"] += copy_index + source_index
            else:
                for observation in report["observations"]:
                    observation["latency_millis"] += copy_index
                    observation.update(reseal_observation(observation))
                report["observation_vector_digest_sha256"] = digest(report["observations"])
            replayed_rounds.append(
                ProbeRound(
                    manifest=source.manifest,
                    report=ValidatorProbeReport.model_validate(reseal_report(report)),
                )
            )
    # Recompute every enclosing decision/scoring digest through the producer:
    # only authenticated probe identity, not envelope metadata, detects replay.
    values["decision"] = decide_weight_submission(
        replayed_rounds,
        terminal=context.terminal,
        registered=context.registered,
        trust_policies=[context.policy],
        window_start_epoch=context.decision.window_start_epoch,
        window_end_epoch=WINDOW_END,
    )
    values["retained_probe_reports"] = _decision_reports(values["decision"])
    with pytest.raises(PublicVerifierError, match="^decision_probe_evidence_replayed$"):
        verify_public_relay_path(**values)


def test_trusted_evaluation_time_tolerance_has_exact_boundaries() -> None:
    for offset in (
        -PUBLIC_EVALUATION_TOLERANCE_SECONDS,
        0,
        PUBLIC_EVALUATION_TOLERANCE_SECONDS,
    ):
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
    complete = metagraph_view()

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
