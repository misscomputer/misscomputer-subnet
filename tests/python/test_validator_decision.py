# SPDX-License-Identifier: AGPL-3.0-only

"""Frozen validator decision semantics: abstain, zero, submit."""

from __future__ import annotations

import json
import random
from pathlib import Path

import pytest
from assignment_probe_context import BASE_EPOCH, FINALIZED_HEIGHT, MINERS, build_deployment
from assignment_probe_context import build_manifest as build_probe_manifest
from contract_checkpoint_context import (
    EXTRA_MINERS,
    REGISTERED_MINERS,
    VALIDATOR_HOTKEY,
    VALIDATOR_UID,
    WINDOW_END,
    WINDOW_START,
    make_window_context,
    registered_set,
)
from pydantic import ValidationError

from misscomputer_subnet.probe_scoring import ProbeScoringError, ProbeScoringPolicy
from misscomputer_subnet.validator_decision import (
    RegisteredMinerSet,
    TerminalManifestObservation,
    ValidatorWeightDecision,
    WeightDecisionError,
    WeightDecisionPolicy,
    decide_weight_submission,
    parse_validator_weight_decision,
    validator_weight_decision_bytes,
    weight_plan_rows_for_submission,
)
from misscomputer_subnet.weight_plan import build_weight_plan

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "contracts" / "fixtures"


def classes(decision: ValidatorWeightDecision) -> dict[str, str]:
    return {row.hotkey: row.classification for row in decision.rows}


def test_golden_window_submits_and_classifies_every_registered_miner() -> None:
    context = make_window_context()
    decision = context.decision
    assert decision.decision == "submit"
    assert decision.abstain_reasons == []
    assert decision.round_count == 45
    assert decision.terminal_manifest_sequence == 3
    assert classes(decision) == {
        "MinerA": "verified_serving",
        "MinerB": "verified_serving",
        "MinerC": "verified_serving",
        "MinerD": "verified_serving",
        "MinerE": "verified_serving",
        "MinerF": "assigned_in_grace",
        "MinerG": "unassigned",
    }
    by_hotkey = {row.hotkey: row for row in decision.rows}
    assert by_hotkey["MinerF"].first_seen_epoch == BASE_EPOCH + 3_000
    assert by_hotkey["MinerE"].first_seen_epoch == BASE_EPOCH + 1_500
    assert by_hotkey["MinerG"].first_seen_epoch is None
    assert by_hotkey["MinerF"].weight == 0.0 and by_hotkey["MinerG"].weight == 0.0
    assert sum(row.weight for row in decision.rows) == pytest.approx(1.0)
    assert decision.max_assigned_miner_count == decision.terminal_assigned_miner_count == 6
    assert (
        validator_weight_decision_bytes(decision)
        == (FIXTURES / "validator-weight-decision.v1.json").read_bytes()
    )


def test_submit_decision_is_the_exact_weight_plan_boundary() -> None:
    pytest.importorskip("misscomputer_subnet.chain")
    from misscomputer_subnet.chain import MetagraphSnapshot, NeuronRecord

    decision = make_window_context().decision
    rows = weight_plan_rows_for_submission(decision)
    assert rows == [{"miner_hotkey": row.hotkey, "weight": row.weight} for row in decision.rows]
    neurons = [
        NeuronRecord(
            uid=VALIDATOR_UID,
            hotkey=VALIDATOR_HOTKEY,
            validator_permit=True,
            tao_stake=1_000.0,
            axon=None,
            active=True,
        ),
        *[
            NeuronRecord(
                uid=uid,
                hotkey=hotkey,
                validator_permit=False,
                tao_stake=1.0,
                axon="127.0.0.1:8091",
                active=True,
            )
            for uid, hotkey in REGISTERED_MINERS
        ],
    ]
    snapshot = MetagraphSnapshot(
        network="finney", netuid=24, block=1_000, tempo=100, neurons=tuple(neurons), finalized=True
    )
    plan = build_weight_plan(
        snapshot=snapshot, validator_hotkey=VALIDATOR_HOTKEY, rows=rows, version_key=1
    )
    again = build_weight_plan(
        snapshot=snapshot,
        validator_hotkey=VALIDATOR_HOTKEY,
        rows=weight_plan_rows_for_submission(
            parse_validator_weight_decision(validator_weight_decision_bytes(decision))
        ),
        version_key=1,
    )
    assert plan.digest_sha256 == again.digest_sha256
    assert {entry.hotkey for entry in plan.weights} == {
        "MinerA",
        "MinerB",
        "MinerC",
        "MinerD",
        "MinerE",
    }


def test_abstain_record_can_never_become_a_plan() -> None:
    context = make_window_context()
    abstained = decide_weight_submission(
        context.rounds,
        terminal=TerminalManifestObservation(
            status="unavailable", evaluated_at_epoch=WINDOW_END, rejection_code="timeout"
        ),
        registered=context.registered,
        window_start_epoch=WINDOW_START,
        window_end_epoch=WINDOW_END,
    )
    assert abstained.decision == "abstain"
    assert abstained.abstain_reasons == ["manifest_unavailable"]
    assert abstained.weight_plan_rows_digest_sha256 is None
    assert abstained.terminal_manifest_rejection_code == "timeout"
    assert abstained.terminal_manifest_digest_sha256 is None
    # Evidence is retained for audit, but it cannot be turned into rows.
    assert classes(abstained)["MinerA"] == "verified_serving"
    with pytest.raises(WeightDecisionError) as failure:
        weight_plan_rows_for_submission(abstained)
    assert failure.value.code == "decision_not_submittable"


def test_invalid_stale_or_expired_manifest_at_close_abstains() -> None:
    context = make_window_context()
    terminal_manifest = context.manifests[2]

    def decide(terminal: TerminalManifestObservation) -> ValidatorWeightDecision:
        return decide_weight_submission(
            context.rounds,
            terminal=terminal,
            registered=context.registered,
            window_start_epoch=WINDOW_START,
            window_end_epoch=WINDOW_END,
        )

    rejected = decide(
        TerminalManifestObservation(
            status="rejected", evaluated_at_epoch=WINDOW_END, rejection_code="manifest_stale"
        )
    )
    assert rejected.abstain_reasons == ["manifest_invalid"]
    assert rejected.terminal_manifest_rejection_code == "manifest_stale"
    expired = decide(
        TerminalManifestObservation(
            status="verified",
            evaluated_at_epoch=terminal_manifest.expires_at_epoch,
            manifest=terminal_manifest,
        )
    )
    assert expired.abstain_reasons == ["manifest_expired_at_close"]
    for bad in (
        TerminalManifestObservation(status="verified", evaluated_at_epoch=WINDOW_END),
        TerminalManifestObservation(
            status="verified",
            evaluated_at_epoch=WINDOW_END,
            manifest=terminal_manifest,
            rejection_code="x",
        ),
        TerminalManifestObservation(status="rejected", evaluated_at_epoch=WINDOW_END),
        TerminalManifestObservation(
            status="unavailable",
            evaluated_at_epoch=WINDOW_END,
            manifest=terminal_manifest,
            rejection_code="x",
        ),
    ):
        with pytest.raises(WeightDecisionError) as failure:
            decide(bad)
        assert failure.value.code == "decision_terminal_status_invalid"
    with pytest.raises(WeightDecisionError) as failure:
        decide(
            TerminalManifestObservation(
                status="verified", evaluated_at_epoch=WINDOW_END - 1, manifest=terminal_manifest
            )
        )
    assert failure.value.code == "decision_terminal_before_close"


def test_insufficient_sampling_abstains_instead_of_zeroing() -> None:
    context = make_window_context()
    few_rounds = decide_weight_submission(
        context.rounds,
        terminal=context.terminal,
        registered=context.registered,
        window_start_epoch=WINDOW_START,
        window_end_epoch=WINDOW_END,
        decision_policy=WeightDecisionPolicy(min_verified_rounds=46),
    )
    assert few_rounds.abstain_reasons == ["rounds_insufficient"]

    # Pull MinerF out of grace with an archived earlier sighting: nine
    # opportunities are then below a ten-attribution coverage requirement, so
    # F's silence is the validator's sampling gap, never a zero.
    delta_endpoint = next(
        replica.endpoint_id
        for item in context.manifests[2].deployments
        for replica in item.replicas
        if replica.miner_hotkey == "MinerF"
    )
    undersampled = decide_weight_submission(
        context.rounds,
        terminal=context.terminal,
        registered=context.registered,
        window_start_epoch=WINDOW_START,
        window_end_epoch=WINDOW_END,
        decision_policy=WeightDecisionPolicy(min_expected_attributions=10),
        endpoint_first_seen_epoch={delta_endpoint: BASE_EPOCH, "unknown-endpoint": BASE_EPOCH},
    )
    assert undersampled.abstain_reasons == ["coverage_insufficient"]
    assert classes(undersampled)["MinerF"] == "assigned_undersampled"
    assert {row.hotkey: row.first_seen_epoch for row in undersampled.rows}["MinerF"] == BASE_EPOCH

    # With enough coverage the same silent miner is an honest zero.
    sampled = decide_weight_submission(
        context.rounds,
        terminal=context.terminal,
        registered=context.registered,
        window_start_epoch=WINDOW_START,
        window_end_epoch=WINDOW_END,
        endpoint_first_seen_epoch={delta_endpoint: BASE_EPOCH},
    )
    assert sampled.decision == "submit"
    assert classes(sampled)["MinerF"] == "assigned_unverified"

    with pytest.raises(WeightDecisionError) as failure:
        decide_weight_submission(
            context.rounds,
            terminal=context.terminal,
            registered=context.registered,
            window_start_epoch=WINDOW_START,
            window_end_epoch=WINDOW_END,
            endpoint_first_seen_epoch={delta_endpoint: BASE_EPOCH + 3_001},
        )
    assert failure.value.code == "decision_first_seen_after_sighting"


def test_no_positive_evidence_means_no_transaction() -> None:
    context = make_window_context()
    empty = decide_weight_submission(
        [],
        terminal=context.terminal,
        registered=context.registered,
        window_start_epoch=WINDOW_START,
        window_end_epoch=WINDOW_END,
    )
    assert empty.decision == "abstain"
    assert empty.abstain_reasons == ["no_positive_evidence", "rounds_insufficient"]
    assert empty.round_count == 0 and empty.scoring_window_digest_sha256 is None
    assert set(classes(empty).values()) == {"assigned_in_grace", "unassigned"}
    assert empty.max_assigned_miner_count == empty.terminal_assigned_miner_count == 6


def test_safe_preconditions_for_zeroing_absent_miners() -> None:
    context = make_window_context()

    def decide(
        registered: RegisteredMinerSet,
        *,
        terminal: TerminalManifestObservation | None = None,
        policy: WeightDecisionPolicy | None = None,
    ) -> ValidatorWeightDecision:
        return decide_weight_submission(
            context.rounds,
            terminal=terminal or context.terminal,
            registered=registered,
            window_start_epoch=WINDOW_START,
            window_end_epoch=WINDOW_END,
            decision_policy=policy,
        )

    behind = decide(registered_set(finalized_height=FINALIZED_HEIGHT + 39))
    assert behind.abstain_reasons == ["registered_set_unbound"]
    far_ahead = decide(
        registered_set(finalized_height=FINALIZED_HEIGHT + 40 + 601),
    )
    assert far_ahead.abstain_reasons == ["registered_set_unbound"]
    assert (
        decide(
            registered_set(finalized_height=FINALIZED_HEIGHT + 40 + 601),
            policy=WeightDecisionPolicy(max_registered_height_gap=601),
        ).decision
        == "submit"
    )

    # A central mass-eviction at window close is not miner evidence.
    gamma = build_deployment("fixture-gamma", EXTRA_MINERS[:1], campaign_sequence=3)
    shrunken = build_probe_manifest(
        context.policy,
        [gamma],
        sequence=4,
        previous=context.manifests[2].manifest_digest_sha256,
        issued_at=BASE_EPOCH + 3_400,
        expires_at=BASE_EPOCH + 3_400 + 3_600,
        finalized_height=FINALIZED_HEIGHT + 45,
        finalized_block_hash=context.manifests[2].finalized_block_hash[::-1],
    )
    guarded = decide(
        context.registered,
        terminal=TerminalManifestObservation(
            status="verified", evaluated_at_epoch=WINDOW_END, manifest=shrunken
        ),
    )
    assert guarded.abstain_reasons == ["mass_unassignment_guard"]
    assert guarded.terminal_assigned_miner_count == 1 and guarded.max_assigned_miner_count == 6
    # Verified evidence keeps its weight even when the miner is no longer assigned.
    assert classes(guarded)["MinerA"] == "verified_serving"
    assert classes(guarded)["MinerF"] == "unassigned"
    permissive = decide(
        context.registered,
        terminal=TerminalManifestObservation(
            status="verified", evaluated_at_epoch=WINDOW_END, manifest=shrunken
        ),
        policy=WeightDecisionPolicy(max_assigned_drop_permille=1_000),
    )
    assert permissive.decision == "submit"


def test_input_consistency_errors_are_not_abstentions() -> None:
    context = make_window_context()
    with pytest.raises(WeightDecisionError) as failure:
        decide_weight_submission(
            context.rounds,
            terminal=TerminalManifestObservation(
                status="verified", evaluated_at_epoch=WINDOW_END, manifest=context.manifests[0]
            ),
            registered=context.registered,
            window_start_epoch=WINDOW_START,
            window_end_epoch=WINDOW_END,
        )
    assert failure.value.code == "decision_round_after_terminal"
    with pytest.raises(WeightDecisionError) as failure:
        decide_weight_submission(
            context.rounds,
            terminal=context.terminal,
            registered=context.registered,
            window_start_epoch=WINDOW_START,
            window_end_epoch=WINDOW_END,
            decision_policy=WeightDecisionPolicy(activation_grace_seconds=3_601),
        )
    assert failure.value.code == "decision_policy_grace_exceeds_window"
    with pytest.raises(WeightDecisionError) as failure:
        decide_weight_submission(
            context.rounds,
            terminal=context.terminal,
            registered=context.registered,
            window_start_epoch=WINDOW_END,
            window_end_epoch=WINDOW_START,
        )
    assert failure.value.code == "decision_epoch_invalid"
    with pytest.raises(ProbeScoringError) as scoring_failure:
        decide_weight_submission(
            context.rounds,
            terminal=context.terminal,
            registered=context.registered.model_copy(update={"validator_hotkey": "Impostor"}),
            window_start_epoch=WINDOW_START,
            window_end_epoch=WINDOW_END,
        )
    assert str(scoring_failure.value) == "scoring_report_identity_mismatch"
    with pytest.raises(ValidationError, match="registered_validator_overlaps_miner"):
        registered_set(miners=sorted((*MINERS, (VALIDATOR_UID, VALIDATOR_HOTKEY))))


def test_decision_is_deterministic_under_round_reordering() -> None:
    context = make_window_context()
    shuffled = list(context.rounds)
    random.Random(7).shuffle(shuffled)  # noqa: S311 - reproducible test ordering only
    again = decide_weight_submission(
        shuffled,
        terminal=context.terminal,
        registered=context.registered,
        window_start_epoch=WINDOW_START,
        window_end_epoch=WINDOW_END,
        scoring_policy=ProbeScoringPolicy(),
    )
    assert validator_weight_decision_bytes(again) == validator_weight_decision_bytes(
        context.decision
    )


def test_decision_bytes_round_trip_and_reject_malleability() -> None:
    rendered = (FIXTURES / "validator-weight-decision.v1.json").read_bytes()
    decision = parse_validator_weight_decision(rendered)
    assert validator_weight_decision_bytes(decision) == rendered
    document = json.loads(rendered)
    document["observation_count"] += 1
    with pytest.raises(ValidationError, match="decision_digest_sha256_mismatch"):
        ValidatorWeightDecision.model_validate(document)
    document = json.loads(rendered)
    document["rows"][0]["weight"] = 0.5
    with pytest.raises(ValidationError, match="weight_plan_rows_digest_mismatch"):
        ValidatorWeightDecision.model_validate(document)
    with pytest.raises(ValueError, match="document_not_canonical"):
        parse_validator_weight_decision(json.dumps(json.loads(rendered)).encode() + b"\n")
