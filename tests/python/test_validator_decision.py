# SPDX-License-Identifier: AGPL-3.0-only

"""Frozen validator decision semantics: abstain, zero, submit."""

from __future__ import annotations

import json
import random
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from assignment_probe_context import (
    BASE_EPOCH,
    FINALIZED_HEIGHT,
    MINERS,
    build_deployment,
    label_digest,
    sign_manifest,
)
from assignment_probe_context import build_manifest as build_probe_manifest
from contract_checkpoint_context import (
    EXTRA_MINERS,
    REGISTERED_HEIGHT,
    REGISTERED_MINERS,
    REGISTERED_TEMPO,
    VALIDATOR_HOTKEY,
    VALIDATOR_UID,
    WINDOW_END,
    WINDOW_START,
    MetagraphNeuron,
    assigned_baseline,
    build_round,
    forged_decision,
    make_window_context,
    metagraph_view,
    registered_set,
    window_deployment,
)
from pydantic import ValidationError

from misscomputer_subnet.assignment_probe import (
    AssignmentProbeError,
    ProbeObservation,
    ValidatorProbeReport,
    build_initial_manifest_chain_state,
    manifest_effective_expires_at_epoch,
    verify_active_assignment_manifest,
)
from misscomputer_subnet.contract_codec import digest as canonical_digest
from misscomputer_subnet.probe_scoring import (
    ProbeRound,
    ProbeScoringError,
    ProbeScoringPolicy,
    accumulate_scoring_window,
)
from misscomputer_subnet.validator_decision import (
    AssignedBaseline,
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
from misscomputer_subnet.weight_plan import (
    WeightPlanError,
    build_weight_plan,
    build_weight_plan_from_decision,
)

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
    assert {hotkey for hotkey, row in by_hotkey.items() if row.assigned_at_close} == {
        "MinerA",
        "MinerB",
        "MinerC",
        "MinerD",
        "MinerE",
        "MinerF",
    }
    assert sum(row.weight for row in decision.rows) == pytest.approx(1.0)
    assert decision.max_assigned_miner_count == decision.terminal_assigned_miner_count == 6
    terminal = context.manifests[2]
    assert decision.terminal_finalized_block_hash == terminal.finalized_block_hash
    assert decision.terminal_finalized_epoch == terminal.finalized_epoch
    assert decision.terminal_manifest_effective_expires_at_epoch == (
        manifest_effective_expires_at_epoch(terminal)
    )
    assert decision.terminal_earliest_lease_expires_at_block == min(
        replica.expires_at_block for item in terminal.deployments for replica in item.replicas
    )
    assert decision.prior_assigned_baseline is None
    assert decision.prior_assigned_baseline_status == "absent"
    assert decision.assigned_baseline == assigned_baseline(
        terminal, established_at_epoch=WINDOW_END
    )
    assert (
        validator_weight_decision_bytes(decision)
        == (FIXTURES / "validator-weight-decision.v1.json").read_bytes()
    )


def test_submit_decision_is_the_exact_weight_plan_boundary() -> None:
    from misscomputer_subnet.chain import MetagraphSnapshot, NeuronRecord

    context = make_window_context()
    decision = context.decision
    rows = weight_plan_rows_for_submission(decision)
    assert rows == [{"miner_hotkey": row.hotkey, "weight": row.weight} for row in decision.rows]
    view = metagraph_view()
    snapshot = MetagraphSnapshot(
        network=view.network,
        netuid=view.netuid,
        block=view.block,
        tempo=view.tempo,
        neurons=tuple(
            NeuronRecord(
                uid=item.uid,
                hotkey=item.hotkey,
                validator_permit=item.validator_permit,
                tao_stake=item.tao_stake,
                axon=item.axon,
                active=item.active,
            )
            for item in view.neurons
        ),
        finalized=True,
    )
    plan = build_weight_plan_from_decision(
        decision,
        snapshot=snapshot,
        finalized_block_hash=context.registered.finalized_block_hash,
        version_key=1,
    )
    direct = build_weight_plan(
        snapshot=snapshot, validator_hotkey=VALIDATOR_HOTKEY, rows=rows, version_key=1
    )
    again = build_weight_plan_from_decision(
        parse_validator_weight_decision(validator_weight_decision_bytes(decision)),
        snapshot=view,  # type: ignore[arg-type]
        finalized_block_hash=context.registered.finalized_block_hash,
        version_key=1,
    )
    assert plan.digest_sha256 == direct.digest_sha256 == again.digest_sha256
    assert plan.snapshot.identity_fingerprint == decision.metagraph_identity_fingerprint_sha256
    assert plan.snapshot.block == decision.registered_finalized_height
    assert plan.snapshot.epoch == decision.registered_finalized_epoch
    assert {entry.hotkey for entry in plan.weights} == {
        "MinerA",
        "MinerB",
        "MinerC",
        "MinerD",
        "MinerE",
    }


def test_decision_aware_plan_builder_refuses_every_metagraph_mismatch() -> None:
    context = make_window_context()
    decision = context.decision
    hash_ = context.registered.finalized_block_hash

    def build(view: Any, *, finalized_block_hash: str = hash_) -> None:
        build_weight_plan_from_decision(
            decision, snapshot=view, finalized_block_hash=finalized_block_hash, version_key=1
        )

    build(metagraph_view())
    cases: dict[str, Any] = {
        "finalized height": metagraph_view(finalized_height=REGISTERED_HEIGHT + 1),
        "finalized epoch": metagraph_view(tempo=REGISTERED_TEMPO + 1),
        "metagraph fingerprint": replace(
            metagraph_view(),
            neurons=tuple(
                replace(item, tao_stake=2.0) if item.hotkey == "MinerG" else item
                for item in metagraph_view().neurons
            ),
        ),
        "row identity": metagraph_view(
            miners=[
                (uid + 1, hotkey) if hotkey == "MinerG" else (uid, hotkey)
                for uid, hotkey in REGISTERED_MINERS
            ]
        ),
        "validator identity": replace(
            metagraph_view(),
            neurons=tuple(
                replace(item, uid=VALIDATOR_UID + 1) if item.hotkey == VALIDATOR_HOTKEY else item
                for item in metagraph_view().neurons
            ),
        ),
        "network identity": replace(metagraph_view(), netuid=25),
        "finalized metagraph": replace(metagraph_view(), finalized=False),
    }
    for message, view in cases.items():
        with pytest.raises(WeightPlanError, match=message):
            build(view)
    with pytest.raises(WeightPlanError, match="block hash"):
        build(metagraph_view(), finalized_block_hash=label_digest("elsewhere"))
    # A decision over a superset of registered miners cannot be applied to a
    # snapshot that has since dropped one of them.
    with pytest.raises(WeightPlanError, match="row identity"):
        build(metagraph_view(miners=REGISTERED_MINERS[:-1]))
    # A registered snapshot with an extra neuron is a different fingerprint.
    with pytest.raises(WeightPlanError, match="fingerprint"):
        build(
            replace(
                metagraph_view(),
                neurons=(
                    *metagraph_view().neurons,
                    MetagraphNeuron(
                        uid=99, hotkey="MinerZ", validator_permit=False, tao_stake=1.0, axon=None
                    ),
                ),
            )
        )


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
    assert abstained.assigned_baseline is None
    # Evidence is retained for audit, but it cannot be turned into rows.
    assert classes(abstained)["MinerA"] == "verified_serving"
    with pytest.raises(WeightDecisionError) as failure:
        weight_plan_rows_for_submission(abstained)
    assert failure.value.code == "decision_not_submittable"


def test_sealed_record_re_derives_every_submit_precondition() -> None:
    """A digest-valid record that says submit while describing an outage is refused."""

    rendered = (FIXTURES / "validator-weight-decision.v1.json").read_bytes()
    outage = forged_decision(
        rendered,
        terminal_manifest_status="unavailable",
        terminal_manifest_rejection_code="timeout",
        terminal_manifest_digest_sha256=None,
        terminal_manifest_sequence=None,
        terminal_manifest_expires_at_epoch=None,
        terminal_manifest_effective_expires_at_epoch=None,
        terminal_earliest_lease_expires_at_block=None,
        terminal_finalized_height=None,
        terminal_finalized_block_hash=None,
        terminal_finalized_epoch=None,
        assigned_baseline=None,
    )
    assert outage["decision"] == "submit"
    with pytest.raises(ValidationError, match="abstain_reasons_not_derived"):
        ValidatorWeightDecision.model_validate(outage)
    with pytest.raises(ValueError, match="document_invalid"):
        parse_validator_weight_decision(
            json.dumps(outage, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"
        )
    # The honest abstain form of the same facts is accepted and unsubmittable.
    honest = forged_decision(
        rendered,
        decision="abstain",
        abstain_reasons=["manifest_unavailable"],
        **{key: value for key, value in outage.items() if key.startswith("terminal_")},
        assigned_baseline=None,
    )
    parsed = ValidatorWeightDecision.model_validate(honest)
    with pytest.raises(WeightDecisionError):
        weight_plan_rows_for_submission(parsed)
    # Conversely, an abstain record whose fields support submitting is refused too:
    # the reason list must be exactly the derived one, in both directions.
    with pytest.raises(ValidationError, match="abstain_reasons_not_derived"):
        ValidatorWeightDecision.model_validate(
            forged_decision(rendered, decision="abstain", abstain_reasons=["rounds_insufficient"])
        )


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


def test_manifest_validity_never_outlives_ticket_or_block_leases() -> None:
    """A manifest whose tickets expire before ``expires_at_epoch`` ends at the ticket expiry."""

    context = make_window_context()
    keys, policy = context.keys, context.policy
    # Tickets end at window close + 1 while the manifest claims another hour.
    short = build_probe_manifest(
        policy,
        [
            build_deployment(
                "fixture-alpha",
                MINERS[:3],
                campaign_sequence=1,
                ticket_expires_at_epoch=WINDOW_END + 1,
                expires_at_block=FINALIZED_HEIGHT + 2_000,
            )
        ],
        sequence=4,
        previous=context.manifests[2].manifest_digest_sha256,
        issued_at=BASE_EPOCH + 3_300,
        expires_at=BASE_EPOCH + 3_300 + 3_600,
        finalized_height=FINALIZED_HEIGHT + 45,
        finalized_block_hash=label_digest("block-four"),
    )
    assert manifest_effective_expires_at_epoch(short) == WINDOW_END + 1
    state_three = verify_active_assignment_manifest(
        context.manifests[2],
        sign_manifest(context.manifests[2], keys),
        policy,
        context.states[2],
        evaluation_epoch=BASE_EPOCH + 3_000,
    ).next_chain_state
    verify_active_assignment_manifest(
        short, sign_manifest(short, keys), policy, state_three, evaluation_epoch=WINDOW_END
    )
    with pytest.raises(AssignmentProbeError) as failure:
        verify_active_assignment_manifest(
            short,
            sign_manifest(short, keys),
            policy,
            state_three,
            evaluation_epoch=WINDOW_END + 1,
        )
    assert failure.value.code == "manifest_expired"
    with pytest.raises(AssignmentProbeError) as failure:
        verify_active_assignment_manifest(
            short,
            sign_manifest(short, keys),
            policy,
            state_three,
            evaluation_epoch=WINDOW_END,
            current_finalized_height=FINALIZED_HEIGHT + 2_000,
        )
    assert failure.value.code == "manifest_replica_lease_expired"

    def decide(terminal: TerminalManifestObservation, **changes: Any) -> ValidatorWeightDecision:
        return decide_weight_submission(
            context.rounds,
            terminal=terminal,
            registered=changes.get("registered", context.registered),
            window_start_epoch=WINDOW_START,
            window_end_epoch=WINDOW_END,
            decision_policy=WeightDecisionPolicy(
                max_assigned_drop_permille=1_000, max_registered_height_gap=10_000
            ),
        )

    still_valid = decide(
        TerminalManifestObservation(
            status="verified", evaluated_at_epoch=WINDOW_END, manifest=short
        )
    )
    assert still_valid.decision == "submit"
    assert still_valid.terminal_manifest_effective_expires_at_epoch == WINDOW_END + 1
    ticket_expired = decide(
        TerminalManifestObservation(
            status="verified", evaluated_at_epoch=WINDOW_END + 1, manifest=short
        )
    )
    assert ticket_expired.abstain_reasons == ["manifest_expired_at_close"]
    lease_expired = decide(
        TerminalManifestObservation(
            status="verified", evaluated_at_epoch=WINDOW_END, manifest=short
        ),
        registered=registered_set(finalized_height=FINALIZED_HEIGHT + 2_000),
    )
    assert lease_expired.abstain_reasons == ["assignment_lease_expired_at_close"]
    assert lease_expired.terminal_earliest_lease_expires_at_block == FINALIZED_HEIGHT + 2_000

    # A round probed after its manifest's ticket horizon is not admissible evidence.
    late = build_round(
        policy,
        short,
        state_three,
        keys,
        responders={"fixture-alpha": "MinerA"},
        label="late",
        evaluation_epoch=WINDOW_END - 1,
    )
    unsigned = late.report.model_dump(mode="json", by_alias=True, exclude={"report_digest_sha256"})
    unsigned["evaluation_epoch"] = WINDOW_END + 1
    late_report = ValidatorProbeReport.model_validate(
        {**unsigned, "report_digest_sha256": canonical_digest(unsigned)}
    )
    with pytest.raises(WeightDecisionError) as failure:
        decide_weight_submission(
            [*context.rounds, ProbeRound(manifest=short, report=late_report)],
            terminal=TerminalManifestObservation(
                status="verified", evaluated_at_epoch=WINDOW_END + 2, manifest=short
            ),
            registered=context.registered,
            window_start_epoch=WINDOW_START,
            window_end_epoch=WINDOW_END + 2,
        )
    assert failure.value.code == "decision_round_after_horizon"


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


def test_positive_evidence_does_not_bypass_minimum_coverage() -> None:
    """Miner A served 15 expected attributions; a policy demanding 46 must abstain."""

    context = make_window_context()
    decision = decide_weight_submission(
        context.rounds,
        terminal=context.terminal,
        registered=context.registered,
        window_start_epoch=WINDOW_START,
        window_end_epoch=WINDOW_END,
        decision_policy=WeightDecisionPolicy(min_expected_attributions=46),
    )
    assert decision.abstain_reasons == ["coverage_insufficient"]
    by_hotkey = {row.hotkey: row for row in decision.rows}
    assert by_hotkey["MinerA"].classification == "verified_serving"
    assert by_hotkey["MinerA"].weight > 0.0
    assert by_hotkey["MinerA"].expected_attributions == 15
    # Coverage is only ever demanded of miners assigned at close and outside
    # grace: F is in grace, G is unassigned, so with a threshold every serving
    # miner clears the same window submits.
    assert (
        decide_weight_submission(
            context.rounds,
            terminal=context.terminal,
            registered=context.registered,
            window_start_epoch=WINDOW_START,
            window_end_epoch=WINDOW_END,
            decision_policy=WeightDecisionPolicy(min_expected_attributions=15),
        ).decision
        == "submit"
    )


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
    terminal_manifest = context.manifests[2]

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
    # At the terminal manifest's own height the registered view must be the
    # same block: same hash and same epoch, or the two views are different
    # chain segments.
    same_block = registered_set(
        finalized_height=terminal_manifest.finalized_height,
        finalized_block_hash=terminal_manifest.finalized_block_hash,
        finalized_epoch=terminal_manifest.finalized_epoch,
    )
    assert decide(same_block).decision == "submit"
    forked = registered_set(
        finalized_height=terminal_manifest.finalized_height,
        finalized_epoch=terminal_manifest.finalized_epoch,
    )
    assert forked.finalized_block_hash != terminal_manifest.finalized_block_hash
    assert decide(forked).abstain_reasons == ["registered_set_unbound"]
    epoch_forked = registered_set(
        finalized_height=terminal_manifest.finalized_height,
        finalized_block_hash=terminal_manifest.finalized_block_hash,
        finalized_epoch=terminal_manifest.finalized_epoch + 1,
    )
    assert decide(epoch_forked).abstain_reasons == ["registered_set_unbound"]
    epoch_behind = registered_set(finalized_epoch=terminal_manifest.finalized_epoch - 1)
    assert decide(epoch_behind).abstain_reasons == ["registered_set_unbound"]

    # A central mass-eviction at window close is not miner evidence.
    gamma = window_deployment("fixture-gamma", EXTRA_MINERS[:1], campaign_sequence=3)
    shrunken = build_probe_manifest(
        context.policy,
        [gamma],
        sequence=4,
        previous=terminal_manifest.manifest_digest_sha256,
        issued_at=BASE_EPOCH + 3_400,
        expires_at=BASE_EPOCH + 3_400 + 3_600,
        finalized_height=FINALIZED_HEIGHT + 45,
        finalized_block_hash=terminal_manifest.finalized_block_hash[::-1],
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


def _reduced_window(
    context: Any, *, prior: AssignedBaseline | None, policy: WeightDecisionPolicy | None = None
) -> ValidatorWeightDecision:
    """A new window whose very first manifest is already reduced to MinerA."""

    reduced_alpha = window_deployment("fixture-alpha", MINERS[:1], campaign_sequence=1)
    reduced = build_probe_manifest(
        context.policy,
        [reduced_alpha],
        sequence=4,
        previous=context.manifests[2].manifest_digest_sha256,
        issued_at=WINDOW_END,
        expires_at=WINDOW_END + 3_600,
        finalized_height=FINALIZED_HEIGHT + 45,
        finalized_block_hash=label_digest("block-four"),
    )
    state_three = verify_active_assignment_manifest(
        context.manifests[2],
        sign_manifest(context.manifests[2], context.keys),
        context.policy,
        context.states[2],
        evaluation_epoch=BASE_EPOCH + 3_000,
    ).next_chain_state
    rounds = [
        build_round(
            context.policy,
            reduced,
            state_three,
            context.keys,
            responders={"fixture-alpha": "MinerA"},
            label=f"reduced-{index}",
            evaluation_epoch=WINDOW_END + 60 + 60 * index,
        )
        for index in range(24)
    ]
    return decide_weight_submission(
        rounds,
        terminal=TerminalManifestObservation(
            status="verified", evaluated_at_epoch=WINDOW_END + 3_000, manifest=reduced
        ),
        registered=registered_set(finalized_height=FINALIZED_HEIGHT + 60),
        window_start_epoch=WINDOW_END,
        window_end_epoch=WINDOW_END + 3_000,
        decision_policy=policy,
        prior_assigned_baseline=prior,
    )


def test_mass_unassignment_baseline_survives_the_window_boundary() -> None:
    context = make_window_context()
    carried = context.decision.assigned_baseline
    assert carried is not None and carried.assigned_miner_count == 6

    # With the previous window's baseline the boundary eviction is caught.
    guarded = _reduced_window(context, prior=carried)
    assert guarded.abstain_reasons == ["mass_unassignment_guard"]
    assert guarded.prior_assigned_baseline == carried
    assert guarded.prior_assigned_baseline_status == "applied"
    assert guarded.max_assigned_miner_count == 6
    assert guarded.terminal_assigned_miner_count == 1
    assert classes(guarded) == {
        "MinerA": "verified_serving",
        "MinerB": "unassigned",
        "MinerC": "unassigned",
        "MinerD": "unassigned",
        "MinerE": "unassigned",
        "MinerF": "unassigned",
        "MinerG": "unassigned",
    }
    # The successor baseline is the verified terminal set, even on abstain.
    assert guarded.assigned_baseline is not None
    assert guarded.assigned_baseline.assigned_miner_count == 1
    assert guarded.assigned_baseline.manifest_sequence == 4

    # The first window of a coordinator has nothing to compare against and
    # says so in the record.
    first = _reduced_window(context, prior=None)
    assert first.decision == "submit"
    assert first.prior_assigned_baseline_status == "absent"

    # A baseline older than the policy age no longer widens the guard, and
    # the record shows it was expired rather than applied.
    stale = _reduced_window(
        context,
        prior=carried.model_copy(update={"established_at_epoch": WINDOW_END - 86_401}),
    )
    assert stale.decision == "submit"
    assert stale.prior_assigned_baseline_status == "expired"
    assert stale.max_assigned_miner_count == 1
    assert stale.assigned_baseline is not None and stale.assigned_baseline.manifest_sequence == 4
    tightened = _reduced_window(
        context,
        prior=carried.model_copy(update={"established_at_epoch": WINDOW_END - 86_401}),
        policy=WeightDecisionPolicy(assigned_baseline_max_age_seconds=90_000),
    )
    assert tightened.abstain_reasons == ["mass_unassignment_guard"]

    # A baseline from the future, from a later sequence than the terminal, or
    # naming a different manifest at a sequence the window also saw, is an
    # input error rather than an abstention.
    for bad in (
        carried.model_copy(update={"established_at_epoch": WINDOW_END + 1}),
        carried.model_copy(update={"manifest_sequence": 5}),
        carried.model_copy(update={"manifest_sequence": 4}),
    ):
        with pytest.raises(WeightDecisionError) as failure:
            _reduced_window(context, prior=bad)
        assert failure.value.code == "decision_baseline_invalid"

    # An outage carries the applied baseline forward untouched; an expired
    # one is dropped so the successor starts clean.
    outage = decide_weight_submission(
        context.rounds,
        terminal=TerminalManifestObservation(
            status="unavailable", evaluated_at_epoch=WINDOW_END, rejection_code="timeout"
        ),
        registered=context.registered,
        window_start_epoch=WINDOW_START,
        window_end_epoch=WINDOW_END,
        prior_assigned_baseline=assigned_baseline(
            context.manifests[0], established_at_epoch=WINDOW_START
        ),
    )
    assert outage.assigned_baseline == outage.prior_assigned_baseline
    assert outage.prior_assigned_baseline_status == "applied"
    assert outage.max_assigned_miner_count == 6
    dropped = decide_weight_submission(
        context.rounds,
        terminal=TerminalManifestObservation(
            status="unavailable", evaluated_at_epoch=WINDOW_END, rejection_code="timeout"
        ),
        registered=context.registered,
        window_start_epoch=WINDOW_START,
        window_end_epoch=WINDOW_END,
        prior_assigned_baseline=assigned_baseline(
            context.manifests[0], established_at_epoch=WINDOW_START - 90_000
        ),
    )
    assert dropped.prior_assigned_baseline_status == "expired"
    assert dropped.assigned_baseline is None


def test_window_manifests_must_form_one_coherent_chain() -> None:
    context = make_window_context()
    keys, policy = context.keys, context.policy

    def decide(rounds: list[ProbeRound], terminal: TerminalManifestObservation) -> None:
        decide_weight_submission(
            rounds,
            terminal=terminal,
            registered=context.registered,
            window_start_epoch=WINDOW_START,
            window_end_epoch=WINDOW_END,
        )

    # Two differently signed manifests at sequence 2 inside one window.
    alpha = window_deployment("fixture-alpha", MINERS[:3], campaign_sequence=1)
    divergent = build_probe_manifest(
        policy,
        [alpha],
        sequence=2,
        previous=context.manifests[0].manifest_digest_sha256,
        issued_at=BASE_EPOCH + 1_500,
        expires_at=BASE_EPOCH + 1_500 + 3_600,
        finalized_height=FINALIZED_HEIGHT + 20,
        finalized_block_hash=context.manifests[1].finalized_block_hash,
    )
    assert divergent.manifest_digest_sha256 != context.manifests[1].manifest_digest_sha256
    divergent_round = build_round(
        policy,
        divergent,
        context.states[1],
        keys,
        responders={"fixture-alpha": "MinerA"},
        label="divergent",
        evaluation_epoch=BASE_EPOCH + 2_000,
    )
    with pytest.raises(WeightDecisionError) as failure:
        decide([*context.rounds, divergent_round], context.terminal)
    assert failure.value.code == "decision_manifest_chain_incoherent"

    # A finalized epoch that goes backwards between sequences, and a fork at
    # one height, are equally incoherent even when every manifest verifies.
    def successor(**changes: Any) -> TerminalManifestObservation:
        values: dict[str, Any] = {
            "sequence": 4,
            "previous": context.manifests[2].manifest_digest_sha256,
            "issued_at": BASE_EPOCH + 3_300,
            "expires_at": BASE_EPOCH + 3_300 + 3_600,
            "finalized_height": FINALIZED_HEIGHT + 45,
            "finalized_block_hash": label_digest("block-four"),
        }
        values.update(changes)
        manifest = build_probe_manifest(
            policy, [item for item in context.manifests[2].deployments], **values
        )
        return TerminalManifestObservation(
            status="verified", evaluated_at_epoch=WINDOW_END, manifest=manifest
        )

    with pytest.raises(WeightDecisionError) as failure:
        decide(
            context.rounds,
            successor(
                finalized_height=FINALIZED_HEIGHT + 40,
                finalized_block_hash=label_digest("fork"),
            ),
        )
    assert failure.value.code == "decision_manifest_chain_incoherent"
    with pytest.raises(WeightDecisionError) as failure:
        decide(context.rounds, successor(previous=context.manifests[1].manifest_digest_sha256))
    assert failure.value.code == "decision_manifest_chain_incoherent"
    with pytest.raises(WeightDecisionError) as failure:
        decide(context.rounds, successor(finalized_height=FINALIZED_HEIGHT + 39))
    assert failure.value.code == "decision_manifest_chain_incoherent"
    with pytest.raises(WeightDecisionError) as failure:
        decide(
            context.rounds,
            successor(
                finalized_height=FINALIZED_HEIGHT + 40,
                finalized_block_hash=context.manifests[2].finalized_block_hash,
                issued_at=BASE_EPOCH + 2_999,
            ),
        )
    assert failure.value.code == "decision_manifest_chain_incoherent"


def test_manifest_finalized_epoch_rollback_is_incoherent() -> None:
    """A later sequence with a lower finalized epoch cannot be part of the same chain."""

    from misscomputer_subnet.assignment_probe import build_active_assignment_manifest

    context = make_window_context()
    rolled = build_active_assignment_manifest(
        context.policy,
        finalized_height=FINALIZED_HEIGHT + 45,
        finalized_block_hash=label_digest("block-four"),
        finalized_epoch=context.manifests[2].finalized_epoch - 1,
        sequence=4,
        previous_manifest_digest_sha256=context.manifests[2].manifest_digest_sha256,
        issued_at_epoch=BASE_EPOCH + 3_300,
        expires_at_epoch=BASE_EPOCH + 3_300 + 3_600,
        route_host_suffix=context.manifests[2].route_host_suffix,
        probe_port=context.manifests[2].probe_port,
        deployments=context.manifests[2].deployments,
    )
    with pytest.raises(WeightDecisionError) as failure:
        decide_weight_submission(
            context.rounds,
            terminal=TerminalManifestObservation(
                status="verified", evaluated_at_epoch=WINDOW_END, manifest=rolled
            ),
            registered=context.registered,
            window_start_epoch=WINDOW_START,
            window_end_epoch=WINDOW_END,
        )
    assert failure.value.code == "decision_manifest_chain_incoherent"


def test_mutated_verified_reports_are_refused_not_consumed() -> None:
    """Appending to a frozen report's nested list after validation must not change a decision."""

    context = make_window_context()
    victim = context.rounds[0]
    extra = ProbeObservation.model_validate(
        victim.report.observations[0].model_dump(mode="json", by_alias=True)
    )
    tampered = ProbeRound(manifest=victim.manifest, report=victim.report)
    tampered.report.observations.append(extra)
    assert len(tampered.report.observations) == 3
    assert tampered.report.deployment_count == 2
    with pytest.raises(WeightDecisionError) as failure:
        decide_weight_submission(
            [tampered, *context.rounds[1:]],
            terminal=context.terminal,
            registered=context.registered,
            window_start_epoch=WINDOW_START,
            window_end_epoch=WINDOW_END,
        )
    assert failure.value.code == "decision_round_invalid"
    with pytest.raises(ProbeScoringError, match="scoring_round_invalid"):
        accumulate_scoring_window(
            [tampered],
            validator_uid=VALIDATOR_UID,
            validator_hotkey=VALIDATOR_HOTKEY,
            window_start_epoch=WINDOW_START,
            window_end_epoch=WINDOW_END,
        )
    # Restore the shared object so later assertions see the pristine round.
    tampered.report.observations.pop()
    clean = decide_weight_submission(
        context.rounds,
        terminal=context.terminal,
        registered=context.registered,
        window_start_epoch=WINDOW_START,
        window_end_epoch=WINDOW_END,
    )
    assert validator_weight_decision_bytes(clean) == validator_weight_decision_bytes(
        context.decision
    )
    # The same holds for a mutated terminal manifest.
    terminal_manifest = context.manifests[2]
    terminal_manifest.deployments.pop()
    with pytest.raises(WeightDecisionError) as failure:
        decide_weight_submission(
            context.rounds,
            terminal=TerminalManifestObservation(
                status="verified", evaluated_at_epoch=WINDOW_END, manifest=terminal_manifest
            ),
            registered=context.registered,
            window_start_epoch=WINDOW_START,
            window_end_epoch=WINDOW_END,
        )
    assert failure.value.code == "decision_terminal_status_invalid"


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
    assert (
        build_initial_manifest_chain_state(make_window_context().policy).last_finalized_epoch
        is None
    )
