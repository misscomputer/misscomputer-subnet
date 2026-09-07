# SPDX-License-Identifier: AGPL-3.0-only

"""Frozen validator decision semantics: abstain, zero, submit."""

from __future__ import annotations

import json
import random
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from fractions import Fraction
from pathlib import Path
from threading import Event
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
    reseal_decision,
    window_deployment,
)
from pydantic import ValidationError

from misscomputer_subnet import weight_plan as weight_plan_module
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
    RegisteredMiner,
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
    eligible_weight_targets,
    snapshot_identity_fingerprint,
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
    assert abstained.assigned_baseline == assigned_baseline(
        context.manifests[2], established_at_epoch=WINDOW_END
    )
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
        current_finalized_height=FINALIZED_HEIGHT,
    ).next_chain_state
    verify_active_assignment_manifest(
        short,
        sign_manifest(short, keys),
        policy,
        state_three,
        evaluation_epoch=WINDOW_END,
        current_finalized_height=FINALIZED_HEIGHT,
    )
    with pytest.raises(AssignmentProbeError) as failure:
        verify_active_assignment_manifest(
            short,
            sign_manifest(short, keys),
            policy,
            state_three,
            evaluation_epoch=WINDOW_END + 1,
            current_finalized_height=FINALIZED_HEIGHT,
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
    # A first window with an in-window drop seals the window's largest set
    # (manifest 3) as the baseline, not the reduced terminal set.
    assert guarded.assigned_baseline == assigned_baseline(
        terminal_manifest, established_at_epoch=WINDOW_END
    )
    permissive = decide(
        context.registered,
        terminal=TerminalManifestObservation(
            status="verified", evaluated_at_epoch=WINDOW_END, manifest=shrunken
        ),
        policy=WeightDecisionPolicy(max_assigned_drop_permille=1_000),
    )
    assert permissive.decision == "submit"
    # Only a terminal manifest that clears the guard refreshes the baseline.
    assert permissive.assigned_baseline == assigned_baseline(
        shrunken, established_at_epoch=WINDOW_END
    )


def _reduced_manifest(context: Any, *, sequence: int, previous: str, issued_at: int) -> Any:
    """A manifest at ``sequence`` that assigns MinerA alone."""

    reduced_alpha = build_deployment(
        "fixture-alpha",
        MINERS[:1],
        campaign_sequence=1,
        expires_at_block=FINALIZED_HEIGHT + 2_000,
        ticket_expires_at_epoch=issued_at + 7_200,
    )
    return build_probe_manifest(
        context.policy,
        [reduced_alpha],
        sequence=sequence,
        previous=previous,
        issued_at=issued_at,
        expires_at=issued_at + 3_600,
        finalized_height=FINALIZED_HEIGHT + 5 * (sequence + 5),
        finalized_block_hash=label_digest(f"block-{sequence}"),
    )


def _reduced_window(
    context: Any,
    *,
    prior: AssignedBaseline | None,
    policy: WeightDecisionPolicy | None = None,
    sequence: int = 4,
    window_start: int = WINDOW_END,
    chain: tuple[Any, ...] = (),
) -> ValidatorWeightDecision:
    """A new window whose very first manifest is already reduced to MinerA.

    ``chain`` lists the manifests accepted after the golden window's manifest
    3 and before this window's reduced manifest, in sequence order.
    """

    state = verify_active_assignment_manifest(
        context.manifests[2],
        sign_manifest(context.manifests[2], context.keys),
        context.policy,
        context.states[2],
        evaluation_epoch=BASE_EPOCH + 3_000,
        current_finalized_height=FINALIZED_HEIGHT,
    ).next_chain_state
    previous = context.manifests[2].manifest_digest_sha256
    for manifest in chain:
        state = verify_active_assignment_manifest(
            manifest,
            sign_manifest(manifest, context.keys),
            context.policy,
            state,
            evaluation_epoch=manifest.issued_at_epoch,
            current_finalized_height=FINALIZED_HEIGHT,
        ).next_chain_state
        previous = manifest.manifest_digest_sha256
    reduced = _reduced_manifest(
        context, sequence=sequence, previous=previous, issued_at=window_start
    )
    rounds = [
        build_round(
            context.policy,
            reduced,
            state,
            context.keys,
            responders={"fixture-alpha": "MinerA"},
            label=f"reduced-{sequence}-{index}",
            evaluation_epoch=window_start + 60 + 60 * index,
        )
        for index in range(24)
    ]
    return decide_weight_submission(
        rounds,
        terminal=TerminalManifestObservation(
            status="verified", evaluated_at_epoch=window_start + 3_000, manifest=reduced
        ),
        registered=registered_set(finalized_height=reduced.finalized_height + 15),
        window_start_epoch=window_start,
        window_end_epoch=window_start + 3_000,
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
    # A guarded drop never anchors the baseline: the pre-drop set is carried
    # forward untouched, so the reduced set cannot become the comparison
    # point for the next window.
    assert guarded.assigned_baseline == carried
    assert guarded.assigned_baseline.assigned_miner_count == 6
    assert guarded.assigned_baseline.manifest_sequence == 3

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

    # An outage carries the largest verified in-window set. On a tie it uses
    # the fresh in-window evidence rather than preserving an older baseline.
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
    assert outage.assigned_baseline == assigned_baseline(
        context.manifests[2], established_at_epoch=WINDOW_END
    )
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
    assert dropped.assigned_baseline == assigned_baseline(
        context.manifests[2], established_at_epoch=WINDOW_END
    )


@pytest.mark.parametrize("expired_prior", [False, True])
@pytest.mark.parametrize(
    ("terminal_status", "terminal_reason"),
    [("unavailable", "manifest_unavailable"), ("rejected", "manifest_invalid")],
)
def test_outage_window_carries_verified_max_into_next_reduction(
    *, expired_prior: bool, terminal_status: Any, terminal_reason: str
) -> None:
    """A close-time outage cannot erase a first-window or expired-prior guard horizon."""

    context = make_window_context()
    prior = (
        assigned_baseline(context.manifests[0], established_at_epoch=WINDOW_START - 90_000)
        if expired_prior
        else None
    )
    outage = decide_weight_submission(
        context.rounds,
        terminal=TerminalManifestObservation(
            status=terminal_status,
            evaluated_at_epoch=WINDOW_END,
            rejection_code="timeout" if terminal_status == "unavailable" else "manifest_stale",
        ),
        registered=context.registered,
        window_start_epoch=WINDOW_START,
        window_end_epoch=WINDOW_END,
        prior_assigned_baseline=prior,
    )
    assert outage.abstain_reasons == [terminal_reason]
    assert outage.prior_assigned_baseline_status == ("expired" if expired_prior else "absent")
    assert outage.assigned_baseline == assigned_baseline(
        context.manifests[2], established_at_epoch=WINDOW_END
    )

    reduced = _reduced_window(context, prior=outage.assigned_baseline)
    assert reduced.decision == "abstain"
    assert reduced.abstain_reasons == ["mass_unassignment_guard"]
    assert reduced.max_assigned_miner_count == 6
    assert reduced.terminal_assigned_miner_count == 1
    assert reduced.assigned_baseline == outage.assigned_baseline


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
    # Move weight between two attested rows so the vector stays normalized:
    # the rows no longer match the digest they were sealed under.
    shifted = 0.2 - document["rows"][0]["weight"]
    document["rows"][0]["weight"] = 0.2
    document["rows"][1]["weight"] -= shifted
    assert document["rows"][1]["weight"] > 0.0
    with pytest.raises(ValidationError, match="weight_plan_rows_digest_mismatch"):
        ValidatorWeightDecision.model_validate(document)
    with pytest.raises(ValueError, match="document_not_canonical"):
        parse_validator_weight_decision(json.dumps(json.loads(rendered)).encode() + b"\n")
    assert (
        build_initial_manifest_chain_state(make_window_context().policy).last_finalized_epoch
        is None
    )


def test_guarded_drop_cannot_redirect_the_next_window() -> None:
    """The baseline a guarded window hands on is the pre-drop set, so the drop stays guarded."""

    context = make_window_context()
    carried = context.decision.assigned_baseline
    assert carried is not None and carried.assigned_miner_count == 6
    guarded = _reduced_window(context, prior=carried)
    assert guarded.abstain_reasons == ["mass_unassignment_guard"]
    assert guarded.assigned_baseline == carried
    assert guarded.terminal_manifest_sequence == 4

    # The window after the drop inherits the pre-drop baseline, so the
    # unchanged reduced assignment is guarded again rather than accepted as
    # the new normal; MinerA never receives the whole vector.
    reduced_four = _reduced_manifest(
        context,
        sequence=4,
        previous=context.manifests[2].manifest_digest_sha256,
        issued_at=WINDOW_END,
    )
    following = _reduced_window(
        context,
        prior=guarded.assigned_baseline,
        sequence=5,
        window_start=WINDOW_END + 3_000,
        chain=(reduced_four,),
    )
    assert following.abstain_reasons == ["mass_unassignment_guard"]
    assert following.prior_assigned_baseline == carried
    assert following.prior_assigned_baseline_status == "applied"
    assert following.max_assigned_miner_count == 6
    assert following.assigned_baseline == carried
    # Had the guarded window refreshed its baseline to the reduced set, the
    # very next window would have redirected every weight to MinerA.
    refreshed_to_drop = assigned_baseline(reduced_four, established_at_epoch=WINDOW_END + 3_000)
    assert refreshed_to_drop.assigned_miner_count == 1
    redirected = _reduced_window(
        context,
        prior=refreshed_to_drop,
        sequence=5,
        window_start=WINDOW_END + 3_000,
        chain=(reduced_four,),
    )
    assert redirected.decision == "submit"
    assert [row.hotkey for row in redirected.rows if row.weight > 0.0] == ["MinerA"]
    # The guard only releases once the baseline ages out by policy, which is
    # the operator's declared tolerance, never a consequence of the drop itself.
    aged = _reduced_window(
        context,
        prior=carried.model_copy(update={"established_at_epoch": WINDOW_END + 3_000 - 86_401}),
        sequence=5,
        window_start=WINDOW_END + 3_000,
        chain=(reduced_four,),
    )
    assert aged.prior_assigned_baseline_status == "expired"
    assert aged.decision == "submit"

    # The sealed record enforces the same rule: a guarded record whose
    # successor baseline is the reduced terminal set is refused, while the
    # honest carried form is accepted and unsubmittable.
    rendered = validator_weight_decision_bytes(guarded)
    document = json.loads(rendered)
    refreshed = forged_decision(
        rendered,
        assigned_baseline=assigned_baseline(
            reduced_four, established_at_epoch=guarded.window_end_epoch
        ).model_dump(mode="json"),
    )
    with pytest.raises(ValidationError, match="assigned_baseline_not_derived"):
        ValidatorWeightDecision.model_validate(refreshed)
    parsed = ValidatorWeightDecision.model_validate(document)
    assert parsed.assigned_baseline is not None
    assert parsed.assigned_baseline.assigned_miner_count == 6
    with pytest.raises(WeightDecisionError):
        weight_plan_rows_for_submission(parsed)
    # A carried baseline that is not the largest set, or that names the
    # terminal sequence, is equally refused.
    five_identities = document["assigned_baseline"]["assigned_identities"][:5]
    for successor in (
        {
            **document["assigned_baseline"],
            "assigned_miner_count": 5,
            "assigned_identities": five_identities,
            "assigned_identity_digest_sha256": canonical_digest(
                [[item["uid"], item["hotkey"]] for item in five_identities]
            ),
        },
        {**document["assigned_baseline"], "established_at_epoch": WINDOW_START},
        {**document["assigned_baseline"], "manifest_sequence": 4},
    ):
        with pytest.raises(ValidationError, match="assigned_baseline_not_derived"):
            ValidatorWeightDecision.model_validate(
                forged_decision(
                    rendered,
                    assigned_baseline=successor,
                )
            )


def test_mass_guard_counts_registered_identities_only() -> None:
    """Padding a manifest with unregistered identities does not hide a registered drop."""

    context = make_window_context()
    ghosts = [(900 + index, f"Ghost{index}") for index in range(5)]
    padded_alpha = build_deployment(
        "fixture-alpha",
        [MINERS[0], *ghosts],
        campaign_sequence=1,
        expires_at_block=FINALIZED_HEIGHT + 2_000,
        ticket_expires_at_epoch=WINDOW_END + 3_600,
    )
    padded = build_probe_manifest(
        context.policy,
        [padded_alpha],
        sequence=4,
        previous=context.manifests[2].manifest_digest_sha256,
        issued_at=BASE_EPOCH + 3_400,
        expires_at=BASE_EPOCH + 3_400 + 3_600,
        finalized_height=FINALIZED_HEIGHT + 45,
        finalized_block_hash=label_digest("padded"),
    )
    assert len({r.miner_hotkey for d in padded.deployments for r in d.replicas}) == 6

    def decide(policy: WeightDecisionPolicy | None = None) -> ValidatorWeightDecision:
        return decide_weight_submission(
            context.rounds,
            terminal=TerminalManifestObservation(
                status="verified", evaluated_at_epoch=WINDOW_END, manifest=padded
            ),
            registered=context.registered,
            window_start_epoch=WINDOW_START,
            window_end_epoch=WINDOW_END,
            decision_policy=policy,
        )

    decision = decide()
    assert decision.abstain_reasons == ["mass_unassignment_guard"]
    assert decision.terminal_assigned_miner_count == 1
    assert decision.max_assigned_miner_count == 6
    assert {row.hotkey for row in decision.rows if row.assigned_at_close} == {"MinerA"}
    assert decision.assigned_baseline == assigned_baseline(
        context.manifests[2], established_at_epoch=WINDOW_END
    )
    # Even with the guard disabled, the sealed terminal set names registered
    # identities only, so the padding never enters a baseline either.
    permissive = decide(WeightDecisionPolicy(max_assigned_drop_permille=1_000))
    assert permissive.decision == "submit"
    assert permissive.assigned_baseline is not None
    assert permissive.assigned_baseline.assigned_miner_count == 1
    assert permissive.assigned_baseline.assigned_identity_digest_sha256 == canonical_digest(
        [[10, "MinerA"]]
    )
    # A record that claims a larger terminal set than its rows assign is a
    # forgery: the count is exactly the rows assigned at close.
    rendered = (FIXTURES / "validator-weight-decision.v1.json").read_bytes()
    document = json.loads(rendered)
    for terminal_count in (7, 5):
        with pytest.raises(ValidationError, match="assigned_counts_invalid"):
            ValidatorWeightDecision.model_validate(
                forged_decision(
                    rendered,
                    terminal_assigned_miner_count=terminal_count,
                    max_assigned_miner_count=max(terminal_count, 6),
                )
            )
    # And the successor baseline's identity digest is always checked.
    with pytest.raises(ValidationError, match="baseline_assignment_not_derived"):
        ValidatorWeightDecision.model_validate(
            forged_decision(
                rendered,
                assigned_baseline={
                    **document["assigned_baseline"],
                    "assigned_identity_digest_sha256": canonical_digest([[10, "MinerA"]]),
                },
            )
        )


def test_digest_valid_six_to_one_rewrite_cannot_reseal_assignment_evidence() -> None:
    """Manifest evidence and scoring opportunities expose a coherent 6-to-1 rewrite."""

    rendered = validator_weight_decision_bytes(make_window_context().decision)
    document = json.loads(rendered)
    evidence = document["assignment_manifest_evidence"]

    def reseal_manifest(manifest: dict[str, Any]) -> None:
        manifest["deployments"] = sorted(
            manifest["deployments"], key=lambda item: item["deployment_id"]
        )
        manifest["assignment_vector_digest_sha256"] = canonical_digest(manifest["deployments"])
        unsigned = {
            key: value for key, value in manifest.items() if key != "manifest_digest_sha256"
        }
        manifest["manifest_digest_sha256"] = canonical_digest(unsigned)

    # Move the terminal-only MinerF deployment into sequence 2, making that
    # manifest's registered assignment set six, then reduce sequence 3 to F.
    # Every nested and outer digest is resealed and the chain link is repaired.
    delta = next(
        item
        for item in evidence[2]["manifest"]["deployments"]
        if item["deployment_id"] == "fixture-delta"
    )
    evidence[1]["manifest"]["deployments"].append(delta)
    reseal_manifest(evidence[1]["manifest"])
    evidence[2]["manifest"]["deployments"] = [delta]
    evidence[2]["manifest"]["previous_manifest_digest_sha256"] = evidence[1]["manifest"][
        "manifest_digest_sha256"
    ]
    reseal_manifest(evidence[2]["manifest"])

    document["terminal_manifest_digest_sha256"] = evidence[2]["manifest"]["manifest_digest_sha256"]
    document["terminal_assigned_miner_count"] = 1
    document["max_assigned_miner_count"] = 6
    document["decision"] = "abstain"
    document["abstain_reasons"] = ["mass_unassignment_guard"]
    for row in document["rows"]:
        row["assigned_at_close"] = row["hotkey"] == "MinerF"

    identities = [
        {"uid": row["uid"], "hotkey": row["hotkey"]}
        for row in document["rows"]
        if row["hotkey"] != "MinerG"
    ]
    document["assigned_baseline"] = {
        "established_at_epoch": document["window_end_epoch"],
        "manifest_sequence": 2,
        "manifest_digest_sha256": evidence[1]["manifest"]["manifest_digest_sha256"],
        "assigned_miner_count": 6,
        "assigned_identity_digest_sha256": canonical_digest(
            [[item["uid"], item["hotkey"]] for item in identities]
        ),
        "assigned_identities": identities,
    }
    forged = reseal_decision(document)

    # Sequence 2 now claims F was present for its twelve linked reports, but
    # the immutable scoring summary records only F's nine sequence-3
    # opportunities. Exact per-manifest opportunity derivation refuses it.
    with pytest.raises(ValidationError, match="scoring_window_evidence_inconsistent"):
        ValidatorWeightDecision.model_validate(forged)


def test_digest_valid_six_to_one_rewrite_cannot_drop_report_manifests() -> None:
    """All sealed reports retain their exact manifest binding in a 6-to-1 rewrite."""

    document = json.loads(validator_weight_decision_bytes(make_window_context().decision))
    evidence = document["assignment_manifest_evidence"]
    reports = [report for item in evidence for report in item["scoring_reports"]]
    terminal = evidence[-1]
    delta = next(
        item
        for item in terminal["manifest"]["deployments"]
        if item["deployment_id"] == "fixture-delta"
    )
    terminal["manifest"]["deployments"] = [delta]
    terminal["manifest"]["assignment_vector_digest_sha256"] = canonical_digest([delta])
    unsigned_manifest = {
        key: value for key, value in terminal["manifest"].items() if key != "manifest_digest_sha256"
    }
    terminal["manifest"]["manifest_digest_sha256"] = canonical_digest(unsigned_manifest)
    terminal["scoring_reports"] = sorted(reports, key=lambda report: report["report_digest_sha256"])
    document["assignment_manifest_evidence"] = [terminal]
    document["terminal_manifest_digest_sha256"] = terminal["manifest"]["manifest_digest_sha256"]
    document["terminal_assigned_miner_count"] = 1
    document["max_assigned_miner_count"] = 1
    for row in document["rows"]:
        row["assigned_at_close"] = row["hotkey"] == "MinerF"
        if row["hotkey"] == "MinerG":
            row["first_seen_epoch"] = None
    document["assigned_baseline"] = {
        "established_at_epoch": document["window_end_epoch"],
        "manifest_sequence": terminal["manifest"]["sequence"],
        "manifest_digest_sha256": terminal["manifest"]["manifest_digest_sha256"],
        "assigned_miner_count": 1,
        "assigned_identity_digest_sha256": canonical_digest([[15, "MinerF"]]),
        "assigned_identities": [{"uid": 15, "hotkey": "MinerF"}],
    }

    # This was accepted when the evidence contained only freely remappable
    # report digests. Full reports still name sequences 1 and 2 (and the
    # original sequence-3 digest), so exact round reconstruction refuses it.
    with pytest.raises(ValidationError, match="scoring_window_evidence_inconsistent"):
        ValidatorWeightDecision.model_validate(reseal_decision(document))


def test_manifest_chain_must_be_unbroken_across_omitted_sequences() -> None:
    """Only actual digest-linked transitions are required across a decision window."""

    context = make_window_context()
    policy = context.policy
    alpha = window_deployment("fixture-alpha", MINERS[:3], campaign_sequence=1)
    fork_two = build_probe_manifest(
        policy,
        [alpha],
        sequence=2,
        previous=context.manifests[0].manifest_digest_sha256,
        issued_at=BASE_EPOCH + 1_500,
        expires_at=BASE_EPOCH + 1_500 + 3_600,
        finalized_height=FINALIZED_HEIGHT + 20,
        finalized_block_hash=label_digest("fork-two"),
    )
    fork_three = build_probe_manifest(
        policy,
        [alpha],
        sequence=3,
        previous=fork_two.manifest_digest_sha256,
        issued_at=BASE_EPOCH + 3_000,
        expires_at=BASE_EPOCH + 3_000 + 3_600,
        finalized_height=FINALIZED_HEIGHT + 40,
        finalized_block_hash=label_digest("fork-three"),
    )
    assert fork_two.manifest_digest_sha256 != context.manifests[1].manifest_digest_sha256
    one_only = context.rounds[:24]

    def decide(
        rounds: list[ProbeRound],
        terminal_manifest: Any,
        archived: list[Any] | None = None,
        **changes: Any,
    ) -> ValidatorWeightDecision:
        return decide_weight_submission(
            rounds,
            terminal=TerminalManifestObservation(
                status="verified", evaluated_at_epoch=WINDOW_END, manifest=terminal_manifest
            ),
            registered=context.registered,
            window_start_epoch=WINDOW_START,
            window_end_epoch=WINDOW_END,
            archived_manifests=archived or [],
            **changes,
        )

    # Sequence 1 probed, sequence 2 omitted, terminal from the fork at 3:
    # the missing sequence is a gap, never a pass.
    with pytest.raises(WeightDecisionError) as failure:
        decide(one_only, fork_three)
    assert failure.value.code == "decision_manifest_chain_gap"
    # Supplying the sequence-2 manifest the coordinator really accepted
    # exposes the fork through the broken link.
    with pytest.raises(WeightDecisionError) as failure:
        decide(one_only, fork_three, [context.manifests[1]])
    assert failure.value.code == "decision_manifest_chain_incoherent"
    # The same gap on the honest chain: probing 1 and 3 but not 2.
    one_and_three = [*context.rounds[:24], *context.rounds[36:]]
    with pytest.raises(WeightDecisionError) as failure:
        decide(one_and_three, context.manifests[2])
    assert failure.value.code == "decision_manifest_chain_gap"
    # The archived intermediate closes it and the window is judged normally.
    honest = decide(one_and_three, context.manifests[2], [context.manifests[1]])
    assert honest.decision == "submit"
    assert honest.round_count == 33
    assert classes(honest)["MinerE"] == "verified_serving"
    # Sequence values may jump without an intermediate publication. A
    # terminal that directly links the last probed digest is therefore a
    # complete chain even when its sequence is not previous + 1.
    direct_jump = build_probe_manifest(
        policy,
        list(context.manifests[2].deployments),
        sequence=context.manifests[0].sequence + policy.max_sequence_gap,
        previous=context.manifests[0].manifest_digest_sha256,
        issued_at=BASE_EPOCH + 3_000,
        expires_at=BASE_EPOCH + 3_000 + 3_600,
        finalized_height=FINALIZED_HEIGHT + 40,
        finalized_block_hash=label_digest("direct-bounded-jump"),
    )
    jumped = decide(one_only, direct_jump)
    assert jumped.terminal_manifest_sequence == direct_jump.sequence
    assert jumped.terminal_manifest_digest_sha256 == direct_jump.manifest_digest_sha256
    # Archived manifests are ordinary chain members: they may not lie beyond
    # the terminal, must re-validate, and contribute sightings and assigned
    # set sizes but no evidence.
    beyond = build_probe_manifest(
        policy,
        list(context.manifests[2].deployments),
        sequence=4,
        previous=context.manifests[2].manifest_digest_sha256,
        issued_at=BASE_EPOCH + 3_300,
        expires_at=BASE_EPOCH + 3_300 + 3_600,
        finalized_height=FINALIZED_HEIGHT + 45,
        finalized_block_hash=label_digest("block-four"),
    )
    with pytest.raises(WeightDecisionError) as failure:
        decide(one_and_three, context.manifests[2], [context.manifests[1], beyond])
    assert failure.value.code == "decision_archived_manifest_invalid"
    tampered = type(context.manifests[1]).model_validate(
        context.manifests[1].model_dump(mode="json", by_alias=True)
    )
    tampered.deployments.pop()
    with pytest.raises(WeightDecisionError) as failure:
        decide(one_and_three, context.manifests[2], [tampered])
    assert failure.value.code == "decision_archived_manifest_invalid"
    shrunken = build_probe_manifest(
        policy,
        [window_deployment("fixture-gamma", EXTRA_MINERS[:1], campaign_sequence=3)],
        sequence=4,
        previous=context.manifests[2].manifest_digest_sha256,
        issued_at=BASE_EPOCH + 3_400,
        expires_at=BASE_EPOCH + 3_400 + 3_600,
        finalized_height=FINALIZED_HEIGHT + 45,
        finalized_block_hash=label_digest("block-four"),
    )
    widened = decide(one_only, shrunken, [context.manifests[1], context.manifests[2]])
    assert "mass_unassignment_guard" in widened.abstain_reasons
    assert widened.max_assigned_miner_count == 6
    assert widened.round_count == 24
    assert {row.hotkey: row.first_seen_epoch for row in widened.rows}["MinerE"] == (
        BASE_EPOCH + 1_500
    )
    assert widened.assigned_baseline == assigned_baseline(
        context.manifests[2], established_at_epoch=WINDOW_END
    )
    # A fully linked alternate chain from the same authority is coherent on
    # its own; detecting that it is not the chain the validator accepted is
    # the chain state's job, which is why the archive must be the real one.
    forked = decide(one_only, fork_three, [fork_two])
    assert forked.terminal_manifest_digest_sha256 == fork_three.manifest_digest_sha256


def test_positive_weight_requires_sealed_serving_evidence() -> None:
    """A digest-valid submit record cannot weight a miner it never observed serving."""

    rendered = (FIXTURES / "validator-weight-decision.v1.json").read_bytes()
    document = json.loads(rendered)
    golden = ValidatorWeightDecision.model_validate(document)
    positive = [row for row in golden.rows if row.weight > 0.0]
    assert positive and all(row.attributions >= 1 for row in positive)
    assert sum(row.attributions for row in golden.rows) <= golden.serving_observation_count
    assert golden.round_count <= golden.observation_count
    for row in golden.rows:
        recomputed = sum(
            (
                Fraction(item.opportunity_count, item.replica_count)
                for item in row.replica_share_counts
            ),
            Fraction(0),
        )
        assert sum(item.opportunity_count for item in row.replica_share_counts) == (
            row.opportunities
        )
        assert (row.expected_attributions_numerator, row.expected_attributions_denominator) == (
            recomputed.numerator,
            recomputed.denominator,
        )
        assert recomputed <= row.opportunities
    rows = document["rows"]

    def refuse(code: str, **changes: Any) -> None:
        forged = forged_decision(rendered, **changes)
        assert forged["decision"] == "submit"
        with pytest.raises(ValidationError, match=code):
            ValidatorWeightDecision.model_validate(forged)

    # Every positive row with its attributions zeroed.
    refuse(
        "row_positive_weight_without_evidence",
        rows=[{**row, "attributions": 0} for row in rows],
    )
    # The rows keep their attributions but the record says nothing served,
    # nothing was observed, or no round ran.
    refuse("observation_counts_invalid", serving_observation_count=0)
    refuse("observation_counts_invalid", observation_count=0, serving_observation_count=0)
    refuse("observation_counts_invalid", round_count=0, scoring_window_digest_sha256=None)
    refuse("observation_counts_invalid", round_count=document["observation_count"] + 1)
    refuse(
        "observation_counts_invalid",
        serving_observation_count=sum(row["attributions"] for row in rows) - 1,
    )
    # A row attributed more often than it could answer, or given more
    # opportunities than the window had observations.
    refuse(
        "row_attributions_exceed_opportunities",
        rows=[
            {**row, "opportunities": row["attributions"] - 1} if row["hotkey"] == "MinerE" else row
            for row in rows
        ],
    )
    refuse(
        "observation_counts_invalid",
        rows=[
            {
                **row,
                "opportunities": document["observation_count"] + 1,
                "expected_attributions_numerator": document["observation_count"] + 1,
                "expected_attributions_denominator": 3,
                "replica_share_counts": [
                    {
                        "opportunity_count": document["observation_count"] + 1,
                        "replica_count": 3,
                    }
                ],
            }
            if row["hotkey"] == "MinerA"
            else row
            for row in rows
        ],
    )
    refuse(
        "row_expected_attributions_inconsistent",
        rows=[
            {**row, "expected_attributions_numerator": 0} if row["hotkey"] == "MinerA" else row
            for row in rows
        ],
    )
    # Expected attribution is no larger than opportunities and is the exact,
    # reduced rational sum of the sealed replica-cardinality buckets.
    refuse(
        "row_expected_attributions_inconsistent",
        rows=[
            {
                **row,
                "expected_attributions_numerator": row["opportunities"] + 1,
                "expected_attributions_denominator": 1,
            }
            if row["hotkey"] == "MinerA"
            else row
            for row in rows
        ],
    )
    refuse(
        "row_expected_attributions_inconsistent",
        rows=[
            {
                **row,
                "replica_share_counts": [
                    {"opportunity_count": row["opportunities"], "replica_count": 2}
                ],
            }
            if row["hotkey"] == "MinerA"
            else row
            for row in rows
        ],
    )
    refuse(
        "row_expected_attributions_inconsistent",
        rows=[
            {
                **row,
                "expected_attributions_numerator": row["expected_attributions_numerator"] * 2,
                "expected_attributions_denominator": row["expected_attributions_denominator"] * 2,
            }
            if row["hotkey"] == "MinerA"
            else row
            for row in rows
        ],
    )
    # Positive weight below the sealed scoring policy's own minimum.
    refuse(
        "row_weight_below_min_attributions",
        scoring_policy={**document["scoring_policy"], "min_attributions": 22},
    )
    # The positive weights must be one normalized distribution.
    refuse(
        "weights_not_normalized",
        rows=[
            {**row, "weight": row["weight"] / 2} if row["hotkey"] == "MinerA" else row
            for row in rows
        ],
    )
    # Moving MinerA's weight to MinerG, which was never assigned or probed.
    moved = {row["hotkey"]: row for row in rows}
    refuse(
        "row_positive_weight_without_evidence",
        rows=[
            {**row, "weight": 0.0, "classification": "assigned_unverified"}
            if row["hotkey"] == "MinerA"
            else {**row, "weight": moved["MinerA"]["weight"], "classification": "verified_serving"}
            if row["hotkey"] == "MinerG"
            else row
            for row in rows
        ],
    )
    # The honest direction: a stricter sealed scoring minimum zeroes the
    # rows below it and the resulting record parses and builds a plan.
    context = make_window_context()
    strict = decide_weight_submission(
        context.rounds,
        terminal=context.terminal,
        registered=context.registered,
        window_start_epoch=WINDOW_START,
        window_end_epoch=WINDOW_END,
        scoring_policy=ProbeScoringPolicy(min_attributions=16),
    )
    assert strict.decision == "submit"
    assert [row.hotkey for row in strict.rows if row.weight > 0.0] == [
        "MinerB",
        "MinerC",
        "MinerE",
    ]
    assert classes(strict)["MinerA"] == classes(strict)["MinerD"] == "assigned_unverified"
    parsed = parse_validator_weight_decision(validator_weight_decision_bytes(strict))
    plan = build_weight_plan_from_decision(
        parsed,
        snapshot=metagraph_view(),  # type: ignore[arg-type]
        finalized_block_hash=context.registered.finalized_block_hash,
        version_key=1,
    )
    assert [entry.hotkey for entry in plan.weights] == ["MinerB", "MinerC", "MinerE"]


def _bound_registered(
    miners: list[tuple[int, str]], view: Any, *, reference: RegisteredMinerSet
) -> RegisteredMinerSet:
    """A registered set over ``miners`` that names ``view``'s complete fingerprint."""

    return RegisteredMinerSet(
        network="finney",
        netuid=24,
        finalized=True,
        finalized_height=reference.finalized_height,
        finalized_block_hash=reference.finalized_block_hash,
        finalized_epoch=reference.finalized_epoch,
        validator_uid=reference.validator_uid,
        validator_hotkey=reference.validator_hotkey,
        miners=[RegisteredMiner(uid=uid, hotkey=hotkey) for uid, hotkey in miners],
        metagraph_identity_fingerprint_sha256=snapshot_identity_fingerprint(view),
    )


def test_decision_rows_must_cover_the_complete_eligible_set(monkeypatch: Any) -> None:
    """A decision that silently omits an eligible miner cannot become a plan."""

    context = make_window_context()
    view = metagraph_view()
    hash_ = context.registered.finalized_block_hash
    assert eligible_weight_targets(view, validator_hotkey=VALIDATOR_HOTKEY) == frozenset(  # type: ignore[arg-type]
        REGISTERED_MINERS
    )

    def decide(registered: RegisteredMinerSet) -> ValidatorWeightDecision:
        return decide_weight_submission(
            context.rounds,
            terminal=context.terminal,
            registered=registered,
            window_start_epoch=WINDOW_START,
            window_end_epoch=WINDOW_END,
        )

    def build(decision: ValidatorWeightDecision, snapshot: Any) -> Any:
        return build_weight_plan_from_decision(
            decision, snapshot=snapshot, finalized_block_hash=hash_, version_key=1
        )

    # MinerG is registered and eligible, the fingerprint names the complete
    # snapshot, but the coordinator left G out of the judgement.
    omitting = _bound_registered(
        [item for item in REGISTERED_MINERS if item[1] != "MinerG"],
        view,
        reference=context.registered,
    )
    omitted = decide(omitting)
    assert omitted.decision == "submit" and "MinerG" not in classes(omitted)
    assert omitted.metagraph_identity_fingerprint_sha256 == snapshot_identity_fingerprint(view)  # type: ignore[arg-type]
    with pytest.raises(WeightPlanError, match="complete eligible miner set"):
        build(omitted, view)
    # The raw rows alone would have been accepted, which is exactly why the
    # decision path must demand complete coverage.
    build_weight_plan(
        snapshot=view,  # type: ignore[arg-type]
        validator_hotkey=VALIDATOR_HOTKEY,
        rows=weight_plan_rows_for_submission(omitted),
        version_key=1,
    )
    # The Pydantic decision is frozen only at its outer shell. Prove that an
    # adversarial concurrent append after committed plan rows were captured
    # cannot make later coverage checks see a different nested list. The old
    # implementation accepted the omitted rows as a plan after this append.
    real_fingerprint = weight_plan_module.snapshot_identity_fingerprint
    fingerprint_entered = Event()
    mutation_complete = Event()
    fingerprint_calls = 0

    def racing_fingerprint(snapshot: Any) -> str:
        nonlocal fingerprint_calls
        fingerprint_calls += 1
        if fingerprint_calls == 1:
            fingerprint_entered.set()
            assert mutation_complete.wait(timeout=5)
        return real_fingerprint(snapshot)

    monkeypatch.setattr(weight_plan_module, "snapshot_identity_fingerprint", racing_fingerprint)
    complete_g = next(row for row in context.decision.rows if row.hotkey == "MinerG")
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(build, omitted, view)
        assert fingerprint_entered.wait(timeout=5)
        omitted.rows.append(complete_g)
        mutation_complete.set()
        with pytest.raises(WeightPlanError, match="complete eligible miner set"):
            future.result(timeout=5)
    # An inactive neuron is not eligible: a decision over the active set
    # builds against a snapshot that carries it, and one that judged it does not.
    dormant = MetagraphNeuron(
        uid=99, hotkey="MinerZ", validator_permit=False, tao_stake=1.0, axon=None, active=False
    )
    with_dormant = replace(view, neurons=(*view.neurons, dormant))
    assert eligible_weight_targets(with_dormant, validator_hotkey=VALIDATOR_HOTKEY) == (  # type: ignore[arg-type]
        frozenset(REGISTERED_MINERS)
    )
    complete = decide(
        _bound_registered(list(REGISTERED_MINERS), with_dormant, reference=context.registered)
    )
    assert build(complete, with_dormant).snapshot.identity_fingerprint == (
        complete.metagraph_identity_fingerprint_sha256
    )
    judged_dormant = decide(
        _bound_registered(
            [*REGISTERED_MINERS, (99, "MinerZ")], with_dormant, reference=context.registered
        )
    )
    with pytest.raises(WeightPlanError, match="complete eligible miner set"):
        build(judged_dormant, with_dormant)
    # Another active validator is an eligible target and must be judged; the
    # deciding validator itself never is.
    peer = MetagraphNeuron(
        uid=98, hotkey="ValidatorB", validator_permit=True, tao_stake=500.0, axon=None
    )
    with_peer = replace(view, neurons=(*view.neurons, peer))
    targets = eligible_weight_targets(with_peer, validator_hotkey=VALIDATOR_HOTKEY)  # type: ignore[arg-type]
    assert (98, "ValidatorB") in targets and (VALIDATOR_UID, VALIDATOR_HOTKEY) not in targets
    with pytest.raises(WeightPlanError, match="complete eligible miner set"):
        build(
            decide(
                _bound_registered(list(REGISTERED_MINERS), with_peer, reference=context.registered)
            ),
            with_peer,
        )
    assert build(
        decide(
            _bound_registered(
                sorted([*REGISTERED_MINERS, (98, "ValidatorB")]),
                with_peer,
                reference=context.registered,
            )
        ),
        with_peer,
    ).snapshot.identity_fingerprint == snapshot_identity_fingerprint(with_peer)  # type: ignore[arg-type]
