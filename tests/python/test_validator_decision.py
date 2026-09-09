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
    build_policy,
    label_digest,
    serving_response,
    sign_attestation,
    sign_manifest,
    signer_keys,
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
    build_future_terminal,
    build_round,
    forged_decision,
    forged_decision_with_report,
    future_terminal_decision,
    make_window_context,
    metagraph_view,
    registered_set,
    reseal_decision,
    reseal_observation,
    reseal_report,
    reseal_report_observations,
    successor_policy_valid_from,
    window_deployment,
)
from pydantic import ValidationError

from misscomputer_subnet import weight_plan as weight_plan_module
from misscomputer_subnet.assignment_probe import (
    AssignmentProbeError,
    ProbeObservation,
    ValidatorProbeReport,
    build_initial_manifest_chain_state,
    build_validator_probe_report,
    evaluate_probe_response,
    manifest_effective_expires_at_epoch,
    verify_active_assignment_manifest,
    verify_observation_policy_binding,
)
from misscomputer_subnet.contract_codec import digest as canonical_digest
from misscomputer_subnet.manifest_publication import rebind_manifest_chain_state_trust_policy
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
        trust_policies=[context.policy],
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
            trust_policies=[context.policy],
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
            trust_policies=[context.policy],
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
            trust_policies=[context.policy],
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
        trust_policies=[context.policy],
        window_start_epoch=WINDOW_START,
        window_end_epoch=WINDOW_END,
        decision_policy=WeightDecisionPolicy(min_verified_rounds=46),
    )
    assert few_rounds.abstain_reasons == ["rounds_insufficient"]

    # Pull MinerF out of grace with an archived earlier sighting of its exact
    # identity: nine opportunities are then below a ten-attribution coverage
    # requirement, so F's silence is the validator's sampling gap, never a
    # zero. A sighting for an identity the chain never published is ignored.
    miner_f = (15, "MinerF")
    undersampled = decide_weight_submission(
        context.rounds,
        terminal=context.terminal,
        registered=context.registered,
        trust_policies=[context.policy],
        window_start_epoch=WINDOW_START,
        window_end_epoch=WINDOW_END,
        decision_policy=WeightDecisionPolicy(min_expected_attributions=10),
        identity_first_seen_epoch={miner_f: BASE_EPOCH, (99, "MinerZ"): BASE_EPOCH},
    )
    assert undersampled.abstain_reasons == ["coverage_insufficient"]
    assert classes(undersampled)["MinerF"] == "assigned_undersampled"
    assert {row.hotkey: row.first_seen_epoch for row in undersampled.rows}["MinerF"] == BASE_EPOCH

    # With enough coverage the same silent miner is an honest zero.
    sampled = decide_weight_submission(
        context.rounds,
        terminal=context.terminal,
        registered=context.registered,
        trust_policies=[context.policy],
        window_start_epoch=WINDOW_START,
        window_end_epoch=WINDOW_END,
        identity_first_seen_epoch={miner_f: BASE_EPOCH},
    )
    assert sampled.decision == "submit"
    assert classes(sampled)["MinerF"] == "assigned_unverified"

    with pytest.raises(WeightDecisionError) as failure:
        decide_weight_submission(
            context.rounds,
            terminal=context.terminal,
            registered=context.registered,
            trust_policies=[context.policy],
            window_start_epoch=WINDOW_START,
            window_end_epoch=WINDOW_END,
            identity_first_seen_epoch={miner_f: BASE_EPOCH + 3_001},
        )
    assert failure.value.code == "decision_first_seen_after_sighting"
    # Every supplied epoch is validated, even for an identity that is ignored.
    invalid_epochs: tuple[Any, ...] = (-1, True, "1800000000")
    for invalid in invalid_epochs:
        with pytest.raises(WeightDecisionError) as failure:
            decide_weight_submission(
                context.rounds,
                terminal=context.terminal,
                registered=context.registered,
                trust_policies=[context.policy],
                window_start_epoch=WINDOW_START,
                window_end_epoch=WINDOW_END,
                identity_first_seen_epoch={(99, "MinerZ"): invalid},
            )
        assert failure.value.code == "decision_epoch_invalid"


def test_positive_evidence_does_not_bypass_minimum_coverage() -> None:
    """Miner A served 15 expected attributions; a policy demanding 46 must abstain."""

    context = make_window_context()
    decision = decide_weight_submission(
        context.rounds,
        terminal=context.terminal,
        registered=context.registered,
        trust_policies=[context.policy],
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
            trust_policies=[context.policy],
            window_start_epoch=WINDOW_START,
            window_end_epoch=WINDOW_END,
            decision_policy=WeightDecisionPolicy(min_expected_attributions=15),
        ).decision
        == "submit"
    )


def test_sealed_first_seen_rejects_later_rewrite_and_accepts_earlier_archive() -> None:
    rendered = validator_weight_decision_bytes(make_window_context().decision)
    document = json.loads(rendered)
    shifted = forged_decision(
        rendered,
        decision_policy={
            **document["decision_policy"],
            "min_expected_attributions": 16,
        },
        rows=[
            {
                **row,
                "first_seen_epoch": WINDOW_END
                - document["decision_policy"]["activation_grace_seconds"]
                + 1,
            }
            if row["hotkey"] in {"MinerA", "MinerD"}
            else row
            for row in document["rows"]
        ],
    )
    with pytest.raises(ValidationError, match="row_first_seen_not_derived"):
        ValidatorWeightDecision.model_validate(shifted)

    earlier = forged_decision(
        rendered,
        rows=[
            {**row, "first_seen_epoch": WINDOW_START - 1} if row["hotkey"] == "MinerA" else row
            for row in document["rows"]
        ],
    )
    parsed = parse_validator_weight_decision(
        json.dumps(earlier, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"
    )
    assert parsed.decision == "submit"
    assert next(row for row in parsed.rows if row.hotkey == "MinerA").first_seen_epoch == (
        WINDOW_START - 1
    )


def _forged_report(report: ValidatorProbeReport, **changes: Any) -> ValidatorProbeReport:
    """A digest-valid report claiming facts live verification never produced."""

    document = report.model_dump(mode="json", by_alias=True)
    return ValidatorProbeReport.model_validate(reseal_report({**document, **changes}))


def test_golden_window_seals_its_skewed_round_under_the_verifying_policy() -> None:
    """The golden window probes manifest 2 once before its issuance, inside the trust bound.

    The bound is the sealed trust policy's ``max_future_skew_seconds``, never a
    decision-local number: the decision policy carries no skew field, the
    record embeds the exact policy document every round was verified under,
    and the parser re-derives the bound from it.
    """

    context = make_window_context()
    skew = context.policy.max_future_skew_seconds
    assert skew > 0
    assert "max_future_skew_seconds" not in WeightDecisionPolicy.model_fields
    assert context.decision.trust_policies == [context.policy]
    leads = sorted(
        entry.report.manifest_issued_at_epoch - entry.report.evaluation_epoch
        for entry in context.rounds
        if entry.report.evaluation_epoch < entry.report.manifest_issued_at_epoch
    )
    assert leads == [skew]
    rendered = validator_weight_decision_bytes(context.decision)
    assert parse_validator_weight_decision(rendered) == context.decision
    assert context.decision.decision == "submit" and context.decision.round_count == 45

    # The verifying policy is not optional: without it no round can be bound.
    with pytest.raises(WeightDecisionError) as missing:
        decide_weight_submission(
            context.rounds,
            terminal=context.terminal,
            registered=context.registered,
            trust_policies=[],
            window_start_epoch=WINDOW_START,
            window_end_epoch=WINDOW_END,
        )
    assert missing.value.code == "decision_trust_policy_missing"
    other = build_policy(context.keys, max_age=3_600, max_future_skew=300)
    with pytest.raises(WeightDecisionError) as wrong:
        decide_weight_submission(
            context.rounds,
            terminal=context.terminal,
            registered=context.registered,
            trust_policies=[other],
            window_start_epoch=WINDOW_START,
            window_end_epoch=WINDOW_END,
        )
    assert wrong.value.code == "decision_trust_policy_missing"

    # A digest-valid rewrite of the skewed report one second further before its
    # manifest is refused on parse under the sealed policy, and the same
    # impossible report is refused by the producer.
    skewed = context.rounds[24]
    assert skewed.report.evaluation_epoch == skewed.report.manifest_issued_at_epoch - skew
    document = forged_decision_with_report(
        rendered,
        report_digest_sha256=skewed.report.report_digest_sha256,
        evaluation_epoch=skewed.report.evaluation_epoch - 1,
    )
    with pytest.raises(ValidationError, match="scoring_window_evidence_inconsistent"):
        ValidatorWeightDecision.model_validate(document)
    impossible = ProbeRound(
        manifest=skewed.manifest,
        report=_forged_report(skewed.report, evaluation_epoch=skewed.report.evaluation_epoch - 1),
    )
    with pytest.raises(WeightDecisionError) as failure:
        decide_weight_submission(
            [*context.rounds[:24], impossible, *context.rounds[25:]],
            terminal=context.terminal,
            registered=context.registered,
            trust_policies=[context.policy],
            window_start_epoch=WINDOW_START,
            window_end_epoch=WINDOW_END,
        )
    assert failure.value.code == "decision_round_invalid"


@pytest.mark.parametrize("lead_seconds", [1, 5])
def test_report_verified_within_trust_skew_is_admitted_end_to_end(lead_seconds: int) -> None:
    """Live verification and decision admission share the verifying policy's bound.

    A validator whose clock trails the publisher's by up to the trust policy's
    ``max_future_skew_seconds`` verifies the manifest and seals a report whose
    ``evaluation_epoch`` precedes ``issued_at_epoch``. The decision, sealing
    that policy, admits the round; one second beyond the bound is refused live
    (``manifest_future``) before any report exists, a report cannot be built
    for an epoch other than the one its manifest was verified at, and a report
    forged past the bound is refused with the stable ``decision_round_invalid``.
    """

    context = make_window_context()
    skew = context.policy.max_future_skew_seconds
    assert skew == 5 and 1 <= lead_seconds <= skew
    manifest_one, manifest_two, _ = context.manifests
    _, state_one, _ = context.states
    issued_at = manifest_two.issued_at_epoch
    evaluation_epoch = issued_at - lead_seconds

    skewed = build_round(
        context.policy,
        manifest_two,
        state_one,
        context.keys,
        responders={"fixture-alpha": "MinerA", "fixture-beta": "MinerB", "fixture-gamma": "MinerE"},
        label=f"skewed-{lead_seconds}",
        evaluation_epoch=evaluation_epoch,
    )
    assert skewed.report.evaluation_epoch == issued_at - lead_seconds
    with pytest.raises(AssignmentProbeError, match="manifest_future"):
        verify_active_assignment_manifest(
            manifest_two,
            sign_manifest(manifest_two, context.keys),
            context.policy,
            state_one,
            evaluation_epoch=issued_at - skew - 1,
            current_finalized_height=FINALIZED_HEIGHT,
        )
    # Report construction is bound to the verification it seals: the epoch and
    # policy are the ones the manifest was actually verified at and under.
    verification = verify_active_assignment_manifest(
        manifest_two,
        sign_manifest(manifest_two, context.keys),
        context.policy,
        state_one,
        evaluation_epoch=evaluation_epoch,
        current_finalized_height=FINALIZED_HEIGHT,
    )
    assert verification.evaluation_epoch == evaluation_epoch
    assert verification.trust_policy_digest_sha256 == context.policy.trust_policy_digest_sha256
    with pytest.raises(AssignmentProbeError, match="report_evaluation_epoch_mismatch"):
        build_validator_probe_report(
            verification,
            context.policy,
            state_one,
            skewed.report.observations,
            validator_uid=VALIDATOR_UID,
            validator_hotkey=VALIDATOR_HOTKEY,
            evaluation_epoch=issued_at - skew - 1,
            edge_origin_override=False,
        )
    with pytest.raises(AssignmentProbeError, match="trust_policy_mismatch"):
        build_validator_probe_report(
            verification,
            build_policy(context.keys, max_age=3_600, max_future_skew=300),
            state_one,
            skewed.report.observations,
            validator_uid=VALIDATOR_UID,
            validator_hotkey=VALIDATOR_HOTKEY,
            evaluation_epoch=evaluation_epoch,
            edge_origin_override=False,
        )

    rounds = [*context.rounds[:24], skewed, *context.rounds[25:]]
    terminal = TerminalManifestObservation(
        status="verified", evaluated_at_epoch=WINDOW_END, manifest=context.manifests[2]
    )
    decision = decide_weight_submission(
        rounds,
        terminal=terminal,
        registered=context.registered,
        trust_policies=[context.policy],
        window_start_epoch=WINDOW_START,
        window_end_epoch=WINDOW_END,
    )
    assert decision.decision == "submit" and decision.round_count == 45
    assert decision.trust_policies == [context.policy]
    sealed_reports = [
        report
        for item in decision.assignment_manifest_evidence
        if item.manifest.sequence == 2
        for report in item.scoring_reports
    ]
    assert skewed.report.report_digest_sha256 in {
        report.report_digest_sha256 for report in sealed_reports
    }
    assert decision.scoring_window is not None
    assert skewed.report.report_digest_sha256 in decision.scoring_window.report_digests
    rendered = validator_weight_decision_bytes(decision)
    assert parse_validator_weight_decision(rendered) == decision
    window = accumulate_scoring_window(
        rounds,
        validator_uid=VALIDATOR_UID,
        validator_hotkey=VALIDATOR_HOTKEY,
        window_start_epoch=WINDOW_START,
        window_end_epoch=WINDOW_END,
    )
    assert canonical_digest(window.model_dump(mode="json")) == decision.scoring_window_digest_sha256

    # The same report forged one second past the policy's bound is impossible
    # under the policy that verified it and is refused, not silently admitted.
    forged = ProbeRound(
        manifest=manifest_two,
        report=_forged_report(skewed.report, evaluation_epoch=issued_at - skew - 1),
    )
    with pytest.raises(WeightDecisionError) as failure:
        decide_weight_submission(
            [*context.rounds[:24], forged, *context.rounds[25:]],
            terminal=terminal,
            registered=context.registered,
            trust_policies=[context.policy],
            window_start_epoch=WINDOW_START,
            window_end_epoch=WINDOW_END,
        )
    assert failure.value.code == "decision_round_invalid"
    # Manifest 1 is issued at window start, so a report evaluated before it
    # also falls outside the window and is refused by the window rule, not
    # by clock skew.
    assert manifest_one.issued_at_epoch == WINDOW_START


def test_policy_rotation_inside_a_window_binds_each_report_to_its_own_policy() -> None:
    """Rotating to a policy with a different skew mid-window keeps every bound exact.

    Manifests 1 and 2 (and their rounds, including the one probed 5s before
    manifest 2's issuance) were verified under the 5s policy; manifest 3 is
    republished under a successor policy with zero tolerance. One bound could
    not serve both: it would refuse genuine evidence or admit impossible
    evidence. The record seals both policy documents and binds every report
    and the terminal to the policy that verified them.
    """

    context = make_window_context()
    current = context.policy
    successor = build_policy(context.keys, max_age=3_600, max_future_skew=0)
    assert successor.trust_policy_digest_sha256 != current.trust_policy_digest_sha256
    manifest_two = context.manifests[1]
    alpha = window_deployment("fixture-alpha", MINERS[:3], campaign_sequence=1)
    beta = window_deployment("fixture-beta", MINERS[1:], campaign_sequence=2)
    gamma = window_deployment("fixture-gamma", EXTRA_MINERS[:1], campaign_sequence=3)
    delta = window_deployment("fixture-delta", EXTRA_MINERS[1:2], campaign_sequence=4)
    rotated_three = build_probe_manifest(
        successor,
        [alpha, beta, gamma, delta],
        sequence=3,
        previous=manifest_two.manifest_digest_sha256,
        issued_at=BASE_EPOCH + 3_000,
        expires_at=BASE_EPOCH + 3_000 + 3_600,
        finalized_height=FINALIZED_HEIGHT + 40,
        finalized_block_hash=label_digest("contract-checkpoint-block-three"),
    )
    state_two = rebind_manifest_chain_state_trust_policy(
        context.states[2], current, successor, evaluation_epoch=BASE_EPOCH + 3_000
    )
    rounds = list(context.rounds[:36])
    for index in range(9):
        rounds.append(
            build_round(
                successor,
                rotated_three,
                state_two,
                context.keys,
                responders={
                    "fixture-alpha": "MinerA",
                    "fixture-beta": "MinerB",
                    "fixture-gamma": "MinerE",
                    "fixture-delta": None,
                },
                label=f"rotated-three-{index}",
                evaluation_epoch=BASE_EPOCH + 3_060 + 60 * index,
            )
        )
    terminal = TerminalManifestObservation(
        status="verified", evaluated_at_epoch=WINDOW_END, manifest=rotated_three
    )

    def decide(window_rounds: list[ProbeRound], *policies: Any) -> ValidatorWeightDecision:
        return decide_weight_submission(
            window_rounds,
            terminal=terminal,
            registered=context.registered,
            trust_policies=list(policies),
            window_start_epoch=WINDOW_START,
            window_end_epoch=WINDOW_END,
        )

    decision = decide(rounds, successor, current)
    assert decision.decision == "submit" and decision.round_count == 45
    assert [item.trust_policy_digest_sha256 for item in decision.trust_policies] == sorted(
        [current.trust_policy_digest_sha256, successor.trust_policy_digest_sha256]
    )
    assert parse_validator_weight_decision(validator_weight_decision_bytes(decision)) == decision
    # Genuine 5s-skewed evidence under the current policy is admitted...
    assert rounds[24].report.evaluation_epoch == manifest_two.issued_at_epoch - 5
    # ...while a report one second before manifest 3's issuance is impossible
    # under the zero-skew successor that verified it, even though the current
    # policy would have allowed it.
    forged = ProbeRound(
        manifest=rotated_three,
        report=_forged_report(
            rounds[36].report, evaluation_epoch=rotated_three.issued_at_epoch - 1
        ),
    )
    with pytest.raises(WeightDecisionError) as failure:
        decide([*rounds[:36], forged, *rounds[37:]], successor, current)
    assert failure.value.code == "decision_round_invalid"
    # Each policy is required for the manifests it verified.
    for supplied in ((current,), (successor,)):
        with pytest.raises(WeightDecisionError) as missing:
            decide(rounds, *supplied)
        assert missing.value.code == "decision_trust_policy_missing"
    # Sealed policies are exactly the verifying set, canonically ordered.
    rendered = validator_weight_decision_bytes(decision)
    document = json.loads(rendered)
    with pytest.raises(ValidationError, match="trust_policies_not_canonical"):
        ValidatorWeightDecision.model_validate(
            forged_decision(rendered, trust_policies=list(reversed(document["trust_policies"])))
        )
    with pytest.raises(ValidationError, match="trust_policies_not_derived"):
        ValidatorWeightDecision.model_validate(
            forged_decision(rendered, trust_policies=document["trust_policies"][:1])
        )
    unrelated = build_policy(context.keys, max_age=3_600, max_future_skew=300)
    padded = sorted(
        [*document["trust_policies"], unrelated.model_dump(mode="json", by_alias=True)],
        key=lambda item: item["trust_policy_digest_sha256"],
    )
    with pytest.raises(ValidationError, match="trust_policies_not_derived"):
        ValidatorWeightDecision.model_validate(forged_decision(rendered, trust_policies=padded))
    foreign = build_policy(
        context.keys, max_age=3_600, central_authority=label_digest("other-authority")
    )
    with pytest.raises(WeightDecisionError) as authority:
        decide(rounds, successor, current, foreign)
    assert authority.value.code == "decision_trust_policy_invalid"


def test_terminal_manifest_issued_beyond_its_policy_skew_is_refused() -> None:
    """The terminal observation is bound to the skew of the policy that verified it.

    A manifest republished after the close instant may lead the validator's
    close evaluation by at most the trust policy's ``max_future_skew_seconds``,
    exactly as live verification requires. Producer and parser both refuse a
    terminal issued further ahead, so a record cannot seal a terminal that
    could never have verified at its evaluation instant.
    """

    context = make_window_context()
    context_policy = context.policy
    skew = context_policy.max_future_skew_seconds
    within, state_three = build_future_terminal(context, lead_seconds=skew)
    beyond, _ = build_future_terminal(context, lead_seconds=skew + 1)
    for manifest, epoch, ok in (
        (within, WINDOW_END, True),
        (beyond, WINDOW_END, False),
        (beyond, WINDOW_END + 1, True),
    ):
        if ok:
            verify_active_assignment_manifest(
                manifest,
                sign_manifest(manifest, context.keys),
                context_policy,
                state_three,
                evaluation_epoch=epoch,
                current_finalized_height=FINALIZED_HEIGHT,
            )
        else:
            with pytest.raises(AssignmentProbeError, match="manifest_future"):
                verify_active_assignment_manifest(
                    manifest,
                    sign_manifest(manifest, context.keys),
                    context_policy,
                    state_three,
                    evaluation_epoch=epoch,
                    current_finalized_height=FINALIZED_HEIGHT,
                )

    def decide(manifest: Any, evaluated_at_epoch: int) -> ValidatorWeightDecision:
        return decide_weight_submission(
            context.rounds,
            terminal=TerminalManifestObservation(
                status="verified", evaluated_at_epoch=evaluated_at_epoch, manifest=manifest
            ),
            registered=context.registered,
            trust_policies=[context_policy],
            window_start_epoch=WINDOW_START,
            window_end_epoch=WINDOW_END,
        )

    at_bound = decide(within, WINDOW_END)
    assert at_bound.decision == "submit" and at_bound.terminal_manifest_sequence == 4
    assert parse_validator_weight_decision(validator_weight_decision_bytes(at_bound)) == at_bound
    with pytest.raises(WeightDecisionError) as failure:
        decide(beyond, WINDOW_END)
    assert failure.value.code == "decision_terminal_future"
    later = decide(beyond, WINDOW_END + 1)
    assert later.decision == "submit" and later.terminal_evaluated_at_epoch == WINDOW_END + 1
    rendered = validator_weight_decision_bytes(later)
    assert parse_validator_weight_decision(rendered) == later
    assert later == future_terminal_decision(skew + 1, evaluated_at_epoch=WINDOW_END + 1)
    # Rewriting the evaluation instant back to the close is digest-valid and
    # still refused: the terminal could not have verified then.
    with pytest.raises(ValidationError, match="terminal_manifest_future"):
        ValidatorWeightDecision.model_validate(
            forged_decision(rendered, terminal_evaluated_at_epoch=WINDOW_END)
        )


def test_terminal_is_readmitted_under_its_policy_at_the_evaluation_instant() -> None:
    """A terminal only its successor policy names is admissible only once that policy is valid.

    The successor policy becomes valid at close+5 and the terminal is issued
    then; at the close instant live verification refuses it
    (``trust_policy_not_yet_valid``) even though it is within the skew bound,
    and producer and parser refuse the same pairing.
    """

    context = make_window_context()
    successor = successor_policy_valid_from(WINDOW_END + 5)
    assert successor.max_future_skew_seconds == 5
    terminal, state_three = build_future_terminal(context, lead_seconds=5, policy=successor)
    assert terminal.issued_at_epoch == successor.valid_from_epoch == WINDOW_END + 5
    rebound = rebind_manifest_chain_state_trust_policy(
        state_three, context.policy, successor, evaluation_epoch=WINDOW_END + 5
    )
    with pytest.raises(AssignmentProbeError, match="trust_policy_not_yet_valid"):
        verify_active_assignment_manifest(
            terminal,
            sign_manifest(terminal, context.keys),
            successor,
            rebound,
            evaluation_epoch=WINDOW_END,
            current_finalized_height=FINALIZED_HEIGHT,
        )
    verify_active_assignment_manifest(
        terminal,
        sign_manifest(terminal, context.keys),
        successor,
        rebound,
        evaluation_epoch=WINDOW_END + 5,
        current_finalized_height=FINALIZED_HEIGHT,
    )

    def decide(evaluated_at_epoch: int) -> ValidatorWeightDecision:
        return decide_weight_submission(
            context.rounds,
            terminal=TerminalManifestObservation(
                status="verified", evaluated_at_epoch=evaluated_at_epoch, manifest=terminal
            ),
            registered=context.registered,
            trust_policies=[context.policy, successor],
            window_start_epoch=WINDOW_START,
            window_end_epoch=WINDOW_END,
        )

    with pytest.raises(WeightDecisionError) as failure:
        decide(WINDOW_END)
    assert failure.value.code == "decision_terminal_policy_rejected"
    valid = decide(WINDOW_END + 5)
    assert valid.decision == "submit"
    assert [item.trust_policy_digest_sha256 for item in valid.trust_policies] == sorted(
        [context.policy.trust_policy_digest_sha256, successor.trust_policy_digest_sha256]
    )
    rendered = validator_weight_decision_bytes(valid)
    assert parse_validator_weight_decision(rendered) == valid
    assert valid == future_terminal_decision(
        5, evaluated_at_epoch=WINDOW_END + 5, successor_policy=successor
    )
    with pytest.raises(ValidationError, match="terminal_policy_rejected"):
        ValidatorWeightDecision.model_validate(
            forged_decision(rendered, terminal_evaluated_at_epoch=WINDOW_END)
        )
    # A terminal that outlives its policy's lifetime bound is refused the same way.
    overlong = build_probe_manifest(
        context.policy,
        list(context.manifests[2].deployments),
        sequence=4,
        previous=context.manifests[2].manifest_digest_sha256,
        issued_at=WINDOW_END,
        expires_at=WINDOW_END + context.policy.max_manifest_lifetime_seconds + 1,
        finalized_height=context.manifests[2].finalized_height,
        finalized_block_hash=context.manifests[2].finalized_block_hash,
    )
    with pytest.raises(WeightDecisionError) as failure:
        decide_weight_submission(
            context.rounds,
            terminal=TerminalManifestObservation(
                status="verified", evaluated_at_epoch=WINDOW_END, manifest=overlong
            ),
            registered=context.registered,
            trust_policies=[context.policy],
            window_start_epoch=WINDOW_START,
            window_end_epoch=WINDOW_END,
        )
    assert failure.value.code == "decision_terminal_policy_rejected"


def test_reports_are_readmitted_under_their_policy_validity_window() -> None:
    """A report evaluated before its manifest's policy became valid is impossible.

    Manifest 3 is republished under a successor policy valid from its own
    issuance; its genuine rounds are admitted, while a report forged one second
    before that validity start (still inside the window and the skew bound)
    is refused by producer and parser.
    """

    context = make_window_context()
    successor = build_policy(
        context.keys, max_age=3_600, valid_from=BASE_EPOCH + 3_000, max_future_skew=5
    )
    manifest_two = context.manifests[1]
    rotated_three = build_probe_manifest(
        successor,
        list(context.manifests[2].deployments),
        sequence=3,
        previous=manifest_two.manifest_digest_sha256,
        issued_at=BASE_EPOCH + 3_000,
        expires_at=BASE_EPOCH + 3_000 + 3_600,
        finalized_height=FINALIZED_HEIGHT + 40,
        finalized_block_hash=label_digest("contract-checkpoint-block-three"),
    )
    state_two = rebind_manifest_chain_state_trust_policy(
        context.states[2], context.policy, successor, evaluation_epoch=BASE_EPOCH + 3_000
    )
    rounds = list(context.rounds[:36])
    for index in range(9):
        rounds.append(
            build_round(
                successor,
                rotated_three,
                state_two,
                context.keys,
                responders={
                    "fixture-alpha": "MinerA",
                    "fixture-beta": "MinerB",
                    "fixture-gamma": "MinerE",
                    "fixture-delta": None,
                },
                label=f"validity-three-{index}",
                evaluation_epoch=BASE_EPOCH + 3_060 + 60 * index,
            )
        )
    terminal = TerminalManifestObservation(
        status="verified", evaluated_at_epoch=WINDOW_END, manifest=rotated_three
    )

    def decide(window_rounds: list[ProbeRound]) -> ValidatorWeightDecision:
        return decide_weight_submission(
            window_rounds,
            terminal=terminal,
            registered=context.registered,
            trust_policies=[context.policy, successor],
            window_start_epoch=WINDOW_START,
            window_end_epoch=WINDOW_END,
        )

    decision = decide(rounds)
    assert decision.decision == "submit" and decision.round_count == 45
    rendered = validator_weight_decision_bytes(decision)
    assert parse_validator_weight_decision(rendered) == decision
    too_early = ProbeRound(
        manifest=rotated_three,
        report=_forged_report(rounds[36].report, evaluation_epoch=BASE_EPOCH + 2_999),
    )
    with pytest.raises(WeightDecisionError) as failure:
        decide([*rounds[:36], too_early, *rounds[37:]])
    assert failure.value.code == "decision_round_policy_rejected"
    with pytest.raises(ValidationError, match="report_policy_rejected"):
        ValidatorWeightDecision.model_validate(
            forged_decision_with_report(
                rendered,
                report_digest_sha256=rounds[36].report.report_digest_sha256,
                evaluation_epoch=BASE_EPOCH + 2_999,
            )
        )


def test_observations_judged_under_a_looser_policy_cannot_be_relabelled() -> None:
    """Every observation must be one the report's policy could have produced.

    Responses presenting certificate B are ``tls_pin_mismatch`` under the
    pinned policy A that verified the manifest; evaluated under a same-authority
    policy without pins they become ``serving``. Sealing them under A is
    refused at report construction, and a report that nevertheless claims them
    is refused by the decision and the parser; the report's probe bounds must
    also be exactly the policy's.
    """

    context = make_window_context()
    pin = label_digest("edge-leaf-a")
    pinned = build_policy(context.keys, max_age=3_600, pinned_edge_leaf_certificate_sha256=(pin,))
    loose = build_policy(context.keys, max_age=3_600)
    alpha = window_deployment("fixture-alpha", MINERS[:3], campaign_sequence=1)
    beta = window_deployment("fixture-beta", MINERS[1:], campaign_sequence=2)
    manifest = build_probe_manifest(pinned, [alpha, beta])
    genesis = build_initial_manifest_chain_state(pinned)
    verification = verify_active_assignment_manifest(
        manifest,
        sign_manifest(manifest, context.keys),
        pinned,
        genesis,
        evaluation_epoch=BASE_EPOCH + 60,
        current_finalized_height=FINALIZED_HEIGHT,
    )

    def observations(leaf: str, policy: Any) -> list[ProbeObservation]:
        items = []
        for deployment in manifest.deployments:
            nonce = label_digest(f"relabel-{deployment.deployment_id}")
            replica = deployment.replicas[0]
            response = serving_response(
                deployment,
                attestation=sign_attestation(deployment, replica, probe_nonce=nonce),
                tls_leaf_certificate_sha256=leaf,
            )
            items.append(
                evaluate_probe_response(deployment, policy, probe_nonce=nonce, result=response)
            )
        return items

    def report(items: list[ProbeObservation]) -> ValidatorProbeReport:
        return build_validator_probe_report(
            verification,
            pinned,
            genesis,
            items,
            validator_uid=VALIDATOR_UID,
            validator_hotkey=VALIDATOR_HOTKEY,
            evaluation_epoch=BASE_EPOCH + 60,
            edge_origin_override=False,
        )

    strict = observations(label_digest("edge-leaf-b"), pinned)
    assert {item.failure_code for item in strict} == {"tls_pin_mismatch"}
    relabelled = observations(label_digest("edge-leaf-b"), loose)
    assert {item.outcome for item in relabelled} == {"serving"}
    with pytest.raises(AssignmentProbeError, match="observation_policy_violation"):
        report(relabelled)
    genuine = report(observations(pin, pinned))
    assert genuine.serving_count == 2
    # Failures reached only after the pin check also need a pinned certificate.
    with pytest.raises(AssignmentProbeError, match="observation_policy_violation"):
        report(
            [
                ProbeObservation.model_validate(
                    reseal_observation(
                        {
                            **item.model_dump(mode="json", by_alias=True),
                            "tls_leaf_certificate_sha256": label_digest("edge-leaf-b"),
                        }
                    )
                )
                for item in genuine.observations
            ]
        )

    def decide(round_report: ValidatorProbeReport, *policies: Any) -> ValidatorWeightDecision:
        return decide_weight_submission(
            [ProbeRound(manifest=manifest, report=round_report)],
            terminal=TerminalManifestObservation(
                status="verified", evaluated_at_epoch=WINDOW_END, manifest=manifest
            ),
            registered=context.registered,
            trust_policies=list(policies),
            window_start_epoch=WINDOW_START,
            window_end_epoch=WINDOW_END,
        )

    accepted = decide(genuine, pinned)
    assert accepted.round_count == 1 and accepted.trust_policies == [pinned]
    genuine_document = genuine.model_dump(mode="json", by_alias=True)
    # The genuine report with its observations swapped for the relabelled ones
    # (report resealed) is refused under the policy it names...
    forged = ValidatorProbeReport.model_validate(
        reseal_report_observations(
            genuine_document, [item.model_dump(mode="json", by_alias=True) for item in relabelled]
        )
    )
    with pytest.raises(WeightDecisionError) as failure:
        decide(forged, pinned)
    assert failure.value.code == "decision_round_policy_rejected"
    # ...and a serving body over the policy's response ceiling is refused too.
    oversized = ValidatorProbeReport.model_validate(
        reseal_report_observations(
            genuine_document,
            [
                {
                    **item.model_dump(mode="json", by_alias=True),
                    "response_bytes": pinned.max_response_bytes + 1,
                }
                for item in genuine.observations
            ],
        )
    )
    with pytest.raises(WeightDecisionError) as failure:
        decide(oversized, pinned)
    assert failure.value.code == "decision_round_policy_rejected"
    # Probe bounds are the policy's scalars, not free report fields.
    loosened = _forged_report(genuine, max_response_bytes=pinned.max_response_bytes + 1)
    with pytest.raises(WeightDecisionError) as failure:
        decide(loosened, pinned)
    assert failure.value.code == "decision_round_invalid"
    # Supplying the loose policy instead does not help: the manifest names A.
    with pytest.raises(WeightDecisionError) as failure:
        decide(forged, loose)
    assert failure.value.code == "decision_trust_policy_missing"


def test_observation_policy_binding_is_branch_complete() -> None:
    pin = label_digest("edge-leaf-a")
    pinned = build_policy(signer_keys(), pinned_edge_leaf_certificate_sha256=(pin,))
    unpinned = build_policy(signer_keys())
    context = make_window_context()
    serving = next(
        item for item in context.rounds[0].report.observations if item.outcome == "serving"
    )
    failed = next(
        item for item in context.rounds[36].report.observations if item.outcome == "failed"
    )
    assert failed.failure_code == "timeout"

    def variant(base: ProbeObservation, **changes: Any) -> ProbeObservation:
        return ProbeObservation.model_validate(
            reseal_observation({**base.model_dump(mode="json", by_alias=True), **changes})
        )

    # Serving: pinned certificate and body within the ceiling are required.
    verify_observation_policy_binding(variant(serving, tls_leaf_certificate_sha256=pin), pinned)
    verify_observation_policy_binding(
        variant(serving, tls_leaf_certificate_sha256=pin, response_bytes=pinned.max_response_bytes),
        pinned,
    )
    for bad in (
        variant(serving),  # no certificate recorded under a pinning policy
        variant(serving, tls_leaf_certificate_sha256=label_digest("edge-leaf-b")),
        variant(serving, response_bytes=pinned.max_response_bytes + 1),
    ):
        with pytest.raises(AssignmentProbeError, match="observation_policy_violation"):
            verify_observation_policy_binding(bad, pinned)
    # Without pins the certificate is free; the size ceiling still binds.
    verify_observation_policy_binding(variant(serving), unpinned)
    with pytest.raises(AssignmentProbeError, match="observation_policy_violation"):
        verify_observation_policy_binding(
            variant(serving, response_bytes=unpinned.max_response_bytes + 1), unpinned
        )
    # Transport failures precede the pin check and carry no policy claim; a
    # pin mismatch is the pin check; post-pin failures need a pinned certificate.
    verify_observation_policy_binding(failed, pinned)
    verify_observation_policy_binding(
        variant(failed, failure_code="tls_pin_mismatch", response_status=200), pinned
    )
    with pytest.raises(AssignmentProbeError, match="observation_policy_violation"):
        verify_observation_policy_binding(
            variant(failed, failure_code="unexpected_status", response_status=503), pinned
        )
    verify_observation_policy_binding(
        variant(
            failed,
            failure_code="unexpected_status",
            response_status=503,
            tls_leaf_certificate_sha256=pin,
        ),
        pinned,
    )


def test_uid_republication_never_erases_the_earning_identity_sighting() -> None:
    """An endpoint republished under a new UID keeps the earlier identity's first sighting.

    Sightings are scoped to the exact ``(uid, hotkey)`` identity, never to the
    last manifest that published an endpoint, so the producer's record always
    round-trips through its own parser instead of raising a raw
    ``row_first_seen_not_derived`` validation error.
    """

    context = make_window_context()
    republished = build_probe_manifest(
        context.policy,
        [
            window_deployment("fixture-alpha", [(99, "MinerA"), *MINERS[1:3]], campaign_sequence=1),
            window_deployment("fixture-beta", MINERS[1:], campaign_sequence=2),
        ],
        sequence=2,
        previous=context.manifests[0].manifest_digest_sha256,
        issued_at=BASE_EPOCH + 1_500,
        expires_at=BASE_EPOCH + 1_500 + 3_600,
        finalized_height=FINALIZED_HEIGHT + 20,
        finalized_block_hash=label_digest("republished-alpha-two"),
    )

    def endpoint_ids(manifest: Any) -> set[str]:
        return {replica.endpoint_id for item in manifest.deployments for replica in item.replicas}

    # The same endpoint lineage, now owned by UID 99, on a successor the
    # coordinator's chain state accepts.
    assert endpoint_ids(republished) == endpoint_ids(context.manifests[0])
    verify_active_assignment_manifest(
        republished,
        sign_manifest(republished, context.keys),
        context.policy,
        context.states[1],
        evaluation_epoch=BASE_EPOCH + 1_500,
        current_finalized_height=FINALIZED_HEIGHT,
    )
    terminal = TerminalManifestObservation(
        status="verified", evaluated_at_epoch=WINDOW_END, manifest=republished
    )

    def decide(**changes: Any) -> ValidatorWeightDecision:
        return decide_weight_submission(
            context.rounds[:24],
            terminal=terminal,
            trust_policies=[context.policy],
            window_start_epoch=WINDOW_START,
            window_end_epoch=WINDOW_END,
            **{"registered": context.registered, **changes},
        )

    decision = decide()
    rendered = validator_weight_decision_bytes(decision)
    parsed = parse_validator_weight_decision(rendered)
    assert validator_weight_decision_bytes(parsed) == rendered
    assert parsed.decision == "submit"
    miner_a = next(row for row in parsed.rows if row.hotkey == "MinerA")
    assert (miner_a.uid, miner_a.classification, miner_a.assigned_at_close) == (
        10,
        "verified_serving",
        False,
    )
    assert miner_a.first_seen_epoch == BASE_EPOCH
    assert miner_a.weight > 0.0
    # The unregistered UID 99 incarnation is not an assigned registered identity.
    assert parsed.terminal_assigned_miner_count == 3
    assert weight_plan_rows_for_submission(parsed)

    # Rewrite resistance is unchanged for the republished record: the earning
    # identity's sighting can be neither erased nor moved later, while a
    # genuinely earlier archived sighting remains legal.
    document = json.loads(rendered)

    def with_miner_a_first_seen(value: int | None) -> dict[str, Any]:
        return forged_decision(
            rendered,
            rows=[
                {**row, "first_seen_epoch": value} if row["hotkey"] == "MinerA" else row
                for row in document["rows"]
            ],
        )

    for rewritten in (None, BASE_EPOCH + 1):
        with pytest.raises(ValidationError, match="row_first_seen_not_derived"):
            ValidatorWeightDecision.model_validate(with_miner_a_first_seen(rewritten))
    earlier = ValidatorWeightDecision.model_validate(with_miner_a_first_seen(WINDOW_START - 1))
    assert next(row for row in earlier.rows if row.hotkey == "MinerA").first_seen_epoch == (
        WINDOW_START - 1
    )

    # An archived sighting names the exact identity it was archived for and
    # may still not post-date that identity's earliest publication.
    archived = decide(identity_first_seen_epoch={(10, "MinerA"): BASE_EPOCH - 100})
    assert next(row for row in archived.rows if row.hotkey == "MinerA").first_seen_epoch == (
        BASE_EPOCH - 100
    )
    assert parse_validator_weight_decision(validator_weight_decision_bytes(archived)) == archived
    with pytest.raises(WeightDecisionError) as failure:
        decide(identity_first_seen_epoch={(10, "MinerA"): BASE_EPOCH + 1})
    assert failure.value.code == "decision_first_seen_after_sighting"

    # Seen from a registered view that already holds the new UID, the new
    # identity's sighting is its own first publication, not the old UID's.
    reregistered = decide(
        registered=registered_set(miners=tuple(sorted([*REGISTERED_MINERS[1:], (99, "MinerA")])))
    )
    parsed_reregistered = parse_validator_weight_decision(
        validator_weight_decision_bytes(reregistered)
    )
    new_a = next(row for row in parsed_reregistered.rows if row.hotkey == "MinerA")
    assert (new_a.uid, new_a.first_seen_epoch, new_a.assigned_at_close) == (
        99,
        BASE_EPOCH + 1_500,
        True,
    )
    assert new_a.weight == 0.0


def test_archived_sighting_of_old_uid_never_leaves_republished_uid_grace() -> None:
    """The old UID's archive cannot cross-credit a new UID that inherited its endpoint.

    UID 10 earned its sighting on the alpha endpoint at window start; the
    endpoint is republished as UID 99 sixty seconds before close. The
    registered view now holds UID 99 alone. With or without the coordinator's
    archived sighting for UID 10, UID 99's sighting is its own republication
    and it stays ``assigned_in_grace``: an archived sighting moves only the
    exact identity it names.
    """

    context = make_window_context()
    republished_at = WINDOW_END - 60
    republished = build_probe_manifest(
        context.policy,
        [
            window_deployment("fixture-alpha", [(99, "MinerA"), *MINERS[1:3]], campaign_sequence=1),
            window_deployment("fixture-beta", MINERS[1:], campaign_sequence=2),
        ],
        sequence=2,
        previous=context.manifests[0].manifest_digest_sha256,
        issued_at=republished_at,
        expires_at=republished_at + 3_600,
        finalized_height=FINALIZED_HEIGHT + 20,
        finalized_block_hash=label_digest("republished-alpha-late"),
    )
    verify_active_assignment_manifest(
        republished,
        sign_manifest(republished, context.keys),
        context.policy,
        context.states[1],
        evaluation_epoch=republished_at,
        current_finalized_height=FINALIZED_HEIGHT,
    )
    terminal = TerminalManifestObservation(
        status="verified", evaluated_at_epoch=WINDOW_END, manifest=republished
    )
    reregistered = registered_set(miners=tuple(sorted([*REGISTERED_MINERS[1:], (99, "MinerA")])))
    old_archive = {(10, "MinerA"): BASE_EPOCH - 100}

    def decide(**changes: Any) -> ValidatorWeightDecision:
        return decide_weight_submission(
            context.rounds[:24],
            terminal=terminal,
            registered=reregistered,
            trust_policies=[context.policy],
            window_start_epoch=WINDOW_START,
            window_end_epoch=WINDOW_END,
            **changes,
        )

    def miner_a(decision: ValidatorWeightDecision) -> tuple[int, int | None, str]:
        row = next(row for row in decision.rows if row.hotkey == "MinerA")
        return (row.uid, row.first_seen_epoch, row.classification)

    without_archive = decide()
    with_old_archive = decide(identity_first_seen_epoch=old_archive)
    for decision in (without_archive, with_old_archive):
        assert decision.decision == "submit"
        assert decision.abstain_reasons == []
        assert miner_a(decision) == (99, republished_at, "assigned_in_grace")
        rendered = validator_weight_decision_bytes(decision)
        parsed = parse_validator_weight_decision(rendered)
        assert parsed == decision
        assert validator_weight_decision_bytes(parsed) == rendered
        assert weight_plan_rows_for_submission(parsed)
    # The old UID's archive changed nothing observable: the sealed records are
    # byte-identical because UID 10 is not a registered identity here.
    assert validator_weight_decision_bytes(with_old_archive) == validator_weight_decision_bytes(
        without_archive
    )

    # Only a sighting archived for UID 99 itself moves UID 99, bounded by its
    # own republication rather than by the endpoint's earlier history.
    own_archive = decide(identity_first_seen_epoch={(99, "MinerA"): BASE_EPOCH + 1})
    assert own_archive.abstain_reasons == ["coverage_insufficient"]
    assert miner_a(own_archive) == (99, BASE_EPOCH + 1, "assigned_undersampled")
    assert parse_validator_weight_decision(validator_weight_decision_bytes(own_archive)) == (
        own_archive
    )
    with pytest.raises(WeightDecisionError) as failure:
        decide(identity_first_seen_epoch={(99, "MinerA"): republished_at + 1})
    assert failure.value.code == "decision_first_seen_after_sighting"
    with pytest.raises(WeightDecisionError) as failure:
        decide(identity_first_seen_epoch={**old_archive, (99, "MinerA"): republished_at + 1})
    assert failure.value.code == "decision_first_seen_after_sighting"

    # A digest-valid rewrite of the sealed record can neither erase UID 99's
    # sighting, move it later, nor back-date it to the old UID's epoch while
    # keeping the grace classification the producer derived.
    rendered = validator_weight_decision_bytes(with_old_archive)
    document = json.loads(rendered)

    def with_uid_99_first_seen(value: int | None) -> dict[str, Any]:
        return forged_decision(
            rendered,
            rows=[
                {**row, "first_seen_epoch": value} if row["hotkey"] == "MinerA" else row
                for row in document["rows"]
            ],
        )

    with pytest.raises(ValidationError, match="row_assigned_first_seen_missing"):
        ValidatorWeightDecision.model_validate(with_uid_99_first_seen(None))
    with pytest.raises(ValidationError, match="row_first_seen_not_derived"):
        ValidatorWeightDecision.model_validate(with_uid_99_first_seen(republished_at + 1))
    with pytest.raises(ValidationError, match="row_classification_not_derived"):
        ValidatorWeightDecision.model_validate(with_uid_99_first_seen(BASE_EPOCH - 100))


def test_no_positive_evidence_means_no_transaction() -> None:
    context = make_window_context()
    empty = decide_weight_submission(
        [],
        terminal=context.terminal,
        registered=context.registered,
        trust_policies=[context.policy],
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
            trust_policies=[context.policy],
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
        trust_policies=[context.policy],
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
        trust_policies=[context.policy],
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
        trust_policies=[context.policy],
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
        trust_policies=[context.policy],
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
            trust_policies=[context.policy],
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
                expires_at=BASE_EPOCH + 2_999 + 3_600,
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
            trust_policies=[context.policy],
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
            trust_policies=[context.policy],
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
        trust_policies=[context.policy],
        window_start_epoch=WINDOW_START,
        window_end_epoch=WINDOW_END,
        decision_policy=context.decision.decision_policy,
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
            trust_policies=[context.policy],
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
            trust_policies=[context.policy],
            window_start_epoch=WINDOW_START,
            window_end_epoch=WINDOW_END,
        )
    assert failure.value.code == "decision_round_after_terminal"
    with pytest.raises(WeightDecisionError) as failure:
        decide_weight_submission(
            context.rounds,
            terminal=context.terminal,
            registered=context.registered,
            trust_policies=[context.policy],
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
            trust_policies=[context.policy],
            window_start_epoch=WINDOW_END,
            window_end_epoch=WINDOW_START,
        )
    assert failure.value.code == "decision_epoch_invalid"
    with pytest.raises(ProbeScoringError) as scoring_failure:
        decide_weight_submission(
            context.rounds,
            terminal=context.terminal,
            registered=context.registered.model_copy(update={"validator_hotkey": "Impostor"}),
            trust_policies=[context.policy],
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
        trust_policies=[context.policy],
        window_start_epoch=WINDOW_START,
        window_end_epoch=WINDOW_END,
        decision_policy=context.decision.decision_policy,
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
            trust_policies=[context.policy],
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
            trust_policies=[context.policy],
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
        trust_policies=[context.policy],
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
            trust_policies=[context.policy],
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
