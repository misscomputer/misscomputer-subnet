# SPDX-License-Identifier: AGPL-3.0-only
"""Organic validator decision: abstain or submit (``validator-weight-decision`` v2)."""

from __future__ import annotations

import json
from typing import Any

import pytest
from assignment_probe_context import FINALIZED_HEIGHT
from organic_context import (
    DECISION_POLICY,
    EPOCH,
    WINDOW_END,
    WINDOW_START,
    WindowContext,
    build_deployment,
    build_manifest,
    decide,
    epoch_probes,
    make_window_context,
    metagraph_snapshot,
    registered_set,
)
from pydantic import ValidationError

from misscomputer_subnet.contract_codec import canonical_json, digest
from misscomputer_subnet.organic_probe import OrganicProbeObservation
from misscomputer_subnet.organic_scoring import _derive_epoch, score_organic_epoch
from misscomputer_subnet.validator_decision import (
    TerminalManifestObservation,
    ValidatorWeightDecision,
    WeightDecisionError,
    WeightDecisionPolicy,
    decide_weight_submission,
    parse_validator_weight_decision,
    validator_weight_decision_bytes,
    weight_plan_rows_for_submission,
)
from misscomputer_subnet.weight_plan import build_weight_plan_from_decision


@pytest.fixture(scope="module")
def context() -> WindowContext:
    return make_window_context()


def test_submit_weights_scored_availability_and_zeroes_fraud_and_unscored(
    context: WindowContext,
) -> None:
    decision = context.decision
    assert (decision.decision, decision.abstain_reasons) == ("submit", [])
    rows = {row.hotkey: (row.classification, row.weight) for row in decision.rows}
    assert rows == {
        "MinerA": ("scored", 1.0),
        "MinerB": ("scored", 11 / 12),
        "MinerC": ("scored", 1.0),
        "MinerD": ("fraud_evidence", 0.0),
        "MinerE": ("unscored", 0.0),
    }
    plan = build_weight_plan_from_decision(
        decision,
        snapshot=metagraph_snapshot(),
        finalized_block_hash=decision.registered_finalized_block_hash,
        version_key=2,
    )
    weights = {entry.hotkey: entry.weight for entry in plan.weights}
    # Zero rows are dropped by the unchanged plan builder; the rest normalize.
    assert set(weights) == {"MinerA", "MinerB", "MinerC"}
    assert weights["MinerB"] / weights["MinerA"] == pytest.approx(11 / 12)
    assert weight_plan_rows_for_submission(decision)[1] == {
        "miner_hotkey": "MinerB",
        "weight": 11 / 12,
    }


def _abstain_case(context: WindowContext, case: str) -> ValidatorWeightDecision:
    policy, manifest, epochs = context.policy, context.manifest, context.epochs
    if case == "terminal_manifest_unavailable":
        return decide(
            policy,
            manifest,
            epochs,
            terminal=TerminalManifestObservation(
                status="unavailable", evaluated_at_epoch=WINDOW_END
            ),
        )
    if case == "terminal_manifest_rejected":
        return decide(
            policy,
            manifest,
            epochs,
            terminal=TerminalManifestObservation(
                status="rejected", evaluated_at_epoch=WINDOW_END, rejection_code="signature_invalid"
            ),
        )
    if case == "terminal_manifest_stale":
        short = build_manifest(
            policy,
            [build_deployment("shop-k3j9x0q2ab", ["MinerA", "MinerB", "MinerC"])],
            expires_at=WINDOW_END,
        )
        return decide(
            policy,
            manifest,
            epochs,
            terminal=TerminalManifestObservation(
                status="verified", evaluated_at_epoch=WINDOW_END, manifest=short
            ),
        )
    if case == "insufficient_scored_epochs":
        return decide(
            policy, manifest, epochs, decision_policy=WeightDecisionPolicy(min_scored_epochs=3)
        )
    if case == "registered_set_unbound":
        return decide(
            policy, manifest, epochs, registered=registered_set(block=FINALIZED_HEIGHT - 1)
        )
    assert case == "no_positive_evidence"
    return decide(policy, manifest, [])


@pytest.mark.parametrize(
    "case",
    [
        "terminal_manifest_unavailable",
        "terminal_manifest_rejected",
        "terminal_manifest_stale",
        "insufficient_scored_epochs",
        "registered_set_unbound",
        "no_positive_evidence",
    ],
)
def test_each_frozen_rule_abstains_and_cannot_become_a_plan(
    context: WindowContext, case: str
) -> None:
    decision = _abstain_case(context, case)
    assert decision.decision == "abstain"
    assert case in decision.abstain_reasons
    assert decision.weight_plan_rows_digest_sha256 is None
    with pytest.raises(WeightDecisionError, match="decision_not_submittable"):
        weight_plan_rows_for_submission(decision)


def test_a_common_mode_epoch_is_not_a_scored_epoch(context: WindowContext) -> None:
    down = {
        replica.endpoint_id: ("edge_down",) * 3
        for deployment in context.manifest.deployments
        for replica in deployment.replicas
    }
    outage = score_organic_epoch(
        [context.manifest],
        epoch_probes(context.policy, context.manifest, down),
        validator_hotkey=context.decision.validator_hotkey,
        epoch_index=EPOCH,
    )
    decision = decide(context.policy, context.manifest, [outage, context.epochs[1]])
    assert decision.scored_epoch_count == 1
    assert decision.abstain_reasons == ["insufficient_scored_epochs"]


def _reseal(document: dict[str, Any]) -> dict[str, Any]:
    unsigned = {k: v for k, v in document.items() if k != "decision_digest_sha256"}
    return {**unsigned, "decision_digest_sha256": digest(unsigned)}


def _forge(decision: ValidatorWeightDecision, mutate: Any) -> dict[str, Any]:
    document = json.loads(validator_weight_decision_bytes(decision))
    mutate(document)
    return _reseal(document)


def _inflate_fraud_row(document: dict[str, Any]) -> None:
    row = next(item for item in document["rows"] if item["hotkey"] == "MinerD")
    row.update(classification="scored", weight=1.0)
    plan = [{"miner_hotkey": item["hotkey"], "weight": item["weight"]} for item in document["rows"]]
    document["weight_plan_rows_digest_sha256"] = digest(plan)


def _drop_epoch(document: dict[str, Any]) -> None:
    document["epochs"] = document["epochs"][:1]


def _forge_success(document: dict[str, Any]) -> None:
    """Turn MinerD's replayed attestation into a success inside a self-consistent epoch.

    The observation, the epoch's tallies and every digest are recomputed, so
    only re-verifying the embedded miner attestation can refuse it.
    """

    epoch = document["epochs"][0]
    for observation in epoch["observations"]:
        if observation["attestation_status"] == "fraudulent":
            observation.update(
                outcome="success",
                failure_code=None,
                attribution="none",
                attestation_status="verified",
            )
            observation["attestation"]["probe_nonce"] = observation["probe_nonce"]
            unsigned = {k: v for k, v in observation.items() if k != "observation_digest_sha256"}
            observation["observation_digest_sha256"] = digest(unsigned)
    observations = [OrganicProbeObservation.model_validate(item) for item in epoch["observations"]]
    epoch.update(
        _derive_epoch(
            observations,
            [],
            epoch_seconds=epoch["epoch_seconds"],
            epoch_index=epoch["epoch_index"],
            min_attempts=epoch["min_attempts"],
        )
    )
    epoch["observation_vector_digest_sha256"] = digest(epoch["observations"])
    unsigned = {k: v for k, v in epoch.items() if k != "epoch_score_digest_sha256"}
    epoch["epoch_score_digest_sha256"] = digest(unsigned)


@pytest.mark.parametrize(
    ("mutate", "reason"),
    [
        pytest.param(_inflate_fraud_row, "decision_rows_mismatch", id="inflated-fraud-row"),
        pytest.param(_drop_epoch, "decision_availability_mismatch", id="dropped-epoch"),
        pytest.param(
            _forge_success, "scoring_attestation_unverified", id="forged-success-in-evidence"
        ),
        pytest.param(
            lambda d: d.update(decision="abstain"),
            "decision_abstain_reasons|decision_outcome",
            id="flipped-outcome",
        ),
        pytest.param(
            lambda d: d.update(terminal_evaluated_at_epoch=WINDOW_END - 1),
            "decision_terminal_invalid",
            id="terminal-before-close",
        ),
    ],
)
def test_forged_records_are_digest_valid_yet_rejected(
    context: WindowContext, mutate: Any, reason: str
) -> None:
    forged = _forge(context.decision, mutate)
    with pytest.raises(ValidationError, match=reason):
        ValidatorWeightDecision.model_validate(forged)
    with pytest.raises(ValueError):
        parse_validator_weight_decision(canonical_json(forged) + b"\n")


def test_an_abstain_record_cannot_be_flipped_to_submit(context: WindowContext) -> None:
    abstain = _abstain_case(context, "terminal_manifest_unavailable")

    def flip(document: dict[str, Any]) -> None:
        plan = [
            {"miner_hotkey": item["hotkey"], "weight": item["weight"]} for item in document["rows"]
        ]
        document.update(
            decision="submit", abstain_reasons=[], weight_plan_rows_digest_sha256=digest(plan)
        )

    with pytest.raises(ValidationError, match="decision_abstain_reasons_mismatch"):
        ValidatorWeightDecision.model_validate(_forge(abstain, flip))


@pytest.mark.parametrize(
    ("change", "code"),
    [
        ("foreign_validator", "decision_validator_mismatch"),
        ("missing_manifest", "decision_manifest_missing"),
        ("missing_policy", "decision_trust_policy_missing"),
        ("inverted_window", "decision_window_invalid"),
    ],
)
def test_untrustworthy_inputs_are_refused(context: WindowContext, change: str, code: str) -> None:
    arguments: dict[str, Any] = {
        "manifests": [context.manifest],
        "terminal": TerminalManifestObservation(
            status="verified", evaluated_at_epoch=WINDOW_END, manifest=context.manifest
        ),
        "registered": context.registered,
        "trust_policies": [context.policy],
        "window_start_epoch": WINDOW_START,
        "window_end_epoch": WINDOW_END,
        "decision_policy": DECISION_POLICY,
    }
    if change == "foreign_validator":
        arguments["registered"] = context.registered.model_copy(
            update={"validator_hotkey": "SomeoneElse"}
        )
    elif change == "missing_manifest":
        arguments["manifests"] = []
        arguments["terminal"] = TerminalManifestObservation(
            status="unavailable", evaluated_at_epoch=WINDOW_END
        )
    elif change == "missing_policy":
        arguments["trust_policies"] = []
    else:
        arguments["window_end_epoch"] = WINDOW_START
    with pytest.raises(WeightDecisionError, match=code):
        decide_weight_submission(context.epochs, **arguments)
