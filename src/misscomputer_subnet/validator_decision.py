# SPDX-License-Identifier: AGPL-3.0-only
"""Frozen validator decision semantics: abstain, zero, or submit (``v1``).

:mod:`misscomputer_subnet.probe_scoring` turns a window of verified probe
reports into a weight vector in which every registered miner is either zero or
positively attested. It deliberately stops short of the question this module
answers: **may this vector become a weight transaction at all?**

Frozen rules
------------
1. **Invalid, unavailable, or stale manifest at window close => ABSTAIN.**
   A validator that cannot verify what is assigned right now must not zero
   everyone; it submits nothing and keeps whatever the chain already holds.
2. **Insufficient sampling coverage => ABSTAIN.** Fewer verified rounds than
   ``min_verified_rounds``, or any assigned miner outside activation grace
   whose fair-round-robin expected attributions are below
   ``min_expected_attributions``, means the validator's own sampling, not the
   miner, is the reason no evidence exists.
3. **Assigned, sufficiently sampled, no verified serving evidence => zero.**
4. **Registered but absent from the valid assignment manifest => zero, only
   when every safe precondition holds:** the terminal manifest verified and
   unexpired at close; the registered set bound to a finalized metagraph view
   at or after the manifest's finalized height and within
   ``max_registered_height_gap``; rules 1 and 2 satisfied; the
   mass-unassignment guard satisfied; and at least one positive attested row.
5. **No positive verified evidence => no weight transaction.**
6. **Activation grace.** A miner whose earliest sighting (across the window's
   accepted manifests, the terminal manifest, and any earlier sighting the
   coordinator supplies from its archive) is less than
   ``activation_grace_seconds`` before window close is never the reason to
   abstain and is reported as ``assigned_in_grace`` if unverified. Grace
   creates no weight: the miner earns weight from the first window in which
   it is attributed.
7. **Finalized window closure.** Reports are admitted only with
   ``window_start_epoch <= evaluation_epoch < window_end_epoch``; the terminal
   manifest observation is taken at or after ``window_end_epoch``; the
   registered set is a finalized view.
8. **Replicas need repeated probing.** Coverage is measured in expected
   attributions, ``opportunities / replica_count`` summed over the rounds a
   miner was published in, so a three-replica deployment needs at least
   ``3 * min_expected_attributions`` observations before its silent replica
   can be zeroed.
9. **Deterministic boundary.** The sealed ``validator-weight-decision`` v1
   document is the only input to ``weight_plan.build_weight_plan``; its
   ``weight_plan_rows_digest_sha256`` commits to the exact rows and is
   ``null`` on abstain, so an abstain record can never be turned into a plan.

This module is pure: no clock, network, file, process, environment, wallet,
chain, randomness, or signing capability.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from fractions import Fraction
from typing import Annotated, Final, Literal, NoReturn, Self

from pydantic import Field, StringConstraints, model_validator

from .assignment_probe import (
    MAX_EPOCH,
    UID,
    ActiveAssignmentManifest,
    Digest,
    Epoch,
    Hotkey,
    PositiveEpoch,
)
from .contract_codec import (
    StrictFrozenModel,
    digest,
    model_bytes,
    model_document,
    parse_model,
    revalidate,
    verify_model_digest,
)
from .probe_scoring import (
    MAX_REGISTERED_MINERS,
    MAX_ROUNDS,
    ProbeRound,
    ProbeScoringPolicy,
    ProbeScoringWindow,
    ProbeWeightVector,
    RegisteredMiner,
    accumulate_scoring_window,
    build_probe_weight_vector,
)

DECISION_SCHEMA: Final = "miss.computer/misscomputer-subnet/validator-weight-decision"
DECISION_SCHEMA_VERSION: Final = 1
DECISION_PURPOSE: Final = "public_validator_weight_decision_v1"
MAX_DECISION_BYTES: Final = 64 * 1_024 * 1_024
PERMILLE: Final = 1_000

ManifestFetchStatus = Literal["rejected", "unavailable", "verified"]
Decision = Literal["abstain", "submit"]
MinerClassification = Literal[
    "assigned_in_grace",
    "assigned_undersampled",
    "assigned_unverified",
    "unassigned",
    "verified_serving",
]
AbstainReason = Literal[
    "coverage_insufficient",
    "manifest_expired_at_close",
    "manifest_invalid",
    "manifest_unavailable",
    "mass_unassignment_guard",
    "no_positive_evidence",
    "registered_set_unbound",
    "rounds_insufficient",
]
DecisionRejectionCode = Literal[
    "decision_epoch_invalid",
    "decision_first_seen_after_sighting",
    "decision_manifest_authority_mismatch",
    "decision_not_submittable",
    "decision_policy_grace_exceeds_window",
    "decision_registered_validator_mismatch",
    "decision_round_after_terminal",
    "decision_terminal_before_close",
    "decision_terminal_status_invalid",
]
RejectionCodeText = Annotated[str, StringConstraints(pattern=r"^[a-z0-9_]{1,64}$")]


class WeightDecisionError(ValueError):
    """Inputs that cannot produce a trustworthy decision record at all."""

    def __init__(self, code: DecisionRejectionCode) -> None:
        super().__init__(code)
        self.code = code


def _reject(code: DecisionRejectionCode) -> NoReturn:
    raise WeightDecisionError(code)


class WeightDecisionPolicy(StrictFrozenModel):
    """Validator-local decision thresholds. Each validator decides independently."""

    #: Verified probe rounds a window needs before any zero can be submitted.
    min_verified_rounds: int = Field(default=24, ge=1, le=MAX_ROUNDS)
    #: Fair-round-robin expected attributions an assigned miner outside grace
    #: must have accrued before its silence counts as evidence.
    min_expected_attributions: int = Field(default=3, ge=1, le=MAX_ROUNDS)
    #: Seconds after a miner's earliest sighting during which its silence is
    #: neither evidence nor a reason to abstain.
    activation_grace_seconds: int = Field(default=1_800, ge=0, le=86_400)
    #: Abstain when the terminal manifest assigns fewer than
    #: ``(1000 - permille) / 1000`` of the largest assigned set seen in the
    #: window: a central mass-eviction is not miner evidence.
    max_assigned_drop_permille: int = Field(default=500, ge=0, le=PERMILLE)
    #: The registered set's finalized height may not lead the terminal
    #: manifest's finalized height by more than this many blocks.
    max_registered_height_gap: int = Field(default=600, ge=0, le=1_000_000)


class RegisteredMinerSet(StrictFrozenModel):
    """The finalized metagraph identity view a decision is bound to."""

    network: Literal["finney"]
    netuid: Literal[24]
    finalized: Literal[True]
    finalized_height: Epoch
    finalized_block_hash: Digest
    finalized_epoch: Epoch
    validator_uid: UID
    validator_hotkey: Hotkey
    miners: list[RegisteredMiner] = Field(min_length=1, max_length=MAX_REGISTERED_MINERS)
    #: ``weight_plan.snapshot_identity_fingerprint`` of the complete finalized
    #: snapshot the miners were taken from; the weight plan repeats it.
    metagraph_identity_fingerprint_sha256: Digest

    @model_validator(mode="after")
    def canonical_registered(self) -> Self:
        keys = [(item.uid, item.hotkey) for item in self.miners]
        if keys != sorted(set(keys)):
            raise ValueError("registered_miners_not_canonical")
        if len({uid for uid, _ in keys}) != len(keys) or len({key for _, key in keys}) != len(keys):
            raise ValueError("registered_miner_duplicate")
        if self.validator_uid in {uid for uid, _ in keys} or self.validator_hotkey in {
            key for _, key in keys
        }:
            raise ValueError("registered_validator_overlaps_miner")
        return self


@dataclass(frozen=True, slots=True)
class TerminalManifestObservation:
    """What the coordinator observed when it fetched the manifest at window close."""

    status: ManifestFetchStatus
    evaluated_at_epoch: int
    manifest: ActiveAssignmentManifest | None = None
    rejection_code: str | None = None


class WeightDecisionRow(StrictFrozenModel):
    """One registered miner: its class, weight, and the evidence counts behind it."""

    uid: UID
    hotkey: Hotkey
    classification: MinerClassification
    weight: float = Field(ge=0.0, le=1.0)
    attributions: int = Field(ge=0)
    opportunities: int = Field(ge=0)
    expected_attributions_numerator: int = Field(ge=0)
    expected_attributions_denominator: int = Field(ge=1)
    first_seen_epoch: Epoch | None

    @model_validator(mode="after")
    def canonical_row(self) -> Self:
        if (self.weight > 0.0) != (self.classification == "verified_serving"):
            raise ValueError("row_weight_classification_invalid")
        if self.classification == "unassigned" and self.first_seen_epoch is not None:
            raise ValueError("row_unassigned_first_seen_invalid")
        if self.classification.startswith("assigned_") and self.first_seen_epoch is None:
            raise ValueError("row_assigned_first_seen_missing")
        return self


class ValidatorWeightDecision(StrictFrozenModel):
    """Sealed, archivable outcome of one scoring window: abstain or submit."""

    contract_schema: Literal["miss.computer/misscomputer-subnet/validator-weight-decision"] = Field(
        alias="schema"
    )
    schema_version: Literal[1]
    purpose: Literal["public_validator_weight_decision_v1"]
    network: Literal["finney"]
    netuid: Literal[24]
    validator_uid: UID
    validator_hotkey: Hotkey
    window_start_epoch: Epoch
    window_end_epoch: PositiveEpoch
    decision: Decision
    abstain_reasons: list[AbstainReason] = Field(max_length=8)
    decision_policy: WeightDecisionPolicy
    scoring_policy: ProbeScoringPolicy
    terminal_manifest_status: ManifestFetchStatus
    terminal_manifest_rejection_code: RejectionCodeText | None
    terminal_evaluated_at_epoch: Epoch
    terminal_manifest_digest_sha256: Digest | None
    terminal_manifest_sequence: PositiveEpoch | None
    terminal_manifest_expires_at_epoch: PositiveEpoch | None
    terminal_finalized_height: Epoch | None
    round_count: int = Field(ge=0, le=MAX_ROUNDS)
    observation_count: int = Field(ge=0)
    serving_observation_count: int = Field(ge=0)
    scoring_window_digest_sha256: Digest | None
    max_assigned_miner_count: int = Field(ge=0, le=MAX_REGISTERED_MINERS)
    terminal_assigned_miner_count: int = Field(ge=0, le=MAX_REGISTERED_MINERS)
    registered_finalized_height: Epoch
    registered_finalized_block_hash: Digest
    registered_finalized_epoch: Epoch
    registered_miner_count: int = Field(ge=1, le=MAX_REGISTERED_MINERS)
    metagraph_identity_fingerprint_sha256: Digest
    rows: list[WeightDecisionRow] = Field(min_length=1, max_length=MAX_REGISTERED_MINERS)
    weight_plan_rows_digest_sha256: Digest | None
    decision_digest_sha256: Digest

    @model_validator(mode="after")
    def canonical_decision(self) -> Self:
        if self.window_end_epoch <= self.window_start_epoch:
            raise ValueError("decision_window_invalid")
        if self.terminal_evaluated_at_epoch < self.window_end_epoch:
            raise ValueError("decision_terminal_before_close")
        if self.abstain_reasons != sorted(set(self.abstain_reasons)):
            raise ValueError("abstain_reasons_not_canonical")
        if (self.decision == "abstain") != bool(self.abstain_reasons):
            raise ValueError("decision_reasons_inconsistent")
        verified = self.terminal_manifest_status == "verified"
        terminal_fields = (
            self.terminal_manifest_digest_sha256,
            self.terminal_manifest_sequence,
            self.terminal_manifest_expires_at_epoch,
            self.terminal_finalized_height,
        )
        if verified != all(value is not None for value in terminal_fields):
            raise ValueError("terminal_manifest_fields_inconsistent")
        if verified != (self.terminal_manifest_rejection_code is None):
            raise ValueError("terminal_rejection_code_inconsistent")
        if (self.round_count == 0) != (self.scoring_window_digest_sha256 is None):
            raise ValueError("scoring_window_digest_inconsistent")
        if self.serving_observation_count > self.observation_count:
            raise ValueError("observation_counts_invalid")
        keys = [(item.uid, item.hotkey) for item in self.rows]
        if keys != sorted(set(keys)):
            raise ValueError("rows_not_canonical")
        if len({uid for uid, _ in keys}) != len(keys) or len({key for _, key in keys}) != len(keys):
            raise ValueError("rows_identity_duplicate")
        if len(self.rows) != self.registered_miner_count:
            raise ValueError("rows_registered_count_mismatch")
        if self.validator_hotkey in {key for _, key in keys} or self.validator_uid in {
            uid for uid, _ in keys
        }:
            raise ValueError("rows_include_validator")
        positive = any(item.weight > 0.0 for item in self.rows)
        if self.decision == "submit":
            if not positive:
                raise ValueError("submit_without_positive_evidence")
            if self.weight_plan_rows_digest_sha256 != digest(_plan_rows(self.rows)):
                raise ValueError("weight_plan_rows_digest_mismatch")
        elif self.weight_plan_rows_digest_sha256 is not None:
            raise ValueError("abstain_with_plan_rows_digest")
        verify_model_digest(self, "decision_digest_sha256")
        return self


def _plan_rows(rows: Sequence[WeightDecisionRow]) -> list[dict[str, object]]:
    return [{"miner_hotkey": item.hotkey, "weight": item.weight} for item in rows]


def weight_plan_rows_for_submission(decision: ValidatorWeightDecision) -> list[dict[str, object]]:
    """The exact ``build_weight_plan`` rows a submit decision commits to.

    Refuses an abstain record: there is structurally no digest to honour.
    """

    decision = revalidate(decision, ValidatorWeightDecision)
    if decision.decision != "submit" or decision.weight_plan_rows_digest_sha256 is None:
        _reject("decision_not_submittable")
    rows = _plan_rows(decision.rows)
    if digest(rows) != decision.weight_plan_rows_digest_sha256:
        _reject("decision_not_submittable")
    return rows


def _validate_epoch(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= MAX_EPOCH:
        _reject("decision_epoch_invalid")
    return value


def _assigned_identities(manifest: ActiveAssignmentManifest) -> set[tuple[int, str]]:
    return {
        (replica.miner_uid, replica.miner_hotkey)
        for item in manifest.deployments
        for replica in item.replicas
    }


def _record_sightings(
    manifest: ActiveAssignmentManifest,
    endpoint_first_seen: dict[str, int],
    endpoint_owner: dict[str, tuple[int, str]],
) -> None:
    for item in manifest.deployments:
        for replica in item.replicas:
            seen = endpoint_first_seen.get(replica.endpoint_id)
            if seen is None or manifest.issued_at_epoch < seen:
                endpoint_first_seen[replica.endpoint_id] = manifest.issued_at_epoch
            endpoint_owner[replica.endpoint_id] = (replica.miner_uid, replica.miner_hotkey)


def decide_weight_submission(
    rounds: Sequence[ProbeRound],
    *,
    terminal: TerminalManifestObservation,
    registered: RegisteredMinerSet,
    window_start_epoch: int,
    window_end_epoch: int,
    decision_policy: WeightDecisionPolicy | None = None,
    scoring_policy: ProbeScoringPolicy | None = None,
    endpoint_first_seen_epoch: Mapping[str, int] | None = None,
) -> ValidatorWeightDecision:
    """Apply the frozen rules to one closed window and seal the decision record.

    ``rounds`` are the verified ``(manifest, report)`` pairs probed inside the
    window. ``terminal`` is the manifest fetch made at or after window close.
    ``endpoint_first_seen_epoch`` lets the coordinator supply earlier
    sightings of an endpoint incarnation from its own accepted-manifest
    archive; a supplied value may only be earlier than the in-window sighting.
    """

    policy = revalidate(decision_policy or WeightDecisionPolicy(), WeightDecisionPolicy)
    scoring = revalidate(scoring_policy or ProbeScoringPolicy(), ProbeScoringPolicy)
    registered = revalidate(registered, RegisteredMinerSet)
    window_start_epoch = _validate_epoch(window_start_epoch)
    window_end_epoch = _validate_epoch(window_end_epoch)
    if window_end_epoch <= window_start_epoch:
        _reject("decision_epoch_invalid")
    if policy.activation_grace_seconds > window_end_epoch - window_start_epoch:
        _reject("decision_policy_grace_exceeds_window")
    evaluated_at = _validate_epoch(terminal.evaluated_at_epoch)
    if evaluated_at < window_end_epoch:
        _reject("decision_terminal_before_close")
    if terminal.status not in ("rejected", "unavailable", "verified"):
        _reject("decision_terminal_status_invalid")
    terminal_manifest: ActiveAssignmentManifest | None = None
    if terminal.status == "verified":
        if terminal.manifest is None or terminal.rejection_code is not None:
            _reject("decision_terminal_status_invalid")
        terminal_manifest = revalidate(terminal.manifest, ActiveAssignmentManifest)
    elif terminal.manifest is not None or not terminal.rejection_code:
        _reject("decision_terminal_status_invalid")

    reasons: set[AbstainReason] = set()
    if terminal.status == "unavailable":
        reasons.add("manifest_unavailable")
    elif terminal.status == "rejected":
        reasons.add("manifest_invalid")
    elif terminal_manifest is not None and terminal_manifest.expires_at_epoch <= evaluated_at:
        reasons.add("manifest_expired_at_close")

    window: ProbeScoringWindow | None = None
    vector: ProbeWeightVector | None = None
    if rounds:
        window = accumulate_scoring_window(
            rounds,
            validator_uid=registered.validator_uid,
            validator_hotkey=registered.validator_hotkey,
            window_start_epoch=window_start_epoch,
            window_end_epoch=window_end_epoch,
        )
        vector = build_probe_weight_vector(window, registered=registered.miners, policy=scoring)
    if len(rounds) < policy.min_verified_rounds:
        reasons.add("rounds_insufficient")

    manifests = [entry.manifest for entry in rounds]
    if terminal_manifest is not None:
        for manifest in manifests:
            if manifest.sequence > terminal_manifest.sequence:
                _reject("decision_round_after_terminal")
    authorities = {manifest.central_authority_fingerprint_sha256 for manifest in manifests}
    if terminal_manifest is not None:
        authorities.add(terminal_manifest.central_authority_fingerprint_sha256)
    if len(authorities) > 1:
        _reject("decision_manifest_authority_mismatch")
    for manifest in manifests:
        if manifest.network != registered.network or manifest.netuid != registered.netuid:
            _reject("decision_manifest_authority_mismatch")

    endpoint_first_seen: dict[str, int] = {}
    endpoint_owner: dict[str, tuple[int, str]] = {}
    for manifest in manifests:
        _record_sightings(manifest, endpoint_first_seen, endpoint_owner)
    if terminal_manifest is not None:
        _record_sightings(terminal_manifest, endpoint_first_seen, endpoint_owner)
    for endpoint_id, supplied in (endpoint_first_seen_epoch or {}).items():
        derived = endpoint_first_seen.get(endpoint_id)
        if derived is None:
            continue
        if _validate_epoch(supplied) > derived:
            _reject("decision_first_seen_after_sighting")
        endpoint_first_seen[endpoint_id] = supplied
    miner_first_seen: dict[tuple[int, str], int] = {}
    for endpoint_id, owner in endpoint_owner.items():
        seen = endpoint_first_seen[endpoint_id]
        if owner not in miner_first_seen or seen < miner_first_seen[owner]:
            miner_first_seen[owner] = seen

    assigned_counts = [len(_assigned_identities(manifest)) for manifest in manifests]
    if terminal_manifest is not None:
        assigned = _assigned_identities(terminal_manifest)
    elif manifests:
        assigned = _assigned_identities(max(manifests, key=lambda item: item.sequence))
    else:
        assigned = set()
    terminal_count = len(assigned)
    max_count = max([*assigned_counts, terminal_count])
    if terminal_manifest is not None:
        if terminal_count * PERMILLE < max_count * (PERMILLE - policy.max_assigned_drop_permille):
            reasons.add("mass_unassignment_guard")
        if (
            registered.finalized_height < terminal_manifest.finalized_height
            or registered.finalized_height - terminal_manifest.finalized_height
            > policy.max_registered_height_gap
        ):
            reasons.add("registered_set_unbound")

    rows: list[WeightDecisionRow] = []
    positive = False
    for miner in sorted(registered.miners, key=lambda item: (item.uid, item.hotkey)):
        key = (miner.uid, miner.hotkey)
        tally = window.tally_for(miner.hotkey) if window is not None else None
        if tally is not None and tally.uid != miner.uid:
            tally = None
        weight = 0.0
        if vector is not None:
            for item in vector.rows:
                if item.uid == miner.uid and item.hotkey == miner.hotkey:
                    weight = item.weight
        expected = tally.expected_attributions if tally is not None else Fraction(0)
        first_seen = miner_first_seen.get(key)
        classification: MinerClassification
        if weight > 0.0:
            classification = "verified_serving"
            positive = True
        elif key not in assigned:
            classification = "unassigned"
            first_seen = None
        elif first_seen is not None and window_end_epoch - first_seen < (
            policy.activation_grace_seconds
        ):
            classification = "assigned_in_grace"
        elif expected < policy.min_expected_attributions:
            classification = "assigned_undersampled"
            reasons.add("coverage_insufficient")
        else:
            classification = "assigned_unverified"
        rows.append(
            WeightDecisionRow(
                uid=miner.uid,
                hotkey=miner.hotkey,
                classification=classification,
                weight=weight,
                attributions=0 if tally is None else tally.attributions,
                opportunities=0 if tally is None else tally.opportunities,
                expected_attributions_numerator=expected.numerator,
                expected_attributions_denominator=expected.denominator,
                first_seen_epoch=first_seen,
            )
        )
    if not positive:
        reasons.add("no_positive_evidence")

    decision: Decision = "abstain" if reasons else "submit"
    unsigned: dict[str, object] = {
        "schema": DECISION_SCHEMA,
        "schema_version": DECISION_SCHEMA_VERSION,
        "purpose": DECISION_PURPOSE,
        "network": registered.network,
        "netuid": registered.netuid,
        "validator_uid": registered.validator_uid,
        "validator_hotkey": registered.validator_hotkey,
        "window_start_epoch": window_start_epoch,
        "window_end_epoch": window_end_epoch,
        "decision": decision,
        "abstain_reasons": sorted(reasons),
        "decision_policy": model_document(policy),
        "scoring_policy": model_document(scoring),
        "terminal_manifest_status": terminal.status,
        "terminal_manifest_rejection_code": (
            None if terminal_manifest is not None else terminal.rejection_code
        ),
        "terminal_evaluated_at_epoch": evaluated_at,
        "terminal_manifest_digest_sha256": (
            None if terminal_manifest is None else terminal_manifest.manifest_digest_sha256
        ),
        "terminal_manifest_sequence": (
            None if terminal_manifest is None else terminal_manifest.sequence
        ),
        "terminal_manifest_expires_at_epoch": (
            None if terminal_manifest is None else terminal_manifest.expires_at_epoch
        ),
        "terminal_finalized_height": (
            None if terminal_manifest is None else terminal_manifest.finalized_height
        ),
        "round_count": len(rounds),
        "observation_count": 0 if window is None else window.observation_count,
        "serving_observation_count": 0 if window is None else window.serving_observation_count,
        "scoring_window_digest_sha256": None if window is None else digest(model_document(window)),
        "max_assigned_miner_count": max_count,
        "terminal_assigned_miner_count": terminal_count,
        "registered_finalized_height": registered.finalized_height,
        "registered_finalized_block_hash": registered.finalized_block_hash,
        "registered_finalized_epoch": registered.finalized_epoch,
        "registered_miner_count": len(registered.miners),
        "metagraph_identity_fingerprint_sha256": registered.metagraph_identity_fingerprint_sha256,
        "rows": [model_document(item) for item in rows],
        "weight_plan_rows_digest_sha256": (
            digest(_plan_rows(rows)) if decision == "submit" else None
        ),
    }
    return ValidatorWeightDecision.model_validate(
        {**unsigned, "decision_digest_sha256": digest(unsigned)}
    )


def validator_weight_decision_bytes(value: ValidatorWeightDecision) -> bytes:
    return model_bytes(value, ValidatorWeightDecision)


def parse_validator_weight_decision(rendered: bytes) -> ValidatorWeightDecision:
    return parse_model(
        rendered,
        ValidatorWeightDecision,
        validator_weight_decision_bytes,
        maximum_bytes=MAX_DECISION_BYTES,
    )
