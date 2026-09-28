# SPDX-License-Identifier: AGPL-3.0-only
"""Organic validator decision: abstain or submit (``validator-weight-decision`` v2).

:mod:`misscomputer_subnet.organic_scoring` turns a validator's own hidden-probe
epochs into per-miner availability. This module answers the remaining
question: **may that availability become a weight transaction at all?** The
synthetic v1 decision (fair round-robin attribution, volume scoring) is
removed with the synthetic flow (contract §13).

Frozen rules
------------
1. **The terminal manifest must verify at window close.** A validator that
   cannot verify what is assigned right now submits nothing: an unavailable
   or rejected terminal fetch, a terminal manifest past its effective horizon
   at close, or one its own trust policy would not admit at that instant, is
   ``abstain``.
2. **Enough scored epochs.** Fewer than ``min_scored_epochs`` epochs with
   status ``scored`` in the window is ``abstain``: common-mode outages and
   under-sampling are the validator's problem, never the miners'.
3. **The registered set must be bound to the manifest's chain view.** The
   finalized registered view may not trail the terminal manifest's finalized
   height, lead it by more than ``max_registered_height_gap`` blocks, or have
   a lower epoch; otherwise ``abstain``.
4. **Rows cover every registered miner.** A registered miner the window
   scored is ``scored`` with weight = its availability; a scored miner with
   attributable attestation fraud is ``fraud_evidence`` with weight 0
   (contract §11.3 trust-zero); every other registered miner is ``unscored``
   with weight 0. A zero row carries no penalty meaning: the weight plan drops
   it, and chain weights are relative. Scores for identities that are not
   registered with exactly that UID and hotkey are ignored.
5. **No positive availability ⇒ no transaction** (``abstain``).
6. **Self-enforcing record.** The sealed record embeds every epoch record and
   every manifest those epochs probed. Parsing replays each epoch against the
   embedded manifests (re-verifying every miner attestation), re-aggregates
   the window, re-admits the terminal manifest under its sealed trust policy,
   and re-derives every abstain reason and row. A record whose stated decision
   or rows do not follow from its evidence is rejected, and
   ``weight_plan_rows_digest_sha256`` is ``null`` on abstain, so an abstain
   record can never become a plan.

Serving volume and request counts never reach this record except as the
epochs' corroboration summaries, which the rows never read.

This module is pure: no clock, network, file, process, environment, wallet,
chain, randomness, or signing capability.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from fractions import Fraction
from typing import Annotated, Final, Literal, NoReturn, Self

from pydantic import Field, StringConstraints, model_validator

from .assignment_probe import (
    AssignmentManifestTrustPolicy,
    AssignmentProbeError,
    verify_manifest_policy_admission,
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
from .organic_contracts import ActiveAssignmentManifestV2
from .organic_manifest import (
    organic_manifest_effective_expires_at_epoch,
    verify_organic_manifest_identities,
)
from .organic_scoring import (
    MAX_EPOCHS,
    OrganicAvailabilityScore,
    OrganicEpochScore,
    OrganicScoringError,
    aggregate_organic_window,
    replay_organic_epoch_score,
)

DECISION_SCHEMA: Final = "miss.computer/misscomputer-subnet/validator-weight-decision"
DECISION_SCHEMA_VERSION: Final = 2
DECISION_PURPOSE: Final = "organic_validator_weight_decision_v2"
MAX_DECISION_BYTES: Final = 64 * 1_024 * 1_024
MAX_REGISTERED_MINERS: Final = 4_096
MAX_TRUST_POLICIES: Final = 16
MAX_MANIFESTS: Final = 1_024
MAX_EPOCH: Final = (1 << 63) - 1

Digest = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
Hotkey = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9]{1,128}$")]
UID = Annotated[int, Field(ge=0, le=(1 << 16) - 1)]
Epoch = Annotated[int, Field(ge=0, le=MAX_EPOCH)]
PositiveEpoch = Annotated[int, Field(ge=1, le=MAX_EPOCH)]
RejectionCodeText = Annotated[str, StringConstraints(pattern=r"^[a-z0-9_]{1,64}$")]
ManifestFetchStatus = Literal["rejected", "unavailable", "verified"]
Decision = Literal["abstain", "submit"]
MinerClassification = Literal["fraud_evidence", "scored", "unscored"]
AbstainReason = Literal[
    "insufficient_scored_epochs",
    "no_positive_evidence",
    "registered_set_unbound",
    "terminal_manifest_policy_rejected",
    "terminal_manifest_rejected",
    "terminal_manifest_stale",
    "terminal_manifest_unavailable",
]
DecisionRejectionCode = Literal[
    "decision_epoch_invalid",
    "decision_epochs_invalid",
    "decision_manifest_missing",
    "decision_not_submittable",
    "decision_terminal_invalid",
    "decision_trust_policy_invalid",
    "decision_trust_policy_missing",
    "decision_validator_mismatch",
    "decision_window_invalid",
]


class WeightDecisionError(ValueError):
    """Inputs that cannot produce a trustworthy decision record at all."""

    def __init__(self, code: DecisionRejectionCode) -> None:
        super().__init__(code)
        self.code = code


def _reject(code: DecisionRejectionCode) -> NoReturn:
    raise WeightDecisionError(code)


class WeightDecisionPolicy(StrictFrozenModel):
    """Validator-local decision thresholds. Each validator decides independently."""

    #: Scored epochs a window needs before any weight can be submitted
    #: (default: half of a one-hour window of five-minute epochs).
    min_scored_epochs: int = Field(default=6, ge=1, le=MAX_EPOCHS)
    #: The registered set's finalized height may not lead the terminal
    #: manifest's finalized height by more than this many blocks.
    max_registered_height_gap: int = Field(default=600, ge=0, le=1_000_000)


class RegisteredMiner(StrictFrozenModel):
    """One metagraph identity eligible to receive weight (never the validator itself)."""

    uid: UID
    hotkey: Hotkey


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
    manifest: ActiveAssignmentManifestV2 | None = None
    rejection_code: str | None = None


class WeightDecisionRow(StrictFrozenModel):
    """One registered miner: its class, weight, and the availability behind it."""

    uid: UID
    hotkey: Hotkey
    classification: MinerClassification
    weight: float = Field(ge=0.0, le=1.0)
    eligible_endpoint_epochs: int = Field(ge=0)
    availability_numerator: int | None = Field(ge=0)
    availability_denominator: int | None = Field(ge=1)


def _abstain_reasons(
    *,
    terminal_status: ManifestFetchStatus,
    terminal_manifest: ActiveAssignmentManifestV2 | None,
    terminal_policy_admitted: bool,
    window_end_epoch: int,
    scored_epochs: int,
    registered: RegisteredMinerSet,
    policy: WeightDecisionPolicy,
    positive_rows: int,
) -> list[AbstainReason]:
    reasons: list[AbstainReason] = []
    if terminal_status == "unavailable":
        reasons.append("terminal_manifest_unavailable")
    elif terminal_status == "rejected":
        reasons.append("terminal_manifest_rejected")
    elif terminal_manifest is not None:
        if window_end_epoch >= organic_manifest_effective_expires_at_epoch(terminal_manifest):
            reasons.append("terminal_manifest_stale")
        if not terminal_policy_admitted:
            reasons.append("terminal_manifest_policy_rejected")
        if (
            registered.finalized_height < terminal_manifest.finalized_height
            or registered.finalized_height - terminal_manifest.finalized_height
            > policy.max_registered_height_gap
            or registered.finalized_epoch < terminal_manifest.finalized_epoch
            or (
                registered.finalized_height == terminal_manifest.finalized_height
                and (
                    registered.finalized_block_hash != terminal_manifest.finalized_block_hash
                    or registered.finalized_epoch != terminal_manifest.finalized_epoch
                )
            )
        ):
            reasons.append("registered_set_unbound")
    if scored_epochs < policy.min_scored_epochs:
        reasons.append("insufficient_scored_epochs")
    if positive_rows == 0:
        reasons.append("no_positive_evidence")
    return sorted(set(reasons))


def _derive_rows(
    registered: RegisteredMinerSet, score: OrganicAvailabilityScore | None
) -> list[dict[str, object]]:
    scored = {(item.miner_uid, item.miner_hotkey): item for item in (score.miners if score else [])}
    rows: list[dict[str, object]] = []
    for miner in registered.miners:
        item = scored.get((miner.uid, miner.hotkey))
        if item is None:
            rows.append(
                {
                    "uid": miner.uid,
                    "hotkey": miner.hotkey,
                    "classification": "unscored",
                    "weight": 0.0,
                    "eligible_endpoint_epochs": 0,
                    "availability_numerator": None,
                    "availability_denominator": None,
                }
            )
            continue
        fraud = item.fraudulent_attestations > 0
        availability = Fraction(item.availability_numerator, item.availability_denominator)
        rows.append(
            {
                "uid": miner.uid,
                "hotkey": miner.hotkey,
                "classification": "fraud_evidence" if fraud else "scored",
                "weight": 0.0 if fraud else float(availability),
                "eligible_endpoint_epochs": item.eligible_endpoint_epochs,
                "availability_numerator": item.availability_numerator,
                "availability_denominator": item.availability_denominator,
            }
        )
    return rows


def _plan_rows(rows: Sequence[WeightDecisionRow]) -> list[dict[str, object]]:
    return [{"miner_hotkey": item.hotkey, "weight": item.weight} for item in rows]


def _terminal_admitted(
    manifest: ActiveAssignmentManifestV2,
    policies: Sequence[AssignmentManifestTrustPolicy],
    evaluated_at_epoch: int,
) -> bool:
    policy = next(
        (
            item
            for item in policies
            if item.trust_policy_digest_sha256 == manifest.trust_policy_digest_sha256
        ),
        None,
    )
    if policy is None:
        return False
    try:
        verify_manifest_policy_admission(manifest, policy, evaluation_epoch=evaluated_at_epoch)
        verify_organic_manifest_identities(manifest)
    except (AssignmentProbeError, ValueError):
        return False
    return True


class ValidatorWeightDecision(StrictFrozenModel):
    """Sealed, archivable outcome of one organic scoring window: abstain or submit."""

    contract_schema: Literal["miss.computer/misscomputer-subnet/validator-weight-decision"] = Field(
        alias="schema"
    )
    schema_version: Literal[2]
    purpose: Literal["organic_validator_weight_decision_v2"]
    network: Literal["finney"]
    netuid: Literal[24]
    validator_uid: UID
    validator_hotkey: Hotkey
    window_start_epoch: Epoch
    window_end_epoch: PositiveEpoch
    decision: Decision
    abstain_reasons: list[AbstainReason] = Field(max_length=7)
    decision_policy: WeightDecisionPolicy
    trust_policies: list[AssignmentManifestTrustPolicy] = Field(max_length=MAX_TRUST_POLICIES)
    terminal_manifest_status: ManifestFetchStatus
    terminal_manifest_rejection_code: RejectionCodeText | None
    terminal_evaluated_at_epoch: Epoch
    terminal_manifest_digest_sha256: Digest | None
    terminal_manifest_sequence: PositiveEpoch | None
    terminal_finalized_height: Epoch | None
    terminal_finalized_block_hash: Digest | None
    terminal_finalized_epoch: Epoch | None
    manifests: list[ActiveAssignmentManifestV2] = Field(max_length=MAX_MANIFESTS)
    epochs: list[OrganicEpochScore] = Field(max_length=MAX_EPOCHS)
    availability_score: OrganicAvailabilityScore | None
    scored_epoch_count: int = Field(ge=0, le=MAX_EPOCHS)
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
        policy_digests = [item.trust_policy_digest_sha256 for item in self.trust_policies]
        if policy_digests != sorted(set(policy_digests)):
            raise ValueError("decision_trust_policies_not_canonical")
        manifest_digests = [item.manifest_digest_sha256 for item in self.manifests]
        if manifest_digests != sorted(set(manifest_digests)):
            raise ValueError("decision_manifests_not_canonical")
        if {item.trust_policy_digest_sha256 for item in self.manifests} != set(policy_digests):
            raise ValueError("decision_trust_policies_not_exact")
        by_digest = {item.manifest_digest_sha256: item for item in self.manifests}
        terminal_fields = (
            self.terminal_manifest_digest_sha256,
            self.terminal_manifest_sequence,
            self.terminal_finalized_height,
            self.terminal_finalized_block_hash,
            self.terminal_finalized_epoch,
        )
        terminal: ActiveAssignmentManifestV2 | None = None
        if self.terminal_manifest_status == "verified":
            terminal = by_digest.get(self.terminal_manifest_digest_sha256 or "")
            if (
                terminal is None
                or self.terminal_manifest_rejection_code is not None
                or terminal_fields
                != (
                    terminal.manifest_digest_sha256,
                    terminal.sequence,
                    terminal.finalized_height,
                    terminal.finalized_block_hash,
                    terminal.finalized_epoch,
                )
            ):
                raise ValueError("decision_terminal_invalid")
            if self.terminal_evaluated_at_epoch < self.window_end_epoch:
                raise ValueError("decision_terminal_invalid")
        elif any(value is not None for value in terminal_fields) or (
            (self.terminal_manifest_status == "rejected")
            != (self.terminal_manifest_rejection_code is not None)
        ):
            raise ValueError("decision_terminal_invalid")
        indexes = [item.epoch_index for item in self.epochs]
        if indexes != sorted(set(indexes)):
            raise ValueError("decision_epochs_not_canonical")
        epoch_manifests: set[str] = set()
        for epoch in self.epochs:
            if epoch.validator_hotkey != self.validator_hotkey:
                raise ValueError("decision_validator_mismatch")
            start = epoch.epoch_index * epoch.epoch_seconds
            if start < self.window_start_epoch or start + epoch.epoch_seconds > (
                self.window_end_epoch
            ):
                raise ValueError("decision_epoch_outside_window")
            epoch_manifests.update(epoch.manifest_digests)
            replay_organic_epoch_score(
                epoch, [by_digest[key] for key in epoch.manifest_digests if key in by_digest]
            )
        expected_manifests = set(epoch_manifests)
        if terminal is not None:
            expected_manifests.add(terminal.manifest_digest_sha256)
        if expected_manifests != set(manifest_digests):
            raise ValueError("decision_manifests_not_exact")
        score = aggregate_organic_window(self.epochs) if self.epochs else None
        if (model_document(score) if score else None) != (
            model_document(self.availability_score) if self.availability_score else None
        ):
            raise ValueError("decision_availability_mismatch")
        scored = sum(item.epoch_status == "scored" for item in self.epochs)
        if scored != self.scored_epoch_count:
            raise ValueError("decision_scored_epochs_mismatch")
        registered = RegisteredMinerSet(
            network=self.network,
            netuid=self.netuid,
            finalized=True,
            finalized_height=self.registered_finalized_height,
            finalized_block_hash=self.registered_finalized_block_hash,
            finalized_epoch=self.registered_finalized_epoch,
            validator_uid=self.validator_uid,
            validator_hotkey=self.validator_hotkey,
            miners=[RegisteredMiner(uid=row.uid, hotkey=row.hotkey) for row in self.rows],
            metagraph_identity_fingerprint_sha256=self.metagraph_identity_fingerprint_sha256,
        )
        if self.registered_miner_count != len(self.rows):
            raise ValueError("decision_registered_count_mismatch")
        rows = _derive_rows(registered, score)
        if [model_document(item) for item in self.rows] != rows:
            raise ValueError("decision_rows_mismatch")
        positive = sum(1 for row in self.rows if row.weight > 0.0)
        reasons = _abstain_reasons(
            terminal_status=self.terminal_manifest_status,
            terminal_manifest=terminal,
            terminal_policy_admitted=terminal is not None
            and _terminal_admitted(terminal, self.trust_policies, self.terminal_evaluated_at_epoch),
            window_end_epoch=self.window_end_epoch,
            scored_epochs=scored,
            registered=registered,
            policy=self.decision_policy,
            positive_rows=positive,
        )
        if self.abstain_reasons != reasons:
            raise ValueError("decision_abstain_reasons_mismatch")
        if (self.decision == "submit") != (not reasons):
            raise ValueError("decision_outcome_mismatch")
        expected_digest = digest(_plan_rows(self.rows)) if self.decision == "submit" else None
        if self.weight_plan_rows_digest_sha256 != expected_digest:
            raise ValueError("decision_weight_plan_digest_mismatch")
        verify_model_digest(self, "decision_digest_sha256")
        return self


def _validated_weight_submission(
    decision: ValidatorWeightDecision,
) -> tuple[ValidatorWeightDecision, tuple[tuple[str, float], ...]]:
    """Snapshot a sealed submission and its committed rows into private immutable values."""

    decision = revalidate(decision, ValidatorWeightDecision)
    if decision.decision != "submit" or decision.weight_plan_rows_digest_sha256 is None:
        _reject("decision_not_submittable")
    row_values = tuple((row.hotkey, row.weight) for row in decision.rows)
    rows = [{"miner_hotkey": hotkey, "weight": weight} for hotkey, weight in row_values]
    if digest(rows) != decision.weight_plan_rows_digest_sha256:
        _reject("decision_not_submittable")
    return decision, row_values


def weight_plan_rows_for_submission(decision: ValidatorWeightDecision) -> list[dict[str, object]]:
    """The exact ``build_weight_plan`` rows a submit decision commits to."""

    _, row_values = _validated_weight_submission(decision)
    return [{"miner_hotkey": hotkey, "weight": weight} for hotkey, weight in row_values]


def _validate_epoch(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= MAX_EPOCH:
        _reject("decision_epoch_invalid")
    return value


def decide_weight_submission(
    epochs: Sequence[OrganicEpochScore],
    *,
    manifests: Sequence[ActiveAssignmentManifestV2],
    terminal: TerminalManifestObservation,
    registered: RegisteredMinerSet,
    trust_policies: Sequence[AssignmentManifestTrustPolicy],
    window_start_epoch: int,
    window_end_epoch: int,
    decision_policy: WeightDecisionPolicy | None = None,
) -> ValidatorWeightDecision:
    """Apply the frozen rules to one closed window and seal the decision record.

    ``epochs`` are the validator's own sealed epoch records inside the window;
    ``manifests`` must include every manifest they probed. ``terminal`` is the
    manifest fetch made at or after window close. ``trust_policies`` are the
    approved policies those manifests were verified under; exactly the ones
    the sealed manifests name are kept.
    """

    start = _validate_epoch(window_start_epoch)
    end = _validate_epoch(window_end_epoch)
    if end <= start:
        _reject("decision_window_invalid")
    policy = decision_policy or WeightDecisionPolicy()
    registered = revalidate(registered, RegisteredMinerSet)
    values = sorted(
        (revalidate(item, OrganicEpochScore) for item in epochs),
        key=lambda item: item.epoch_index,
    )
    if len({item.epoch_index for item in values}) != len(values) or len(values) > MAX_EPOCHS:
        _reject("decision_epochs_invalid")
    if any(item.validator_hotkey != registered.validator_hotkey for item in values):
        _reject("decision_validator_mismatch")
    available = {
        item.manifest_digest_sha256: item
        for item in (revalidate(value, ActiveAssignmentManifestV2) for value in manifests)
    }
    needed = {key for item in values for key in item.manifest_digests}
    if not needed <= set(available):
        _reject("decision_manifest_missing")
    evaluated = _validate_epoch(terminal.evaluated_at_epoch)
    terminal_manifest: ActiveAssignmentManifestV2 | None = None
    if terminal.status == "verified":
        if terminal.manifest is None or terminal.rejection_code is not None or evaluated < end:
            _reject("decision_terminal_invalid")
        terminal_manifest = revalidate(terminal.manifest, ActiveAssignmentManifestV2)
        needed.add(terminal_manifest.manifest_digest_sha256)
        available[terminal_manifest.manifest_digest_sha256] = terminal_manifest
    elif terminal.manifest is not None or (
        (terminal.status == "rejected") != (terminal.rejection_code is not None)
    ):
        _reject("decision_terminal_invalid")
    sealed_manifests = [available[key] for key in sorted(needed)]
    named = {item.trust_policy_digest_sha256 for item in sealed_manifests}
    policies = {
        item.trust_policy_digest_sha256: item
        for item in (revalidate(value, AssignmentManifestTrustPolicy) for value in trust_policies)
    }
    if len(policies) > MAX_TRUST_POLICIES:
        _reject("decision_trust_policy_invalid")
    if not named <= set(policies):
        _reject("decision_trust_policy_missing")
    sealed_policies = [policies[key] for key in sorted(named)]
    try:
        score = aggregate_organic_window(values) if values else None
    except OrganicScoringError:
        _reject("decision_epochs_invalid")
    rows = _derive_rows(registered, score)
    positive = sum(1 for row in rows if isinstance(row["weight"], float) and row["weight"] > 0.0)
    scored = sum(item.epoch_status == "scored" for item in values)
    reasons = _abstain_reasons(
        terminal_status=terminal.status,
        terminal_manifest=terminal_manifest,
        terminal_policy_admitted=terminal_manifest is not None
        and _terminal_admitted(terminal_manifest, sealed_policies, evaluated),
        window_end_epoch=end,
        scored_epochs=scored,
        registered=registered,
        policy=policy,
        positive_rows=positive,
    )
    decision: Decision = "abstain" if reasons else "submit"
    plan_rows = [{"miner_hotkey": row["hotkey"], "weight": row["weight"]} for row in rows]
    unsigned: dict[str, object] = {
        "schema": DECISION_SCHEMA,
        "schema_version": DECISION_SCHEMA_VERSION,
        "purpose": DECISION_PURPOSE,
        "network": registered.network,
        "netuid": registered.netuid,
        "validator_uid": registered.validator_uid,
        "validator_hotkey": registered.validator_hotkey,
        "window_start_epoch": start,
        "window_end_epoch": end,
        "decision": decision,
        "abstain_reasons": reasons,
        "decision_policy": model_document(policy),
        "trust_policies": [model_document(item) for item in sealed_policies],
        "terminal_manifest_status": terminal.status,
        "terminal_manifest_rejection_code": terminal.rejection_code,
        "terminal_evaluated_at_epoch": evaluated,
        "terminal_manifest_digest_sha256": (
            terminal_manifest.manifest_digest_sha256 if terminal_manifest else None
        ),
        "terminal_manifest_sequence": terminal_manifest.sequence if terminal_manifest else None,
        "terminal_finalized_height": (
            terminal_manifest.finalized_height if terminal_manifest else None
        ),
        "terminal_finalized_block_hash": (
            terminal_manifest.finalized_block_hash if terminal_manifest else None
        ),
        "terminal_finalized_epoch": (
            terminal_manifest.finalized_epoch if terminal_manifest else None
        ),
        "manifests": [model_document(item) for item in sealed_manifests],
        "epochs": [model_document(item) for item in values],
        "availability_score": model_document(score) if score else None,
        "scored_epoch_count": scored,
        "registered_finalized_height": registered.finalized_height,
        "registered_finalized_block_hash": registered.finalized_block_hash,
        "registered_finalized_epoch": registered.finalized_epoch,
        "registered_miner_count": len(registered.miners),
        "metagraph_identity_fingerprint_sha256": (registered.metagraph_identity_fingerprint_sha256),
        "rows": rows,
        "weight_plan_rows_digest_sha256": digest(plan_rows) if decision == "submit" else None,
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
