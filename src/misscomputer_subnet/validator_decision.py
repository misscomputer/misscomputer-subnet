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
   A manifest is stale at close when its *effective* horizon has passed: its
   own expiry or the earliest assignment-ticket expiry it publishes, and it
   is likewise stale when any published block lease has ended at the
   registered set's finalized height.
2. **Insufficient sampling coverage => ABSTAIN.** Fewer verified rounds than
   ``min_verified_rounds``, or any miner assigned at close and outside
   activation grace whose fair-round-robin expected attributions are below
   ``min_expected_attributions``, means the validator's own sampling, not the
   miner, is the reason the window cannot be judged. This holds even for a
   miner that did earn positive evidence: an under-sampled window is not a
   basis for zeroing that miner's peers.
3. **Assigned, sufficiently sampled, no verified serving evidence => zero.**
4. **Registered but absent from the valid assignment manifest => zero, only
   when every safe precondition holds:** the terminal manifest verified and
   within its effective horizon at close; the registered set bound to a
   finalized metagraph view that agrees with the manifest's chain view (same
   hash and epoch at the same height, never behind it, never more than
   ``max_registered_height_gap`` ahead, epoch never lower); rules 1 and 2
   satisfied; the mass-unassignment guard satisfied; and at least one
   positive attested row.
5. **No positive verified evidence => no weight transaction.**
6. **Activation grace.** A miner whose earliest sighting (across the window's
   accepted manifests, the terminal manifest, and any earlier sighting the
   coordinator supplies from its archive) is less than
   ``activation_grace_seconds`` before window close is never the reason to
   abstain and is reported as ``assigned_in_grace`` if unverified. Grace
   creates no weight: the miner earns weight from the first window in which
   it is attributed.
7. **Finalized window closure.** Reports are admitted only with
   ``window_start_epoch <= evaluation_epoch < window_end_epoch`` and before
   their manifest's effective horizon; the terminal manifest observation is
   taken at or after ``window_end_epoch``; the registered set is a finalized
   view.
8. **Replicas need repeated probing.** Coverage is measured in expected
   attributions, ``opportunities / replica_count`` summed over the rounds a
   miner was published in, so a three-replica deployment needs at least
   ``3 * min_expected_attributions`` observations before its silent replica
   can be zeroed.
9. **Mass-unassignment baseline outlives the window.** The largest assigned
   set the guard compares against includes the sealed baseline carried from
   the previous decision, so a central mass-eviction that lands exactly on a
   window boundary is still not miner evidence. Assigned sets are counted in
   *registered* identities only, so padding a manifest with unregistered
   identities cannot hide a drop. The baseline decays after
   ``assigned_baseline_max_age_seconds`` and is refreshed by a verified
   terminal manifest that clears the guard; while the guard holds, the
   largest set (the applied prior baseline or the window's largest manifest)
   is carried instead, so a guarded drop can never become the next window's
   baseline.
10. **One coherent, unbroken manifest chain.** Every manifest in the window,
    every archived manifest the coordinator accepted between them, and the
    terminal manifest must form one chain: one central authority, one
    manifest per sequence and every actual digest-linked transition supplied
    from the window's first to the terminal, with monotonic finalized height
    and epoch and one hash and epoch per height. Sequence values may make the
    bounded jumps already enforced when each publication was accepted. Two
    different manifests at one sequence are publisher equivocation and a
    missing actual predecessor is a gap; both refuse the inputs outright.
11. **Deterministic, self-enforcing boundary.** The sealed
    ``validator-weight-decision`` v1 document is the only input to the
    decision-aware weight-plan builder. Every abstain reason and every row
    classification is re-derived from the sealed fields on parse, so a record
    that says ``submit`` while its own fields describe an outage, a coverage
    gap, a mass drop, or an unbound registered view is rejected; its
    ``weight_plan_rows_digest_sha256`` commits to the exact rows and is
    ``null`` on abstain, so an abstain record can never be turned into a plan.
12. **Positive weight needs sealed serving evidence.** A positive row must
    carry at least ``scoring_policy.min_attributions`` attributions, bounded
    by its opportunities and by the record's serving observation count, and
    its expected attributions are recomputed exactly from sealed
    replica-cardinality opportunity buckets. The positive weights must be one
    normalized distribution; a digest-valid record cannot assign weight to a
    miner it never observed serving.

This module is pure: no clock, network, file, process, environment, wallet,
chain, randomness, or signing capability.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from fractions import Fraction
from typing import Annotated, Final, Literal, NoReturn, Self

from pydantic import Field, StringConstraints, ValidationError, model_validator

from .assignment_probe import (
    MAX_EPOCH,
    MAX_REPLICAS,
    UID,
    ActiveAssignmentManifest,
    Digest,
    Epoch,
    Hotkey,
    PositiveEpoch,
    ValidatorProbeReport,
    manifest_earliest_lease_expires_at_block,
    manifest_effective_expires_at_epoch,
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
    ReplicaShareCount,
    accumulate_scoring_window,
    build_probe_weight_vector,
)

DECISION_SCHEMA: Final = "miss.computer/misscomputer-subnet/validator-weight-decision"
DECISION_SCHEMA_VERSION: Final = 1
DECISION_PURPOSE: Final = "public_validator_weight_decision_v1"
MAX_DECISION_BYTES: Final = 64 * 1_024 * 1_024
PERMILLE: Final = 1_000
MAX_BASELINE_AGE_SECONDS: Final = 30 * 86_400

ManifestFetchStatus = Literal["rejected", "unavailable", "verified"]
Decision = Literal["abstain", "submit"]
BaselineStatus = Literal["absent", "applied", "expired"]
MinerClassification = Literal[
    "assigned_in_grace",
    "assigned_undersampled",
    "assigned_unverified",
    "unassigned",
    "verified_serving",
]
AbstainReason = Literal[
    "assignment_lease_expired_at_close",
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
    "decision_archived_manifest_invalid",
    "decision_baseline_invalid",
    "decision_epoch_invalid",
    "decision_first_seen_after_sighting",
    "decision_manifest_authority_mismatch",
    "decision_manifest_chain_gap",
    "decision_manifest_chain_incoherent",
    "decision_not_submittable",
    "decision_policy_grace_exceeds_window",
    "decision_registered_validator_mismatch",
    "decision_round_after_horizon",
    "decision_round_after_terminal",
    "decision_round_invalid",
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
    #: must have accrued before the window can be judged at all.
    min_expected_attributions: int = Field(default=3, ge=1, le=MAX_ROUNDS)
    #: Seconds after a miner's earliest sighting during which its silence is
    #: neither evidence nor a reason to abstain.
    activation_grace_seconds: int = Field(default=1_800, ge=0, le=86_400)
    #: Abstain when the terminal manifest assigns fewer than
    #: ``(1000 - permille) / 1000`` of the largest assigned set seen in the
    #: window or carried in the baseline: a central mass-eviction is not
    #: miner evidence.
    max_assigned_drop_permille: int = Field(default=500, ge=0, le=PERMILLE)
    #: The registered set's finalized height may not lead the terminal
    #: manifest's finalized height by more than this many blocks.
    max_registered_height_gap: int = Field(default=600, ge=0, le=1_000_000)
    #: A baseline established longer ago than this before window close no
    #: longer widens the mass-unassignment guard; the guard then falls back to
    #: the window itself. Refreshed by every verified terminal manifest that
    #: clears the guard; a guarded drop carries the largest set forward.
    assigned_baseline_max_age_seconds: int = Field(
        default=86_400, ge=0, le=MAX_BASELINE_AGE_SECONDS
    )


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


class AssignedBaseline(StrictFrozenModel):
    """The largest verified assigned set a decision hands to its successor window.

    ``established_at_epoch`` is the close of the window that established it;
    ``assigned_identity_digest_sha256`` is the digest of the sorted
    ``[uid, hotkey]`` pairs of *registered* miners assigned in that manifest,
    and ``assigned_miner_count`` counts exactly those pairs.
    """

    established_at_epoch: Epoch
    manifest_sequence: PositiveEpoch
    manifest_digest_sha256: Digest
    assigned_miner_count: int = Field(ge=0, le=MAX_REGISTERED_MINERS)
    assigned_identity_digest_sha256: Digest


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
    #: Counts of opportunities grouped by the published replica-set size.
    #: These buckets make the fair-share expectation independently
    #: recomputable from the sealed decision instead of trusting its fraction.
    replica_share_counts: list[ReplicaShareCount] = Field(max_length=MAX_REPLICAS)
    first_seen_epoch: Epoch | None
    #: Whether the terminal manifest (or, absent one, the latest accepted
    #: manifest) assigns this miner. Sealed so that classification and the
    #: coverage rule are re-derivable from the record alone.
    assigned_at_close: bool

    @model_validator(mode="after")
    def canonical_row(self) -> Self:
        if (self.weight > 0.0) != (self.classification == "verified_serving"):
            raise ValueError("row_weight_classification_invalid")
        if self.attributions > self.opportunities:
            raise ValueError("row_attributions_exceed_opportunities")
        replica_counts = [item.replica_count for item in self.replica_share_counts]
        if replica_counts != sorted(set(replica_counts)):
            raise ValueError("row_replica_share_counts_not_canonical")
        if sum(item.opportunity_count for item in self.replica_share_counts) != (
            self.opportunities
        ):
            raise ValueError("row_expected_attributions_inconsistent")
        recomputed_expected = sum(
            (
                Fraction(item.opportunity_count, item.replica_count)
                for item in self.replica_share_counts
            ),
            Fraction(0),
        )
        if self.expected_attributions > self.opportunities or (
            self.expected_attributions_numerator,
            self.expected_attributions_denominator,
        ) != (recomputed_expected.numerator, recomputed_expected.denominator):
            raise ValueError("row_expected_attributions_inconsistent")
        if self.weight > 0.0 and self.attributions == 0:
            raise ValueError("row_positive_weight_without_evidence")
        if self.classification == "unassigned" and (
            self.first_seen_epoch is not None or self.assigned_at_close
        ):
            raise ValueError("row_unassigned_first_seen_invalid")
        if self.classification.startswith("assigned_") and (
            self.first_seen_epoch is None or not self.assigned_at_close
        ):
            raise ValueError("row_assigned_first_seen_missing")
        if (
            self.classification == "verified_serving"
            and self.assigned_at_close
            and (self.first_seen_epoch is None)
        ):
            raise ValueError("row_assigned_first_seen_missing")
        return self

    @property
    def expected_attributions(self) -> Fraction:
        return Fraction(
            self.expected_attributions_numerator, self.expected_attributions_denominator
        )


def _in_grace(row: WeightDecisionRow, *, window_end_epoch: int, grace_seconds: int) -> bool:
    return row.first_seen_epoch is not None and window_end_epoch - row.first_seen_epoch < (
        grace_seconds
    )


def _derived_classification(
    row: WeightDecisionRow, *, window_end_epoch: int, policy: WeightDecisionPolicy
) -> MinerClassification:
    if row.weight > 0.0:
        return "verified_serving"
    if not row.assigned_at_close:
        return "unassigned"
    if _in_grace(
        row, window_end_epoch=window_end_epoch, grace_seconds=policy.activation_grace_seconds
    ):
        return "assigned_in_grace"
    if row.expected_attributions < policy.min_expected_attributions:
        return "assigned_undersampled"
    return "assigned_unverified"


def _coverage_insufficient(
    rows: Sequence[WeightDecisionRow], *, window_end_epoch: int, policy: WeightDecisionPolicy
) -> bool:
    return any(
        row.assigned_at_close
        and not _in_grace(
            row, window_end_epoch=window_end_epoch, grace_seconds=policy.activation_grace_seconds
        )
        and row.expected_attributions < policy.min_expected_attributions
        for row in rows
    )


def _registered_set_unbound(
    *,
    registered_finalized_height: int,
    registered_finalized_block_hash: str,
    registered_finalized_epoch: int,
    terminal_finalized_height: int,
    terminal_finalized_block_hash: str,
    terminal_finalized_epoch: int,
    policy: WeightDecisionPolicy,
) -> bool:
    if registered_finalized_height < terminal_finalized_height:
        return True
    if registered_finalized_height - terminal_finalized_height > policy.max_registered_height_gap:
        return True
    if registered_finalized_height == terminal_finalized_height:
        return (
            registered_finalized_block_hash != terminal_finalized_block_hash
            or registered_finalized_epoch != terminal_finalized_epoch
        )
    return registered_finalized_epoch < terminal_finalized_epoch


def _baseline_status(
    prior: AssignedBaseline | None, *, window_end_epoch: int, policy: WeightDecisionPolicy
) -> BaselineStatus:
    if prior is None:
        return "absent"
    if window_end_epoch - prior.established_at_epoch > policy.assigned_baseline_max_age_seconds:
        return "expired"
    return "applied"


def _identity_digest(identities: set[tuple[int, str]]) -> str:
    return digest([[uid, hotkey] for uid, hotkey in sorted(identities)])


#: Positive weights are exact rational shares rendered as floats; their sum
#: may differ from one only by float rounding, never by a forged row.
_NORMALIZATION_TOLERANCE: Final = Fraction(1, 10**9)


def _mass_drop(
    terminal_assigned_miner_count: int, max_assigned_miner_count: int, policy: WeightDecisionPolicy
) -> bool:
    return terminal_assigned_miner_count * PERMILLE < max_assigned_miner_count * (
        PERMILLE - policy.max_assigned_drop_permille
    )


class ValidatorWeightDecision(StrictFrozenModel):
    """Sealed, archivable outcome of one scoring window: abstain or submit.

    Parsing re-derives every abstain reason and every row classification from
    the sealed fields; a record is accepted only when the ``decision`` it
    states is the one its own fields imply.
    """

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
    abstain_reasons: list[AbstainReason] = Field(max_length=9)
    decision_policy: WeightDecisionPolicy
    scoring_policy: ProbeScoringPolicy
    terminal_manifest_status: ManifestFetchStatus
    terminal_manifest_rejection_code: RejectionCodeText | None
    terminal_evaluated_at_epoch: Epoch
    terminal_manifest_digest_sha256: Digest | None
    terminal_manifest_sequence: PositiveEpoch | None
    terminal_manifest_expires_at_epoch: PositiveEpoch | None
    #: ``min(expires_at_epoch, earliest ticket expiry)`` of the terminal manifest.
    terminal_manifest_effective_expires_at_epoch: PositiveEpoch | None
    #: Earliest ``expires_at_block`` across the terminal manifest's replicas.
    terminal_earliest_lease_expires_at_block: PositiveEpoch | None
    terminal_finalized_height: Epoch | None
    terminal_finalized_block_hash: Digest | None
    terminal_finalized_epoch: Epoch | None
    round_count: int = Field(ge=0, le=MAX_ROUNDS)
    observation_count: int = Field(ge=0)
    serving_observation_count: int = Field(ge=0)
    scoring_window_digest_sha256: Digest | None
    prior_assigned_baseline: AssignedBaseline | None
    prior_assigned_baseline_status: BaselineStatus
    max_assigned_miner_count: int = Field(ge=0, le=MAX_REGISTERED_MINERS)
    terminal_assigned_miner_count: int = Field(ge=0, le=MAX_REGISTERED_MINERS)
    assigned_baseline: AssignedBaseline | None
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
        if self.decision_policy.activation_grace_seconds > (
            self.window_end_epoch - self.window_start_epoch
        ):
            raise ValueError("decision_policy_grace_exceeds_window")
        if self.abstain_reasons != sorted(set(self.abstain_reasons)):
            raise ValueError("abstain_reasons_not_canonical")
        if (self.decision == "abstain") != bool(self.abstain_reasons):
            raise ValueError("decision_reasons_inconsistent")
        verified = self.terminal_manifest_status == "verified"
        terminal_fields = (
            self.terminal_manifest_digest_sha256,
            self.terminal_manifest_sequence,
            self.terminal_manifest_expires_at_epoch,
            self.terminal_manifest_effective_expires_at_epoch,
            self.terminal_earliest_lease_expires_at_block,
            self.terminal_finalized_height,
            self.terminal_finalized_block_hash,
            self.terminal_finalized_epoch,
        )
        if verified != all(value is not None for value in terminal_fields):
            raise ValueError("terminal_manifest_fields_inconsistent")
        if verified != (self.terminal_manifest_rejection_code is None):
            raise ValueError("terminal_rejection_code_inconsistent")
        terminal_sequence = self.terminal_manifest_sequence
        if (
            self.terminal_manifest_effective_expires_at_epoch is not None
            and self.terminal_manifest_expires_at_epoch is not None
            and self.terminal_manifest_effective_expires_at_epoch
            > self.terminal_manifest_expires_at_epoch
        ):
            raise ValueError("terminal_manifest_fields_inconsistent")
        if (
            self.terminal_earliest_lease_expires_at_block is not None
            and self.terminal_finalized_height is not None
            and self.terminal_earliest_lease_expires_at_block <= self.terminal_finalized_height
        ):
            raise ValueError("terminal_manifest_fields_inconsistent")
        if (self.round_count == 0) != (self.scoring_window_digest_sha256 is None):
            raise ValueError("scoring_window_digest_inconsistent")
        if self.serving_observation_count > self.observation_count:
            raise ValueError("observation_counts_invalid")
        if self.round_count > self.observation_count:
            raise ValueError("observation_counts_invalid")
        if self.round_count == 0 and self.observation_count > 0:
            raise ValueError("observation_counts_invalid")
        if self.observation_count == 0 and any(row.opportunities > 0 for row in self.rows):
            raise ValueError("observation_counts_invalid")
        if any(row.opportunities > self.observation_count for row in self.rows):
            raise ValueError("observation_counts_invalid")
        if sum(row.attributions for row in self.rows) > self.serving_observation_count:
            raise ValueError("observation_counts_invalid")
        positive_rows = [row for row in self.rows if row.weight > 0.0]
        if any(row.attributions < self.scoring_policy.min_attributions for row in positive_rows):
            raise ValueError("row_weight_below_min_attributions")
        if positive_rows:
            total = sum((Fraction(row.weight) for row in positive_rows), Fraction(0))
            if abs(total - 1) > _NORMALIZATION_TOLERANCE:
                raise ValueError("weights_not_normalized")
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
        policy = self.decision_policy
        for row in self.rows:
            if row.classification != _derived_classification(
                row, window_end_epoch=self.window_end_epoch, policy=policy
            ):
                raise ValueError("row_classification_not_derived")
        assigned_rows = {(row.uid, row.hotkey) for row in self.rows if row.assigned_at_close}
        # Assigned sets are counted in registered identities only, so the
        # terminal count is exactly the rows assigned at close: a manifest
        # padded with unregistered identities cannot inflate it.
        if self.terminal_assigned_miner_count != len(assigned_rows):
            raise ValueError("assigned_counts_invalid")
        if self.max_assigned_miner_count < self.terminal_assigned_miner_count:
            raise ValueError("assigned_counts_invalid")
        status = _baseline_status(
            self.prior_assigned_baseline, window_end_epoch=self.window_end_epoch, policy=policy
        )
        if status != self.prior_assigned_baseline_status:
            raise ValueError("baseline_status_not_derived")
        prior = self.prior_assigned_baseline
        if prior is not None:
            if prior.established_at_epoch > self.window_start_epoch:
                raise ValueError("baseline_after_window_start")
            if terminal_sequence is not None and prior.manifest_sequence > terminal_sequence:
                raise ValueError("baseline_after_terminal")
            if status == "applied" and self.max_assigned_miner_count < prior.assigned_miner_count:
                raise ValueError("assigned_counts_invalid")
        reasons = self._derived_reasons()
        if sorted(reasons) != self.abstain_reasons:
            raise ValueError("abstain_reasons_not_derived")
        successor = self.assigned_baseline
        if verified and "mass_unassignment_guard" in reasons:
            # A guarded drop never anchors the baseline: the largest set is
            # carried instead, either the applied prior baseline or a manifest
            # observed in this window, never the reduced terminal set.
            if successor is None or successor.assigned_miner_count != (
                self.max_assigned_miner_count
            ):
                raise ValueError("assigned_baseline_not_derived")
            if (
                prior is not None
                and status == "applied"
                and (prior.assigned_miner_count == self.max_assigned_miner_count)
            ):
                if successor != prior:
                    raise ValueError("assigned_baseline_not_derived")
            elif (
                terminal_sequence is None
                or successor.established_at_epoch != self.window_end_epoch
                or successor.manifest_sequence >= terminal_sequence
                or successor.manifest_digest_sha256 == self.terminal_manifest_digest_sha256
            ):
                raise ValueError("assigned_baseline_not_derived")
        elif verified:
            if (
                successor is None
                or successor.established_at_epoch != self.window_end_epoch
                or successor.manifest_sequence != terminal_sequence
                or successor.manifest_digest_sha256 != self.terminal_manifest_digest_sha256
                or successor.assigned_miner_count != self.terminal_assigned_miner_count
                or successor.assigned_identity_digest_sha256 != _identity_digest(assigned_rows)
            ):
                raise ValueError("assigned_baseline_not_derived")
        elif status == "applied":
            if self.assigned_baseline != prior:
                raise ValueError("assigned_baseline_not_derived")
        elif self.assigned_baseline is not None:
            raise ValueError("assigned_baseline_not_derived")
        if self.decision == "submit":
            if self.weight_plan_rows_digest_sha256 != digest(_plan_rows(self.rows)):
                raise ValueError("weight_plan_rows_digest_mismatch")
        elif self.weight_plan_rows_digest_sha256 is not None:
            raise ValueError("abstain_with_plan_rows_digest")
        verify_model_digest(self, "decision_digest_sha256")
        return self

    def _derived_reasons(self) -> set[AbstainReason]:
        policy = self.decision_policy
        reasons: set[AbstainReason] = set()
        if self.terminal_manifest_status == "unavailable":
            reasons.add("manifest_unavailable")
        elif self.terminal_manifest_status == "rejected":
            reasons.add("manifest_invalid")
        else:
            effective = self.terminal_manifest_effective_expires_at_epoch
            lease_block = self.terminal_earliest_lease_expires_at_block
            terminal_height = self.terminal_finalized_height
            terminal_hash = self.terminal_finalized_block_hash
            terminal_epoch = self.terminal_finalized_epoch
            if (
                effective is None
                or lease_block is None
                or terminal_height is None
                or terminal_hash is None
                or terminal_epoch is None
            ):
                raise ValueError("terminal_manifest_fields_inconsistent")
            if effective <= self.terminal_evaluated_at_epoch:
                reasons.add("manifest_expired_at_close")
            if lease_block <= self.registered_finalized_height:
                reasons.add("assignment_lease_expired_at_close")
            if _registered_set_unbound(
                registered_finalized_height=self.registered_finalized_height,
                registered_finalized_block_hash=self.registered_finalized_block_hash,
                registered_finalized_epoch=self.registered_finalized_epoch,
                terminal_finalized_height=terminal_height,
                terminal_finalized_block_hash=terminal_hash,
                terminal_finalized_epoch=terminal_epoch,
                policy=policy,
            ):
                reasons.add("registered_set_unbound")
            if _mass_drop(
                self.terminal_assigned_miner_count, self.max_assigned_miner_count, policy
            ):
                reasons.add("mass_unassignment_guard")
        if self.round_count < policy.min_verified_rounds:
            reasons.add("rounds_insufficient")
        if _coverage_insufficient(self.rows, window_end_epoch=self.window_end_epoch, policy=policy):
            reasons.add("coverage_insufficient")
        if not any(row.weight > 0.0 for row in self.rows):
            reasons.add("no_positive_evidence")
        return reasons


def _plan_rows(rows: Sequence[WeightDecisionRow]) -> list[dict[str, object]]:
    return [{"miner_hotkey": item.hotkey, "weight": item.weight} for item in rows]


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
    """The exact ``build_weight_plan`` rows a submit decision commits to.

    Refuses an abstain record: there is structurally no digest to honour. The
    record is re-validated first, which re-derives every precondition; a
    forged or defective ``submit`` never reaches this point.
    """

    _, row_values = _validated_weight_submission(decision)
    return [{"miner_hotkey": hotkey, "weight": weight} for hotkey, weight in row_values]


def _validate_epoch(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= MAX_EPOCH:
        _reject("decision_epoch_invalid")
    return value


def _assigned_identities(
    manifest: ActiveAssignmentManifest, registered_keys: frozenset[tuple[int, str]]
) -> set[tuple[int, str]]:
    """The registered identities a manifest assigns.

    Unregistered identities are not counted: the mass-unassignment guard
    measures registered-miner cardinality, so a manifest that drops registered
    miners and pads itself with identities outside the metagraph is still a
    drop.
    """

    return {
        (replica.miner_uid, replica.miner_hotkey)
        for item in manifest.deployments
        for replica in item.replicas
        if (replica.miner_uid, replica.miner_hotkey) in registered_keys
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


def _revalidate_rounds(rounds: Sequence[ProbeRound]) -> list[ProbeRound]:
    """Rebuild every round from its canonical document so later mutation cannot leak in.

    Frozen models still hold mutable lists; a report whose ``observations``
    were appended to after verification would otherwise be consumed with its
    stale digest and declared counts. Re-validation re-runs every digest and
    count check, so a tampered round is refused here.
    """

    fresh: list[ProbeRound] = []
    for entry in rounds:
        try:
            fresh.append(
                ProbeRound(
                    manifest=revalidate(entry.manifest, ActiveAssignmentManifest),
                    report=revalidate(entry.report, ValidatorProbeReport),
                )
            )
        except (ValidationError, ValueError, TypeError, AttributeError):
            _reject("decision_round_invalid")
    return fresh


def _revalidate_archived_manifests(
    manifests: Sequence[ActiveAssignmentManifest],
) -> list[ActiveAssignmentManifest]:
    fresh: list[ActiveAssignmentManifest] = []
    for manifest in manifests:
        try:
            fresh.append(revalidate(manifest, ActiveAssignmentManifest))
        except (ValidationError, ValueError, TypeError, AttributeError):
            _reject("decision_archived_manifest_invalid")
    return fresh


def _verify_manifest_chain(
    manifests: Sequence[ActiveAssignmentManifest],
    registered: RegisteredMinerSet,
) -> None:
    """Refuse a window whose manifests are not one unbroken chain from one authority.

    Every manifest's ``previous`` link must name the preceding supplied
    manifest. Sequence numbers may make the bounded positive jumps permitted
    by the trust policy when each publication was accepted; a skipped integer
    is not evidence that an intermediate publication existed. The coordinator
    must supply every *actual* digest-linked transition, using an archived
    manifest for one it did not probe. Without this, rounds probed on one chain
    could be combined with a terminal manifest from a fork simply by omitting
    the transition at which the two chains diverge.
    """

    # One authority per window; the trust-policy digest may legitimately
    # change inside a window at a key-rotation boundary, so it is not compared.
    authorities = {manifest.central_authority_fingerprint_sha256 for manifest in manifests}
    if len(authorities) > 1:
        _reject("decision_manifest_authority_mismatch")
    for manifest in manifests:
        if manifest.network != registered.network or manifest.netuid != registered.netuid:
            _reject("decision_manifest_authority_mismatch")
    by_sequence: dict[int, ActiveAssignmentManifest] = {}
    for manifest in manifests:
        known = by_sequence.get(manifest.sequence)
        if known is None:
            by_sequence[manifest.sequence] = manifest
        elif known.manifest_digest_sha256 != manifest.manifest_digest_sha256:
            _reject("decision_manifest_chain_incoherent")
    ordered = [by_sequence[sequence] for sequence in sorted(by_sequence)]
    for previous, current in zip(ordered, ordered[1:], strict=False):
        if current.previous_manifest_digest_sha256 != previous.manifest_digest_sha256:
            if current.sequence - previous.sequence > 1:
                _reject("decision_manifest_chain_gap")
            _reject("decision_manifest_chain_incoherent")
        if (
            current.finalized_height < previous.finalized_height
            or current.finalized_epoch < previous.finalized_epoch
            or current.issued_at_epoch < previous.issued_at_epoch
        ):
            _reject("decision_manifest_chain_incoherent")
        if current.finalized_height == previous.finalized_height and (
            current.finalized_block_hash != previous.finalized_block_hash
            or current.finalized_epoch != previous.finalized_epoch
        ):
            _reject("decision_manifest_chain_incoherent")


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
    prior_assigned_baseline: AssignedBaseline | None = None,
    archived_manifests: Sequence[ActiveAssignmentManifest] = (),
) -> ValidatorWeightDecision:
    """Apply the frozen rules to one closed window and seal the decision record.

    ``rounds`` are the verified ``(manifest, report)`` pairs probed inside the
    window. ``terminal`` is the manifest fetch made at or after window close.
    ``archived_manifests`` are the actual publications the coordinator accepted
    into its chain state between the window's first probed manifest and the
    terminal but did not probe; the whole span must be one unbroken digest
    chain, so every intermediate publication has to be supplied. They
    contribute sightings and assigned-set sizes but no evidence.
    ``endpoint_first_seen_epoch`` lets the coordinator supply earlier sightings
    of an endpoint incarnation from its own accepted-manifest archive; a
    supplied value may only be earlier than the in-window sighting.
    ``prior_assigned_baseline`` is the
    ``assigned_baseline`` sealed by the coordinator's previous decision; a
    coordinator that holds one must supply it, and the record seals both what
    was supplied and how it was applied.
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
        try:
            terminal_manifest = revalidate(terminal.manifest, ActiveAssignmentManifest)
        except (ValidationError, ValueError, TypeError, AttributeError):
            _reject("decision_terminal_status_invalid")
    elif terminal.manifest is not None or not terminal.rejection_code:
        _reject("decision_terminal_status_invalid")
    prior = (
        None
        if prior_assigned_baseline is None
        else revalidate(prior_assigned_baseline, AssignedBaseline)
    )
    if prior is not None and prior.established_at_epoch > window_start_epoch:
        _reject("decision_baseline_invalid")

    rounds = _revalidate_rounds(rounds)
    manifests = [entry.manifest for entry in rounds]
    for entry in rounds:
        if entry.report.evaluation_epoch >= manifest_effective_expires_at_epoch(entry.manifest):
            _reject("decision_round_after_horizon")
    archived = _revalidate_archived_manifests(archived_manifests)
    chain = [*manifests, *archived]
    if terminal_manifest is not None:
        for manifest in manifests:
            if manifest.sequence > terminal_manifest.sequence:
                _reject("decision_round_after_terminal")
        for manifest in archived:
            if manifest.sequence > terminal_manifest.sequence:
                _reject("decision_archived_manifest_invalid")
        chain.append(terminal_manifest)
    _verify_manifest_chain(chain, registered)
    if prior is not None:
        if terminal_manifest is not None and prior.manifest_sequence > terminal_manifest.sequence:
            _reject("decision_baseline_invalid")
        for manifest in chain:
            if manifest.sequence < prior.manifest_sequence or (
                manifest.sequence == prior.manifest_sequence
                and manifest.manifest_digest_sha256 != prior.manifest_digest_sha256
            ):
                _reject("decision_baseline_invalid")

    reasons: set[AbstainReason] = set()
    if terminal.status == "unavailable":
        reasons.add("manifest_unavailable")
    elif terminal.status == "rejected":
        reasons.add("manifest_invalid")

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

    endpoint_first_seen: dict[str, int] = {}
    endpoint_owner: dict[str, tuple[int, str]] = {}
    for manifest in chain:
        _record_sightings(manifest, endpoint_first_seen, endpoint_owner)
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

    registered_keys = frozenset((miner.uid, miner.hotkey) for miner in registered.miners)
    # Window manifests: everything in the chain except the terminal, one per
    # sequence, so the largest assigned set of the window can be named.
    window_manifests: dict[int, ActiveAssignmentManifest] = {}
    for manifest in chain:
        if terminal_manifest is not None and manifest.sequence == terminal_manifest.sequence:
            continue
        window_manifests.setdefault(manifest.sequence, manifest)
    window_sets = {
        sequence: _assigned_identities(manifest, registered_keys)
        for sequence, manifest in window_manifests.items()
    }
    if terminal_manifest is not None:
        assigned = _assigned_identities(terminal_manifest, registered_keys)
    elif window_manifests:
        assigned = window_sets[max(window_manifests)]
    else:
        assigned = set()
    terminal_count = len(assigned)
    baseline_status = _baseline_status(prior, window_end_epoch=window_end_epoch, policy=policy)
    baseline_counts = (
        [prior.assigned_miner_count] if (prior is not None and baseline_status == "applied") else []
    )
    window_counts = [len(identities) for identities in window_sets.values()]
    max_count = max([*window_counts, *baseline_counts, terminal_count])
    terminal_effective_expiry: int | None = None
    terminal_lease_block: int | None = None
    guarded = False
    if terminal_manifest is not None:
        terminal_effective_expiry = manifest_effective_expires_at_epoch(terminal_manifest)
        terminal_lease_block = manifest_earliest_lease_expires_at_block(terminal_manifest)
        if terminal_effective_expiry <= evaluated_at:
            reasons.add("manifest_expired_at_close")
        if terminal_lease_block <= registered.finalized_height:
            reasons.add("assignment_lease_expired_at_close")
        guarded = _mass_drop(terminal_count, max_count, policy)
        if guarded:
            reasons.add("mass_unassignment_guard")
        if _registered_set_unbound(
            registered_finalized_height=registered.finalized_height,
            registered_finalized_block_hash=registered.finalized_block_hash,
            registered_finalized_epoch=registered.finalized_epoch,
            terminal_finalized_height=terminal_manifest.finalized_height,
            terminal_finalized_block_hash=terminal_manifest.finalized_block_hash,
            terminal_finalized_epoch=terminal_manifest.finalized_epoch,
            policy=policy,
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
        assigned_at_close = key in assigned
        first_seen = miner_first_seen.get(key)
        in_grace = first_seen is not None and window_end_epoch - first_seen < (
            policy.activation_grace_seconds
        )
        classification: MinerClassification
        if weight > 0.0:
            classification = "verified_serving"
            positive = True
        elif not assigned_at_close:
            classification = "unassigned"
        elif in_grace:
            classification = "assigned_in_grace"
        elif expected < policy.min_expected_attributions:
            classification = "assigned_undersampled"
        else:
            classification = "assigned_unverified"
        if classification == "unassigned":
            first_seen = None
        if assigned_at_close and not in_grace and expected < policy.min_expected_attributions:
            reasons.add("coverage_insufficient")
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
                replica_share_counts=([] if tally is None else list(tally.replica_share_counts)),
                first_seen_epoch=first_seen,
                assigned_at_close=assigned_at_close,
            )
        )
    if not positive:
        reasons.add("no_positive_evidence")

    successor_baseline: dict[str, object] | None
    if terminal_manifest is not None and guarded:
        # The guard fired: the reduced terminal set must not become the next
        # window's baseline. Carry the largest set instead: the applied prior
        # baseline when it is (still) the largest, otherwise the largest
        # manifest observed in this window, latest sequence on a tie.
        if (
            prior is not None
            and baseline_status == "applied"
            and (prior.assigned_miner_count == max_count)
        ):
            successor_baseline = model_document(prior)
        else:
            largest_sequence = max(
                window_sets, key=lambda sequence: (len(window_sets[sequence]), sequence)
            )
            largest = window_manifests[largest_sequence]
            successor_baseline = {
                "established_at_epoch": window_end_epoch,
                "manifest_sequence": largest.sequence,
                "manifest_digest_sha256": largest.manifest_digest_sha256,
                "assigned_miner_count": len(window_sets[largest_sequence]),
                "assigned_identity_digest_sha256": _identity_digest(window_sets[largest_sequence]),
            }
    elif terminal_manifest is not None:
        successor_baseline = {
            "established_at_epoch": window_end_epoch,
            "manifest_sequence": terminal_manifest.sequence,
            "manifest_digest_sha256": terminal_manifest.manifest_digest_sha256,
            "assigned_miner_count": terminal_count,
            "assigned_identity_digest_sha256": _identity_digest(assigned),
        }
    elif prior is not None and baseline_status == "applied":
        successor_baseline = model_document(prior)
    else:
        successor_baseline = None

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
        "terminal_manifest_effective_expires_at_epoch": terminal_effective_expiry,
        "terminal_earliest_lease_expires_at_block": terminal_lease_block,
        "terminal_finalized_height": (
            None if terminal_manifest is None else terminal_manifest.finalized_height
        ),
        "terminal_finalized_block_hash": (
            None if terminal_manifest is None else terminal_manifest.finalized_block_hash
        ),
        "terminal_finalized_epoch": (
            None if terminal_manifest is None else terminal_manifest.finalized_epoch
        ),
        "round_count": len(rounds),
        "observation_count": 0 if window is None else window.observation_count,
        "serving_observation_count": 0 if window is None else window.serving_observation_count,
        "scoring_window_digest_sha256": None if window is None else digest(model_document(window)),
        "prior_assigned_baseline": None if prior is None else model_document(prior),
        "prior_assigned_baseline_status": baseline_status,
        "max_assigned_miner_count": max_count,
        "terminal_assigned_miner_count": terminal_count,
        "assigned_baseline": successor_baseline,
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
