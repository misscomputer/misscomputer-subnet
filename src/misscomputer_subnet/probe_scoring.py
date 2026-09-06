# SPDX-License-Identifier: AGPL-3.0-only

"""Turn verified active-assignment probe reports into a per-miner weight vector.

``assignment_probe`` proves that a published route serves the exact hidden
challenge right now and, through the mandatory miner attestation, names the
replica that answered. It stops there: a ``validator-probe-report`` is, by its
own contract, "not a score, not a weight, and not an authorization to submit
anything".

This module is the missing bridge. It accumulates many verified reports across
a scoring window and derives one weight vector in which every registered miner
starts at zero and only proven, attested, correctly-serving replicas rise above
it. The result is handed to :func:`misscomputer_subnet.weight_plan.build_weight_plan`,
the existing submission path; no new path to the chain is introduced here.

Why a window and not a single report
------------------------------------
The public probe issues one untargeted request per deployment, and the central
edge round-robins it across that deployment's healthy replicas. One request
therefore attributes exactly one replica, as the probe design document states
under "Known limitations". Scoring a three-replica deployment from a single
report would score one miner and silently zero its two healthy peers. Only
repeated probing across the window covers the replica set, so the accumulator
consumes many rounds and compares what it actually observed against what fair
round-robin predicts.

Independence
------------
Every input is either the validator's own probe output or the finalized
metagraph. No other validator's data participates, so two honest validators
that observed the same serving behaviour converge without coordinating, and the
chain reconciles the rest under ordinary Yuma consensus.

Determinism
-----------
All accumulation is exact rational arithmetic. Floating point appears only at
the boundary where a row is handed to the weight plan, so the score does not
depend on the order in which reports were accumulated.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from fractions import Fraction
from typing import Annotated, Final, Literal, NoReturn, Self

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from .assignment_probe import (
    ActiveAssignmentManifest,
    ActiveDeploymentAssignment,
    ValidatorProbeReport,
)

SCORING_PURPOSE: Final = "public_validator_probe_scoring_v1"
SCORING_SCHEMA_VERSION: Final = 1

MAX_ROUNDS: Final = 4_096
MAX_REGISTERED_MINERS: Final = 4_096
MAX_LATENCY_MILLIS: Final = 3_600_000

Hotkey = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9]{1,128}$")]
UID = Annotated[int, Field(ge=0, le=(1 << 16) - 1)]
Epoch = Annotated[int, Field(ge=0, le=(1 << 63) - 1)]

ScoringRejectionCode = Literal[
    "scoring_identity_conflict",
    "scoring_manifest_mismatch",
    "scoring_registered_duplicate",
    "scoring_report_duplicate",
    "scoring_report_identity_mismatch",
    "scoring_report_outside_window",
    "scoring_rounds_empty",
    "scoring_unpublished_attribution",
    "scoring_window_invalid",
]


class ProbeScoringError(ValueError):
    """A scoring window that cannot be trusted to produce a weight vector."""


def _reject(code: ScoringRejectionCode) -> NoReturn:
    raise ProbeScoringError(code)


class _StrictFrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True, populate_by_name=True)


class ProbeScoringPolicy(_StrictFrozenModel):
    """Validator-local scoring parameters.

    These are policy, not consensus: a validator may tune them without breaking
    anything, because each validator scores independently.
    """

    #: Latency at or below which a miner keeps its full quality factor. Above
    #: it the factor decays as ``target / observed``, matching the latency
    #: shape the Go control plane already uses for benchmark observations.
    latency_target_millis: int = Field(default=1_000, ge=1, le=MAX_LATENCY_MILLIS)
    #: Minimum verified attributions before a miner earns any weight. The
    #: default of 1 honours the rule that any proven, attested, correctly
    #: serving replica scores above zero.
    min_attributions: int = Field(default=1, ge=1, le=MAX_ROUNDS)
    #: When true, a miner published as a replica that fails to answer its share
    #: of probes is penalised in proportion to the share it missed. Disabling
    #: this scores pure observed volume and ignores reliability.
    apply_coverage_penalty: bool = True


class RegisteredMiner(_StrictFrozenModel):
    """One metagraph identity eligible to receive weight.

    Callers derive these from the finalized snapshot. The validator's own
    hotkey and inactive neurons must be excluded:
    :func:`~misscomputer_subnet.weight_plan.build_weight_plan` rejects a row
    naming either, and it does so before it looks at the weight, so a zero row
    is not a safe way to mention them.
    """

    uid: UID
    hotkey: Hotkey


@dataclass(frozen=True, slots=True)
class ProbeRound:
    """One verified manifest and the report produced by probing it."""

    manifest: ActiveAssignmentManifest
    report: ValidatorProbeReport


class MinerProbeTally(_StrictFrozenModel):
    """What one scoring window observed about one miner identity."""

    uid: UID
    hotkey: Hotkey
    #: Observations in which this miner was a published replica of the probed
    #: deployment, and so could have answered.
    opportunities: int = Field(ge=0)
    #: Observations whose verified attestation names this miner and whose
    #: outcome is ``serving``.
    attributions: int = Field(ge=0)
    #: Attributions predicted by fair round-robin over the replica sets this
    #: miner appeared in, as an exact rational ``numerator/denominator``.
    expected_attributions_numerator: int = Field(ge=0)
    expected_attributions_denominator: int = Field(ge=1)
    total_latency_millis: int = Field(ge=0)

    @property
    def expected_attributions(self) -> Fraction:
        return Fraction(
            self.expected_attributions_numerator, self.expected_attributions_denominator
        )

    @property
    def mean_latency_millis(self) -> Fraction | None:
        if self.attributions == 0:
            return None
        return Fraction(self.total_latency_millis, self.attributions)

    def coverage(self) -> Fraction:
        """Observed share of the attributions fair round-robin predicted.

        Capped at one: being selected more often than predicted is edge
        scheduling noise, never extra credit.
        """

        expected = self.expected_attributions
        if expected <= 0:
            return Fraction(0)
        observed = Fraction(self.attributions) / expected
        return min(observed, Fraction(1))

    def latency_factor(self, policy: ProbeScoringPolicy) -> Fraction:
        mean = self.mean_latency_millis
        if mean is None:
            return Fraction(0)
        target = Fraction(policy.latency_target_millis)
        if mean <= target:
            return Fraction(1)
        return target / mean

    def score(self, policy: ProbeScoringPolicy) -> Fraction:
        """Exact unnormalized score for this miner.

        Volume of proven serving is the primary term: a miner cannot be
        attributed without a valid Ed25519 attestation over the exact published
        challenge digest, so attributions cannot be inflated. Latency scales
        quality, and coverage penalises a miner that stayed published but
        stopped answering.
        """

        if self.attributions < policy.min_attributions:
            return Fraction(0)
        value = Fraction(self.attributions) * self.latency_factor(policy)
        if policy.apply_coverage_penalty:
            value *= self.coverage()
        return value


class ProbeScoringWindow(_StrictFrozenModel):
    """Everything one validator observed across a bounded scoring window."""

    purpose: Literal["public_validator_probe_scoring_v1"] = SCORING_PURPOSE
    schema_version: Literal[1] = SCORING_SCHEMA_VERSION
    validator_uid: UID
    validator_hotkey: Hotkey
    window_start_epoch: Epoch
    window_end_epoch: Epoch
    round_count: int = Field(ge=1, le=MAX_ROUNDS)
    observation_count: int = Field(ge=0)
    serving_observation_count: int = Field(ge=0)
    report_digests: tuple[str, ...]
    tallies: tuple[MinerProbeTally, ...]

    @model_validator(mode="after")
    def canonical_window(self) -> Self:
        if self.window_end_epoch <= self.window_start_epoch:
            _reject("scoring_window_invalid")
        if self.serving_observation_count > self.observation_count:
            _reject("scoring_window_invalid")
        keys = [(item.uid, item.hotkey) for item in self.tallies]
        if keys != sorted(keys):
            _reject("scoring_window_invalid")
        if len({uid for uid, _ in keys}) != len(keys) or len({key for _, key in keys}) != len(keys):
            _reject("scoring_identity_conflict")
        if len(set(self.report_digests)) != len(self.report_digests):
            _reject("scoring_report_duplicate")
        return self

    def tally_for(self, hotkey: str) -> MinerProbeTally | None:
        for item in self.tallies:
            if item.hotkey == hotkey:
                return item
        return None


class ProbeWeightRow(_StrictFrozenModel):
    """One registered miner's derived weight and the evidence behind it."""

    uid: UID
    hotkey: Hotkey
    weight: float = Field(ge=0.0, le=1.0)
    attributions: int = Field(ge=0)
    opportunities: int = Field(ge=0)

    def weight_plan_row(self) -> dict[str, object]:
        """The exact row shape ``build_weight_plan`` consumes."""

        return {"miner_hotkey": self.hotkey, "weight": self.weight}


class ProbeWeightVector(_StrictFrozenModel):
    """A complete weight vector over the registered miner set.

    Every registered miner appears exactly once. Miners that never served a
    verified, attested probe carry weight ``0.0``.
    """

    purpose: Literal["public_validator_probe_scoring_v1"] = SCORING_PURPOSE
    schema_version: Literal[1] = SCORING_SCHEMA_VERSION
    validator_uid: UID
    validator_hotkey: Hotkey
    window_start_epoch: Epoch
    window_end_epoch: Epoch
    rows: tuple[ProbeWeightRow, ...]

    @model_validator(mode="after")
    def canonical_vector(self) -> Self:
        keys = [(item.uid, item.hotkey) for item in self.rows]
        if keys != sorted(keys):
            _reject("scoring_registered_duplicate")
        if len({uid for uid, _ in keys}) != len(keys) or len({key for _, key in keys}) != len(keys):
            _reject("scoring_registered_duplicate")
        return self

    @property
    def scored_rows(self) -> tuple[ProbeWeightRow, ...]:
        return tuple(row for row in self.rows if row.weight > 0.0)

    def weight_plan_rows(self) -> list[dict[str, object]]:
        """Rows for ``build_weight_plan``.

        Zero rows are included deliberately: the default is an explicit zero
        for every registered miner, not an omission. ``build_weight_plan``
        drops them when it normalizes, and refuses the plan outright if none is
        positive — which is the correct outcome for a validator that observed
        no proven serving at all.
        """

        return [row.weight_plan_row() for row in self.rows]


def _deployment_index(
    manifest: ActiveAssignmentManifest,
) -> dict[str, ActiveDeploymentAssignment]:
    return {item.deployment_id: item for item in manifest.deployments}


@dataclass
class _MutableTally:
    uid: int
    hotkey: str
    opportunities: int = 0
    attributions: int = 0
    expected: Fraction = Fraction(0)
    total_latency_millis: int = 0


def accumulate_scoring_window(
    rounds: Sequence[ProbeRound],
    *,
    validator_uid: int,
    validator_hotkey: str,
    window_start_epoch: int,
    window_end_epoch: int,
) -> ProbeScoringWindow:
    """Accumulate verified probe rounds into one scoring window.

    Each round must pair a manifest with the report produced by probing exactly
    that manifest. Callers are expected to have verified both already, through
    ``verify_active_assignment_manifest`` and the report's own canonical
    validators; this function re-derives every binding it depends on rather
    than trusting that it was done.
    """

    if not rounds:
        _reject("scoring_rounds_empty")
    if len(rounds) > MAX_ROUNDS:
        _reject("scoring_rounds_empty")
    if window_end_epoch <= window_start_epoch:
        _reject("scoring_window_invalid")

    tallies: dict[tuple[int, str], _MutableTally] = {}
    uid_to_hotkey: dict[int, str] = {}
    hotkey_to_uid: dict[str, int] = {}
    digests: set[str] = set()
    observation_count = 0
    serving_count = 0

    def identify(uid: int, hotkey: str) -> _MutableTally:
        # A UID rebound to a different hotkey inside one window makes every
        # tally for that identity ambiguous, so fail closed rather than
        # silently attributing one miner's work to another.
        if uid_to_hotkey.setdefault(uid, hotkey) != hotkey:
            _reject("scoring_identity_conflict")
        if hotkey_to_uid.setdefault(hotkey, uid) != uid:
            _reject("scoring_identity_conflict")
        return tallies.setdefault((uid, hotkey), _MutableTally(uid=uid, hotkey=hotkey))

    for entry in rounds:
        report = entry.report
        manifest = entry.manifest
        if report.validator_uid != validator_uid or report.validator_hotkey != validator_hotkey:
            _reject("scoring_report_identity_mismatch")
        if not window_start_epoch <= report.evaluation_epoch < window_end_epoch:
            _reject("scoring_report_outside_window")
        if report.manifest_digest_sha256 != manifest.manifest_digest_sha256:
            _reject("scoring_manifest_mismatch")
        # Two genuine probes never produce the same sealed report: the report
        # binds fresh per-request nonces. An exact repeat is a replay, and
        # counting it would let one observation be spent many times.
        if report.report_digest_sha256 in digests:
            _reject("scoring_report_duplicate")
        digests.add(report.report_digest_sha256)

        deployments = _deployment_index(manifest)
        for observation in report.observations:
            deployment = deployments.get(observation.deployment_id)
            if (
                deployment is None
                or deployment.assignment_digest_sha256 != observation.assignment_digest_sha256
            ):
                _reject("scoring_manifest_mismatch")
            observation_count += 1

            # Every published replica could have answered this untargeted
            # request, so each accrues one opportunity and its round-robin
            # share of one expected attribution.
            share = Fraction(1, len(deployment.replicas))
            for replica in deployment.replicas:
                tally = identify(replica.miner_uid, replica.miner_hotkey)
                tally.opportunities += 1
                tally.expected += share

            if observation.outcome != "serving":
                continue
            attestation = observation.attestation
            if attestation is None:
                # Unreachable: a serving observation always carries a verified
                # attestation. Kept because the credit below depends on it.
                _reject("scoring_unpublished_attribution")
            serving_count += 1
            # Credit only an identity the manifest actually published for this
            # deployment, on the exact endpoint the attestation names.
            published = any(
                replica.miner_uid == attestation.miner_uid
                and replica.miner_hotkey == attestation.miner_hotkey
                and replica.endpoint_id == attestation.endpoint_id
                for replica in deployment.replicas
            )
            if not published:
                _reject("scoring_unpublished_attribution")
            credited = identify(attestation.miner_uid, attestation.miner_hotkey)
            credited.attributions += 1
            credited.total_latency_millis += observation.latency_millis

    ordered = sorted(tallies.values(), key=lambda item: (item.uid, item.hotkey))
    return ProbeScoringWindow(
        validator_uid=validator_uid,
        validator_hotkey=validator_hotkey,
        window_start_epoch=window_start_epoch,
        window_end_epoch=window_end_epoch,
        round_count=len(rounds),
        observation_count=observation_count,
        serving_observation_count=serving_count,
        report_digests=tuple(sorted(digests)),
        tallies=tuple(
            MinerProbeTally(
                uid=item.uid,
                hotkey=item.hotkey,
                opportunities=item.opportunities,
                attributions=item.attributions,
                expected_attributions_numerator=item.expected.numerator,
                expected_attributions_denominator=item.expected.denominator,
                total_latency_millis=item.total_latency_millis,
            )
            for item in ordered
        ),
    )


def build_probe_weight_vector(
    window: ProbeScoringWindow,
    *,
    registered: Iterable[RegisteredMiner],
    policy: ProbeScoringPolicy | None = None,
) -> ProbeWeightVector:
    """Derive the normalized weight vector for one scoring window.

    Every registered miner is emitted. A miner that never appeared in a
    manifest, or never produced a verified attested serving observation, is
    emitted at exactly ``0.0``.
    """

    effective = policy if policy is not None else ProbeScoringPolicy()
    entries = list(registered)
    if len(entries) > MAX_REGISTERED_MINERS:
        _reject("scoring_registered_duplicate")
    keys = [(item.uid, item.hotkey) for item in entries]
    if len({uid for uid, _ in keys}) != len(keys) or len({key for _, key in keys}) != len(keys):
        _reject("scoring_registered_duplicate")
    if window.validator_hotkey in {item.hotkey for item in entries}:
        # build_weight_plan rejects any row naming the validator, including a
        # zero row, so it must never enter the registered set.
        _reject("scoring_registered_duplicate")

    by_identity = {(item.uid, item.hotkey): item for item in window.tallies}
    scores: dict[tuple[int, str], Fraction] = {}
    for entry in entries:
        tally = by_identity.get((entry.uid, entry.hotkey))
        scores[(entry.uid, entry.hotkey)] = Fraction(0) if tally is None else tally.score(effective)

    total = sum(scores.values(), Fraction(0))
    rows: list[ProbeWeightRow] = []
    for entry in sorted(entries, key=lambda item: (item.uid, item.hotkey)):
        key = (entry.uid, entry.hotkey)
        tally = by_identity.get(key)
        share = Fraction(0) if total <= 0 else scores[key] / total
        rows.append(
            ProbeWeightRow(
                uid=entry.uid,
                hotkey=entry.hotkey,
                weight=float(share),
                attributions=0 if tally is None else tally.attributions,
                opportunities=0 if tally is None else tally.opportunities,
            )
        )
    return ProbeWeightVector(
        validator_uid=window.validator_uid,
        validator_hotkey=window.validator_hotkey,
        window_start_epoch=window.window_start_epoch,
        window_end_epoch=window.window_end_epoch,
        rows=tuple(rows),
    )


def score_probe_rounds(
    rounds: Sequence[ProbeRound],
    *,
    validator_uid: int,
    validator_hotkey: str,
    window_start_epoch: int,
    window_end_epoch: int,
    registered: Iterable[RegisteredMiner],
    policy: ProbeScoringPolicy | None = None,
) -> ProbeWeightVector:
    """Accumulate and score in one step."""

    window = accumulate_scoring_window(
        rounds,
        validator_uid=validator_uid,
        validator_hotkey=validator_hotkey,
        window_start_epoch=window_start_epoch,
        window_end_epoch=window_end_epoch,
    )
    return build_probe_weight_vector(window, registered=registered, policy=policy)
