# SPDX-License-Identifier: AGPL-3.0-only
"""Organic central score report: the only score input to signed checkpoints.

The synthetic campaign score report is removed (contract §13). The central
validator scores organic availability exactly like every other validator
(:mod:`misscomputer_subnet.organic_scoring`); this module seals that result,
together with the finalized chain view and the scoring policy, into the
``organic-central-score-report`` v1 document a
``central-score-checkpoint`` binds and external validators relay.

Every miner row is re-derived from the embedded
``organic-availability-score`` on parse:

- ``canonical_score_ppm`` is ``floor(availability * 1_000_000)``;
- a miner whose window carries cryptographically attributable attestation
  fraud is ``ineligible`` with score 0 (contract §11.3 trust-zero); every
  other scored miner is ``eligible``;
- unscored miners are absent, never zero rows.

Serving volume, request counts and customer identity cannot reach this
document. This module is pure: no clock, network, file, process,
environment, wallet, chain, randomness, or signing capability.
"""

from __future__ import annotations

from fractions import Fraction
from typing import Annotated, Final, Literal, Self

from pydantic import Field, model_validator

from .contract_codec import (
    StrictFrozenModel,
    digest,
    model_bytes,
    model_document,
    parse_model,
    revalidate,
    verify_model_digest,
)
from .organic_scoring import SCORING_PURPOSE, OrganicAvailabilityScore

REPORT_SCHEMA: Final = "miss.computer/misscomputer-subnet/organic-central-score-report"
FIXED_POINT_SCALE: Final = 1_000_000
MAX_REPORT_BYTES: Final = 64 * 1_024 * 1_024

Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
Hotkey = Annotated[str, Field(pattern=r"^[A-Za-z0-9]{1,128}$")]
UID = Annotated[int, Field(ge=0, le=(1 << 16) - 1)]
BoundedHeight = Annotated[int, Field(ge=0, le=(1 << 63) - 1)]
EligibilityStatus = Literal["eligible", "ineligible"]
ReasonCode = Literal["attestation_fraud", "eligible"]


class ScoreContractError(ValueError):
    pass


class OrganicScoringPolicy(StrictFrozenModel):
    """The central scoring parameters a checkpoint trust policy pins by digest."""

    purpose: Literal["organic_availability_scoring_v1"]
    epoch_seconds: int = Field(ge=60, le=3_600)
    probes_per_endpoint: int = Field(ge=1, le=16)
    min_attempts: int = Field(ge=1, le=16)
    fraud_disposition: Literal["ineligible"]


class MinerScoreRecord(StrictFrozenModel):
    miner_uid: UID
    miner_hotkey: Hotkey
    eligibility_status: EligibilityStatus
    reason_codes: list[ReasonCode] = Field(min_length=1, max_length=2)
    eligible_endpoint_epochs: int = Field(ge=1)
    availability_numerator: int = Field(ge=0)
    availability_denominator: int = Field(ge=1)
    fraudulent_attestations: int = Field(ge=0)
    canonical_score_ppm: int = Field(ge=0, le=FIXED_POINT_SCALE)
    record_digest_sha256: Digest

    @model_validator(mode="after")
    def valid_record(self) -> Self:
        verify_model_digest(self, "record_digest_sha256")
        return self


class CanonicalScoreReport(StrictFrozenModel):
    """``organic-central-score-report`` v1: the central validator's sealed availability."""

    contract_schema: Literal["miss.computer/misscomputer-subnet/organic-central-score-report"] = (
        Field(alias="schema")
    )
    schema_version: Literal[1]
    policy_digest_sha256: Digest
    scoring_policy: OrganicScoringPolicy
    input_snapshot_digest_sha256: Digest
    central_authority_fingerprint_sha256: Digest
    network: Literal["finney"]
    netuid: Literal[24]
    finalized_height: BoundedHeight
    finalized_block_hash: Digest
    availability_score: OrganicAvailabilityScore
    eligible_miner_count: int = Field(ge=0, le=4_096)
    ineligible_miner_count: int = Field(ge=0, le=4_096)
    miner_scores: list[MinerScoreRecord] = Field(max_length=4_096)
    score_vector_digest_sha256: Digest
    report_digest_sha256: Digest

    @model_validator(mode="after")
    def valid_report(self) -> Self:
        if self.policy_digest_sha256 != digest(model_document(self.scoring_policy)):
            raise ValueError("score report policy digest does not match")
        if self.availability_score.epoch_seconds != self.scoring_policy.epoch_seconds:
            raise ValueError("score report epoch length does not match its policy")
        if self.input_snapshot_digest_sha256 != self.availability_score.score_digest_sha256:
            raise ValueError("score report input snapshot does not match its availability")
        expected = derive_miner_scores(self.availability_score)
        if [model_document(item) for item in self.miner_scores] != expected:
            raise ValueError("score report rows do not follow from its availability")
        eligible = sum(item.eligibility_status == "eligible" for item in self.miner_scores)
        if (
            eligible != self.eligible_miner_count
            or len(self.miner_scores) - eligible != self.ineligible_miner_count
        ):
            raise ValueError("miner counts do not match score vector")
        if self.score_vector_digest_sha256 != digest(expected):
            raise ValueError("score vector digest does not match")
        verify_model_digest(self, "report_digest_sha256")
        return self


def derive_miner_scores(score: OrganicAvailabilityScore) -> list[dict[str, object]]:
    """The exact canonical rows for one availability window."""

    rows: list[dict[str, object]] = []
    for item in score.miners:
        fraud = item.fraudulent_attestations > 0
        availability = Fraction(item.availability_numerator, item.availability_denominator)
        document: dict[str, object] = {
            "miner_uid": item.miner_uid,
            "miner_hotkey": item.miner_hotkey,
            "eligibility_status": "ineligible" if fraud else "eligible",
            "reason_codes": ["attestation_fraud"] if fraud else ["eligible"],
            "eligible_endpoint_epochs": item.eligible_endpoint_epochs,
            "availability_numerator": item.availability_numerator,
            "availability_denominator": item.availability_denominator,
            "fraudulent_attestations": item.fraudulent_attestations,
            "canonical_score_ppm": 0 if fraud else int(availability * FIXED_POINT_SCALE),
        }
        rows.append({**document, "record_digest_sha256": digest(document)})
    return rows


def build_scoring_policy(
    *, epoch_seconds: int, probes_per_endpoint: int, min_attempts: int
) -> OrganicScoringPolicy:
    return OrganicScoringPolicy(
        purpose=SCORING_PURPOSE,
        epoch_seconds=epoch_seconds,
        probes_per_endpoint=probes_per_endpoint,
        min_attempts=min_attempts,
        fraud_disposition="ineligible",
    )


def build_canonical_score_report(
    score: OrganicAvailabilityScore,
    policy: OrganicScoringPolicy,
    *,
    central_authority_fingerprint_sha256: str,
    finalized_height: int,
    finalized_block_hash: str,
) -> CanonicalScoreReport:
    """Seal the central validator's availability window with its chain view."""

    value = revalidate(score, OrganicAvailabilityScore)
    scoring = revalidate(policy, OrganicScoringPolicy)
    rows = derive_miner_scores(value)
    eligible = sum(row["eligibility_status"] == "eligible" for row in rows)
    unsigned: dict[str, object] = {
        "schema": REPORT_SCHEMA,
        "schema_version": 1,
        "policy_digest_sha256": digest(model_document(scoring)),
        "scoring_policy": model_document(scoring),
        "input_snapshot_digest_sha256": value.score_digest_sha256,
        "central_authority_fingerprint_sha256": central_authority_fingerprint_sha256,
        "network": value.network,
        "netuid": value.netuid,
        "finalized_height": finalized_height,
        "finalized_block_hash": finalized_block_hash,
        "availability_score": model_document(value),
        "eligible_miner_count": eligible,
        "ineligible_miner_count": len(rows) - eligible,
        "miner_scores": rows,
        "score_vector_digest_sha256": digest(rows),
    }
    return CanonicalScoreReport.model_validate(
        {**unsigned, "report_digest_sha256": digest(unsigned)}
    )


def canonical_score_report_bytes(report: CanonicalScoreReport) -> bytes:
    return model_bytes(report, CanonicalScoreReport)


def parse_canonical_score_report(rendered: bytes) -> CanonicalScoreReport:
    try:
        return parse_model(
            rendered,
            CanonicalScoreReport,
            canonical_score_report_bytes,
            maximum_bytes=MAX_REPORT_BYTES,
        )
    except ValueError as exc:
        raise ScoreContractError(str(exc)) from exc
