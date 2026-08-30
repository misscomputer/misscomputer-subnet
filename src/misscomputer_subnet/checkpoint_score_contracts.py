# SPDX-License-Identifier: AGPL-3.0-only
"""Credential-free canonical score report protocol boundary.

This module intentionally exposes only the signed report shape consumed by
third-party checkpoint verification. Central scoring policy and implementation
remain outside the public package.
"""

from __future__ import annotations

import hashlib
import json
from typing import Annotated, Final, Literal, Self, cast

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

FIXED_POINT_SCALE: Final = 1_000_000
Digest = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
Hotkey = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9]{1,128}$")]
CanonicalTimestamp = Annotated[
    str,
    StringConstraints(
        pattern=(
            r"^[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])"
            r"T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]"
            r"(?:\.[0-9]{1,9})?Z$"
        )
    ),
]
UID = Annotated[int, Field(ge=0, le=(1 << 16) - 1)]
BoundedCount = Annotated[int, Field(ge=0, le=1_000_000)]
BoundedHeight = Annotated[int, Field(ge=0, le=(1 << 63) - 1)]
EligibilityStatus = Literal["eligible", "ineligible"]
ReasonCode = Literal[
    "authority_mismatch",
    "campaign_binding_mismatch",
    "chain_binding_mismatch",
    "correlated_artifact_reuse",
    "correlated_challenge_reuse",
    "correlated_route_reuse",
    "correlated_workload_reuse",
    "eligible",
    "equivocation_detected",
    "future_evidence",
    "insufficient_epoch_deployments",
    "insufficient_independent_deployments",
    "insufficient_scored_observations",
    "insufficient_targeted_assignments",
    "late_completion",
    "miner_identity_churn",
    "missing_observation",
    "noncanonical_target_assignment",
    "noncompleted_disposition",
    "policy_binding_mismatch",
    "repeated_triad_concentration",
    "replay_detected",
    "selective_omission",
    "self_selection_detected",
    "stale_evidence",
    "unexpected_evidence",
    "window_binding_mismatch",
]


class ScoreContractError(ValueError):
    pass


class _StrictFrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
        ).encode("ascii")
    except (TypeError, ValueError, RecursionError) as exc:
        raise ScoreContractError("canonical_json_failed") from exc


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _content(model: BaseModel, field: str) -> dict[str, object]:
    return cast(dict[str, object], model.model_dump(mode="json", exclude={field}, by_alias=True))


def _verify_digest(model: BaseModel, field: str) -> None:
    if cast(str, getattr(model, field)) != _digest(_content(model, field)):
        raise ValueError(f"{field} does not match canonical content")


class ScoreComponentTotals(_StrictFrozenModel):
    expected_assignment_count: BoundedCount
    matched_evidence_count: BoundedCount
    scored_observation_count: BoundedCount
    success_count: BoundedCount
    target_failure_count: BoundedCount
    replica_success_count: BoundedCount
    replica_failure_count: BoundedCount
    missing_observation_count: BoundedCount
    late_completion_count: BoundedCount
    distinct_deployment_count: BoundedCount
    distinct_replica_triad_count: BoundedCount
    maximum_triad_concentration_ppm: int = Field(ge=0, le=FIXED_POINT_SCALE)
    success_component_total_ppm: int = Field(ge=0, le=1_000_000_000_000)
    latency_component_total_ppm: int = Field(ge=0, le=1_000_000_000_000)
    throughput_component_total_ppm: int = Field(ge=0, le=1_000_000_000_000)
    reliability_component_total_ppm: int = Field(ge=0, le=1_000_000_000_000)
    failure_penalty_total_ppm: int = Field(ge=0, le=1_000_000_000_000)
    weighted_component_total_ppm: int = Field(ge=0, le=1_000_000_000_000)


class MinerScoreRecord(_StrictFrozenModel):
    contract_schema: Literal["miss.computer/misscomputer-subnet/synthetic-miner-score-record"] = (
        Field(alias="schema")
    )
    schema_version: Literal[1]
    miner_uid: UID
    miner_hotkey: Hotkey
    eligibility_status: EligibilityStatus
    reason_codes: list[ReasonCode] = Field(min_length=1, max_length=32)
    evidence_content_digest_sha256: Digest
    component_totals: ScoreComponentTotals
    success_component_ppm: int = Field(ge=0, le=FIXED_POINT_SCALE)
    latency_component_ppm: int = Field(ge=0, le=FIXED_POINT_SCALE)
    throughput_component_ppm: int = Field(ge=0, le=FIXED_POINT_SCALE)
    reliability_component_ppm: int = Field(ge=0, le=FIXED_POINT_SCALE)
    failure_penalty_ppm: int = Field(ge=0, le=FIXED_POINT_SCALE)
    raw_score_ppm: int = Field(ge=0, le=FIXED_POINT_SCALE)
    canonical_score_ppm: int = Field(ge=0, le=FIXED_POINT_SCALE)
    record_digest_sha256: Digest

    @model_validator(mode="after")
    def valid_record(self) -> Self:
        if self.reason_codes != sorted(set(self.reason_codes)):
            raise ValueError("score reason codes must be unique and sorted")
        if self.eligibility_status == "eligible":
            if self.reason_codes != ["eligible"] or self.canonical_score_ppm != self.raw_score_ppm:
                raise ValueError("eligible score record is invalid")
        elif "eligible" in self.reason_codes or self.canonical_score_ppm != 0:
            raise ValueError("ineligible score record must fail closed")
        _verify_digest(self, "record_digest_sha256")
        return self


class CanonicalScoreReport(_StrictFrozenModel):
    contract_schema: Literal[
        "miss.computer/misscomputer-subnet/canonical-synthetic-score-report"
    ] = Field(alias="schema")
    schema_version: Literal[1]
    policy_digest_sha256: Digest
    input_snapshot_digest_sha256: Digest
    central_authority_fingerprint_sha256: Digest
    network: Literal["finney"]
    netuid: Literal[24]
    finalized_height: BoundedHeight
    finalized_block_hash: Digest
    window_started_at: CanonicalTimestamp
    window_ended_at: CanonicalTimestamp
    eligible_miner_count: BoundedCount
    ineligible_miner_count: BoundedCount
    global_reason_codes: list[ReasonCode] = Field(max_length=32)
    miner_scores: list[MinerScoreRecord] = Field(max_length=4_096)
    score_vector_digest_sha256: Digest
    report_digest_sha256: Digest

    @model_validator(mode="after")
    def valid_report(self) -> Self:
        keys = [(item.miner_uid, item.miner_hotkey) for item in self.miner_scores]
        if keys != sorted(set(keys)):
            raise ValueError("canonical score vector must be unique and sorted")
        eligible = sum(item.eligibility_status == "eligible" for item in self.miner_scores)
        if (
            eligible != self.eligible_miner_count
            or len(self.miner_scores) - eligible != self.ineligible_miner_count
        ):
            raise ValueError("miner counts do not match score vector")
        if self.global_reason_codes != sorted(set(self.global_reason_codes)):
            raise ValueError("global reason codes must be unique and sorted")
        vector = [item.model_dump(mode="json", by_alias=True) for item in self.miner_scores]
        if self.score_vector_digest_sha256 != _digest(vector):
            raise ValueError("score vector digest does not match")
        _verify_digest(self, "report_digest_sha256")
        return self


def canonical_score_report_bytes(report: CanonicalScoreReport) -> bytes:
    value = CanonicalScoreReport.model_validate(report.model_dump(mode="json", by_alias=True))
    return _canonical_json(value.model_dump(mode="json", by_alias=True)) + b"\n"


def _reject_constant(value: str) -> None:
    raise ScoreContractError(f"nonstandard_json_constant:{value}")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ScoreContractError("duplicate_json_key")
        result[key] = value
    return result


def parse_canonical_score_report(rendered: bytes) -> CanonicalScoreReport:
    if not rendered or len(rendered) > 32 * 1_024 * 1_024:
        raise ScoreContractError("document_size_invalid")
    try:
        document = json.loads(
            rendered.decode("ascii"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
        report = CanonicalScoreReport.model_validate(document)
    except ScoreContractError:
        raise
    except (UnicodeDecodeError, ValueError, TypeError, RecursionError) as exc:
        raise ScoreContractError("document_invalid") from exc
    if rendered != canonical_score_report_bytes(report):
        raise ScoreContractError("document_not_canonical")
    return report
