# SPDX-License-Identifier: AGPL-3.0-only
"""Separately gated one-shot verification and execution of WeightPlan v1."""

from __future__ import annotations

import argparse
import asyncio
import fcntl
import hashlib
import json
import math
import os
import re
import secrets
import sys
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from typing import Literal, Protocol

from .chain import ChainQuery, MetagraphSnapshot
from .chain_quorum import build_chain_query, json_stderr_alert
from .weight_plan import (
    MAX_BLOCK,
    MAX_VERSION_KEY,
    MAX_WEIGHT_PLAN_BYTES,
    WEIGHT_PLAN_FILE_MODE,
    WEIGHT_PLAN_PROTOCOL_VERSION_KEY,
    WeightPlan,
    WeightPlanError,
    WeightPlanTargetError,
    _canonical_json,
    _pin_directory_chain,
    _prepare_temporary_plan,
    _read_existing,
    _revalidate_pinned_chain,
    _same_target,
    _secure_file_location,
    _target_stat,
    _validate_existing_target,
    _validate_network_identity,
    _validate_temporary_descriptor,
    _validate_temporary_name,
    _verify_configured_target,
    load_weight_plan,
    snapshot_identity_fingerprint,
)

WEIGHT_EXECUTION_VECTOR_SCHEMA = "miss.computer/misscomputer-subnet/weight-execution-vector"
WEIGHT_EXECUTION_VECTOR_SCHEMA_VERSION = 1
WEIGHT_EXECUTION_AUDIT_SCHEMA = "miss.computer/misscomputer-subnet/weight-execution-audit"
WEIGHT_EXECUTION_AUDIT_SCHEMA_VERSION = 1
EXECUTION_ACK_ENV = "MISSCOMPUTER_WEIGHT_EXECUTION_ACK"
EXECUTION_ACK_VALUE = "I_ACKNOWLEDGE_THIS_SUBMITS_VALIDATOR_WEIGHTS"
MAX_AUDIT_ATTEMPTS = 4_096
MAX_SUBMISSION_TIMEOUT_SECONDS = 3_600.0

_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_ERROR_CODE_RE = re.compile(r"^[a-z0-9_]{1,64}$")
_REFERENCE_RE = re.compile(r"^[!-~]{1,256}$")


class WeightExecutionError(RuntimeError):
    """A fail-closed executor rejection with a safe operator-facing code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class AuditStateError(WeightExecutionError):
    """The durable audit state is unsafe, invalid, busy, or unavailable."""


class ExecutionChain(ChainQuery, Protocol):
    """Executor reads, including the exact-block weight submission mode."""

    async def commit_reveal_enabled(self, block: int) -> bool: ...


def _validate_digest(value: object, field_name: str) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise AuditStateError("audit_state_invalid", f"{field_name} is invalid")
    return value


def _validate_public_text(value: object, field_name: str, maximum: int = 256) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or value != value.strip()
        or not value.isascii()
        or any(ord(character) < 0x21 or ord(character) > 0x7E for character in value)
    ):
        raise WeightExecutionError("invalid_identity", f"{field_name} is invalid")
    return value


def _validate_public_network(value: object, field_name: str) -> str:
    try:
        return _validate_network_identity(value, field_name=field_name)
    except WeightPlanError as exc:
        raise WeightExecutionError("invalid_identity", f"{field_name} is invalid") from exc


def _validate_uint(value: object, field_name: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise WeightExecutionError("invalid_integer", f"{field_name} is invalid")
    return value


@dataclass(frozen=True, slots=True)
class ExecutionWeight:
    hotkey: str
    planned_uid: int
    uid: int
    weight: float

    def __post_init__(self) -> None:
        _validate_public_text(self.hotkey, "execution hotkey")
        _validate_uint(self.planned_uid, "planned UID", 65_535)
        _validate_uint(self.uid, "execution UID", 65_535)
        try:
            normalized = float(self.weight)
        except (TypeError, ValueError, OverflowError) as exc:
            raise WeightExecutionError("invalid_weights", "execution weight is invalid") from exc
        if (
            isinstance(self.weight, bool)
            or not isinstance(self.weight, (int, float))
            or not (math.isfinite(normalized) and 0.0 < normalized <= 1.0)
        ):
            raise WeightExecutionError("invalid_weights", "execution weight is invalid")
        object.__setattr__(self, "weight", normalized)

    def document(self) -> dict[str, object]:
        return {
            "hotkey": self.hotkey,
            "planned_uid": self.planned_uid,
            "uid": self.uid,
            "weight": self.weight,
        }


@dataclass(frozen=True, slots=True)
class OmittedWeight:
    hotkey: str
    planned_uid: int

    def __post_init__(self) -> None:
        _validate_public_text(self.hotkey, "omitted hotkey")
        _validate_uint(self.planned_uid, "omitted planned UID", 65_535)

    def document(self) -> dict[str, object]:
        return {"hotkey": self.hotkey, "planned_uid": self.planned_uid}


@dataclass(frozen=True, slots=True)
class ExecutionVector:
    plan_digest_sha256: str
    network: str
    netuid: int
    validator_hotkey: str
    version_key: int
    weights: tuple[ExecutionWeight, ...]
    omitted: tuple[OmittedWeight, ...]
    digest_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        if _DIGEST_RE.fullmatch(self.plan_digest_sha256) is None:
            raise WeightExecutionError("invalid_plan", "plan digest is invalid")
        _validate_public_network(self.network, "execution network")
        _validate_uint(self.netuid, "execution netuid", 65_535)
        _validate_public_text(self.validator_hotkey, "execution validator hotkey")
        _validate_uint(self.version_key, "execution version key", MAX_VERSION_KEY)
        if not self.weights:
            raise WeightExecutionError(
                "no_valid_planned_hotkeys", "no valid planned hotkeys remain"
            )
        if self.weights != tuple(sorted(self.weights, key=lambda item: (item.uid, item.hotkey))):
            raise WeightExecutionError("invalid_weights", "execution weights are not canonical")
        if self.omitted != tuple(
            sorted(self.omitted, key=lambda item: (item.planned_uid, item.hotkey))
        ):
            raise WeightExecutionError("invalid_weights", "omitted weights are not canonical")
        all_hotkeys = [item.hotkey for item in self.weights] + [
            item.hotkey for item in self.omitted
        ]
        if len(set(all_hotkeys)) != len(all_hotkeys):
            raise WeightExecutionError("invalid_weights", "execution hotkeys are duplicated")
        if len({item.uid for item in self.weights}) != len(self.weights):
            raise WeightExecutionError("invalid_weights", "execution UIDs are duplicated")
        if not math.isclose(
            math.fsum(item.weight for item in self.weights),
            1.0,
            rel_tol=0.0,
            abs_tol=1e-15,
        ):
            raise WeightExecutionError("invalid_weights", "execution weights are not normalized")
        object.__setattr__(
            self,
            "digest_sha256",
            hashlib.sha256(_canonical_json(self._unsigned_document())).hexdigest(),
        )

    def _unsigned_document(self) -> dict[str, object]:
        return {
            "netuid": self.netuid,
            "network": self.network,
            "omitted": [item.document() for item in self.omitted],
            "plan_digest_sha256": self.plan_digest_sha256,
            "schema": WEIGHT_EXECUTION_VECTOR_SCHEMA,
            "schema_version": WEIGHT_EXECUTION_VECTOR_SCHEMA_VERSION,
            "validator_hotkey": self.validator_hotkey,
            "version_key": self.version_key,
            "weights": [item.document() for item in self.weights],
        }

    def document(self) -> dict[str, object]:
        value = self._unsigned_document()
        value["digest_sha256"] = self.digest_sha256
        return value

    @property
    def moved_count(self) -> int:
        return sum(item.uid != item.planned_uid for item in self.weights)


def validate_execution_preflight(
    plan: WeightPlan,
    snapshot: MetagraphSnapshot,
    *,
    network: str,
    netuid: int,
    validator_hotkey: str,
) -> None:
    """Validate immutable configuration and one current finalized chain view."""

    if plan.network != network or snapshot.network != network:
        raise WeightExecutionError("wrong_network", "network does not match the plan")
    if plan.netuid != netuid or snapshot.netuid != netuid:
        raise WeightExecutionError("wrong_netuid", "netuid does not match the plan")
    if plan.validator_hotkey != validator_hotkey:
        raise WeightExecutionError("wrong_validator", "validator does not match the plan")
    if plan.version_key != WEIGHT_PLAN_PROTOCOL_VERSION_KEY:
        raise WeightExecutionError(
            "unsupported_version_key", "the plan weight version key is unsupported"
        )
    if snapshot.finalized is not True:
        raise WeightExecutionError(
            "unfinalized_chain_state", "the current metagraph is not finalized"
        )
    try:
        snapshot_identity_fingerprint(snapshot)
    except WeightPlanError as exc:
        raise WeightExecutionError(
            "invalid_chain_state", "the current metagraph identity is invalid"
        ) from exc
    if snapshot.block < plan.created_block:
        raise WeightExecutionError("chain_rollback", "current block predates the plan")
    if snapshot.block >= plan.expires_at_block:
        raise WeightExecutionError("expired_plan", "the plan has expired")
    validator = snapshot.by_hotkey(validator_hotkey)
    if validator is None or not validator.active or not validator.validator_permit:
        raise WeightExecutionError(
            "validator_not_permitted",
            "validator is absent, inactive, or lacks a permit",
        )


def derive_execution_vector(
    plan: WeightPlan,
    snapshot: MetagraphSnapshot,
    *,
    network: str,
    netuid: int,
    validator_hotkey: str,
) -> ExecutionVector:
    """Resolve planned hotkeys to current UIDs and renormalize omissions."""

    validate_execution_preflight(
        plan,
        snapshot,
        network=network,
        netuid=netuid,
        validator_hotkey=validator_hotkey,
    )
    current = {neuron.hotkey: neuron for neuron in snapshot.neurons}
    retained: list[tuple[int, str, int, float]] = []
    omitted: list[OmittedWeight] = []
    for planned in plan.weights:
        neuron = current.get(planned.hotkey)
        if neuron is None or not neuron.active:
            omitted.append(OmittedWeight(hotkey=planned.hotkey, planned_uid=planned.uid))
            continue
        retained.append((neuron.uid, planned.hotkey, planned.uid, planned.weight))
    if not retained:
        raise WeightExecutionError("no_valid_planned_hotkeys", "no valid planned hotkeys remain")
    retained.sort(key=lambda item: (item[0], item[1]))
    total = math.fsum(item[3] for item in retained)
    if not math.isfinite(total) or total <= 0.0:
        raise WeightExecutionError("invalid_weights", "remaining weight total is invalid")
    normalized = [item[3] / total for item in retained]
    correction_index = max(range(len(normalized)), key=lambda index: normalized[index])
    normalized[correction_index] += 1.0 - math.fsum(normalized)
    weights = tuple(
        ExecutionWeight(
            uid=uid,
            hotkey=hotkey,
            planned_uid=planned_uid,
            weight=normalized[index],
        )
        for index, (uid, hotkey, planned_uid, _) in enumerate(retained)
    )
    return ExecutionVector(
        plan_digest_sha256=plan.digest_sha256,
        network=network,
        netuid=netuid,
        validator_hotkey=validator_hotkey,
        version_key=plan.version_key,
        weights=weights,
        omitted=tuple(sorted(omitted, key=lambda item: (item.planned_uid, item.hotkey))),
    )


@dataclass(frozen=True, slots=True)
class SubmissionResult:
    success: bool
    extrinsic_ref: str | None = None
    error_code: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.success, bool):
            raise ValueError("submission result success flag is invalid")
        if self.extrinsic_ref is not None and _safe_reference(self.extrinsic_ref) is None:
            raise ValueError("submission result extrinsic reference is invalid")
        if self.error_code is not None and _safe_error_code(self.error_code) != self.error_code:
            raise ValueError("submission result error code is invalid")


class WeightSubmitter(Protocol):
    hotkey: str

    async def open(self) -> None: ...

    async def close(self) -> None: ...

    async def submit(self, vector: ExecutionVector) -> SubmissionResult: ...


def _safe_reference(value: object) -> str | None:
    if not isinstance(value, str) or _REFERENCE_RE.fullmatch(value) is None:
        return None
    return value


def _safe_error_code(value: object) -> str | None:
    if value is None:
        return None
    rendered = str(value).lower().replace("-", "_")
    return rendered if _ERROR_CODE_RE.fullmatch(rendered) is not None else None


AuditStatus = Literal["in_progress", "confirmed", "failed", "ambiguous"]
ReceiptOutcome = Literal["confirmed", "pre_send_failure", "definite_failure", "ambiguous"]


def _validate_timestamp(value: object) -> str:
    if not isinstance(value, str) or not value.endswith("Z") or len(value) > 40:
        raise AuditStateError("audit_state_invalid", "audit timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise AuditStateError("audit_state_invalid", "audit timestamp is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != UTC.utcoffset(parsed):
        raise AuditStateError("audit_state_invalid", "audit timestamp is invalid")
    return value


def _utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def execution_attempt_key(plan_digest_sha256: str, execution_digest_sha256: str) -> str:
    _validate_digest(plan_digest_sha256, "plan digest")
    _validate_digest(execution_digest_sha256, "execution digest")
    document = {
        "execution_digest_sha256": execution_digest_sha256,
        "plan_digest_sha256": plan_digest_sha256,
    }
    return hashlib.sha256(_canonical_json(document)).hexdigest()


@dataclass(frozen=True, slots=True)
class AuditReceipt:
    outcome: ReceiptOutcome
    extrinsic_ref: str | None
    error_code: str | None

    def __post_init__(self) -> None:
        if self.outcome not in {
            "confirmed",
            "pre_send_failure",
            "definite_failure",
            "ambiguous",
        }:
            raise AuditStateError("audit_state_invalid", "audit receipt outcome is invalid")
        if self.extrinsic_ref is not None and _safe_reference(self.extrinsic_ref) is None:
            raise AuditStateError("audit_state_invalid", "audit extrinsic reference is invalid")
        if self.error_code is not None and _safe_error_code(self.error_code) != self.error_code:
            raise AuditStateError("audit_state_invalid", "audit error code is invalid")
        if self.outcome == "confirmed":
            if self.extrinsic_ref is None or self.error_code is not None:
                raise AuditStateError("audit_state_invalid", "confirmed receipt is incomplete")
        elif self.error_code is None:
            raise AuditStateError("audit_state_invalid", "failure receipt lacks an error code")

    def document(self) -> dict[str, object]:
        return {
            "error_code": self.error_code,
            "extrinsic_ref": self.extrinsic_ref,
            "outcome": self.outcome,
        }


@dataclass(frozen=True, slots=True)
class AuditAttempt:
    attempt_id: str
    attempt_key: str
    plan_digest_sha256: str
    execution_digest_sha256: str
    network: str
    netuid: int
    validator_hotkey: str
    version_key: int
    preflight_block: int
    send_check_block: int | None
    status: AuditStatus
    submission_started: bool
    started_at: str
    updated_at: str
    weights: tuple[ExecutionWeight, ...]
    omitted: tuple[OmittedWeight, ...]
    receipt: AuditReceipt | None

    def __post_init__(self) -> None:
        _validate_digest(self.attempt_id, "attempt id")
        _validate_digest(self.attempt_key, "attempt key")
        plan_digest = _validate_digest(self.plan_digest_sha256, "plan digest")
        execution_digest = _validate_digest(self.execution_digest_sha256, "execution digest")
        if self.attempt_key != execution_attempt_key(plan_digest, execution_digest):
            raise AuditStateError("audit_state_invalid", "audit attempt key is invalid")
        _validate_public_network(self.network, "audit network")
        _validate_uint(self.netuid, "audit netuid", 65_535)
        _validate_public_text(self.validator_hotkey, "audit validator hotkey")
        _validate_uint(self.version_key, "audit version key", MAX_VERSION_KEY)
        _validate_uint(self.preflight_block, "audit preflight block", MAX_BLOCK)
        if self.send_check_block is not None:
            _validate_uint(self.send_check_block, "audit send-check block", MAX_BLOCK)
            if self.send_check_block < self.preflight_block:
                raise AuditStateError(
                    "audit_state_invalid", "audit send-check block predates preflight"
                )
        if self.status not in {"in_progress", "confirmed", "failed", "ambiguous"}:
            raise AuditStateError("audit_state_invalid", "audit status is invalid")
        if not isinstance(self.submission_started, bool):
            raise AuditStateError("audit_state_invalid", "submission flag is invalid")
        _validate_timestamp(self.started_at)
        _validate_timestamp(self.updated_at)
        if not self.weights:
            raise AuditStateError("audit_state_invalid", "audit execution vector is empty")
        vector = ExecutionVector(
            plan_digest_sha256=self.plan_digest_sha256,
            network=self.network,
            netuid=self.netuid,
            validator_hotkey=self.validator_hotkey,
            version_key=self.version_key,
            weights=self.weights,
            omitted=self.omitted,
        )
        if vector.digest_sha256 != self.execution_digest_sha256:
            raise AuditStateError(
                "audit_state_invalid", "audit execution mapping digest does not match"
            )
        if self.status == "in_progress":
            if self.receipt is not None:
                raise AuditStateError("audit_state_invalid", "in-progress attempt has a receipt")
        else:
            if self.receipt is None:
                raise AuditStateError("audit_state_invalid", "finished attempt lacks a receipt")
            expected_outcome = {
                "confirmed": "confirmed",
                "ambiguous": "ambiguous",
                "failed": ("definite_failure" if self.submission_started else "pre_send_failure"),
            }[self.status]
            if self.receipt.outcome != expected_outcome:
                raise AuditStateError(
                    "audit_state_invalid", "receipt outcome conflicts with status"
                )
        if self.submission_started and self.send_check_block is None:
            raise AuditStateError(
                "audit_state_invalid", "started submission lacks send-check block"
            )
        if not self.submission_started and self.send_check_block is not None:
            raise AuditStateError("audit_state_invalid", "pre-send attempt has a send-check block")
        if self.status in {"confirmed", "ambiguous"} and not self.submission_started:
            raise AuditStateError("audit_state_invalid", "submission outcome was never started")

    def document(self) -> dict[str, object]:
        return {
            "attempt_id": self.attempt_id,
            "attempt_key": self.attempt_key,
            "execution_digest_sha256": self.execution_digest_sha256,
            "mapping": {
                "omitted": [item.document() for item in self.omitted],
                "weights": [item.document() for item in self.weights],
            },
            "netuid": self.netuid,
            "network": self.network,
            "plan_digest_sha256": self.plan_digest_sha256,
            "preflight_block": self.preflight_block,
            "receipt": None if self.receipt is None else self.receipt.document(),
            "send_check_block": self.send_check_block,
            "started_at": self.started_at,
            "status": self.status,
            "submission_started": self.submission_started,
            "updated_at": self.updated_at,
            "validator_hotkey": self.validator_hotkey,
            "version_key": self.version_key,
        }


@dataclass(frozen=True, slots=True)
class AuditState:
    attempts: tuple[AuditAttempt, ...] = ()
    digest_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        if len(self.attempts) > MAX_AUDIT_ATTEMPTS:
            raise AuditStateError("audit_state_full", "audit state has reached its retention limit")
        attempt_ids = [attempt.attempt_id for attempt in self.attempts]
        if len(set(attempt_ids)) != len(attempt_ids):
            raise AuditStateError("audit_state_invalid", "audit attempt IDs are duplicated")
        object.__setattr__(
            self,
            "digest_sha256",
            hashlib.sha256(_canonical_json(self._unsigned_document())).hexdigest(),
        )

    def _unsigned_document(self) -> dict[str, object]:
        return {
            "attempts": [attempt.document() for attempt in self.attempts],
            "schema": WEIGHT_EXECUTION_AUDIT_SCHEMA,
            "schema_version": WEIGHT_EXECUTION_AUDIT_SCHEMA_VERSION,
        }

    def document(self) -> dict[str, object]:
        value = self._unsigned_document()
        value["digest_sha256"] = self.digest_sha256
        return value

    def canonical_bytes(self) -> bytes:
        return _canonical_json(self.document()) + b"\n"


def _exact_mapping(
    value: object,
    *,
    field_name: str,
    keys: frozenset[str],
) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise AuditStateError("audit_state_invalid", f"{field_name} has an invalid shape")
    return value


def _sequence(value: object, field_name: str) -> list[object]:
    if not isinstance(value, list):
        raise AuditStateError("audit_state_invalid", f"{field_name} is not an array")
    return value


def _parse_execution_weight(value: object) -> ExecutionWeight:
    row = _exact_mapping(
        value,
        field_name="audit execution weight",
        keys=frozenset({"hotkey", "planned_uid", "uid", "weight"}),
    )
    return ExecutionWeight(
        hotkey=row["hotkey"],  # type: ignore[arg-type]
        planned_uid=row["planned_uid"],  # type: ignore[arg-type]
        uid=row["uid"],  # type: ignore[arg-type]
        weight=row["weight"],  # type: ignore[arg-type]
    )


def _parse_omitted_weight(value: object) -> OmittedWeight:
    row = _exact_mapping(
        value,
        field_name="audit omitted weight",
        keys=frozenset({"hotkey", "planned_uid"}),
    )
    return OmittedWeight(
        hotkey=row["hotkey"],  # type: ignore[arg-type]
        planned_uid=row["planned_uid"],  # type: ignore[arg-type]
    )


def _parse_receipt(value: object) -> AuditReceipt | None:
    if value is None:
        return None
    receipt = _exact_mapping(
        value,
        field_name="audit receipt",
        keys=frozenset({"error_code", "extrinsic_ref", "outcome"}),
    )
    return AuditReceipt(
        outcome=receipt["outcome"],  # type: ignore[arg-type]
        extrinsic_ref=receipt["extrinsic_ref"],  # type: ignore[arg-type]
        error_code=receipt["error_code"],  # type: ignore[arg-type]
    )


def _parse_attempt(value: object) -> AuditAttempt:
    row = _exact_mapping(
        value,
        field_name="audit attempt",
        keys=frozenset(
            {
                "attempt_id",
                "attempt_key",
                "execution_digest_sha256",
                "mapping",
                "netuid",
                "network",
                "plan_digest_sha256",
                "preflight_block",
                "receipt",
                "send_check_block",
                "started_at",
                "status",
                "submission_started",
                "updated_at",
                "validator_hotkey",
                "version_key",
            }
        ),
    )
    mapping = _exact_mapping(
        row["mapping"],
        field_name="audit execution mapping",
        keys=frozenset({"omitted", "weights"}),
    )
    return AuditAttempt(
        attempt_id=row["attempt_id"],  # type: ignore[arg-type]
        attempt_key=row["attempt_key"],  # type: ignore[arg-type]
        plan_digest_sha256=row["plan_digest_sha256"],  # type: ignore[arg-type]
        execution_digest_sha256=row["execution_digest_sha256"],  # type: ignore[arg-type]
        network=row["network"],  # type: ignore[arg-type]
        netuid=row["netuid"],  # type: ignore[arg-type]
        validator_hotkey=row["validator_hotkey"],  # type: ignore[arg-type]
        version_key=row["version_key"],  # type: ignore[arg-type]
        preflight_block=row["preflight_block"],  # type: ignore[arg-type]
        send_check_block=row["send_check_block"],  # type: ignore[arg-type]
        status=row["status"],  # type: ignore[arg-type]
        submission_started=row["submission_started"],  # type: ignore[arg-type]
        started_at=row["started_at"],  # type: ignore[arg-type]
        updated_at=row["updated_at"],  # type: ignore[arg-type]
        weights=tuple(
            _parse_execution_weight(item) for item in _sequence(mapping["weights"], "weights")
        ),
        omitted=tuple(
            _parse_omitted_weight(item) for item in _sequence(mapping["omitted"], "omitted")
        ),
        receipt=_parse_receipt(row["receipt"]),
    )


def parse_audit_state(rendered: bytes) -> AuditState:
    def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        value: dict[str, object] = {}
        for key, item in pairs:
            if key in value:
                raise AuditStateError("audit_state_invalid", "audit state has duplicate keys")
            value[key] = item
        return value

    try:
        document = json.loads(rendered.decode("ascii"), object_pairs_hook=unique_object)
    except AuditStateError:
        raise
    except (ValueError, UnicodeDecodeError, RecursionError) as exc:
        raise AuditStateError("audit_state_invalid", "audit state is not canonical JSON") from exc
    root = _exact_mapping(
        document,
        field_name="audit state",
        keys=frozenset({"attempts", "digest_sha256", "schema", "schema_version"}),
    )
    if root["schema"] != WEIGHT_EXECUTION_AUDIT_SCHEMA:
        raise AuditStateError("audit_state_invalid", "audit state schema is unsupported")
    if root["schema_version"] != WEIGHT_EXECUTION_AUDIT_SCHEMA_VERSION:
        raise AuditStateError("audit_state_invalid", "audit state version is unsupported")
    state = AuditState(
        attempts=tuple(
            _parse_attempt(item) for item in _sequence(root["attempts"], "audit attempts")
        )
    )
    if root["digest_sha256"] != state.digest_sha256:
        raise AuditStateError("audit_state_invalid", "audit state digest does not match")
    if rendered != state.canonical_bytes():
        raise AuditStateError("audit_state_invalid", "audit state bytes are not canonical")
    return state


class AuditStateStore:
    """Locked, pinned-dirfd, atomic and durable audit-state storage."""

    def __init__(self, path: str | os.PathLike[str]) -> None:
        try:
            parent, name = _secure_file_location(path)
            self._chain = _pin_directory_chain(parent)
        except (OSError, WeightPlanTargetError) as exc:
            raise AuditStateError("audit_state_unsafe", "audit state path is unsafe") from exc
        self._name = name
        self._lock_name = f".{name}.lock"
        self._lock_descriptor = -1
        self._target: os.stat_result | None = None
        self.state = AuditState()
        try:
            self._open_lock()
            self._load()
        except Exception:
            self.close()
            raise

    def _open_lock(self) -> None:
        flags = os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW
        created = False
        try:
            try:
                descriptor = os.open(
                    self._lock_name,
                    flags | os.O_CREAT | os.O_EXCL,
                    WEIGHT_PLAN_FILE_MODE,
                    dir_fd=self._chain.parent_fd,
                )
                created = True
            except FileExistsError:
                descriptor = os.open(self._lock_name, flags, dir_fd=self._chain.parent_fd)
        except OSError as exc:
            raise AuditStateError("audit_state_unsafe", "audit lock path is unsafe") from exc
        self._lock_descriptor = descriptor
        if created:
            os.fchmod(descriptor, WEIGHT_PLAN_FILE_MODE)
        value = os.fstat(descriptor)
        try:
            _validate_existing_target(value)
        except WeightPlanTargetError as exc:
            raise AuditStateError("audit_state_unsafe", "audit lock inode is unsafe") from exc
        if value.st_size != 0:
            raise AuditStateError("audit_state_unsafe", "audit lock file is not empty")
        named = os.stat(self._lock_name, dir_fd=self._chain.parent_fd, follow_symlinks=False)
        if (named.st_dev, named.st_ino) != (value.st_dev, value.st_ino):
            raise AuditStateError("audit_state_unsafe", "audit lock path changed identity")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise AuditStateError(
                "audit_state_busy", "another executor owns the audit lock"
            ) from exc
        _revalidate_pinned_chain(self._chain)
        after = os.fstat(descriptor)
        if not _same_target(value, after):
            raise AuditStateError("audit_state_unsafe", "audit lock changed during validation")

    def _load(self) -> None:
        try:
            _revalidate_pinned_chain(self._chain)
            target = _target_stat(self._chain.parent_fd, self._name)
            if target is None:
                self._target = None
                self.state = AuditState()
                return
            rendered = _read_existing(self._chain.parent_fd, self._name, target)
            if not _same_target(target, _target_stat(self._chain.parent_fd, self._name)):
                raise AuditStateError("audit_state_unsafe", "audit state changed while read")
            _verify_configured_target(
                self._chain,
                self._name,
                identity=(target.st_dev, target.st_ino),
                rendered=rendered,
            )
            self.state = parse_audit_state(rendered)
            self._target = target
        except AuditStateError:
            raise
        except (OSError, WeightPlanTargetError) as exc:
            raise AuditStateError("audit_state_unsafe", "audit state is unsafe") from exc

    def _persist(self, state: AuditState) -> None:
        rendered = state.canonical_bytes()
        if len(rendered) > MAX_WEIGHT_PLAN_BYTES:
            raise AuditStateError("audit_state_full", "audit state exceeds its size limit")
        temporary = None
        try:
            _revalidate_pinned_chain(self._chain)
            if not _same_target(
                self._target,
                _target_stat(self._chain.parent_fd, self._name),
            ):
                raise AuditStateError("audit_state_unsafe", "audit state changed before update")
            temporary = _prepare_temporary_plan(self._chain.parent_fd, rendered)
            _revalidate_pinned_chain(self._chain)
            if not _same_target(
                self._target,
                _target_stat(self._chain.parent_fd, self._name),
            ):
                raise AuditStateError("audit_state_unsafe", "audit state changed before install")
            _validate_temporary_descriptor(
                temporary,
                expected_size=len(rendered),
                expected_nlink=1,
            )
            _validate_temporary_name(
                temporary,
                self._chain.parent_fd,
                expected_size=len(rendered),
            )
            assert temporary.name is not None
            os.replace(
                temporary.name,
                self._name,
                src_dir_fd=self._chain.parent_fd,
                dst_dir_fd=self._chain.parent_fd,
            )
            temporary.name = None
            _validate_temporary_descriptor(
                temporary,
                expected_size=len(rendered),
                expected_nlink=1,
            )
            installed = _target_stat(self._chain.parent_fd, self._name)
            if installed is None or (installed.st_dev, installed.st_ino) != temporary.identity:
                raise AuditStateError(
                    "audit_state_unsafe", "installed audit state changed identity"
                )
            os.fsync(self._chain.parent_fd)
            _verify_configured_target(
                self._chain,
                self._name,
                identity=temporary.identity,
                rendered=rendered,
            )
            self._target = installed
            self.state = state
        except AuditStateError:
            raise
        except (OSError, WeightPlanTargetError) as exc:
            raise AuditStateError("audit_state_unsafe", "audit state update failed") from exc
        finally:
            if temporary is not None and temporary.name is not None:
                try:
                    named = os.stat(
                        temporary.name,
                        dir_fd=self._chain.parent_fd,
                        follow_symlinks=False,
                    )
                    if (named.st_dev, named.st_ino) == temporary.identity:
                        os.unlink(temporary.name, dir_fd=self._chain.parent_fd)
                except FileNotFoundError:
                    pass
            if temporary is not None:
                os.close(temporary.descriptor)

    def blocking_attempt(self, plan_digest_sha256: str) -> AuditAttempt | None:
        for attempt in reversed(self.state.attempts):
            if attempt.plan_digest_sha256 != plan_digest_sha256:
                continue
            if attempt.status in {"in_progress", "confirmed", "ambiguous"}:
                return attempt
            if attempt.status == "failed" and attempt.submission_started:
                return attempt
        return None

    def start_attempt(
        self,
        vector: ExecutionVector,
        *,
        preflight_block: int,
        timestamp: str,
        attempt_nonce: str | None = None,
    ) -> AuditAttempt:
        if self.blocking_attempt(vector.plan_digest_sha256) is not None:
            raise AuditStateError(
                "idempotency_blocked",
                "this plan has a prior non-retryable or unresolved attempt",
            )
        _validate_timestamp(timestamp)
        nonce = secrets.token_hex(32) if attempt_nonce is None else attempt_nonce
        _validate_digest(nonce, "attempt nonce")
        attempt_id = hashlib.sha256(
            _canonical_json(
                {
                    "attempt_nonce": nonce,
                    "execution_digest_sha256": vector.digest_sha256,
                    "plan_digest_sha256": vector.plan_digest_sha256,
                    "started_at": timestamp,
                }
            )
        ).hexdigest()
        attempt = AuditAttempt(
            attempt_id=attempt_id,
            attempt_key=execution_attempt_key(vector.plan_digest_sha256, vector.digest_sha256),
            plan_digest_sha256=vector.plan_digest_sha256,
            execution_digest_sha256=vector.digest_sha256,
            network=vector.network,
            netuid=vector.netuid,
            validator_hotkey=vector.validator_hotkey,
            version_key=vector.version_key,
            preflight_block=preflight_block,
            send_check_block=None,
            status="in_progress",
            submission_started=False,
            started_at=timestamp,
            updated_at=timestamp,
            weights=vector.weights,
            omitted=vector.omitted,
            receipt=None,
        )
        self._persist(AuditState((*self.state.attempts, attempt)))
        return attempt

    def _update_attempt(self, attempt_id: str, updated: AuditAttempt) -> AuditAttempt:
        matches = [
            index for index, item in enumerate(self.state.attempts) if item.attempt_id == attempt_id
        ]
        if len(matches) != 1:
            raise AuditStateError("audit_state_invalid", "audit attempt is missing or duplicated")
        index = matches[0]
        current = self.state.attempts[index]
        if current.status != "in_progress":
            raise AuditStateError("audit_state_invalid", "audit attempt is already final")
        attempts = list(self.state.attempts)
        attempts[index] = updated
        self._persist(AuditState(tuple(attempts)))
        return updated

    def mark_submission_started(
        self,
        attempt_id: str,
        *,
        send_check_block: int,
        timestamp: str,
    ) -> AuditAttempt:
        current = next(
            (item for item in self.state.attempts if item.attempt_id == attempt_id),
            None,
        )
        if current is None:
            raise AuditStateError("audit_state_invalid", "audit attempt is missing")
        return self._update_attempt(
            attempt_id,
            replace(
                current,
                send_check_block=send_check_block,
                submission_started=True,
                updated_at=timestamp,
            ),
        )

    def finish_attempt(
        self,
        attempt_id: str,
        *,
        status: Literal["confirmed", "failed", "ambiguous"],
        outcome: ReceiptOutcome,
        extrinsic_ref: str | None,
        error_code: str | None,
        timestamp: str,
    ) -> AuditAttempt:
        current = next(
            (item for item in self.state.attempts if item.attempt_id == attempt_id),
            None,
        )
        if current is None:
            raise AuditStateError("audit_state_invalid", "audit attempt is missing")
        updated = replace(
            current,
            status=status,
            receipt=AuditReceipt(
                outcome=outcome,
                extrinsic_ref=extrinsic_ref,
                error_code=error_code,
            ),
            updated_at=timestamp,
        )
        return self._update_attempt(attempt_id, updated)

    def close(self) -> None:
        descriptor = getattr(self, "_lock_descriptor", -1)
        if descriptor >= 0:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)
            self._lock_descriptor = -1
        chain = getattr(self, "_chain", None)
        if chain is not None:
            chain.close()

    def __enter__(self) -> AuditStateStore:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


@dataclass(frozen=True, slots=True)
class ExecutorConfig:
    plan_path: str
    network: str
    netuid: int
    validator_hotkey: str
    execute: bool = False
    confirm_network: str | None = None
    confirm_netuid: int | None = None
    confirm_plan_digest: str | None = None
    audit_state_path: str | None = None
    submission_timeout_seconds: float = 180.0
    confirm_execution_digest: str | None = None
    signer_socket_path: str | None = None
    signer_uid: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.plan_path, str) or not self.plan_path:
            raise WeightExecutionError("invalid_plan_path", "plan path is required")
        _validate_public_network(self.network, "configured network")
        _validate_uint(self.netuid, "configured netuid", 65_535)
        _validate_public_text(self.validator_hotkey, "configured validator hotkey")
        if (
            isinstance(self.submission_timeout_seconds, bool)
            or not isinstance(self.submission_timeout_seconds, (int, float))
            or not math.isfinite(float(self.submission_timeout_seconds))
            or not 0.0 < float(self.submission_timeout_seconds) <= MAX_SUBMISSION_TIMEOUT_SECONDS
        ):
            raise WeightExecutionError(
                "invalid_submission_timeout", "submission timeout is invalid"
            )
        if self.confirm_execution_digest is not None:
            _validate_digest(self.confirm_execution_digest, "confirmed execution digest")
        if self.signer_uid is not None:
            _validate_uint(self.signer_uid, "signer UID", 2**32 - 2)


@dataclass(frozen=True, slots=True)
class ExecutionSummary:
    mode: Literal["dry-run", "execute"]
    status: Literal["validated", "confirmed"]
    network: str
    netuid: int
    current_block: int
    plan_digest_sha256: str
    execution_digest_sha256: str
    target_count: int
    moved_count: int
    omitted_count: int
    attempt_id: str | None = None
    extrinsic_ref: str | None = None

    def redacted_document(self) -> dict[str, object]:
        return {
            "attempt_id": self.attempt_id,
            "current_block": self.current_block,
            "execution_digest_sha256": self.execution_digest_sha256,
            "extrinsic_ref": self.extrinsic_ref,
            "mode": self.mode,
            "moved_count": self.moved_count,
            "netuid": self.netuid,
            "network": self.network,
            "omitted_count": self.omitted_count,
            "plan_digest_sha256": self.plan_digest_sha256,
            "status": self.status,
            "target_count": self.target_count,
        }


def _validate_execution_gates(
    config: ExecutorConfig,
    plan: WeightPlan,
    environ: Mapping[str, str],
) -> None:
    if not config.execute:
        return
    if config.confirm_network != config.network or config.confirm_network != plan.network:
        raise WeightExecutionError(
            "network_confirmation_required",
            "execution requires the exact network confirmation",
        )
    if config.confirm_netuid != config.netuid or config.confirm_netuid != plan.netuid:
        raise WeightExecutionError(
            "netuid_confirmation_required",
            "execution requires the exact netuid confirmation",
        )
    if config.confirm_plan_digest != plan.digest_sha256:
        raise WeightExecutionError(
            "plan_digest_confirmation_required",
            "execution requires the exact plan digest confirmation",
        )
    if environ.get(EXECUTION_ACK_ENV) != EXECUTION_ACK_VALUE:
        raise WeightExecutionError(
            "environment_acknowledgement_required",
            "execution requires the explicit environment acknowledgement",
        )
    if config.audit_state_path is None or not config.audit_state_path:
        raise WeightExecutionError(
            "audit_state_required", "execution requires a durable audit-state path"
        )
    try:
        plan_absolute = os.path.abspath(config.plan_path)
        audit_absolute = os.path.abspath(config.audit_state_path)
    except (OSError, ValueError) as exc:
        raise WeightExecutionError("audit_state_unsafe", "audit state path is unsafe") from exc
    if plan_absolute == audit_absolute:
        raise WeightExecutionError(
            "audit_state_unsafe", "plan and audit state paths must be distinct"
        )


def _pre_send_failure(
    store: AuditStateStore,
    attempt: AuditAttempt,
    *,
    code: str,
    clock: Callable[[], str],
) -> None:
    store.finish_attempt(
        attempt.attempt_id,
        status="failed",
        outcome="pre_send_failure",
        extrinsic_ref=None,
        error_code=code,
        timestamp=clock(),
    )


async def run_weight_executor(
    config: ExecutorConfig,
    *,
    chain: ExecutionChain,
    submitter_factory: Callable[[], WeightSubmitter] | None = None,
    environ: Mapping[str, str] | None = None,
    clock: Callable[[], str] | None = None,
    attempt_nonce_factory: Callable[[], str] | None = None,
) -> ExecutionSummary:
    """Verify one plan, optionally submit once, durably record the result, and exit."""

    effective_clock = _utc_now if clock is None else clock
    try:
        plan = load_weight_plan(config.plan_path)
    except (WeightPlanError, WeightPlanTargetError, OSError) as exc:
        raise WeightExecutionError("invalid_plan", "plan verification failed") from exc
    if plan.network != config.network:
        raise WeightExecutionError("wrong_network", "configured network differs from plan")
    if plan.netuid != config.netuid:
        raise WeightExecutionError("wrong_netuid", "configured netuid differs from plan")
    if plan.validator_hotkey != config.validator_hotkey:
        raise WeightExecutionError("wrong_validator", "configured validator differs from plan")
    if plan.version_key != WEIGHT_PLAN_PROTOCOL_VERSION_KEY:
        raise WeightExecutionError(
            "unsupported_version_key", "the plan weight version key is unsupported"
        )
    environment = os.environ if environ is None else environ
    _validate_execution_gates(config, plan, environment)

    opened = False
    try:
        try:
            await chain.open()
            opened = True
            snapshot = await chain.sync()
        except Exception as exc:
            raise WeightExecutionError(
                "chain_preflight_failed", "current finalized chain state is unavailable"
            ) from exc
        vector = derive_execution_vector(
            plan,
            snapshot,
            network=config.network,
            netuid=config.netuid,
            validator_hotkey=config.validator_hotkey,
        )
        if (
            config.confirm_execution_digest is not None
            and vector.digest_sha256 != config.confirm_execution_digest
        ):
            raise WeightExecutionError(
                "execution_digest_confirmation_required",
                "execution requires the exact adjusted execution digest",
            )
        if not config.execute:
            return ExecutionSummary(
                mode="dry-run",
                status="validated",
                network=config.network,
                netuid=config.netuid,
                current_block=snapshot.block,
                plan_digest_sha256=plan.digest_sha256,
                execution_digest_sha256=vector.digest_sha256,
                target_count=len(vector.weights),
                moved_count=vector.moved_count,
                omitted_count=len(vector.omitted),
            )

        try:
            commit_reveal_enabled = await chain.commit_reveal_enabled(snapshot.block)
        except Exception as exc:
            raise WeightExecutionError(
                "chain_preflight_failed", "weight submission mode is unavailable"
            ) from exc
        if commit_reveal_enabled:
            raise WeightExecutionError(
                "commit_reveal_unsupported",
                "commit-reveal weights are unsupported by this executor",
            )

        assert config.audit_state_path is not None
        if submitter_factory is None:
            raise WeightExecutionError(
                "submitter_unavailable", "execution signing capability is unavailable"
            )
        try:
            store_context = AuditStateStore(config.audit_state_path)
        except AuditStateError:
            raise
        except Exception as exc:
            raise AuditStateError("audit_state_unsafe", "audit state is unavailable") from exc
        with store_context as store:
            blocking = store.blocking_attempt(plan.digest_sha256)
            if blocking is not None:
                raise AuditStateError(
                    "idempotency_blocked",
                    "this plan has a prior non-retryable or unresolved attempt",
                )
            attempt = store.start_attempt(
                vector,
                preflight_block=snapshot.block,
                timestamp=effective_clock(),
                attempt_nonce=(None if attempt_nonce_factory is None else attempt_nonce_factory()),
            )
            submitter: WeightSubmitter | None = None
            submitter_opened = False
            try:
                try:
                    submitter = submitter_factory()
                    if submitter.hotkey != config.validator_hotkey:
                        raise WeightExecutionError(
                            "signer_hotkey_mismatch",
                            "signing wallet does not match the configured validator",
                        )
                    await submitter.open()
                    submitter_opened = True
                except WeightExecutionError as exc:
                    _pre_send_failure(store, attempt, code=exc.code, clock=effective_clock)
                    raise
                except Exception as exc:
                    _pre_send_failure(
                        store,
                        attempt,
                        code="signer_unavailable",
                        clock=effective_clock,
                    )
                    raise WeightExecutionError(
                        "signer_unavailable", "signing capability could not be loaded"
                    ) from exc

                try:
                    send_snapshot = await chain.sync()
                    if send_snapshot.block < snapshot.block:
                        raise WeightExecutionError(
                            "pre_send_state_changed", "chain state rolled back before submission"
                        )
                    if send_snapshot.block == snapshot.block and snapshot_identity_fingerprint(
                        send_snapshot
                    ) != snapshot_identity_fingerprint(snapshot):
                        raise WeightExecutionError(
                            "pre_send_state_changed",
                            "same-height chain identity changed before submission",
                        )
                    send_vector = derive_execution_vector(
                        plan,
                        send_snapshot,
                        network=config.network,
                        netuid=config.netuid,
                        validator_hotkey=config.validator_hotkey,
                    )
                    if await chain.commit_reveal_enabled(send_snapshot.block):
                        raise WeightExecutionError(
                            "commit_reveal_unsupported",
                            "commit-reveal weights are unsupported by this executor",
                        )
                    if send_vector.digest_sha256 != vector.digest_sha256:
                        raise WeightExecutionError(
                            "pre_send_state_changed",
                            "the adjusted execution vector changed before submission",
                        )
                except WeightExecutionError as exc:
                    _pre_send_failure(store, attempt, code=exc.code, clock=effective_clock)
                    raise
                except Exception as exc:
                    _pre_send_failure(
                        store,
                        attempt,
                        code="pre_send_state_unavailable",
                        clock=effective_clock,
                    )
                    raise WeightExecutionError(
                        "pre_send_state_unavailable",
                        "final send-check chain state is unavailable",
                    ) from exc

                attempt = store.mark_submission_started(
                    attempt.attempt_id,
                    send_check_block=send_snapshot.block,
                    timestamp=effective_clock(),
                )
                try:
                    result = await asyncio.wait_for(
                        submitter.submit(send_vector),
                        timeout=float(config.submission_timeout_seconds),
                    )
                    if not isinstance(result, SubmissionResult):
                        raise TypeError("submitter returned an unsupported result")
                except TimeoutError as exc:
                    store.finish_attempt(
                        attempt.attempt_id,
                        status="ambiguous",
                        outcome="ambiguous",
                        extrinsic_ref=None,
                        error_code="submission_timeout",
                        timestamp=effective_clock(),
                    )
                    raise WeightExecutionError(
                        "submission_ambiguous",
                        "submission timed out and must be reconciled before retry",
                    ) from exc
                except Exception as exc:
                    store.finish_attempt(
                        attempt.attempt_id,
                        status="ambiguous",
                        outcome="ambiguous",
                        extrinsic_ref=None,
                        error_code="submission_exception",
                        timestamp=effective_clock(),
                    )
                    raise WeightExecutionError(
                        "submission_ambiguous",
                        "submission response was lost and must be reconciled before retry",
                    ) from exc
                if result.success:
                    if result.extrinsic_ref is None:
                        store.finish_attempt(
                            attempt.attempt_id,
                            status="ambiguous",
                            outcome="ambiguous",
                            extrinsic_ref=None,
                            error_code="missing_extrinsic_reference",
                            timestamp=effective_clock(),
                        )
                        raise WeightExecutionError(
                            "submission_ambiguous",
                            "success lacked a durable extrinsic reference",
                        )
                    store.finish_attempt(
                        attempt.attempt_id,
                        status="confirmed",
                        outcome="confirmed",
                        extrinsic_ref=result.extrinsic_ref,
                        error_code=None,
                        timestamp=effective_clock(),
                    )
                    return ExecutionSummary(
                        mode="execute",
                        status="confirmed",
                        network=config.network,
                        netuid=config.netuid,
                        current_block=send_snapshot.block,
                        plan_digest_sha256=plan.digest_sha256,
                        execution_digest_sha256=vector.digest_sha256,
                        target_count=len(vector.weights),
                        moved_count=vector.moved_count,
                        omitted_count=len(vector.omitted),
                        attempt_id=attempt.attempt_id,
                        extrinsic_ref=result.extrinsic_ref,
                    )
                store.finish_attempt(
                    attempt.attempt_id,
                    status="failed",
                    outcome="definite_failure",
                    extrinsic_ref=result.extrinsic_ref,
                    error_code=result.error_code or "chain_rejected",
                    timestamp=effective_clock(),
                )
                raise WeightExecutionError(
                    "submission_failed", "chain submission was definitively rejected"
                )
            finally:
                if submitter is not None and submitter_opened:
                    with suppress(Exception):
                        await submitter.close()
    finally:
        if opened:
            with suppress(Exception):
                await chain.close()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", required=True, help="canonical mode-0600 WeightPlan v1 path")
    parser.add_argument(
        "--subtensor-network",
        default=os.getenv("BT_NETWORK", "finney"),
        help="exact network configured for read-only preflight",
    )
    parser.add_argument("--netuid", type=int, required=True)
    parser.add_argument(
        "--rpc-endpoint",
        action="append",
        default=[],
        help="independent RPC endpoint; repeat at least twice to require finalized agreement",
    )
    parser.add_argument(
        "--rpc-max-finalized-lag",
        type=int,
        default=8,
        help="maximum block-height spread allowed across redundant finalized RPC heads",
    )
    parser.add_argument(
        "--validator-hotkey",
        default=os.getenv("BT_VALIDATOR_HOTKEY"),
        required=os.getenv("BT_VALIDATOR_HOTKEY") is None,
        help="expected public validator hotkey; does not load a wallet",
    )
    parser.add_argument("--execute", action="store_true", help="enable the gated write path")
    parser.add_argument("--confirm-network")
    parser.add_argument("--confirm-netuid", type=int)
    parser.add_argument("--confirm-plan-digest")
    parser.add_argument("--audit-state")
    parser.add_argument("--submission-timeout", type=float, default=180.0)
    parser.add_argument("--signer-socket", help="purpose-restricted signer Unix socket")
    parser.add_argument("--signer-uid", type=int, help="required signer process UID")
    return parser


def _config_from_args(args: argparse.Namespace) -> ExecutorConfig:
    return ExecutorConfig(
        plan_path=args.plan,
        network=args.subtensor_network,
        netuid=args.netuid,
        validator_hotkey=args.validator_hotkey,
        execute=args.execute,
        confirm_network=args.confirm_network,
        confirm_netuid=args.confirm_netuid,
        confirm_plan_digest=args.confirm_plan_digest,
        audit_state_path=args.audit_state,
        submission_timeout_seconds=args.submission_timeout,
        signer_socket_path=args.signer_socket,
        signer_uid=args.signer_uid,
    )


def main() -> None:
    args = build_parser().parse_args()
    try:
        config = _config_from_args(args)
        try:
            chain = build_chain_query(
                network=config.network,
                netuid=config.netuid,
                rpc_endpoints=args.rpc_endpoint,
                max_finalized_lag=args.rpc_max_finalized_lag,
                alert_sink=json_stderr_alert,
            )
        except ValueError as exc:
            raise WeightExecutionError(
                "rpc_configuration_invalid", "redundant RPC configuration is invalid"
            ) from exc

        submitter_factory: Callable[[], WeightSubmitter] | None = None
        if config.execute:
            if not config.signer_socket_path or config.signer_uid is None:
                raise WeightExecutionError(
                    "signer_boundary_required",
                    "execution requires a purpose-restricted signer socket and UID",
                )
            signer_socket_path = config.signer_socket_path
            signer_uid = config.signer_uid
            from .weight_signer_protocol import UnixWeightSignerClient

            def submitter_factory() -> WeightSubmitter:
                return UnixWeightSignerClient(
                    socket_path=signer_socket_path,
                    signer_uid=signer_uid,
                    hotkey=config.validator_hotkey,
                    timeout_seconds=config.submission_timeout_seconds,
                )

        summary = asyncio.run(
            run_weight_executor(
                config,
                chain=chain,
                submitter_factory=submitter_factory,
            )
        )
    except WeightExecutionError as exc:
        print(
            json.dumps(
                {"error_code": exc.code, "status": "rejected"},
                sort_keys=True,
                separators=(",", ":"),
            ),
            file=sys.stderr,
        )
        raise SystemExit(2) from None
    print(json.dumps(summary.redacted_document(), sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
