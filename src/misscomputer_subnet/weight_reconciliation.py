# SPDX-License-Identifier: AGPL-3.0-only
"""Read-only evidence report for durable validator-weight execution attempts."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import math
import os
import sys
from contextlib import suppress
from dataclasses import dataclass, field
from typing import Literal, Protocol

from .chain import MetagraphSnapshot
from .chain_quorum import build_chain_query, json_stderr_alert
from .weight_executor import AuditAttempt, AuditState, AuditStateError, parse_audit_state
from .weight_plan import (
    WeightPlanTargetError,
    _canonical_json,
    _pin_directory_chain,
    _read_existing,
    _revalidate_pinned_chain,
    _same_target,
    _secure_file_location,
    _target_stat,
)

WEIGHT_RECONCILIATION_SCHEMA = "miss.computer/misscomputer-subnet/weight-reconciliation-report"
WEIGHT_RECONCILIATION_SCHEMA_VERSION = 1


class WeightReconciliationError(RuntimeError):
    """A sanitized read-only reconciliation rejection."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class ReconciliationChain(Protocol):
    async def open(self) -> None: ...

    async def close(self) -> None: ...

    async def sync(self) -> MetagraphSnapshot: ...

    async def validator_weights(self, block: int, validator_uid: int) -> dict[int, float]: ...


EvidenceRelation = Literal["consistent", "different", "unavailable"]
IdentityStatus = Literal["exact", "changed", "validator_missing"]
RetryDisposition = Literal["eligible_pre_send", "blocked_requires_operator"]


@dataclass(frozen=True, slots=True)
class WeightReconciliationReport:
    audit_digest_sha256: str
    attempt_id: str
    attempt_status: str
    submission_started: bool
    network: str
    netuid: int
    validator_hotkey: str
    evidence_block: int
    validator_uid: int | None
    target_identity_status: IdentityStatus
    evidence_relation: EvidenceRelation
    expected_row_digest_sha256: str
    observed_row_digest_sha256: str | None
    retry_disposition: RetryDisposition
    conclusion: str
    alert_required: bool
    digest_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "digest_sha256",
            hashlib.sha256(_canonical_json(self._unsigned_document())).hexdigest(),
        )

    def _unsigned_document(self) -> dict[str, object]:
        return {
            "alert_required": self.alert_required,
            "attempt_id": self.attempt_id,
            "attempt_status": self.attempt_status,
            "audit_digest_sha256": self.audit_digest_sha256,
            "conclusion": self.conclusion,
            "evidence": {
                "block": self.evidence_block,
                "expected_row_digest_sha256": self.expected_row_digest_sha256,
                "observed_row_digest_sha256": self.observed_row_digest_sha256,
                "relation": self.evidence_relation,
                "target_identity_status": self.target_identity_status,
                "validator_uid": self.validator_uid,
            },
            "netuid": self.netuid,
            "network": self.network,
            "retry_disposition": self.retry_disposition,
            "schema": WEIGHT_RECONCILIATION_SCHEMA,
            "schema_version": WEIGHT_RECONCILIATION_SCHEMA_VERSION,
            "submission_started": self.submission_started,
            "validator_hotkey": self.validator_hotkey,
        }

    def document(self) -> dict[str, object]:
        value = self._unsigned_document()
        value["digest_sha256"] = self.digest_sha256
        return value

    def canonical_bytes(self) -> bytes:
        return _canonical_json(self.document()) + b"\n"


def load_audit_state_readonly(path: str | os.PathLike[str]) -> AuditState:
    """Pin and read an existing audit ledger without creating files or locks."""

    directory_chain = None
    try:
        parent, name = _secure_file_location(path)
        directory_chain = _pin_directory_chain(parent)
        target = _target_stat(directory_chain.parent_fd, name)
        if target is None:
            raise WeightReconciliationError("audit_state_unavailable", "audit state does not exist")
        rendered = _read_existing(directory_chain.parent_fd, name, target)
        _revalidate_pinned_chain(directory_chain)
        current = _target_stat(directory_chain.parent_fd, name)
        if not _same_target(target, current):
            raise WeightReconciliationError(
                "audit_state_changed", "audit state changed during read-only inspection"
            )
        return parse_audit_state(rendered)
    except WeightReconciliationError:
        raise
    except (AuditStateError, WeightPlanTargetError, OSError) as exc:
        raise WeightReconciliationError(
            "audit_state_invalid", "audit state is unavailable or unsafe"
        ) from exc
    finally:
        if directory_chain is not None:
            directory_chain.close()


def _select_attempt(state: AuditState, attempt_id: str | None) -> AuditAttempt:
    if attempt_id is not None:
        for attempt in state.attempts:
            if attempt.attempt_id == attempt_id:
                return attempt
        raise WeightReconciliationError("attempt_not_found", "audit attempt was not found")
    if not state.attempts:
        raise WeightReconciliationError("attempt_not_found", "audit state has no attempts")
    for attempt in reversed(state.attempts):
        if attempt.status in {"in_progress", "ambiguous"} or (
            attempt.status == "failed" and attempt.submission_started
        ):
            return attempt
    return state.attempts[-1]


def _row_digest(row: dict[int, float]) -> str:
    document = [{"uid": uid, "weight_hex": weight.hex()} for uid, weight in sorted(row.items())]
    return hashlib.sha256(_canonical_json(document)).hexdigest()


def _row_relation(expected: dict[int, float], observed: dict[int, float]) -> EvidenceRelation:
    if set(expected) != set(observed):
        return "different"
    tolerance = max(2.0 / 65_535.0, len(expected) / 65_535.0)
    return (
        "consistent"
        if all(
            math.isclose(expected[uid], observed[uid], rel_tol=0.0, abs_tol=tolerance)
            for uid in expected
        )
        else "different"
    )


def _target_identity_status(
    attempt: AuditAttempt, snapshot: MetagraphSnapshot, validator_uid: int | None
) -> IdentityStatus:
    if validator_uid is None:
        return "validator_missing"
    by_hotkey = {neuron.hotkey: neuron for neuron in snapshot.neurons}
    for weight in attempt.weights:
        current = by_hotkey.get(weight.hotkey)
        if current is None or not current.active or current.uid != weight.uid:
            return "changed"
    return "exact"


async def reconcile_weight_attempt(
    *,
    audit_state_path: str,
    chain: ReconciliationChain,
    network: str,
    netuid: int,
    validator_hotkey: str,
    attempt_id: str | None = None,
) -> WeightReconciliationReport:
    """Observe current finalized evidence without changing the audit ledger."""

    state = load_audit_state_readonly(audit_state_path)
    attempt = _select_attempt(state, attempt_id)
    if (
        attempt.network != network
        or attempt.netuid != netuid
        or attempt.validator_hotkey != validator_hotkey
    ):
        raise WeightReconciliationError(
            "audit_identity_mismatch", "audit attempt differs from configured chain identity"
        )
    opened = False
    try:
        try:
            await chain.open()
            opened = True
            snapshot = await chain.sync()
        except Exception as exc:
            raise WeightReconciliationError(
                "chain_evidence_unavailable", "finalized chain evidence is unavailable"
            ) from exc
        hotkeys = [neuron.hotkey for neuron in snapshot.neurons]
        uids = [neuron.uid for neuron in snapshot.neurons]
        if len(set(hotkeys)) != len(hotkeys) or len(set(uids)) != len(uids):
            raise WeightReconciliationError(
                "chain_evidence_invalid", "finalized metagraph identity is ambiguous"
            )
        validator = snapshot.by_hotkey(validator_hotkey)
        validator_uid = (
            None
            if validator is None or not validator.active or not validator.validator_permit
            else validator.uid
        )
        expected = {weight.uid: weight.weight for weight in attempt.weights}
        observed: dict[int, float] | None = None
        relation: EvidenceRelation = "unavailable"
        if validator_uid is not None:
            try:
                observed = await chain.validator_weights(snapshot.block, validator_uid)
            except Exception as exc:
                raise WeightReconciliationError(
                    "chain_evidence_unavailable", "finalized validator weights are unavailable"
                ) from exc
            relation = _row_relation(expected, observed)
        identity_status = _target_identity_status(attempt, snapshot, validator_uid)
    finally:
        if opened:
            with suppress(Exception):
                await chain.close()

    if attempt.status == "failed" and not attempt.submission_started:
        retry_disposition: RetryDisposition = "eligible_pre_send"
        conclusion = "durable audit proves submission never started"
        alert_required = False
    elif attempt.status == "confirmed":
        retry_disposition = "blocked_requires_operator"
        conclusion = "durable audit records finalized submission"
        alert_required = False
    elif relation == "consistent":
        retry_disposition = "blocked_requires_operator"
        conclusion = "current row is consistent with the attempt but is not proof of inclusion"
        alert_required = True
    elif relation == "different":
        retry_disposition = "blocked_requires_operator"
        conclusion = "current row differs but may have been overwritten after the attempt"
        alert_required = True
    else:
        retry_disposition = "blocked_requires_operator"
        conclusion = "validator identity is unavailable; submission outcome remains unresolved"
        alert_required = True

    return WeightReconciliationReport(
        audit_digest_sha256=state.digest_sha256,
        attempt_id=attempt.attempt_id,
        attempt_status=attempt.status,
        submission_started=attempt.submission_started,
        network=network,
        netuid=netuid,
        validator_hotkey=validator_hotkey,
        evidence_block=snapshot.block,
        validator_uid=validator_uid,
        target_identity_status=identity_status,
        evidence_relation=relation,
        expected_row_digest_sha256=_row_digest(expected),
        observed_row_digest_sha256=None if observed is None else _row_digest(observed),
        retry_disposition=retry_disposition,
        conclusion=conclusion,
        alert_required=alert_required,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit-state", required=True)
    parser.add_argument("--attempt-id")
    parser.add_argument("--subtensor-network", default=os.getenv("BT_NETWORK", "finney"))
    parser.add_argument("--netuid", type=int, required=True)
    parser.add_argument("--validator-hotkey", required=True)
    parser.add_argument("--rpc-endpoint", action="append", default=[], required=True)
    parser.add_argument("--rpc-max-finalized-lag", type=int, default=8)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    try:
        if len(args.rpc_endpoint) < 2:
            raise WeightReconciliationError(
                "rpc_configuration_invalid", "reconciliation requires at least two RPCs"
            )
        try:
            chain = build_chain_query(
                network=args.subtensor_network,
                netuid=args.netuid,
                rpc_endpoints=args.rpc_endpoint,
                max_finalized_lag=args.rpc_max_finalized_lag,
                alert_sink=json_stderr_alert,
            )
        except ValueError as exc:
            raise WeightReconciliationError(
                "rpc_configuration_invalid", "reconciliation RPC configuration is invalid"
            ) from exc
        report = asyncio.run(
            reconcile_weight_attempt(
                audit_state_path=args.audit_state,
                chain=chain,
                network=args.subtensor_network,
                netuid=args.netuid,
                validator_hotkey=args.validator_hotkey,
                attempt_id=args.attempt_id,
            )
        )
    except WeightReconciliationError as exc:
        print(
            json.dumps(
                {"error_code": exc.code, "status": "rejected"},
                sort_keys=True,
                separators=(",", ":"),
            ),
            file=sys.stderr,
        )
        raise SystemExit(2) from None
    sys.stdout.buffer.write(report.canonical_bytes())
    if report.alert_required:
        raise SystemExit(3)


if __name__ == "__main__":
    main()
