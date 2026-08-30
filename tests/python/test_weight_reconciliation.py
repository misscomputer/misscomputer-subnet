# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from misscomputer_subnet import weight_reconciliation as reconciliation_module
from misscomputer_subnet.chain import MetagraphSnapshot, NeuronRecord
from misscomputer_subnet.weight_executor import (
    AuditAttempt,
    AuditReceipt,
    AuditState,
    ExecutionVector,
    ExecutionWeight,
    execution_attempt_key,
)
from misscomputer_subnet.weight_reconciliation import (
    WeightReconciliationError,
    load_audit_state_readonly,
    reconcile_weight_attempt,
)

VALIDATOR = "validator-hotkey"
MINER_A = "miner-a-hotkey"
MINER_B = "miner-b-hotkey"
NOW = "2026-08-25T00:00:00.000000Z"
ROOT = Path(__file__).resolve().parents[2]


class CliReport:
    def __init__(self, *, alert_required: bool) -> None:
        self.alert_required = alert_required

    def canonical_bytes(self) -> bytes:
        return b'{"status":"ok"}\n'


def snapshot(
    *, validator: bool = True, validator_permit: bool = True, rebound: bool = False
) -> MetagraphSnapshot:
    neurons: list[NeuronRecord] = []
    if validator:
        neurons.append(NeuronRecord(0, VALIDATOR, validator_permit, 100.0, None))
    neurons.extend(
        (
            NeuronRecord(13 if rebound else 3, MINER_A, False, 10.0, "1.1.1.1:8091"),
            NeuronRecord(9, MINER_B, False, 11.0, "8.8.8.8:8091"),
        )
    )
    return MetagraphSnapshot(
        network="finney",
        netuid=24,
        block=110,
        tempo=20,
        neurons=tuple(neurons),
        finalized=True,
    )


def attempt(
    *,
    status: str = "ambiguous",
    submission_started: bool = True,
    attempt_id: str = "a" * 64,
) -> AuditAttempt:
    weights = (
        ExecutionWeight(MINER_A, 3, 3, 0.4),
        ExecutionWeight(MINER_B, 9, 9, 0.6),
    )
    vector = ExecutionVector(
        plan_digest_sha256="b" * 64,
        network="finney",
        netuid=24,
        validator_hotkey=VALIDATOR,
        version_key=2,
        weights=weights,
        omitted=(),
    )
    if status == "in_progress":
        receipt = None
    elif status == "confirmed":
        receipt = AuditReceipt("confirmed", "105-0001", None)
    elif status == "failed":
        receipt = AuditReceipt(
            "definite_failure" if submission_started else "pre_send_failure",
            None,
            "chain_rejected" if submission_started else "snapshot_changed",
        )
    else:
        receipt = AuditReceipt("ambiguous", None, "submission_timeout")
    return AuditAttempt(
        attempt_id=attempt_id,
        attempt_key=execution_attempt_key("b" * 64, vector.digest_sha256),
        plan_digest_sha256="b" * 64,
        execution_digest_sha256=vector.digest_sha256,
        network="finney",
        netuid=24,
        validator_hotkey=VALIDATOR,
        version_key=2,
        preflight_block=100,
        send_check_block=101 if submission_started else None,
        status=status,  # type: ignore[arg-type]
        submission_started=submission_started,
        started_at=NOW,
        updated_at=NOW,
        weights=weights,
        omitted=(),
        receipt=receipt,
    )


def persist_audit(tmp_path: Path, *attempts: AuditAttempt) -> Path:
    path = tmp_path / "audit.json"
    path.write_bytes(AuditState(tuple(attempts)).canonical_bytes())
    path.chmod(0o600)
    return path


class EvidenceChain:
    def __init__(
        self,
        *,
        view: MetagraphSnapshot | None = None,
        row: dict[int, float] | None = None,
    ) -> None:
        self.view = view or snapshot()
        self.row = row or {3: 0.4, 9: 0.6}
        self.open_count = 0
        self.close_count = 0
        self.reads: list[tuple[int, int]] = []

    async def open(self) -> None:
        self.open_count += 1

    async def close(self) -> None:
        self.close_count += 1

    async def sync(self) -> MetagraphSnapshot:
        return self.view

    async def validator_weights(self, block: int, validator_uid: int) -> dict[int, float]:
        self.reads.append((block, validator_uid))
        return self.row


async def test_ambiguous_matching_row_remains_blocked_and_alerting(tmp_path: Path) -> None:
    path = persist_audit(tmp_path, attempt())
    chain = EvidenceChain()

    report = await reconcile_weight_attempt(
        audit_state_path=str(path),
        chain=chain,
        network="finney",
        netuid=24,
        validator_hotkey=VALIDATOR,
    )

    assert report.evidence_relation == "consistent"
    assert report.target_identity_status == "exact"
    assert report.retry_disposition == "blocked_requires_operator"
    assert report.alert_required is True
    assert "not proof" in report.conclusion
    assert chain.reads == [(110, 0)]
    assert chain.open_count == chain.close_count == 1
    assert report.canonical_bytes().endswith(b"\n")
    assert report.document()["digest_sha256"] == report.digest_sha256


async def test_different_row_cannot_prove_non_submission(tmp_path: Path) -> None:
    path = persist_audit(tmp_path, attempt())
    chain = EvidenceChain(row={3: 0.5, 9: 0.5})

    report = await reconcile_weight_attempt(
        audit_state_path=str(path),
        chain=chain,
        network="finney",
        netuid=24,
        validator_hotkey=VALIDATOR,
    )

    assert report.evidence_relation == "different"
    assert report.retry_disposition == "blocked_requires_operator"
    assert "overwritten" in report.conclusion


async def test_pre_send_failure_is_the_only_retry_eligible_result(tmp_path: Path) -> None:
    path = persist_audit(tmp_path, attempt(status="failed", submission_started=False))

    report = await reconcile_weight_attempt(
        audit_state_path=str(path),
        chain=EvidenceChain(),
        network="finney",
        netuid=24,
        validator_hotkey=VALIDATOR,
    )

    assert report.retry_disposition == "eligible_pre_send"
    assert report.alert_required is False
    assert "never started" in report.conclusion


async def test_rebound_target_is_reported_without_weakening_block(tmp_path: Path) -> None:
    path = persist_audit(tmp_path, attempt())

    report = await reconcile_weight_attempt(
        audit_state_path=str(path),
        chain=EvidenceChain(view=snapshot(rebound=True)),
        network="finney",
        netuid=24,
        validator_hotkey=VALIDATOR,
    )

    assert report.target_identity_status == "changed"
    assert report.retry_disposition == "blocked_requires_operator"


async def test_missing_validator_produces_unavailable_evidence(tmp_path: Path) -> None:
    path = persist_audit(tmp_path, attempt())
    chain = EvidenceChain(view=snapshot(validator=False))

    report = await reconcile_weight_attempt(
        audit_state_path=str(path),
        chain=chain,
        network="finney",
        netuid=24,
        validator_hotkey=VALIDATOR,
    )

    assert report.validator_uid is None
    assert report.target_identity_status == "validator_missing"
    assert report.evidence_relation == "unavailable"
    assert chain.reads == []


async def test_validator_without_permit_produces_unavailable_evidence(tmp_path: Path) -> None:
    path = persist_audit(tmp_path, attempt())
    chain = EvidenceChain(view=snapshot(validator_permit=False))

    report = await reconcile_weight_attempt(
        audit_state_path=str(path),
        chain=chain,
        network="finney",
        netuid=24,
        validator_hotkey=VALIDATOR,
    )

    assert report.validator_uid is None
    assert report.target_identity_status == "validator_missing"
    assert chain.reads == []


async def test_explicit_attempt_selection_and_identity_binding(tmp_path: Path) -> None:
    first = attempt(status="failed", submission_started=False, attempt_id="a" * 64)
    second = attempt(attempt_id="c" * 64)
    path = persist_audit(tmp_path, first, second)

    report = await reconcile_weight_attempt(
        audit_state_path=str(path),
        chain=EvidenceChain(),
        network="finney",
        netuid=24,
        validator_hotkey=VALIDATOR,
        attempt_id=first.attempt_id,
    )
    assert report.attempt_id == first.attempt_id
    assert report.retry_disposition == "eligible_pre_send"

    with pytest.raises(WeightReconciliationError) as error:
        await reconcile_weight_attempt(
            audit_state_path=str(path),
            chain=EvidenceChain(),
            network="finney",
            netuid=25,
            validator_hotkey=VALIDATOR,
        )
    assert error.value.code == "audit_identity_mismatch"


def test_readonly_loader_does_not_create_or_change_files(tmp_path: Path) -> None:
    path = persist_audit(tmp_path, attempt())
    before = path.stat()
    names_before = set(os.listdir(tmp_path))

    state = load_audit_state_readonly(path)

    after = path.stat()
    assert state.attempts[0].attempt_id == "a" * 64
    assert set(os.listdir(tmp_path)) == names_before
    assert (before.st_dev, before.st_ino, before.st_mtime_ns, before.st_ctime_ns) == (
        after.st_dev,
        after.st_ino,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )


def test_readonly_loader_rejects_symlink_and_missing_path_without_creation(tmp_path: Path) -> None:
    path = persist_audit(tmp_path, attempt())
    symlink = tmp_path / "audit-link.json"
    symlink.symlink_to(path)
    with pytest.raises(WeightReconciliationError) as error:
        load_audit_state_readonly(symlink)
    assert error.value.code == "audit_state_invalid"

    missing = tmp_path / "missing.json"
    with pytest.raises(WeightReconciliationError) as error:
        load_audit_state_readonly(missing)
    assert error.value.code == "audit_state_unavailable"
    assert not missing.exists()


def test_committed_reconciliation_fixture_matches_schema() -> None:
    schema = json.loads(
        (ROOT / "contracts/schemas/weight-reconciliation-report.v1.schema.json").read_text()
    )
    fixture = json.loads(
        (ROOT / "contracts/fixtures/weight-reconciliation-report.v1.json").read_text()
    )
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(fixture)


def cli_args(tmp_path: Path, *endpoints: str) -> list[str]:
    args = [
        "misscomputer-weight-reconcile",
        "--audit-state",
        str(tmp_path / "audit.json"),
        "--netuid",
        "24",
        "--validator-hotkey",
        VALIDATOR,
    ]
    for endpoint in endpoints:
        args.extend(("--rpc-endpoint", endpoint))
    return args


def test_reconciliation_cli_rejects_duplicate_rpc_identity_with_exit_two(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    first = "wss://RPC.example.invalid"
    second = "wss://rpc.example.invalid:443/"
    monkeypatch.setattr(reconciliation_module.sys, "argv", cli_args(tmp_path, first, second))

    with pytest.raises(SystemExit) as exit_info:
        reconciliation_module.main()

    assert exit_info.value.code == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == '{"error_code":"rpc_configuration_invalid","status":"rejected"}\n'
    assert first not in captured.err
    assert second not in captured.err
    assert str(tmp_path) not in captured.err


@pytest.mark.parametrize(("alert_required", "exit_code"), [(False, None), (True, 3)])
def test_reconciliation_cli_report_exit_behavior(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    alert_required: bool,
    exit_code: int | None,
) -> None:
    chain = EvidenceChain()

    async def fake_reconcile(**kwargs: object) -> CliReport:
        assert kwargs["chain"] is chain
        return CliReport(alert_required=alert_required)

    monkeypatch.setattr(
        reconciliation_module.sys,
        "argv",
        cli_args(tmp_path, "wss://one.example.invalid", "wss://two.example.invalid"),
    )
    monkeypatch.setattr(reconciliation_module, "build_chain_query", lambda **_kwargs: chain)
    monkeypatch.setattr(reconciliation_module, "reconcile_weight_attempt", fake_reconcile)

    if exit_code is None:
        reconciliation_module.main()
    else:
        with pytest.raises(SystemExit) as exit_info:
            reconciliation_module.main()
        assert exit_info.value.code == exit_code

    captured = capsys.readouterr()
    assert captured.out == '{"status":"ok"}\n'
    assert captured.err == ""
