# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import asyncio
import json
import math
import os
import stat
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, FormatChecker

import misscomputer_subnet.weight_executor as executor_module
import misscomputer_subnet.weight_plan as weight_plan_module
from misscomputer_subnet.chain import MetagraphSnapshot, NeuronRecord
from misscomputer_subnet.weight_executor import (
    EXECUTION_ACK_ENV,
    EXECUTION_ACK_VALUE,
    AuditStateError,
    AuditStateStore,
    ExecutionVector,
    ExecutorConfig,
    SubmissionResult,
    WeightExecutionError,
    derive_execution_vector,
    parse_audit_state,
    run_weight_executor,
)
from misscomputer_subnet.weight_plan import (
    WeightPlan,
    WeightPlanError,
    WeightPlanTargetError,
    build_weight_plan,
    load_weight_plan,
    write_weight_plan_atomic,
)

VALIDATOR = "validator-hotkey"
MINER_A = "miner-a-hotkey"
MINER_B = "miner-b-hotkey"
MINER_C = "miner-c-hotkey"
ROOT = Path(__file__).resolve().parents[2]
FIXED_TIME = "2026-08-24T12:00:00.000000Z"


def metagraph(
    *,
    block: int = 101,
    neurons: tuple[NeuronRecord, ...] | None = None,
    network: str = "finney",
    netuid: int = 24,
    finalized: bool = True,
) -> MetagraphSnapshot:
    return MetagraphSnapshot(
        network=network,
        netuid=netuid,
        block=block,
        tempo=20,
        neurons=neurons
        or (
            NeuronRecord(0, VALIDATOR, True, 2_000.0, None),
            NeuronRecord(3, MINER_B, False, 11.0, "1.1.1.1:8091"),
            NeuronRecord(9, MINER_A, False, 10.0, "8.8.8.8:8091"),
        ),
        finalized=finalized,
    )


def make_plan(*, three: bool = False) -> WeightPlan:
    neurons = list(metagraph().neurons)
    rows: list[dict[str, object]] = [
        {"miner_hotkey": MINER_A, "weight": 0.2},
        {"miner_hotkey": MINER_B, "weight": 0.3},
    ]
    if three:
        neurons.append(NeuronRecord(12, MINER_C, False, 12.0, "9.9.9.9:8091"))
        rows.append({"miner_hotkey": MINER_C, "weight": 0.5})
    return build_weight_plan(
        snapshot=metagraph(neurons=tuple(neurons)),
        validator_hotkey=VALIDATOR,
        rows=rows,
        version_key=2,
    )


def persist_plan(tmp_path: Path, plan: WeightPlan | None = None) -> tuple[WeightPlan, Path]:
    value = plan or make_plan()
    target = tmp_path / "plan.json"
    write_weight_plan_atomic(value, target)
    return value, target


class SequenceChain:
    def __init__(
        self,
        *snapshots: MetagraphSnapshot,
        commit_reveal: tuple[bool, ...] = (),
    ) -> None:
        self.snapshots = list(snapshots)
        self.commit_reveal = list(commit_reveal)
        self.open_count = 0
        self.close_count = 0
        self.sync_count = 0
        self.commit_reveal_blocks: list[int] = []

    async def open(self) -> None:
        self.open_count += 1

    async def close(self) -> None:
        self.close_count += 1

    async def sync(self) -> MetagraphSnapshot:
        self.sync_count += 1
        if not self.snapshots:
            raise RuntimeError("no mock snapshot")
        if len(self.snapshots) == 1:
            return self.snapshots[0]
        return self.snapshots.pop(0)

    async def commit_reveal_enabled(self, block: int) -> bool:
        self.commit_reveal_blocks.append(block)
        if not self.commit_reveal:
            return False
        if len(self.commit_reveal) == 1:
            return self.commit_reveal[0]
        return self.commit_reveal.pop(0)


class FakeSubmitter:
    def __init__(
        self,
        *,
        hotkey: str = VALIDATOR,
        result: SubmissionResult | None = None,
        error: BaseException | None = None,
        delay: float = 0.0,
    ) -> None:
        self.hotkey = hotkey
        self.result = result or SubmissionResult(True, "103-2")
        self.error = error
        self.delay = delay
        self.open_count = 0
        self.close_count = 0
        self.submit_count = 0
        self.vectors: list[ExecutionVector] = []

    async def open(self) -> None:
        self.open_count += 1

    async def close(self) -> None:
        self.close_count += 1

    async def submit(self, vector: ExecutionVector) -> SubmissionResult:
        self.submit_count += 1
        self.vectors.append(vector)
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.error is not None:
            raise self.error
        return self.result


class SimulatedCrash(BaseException):
    pass


def execute_config(
    plan: WeightPlan,
    path: Path,
    audit: Path,
    **updates: object,
) -> ExecutorConfig:
    config = ExecutorConfig(
        plan_path=str(path),
        network="finney",
        netuid=24,
        validator_hotkey=VALIDATOR,
        execute=True,
        confirm_network="finney",
        confirm_netuid=24,
        confirm_plan_digest=plan.digest_sha256,
        audit_state_path=str(audit),
        submission_timeout_seconds=1.0,
    )
    return replace(config, **updates)


def acknowledged() -> dict[str, str]:
    return {EXECUTION_ACK_ENV: EXECUTION_ACK_VALUE}


def test_safe_plan_loader_requires_exact_canonical_digest_and_inode(tmp_path: Path) -> None:
    candidate, target = persist_plan(tmp_path)
    assert load_weight_plan(target) == candidate

    document = candidate.document()
    document["network"] = "tampered"
    target.write_text(json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n")
    target.chmod(0o600)
    with pytest.raises(WeightPlanError, match="digest"):
        load_weight_plan(target)

    target.write_bytes(candidate.canonical_bytes().replace(b'"netuid":24', b'"netuid": 24'))
    target.chmod(0o600)
    with pytest.raises(WeightPlanError, match="canonical"):
        load_weight_plan(target)


@pytest.mark.parametrize(
    "endpoint",
    [
        "wss://user:password@example.invalid",
        "wss://example.invalid/ws",
        "wss://example.invalid?token=secret",
        "wss://example.invalid#secret",
        "finney?token=secret",
        "user:password@example.invalid",
    ],
)
def test_network_identity_rejects_credential_or_token_bearing_endpoints(endpoint: str) -> None:
    with pytest.raises(WeightPlanError, match="credential-free"):
        build_weight_plan(
            snapshot=metagraph(network=endpoint),
            validator_hotkey=VALIDATOR,
            rows=[
                {"miner_hotkey": MINER_A, "weight": 0.4},
                {"miner_hotkey": MINER_B, "weight": 0.6},
            ],
            version_key=2,
        )

    with pytest.raises(WeightExecutionError) as error:
        ExecutorConfig(
            plan_path="plan.json",
            network=endpoint,
            netuid=24,
            validator_hotkey=VALIDATOR,
        )
    assert error.value.code == "invalid_identity"


def test_network_identity_accepts_public_alias_and_plain_websocket_endpoint() -> None:
    for network in ("finney", "wss://rpc.example.invalid:443", "ws://127.0.0.1:9944"):
        candidate = build_weight_plan(
            snapshot=metagraph(network=network),
            validator_hotkey=VALIDATOR,
            rows=[
                {"miner_hotkey": MINER_A, "weight": 0.4},
                {"miner_hotkey": MINER_B, "weight": 0.6},
            ],
            version_key=2,
        )
        assert candidate.network == network


@pytest.mark.parametrize(
    "mutation",
    [
        (b'"version_key":2', b'"version_key":' + b"9" * 5_000),
        (b'"weight":0.6', b'"weight":' + b"9" * 400),
    ],
)
def test_malformed_huge_json_numbers_return_one_sanitized_cli_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    mutation: tuple[bytes, bytes],
) -> None:
    target = tmp_path / "plan.json"
    raw = make_plan().canonical_bytes().replace(*mutation, 1)
    target.write_bytes(raw)
    target.chmod(0o600)
    monkeypatch.setattr(
        executor_module.sys,
        "argv",
        [
            "misscomputer-weight-executor",
            "--plan",
            str(target),
            "--subtensor-network",
            "finney",
            "--netuid",
            "24",
            "--validator-hotkey",
            VALIDATOR,
        ],
    )

    with pytest.raises(SystemExit) as exit_info:
        executor_module.main()

    assert exit_info.value.code == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == '{"error_code":"invalid_plan","status":"rejected"}\n'
    assert str(tmp_path) not in captured.err
    assert "Traceback" not in captured.err


def test_safe_plan_loader_rejects_mode_links_symlinks_and_read_race(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate, target = persist_plan(tmp_path)
    target.chmod(0o644)
    with pytest.raises(WeightPlanTargetError, match="0600"):
        load_weight_plan(target)

    target.chmod(0o600)
    hardlink = tmp_path / "hardlink.json"
    os.link(target, hardlink)
    with pytest.raises(WeightPlanTargetError, match="hard links"):
        load_weight_plan(target)
    hardlink.unlink()

    victim = tmp_path / "victim.json"
    target.replace(victim)
    symlink = tmp_path / "plan.json"
    symlink.symlink_to(victim)
    with pytest.raises(WeightPlanTargetError):
        load_weight_plan(symlink)
    symlink.unlink()
    victim.replace(target)

    real_read = weight_plan_module._read_existing

    def replace_after_read(directory_fd: int, name: str, expected: os.stat_result) -> bytes:
        rendered = real_read(directory_fd, name, expected)
        replacement = tmp_path / "replacement.json"
        replacement.write_bytes(candidate.canonical_bytes())
        replacement.chmod(0o600)
        replacement.replace(target)
        return rendered

    monkeypatch.setattr(weight_plan_module, "_read_existing", replace_after_read)
    with pytest.raises(WeightPlanTargetError, match="changed"):
        load_weight_plan(target)


def test_plan_object_rejects_validator_self_weight() -> None:
    base = make_plan()
    with pytest.raises(WeightPlanError, match="validator"):
        replace(
            base,
            weights=(replace(base.weights[0], hotkey=VALIDATOR), base.weights[1]),
        )


def test_hotkey_identity_drives_same_moved_vanished_and_replacement_resolution() -> None:
    plan = make_plan()
    same = derive_execution_vector(
        plan,
        metagraph(block=102),
        network="finney",
        netuid=24,
        validator_hotkey=VALIDATOR,
    )
    assert [(item.hotkey, item.planned_uid, item.uid) for item in same.weights] == [
        (MINER_B, 3, 3),
        (MINER_A, 9, 9),
    ]
    assert [item.weight for item in same.weights] == pytest.approx([0.6, 0.4])

    churned = metagraph(
        block=103,
        neurons=(
            NeuronRecord(0, VALIDATOR, True, 2_000.0, None),
            NeuronRecord(7, MINER_B, False, 11.0, "1.1.1.1:8091"),
            NeuronRecord(9, "replacement-hotkey", False, 12.0, "9.9.9.9:8091"),
        ),
    )
    adjusted = derive_execution_vector(
        plan,
        churned,
        network="finney",
        netuid=24,
        validator_hotkey=VALIDATOR,
    )
    assert [
        (item.hotkey, item.planned_uid, item.uid, item.weight) for item in adjusted.weights
    ] == [(MINER_B, 3, 7, 1.0)]
    assert [(item.hotkey, item.planned_uid) for item in adjusted.omitted] == [(MINER_A, 9)]
    assert all(item.hotkey != "replacement-hotkey" for item in adjusted.weights)
    assert adjusted.digest_sha256 == (
        "e123d3ce5fb3f3d16aed0b08c669f29933f84e2ab23d25efd38b63203d753ac2"
    )


def test_renormalization_and_digest_are_deterministic_across_snapshot_order() -> None:
    plan = make_plan(three=True)
    records = (
        NeuronRecord(0, VALIDATOR, True, 2_000.0, None),
        NeuronRecord(18, MINER_A, False, 10.0, "8.8.8.8:8091"),
        NeuronRecord(5, MINER_C, False, 12.0, "9.9.9.9:8091"),
        NeuronRecord(3, "replacement-hotkey", False, 11.0, "1.1.1.1:8091"),
    )
    first = derive_execution_vector(
        plan,
        metagraph(block=103, neurons=records),
        network="finney",
        netuid=24,
        validator_hotkey=VALIDATOR,
    )
    second = derive_execution_vector(
        plan,
        metagraph(block=104, neurons=tuple(reversed(records))),
        network="finney",
        netuid=24,
        validator_hotkey=VALIDATOR,
    )
    assert first == second
    assert first.digest_sha256 == second.digest_sha256
    assert [(item.hotkey, item.uid) for item in first.weights] == [(MINER_C, 5), (MINER_A, 18)]
    assert [item.weight for item in first.weights] == pytest.approx([5 / 7, 2 / 7])
    assert math.fsum(item.weight for item in first.weights) == 1.0
    assert [(item.hotkey, item.planned_uid) for item in first.omitted] == [(MINER_B, 3)]


def test_no_remaining_hotkey_and_validator_safety_checks_fail_closed() -> None:
    plan = make_plan()
    only_validator = metagraph(
        block=102,
        neurons=(NeuronRecord(0, VALIDATOR, True, 2_000.0, None),),
    )
    with pytest.raises(WeightExecutionError, match="no valid planned"):
        derive_execution_vector(
            plan,
            only_validator,
            network="finney",
            netuid=24,
            validator_hotkey=VALIDATOR,
        )

    no_permit = replace(
        metagraph(block=102),
        neurons=(replace(metagraph().neurons[0], validator_permit=False), *metagraph().neurons[1:]),
    )
    with pytest.raises(WeightExecutionError) as error:
        derive_execution_vector(
            plan,
            no_permit,
            network="finney",
            netuid=24,
            validator_hotkey=VALIDATOR,
        )
    assert error.value.code == "validator_not_permitted"

    with pytest.raises(WeightExecutionError) as error:
        derive_execution_vector(
            plan,
            metagraph(block=106),
            network="finney",
            netuid=24,
            validator_hotkey=VALIDATOR,
        )
    assert error.value.code == "expired_plan"

    with pytest.raises(WeightExecutionError) as error:
        derive_execution_vector(
            plan,
            metagraph(block=102, finalized=False),
            network="finney",
            netuid=24,
            validator_hotkey=VALIDATOR,
        )
    assert error.value.code == "unfinalized_chain_state"


@pytest.mark.parametrize(
    ("plan_value", "snapshot", "network", "netuid", "validator", "code"),
    [
        (
            make_plan(),
            metagraph(block=102, network="test"),
            "finney",
            24,
            VALIDATOR,
            "wrong_network",
        ),
        (make_plan(), metagraph(block=102, netuid=25), "finney", 24, VALIDATOR, "wrong_netuid"),
        (
            make_plan(),
            metagraph(
                block=102,
                neurons=(
                    NeuronRecord(0, "other-validator", True, 2_000.0, None),
                    *metagraph().neurons[1:],
                ),
            ),
            "finney",
            24,
            VALIDATOR,
            "validator_not_permitted",
        ),
        (
            replace(make_plan(), version_key=3),
            metagraph(block=102),
            "finney",
            24,
            VALIDATOR,
            "unsupported_version_key",
        ),
    ],
)
def test_wrong_chain_identity_validator_and_version_key_are_rejected(
    plan_value: WeightPlan,
    snapshot: MetagraphSnapshot,
    network: str,
    netuid: int,
    validator: str,
    code: str,
) -> None:
    with pytest.raises(WeightExecutionError) as error:
        derive_execution_vector(
            plan_value,
            snapshot,
            network=network,
            netuid=netuid,
            validator_hotkey=validator,
        )
    assert error.value.code == code


@pytest.mark.asyncio
async def test_default_dry_run_never_constructs_signer_or_touches_audit_state(
    tmp_path: Path,
) -> None:
    plan, path = persist_plan(tmp_path)
    audit = tmp_path / "audit.json"
    chain = SequenceChain(metagraph(block=102))
    factory_calls = 0

    def poison_factory() -> FakeSubmitter:
        nonlocal factory_calls
        factory_calls += 1
        raise AssertionError("dry-run loaded signing capability")

    summary = await run_weight_executor(
        ExecutorConfig(
            plan_path=str(path),
            network="finney",
            netuid=24,
            validator_hotkey=VALIDATOR,
            audit_state_path=str(audit),
        ),
        chain=chain,
        submitter_factory=poison_factory,
        environ=acknowledged(),
    )

    assert summary.mode == "dry-run"
    assert summary.status == "validated"
    assert summary.plan_digest_sha256 == plan.digest_sha256
    assert factory_calls == 0
    assert not audit.exists()
    assert not (tmp_path / ".audit.json.lock").exists()
    assert chain.open_count == chain.close_count == 1
    assert chain.sync_count == 1
    output = summary.redacted_document()
    assert "validator_hotkey" not in output
    assert "weights" not in output
    assert MINER_A not in json.dumps(output)


@pytest.mark.asyncio
async def test_commit_reveal_enabled_fails_before_audit_or_signer_access(tmp_path: Path) -> None:
    plan, path = persist_plan(tmp_path)
    audit = tmp_path / "audit.json"
    chain = SequenceChain(metagraph(block=102), commit_reveal=(True,))
    factory_called = False

    def poison_factory() -> FakeSubmitter:
        nonlocal factory_called
        factory_called = True
        raise AssertionError("commit-reveal rejection loaded signing capability")

    with pytest.raises(WeightExecutionError) as error:
        await run_weight_executor(
            execute_config(plan, path, audit),
            chain=chain,
            submitter_factory=poison_factory,
            environ=acknowledged(),
        )

    assert error.value.code == "commit_reveal_unsupported"
    assert chain.commit_reveal_blocks == [102]
    assert factory_called is False
    assert not audit.exists()


@pytest.mark.asyncio
async def test_commit_reveal_flip_at_send_check_is_retryable_pre_send_failure(
    tmp_path: Path,
) -> None:
    plan, path = persist_plan(tmp_path)
    audit = tmp_path / "audit.json"
    chain = SequenceChain(
        metagraph(block=102),
        metagraph(block=103),
        commit_reveal=(False, True),
    )
    submitter = FakeSubmitter()

    with pytest.raises(WeightExecutionError) as error:
        await run_weight_executor(
            execute_config(plan, path, audit),
            chain=chain,
            submitter_factory=lambda: submitter,
            environ=acknowledged(),
            clock=lambda: FIXED_TIME,
        )

    assert error.value.code == "commit_reveal_unsupported"
    assert chain.commit_reveal_blocks == [102, 103]
    assert submitter.submit_count == 0
    attempt = parse_audit_state(audit.read_bytes()).attempts[0]
    assert attempt.status == "failed"
    assert attempt.submission_started is False
    assert attempt.receipt is not None
    assert attempt.receipt.error_code == "commit_reveal_unsupported"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("updates", "environment", "code"),
    [
        ({"confirm_network": None}, acknowledged(), "network_confirmation_required"),
        ({"confirm_network": "test"}, acknowledged(), "network_confirmation_required"),
        ({"confirm_netuid": None}, acknowledged(), "netuid_confirmation_required"),
        ({"confirm_netuid": 25}, acknowledged(), "netuid_confirmation_required"),
        (
            {"confirm_plan_digest": None},
            acknowledged(),
            "plan_digest_confirmation_required",
        ),
        (
            {"confirm_plan_digest": "0" * 64},
            acknowledged(),
            "plan_digest_confirmation_required",
        ),
        ({}, {}, "environment_acknowledgement_required"),
        ({}, {EXECUTION_ACK_ENV: "wrong"}, "environment_acknowledgement_required"),
        ({"audit_state_path": None}, acknowledged(), "audit_state_required"),
    ],
)
async def test_every_execute_gate_fails_before_chain_and_signer_access(
    tmp_path: Path,
    updates: dict[str, object],
    environment: dict[str, str],
    code: str,
) -> None:
    plan, path = persist_plan(tmp_path)
    audit = tmp_path / "audit.json"
    config = execute_config(plan, path, audit, **updates)
    chain = SequenceChain(metagraph(block=102))
    factory_called = False

    def poison() -> FakeSubmitter:
        nonlocal factory_called
        factory_called = True
        raise AssertionError("gate failure loaded signer")

    with pytest.raises(WeightExecutionError) as error:
        await run_weight_executor(
            config,
            chain=chain,
            submitter_factory=poison,
            environ=environment,
        )
    assert error.value.code == code
    assert chain.open_count == 0
    assert factory_called is False
    assert not audit.exists()


@pytest.mark.asyncio
async def test_execute_confirmed_persists_exact_receipt_and_is_idempotent(
    tmp_path: Path,
) -> None:
    plan, path = persist_plan(tmp_path)
    audit = tmp_path / "audit.json"
    current = metagraph(block=102)
    send = metagraph(block=103)
    submitter = FakeSubmitter(result=SubmissionResult(True, "103-2"))
    summary = await run_weight_executor(
        execute_config(plan, path, audit),
        chain=SequenceChain(current, send),
        submitter_factory=lambda: submitter,
        environ=acknowledged(),
        clock=lambda: FIXED_TIME,
    )

    assert summary.status == "confirmed"
    assert submitter.open_count == submitter.close_count == submitter.submit_count == 1
    assert len(submitter.vectors) == 1
    state = parse_audit_state(audit.read_bytes())
    assert len(state.attempts) == 1
    attempt = state.attempts[0]
    assert attempt.status == "confirmed"
    assert attempt.submission_started is True
    assert attempt.plan_digest_sha256 == plan.digest_sha256
    assert attempt.execution_digest_sha256 == summary.execution_digest_sha256
    assert attempt.receipt is not None
    assert attempt.receipt.outcome == "confirmed"
    assert attempt.receipt.extrinsic_ref == "103-2"
    assert stat.S_IMODE(audit.stat().st_mode) == 0o600
    assert audit.stat().st_nlink == 1

    second_factory_called = False

    def second_factory() -> FakeSubmitter:
        nonlocal second_factory_called
        second_factory_called = True
        return FakeSubmitter()

    with pytest.raises(AuditStateError) as error:
        await run_weight_executor(
            execute_config(plan, path, audit),
            chain=SequenceChain(metagraph(block=104)),
            submitter_factory=second_factory,
            environ=acknowledged(),
            clock=lambda: FIXED_TIME,
        )
    assert error.value.code == "idempotency_blocked"
    assert second_factory_called is False
    assert len(parse_audit_state(audit.read_bytes()).attempts) == 1


@pytest.mark.asyncio
async def test_definite_failure_is_recorded_and_never_blindly_resubmitted(
    tmp_path: Path,
) -> None:
    plan, path = persist_plan(tmp_path)
    audit = tmp_path / "audit.json"
    submitter = FakeSubmitter(result=SubmissionResult(False, "103-2", "not_authorized"))
    with pytest.raises(WeightExecutionError) as error:
        await run_weight_executor(
            execute_config(plan, path, audit),
            chain=SequenceChain(metagraph(block=102), metagraph(block=103)),
            submitter_factory=lambda: submitter,
            environ=acknowledged(),
            clock=lambda: FIXED_TIME,
        )
    assert error.value.code == "submission_failed"
    attempt = parse_audit_state(audit.read_bytes()).attempts[0]
    assert attempt.status == "failed"
    assert attempt.submission_started is True
    assert attempt.receipt is not None
    assert attempt.receipt.outcome == "definite_failure"
    assert attempt.receipt.error_code == "not_authorized"

    with pytest.raises(AuditStateError) as repeated:
        await run_weight_executor(
            execute_config(plan, path, audit),
            chain=SequenceChain(metagraph(block=104)),
            submitter_factory=lambda: FakeSubmitter(),
            environ=acknowledged(),
            clock=lambda: FIXED_TIME,
        )
    assert repeated.value.code == "idempotency_blocked"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("submitter", "expected_error"),
    [
        (FakeSubmitter(error=RuntimeError("lost RPC response")), "submission_exception"),
        (FakeSubmitter(delay=0.2), "submission_timeout"),
        (
            FakeSubmitter(result=SubmissionResult(True, None)),
            "missing_extrinsic_reference",
        ),
    ],
)
async def test_unknown_submission_results_are_ambiguous_and_block_restart(
    tmp_path: Path,
    submitter: FakeSubmitter,
    expected_error: str,
) -> None:
    plan, path = persist_plan(tmp_path)
    audit = tmp_path / "audit.json"
    timeout = 0.01 if submitter.delay else 1.0
    with pytest.raises(WeightExecutionError) as error:
        await run_weight_executor(
            execute_config(plan, path, audit, submission_timeout_seconds=timeout),
            chain=SequenceChain(metagraph(block=102), metagraph(block=103)),
            submitter_factory=lambda: submitter,
            environ=acknowledged(),
            clock=lambda: FIXED_TIME,
        )
    assert error.value.code == "submission_ambiguous"
    attempt = parse_audit_state(audit.read_bytes()).attempts[0]
    assert attempt.status == "ambiguous"
    assert attempt.submission_started is True
    assert attempt.receipt is not None
    assert attempt.receipt.error_code == expected_error

    retry = FakeSubmitter()
    with pytest.raises(AuditStateError) as repeated:
        await run_weight_executor(
            execute_config(plan, path, audit),
            chain=SequenceChain(metagraph(block=104)),
            submitter_factory=lambda: retry,
            environ=acknowledged(),
            clock=lambda: FIXED_TIME,
        )
    assert repeated.value.code == "idempotency_blocked"
    assert retry.submit_count == 0


@pytest.mark.asyncio
async def test_proven_pre_send_failure_is_retryable_and_preserves_history(
    tmp_path: Path,
) -> None:
    plan, path = persist_plan(tmp_path)
    audit = tmp_path / "audit.json"

    def unavailable_signer() -> FakeSubmitter:
        raise RuntimeError("wallet unavailable")

    with pytest.raises(WeightExecutionError) as first_error:
        await run_weight_executor(
            execute_config(plan, path, audit),
            chain=SequenceChain(metagraph(block=102)),
            submitter_factory=unavailable_signer,
            environ=acknowledged(),
            clock=lambda: FIXED_TIME,
        )
    assert first_error.value.code == "signer_unavailable"
    first = parse_audit_state(audit.read_bytes()).attempts[0]
    assert first.status == "failed"
    assert first.submission_started is False
    assert first.receipt is not None
    assert first.receipt.outcome == "pre_send_failure"

    submitter = FakeSubmitter()
    result = await run_weight_executor(
        execute_config(plan, path, audit),
        chain=SequenceChain(metagraph(block=103), metagraph(block=104)),
        submitter_factory=lambda: submitter,
        environ=acknowledged(),
        clock=lambda: "2026-08-24T12:00:01.000000Z",
    )
    assert result.status == "confirmed"
    state = parse_audit_state(audit.read_bytes())
    assert [attempt.status for attempt in state.attempts] == ["failed", "confirmed"]
    assert state.attempts[0].attempt_key == state.attempts[1].attempt_key
    assert state.attempts[0].attempt_id != state.attempts[1].attempt_id
    assert submitter.submit_count == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("crash_stage", ["factory", "submit"])
async def test_crash_cuts_leave_in_progress_and_permanently_block_automatic_retry(
    tmp_path: Path,
    crash_stage: str,
) -> None:
    plan, path = persist_plan(tmp_path)
    audit = tmp_path / "audit.json"
    crashing_submitter = FakeSubmitter(error=SimulatedCrash())

    def factory() -> FakeSubmitter:
        if crash_stage == "factory":
            raise SimulatedCrash()
        return crashing_submitter

    with pytest.raises(SimulatedCrash):
        await run_weight_executor(
            execute_config(plan, path, audit),
            chain=SequenceChain(metagraph(block=102), metagraph(block=103)),
            submitter_factory=factory,
            environ=acknowledged(),
            clock=lambda: FIXED_TIME,
        )
    attempt = parse_audit_state(audit.read_bytes()).attempts[0]
    assert attempt.status == "in_progress"
    assert attempt.receipt is None
    assert attempt.submission_started is (crash_stage == "submit")

    retry = FakeSubmitter()
    with pytest.raises(AuditStateError) as error:
        await run_weight_executor(
            execute_config(plan, path, audit),
            chain=SequenceChain(metagraph(block=104)),
            submitter_factory=lambda: retry,
            environ=acknowledged(),
            clock=lambda: FIXED_TIME,
        )
    assert error.value.code == "idempotency_blocked"
    assert retry.submit_count == 0


@pytest.mark.asyncio
async def test_crash_after_sdk_success_before_receipt_persistence_blocks_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan, path = persist_plan(tmp_path)
    audit = tmp_path / "audit.json"
    real_finish = AuditStateStore.finish_attempt

    def crash_on_confirm(
        self: AuditStateStore,
        attempt_id: str,
        **kwargs: object,
    ) -> Any:
        if kwargs.get("status") == "confirmed":
            raise SimulatedCrash()
        return real_finish(self, attempt_id, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(AuditStateStore, "finish_attempt", crash_on_confirm)
    submitter = FakeSubmitter(result=SubmissionResult(True, "103-2"))
    with pytest.raises(SimulatedCrash):
        await run_weight_executor(
            execute_config(plan, path, audit),
            chain=SequenceChain(metagraph(block=102), metagraph(block=103)),
            submitter_factory=lambda: submitter,
            environ=acknowledged(),
            clock=lambda: FIXED_TIME,
        )
    attempt = parse_audit_state(audit.read_bytes()).attempts[0]
    assert attempt.status == "in_progress"
    assert attempt.submission_started is True
    assert submitter.submit_count == 1

    monkeypatch.setattr(AuditStateStore, "finish_attempt", real_finish)
    retry = FakeSubmitter()
    with pytest.raises(AuditStateError) as error:
        await run_weight_executor(
            execute_config(plan, path, audit),
            chain=SequenceChain(metagraph(block=104)),
            submitter_factory=lambda: retry,
            environ=acknowledged(),
            clock=lambda: FIXED_TIME,
        )
    assert error.value.code == "idempotency_blocked"
    assert retry.submit_count == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("race", ["uid_move", "vanish", "permit_loss", "same_height_conflict"])
async def test_current_state_race_between_preflight_and_send_fails_before_submission(
    tmp_path: Path,
    race: str,
) -> None:
    plan, path = persist_plan(tmp_path)
    audit = tmp_path / "audit.json"
    first = metagraph(block=102)
    if race == "uid_move":
        second = metagraph(
            block=103,
            neurons=(
                first.neurons[0],
                replace(first.neurons[1], uid=7),
                first.neurons[2],
            ),
        )
    elif race == "vanish":
        second = metagraph(block=103, neurons=(first.neurons[0], first.neurons[1]))
    elif race == "permit_loss":
        second = metagraph(
            block=103,
            neurons=(replace(first.neurons[0], validator_permit=False), *first.neurons[1:]),
        )
    else:
        second = metagraph(
            block=102,
            neurons=(first.neurons[0], replace(first.neurons[1], tao_stake=99.0), first.neurons[2]),
        )
    submitter = FakeSubmitter()
    with pytest.raises(WeightExecutionError) as error:
        await run_weight_executor(
            execute_config(plan, path, audit),
            chain=SequenceChain(first, second),
            submitter_factory=lambda: submitter,
            environ=acknowledged(),
            clock=lambda: FIXED_TIME,
        )
    assert error.value.code in {"pre_send_state_changed", "validator_not_permitted"}
    assert submitter.submit_count == 0
    attempt = parse_audit_state(audit.read_bytes()).attempts[0]
    assert attempt.status == "failed"
    assert attempt.submission_started is False
    assert attempt.receipt is not None
    assert attempt.receipt.outcome == "pre_send_failure"


@pytest.mark.asyncio
async def test_stable_churn_before_preflight_executes_adjusted_vector_without_replan(
    tmp_path: Path,
) -> None:
    plan, path = persist_plan(tmp_path)
    audit = tmp_path / "audit.json"
    records = (
        NeuronRecord(0, VALIDATOR, True, 2_000.0, None),
        NeuronRecord(7, MINER_B, False, 11.0, "1.1.1.1:8091"),
        NeuronRecord(9, "replacement-hotkey", False, 12.0, "9.9.9.9:8091"),
    )
    submitter = FakeSubmitter()
    summary = await run_weight_executor(
        execute_config(plan, path, audit),
        chain=SequenceChain(
            metagraph(block=102, neurons=records),
            metagraph(block=103, neurons=tuple(reversed(records))),
        ),
        submitter_factory=lambda: submitter,
        environ=acknowledged(),
        clock=lambda: FIXED_TIME,
    )
    assert summary.status == "confirmed"
    assert summary.moved_count == 1
    assert summary.omitted_count == 1
    assert [(item.hotkey, item.uid, item.weight) for item in submitter.vectors[0].weights] == [
        (MINER_B, 7, 1.0)
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize("attack", ["mode", "hardlink", "symlink", "writable_parent"])
async def test_unsafe_audit_state_never_loads_signer(
    tmp_path: Path,
    attack: str,
) -> None:
    plan, path = persist_plan(tmp_path)
    parent = tmp_path / "state"
    parent.mkdir(mode=0o700)
    audit = parent / "audit.json"
    if attack in {"mode", "hardlink"}:
        audit.write_bytes(b"{}\n")
        audit.chmod(0o644 if attack == "mode" else 0o600)
        if attack == "hardlink":
            os.link(audit, parent / "linked.json")
    elif attack == "symlink":
        victim = parent / "victim.json"
        victim.write_bytes(b"{}\n")
        victim.chmod(0o600)
        audit.symlink_to(victim)
    else:
        parent.chmod(0o777)
    factory_called = False

    def factory() -> FakeSubmitter:
        nonlocal factory_called
        factory_called = True
        return FakeSubmitter()

    with pytest.raises(AuditStateError) as error:
        await run_weight_executor(
            execute_config(plan, path, audit),
            chain=SequenceChain(metagraph(block=102)),
            submitter_factory=factory,
            environ=acknowledged(),
            clock=lambda: FIXED_TIME,
        )
    assert error.value.code == "audit_state_unsafe"
    assert factory_called is False


def test_audit_store_lock_tamper_and_canonical_integrity(tmp_path: Path) -> None:
    audit = tmp_path / "audit.json"
    with AuditStateStore(audit):
        with pytest.raises(AuditStateError) as error:
            AuditStateStore(audit)
        assert error.value.code == "audit_state_busy"

    fixture = (ROOT / "contracts" / "fixtures" / "weight-execution-audit.v1.json").read_bytes()
    audit.write_bytes(fixture)
    audit.chmod(0o600)
    with AuditStateStore(audit) as store:
        assert len(store.state.attempts) == 1

    document = json.loads(fixture)
    document["attempts"][0]["mapping"]["weights"][0]["uid"] = 8
    audit.write_text(json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n")
    audit.chmod(0o600)
    with pytest.raises(AuditStateError) as error:
        AuditStateStore(audit)
    assert error.value.code == "audit_state_invalid"


def test_committed_audit_schema_and_golden_fixture() -> None:
    schema = json.loads(
        (ROOT / "contracts" / "schemas" / "weight-execution-audit.v1.schema.json").read_text()
    )
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    fixture = (ROOT / "contracts" / "fixtures" / "weight-execution-audit.v1.json").read_bytes()
    state = parse_audit_state(fixture)
    validator.validate(json.loads(fixture))
    assert state.digest_sha256 == (
        "96795140ecd1febe9031472891eb3b4fc3ff52f1ee52622758e1f9f43a5e37ed"
    )
    assert state.attempts[0].execution_digest_sha256 == (
        "e123d3ce5fb3f3d16aed0b08c669f29933f84e2ab23d25efd38b63203d753ac2"
    )
