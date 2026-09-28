# SPDX-License-Identifier: AGPL-3.0-only
"""The standalone signer against the real executor client, socket, ledger, and SDK path."""

from __future__ import annotations

import asyncio
import os
from contextlib import suppress
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

import bittensor as bt
import pytest
from bittensor.result import ExtrinsicResult
from test_weight_executor import (
    FIXED_TIME,
    MINER_A,
    VALIDATOR,
    SequenceChain,
    SimulatedCrash,
    acknowledged,
    execute_config,
    make_plan,
    metagraph,
)

from misscomputer_subnet.chain import NeuronRecord
from misscomputer_subnet.weight_executor import (
    AuditStateStore,
    ExecutionVector,
    ExecutionWeight,
    SubmissionResult,
    derive_execution_vector,
    run_weight_executor,
)
from misscomputer_subnet.weight_plan import WeightPlan, write_weight_plan_atomic
from misscomputer_subnet.weight_signer import (
    BittensorWeightSubmission,
    SignerConfig,
    SubmissionOutcome,
    WeightSignerError,
    require_separate_identity,
    run_weight_signer,
)
from misscomputer_subnet.weight_signer_protocol import SignerProtocolError, UnixWeightSignerClient


@dataclass(slots=True)
class Layout:
    plan: WeightPlan
    executor_plan: Path
    executor_audit: Path
    signer_plan: Path
    signer_audit: Path
    socket: Path


def layout(tmp_path: Path) -> Layout:
    plan = make_plan()
    directories = {name: tmp_path / name for name in ("exec", "signer", "run")}
    for directory in directories.values():
        directory.mkdir(mode=0o700)
    directories["run"].chmod(0o750)
    value = Layout(
        plan=plan,
        executor_plan=directories["exec"] / "plan.json",
        executor_audit=directories["exec"] / "audit.json",
        signer_plan=directories["signer"] / "plan.json",
        signer_audit=directories["signer"] / "audit.json",
        socket=directories["run"] / "s.sock",
    )
    # Independent copies: the signer never reads the executor's plan file.
    write_weight_plan_atomic(plan, value.executor_plan)
    write_weight_plan_atomic(plan, value.signer_plan)
    return value


def expected_vector(plan: WeightPlan) -> ExecutionVector:
    return derive_execution_vector(
        plan, metagraph(block=102), network="finney", netuid=24, validator_hotkey=VALIDATOR
    )


def signer_config(value: Layout, **updates: object) -> SignerConfig:
    config = SignerConfig(
        plan_path=str(value.signer_plan),
        audit_state_path=str(value.signer_audit),
        socket_path=str(value.socket),
        executor_uid=os.geteuid(),
        network="finney",
        netuid=24,
        validator_hotkey=VALIDATOR,
        confirm_plan_digest=value.plan.digest_sha256,
        confirm_execution_digest=expected_vector(value.plan).digest_sha256,
        accept_timeout_seconds=5.0,
        request_timeout_seconds=5.0,
        submission_timeout_seconds=1.0,
    )
    return replace(config, **updates)


class FakeSubmission:
    """The wallet-holding capability; records whether it was ever constructed."""

    def __init__(
        self,
        outcome: SubmissionOutcome | None = None,
        *,
        hotkey: str = VALIDATOR,
        error: BaseException | None = None,
        delay: float = 0.0,
    ) -> None:
        self.outcome = outcome or SubmissionOutcome("confirmed", "103-2")
        self.hotkey = hotkey
        self.error = error
        self.delay = delay
        self.constructed = 0
        self.opened = 0
        self.closed = 0
        self.vectors: list[ExecutionVector] = []

    def factory(self, plan: WeightPlan) -> FakeSubmission:
        del plan
        self.constructed += 1
        return self

    async def open(self) -> None:
        self.opened += 1

    async def close(self) -> None:
        self.closed += 1

    async def submit(self, vector: ExecutionVector) -> SubmissionOutcome:
        self.vectors.append(vector)
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.error is not None:
            raise self.error
        return self.outcome


def signer_chain(*blocks: int) -> SequenceChain:
    return SequenceChain(*(metagraph(block=block) for block in blocks or (101, 102)))


def signer_attempts(value: Layout) -> tuple[Any, ...]:
    with AuditStateStore(value.signer_audit) as store:
        return store.state.attempts


def client(value: Layout) -> UnixWeightSignerClient:
    return UnixWeightSignerClient(
        socket_path=str(value.socket),
        signer_uid=os.geteuid(),
        hotkey=VALIDATOR,
        timeout_seconds=5.0,
    )


async def exchange(value: Layout, vector: ExecutionVector) -> SubmissionResult:
    peer = client(value)
    await peer.open()
    try:
        return await peer.submit(vector)
    finally:
        # A dropped peer can fail the client's own writer retirement; the
        # executor reports that separately as cleanup health.
        with suppress(OSError):
            await peer.close()


async def test_executor_and_signer_submit_exactly_once_over_published_socket(
    tmp_path: Path,
) -> None:
    value = layout(tmp_path)
    submission = FakeSubmission()

    executor_result, signer_result = await asyncio.gather(
        run_weight_executor(
            execute_config(value.plan, value.executor_plan, value.executor_audit),
            chain=SequenceChain(metagraph(block=101), metagraph(block=102)),
            submitter_factory=lambda: client(value),
            environ=acknowledged(),
            clock=lambda: FIXED_TIME,
        ),
        run_weight_signer(
            signer_config(value),
            chain=signer_chain(),
            submission_factory=submission.factory,
            clock=lambda: FIXED_TIME,
        ),
    )

    assert executor_result.status == "confirmed"
    assert executor_result.extrinsic_ref == "103-2"
    assert signer_result.status == "confirmed"
    assert signer_result.extrinsic_ref == "103-2"
    assert submission.vectors == [expected_vector(value.plan)]
    assert (submission.opened, submission.closed) == (1, 1)
    (attempt,) = signer_attempts(value)
    assert attempt.status == "confirmed"
    assert attempt.submission_started is True
    assert attempt.send_check_block == 102
    assert attempt.receipt.extrinsic_ref == "103-2"
    assert attempt.execution_digest_sha256 == executor_result.execution_digest_sha256
    assert not value.socket.exists(follow_symlinks=False)


async def test_unauthorized_peer_is_dropped_without_signing(tmp_path: Path) -> None:
    value = layout(tmp_path)
    submission = FakeSubmission()
    signer = asyncio.create_task(
        run_weight_signer(
            signer_config(value, executor_uid=os.geteuid() + 1, accept_timeout_seconds=1.0),
            chain=signer_chain(),
            submission_factory=submission.factory,
        )
    )

    with pytest.raises(SignerProtocolError) as rejected:
        await exchange(value, expected_vector(value.plan))
    with pytest.raises(WeightSignerError) as timed_out:
        await signer

    assert rejected.value.code in {"signer_unavailable", "signer_protocol_invalid"}
    assert timed_out.value.code == "request_timeout"
    assert submission.constructed == 0
    assert signer_attempts(value) == ()
    assert not value.socket.exists(follow_symlinks=False)


async def test_request_vector_that_differs_from_signer_derivation_is_rejected(
    tmp_path: Path,
) -> None:
    value = layout(tmp_path)
    submission = FakeSubmission()
    forged = ExecutionVector(
        plan_digest_sha256=value.plan.digest_sha256,
        network="finney",
        netuid=24,
        validator_hotkey=VALIDATOR,
        version_key=2,
        weights=(ExecutionWeight(MINER_A, 9, 9, 1.0),),
        omitted=(),
    )

    result, signer_result = await asyncio.gather(
        exchange(value, forged),
        run_weight_signer(
            signer_config(value), chain=signer_chain(), submission_factory=submission.factory
        ),
    )

    assert result == SubmissionResult(False, None, "execution_vector_mismatch")
    assert signer_result.status == "rejected"
    assert submission.constructed == 0
    assert signer_attempts(value) == ()


MOVED = metagraph(
    block=103,
    neurons=(
        NeuronRecord(0, VALIDATOR, True, 2_000.0, None),
        NeuronRecord(3, "miner-b-hotkey", False, 11.0, "1.1.1.1:8091"),
        NeuronRecord(10, MINER_A, False, 10.0, "8.8.8.8:8091"),
    ),
)


@pytest.mark.parametrize(
    ("chain", "submission", "code"),
    [
        (
            SequenceChain(metagraph(block=102), MOVED),
            FakeSubmission(),
            "pre_send_state_changed",
        ),
        (
            SequenceChain(metagraph(block=102), commit_reveal=(False, True)),
            FakeSubmission(),
            "commit_reveal_unsupported",
        ),
        (signer_chain(), FakeSubmission(hotkey="other-hotkey"), "signer_hotkey_mismatch"),
    ],
    ids=["send-check-vector-moved", "send-check-commit-reveal", "wallet-hotkey-mismatch"],
)
async def test_pre_send_failure_after_durable_receipt_never_submits(
    tmp_path: Path,
    chain: SequenceChain,
    submission: FakeSubmission,
    code: str,
) -> None:
    value = layout(tmp_path)

    result, signer_result = await asyncio.gather(
        exchange(value, expected_vector(value.plan)),
        run_weight_signer(signer_config(value), chain=chain, submission_factory=submission.factory),
    )

    assert result == SubmissionResult(False, None, code)
    assert signer_result.error_code == code
    assert submission.vectors == []
    (attempt,) = signer_attempts(value)
    assert (attempt.status, attempt.submission_started) == ("failed", False)
    assert attempt.receipt.outcome == "pre_send_failure"
    assert attempt.receipt.error_code == code


@pytest.mark.parametrize(
    ("submission", "response_ref", "status", "outcome", "ledger_ref", "code"),
    [
        (
            FakeSubmission(SubmissionOutcome("ambiguous", "103-4", "submission_not_included")),
            "103-4",
            "ambiguous",
            "ambiguous",
            "103-4",
            "submission_not_included",
        ),
        (
            FakeSubmission(SubmissionOutcome("rejected", "103-5", "chain_rejected")),
            None,
            "failed",
            "definite_failure",
            "103-5",
            "chain_rejected",
        ),
        (
            FakeSubmission(error=RuntimeError("websocket dropped")),
            None,
            "ambiguous",
            "ambiguous",
            None,
            "submission_exception",
        ),
        (
            FakeSubmission(delay=5.0),
            None,
            "ambiguous",
            "ambiguous",
            None,
            "submission_timeout",
        ),
    ],
    ids=["ambiguous-with-ref", "included-dispatch-failure", "sdk-exception", "timeout"],
)
async def test_post_send_outcome_is_durable_and_answered_with_exact_certainty(
    tmp_path: Path,
    submission: FakeSubmission,
    response_ref: str | None,
    status: str,
    outcome: str,
    ledger_ref: str | None,
    code: str,
) -> None:
    value = layout(tmp_path)

    exchanged, signer_result = await asyncio.gather(
        exchange(value, expected_vector(value.plan)),
        run_weight_signer(
            signer_config(value), chain=signer_chain(), submission_factory=submission.factory
        ),
        return_exceptions=True,
    )

    assert not isinstance(signer_result, BaseException)
    if outcome == "ambiguous":
        assert isinstance(exchanged, SignerProtocolError)
        assert exchanged.code == "submission_ambiguous"
        assert exchanged.extrinsic_ref == response_ref
    else:
        assert exchanged == SubmissionResult(False, None, code)
    (attempt,) = signer_attempts(value)
    assert (attempt.status, attempt.submission_started) == (status, True)
    assert attempt.receipt.outcome == outcome
    assert attempt.receipt.extrinsic_ref == ledger_ref
    assert attempt.receipt.error_code == code


async def test_crash_after_send_marker_blocks_every_later_run(tmp_path: Path) -> None:
    value = layout(tmp_path)
    crashed = FakeSubmission(error=SimulatedCrash())

    exchanged, first = await asyncio.gather(
        exchange(value, expected_vector(value.plan)),
        run_weight_signer(
            signer_config(value), chain=signer_chain(), submission_factory=crashed.factory
        ),
        return_exceptions=True,
    )
    assert isinstance(first, SimulatedCrash)
    assert isinstance(exchanged, SignerProtocolError)
    (attempt,) = signer_attempts(value)
    assert (attempt.status, attempt.submission_started) == ("in_progress", True)

    retry = FakeSubmission()
    with pytest.raises(WeightSignerError) as blocked:
        await run_weight_signer(
            signer_config(value), chain=signer_chain(), submission_factory=retry.factory
        )

    assert blocked.value.code == "idempotency_blocked"
    assert retry.constructed == 0
    assert not value.socket.exists(follow_symlinks=False)
    assert len(signer_attempts(value)) == 1


def unconfirmed_plan(value: Layout) -> dict[str, object]:
    return {"confirm_plan_digest": "0" * 64}


def other_accessible_socket_directory(value: Layout) -> dict[str, object]:
    value.socket.parent.chmod(0o755)
    return {}


def existing_socket_path(value: Layout) -> dict[str, object]:
    value.socket.write_bytes(b"")
    return {}


@pytest.mark.parametrize(
    ("prepare", "code"),
    [
        (unconfirmed_plan, "plan_digest_confirmation_required"),
        (other_accessible_socket_directory, "signer_socket_unsafe"),
        (existing_socket_path, "signer_socket_exists"),
    ],
)
async def test_startup_refusals_publish_nothing(
    tmp_path: Path,
    prepare: Any,
    code: str,
) -> None:
    value = layout(tmp_path)
    updates = prepare(value)
    before = sorted(path.name for path in value.socket.parent.iterdir())
    submission = FakeSubmission()

    with pytest.raises(WeightSignerError) as refused:
        await run_weight_signer(
            signer_config(value, **updates),
            chain=signer_chain(),
            submission_factory=submission.factory,
        )

    assert refused.value.code == code
    assert sorted(path.name for path in value.socket.parent.iterdir()) == before
    assert submission.constructed == 0


def test_signer_identity_must_be_unprivileged_and_distinct() -> None:
    for signer_uid, executor_uid in ((0, 1000), (1000, 1000)):
        with pytest.raises(WeightSignerError) as refused:
            require_separate_identity(signer_uid=signer_uid, executor_uid=executor_uid)
        assert refused.value.code == "signer_identity_unsafe"
    require_separate_identity(signer_uid=1001, executor_uid=1000)


class OfflineSubstrate:
    """Transport double below the real SDK ``Client.execute`` and ``SetWeights`` code."""

    def __init__(self, *, commit_reveal: bool, result: ExtrinsicResult) -> None:
        self.commit_reveal = commit_reveal
        self.result = result
        self.submitted: list[tuple[Any, dict[str, Any]]] = []

    async def connect(self) -> None:
        return None

    async def close(self) -> None:
        return None

    async def block_number(self) -> int:
        return 1_000

    async def block_hash(self, block: int) -> str:
        del block
        return "0x" + "00" * 32

    async def block_time(self) -> float:
        return 12.0

    async def query(self, module: str, name: str, params: Any, **_: Any) -> Any:
        del module, params
        return {
            "Uids": 0,
            "CommitRevealWeightsEnabled": self.commit_reveal,
            "WeightsSetRateLimit": 0,
            "LastUpdate": [0],
            "MinAllowedWeights": 0,
            "MaxWeightsLimit": 65_535,
            "Tempo": 360,
            "RevealPeriodEpochs": 1,
            "LastEpochBlock": 900,
            "PendingEpochAt": 0,
            "SubnetEpochIndex": 2,
            "BlocksSinceLastStep": 100,
        }[name]

    async def compose(self, call: Any) -> Any:
        return call

    async def estimate_fee(self, call: Any, public: Any) -> Any:
        raise RuntimeError("fee estimation is unavailable offline")

    async def submit(self, call: Any, keypair: Any, **options: Any) -> ExtrinsicResult:
        del keypair
        self.submitted.append((call, options))
        return self.result


BLOCK_HASH = "0x" + "11" * 32


@pytest.mark.parametrize(
    ("commit_reveal", "result", "expected", "submits"),
    [
        (
            False,
            ExtrinsicResult(True, "Success", BLOCK_HASH, "1001-0003"),
            SubmissionOutcome("confirmed", "1001-0003"),
            1,
        ),
        (
            True,
            ExtrinsicResult(True, "Success", BLOCK_HASH, "1001-0003"),
            SubmissionOutcome("rejected", None, "commit_reveal_unsupported"),
            0,
        ),
        (
            False,
            ExtrinsicResult(False, "Priority is too low"),
            SubmissionOutcome("ambiguous", None, "submission_not_included"),
            1,
        ),
        (
            False,
            ExtrinsicResult(False, "SettingWeightsTooFast", BLOCK_HASH, "1001-0004"),
            SubmissionOutcome("rejected", "1001-0004", "chain_rejected"),
            1,
        ),
        (
            False,
            ExtrinsicResult(True, "Success"),
            SubmissionOutcome("ambiguous", None, "missing_extrinsic_reference"),
            1,
        ),
    ],
    ids=[
        "plaintext-confirmed",
        "commit-reveal-refused-before-signing",
        "transient-pool-failure-not-retried",
        "included-dispatch-failure",
        "success-without-reference",
    ],
)
async def test_sdk_submission_classifies_effect_through_real_execute(
    commit_reveal: bool,
    result: ExtrinsicResult,
    expected: SubmissionOutcome,
    submits: int,
) -> None:
    keypair = bt.sp_core.Keypair.create_from_uri("//Alice")
    substrate = OfflineSubstrate(commit_reveal=commit_reveal, result=result)
    submission = BittensorWeightSubmission(
        netuid=24,
        version_key=2,
        wallet_factory=lambda: (keypair, keypair.ss58_address),
        client_factory=lambda: bt.Client("finney", substrate=substrate),
    )
    vector = ExecutionVector(
        plan_digest_sha256="a" * 64,
        network="finney",
        netuid=24,
        validator_hotkey=keypair.ss58_address,
        version_key=2,
        weights=(ExecutionWeight("miner-a", 1, 1, 0.4), ExecutionWeight("miner-b", 2, 2, 0.6)),
        omitted=(),
    )

    await submission.open()
    try:
        assert await submission.submit(vector) == expected
        with pytest.raises(WeightSignerError):
            await submission.submit(vector)
    finally:
        await submission.close()

    assert len(substrate.submitted) == submits
    for call, options in substrate.submitted:
        assert call.function == "set_mechanism_weights"
        assert call.params["dests"] == [1, 2]
        assert call.params["version_key"] == 2
        assert options["wait_for_finalization"] is True
