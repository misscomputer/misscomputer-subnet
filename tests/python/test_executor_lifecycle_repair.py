# SPDX-License-Identifier: AGPL-3.0-only
"""Post-send failures exercise the real CLI, atomic store, and owned transports."""

from __future__ import annotations

import asyncio
import errno
import fcntl
import json
import os
import socket
from pathlib import Path
from typing import Any

import pytest
from test_weight_executor import (
    VALIDATOR,
    FakeSubmitter,
    SequenceChain,
    SimulatedCrash,
    acknowledged,
    execute_config,
    metagraph,
    persist_plan,
)

import misscomputer_subnet.weight_executor as executor
import misscomputer_subnet.weight_plan as weight_plan
import misscomputer_subnet.weight_signer_protocol as signer


@pytest.mark.parametrize("outcome", ["lost", "timeout", "missing", "confirmed", "rejected"])
@pytest.mark.parametrize(
    "fault",
    [
        "replace",
        "unlink",
        "directory_fsync",
        "temp_close",
        "clock",
        "write",
        "file_fsync",
        "verify",
    ],
)
@pytest.mark.parametrize("fault_type", [OSError, SimulatedCrash, asyncio.CancelledError])
def test_cli_post_send_persistence_failure_keeps_certainty_and_closes_fd(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    outcome: str,
    fault: str,
    fault_type: type[BaseException],
) -> None:
    plan, path = persist_plan(tmp_path)
    audit = tmp_path / "audit.json"
    submitted = False
    descriptors: list[int] = []
    real_prepare = executor._prepare_temporary_plan
    real_replace, real_unlink, real_fsync, real_close = (
        os.replace,
        os.unlink,
        os.fsync,
        os.close,
    )
    real_write = os.write
    real_verify = executor._verify_configured_target

    class Submitter(FakeSubmitter):
        async def submit(self, vector: executor.ExecutionVector) -> executor.SubmissionResult:
            nonlocal submitted
            submitted = True
            return await super().submit(vector)

    result = executor.SubmissionResult(
        outcome != "rejected", None if outcome == "missing" else "103-2"
    )
    submitter = Submitter(
        result=result,
        error=RuntimeError("private-error-sentinel") if outcome == "lost" else None,
        delay=0.2 if outcome == "timeout" else 0,
    )

    def prepare(*args: Any, **kwargs: Any) -> Any:
        temporary = real_prepare(*args, **kwargs)
        if submitted:
            descriptors.append(temporary.descriptor)
        return temporary

    def replace(*args: Any, **kwargs: Any) -> None:
        if submitted and fault in {"replace", "unlink"}:
            raise fault_type("private-replace-sentinel")
        real_replace(*args, **kwargs)

    def unlink(*args: Any, **kwargs: Any) -> None:
        if submitted and fault == "unlink":
            raise fault_type("private-unlink-sentinel")
        real_unlink(*args, **kwargs)

    def fsync(descriptor: int) -> None:
        if submitted and fault == "directory_fsync" and descriptor not in descriptors:
            # A prepared temp has been returned only once the file fsync succeeded.
            if descriptors:
                raise fault_type("private-fsync-sentinel")
        if submitted and fault == "file_fsync":
            raise fault_type("private-file-fsync-sentinel")
        real_fsync(descriptor)

    def close(descriptor: int) -> None:
        real_close(descriptor)
        if submitted and fault == "temp_close" and descriptor in descriptors:
            raise fault_type("private-close-sentinel")

    def write(descriptor: int, data: Any) -> int:
        if submitted and fault == "write":
            raise fault_type("private-write-sentinel")
        return real_write(descriptor, data)

    def verify(*args: Any, **kwargs: Any) -> None:
        if submitted and fault == "verify":
            raise fault_type("private-verify-sentinel")
        real_verify(*args, **kwargs)

    def clock() -> str:
        if submitted and fault == "clock":
            raise fault_type("private-clock-sentinel")
        return "2026-09-11T18:00:00.000000Z"

    argv = [
        "misscomputer-weight-executor",
        "--plan",
        str(path),
        "--subtensor-network",
        "finney",
        "--netuid",
        "24",
        "--validator-hotkey",
        VALIDATOR,
        "--execute",
        "--confirm-network",
        "finney",
        "--confirm-netuid",
        "24",
        "--confirm-plan-digest",
        plan.digest_sha256,
        "--audit-state",
        str(audit),
        "--signer-socket",
        str(tmp_path / "signer.sock"),
        "--signer-uid",
        str(os.getuid()),
        "--submission-timeout",
        "0.01" if outcome == "timeout" else "1",
    ]
    with monkeypatch.context() as patch:
        patch.setattr(executor, "_prepare_temporary_plan", prepare)
        patch.setattr(os, "replace", replace)
        patch.setattr(os, "unlink", unlink)
        patch.setattr(os, "fsync", fsync)
        patch.setattr(os, "close", close)
        patch.setattr(os, "write", write)
        patch.setattr(executor, "_verify_configured_target", verify)
        patch.setattr(executor, "_utc_now", clock)
        patch.setattr(executor.sys, "argv", argv)
        patch.setattr(
            executor, "build_chain_query", lambda **_: SequenceChain(metagraph(block=102))
        )
        patch.setattr(signer, "UnixWeightSignerClient", lambda **_: submitter)
        for key, value in acknowledged().items():
            patch.setenv(key, value)
        escaped: BaseException | None = None
        try:
            executor.main()
        except BaseException as error:
            escaped = error
        captured = capsys.readouterr()

    leaked = []
    for descriptor in descriptors:
        try:
            os.fstat(descriptor)
        except OSError as error:
            assert error.errno == errno.EBADF
        else:
            leaked.append(descriptor)
            real_close(descriptor)
    assert submitter.submit_count == 1
    with executor.AuditStateStore(audit) as store:
        assert store.blocking_attempt(plan.digest_sha256) is not None
    retry = FakeSubmitter()
    with pytest.raises(executor.AuditStateError, match="prior non-retryable"):
        asyncio.run(
            executor.run_weight_executor(
                execute_config(plan, path, audit),
                chain=SequenceChain(metagraph(block=103)),
                submitter_factory=lambda: retry,
                environ=acknowledged(),
            )
        )
    assert retry.submit_count == 0
    assert isinstance(escaped, SystemExit), type(escaped).__name__
    assert escaped.code == 2
    assert captured.out == ""
    document = json.loads(captured.err)
    assert document["status"] == (
        "confirmed"
        if outcome == "confirmed"
        else "rejected"
        if outcome == "rejected"
        else "ambiguous"
    )
    assert document["error_code"] == (
        "submission_confirmed_audit_failed"
        if outcome == "confirmed"
        else "submission_failed"
        if outcome == "rejected"
        else "submission_ambiguous"
    )
    assert document["audit_error_code"] == "audit_persistence_failed"
    assert "private-" not in captured.err
    assert not leaked, "result temp descriptor leaked when cleanup failed"


@pytest.mark.parametrize("primary", ["ambiguous", "confirmed", "crash", "cancelled"])
@pytest.mark.parametrize("close_error", [False, True])
async def test_repeated_cancellation_drains_both_owned_real_socket_adapters(
    tmp_path: Path,
    primary: str,
    close_error: bool,
) -> None:
    plan, path = persist_plan(tmp_path)
    audit = tmp_path / "audit.json"
    started = [asyncio.Event(), asyncio.Event()]
    released = [asyncio.Event(), asyncio.Event()]
    sockets = [socket.socketpair(), socket.socketpair()]
    closed: list[int] = []
    submit_entered = asyncio.Event()

    async def retire(index: int) -> None:
        started[index].set()
        await released[index].wait()
        sockets[index][0].close()
        closed.append(index)
        if close_error:
            raise SimulatedCrash()

    class Submitter(FakeSubmitter):
        async def submit(self, vector: executor.ExecutionVector) -> executor.SubmissionResult:
            submit_entered.set()
            if primary == "cancelled":
                self.submit_count += 1
                await asyncio.Event().wait()
            return await super().submit(vector)

        async def close(self) -> None:
            await retire(0)

    class Chain(SequenceChain):
        async def close(self) -> None:
            await retire(1)

    error = (
        RuntimeError("lost")
        if primary == "ambiguous"
        else SimulatedCrash()
        if primary == "crash"
        else None
    )
    submitter = Submitter(error=error)
    task = asyncio.create_task(
        executor.run_weight_executor(
            execute_config(plan, path, audit),
            chain=Chain(metagraph(block=102)),
            submitter_factory=lambda: submitter,
            environ=acknowledged(),
        )
    )
    escaped: BaseException | None = None
    summary = None
    try:
        await asyncio.wait_for(submit_entered.wait(), 1)
        if primary == "cancelled":
            task.cancel()
        for index in range(2):
            await asyncio.wait_for(started[index].wait(), 1)
            for _ in range(3):
                task.cancel()
                await asyncio.sleep(0)
            released[index].set()
        try:
            summary = await asyncio.wait_for(task, 1)
        except BaseException as caught:
            escaped = caught
        assert closed == [0, 1]
        assert all(pair[0].fileno() == -1 for pair in sockets)
        for pair in sockets:
            assert pair[1].recv(1) == b""
        assert not [
            pending
            for pending in asyncio.all_tasks()
            if pending is not asyncio.current_task() and not pending.done()
        ]
        assert submitter.submit_count == 1
        if primary == "confirmed":
            assert escaped is None
            assert summary is not None and summary.status == "confirmed"
            if close_error:
                assert summary.redacted_document()["cleanup_error_codes"] == [
                    "submitter_cleanup_failed",
                    "chain_cleanup_failed",
                ]
        elif primary == "ambiguous":
            assert isinstance(escaped, executor.WeightExecutionError)
            assert escaped.code == "submission_ambiguous"
        elif primary == "crash":
            assert escaped is error
        else:
            assert isinstance(escaped, asyncio.CancelledError)
        with executor.AuditStateStore(audit) as store:
            assert store.blocking_attempt(plan.digest_sha256) is not None
    finally:
        for event in released:
            event.set()
        if not task.done():
            task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        for pair in sockets:
            for endpoint in pair:
                endpoint.close()


@pytest.mark.parametrize("fault", ["unlock", "lock_close", "directory_close"])
def test_audit_close_attempts_every_descriptor_even_when_an_earlier_close_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fault: str,
) -> None:
    store = executor.AuditStateStore(tmp_path / "audit.json")
    lock = store._lock_descriptor
    descriptors = [lock, *store._chain.descriptors]
    real_close, real_flock = os.close, fcntl.flock

    def close(descriptor: int) -> None:
        real_close(descriptor)
        if descriptor == (lock if fault == "lock_close" else descriptors[-1]):
            if fault != "unlock":
                raise SimulatedCrash()

    def flock(descriptor: int, operation: int) -> None:
        if fault == "unlock" and operation == fcntl.LOCK_UN:
            raise SimulatedCrash()
        real_flock(descriptor, operation)

    with monkeypatch.context() as patch:
        patch.setattr(os, "close", close)
        patch.setattr(fcntl, "flock", flock)
        with pytest.raises(SimulatedCrash):
            store.close()
    leaked = []
    for descriptor in descriptors:
        try:
            os.fstat(descriptor)
        except OSError as error:
            assert error.errno == errno.EBADF
        else:
            leaked.append(descriptor)
            real_close(descriptor)
    assert not leaked
    assert store._lock_descriptor == -1
    assert store._chain.descriptors == []
    store.close()


def test_temporary_cleanup_preserves_baseexception_and_closes_fd(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    primary = SimulatedCrash()
    descriptors = []
    real_prepare = executor._prepare_temporary_plan
    with executor.AuditStateStore(tmp_path / "audit.json") as store:

        def prepare(*args: Any, **kwargs: Any) -> Any:
            temporary = real_prepare(*args, **kwargs)
            descriptors.append(temporary.descriptor)
            return temporary

        def fail_replace(*_: Any, **__: Any) -> None:
            raise primary

        def fail_unlink(*_: Any, **__: Any) -> None:
            raise OSError("cleanup-error-sentinel")

        with monkeypatch.context() as patch:
            patch.setattr(executor, "_prepare_temporary_plan", prepare)
            patch.setattr(os, "replace", fail_replace)
            patch.setattr(os, "unlink", fail_unlink)
            with pytest.raises(SimulatedCrash) as caught:
                store._persist(executor.AuditState())
        assert caught.value is primary
        for descriptor in descriptors:
            with pytest.raises(OSError) as error:
                os.fstat(descriptor)
            assert error.value.errno == errno.EBADF


@pytest.mark.parametrize("stage", ["chain", "submitter"])
@pytest.mark.parametrize("failure", [RuntimeError, SimulatedCrash, asyncio.CancelledError])
async def test_owns_adapters_before_open_returns(
    tmp_path: Path,
    stage: str,
    failure: type[BaseException],
) -> None:
    plan, path = persist_plan(tmp_path)
    chain = SequenceChain(metagraph(block=102))
    submitter = FakeSubmitter()
    original = failure()

    async def fail_open() -> None:
        raise original

    if stage == "chain":
        chain.open = fail_open  # type: ignore[method-assign]
    else:
        submitter.open = fail_open  # type: ignore[method-assign]
    with pytest.raises(BaseException) as caught:
        await executor.run_weight_executor(
            execute_config(plan, path, tmp_path / "audit.json"),
            chain=chain,
            submitter_factory=lambda: submitter,
            environ=acknowledged(),
        )
    assert chain.close_count == 1
    assert submitter.close_count == (1 if stage == "submitter" else 0)
    assert submitter.submit_count == 0
    if not issubclass(failure, Exception):
        assert caught.value is original


async def test_real_unix_signer_drains_after_response_and_repeated_cancellation(
    tmp_path: Path,
) -> None:
    plan, path = persist_plan(tmp_path)
    # Keep the AF_UNIX address below its platform path-length limit.
    socket_path = tmp_path / "s"
    close_entered, close_release, peer_eof = asyncio.Event(), asyncio.Event(), asyncio.Event()
    server_tasks: set[asyncio.Task[Any]] = set()
    sent = 0

    async def serve(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        nonlocal sent
        try:
            request = signer.SignerRequest.from_bytes(await signer.read_message(reader))
            sent += 1
            response = signer.SignerResponse(request.request_id, "confirmed", "103-2", None)
            writer.write(response.canonical_bytes())
            await writer.drain()
            assert await reader.read() == b""
            peer_eof.set()
        finally:
            writer.close()
            await writer.wait_closed()

    def accept(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        server_tasks.add(asyncio.create_task(serve(reader, writer)))

    class Client(signer.UnixWeightSignerClient):
        async def close(self) -> None:
            close_entered.set()
            await close_release.wait()
            await super().close()

    server = await asyncio.start_unix_server(accept, path=socket_path)
    socket_path.chmod(0o600)
    client = Client(
        socket_path=str(socket_path), signer_uid=os.getuid(), hotkey=VALIDATOR, timeout_seconds=1
    )
    task = asyncio.create_task(
        executor.run_weight_executor(
            execute_config(plan, path, tmp_path / "audit.json"),
            chain=SequenceChain(metagraph(block=102)),
            submitter_factory=lambda: client,
            environ=acknowledged(),
        )
    )
    try:
        await asyncio.wait_for(close_entered.wait(), 1)
        assert client._writer is not None
        transport_socket = client._writer.get_extra_info("socket")
        for _ in range(3):
            task.cancel()
            await asyncio.sleep(0)
        close_release.set()
        summary = await asyncio.wait_for(task, 1)
        await asyncio.wait_for(peer_eof.wait(), 1)
        assert summary.status == "confirmed" and sent == 1
        assert client._writer is None and client._reader is None
        assert transport_socket.fileno() == -1
    finally:
        close_release.set()
        await asyncio.gather(task, return_exceptions=True)
        await client.close()
        server.close()
        await server.wait_closed()
        await asyncio.gather(*server_tasks)
    assert all(task.done() for task in server_tasks)


@pytest.mark.parametrize("visible", [False, True])
@pytest.mark.parametrize("failure", [OSError, SimulatedCrash, asyncio.CancelledError])
def test_prepared_result_temp_is_owned_before_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    visible: bool,
    failure: type[BaseException],
) -> None:
    primary = failure("primary-sentinel")
    descriptors = []
    real_open = os.open
    real_unlink = os.unlink
    with executor.AuditStateStore(tmp_path / "audit.json") as store:

        def open_temporary(*args: Any, **kwargs: Any) -> int:
            descriptor = real_open(*args, **kwargs)
            descriptors.append(descriptor)
            return descriptor

        def fail_validate(*_: Any, **__: Any) -> None:
            raise primary

        def fail_unlink(*_: Any, **__: Any) -> None:
            raise OSError("unlink-sentinel")

        with monkeypatch.context() as patch:
            if visible:
                patch.setattr(weight_plan, "_open_unnamed_temporary", lambda _: None)
            patch.setattr(os, "open", open_temporary)
            patch.setattr(weight_plan, "_validate_temporary_name", fail_validate)
            patch.setattr(os, "unlink", fail_unlink)
            with pytest.raises(failure) as caught:
                weight_plan._prepare_temporary_plan(store._chain.parent_fd, b"result\n")
        leaked = []
        for descriptor in descriptors:
            try:
                os.fstat(descriptor)
            except OSError as error:
                assert error.errno == errno.EBADF
            else:
                leaked.append(descriptor)
                os.close(descriptor)
        for temporary in tmp_path.glob(".weight-plan.tmp-*"):
            real_unlink(temporary)
        assert caught.value is primary
        assert not leaked


@pytest.mark.parametrize("outcome", ["confirmed", "ambiguous"])
async def test_audit_unlock_failure_does_not_override_submission_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    outcome: str,
) -> None:
    plan, path = persist_plan(tmp_path)
    real_flock = fcntl.flock
    chain = SequenceChain(metagraph(block=102))
    submitter = FakeSubmitter(error=RuntimeError("lost") if outcome == "ambiguous" else None)

    def flock(descriptor: int, operation: int) -> None:
        if operation == fcntl.LOCK_UN:
            raise OSError("unlock-sentinel")
        real_flock(descriptor, operation)

    with monkeypatch.context() as patch:
        patch.setattr(fcntl, "flock", flock)
        try:
            summary = await executor.run_weight_executor(
                execute_config(plan, path, tmp_path / "audit.json"),
                chain=chain,
                submitter_factory=lambda: submitter,
                environ=acknowledged(),
            )
            document = summary.redacted_document()
        except executor.WeightExecutionError as error:
            assert outcome == "ambiguous" and error.code == "submission_ambiguous"
            document = error.redacted_document()
    assert document["status"] == outcome
    assert document["cleanup_error_codes"] == ["audit_cleanup_failed"]
    assert "audit_error_code" not in document
    assert submitter.submit_count == submitter.close_count == chain.close_count == 1
