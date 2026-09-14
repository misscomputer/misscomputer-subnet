# SPDX-License-Identifier: AGPL-3.0-only
"""PR13 round-15 signer request-retirement regressions."""

from __future__ import annotations

import asyncio
import os
from contextlib import suppress
from pathlib import Path
from typing import Any

import pytest

import misscomputer_subnet.weight_signer_protocol as signer
from misscomputer_subnet.weight_executor import ExecutionVector, ExecutionWeight, SubmissionResult


def _vector() -> ExecutionVector:
    return ExecutionVector(
        plan_digest_sha256="ab" * 32,
        network="finney",
        netuid=24,
        validator_hotkey="Validator",
        version_key=1,
        weights=(ExecutionWeight(uid=7, hotkey="Miner", planned_uid=7, weight=1.0),),
        omitted=(),
    )


async def _cancel_repeatedly(task: asyncio.Task[Any]) -> None:
    for _ in range(3):
        task.cancel()
        await asyncio.sleep(0)


@pytest.mark.parametrize("status", ["confirmed", "ambiguous"])
async def test_signer_close_drains_response_handoff_before_reopen_without_overjoining_caller(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    status: str,
) -> None:
    """One generation owns a full submit operation, not its caller's later lifetime."""

    socket_path = tmp_path / "s"
    response_read = asyncio.Event()
    release_response = asyncio.Event()
    cancellation_seen = asyncio.Event()
    operation_returned = asyncio.Event()
    release_unrelated_caller = asyncio.Event()
    peer_eof = asyncio.Event()
    server_tasks: set[asyncio.Task[Any]] = set()

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            rendered = await reader.readline()
            if rendered:
                request = signer.SignerRequest.from_bytes(rendered)
                response = signer.SignerResponse(
                    request_id=request.request_id,
                    status=status,  # type: ignore[arg-type]
                    extrinsic_ref="103-2",
                    error_code=None if status == "confirmed" else "submission_timeout",
                )
                writer.write(response.canonical_bytes())
                await writer.drain()
            assert await reader.read() == b""
            peer_eof.set()
        finally:
            writer.close()
            await writer.wait_closed()

    def accept(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.create_task(handle(reader, writer), name="round15-signer-peer")
        server_tasks.add(task)

    real_read_message = signer.read_message

    async def pause_after_response_read(reader: asyncio.StreamReader) -> bytes:
        rendered = await real_read_message(reader)
        response_read.set()
        while not release_response.is_set():
            try:
                await release_response.wait()
            except asyncio.CancelledError:
                # Model an admitted request that must retain already-read effect
                # certainty while its owner performs bounded local bookkeeping.
                cancellation_seen.set()
        return rendered

    baseline_fds = set(os.listdir("/proc/self/fd"))
    server = await asyncio.start_unix_server(accept, path=socket_path)
    socket_path.chmod(0o600)
    client = signer.UnixWeightSignerClient(
        socket_path=str(socket_path),
        signer_uid=os.getuid(),
        hotkey="Validator",
        timeout_seconds=1,
    )
    await client.open()
    monkeypatch.setattr(signer, "read_message", pause_after_response_read)
    observed: list[SubmissionResult | signer.SignerProtocolError] = []

    async def long_lived_caller() -> None:
        try:
            observed.append(await client.submit(_vector()))
        except signer.SignerProtocolError as exc:
            observed.append(exc)
        finally:
            operation_returned.set()
        await release_unrelated_caller.wait()

    caller = asyncio.create_task(long_lived_caller(), name="round15-long-lived-caller")
    first_close: asyncio.Task[None] | None = None
    second_close: asyncio.Task[None] | None = None
    close_returned_early = False
    reopened_early = False
    caller_overjoined = False
    try:
        await asyncio.wait_for(response_read.wait(), 1)
        first_close = asyncio.create_task(client.close(), name="round15-first-signer-close")
        second_close = asyncio.create_task(client.close(), name="round15-second-signer-close")
        await _cancel_repeatedly(first_close)
        done, _ = await asyncio.wait({second_close}, timeout=0.1)
        close_returned_early = bool(done)
        try:
            await client.open()
        except signer.SignerProtocolError:
            pass
        else:
            reopened_early = True

        release_response.set()
        await asyncio.wait_for(operation_returned.wait(), 1)
        await asyncio.wait_for(second_close, 1)
        caller_overjoined = not second_close.done() or caller.done()
        await asyncio.gather(first_close, return_exceptions=True)

        assert cancellation_seen.is_set(), "close did not cancel its admitted submit operation"
        assert not close_returned_early, "close returned before its submit operation settled"
        assert not reopened_early, "a replacement generation opened before submit retirement"
        assert not caller_overjoined, "close joined the submit caller's unrelated later lifetime"
        assert len(observed) == 1
        if status == "confirmed":
            result = observed[0]
            assert isinstance(result, SubmissionResult)
            assert result.success and result.extrinsic_ref == "103-2"
        else:
            error = observed[0]
            assert isinstance(error, signer.SignerProtocolError)
            assert error.code == "submission_ambiguous"
            assert error.extrinsic_ref == "103-2"
        await client.open()
        await client.close()
    finally:
        release_response.set()
        release_unrelated_caller.set()
        await asyncio.gather(caller, return_exceptions=True)
        if first_close is not None:
            await asyncio.gather(first_close, return_exceptions=True)
        if second_close is not None:
            await asyncio.gather(second_close, return_exceptions=True)
        with suppress(BaseException):
            await client.close()
        server.close()
        await server.wait_closed()
        if server_tasks:
            await asyncio.gather(*server_tasks, return_exceptions=True)
    for _ in range(4):
        await asyncio.sleep(0)
    assert peer_eof.is_set()
    assert set(os.listdir("/proc/self/fd")) == baseline_fds
