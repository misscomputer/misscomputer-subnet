# SPDX-License-Identifier: AGPL-3.0-only
"""PR13 round-12 public lifecycle and temporary-file regressions."""

from __future__ import annotations

import asyncio
import errno
import os
from contextlib import AsyncExitStack
from pathlib import Path
from typing import Any

import bittensor
import pytest
from bittensor._substrate import RpcSubstrate, StateDiscardedError
from bittensor._transport.interface import SubstrateConnection
from bittensor._transport.runtime import RuntimeManager
from websockets.asyncio.server import serve

import misscomputer_subnet.weight_plan as weight_plan
import misscomputer_subnet.weight_signer_protocol as signer
from misscomputer_subnet.chain import BittensorChain


class CleanupSentinel(BaseException):
    """Cancellation-grade cleanup failure with stable object identity."""


def _owned_tasks() -> set[asyncio.Task[Any]]:
    names = {
        "bittensor-chain-cleanup",
        "bittensor-chain-close",
        "bittensor-transport-cleanup",
        "bittensor-transport-retirement",
        "rpc-session",
        "weight-signer-cleanup",
        "weight-signer-close",
        "weight-signer-open",
        "weight-signer-open-cleanup",
        "weight-signer-retirement",
    }
    return {task for task in asyncio.all_tasks() if task.get_name() in names and not task.done()}


async def _settle() -> None:
    for _ in range(4):
        await asyncio.sleep(0)


async def test_signer_close_failure_aborts_real_socket_within_client_timeout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failing StreamWriter.close cannot bypass abort or bounded retirement."""

    socket_path = tmp_path / "s"
    peer_eof, handler_done = asyncio.Event(), asyncio.Event()
    server_tasks: set[asyncio.Task[Any]] = set()

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            assert await reader.read() == b""
            peer_eof.set()
        finally:
            writer.close()
            await writer.wait_closed()
            handler_done.set()

    def accept(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        server_tasks.add(asyncio.create_task(handle(reader, writer)))

    baseline_fds = set(os.listdir("/proc/self/fd"))
    baseline_tasks = _owned_tasks()
    server = await asyncio.start_unix_server(accept, path=socket_path)
    socket_path.chmod(0o600)
    client = signer.UnixWeightSignerClient(
        socket_path=str(socket_path),
        signer_uid=os.getuid(),
        hotkey="Validator",
        timeout_seconds=0.05,
    )
    await client.open()
    writer = client._writer
    assert writer is not None
    transport = writer.transport
    transport_socket = writer.get_extra_info("socket")
    assert transport_socket is not None and transport_socket.fileno() >= 0
    release_wait = asyncio.Event()
    original_close = asyncio.StreamWriter.close
    original_wait_closed = asyncio.StreamWriter.wait_closed
    close_error = CleanupSentinel("writer-close-failed")

    def close(candidate: asyncio.StreamWriter) -> None:
        if candidate is writer:
            raise close_error
        original_close(candidate)

    async def wait_closed(candidate: asyncio.StreamWriter) -> None:
        if candidate is writer:
            await release_wait.wait()
            return
        await original_wait_closed(candidate)

    monkeypatch.setattr(asyncio.StreamWriter, "close", close)
    monkeypatch.setattr(asyncio.StreamWriter, "wait_closed", wait_closed)
    closing = asyncio.create_task(client.close(), name="round12-signer-bounded-close")
    try:
        await asyncio.sleep(0.2)
        bounded = closing.done()
        socket_retired = transport_socket.fileno() < 0
        if not socket_retired:
            transport.abort()
        release_wait.set()
        result = (await asyncio.gather(closing, return_exceptions=True))[0]
        await asyncio.wait_for(peer_eof.wait(), 1)
        await asyncio.wait_for(handler_done.wait(), 1)
        assert bounded, "signer close exceeded its configured client timeout"
        assert socket_retired, "writer.close failure left the Unix transport live"
        assert result is close_error
    finally:
        if transport_socket.fileno() >= 0:
            transport.abort()
        release_wait.set()
        await asyncio.gather(closing, return_exceptions=True)
        await asyncio.gather(client.close(), return_exceptions=True)
        server.close()
        await server.wait_closed()
        await asyncio.gather(*server_tasks, return_exceptions=True)
    await _settle()
    assert _owned_tasks() == baseline_tasks
    assert set(os.listdir("/proc/self/fd")) == baseline_fds


async def test_signer_close_callers_join_generation_and_block_reopen(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The writer slot cannot look reusable while its generation is retiring."""

    socket_path = tmp_path / "s"
    peers: list[asyncio.StreamWriter] = []
    handlers: set[asyncio.Task[Any]] = set()

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peers.append(writer)
        try:
            await reader.read()
        finally:
            writer.close()
            await writer.wait_closed()

    def accept(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        handlers.add(asyncio.create_task(handle(reader, writer)))

    baseline_fds = set(os.listdir("/proc/self/fd"))
    baseline_tasks = _owned_tasks()
    server = await asyncio.start_unix_server(accept, path=socket_path)
    socket_path.chmod(0o600)
    client = signer.UnixWeightSignerClient(
        socket_path=str(socket_path),
        signer_uid=os.getuid(),
        hotkey="Validator",
        timeout_seconds=1,
    )
    await client.open()
    writer = client._writer
    assert writer is not None
    close_entered, release_close = asyncio.Event(), asyncio.Event()
    original_wait_closed = asyncio.StreamWriter.wait_closed

    async def wait_closed(candidate: asyncio.StreamWriter) -> None:
        if candidate is writer:
            close_entered.set()
            await release_close.wait()
        await original_wait_closed(candidate)

    monkeypatch.setattr(asyncio.StreamWriter, "wait_closed", wait_closed)
    first = asyncio.create_task(client.close(), name="round12-signer-first-close")
    second: asyncio.Task[None] | None = None
    reopen_succeeded = False
    second_returned_early = False
    try:
        await asyncio.wait_for(close_entered.wait(), 1)
        second = asyncio.create_task(client.close(), name="round12-signer-second-close")
        await asyncio.sleep(0.05)
        second_returned_early = second.done()
        try:
            await client.open()
        except signer.SignerProtocolError:
            pass
        else:
            reopen_succeeded = True
        release_close.set()
        await asyncio.gather(first, second)
        await client.close()
        assert not second_returned_early, "a second close did not join writer retirement"
        assert not reopen_succeeded, "open admitted a new writer during retirement"
    finally:
        release_close.set()
        await asyncio.gather(first, return_exceptions=True)
        if second is not None:
            await asyncio.gather(second, return_exceptions=True)
        await asyncio.gather(client.close(), return_exceptions=True)
        for peer in peers:
            peer.close()
        await asyncio.gather(*(peer.wait_closed() for peer in peers), return_exceptions=True)
        server.close()
        await server.wait_closed()
        await asyncio.gather(*handlers, return_exceptions=True)
    await _settle()
    assert _owned_tasks() == baseline_tasks
    assert set(os.listdir("/proc/self/fd")) == baseline_fds


def _install_warm_sdk(
    monkeypatch: pytest.MonkeyPatch,
    connections: list[SubstrateConnection],
    *,
    fail_second_codec: bool = False,
) -> None:
    real_interface = RpcSubstrate._interface
    codec_calls = 0

    def interface(self: Any, *args: Any) -> SubstrateConnection:
        raw = real_interface(self, *args)
        connections.append(raw)
        return raw

    async def codec(*args: Any, **kwargs: Any) -> None:
        nonlocal codec_calls
        codec_calls += 1
        if fail_second_codec and codec_calls == 2:
            raise CleanupSentinel("late-archive-codec-failed")

    monkeypatch.setattr(RpcSubstrate, "_interface", interface)
    monkeypatch.setattr(RuntimeManager, "codec_at", codec)
    monkeypatch.setattr(bittensor.config, "token_symbols_fresh", lambda _: True)
    monkeypatch.setattr(bittensor.config, "load_token_symbols", lambda _: {})


async def test_chain_close_drains_block_hash_through_late_archive_fixed_point(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An admitted pinned-SDK read and its late archive work outlive no close."""

    assert bittensor.__version__ == "11.1.0"
    connections: list[SubstrateConnection] = []
    peers: list[Any] = []
    _install_warm_sdk(monkeypatch, connections)

    async def handle(websocket: Any) -> None:
        peers.append(websocket)
        await websocket.wait_closed()

    async with AsyncExitStack() as stack:
        servers = [await stack.enter_async_context(serve(handle, "127.0.0.1", 0)) for _ in range(2)]
        endpoints = [f"ws://127.0.0.1:{server.sockets[0].getsockname()[1]}" for server in servers]
        baseline_fds = set(os.listdir("/proc/self/fd"))
        baseline_tasks = _owned_tasks()
        chain = BittensorChain(network="finney", netuid=24, rpc_endpoint=endpoints[0])
        await chain.open()
        substrate = chain._BittensorChain__client._substrate
        substrate.archive_endpoints = [endpoints[1]]
        primary = substrate.raw
        read_entered, release_read, archive_read = (
            asyncio.Event(),
            asyncio.Event(),
            asyncio.Event(),
        )
        expected_hash = "0x" + "ab" * 32

        async def get_chain_head(raw: SubstrateConnection) -> str:
            if raw is primary:
                read_entered.set()
                await release_read.wait()
                raise StateDiscardedError("0x" + "00" * 32)
            archive_read.set()
            return expected_hash

        monkeypatch.setattr(SubstrateConnection, "get_chain_head", get_chain_head)
        reading = asyncio.create_task(substrate.block_hash(), name="round12-pinned-block-hash")
        closing: asyncio.Task[None] | None = None
        close_returned_early = False
        result: object = None
        try:
            await asyncio.wait_for(read_entered.wait(), 1)
            closing = asyncio.create_task(chain.close(), name="round12-chain-close")
            await asyncio.sleep(0.1)
            close_returned_early = closing.done()
            release_read.set()
            result = (await asyncio.gather(reading, return_exceptions=True))[0]
            await asyncio.gather(closing, return_exceptions=True)
            assert not close_returned_early, "chain close returned with an admitted read pending"
            assert result == expected_hash
            assert archive_read.is_set(), "admitted read could not finish its late archive fallback"
        finally:
            release_read.set()
            await asyncio.gather(reading, return_exceptions=True)
            if closing is not None:
                await asyncio.gather(closing, return_exceptions=True)
            await asyncio.gather(chain.close(), return_exceptions=True)
            for raw in connections:
                await asyncio.gather(raw.close(), return_exceptions=True)
            for peer in peers:
                peer.transport.abort()
            await asyncio.gather(*(peer.wait_closed() for peer in peers), return_exceptions=True)
        await _settle()
        assert all(raw._session._ws is None for raw in connections)
        assert _owned_tasks() == baseline_tasks
        assert set(os.listdir("/proc/self/fd")) == baseline_fds


async def test_transport_internal_archive_failure_does_not_self_join(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Cleanup requested by an admitted operation excludes its own caller."""

    connections: list[SubstrateConnection] = []
    peers: list[Any] = []
    _install_warm_sdk(monkeypatch, connections, fail_second_codec=True)

    async def handle(websocket: Any) -> None:
        peers.append(websocket)
        await websocket.wait_closed()

    async with serve(handle, "127.0.0.1", 0) as server:
        baseline_fds = set(os.listdir("/proc/self/fd"))
        baseline_tasks = _owned_tasks()
        endpoint = f"ws://127.0.0.1:{server.sockets[0].getsockname()[1]}"
        chain = BittensorChain(network="finney", netuid=24, rpc_endpoint=endpoint)
        await chain.open()
        substrate = chain._BittensorChain__client._substrate
        substrate.archive_endpoints = [endpoint]

        async def discarded(raw: SubstrateConnection) -> None:
            del raw
            raise StateDiscardedError("0x" + "00" * 32)

        try:
            with pytest.raises(CleanupSentinel, match="late-archive-codec-failed"):
                await asyncio.wait_for(substrate._read(discarded), 1)
        finally:
            await asyncio.gather(chain.close(), return_exceptions=True)
            for raw in connections:
                await asyncio.gather(raw.close(), return_exceptions=True)
            for peer in peers:
                peer.transport.abort()
            await asyncio.gather(*(peer.wait_closed() for peer in peers), return_exceptions=True)
        await _settle()
        assert _owned_tasks() == baseline_tasks
        assert set(os.listdir("/proc/self/fd")) == baseline_fds


def test_visible_temporary_first_fstat_failure_unlinks_owned_inode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Acquisition owns a visible name even when its first fstat fails."""

    directory_fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    baseline_fds = set(os.listdir("/proc/self/fd"))
    opened: list[int] = []
    real_open, real_fstat = os.open, os.fstat
    first = True
    failure = OSError(errno.EIO, "first temporary fstat failed")

    def open_file(*args: Any, **kwargs: Any) -> int:
        descriptor = real_open(*args, **kwargs)
        opened.append(descriptor)
        return descriptor

    def fstat(descriptor: int) -> os.stat_result:
        nonlocal first
        if first and descriptor in opened:
            first = False
            raise failure
        return real_fstat(descriptor)

    try:
        with monkeypatch.context() as patch:
            patch.setattr(weight_plan, "_open_unnamed_temporary", lambda _: None)
            patch.setattr(os, "open", open_file)
            patch.setattr(os, "fstat", fstat)
            with pytest.raises(OSError) as caught:
                weight_plan._prepare_temporary_plan(directory_fd, b"round-12\n")
        assert caught.value is failure
        assert not list(tmp_path.glob(".weight-plan.tmp-*"))
        for descriptor in opened:
            with pytest.raises(OSError) as closed:
                os.fstat(descriptor)
            assert closed.value.errno == errno.EBADF
        assert set(os.listdir("/proc/self/fd")) == baseline_fds
    finally:
        os.close(directory_fd)
