# SPDX-License-Identifier: AGPL-3.0-only
"""PR13 round-13 shutdown fixed-point regressions on real local sockets."""

from __future__ import annotations

import asyncio
import json
import os
from contextlib import AsyncExitStack, suppress
from pathlib import Path
from typing import Any

import bittensor
import pytest
from bittensor._substrate import RpcSubstrate, StateDiscardedError
from bittensor._transport.interface import SubstrateConnection
from bittensor._transport.runtime import RuntimeManager
from websockets.asyncio.server import serve

import misscomputer_subnet.weight_signer_protocol as signer
from misscomputer_subnet.chain import BittensorChain
from misscomputer_subnet.chain_quorum import FinalizedRpcQuorum


def _install_warm_sdk(
    monkeypatch: pytest.MonkeyPatch,
    connections: list[SubstrateConnection],
) -> None:
    real_interface = RpcSubstrate._interface

    def interface(self: Any, *args: Any) -> SubstrateConnection:
        raw = real_interface(self, *args)
        connections.append(raw)
        return raw

    async def warm_codec(*args: Any, **kwargs: Any) -> None:
        return None

    monkeypatch.setattr(RpcSubstrate, "_interface", interface)
    monkeypatch.setattr(RuntimeManager, "codec_at", warm_codec)
    monkeypatch.setattr(bittensor.config, "token_symbols_fresh", lambda _: True)
    monkeypatch.setattr(bittensor.config, "load_token_symbols", lambda _: {})


async def _cancel_repeatedly(task: asyncio.Task[Any]) -> None:
    for _ in range(3):
        task.cancel()
        await asyncio.sleep(0)


async def _settle() -> None:
    for _ in range(4):
        await asyncio.sleep(0)


@pytest.mark.parametrize("topology", ["primary", "archive", "quorum"])
async def test_failed_rpc_supervisor_requests_do_not_deadlock_close(
    monkeypatch: pytest.MonkeyPatch,
    topology: str,
) -> None:
    """A normal peer close plus a failed supervisor cannot strand an admitted read."""

    assert bittensor.__version__ == "11.1.0"
    connections: list[SubstrateConnection] = []
    peers: list[Any] = []
    _install_warm_sdk(monkeypatch, connections)

    endpoint_count = 2 if topology in {"archive", "quorum"} else 1
    request_seen = [asyncio.Event() for _ in range(endpoint_count)]

    async def drop_request(websocket: Any, index: int) -> None:
        peers.append(websocket)
        try:
            with suppress(BaseException):
                await websocket.recv()
            if websocket.state.name == "CLOSED":
                return
            request_seen[index].set()
            await websocket.close(code=1000)
        finally:
            await websocket.wait_closed()

    async with AsyncExitStack() as stack:
        servers = [
            await stack.enter_async_context(
                serve(
                    lambda websocket, index=index: drop_request(websocket, index),
                    "127.0.0.1",
                    0,
                )
            )
            for index in range(endpoint_count)
        ]
        endpoints = [f"ws://127.0.0.1:{server.sockets[0].getsockname()[1]}" for server in servers]
        baseline_fds = set(os.listdir("/proc/self/fd"))
        chain_endpoints = endpoints if topology == "quorum" else endpoints[:1]
        chains = tuple(
            BittensorChain(network="finney", netuid=24, rpc_endpoint=endpoint)
            for endpoint in chain_endpoints
        )
        owner: BittensorChain | FinalizedRpcQuorum
        if topology == "quorum":
            owner = FinalizedRpcQuorum(chains)
        else:
            owner = chains[0]
        await owner.open()

        targets: list[SubstrateConnection]
        substrates = [chain._BittensorChain__client._substrate for chain in chains]
        first_close: asyncio.Task[None]
        second_close: asyncio.Task[None]
        if topology == "archive":
            substrate = substrates[0]
            substrate.archive_endpoints = [endpoints[1]]
            primary = substrate.raw
            primary_read_entered = asyncio.Event()
            release_primary_read = asyncio.Event()

            async def archive_read(raw: SubstrateConnection) -> str:
                if raw is primary:
                    primary_read_entered.set()
                    await release_primary_read.wait()
                    raise StateDiscardedError("0x" + "00" * 32)
                return await raw._session.request("chain_getHead", [])

            monkeypatch.setattr(SubstrateConnection, "get_chain_head", archive_read)
            reads = [asyncio.create_task(substrate.block_hash(), name="round13-archive-read")]
            await asyncio.wait_for(primary_read_entered.wait(), 2)
            first_close = asyncio.create_task(owner.close(), name="round13-first-rpc-close")
            second_close = asyncio.create_task(owner.close(), name="round13-second-rpc-close")
            await asyncio.sleep(0)
            await _cancel_repeatedly(first_close)
            release_primary_read.set()
            await asyncio.wait_for(request_seen[1].wait(), 2)
            targets = [connections[1]]
            target_events = [request_seen[1]]
        else:
            targets = [substrate.raw for substrate in substrates]
            target_events = request_seen
            reads = [
                asyncio.create_task(substrate.block_hash(), name="round13-primary-read")
                for substrate in substrates
            ]

        await asyncio.wait_for(
            asyncio.gather(*(event.wait() for event in target_events)),
            2,
        )
        supervisors = [raw._session._supervisor for raw in targets]
        assert all(supervisor is not None for supervisor in supervisors)
        for supervisor in supervisors:
            assert supervisor is not None
            supervisor.cancel()
        await asyncio.gather(*supervisors, return_exceptions=True)
        assert all(raw._session._pending for raw in targets)

        if topology != "archive":
            first_close = asyncio.create_task(owner.close(), name="round13-first-rpc-close")
            second_close = asyncio.create_task(owner.close(), name="round13-second-rpc-close")
            await asyncio.sleep(0)
            await _cancel_repeatedly(first_close)
        completed, _ = await asyncio.wait({second_close}, timeout=0.2)
        close_stalled = not completed

        # Reclaim the intentionally stranded old-revision requests only after
        # recording the regression, so a failing run never leaks test resources.
        if close_stalled:
            for raw in targets:
                raw._session._give_up(RuntimeError("test releases stranded request"))
        results = await asyncio.wait_for(
            asyncio.gather(*reads, first_close, second_close, return_exceptions=True),
            2,
        )
        await asyncio.gather(owner.close(), return_exceptions=True)
        for raw in connections:
            await asyncio.gather(raw.close(), return_exceptions=True)
        await asyncio.gather(*(peer.wait_closed() for peer in peers), return_exceptions=True)
        await _settle()

        assert not close_stalled, "close waited on requests only session shutdown could settle"
        assert any(isinstance(result, asyncio.CancelledError) for result in results)
        assert all(not raw._session._pending for raw in targets)
        assert all(raw._session._supervisor is None for raw in connections)
        assert set(os.listdir("/proc/self/fd")) == baseline_fds


async def test_signer_close_retires_cancellation_resistant_late_writer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A Unix dial that completes after the close snapshot remains generation-owned."""

    socket_path = tmp_path / "signer.sock"
    dial_entered, dial_cancelled, release_dial = (
        asyncio.Event(),
        asyncio.Event(),
        asyncio.Event(),
    )
    peer_eof = asyncio.Event()
    handlers: set[asyncio.Task[Any]] = set()

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            assert await reader.read() == b""
            peer_eof.set()
        finally:
            writer.close()
            await writer.wait_closed()

    def accept(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        handlers.add(asyncio.create_task(handle(reader, writer)))

    baseline_fds = set(os.listdir("/proc/self/fd"))
    server = await asyncio.start_unix_server(accept, path=socket_path)
    socket_path.chmod(0o600)
    real_open = asyncio.open_unix_connection
    acquired: list[asyncio.StreamWriter] = []

    async def resistant_open(*args: Any, **kwargs: Any) -> tuple[Any, asyncio.StreamWriter]:
        dial_entered.set()
        while not release_dial.is_set():
            try:
                await release_dial.wait()
            except asyncio.CancelledError:
                dial_cancelled.set()
        reader, writer = await real_open(*args, **kwargs)
        acquired.append(writer)
        return reader, writer

    monkeypatch.setattr(asyncio, "open_unix_connection", resistant_open)
    client = signer.UnixWeightSignerClient(
        socket_path=str(socket_path),
        signer_uid=os.getuid(),
        hotkey="Validator",
        timeout_seconds=1,
    )
    opening = asyncio.create_task(client.open(), name="round13-signer-open")
    first_close: asyncio.Task[None] | None = None
    second_close: asyncio.Task[None] | None = None
    escaped = False
    try:
        await asyncio.wait_for(dial_entered.wait(), 1)
        first_close = asyncio.create_task(client.close(), name="round13-first-signer-close")
        second_close = asyncio.create_task(client.close(), name="round13-second-signer-close")
        await asyncio.wait_for(dial_cancelled.wait(), 1)
        await _cancel_repeatedly(first_close)
        assert not second_close.done()
        with pytest.raises(signer.SignerProtocolError):
            await client.open()

        release_dial.set()
        results = await asyncio.wait_for(
            asyncio.gather(opening, first_close, second_close, return_exceptions=True),
            2,
        )
        assert acquired
        late_writer = acquired[0]
        late_socket = late_writer.get_extra_info("socket")
        escaped = (
            client._writer is late_writer
            or not late_writer.transport.is_closing()
            or late_socket is None
            or late_socket.fileno() >= 0
        )
        if escaped:
            late_writer.transport.abort()
        await asyncio.wait_for(peer_eof.wait(), 1)
        assert isinstance(results[0], signer.SignerProtocolError)
        assert isinstance(results[1], asyncio.CancelledError)
        assert results[2] is None
    finally:
        release_dial.set()
        await asyncio.gather(opening, return_exceptions=True)
        if first_close is not None:
            await asyncio.gather(first_close, return_exceptions=True)
        if second_close is not None:
            await asyncio.gather(second_close, return_exceptions=True)
        for writer in acquired:
            writer.transport.abort()
        await asyncio.gather(client.close(), return_exceptions=True)
        server.close()
        await server.wait_closed()
        await asyncio.gather(*handlers, return_exceptions=True)
    await _settle()
    assert not escaped, "a cancellation-resistant Unix dial escaped its close generation"
    assert client._writer is None
    assert set(os.listdir("/proc/self/fd")) == baseline_fds


@pytest.mark.parametrize("topology", ["chain", "quorum"])
async def test_public_finalized_reads_are_retired_before_lifecycle_reopens(
    monkeypatch: pytest.MonkeyPatch,
    topology: str,
) -> None:
    """Raw finalized-head access and every later read step share lifecycle admission."""

    assert bittensor.__version__ == "11.1.0"
    connections: list[SubstrateConnection] = []
    peers: list[Any] = []
    _install_warm_sdk(monkeypatch, connections)
    block_hash = "0x" + "ab" * 32

    async def reply(websocket: Any) -> None:
        peers.append(websocket)
        async for rendered in websocket:
            request = json.loads(rendered)
            result: object
            if request["method"] == "chain_getFinalizedHead":
                result = block_hash
            elif request["method"] == "chain_getHeader":
                result = {"number": "0x2a"}
            else:
                result = None
            await websocket.send(
                json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": result})
            )

    endpoint_count = 2 if topology == "quorum" else 1
    async with AsyncExitStack() as stack:
        servers = [
            await stack.enter_async_context(serve(reply, "127.0.0.1", 0))
            for _ in range(endpoint_count)
        ]
        endpoints = [f"ws://127.0.0.1:{server.sockets[0].getsockname()[1]}" for server in servers]
        baseline_fds = set(os.listdir("/proc/self/fd"))
        chains = tuple(
            BittensorChain(network="finney", netuid=24, rpc_endpoint=endpoint)
            for endpoint in endpoints
        )
        owner: BittensorChain | FinalizedRpcQuorum
        if topology == "quorum":
            owner = FinalizedRpcQuorum(chains)
        else:
            owner = chains[0]
        await owner.open()

        entered = {raw: asyncio.Event() for raw in connections}
        cancelled = {raw: asyncio.Event() for raw in connections}
        release = asyncio.Event()
        real_finalized = SubstrateConnection.get_chain_finalised_head

        async def delayed_finalized(raw: SubstrateConnection) -> str:
            result = await real_finalized(raw)
            entered[raw].set()
            while not release.is_set():
                try:
                    await release.wait()
                except asyncio.CancelledError:
                    cancelled[raw].set()
            return result

        monkeypatch.setattr(SubstrateConnection, "get_chain_finalised_head", delayed_finalized)
        if topology == "quorum":
            reading = asyncio.create_task(owner.sync(), name="round13-quorum-public-read")
        else:
            reading = asyncio.create_task(
                chains[0].latest_finalized_block(), name="round13-chain-public-read"
            )
        await asyncio.wait_for(asyncio.gather(*(event.wait() for event in entered.values())), 2)

        first_close = asyncio.create_task(owner.close(), name="round13-first-owner-close")
        second_close = asyncio.create_task(owner.close(), name="round13-second-owner-close")
        await asyncio.sleep(0)
        await _cancel_repeatedly(first_close)
        await asyncio.sleep(0.1)
        close_returned_early = second_close.done()
        cancelled_before_release = all(event.is_set() for event in cancelled.values())
        release.set()
        results = await asyncio.wait_for(
            asyncio.gather(reading, first_close, second_close, return_exceptions=True),
            2,
        )
        await asyncio.gather(owner.close(), return_exceptions=True)
        for raw in connections:
            await asyncio.gather(raw.close(), return_exceptions=True)
        await asyncio.gather(*(peer.wait_closed() for peer in peers), return_exceptions=True)
        await _settle()

        assert not close_returned_early, "close returned before a public finalized read unwound"
        assert cancelled_before_release, "close did not actively cancel admitted public reads"
        assert reading.done()
        assert any(isinstance(result, asyncio.CancelledError) for result in results)
        assert set(os.listdir("/proc/self/fd")) == baseline_fds
