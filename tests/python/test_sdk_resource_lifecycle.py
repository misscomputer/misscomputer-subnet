# SPDX-License-Identifier: AGPL-3.0-only
"""Pinned Bittensor 11.1.0 and real localhost socket acquisition regressions."""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Any

import bittensor
import pytest
from bittensor._substrate import RpcSubstrate
from bittensor._transport.interface import SubstrateConnection
from bittensor._transport.runtime import RuntimeManager
from test_chain_quorum import FakeFinalizedChain
from test_weight_executor import SimulatedCrash
from websockets.asyncio.server import serve

import misscomputer_subnet.weight_signer_protocol as signer
from misscomputer_subnet.chain import BittensorChain
from misscomputer_subnet.chain_quorum import FinalizedRpcQuorum


async def test_real_sdk_cancellation_during_websocket_handshake_drains_waiters() -> None:
    connected, eof, handler_done = asyncio.Event(), asyncio.Event(), asyncio.Event()

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            await reader.readuntil(b"\r\n\r\n")
            connected.set()
            assert await reader.read() == b""
            eof.set()
        finally:
            writer.close()
            await writer.wait_closed()
            handler_done.set()

    before = asyncio.all_tasks()
    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    async with server:
        endpoint = f"ws://127.0.0.1:{server.sockets[0].getsockname()[1]}"
        chain = BittensorChain(network="finney", netuid=24, rpc_endpoint=endpoint)
        task = asyncio.create_task(chain.open())
        await asyncio.wait_for(connected.wait(), 2)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, 2)
        await chain.close()
        await asyncio.wait_for(eof.wait(), 2)
        await asyncio.wait_for(handler_done.wait(), 2)
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        assert not [task for task in asyncio.all_tasks() - before if not task.done()]


@pytest.mark.parametrize(
    "stage", ["state_getRuntimeVersion", "chain_getBlockHash", "state_call", "state_getMetadata"]
)
@pytest.mark.parametrize("failure", ["cancel", "malformed"])
async def test_real_sdk_partial_initialization_closes_socket_and_rpc_session(
    monkeypatch: pytest.MonkeyPatch, stage: str, failure: str
) -> None:
    assert bittensor.__version__ == "11.1.0"
    reached, close_started, release_close = asyncio.Event(), asyncio.Event(), asyncio.Event()
    raw_connections: list[SubstrateConnection] = []
    server_connections: list[Any] = []
    real_interface, real_close = RpcSubstrate._interface, SubstrateConnection.close

    def interface(self: Any, *args: Any) -> SubstrateConnection:
        raw = real_interface(self, *args)
        raw_connections.append(raw)
        return raw

    async def close(raw: SubstrateConnection) -> None:
        close_started.set()
        await release_close.wait()
        await real_close(raw)

    async def handle(websocket: Any) -> None:
        server_connections.append(websocket)
        async for rendered in websocket:
            request = json.loads(rendered)
            method = request["method"]
            responses: dict[str, Any] = {
                "state_getRuntimeVersion": {"specVersion": 999999, "transactionVersion": 1},
                "chain_getBlockHash": "0x" + "ab" * 32,
                "state_call": None,
                "state_getMetadata": "0xnot-hex",
            }
            result = responses[method]
            if method == stage:
                reached.set()
                if failure == "cancel":
                    await websocket.wait_closed()
                    return
                # Invalid metadata/shape raises outside SDK's narrow cleanup catches.
                result = {} if method == "state_getRuntimeVersion" else 7
            await websocket.send(
                json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": result})
            )

    monkeypatch.setattr(RpcSubstrate, "_interface", interface)
    monkeypatch.setattr(SubstrateConnection, "close", close)
    async with serve(handle, "127.0.0.1", 0) as server:
        endpoint = f"ws://127.0.0.1:{server.sockets[0].getsockname()[1]}"
        chain = BittensorChain(network="finney", netuid=24, rpc_endpoint=endpoint)
        task = asyncio.create_task(chain.open())
        await asyncio.wait_for(reached.wait(), 2)
        if failure == "cancel":
            task.cancel()
        # Bound the old implementation, which exits without attempting any close.
        watcher = asyncio.create_task(close_started.wait())
        await asyncio.wait({task, watcher}, timeout=2, return_when=asyncio.FIRST_COMPLETED)
        if close_started.is_set():
            for _ in range(3):
                task.cancel()
                await asyncio.sleep(0)
        watcher.cancel()
        await asyncio.gather(watcher, return_exceptions=True)
        release_close.set()
        with pytest.raises(BaseException) as error:
            await asyncio.wait_for(task, 2)
        if failure == "cancel":
            assert isinstance(error.value, asyncio.CancelledError)
        else:
            assert not isinstance(error.value, asyncio.CancelledError)
        await chain.close()
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        leaked = [raw for raw in raw_connections if raw._session._ws is not None]
        live_tasks = [
            task
            for task in asyncio.all_tasks()
            if task.get_name() == "rpc-session" and not task.done()
        ]
        # Cleanup test-owned leaked SDK transports after recording the failing-old evidence.
        for raw in raw_connections:
            await real_close(raw)
        for websocket in server_connections:
            await asyncio.wait_for(websocket.wait_closed(), 2)
        assert raw_connections
        assert not leaked, "partial SDK websocket was never published to cleanup"
        assert not live_tasks, "partial SDK rpc-session survived chain.close"


@pytest.mark.parametrize("failure", ["cancel", "malformed"])
async def test_lazy_archive_transport_is_owned_before_await(
    monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    raw_connections: list[SubstrateConnection] = []
    reached = asyncio.Event()
    real_interface = RpcSubstrate._interface

    def interface(self: Any, *args: Any) -> SubstrateConnection:
        raw = real_interface(self, *args)
        raw_connections.append(raw)
        return raw

    async def handle(websocket: Any) -> None:
        async for rendered in websocket:
            request = json.loads(rendered)
            reached.set()
            if failure == "cancel":
                await websocket.wait_closed()
                return
            await websocket.send(json.dumps({"id": request["id"], "result": {}}))

    async def warm_codec(*args: Any, **kwargs: Any) -> None:
        return None

    monkeypatch.setattr(RpcSubstrate, "_interface", interface)
    async with serve(handle, "127.0.0.1", 0) as primary, serve(handle, "127.0.0.1", 0) as archive:
        endpoint = f"ws://127.0.0.1:{primary.sockets[0].getsockname()[1]}"
        chain = BittensorChain(network="finney", netuid=24, rpc_endpoint=endpoint)
        # Only codec warming/display metadata are stubbed for the successful primary;
        # primary and secondary connect/session lifecycle use the actual pinned SDK.
        with monkeypatch.context() as patch:
            patch.setattr(RuntimeManager, "codec_at", warm_codec)
            patch.setattr(bittensor.config, "token_symbols_fresh", lambda _: True)
            patch.setattr(bittensor.config, "load_token_symbols", lambda _: {})
            await chain.open()
        substrate = chain._BittensorChain__client._substrate
        substrate.archive_endpoints = [f"ws://127.0.0.1:{archive.sockets[0].getsockname()[1]}"]
        task = asyncio.create_task(substrate._archive())
        await asyncio.wait_for(reached.wait(), 2)
        if failure == "cancel":
            task.cancel()
        with pytest.raises(asyncio.CancelledError if failure == "cancel" else KeyError):
            await asyncio.wait_for(task, 2)
        await chain.close()
        leaked = [raw for raw in raw_connections if raw._session._ws is not None]
        for raw in raw_connections:
            await raw.close()
        assert len(raw_connections) == 2
        assert not leaked, "lazy SDK archive socket escaped cleanup"


async def test_quorum_outer_cancel_drains_open_children_before_return() -> None:
    started = [asyncio.Event(), asyncio.Event()]
    close_started, release_close = asyncio.Event(), asyncio.Event()

    class Chain(FakeFinalizedChain):
        def __init__(self, index: int) -> None:
            super().__init__()
            self.index = index

        async def open(self) -> None:
            self.open_count += 1
            started[self.index].set()
            if self.index == 1:
                await asyncio.Event().wait()

        async def close(self) -> None:
            self.close_count += 1
            close_started.set()
            await release_close.wait()

    chains = (Chain(0), Chain(1))
    quorum = FinalizedRpcQuorum(chains)
    task = asyncio.create_task(quorum.open())
    await asyncio.gather(*(event.wait() for event in started))
    task.cancel()
    watcher = asyncio.create_task(close_started.wait())
    await asyncio.wait({task, watcher}, timeout=2, return_when=asyncio.FIRST_COMPLETED)
    if close_started.is_set():
        for _ in range(3):
            task.cancel()
            await asyncio.sleep(0)
    watcher.cancel()
    await asyncio.gather(watcher, return_exceptions=True)
    release_close.set()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, 2)
    await quorum.close()
    assert [chain.close_count for chain in chains] == [1, 1]


@pytest.mark.parametrize("failing_index", [0, 1])
async def test_real_sdk_close_failure_still_attempts_both_transports(
    monkeypatch: pytest.MonkeyPatch, failing_index: int
) -> None:
    connections: list[SubstrateConnection] = []
    real_interface, real_close = RpcSubstrate._interface, SubstrateConnection.close

    def interface(self: Any, *args: Any) -> SubstrateConnection:
        raw = real_interface(self, *args)
        connections.append(raw)
        return raw

    async def warm_codec(*args: Any, **kwargs: Any) -> None:
        return None

    async def close(raw: SubstrateConnection) -> None:
        await real_close(raw)
        if raw is connections[failing_index]:
            raise SimulatedCrash("private-transport-close")

    async def handle(websocket: Any) -> None:
        await websocket.wait_closed()

    monkeypatch.setattr(RpcSubstrate, "_interface", interface)
    monkeypatch.setattr(RuntimeManager, "codec_at", warm_codec)
    monkeypatch.setattr(bittensor.config, "token_symbols_fresh", lambda _: True)
    monkeypatch.setattr(bittensor.config, "load_token_symbols", lambda _: {})
    async with serve(handle, "127.0.0.1", 0) as primary, serve(handle, "127.0.0.1", 0) as archive:
        endpoint = f"ws://127.0.0.1:{primary.sockets[0].getsockname()[1]}"
        chain = BittensorChain(network="finney", netuid=24, rpc_endpoint=endpoint)
        await chain.open()
        substrate = chain._BittensorChain__client._substrate
        substrate.archive_endpoints = [f"ws://127.0.0.1:{archive.sockets[0].getsockname()[1]}"]
        await substrate._archive()
        monkeypatch.setattr(SubstrateConnection, "close", close)
        with pytest.raises(SimulatedCrash, match="private-transport-close"):
            await chain.close()
        leaked = [raw for raw in connections if raw._session._ws is not None]
        for raw in connections:
            await real_close(raw)
        assert not leaked, "one failed SDK close prevented another transport cleanup"


@pytest.mark.parametrize("fault_type", [OSError, SimulatedCrash, asyncio.CancelledError])
@pytest.mark.parametrize("repeated_cancel", [False, True])
async def test_unix_connect_baseexception_retires_real_writer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fault_type: type[BaseException],
    repeated_cancel: bool,
) -> None:
    socket_path = tmp_path / "signer.sock"
    connected, eof = asyncio.Event(), asyncio.Event()
    server_writers: list[asyncio.StreamWriter] = []
    client_writers: list[asyncio.StreamWriter] = []
    real_connect = asyncio.open_unix_connection
    real_wait_closed = asyncio.StreamWriter.wait_closed
    close_started, release_close = asyncio.Event(), asyncio.Event()

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        server_writers.append(writer)
        connected.set()
        await reader.read()
        eof.set()
        writer.close()
        await writer.wait_closed()

    async def connect(*args: Any, **kwargs: Any) -> Any:
        reader, writer = await real_connect(*args, **kwargs)
        client_writers.append(writer)
        return reader, writer

    def peer_uid(*args: Any) -> int:
        raise fault_type("private-post-connect-failure")

    async def wait_closed(writer: asyncio.StreamWriter) -> None:
        if repeated_cancel and writer in client_writers:
            close_started.set()
            await release_close.wait()
        await real_wait_closed(writer)

    server = await asyncio.start_unix_server(handle, path=str(socket_path))
    socket_path.chmod(0o600)
    monkeypatch.setattr(asyncio, "open_unix_connection", connect)
    monkeypatch.setattr(signer, "unix_peer_uid", peer_uid)
    monkeypatch.setattr(asyncio.StreamWriter, "wait_closed", wait_closed)
    client = signer.UnixWeightSignerClient(
        socket_path=str(socket_path),
        signer_uid=os.getuid(),
        hotkey="Validator",
        timeout_seconds=1,
    )
    async with server:
        task = asyncio.create_task(client.open())
        if repeated_cancel:
            watcher = asyncio.create_task(close_started.wait())
            await asyncio.wait({task, watcher}, timeout=2, return_when=asyncio.FIRST_COMPLETED)
            if close_started.is_set():
                for _ in range(3):
                    task.cancel()
                    await asyncio.sleep(0)
            watcher.cancel()
            await asyncio.gather(watcher, return_exceptions=True)
            release_close.set()
        with pytest.raises(fault_type):
            await asyncio.wait_for(task, 2)
        await asyncio.wait_for(connected.wait(), 1)
        await client.close()
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        leaked = [writer for writer in client_writers if not writer.is_closing()]
        for writer in client_writers:
            writer.close()
            await writer.wait_closed()
        await asyncio.wait_for(eof.wait(), 1)
        assert not leaked, "post-connect BaseException left the signer FD open"
