# SPDX-License-Identifier: AGPL-3.0-only
"""PR13 round-9 lifecycle and schema-parity regressions."""

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
from jsonschema import Draft202012Validator
from websockets.asyncio.server import serve

from misscomputer_subnet.chain import BittensorChain
from misscomputer_subnet.chain_quorum import FinalizedRpcQuorum
from misscomputer_subnet.weight_signer_protocol import SignerProtocolError, SignerResponse

ROOT = Path(__file__).resolve().parents[2]


class LifecycleSentinel(BaseException):
    """Non-Exception failure used to exercise cancellation-grade cleanup."""


async def _assert_transport_baseline(
    connections: list[SubstrateConnection],
    baseline_fds: set[str],
    baseline_tasks: set[asyncio.Task[Any]],
) -> None:
    await asyncio.sleep(0)
    await asyncio.sleep(0)
    assert all(raw._session._ws is None for raw in connections)
    assert all(
        raw._session._supervisor is None or raw._session._supervisor.done() for raw in connections
    )
    current_tasks = {
        task for task in asyncio.all_tasks() if task.get_name() == "rpc-session" and not task.done()
    }
    assert current_tasks == baseline_tasks
    assert set(os.listdir("/proc/self/fd")) == baseline_fds


@pytest.mark.parametrize(
    "first_failure",
    [None, OSError, LifecycleSentinel, asyncio.CancelledError],
    ids=["success", "exception", "baseexception", "cancelled"],
)
@pytest.mark.parametrize("cancel_close", [False, True], ids=["ordinary", "repeated-cancel"])
async def test_close_drains_old_open_without_retiring_replacement(
    monkeypatch: pytest.MonkeyPatch,
    first_failure: type[BaseException] | None,
    cancel_close: bool,
) -> None:
    """An admitted opener cannot survive close or act on a later generation."""

    assert bittensor.__version__ == "11.1.0"
    entered, release = asyncio.Event(), asyncio.Event()
    connections: list[SubstrateConnection] = []
    peers: list[Any] = []
    real_interface = RpcSubstrate._interface
    codec_calls = 0

    def interface(self: Any, *args: Any) -> SubstrateConnection:
        raw = real_interface(self, *args)
        connections.append(raw)
        return raw

    async def codec(*args: Any, **kwargs: Any) -> None:
        nonlocal codec_calls
        codec_calls += 1
        if codec_calls == 1:
            entered.set()
            try:
                await release.wait()
            except asyncio.CancelledError:
                # Model an initializer that cannot stop until its codec boundary
                # is released by the underlying SDK.
                await release.wait()
            if first_failure is not None:
                raise first_failure("old-initialization-failure")

    async def handle(websocket: Any) -> None:
        peers.append(websocket)
        await websocket.wait_closed()

    monkeypatch.setattr(RpcSubstrate, "_interface", interface)
    monkeypatch.setattr(RuntimeManager, "codec_at", codec)
    monkeypatch.setattr(bittensor.config, "token_symbols_fresh", lambda _: True)
    monkeypatch.setattr(bittensor.config, "load_token_symbols", lambda _: {})
    async with serve(handle, "127.0.0.1", 0) as server:
        baseline_fds = set(os.listdir("/proc/self/fd"))
        baseline_tasks = {
            task
            for task in asyncio.all_tasks()
            if task.get_name() == "rpc-session" and not task.done()
        }
        endpoint = f"ws://127.0.0.1:{server.sockets[0].getsockname()[1]}"
        chain = BittensorChain(network="finney", netuid=24, rpc_endpoint=endpoint)
        opening = asyncio.create_task(chain.open(), name="round9-old-chain-open")
        closer: asyncio.Task[None] | None = None
        try:
            await asyncio.wait_for(entered.wait(), 2)
            first_raw = connections[0]
            first_websocket = first_raw._session._ws
            first_socket = first_websocket.transport.get_extra_info("socket")
            first_supervisor = first_raw._session._supervisor
            assert first_socket is not None and first_socket.fileno() >= 0
            assert first_supervisor is not None and not first_supervisor.done()

            closer = asyncio.create_task(chain.close(), name="round9-chain-close")
            await asyncio.sleep(0)
            if cancel_close:
                for _ in range(3):
                    closer.cancel()
                    await asyncio.sleep(0)
            completed, _ = await asyncio.wait({closer}, timeout=0.1)
            close_returned_early = bool(completed)
            replacement: Any = None
            replacement_socket: Any = None
            if close_returned_early:
                await chain.open()
                replacement = chain._BittensorChain__client
                replacement_websocket = connections[1]._session._ws
                replacement_socket = replacement_websocket.transport.get_extra_info("socket")
                assert replacement_socket is not None and replacement_socket.fileno() >= 0

            release.set()
            await asyncio.wait_for(asyncio.gather(opening, return_exceptions=True), 2)
            await asyncio.gather(closer, return_exceptions=True)
            assert not close_returned_early
            if replacement is not None:
                assert chain._BittensorChain__client is replacement
                assert replacement_socket.fileno() >= 0
        finally:
            release.set()
            await asyncio.gather(opening, return_exceptions=True)
            if closer is not None:
                await asyncio.gather(closer, return_exceptions=True)
            await asyncio.gather(chain.close(), return_exceptions=True)
            for raw in connections:
                await asyncio.gather(raw.close(), return_exceptions=True)
            for peer in peers:
                peer.transport.abort()
            await asyncio.gather(*(peer.wait_closed() for peer in peers), return_exceptions=True)
            await _assert_transport_baseline(connections, baseline_fds, baseline_tasks)


@pytest.mark.parametrize("topology", ["primary", "archive", "quorum"])
@pytest.mark.parametrize(
    "fault_type",
    [KeyError, LifecycleSentinel, asyncio.CancelledError],
    ids=["exception", "baseexception", "cancelled"],
)
async def test_owner_close_joins_transport_initiated_retirement(
    monkeypatch: pytest.MonkeyPatch,
    topology: str,
    fault_type: type[BaseException],
) -> None:
    """Owner close joins cleanup already started inside the RPC transport."""

    assert bittensor.__version__ == "11.1.0"
    entered, release = asyncio.Event(), asyncio.Event()
    connections: list[SubstrateConnection] = []
    peers: list[Any] = []
    real_interface = RpcSubstrate._interface
    real_close = SubstrateConnection.close
    codec_calls = 0
    close_calls = 0

    def interface(self: Any, *args: Any) -> SubstrateConnection:
        raw = real_interface(self, *args)
        connections.append(raw)
        return raw

    async def codec(*args: Any, **kwargs: Any) -> None:
        nonlocal codec_calls
        codec_calls += 1
        failure_call = {"primary": 1, "archive": 2, "quorum": 3}[topology]
        if codec_calls == failure_call:
            raise fault_type("transport-initialization-failure")

    async def delayed_close(raw: SubstrateConnection) -> None:
        nonlocal close_calls
        close_calls += 1
        if close_calls == 1:
            entered.set()
            try:
                await release.wait()
            except asyncio.CancelledError:
                await release.wait()
        await real_close(raw)

    async def handle(websocket: Any) -> None:
        peers.append(websocket)
        await websocket.wait_closed()

    monkeypatch.setattr(RpcSubstrate, "_interface", interface)
    monkeypatch.setattr(SubstrateConnection, "close", delayed_close)
    monkeypatch.setattr(RuntimeManager, "codec_at", codec)
    monkeypatch.setattr(bittensor.config, "token_symbols_fresh", lambda _: True)
    monkeypatch.setattr(bittensor.config, "load_token_symbols", lambda _: {})
    async with serve(handle, "127.0.0.1", 0) as server:
        baseline_fds = set(os.listdir("/proc/self/fd"))
        baseline_tasks = {
            task
            for task in asyncio.all_tasks()
            if task.get_name() == "rpc-session" and not task.done()
        }
        endpoint = f"ws://127.0.0.1:{server.sockets[0].getsockname()[1]}"
        chain = BittensorChain(network="finney", netuid=24, rpc_endpoint=endpoint)
        owner: BittensorChain | FinalizedRpcQuorum = chain
        if topology == "quorum":
            owner = FinalizedRpcQuorum(
                (
                    chain,
                    BittensorChain(network="finney", netuid=24, rpc_endpoint=endpoint),
                )
            )
        if topology in {"archive", "quorum"}:
            await owner.open()
            substrate = chain._BittensorChain__client._substrate
            substrate.archive_endpoints = [endpoint]
            initializing = asyncio.create_task(
                substrate._archive(), name="round9-archive-initialization"
            )
        else:
            initializing = asyncio.create_task(chain.open(), name="round9-primary-open")
        closer: asyncio.Task[None] | None = None
        try:
            await asyncio.wait_for(entered.wait(), 2)
            sockets = [raw._session._ws.transport.get_extra_info("socket") for raw in connections]
            assert all(sock is not None and sock.fileno() >= 0 for sock in sockets)
            closer = asyncio.create_task(owner.close(), name="round9-owner-close")
            completed, _ = await asyncio.wait({closer}, timeout=0.1)
            live = [sock for sock in sockets if sock is not None and sock.fileno() >= 0]
            assert not completed or not live
        finally:
            release.set()
            await asyncio.gather(initializing, return_exceptions=True)
            if closer is not None:
                await asyncio.gather(closer, return_exceptions=True)
            await asyncio.gather(owner.close(), return_exceptions=True)
            for raw in connections:
                await asyncio.gather(real_close(raw), return_exceptions=True)
            for peer in peers:
                peer.transport.abort()
            await asyncio.gather(*(peer.wait_closed() for peer in peers), return_exceptions=True)
            await _assert_transport_baseline(connections, baseline_fds, baseline_tasks)


def test_schema_and_parser_both_reject_terminal_newline_reference() -> None:
    document = {
        "error_code": "submission_timeout",
        "extrinsic_ref": "bad\n",
        "request_id": "ab" * 32,
        "schema": "miss.computer/misscomputer-subnet/weight-signer-response",
        "schema_version": 2,
        "status": "ambiguous",
    }
    schema = json.loads(
        (ROOT / "contracts/schemas/weight-signer-response.v2.schema.json").read_text()
    )
    assert not Draft202012Validator(schema).is_valid(document)
    encoded = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"
    with pytest.raises(SignerProtocolError):
        SignerResponse.from_bytes(encoded)
