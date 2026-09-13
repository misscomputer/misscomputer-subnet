# SPDX-License-Identifier: AGPL-3.0-only
"""PR13 round-10 public-open handoff and response-schema regressions."""

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
from misscomputer_subnet.weight_executor import WeightExecutionError
from misscomputer_subnet.weight_signer_protocol import SignerResponse

ROOT = Path(__file__).resolve().parents[2]
OWNED_TASK_NAMES = frozenset(
    {
        "bittensor-chain-cleanup",
        "bittensor-chain-close",
        "bittensor-chain-initialization-cleanup",
        "bittensor-chain-open",
        "bittensor-chain-open-cleanup",
        "bittensor-transport-cleanup",
        "bittensor-transport-retirement",
        "rpc-session",
    }
)


def _owned_tasks() -> set[asyncio.Task[Any]]:
    return {
        task
        for task in asyncio.all_tasks()
        if task.get_name() in OWNED_TASK_NAMES and not task.done()
    }


async def _assert_resource_baseline(
    connections: list[SubstrateConnection],
    baseline_fds: set[str],
    baseline_tasks: set[asyncio.Task[Any]],
) -> None:
    for _ in range(3):
        await asyncio.sleep(0)
    assert all(raw._session._ws is None for raw in connections)
    assert all(
        raw._session._supervisor is None or raw._session._supervisor.done() for raw in connections
    )
    assert _owned_tasks() == baseline_tasks
    assert set(os.listdir("/proc/self/fd")) == baseline_fds


def _install_warm_sdk(
    monkeypatch: pytest.MonkeyPatch,
    connections: list[SubstrateConnection],
) -> None:
    real_interface = RpcSubstrate._interface

    def interface(self: Any, *args: Any) -> SubstrateConnection:
        raw = real_interface(self, *args)
        connections.append(raw)
        return raw

    async def codec(*args: Any, **kwargs: Any) -> None:
        return None

    monkeypatch.setattr(RpcSubstrate, "_interface", interface)
    monkeypatch.setattr(RuntimeManager, "codec_at", codec)
    monkeypatch.setattr(bittensor.config, "token_symbols_fresh", lambda _: True)
    monkeypatch.setattr(bittensor.config, "load_token_symbols", lambda _: {})


@pytest.mark.parametrize("operation", ["reopen", "repeated-close"])
@pytest.mark.parametrize("iteration", range(5))
async def test_cancel_before_admitted_opener_first_step_is_failure_atomic(
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
    iteration: int,
) -> None:
    """A child cancelled before its first opcode cannot retain chain ownership."""

    assert bittensor.__version__ == "11.1.0"
    connections: list[SubstrateConnection] = []
    peers: list[Any] = []
    _install_warm_sdk(monkeypatch, connections)

    async def handle(websocket: Any) -> None:
        peers.append(websocket)
        await websocket.wait_closed()

    async with serve(handle, "127.0.0.1", 0) as server:
        baseline_fds = set(os.listdir("/proc/self/fd"))
        baseline_tasks = _owned_tasks()
        endpoint = f"ws://127.0.0.1:{server.sockets[0].getsockname()[1]}"
        chain = BittensorChain(network="finney", netuid=24, rpc_endpoint=endpoint)
        opening = asyncio.create_task(chain.open(), name=f"round10-prestart-{iteration}")
        # create_task enqueues open() before this callback. open() admits and
        # creates its child, then this callback cancels the parent before the
        # newly enqueued child can execute its first opcode.
        asyncio.get_running_loop().call_soon(opening.cancel)
        retained_client = False
        retained_opener = False
        observed: BaseException | None = None
        try:
            result = (await asyncio.gather(opening, return_exceptions=True))[0]
            assert isinstance(result, asyncio.CancelledError)
            retained_client = chain._BittensorChain__client is not None
            retained_opener = chain._BittensorChain__open_task is not None
            try:
                if operation == "reopen":
                    await chain.open()
                else:
                    await chain.close()
                    await chain.close()
            except BaseException as exc:
                observed = exc
        finally:
            await asyncio.gather(chain.close(), return_exceptions=True)
            for raw in connections:
                await asyncio.gather(raw.close(), return_exceptions=True)
            for peer in peers:
                peer.transport.abort()
            await asyncio.gather(*(peer.wait_closed() for peer in peers), return_exceptions=True)
            await _assert_resource_baseline(connections, baseline_fds, baseline_tasks)
        assert not retained_client
        assert not retained_opener
        assert observed is None


@pytest.mark.parametrize("iteration", range(5))
async def test_cancel_after_connect_before_public_result_retires_client(
    monkeypatch: pytest.MonkeyPatch,
    iteration: int,
) -> None:
    """A successful child/result handoff remains owned until open() returns."""

    assert bittensor.__version__ == "11.1.0"
    connections: list[SubstrateConnection] = []
    peers: list[Any] = []
    real_connect = bittensor.Client.connect
    _install_warm_sdk(monkeypatch, connections)
    opening: asyncio.Task[None] | None = None

    async def connect(client: Any) -> Any:
        result = await real_connect(client)
        assert opening is not None
        # The child has acquired a real socket and supervisor. Cancel the
        # public caller at the result-delivery handoff.
        asyncio.get_running_loop().call_soon(opening.cancel)
        return result

    async def handle(websocket: Any) -> None:
        peers.append(websocket)
        await websocket.wait_closed()

    monkeypatch.setattr(bittensor.Client, "connect", connect)
    async with serve(handle, "127.0.0.1", 0) as server:
        baseline_fds = set(os.listdir("/proc/self/fd"))
        baseline_tasks = _owned_tasks()
        endpoint = f"ws://127.0.0.1:{server.sockets[0].getsockname()[1]}"
        chain = BittensorChain(network="finney", netuid=24, rpc_endpoint=endpoint)
        opening = asyncio.create_task(chain.open(), name=f"round10-handoff-{iteration}")
        retained_client = False
        retained_opener = False
        live_sockets: list[int] = []
        live_supervisors: list[asyncio.Task[Any]] = []
        try:
            result = (await asyncio.gather(opening, return_exceptions=True))[0]
            assert isinstance(result, asyncio.CancelledError)
            retained_client = chain._BittensorChain__client is not None
            retained_opener = chain._BittensorChain__open_task is not None
            live_sockets = [
                socket.fileno()
                for raw in connections
                if raw._session._ws is not None
                if (socket := raw._session._ws.transport.get_extra_info("socket")) is not None
                and socket.fileno() >= 0
            ]
            live_supervisors = [
                supervisor
                for raw in connections
                if (supervisor := raw._session._supervisor) is not None and not supervisor.done()
            ]
            await chain.close()
            await chain.close()
            await chain.open()
        finally:
            await asyncio.gather(chain.close(), return_exceptions=True)
            for raw in connections:
                await asyncio.gather(raw.close(), return_exceptions=True)
            for peer in peers:
                peer.transport.abort()
            await asyncio.gather(*(peer.wait_closed() for peer in peers), return_exceptions=True)
            await _assert_resource_baseline(connections, baseline_fds, baseline_tasks)
        assert not retained_client
        assert not retained_opener
        assert not live_sockets
        assert not live_supervisors


def _response_for(field: str, value: str) -> dict[str, object]:
    document: dict[str, object] = {
        "error_code": None,
        "extrinsic_ref": "103-2",
        "request_id": "ab" * 32,
        "schema": "miss.computer/misscomputer-subnet/weight-signer-response",
        "schema_version": 2,
        "status": "confirmed",
    }
    if field == "error_code":
        document.update(error_code=value, extrinsic_ref=None, status="rejected")
    else:
        document[field] = value
    return document


def _parser_accepts(document: dict[str, object]) -> bool:
    rendered = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"
    try:
        SignerResponse.from_bytes(rendered)
    except WeightExecutionError:
        return False
    return True


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("extrinsic_ref", ""),
        ("extrinsic_ref", "x" * 257),
        ("extrinsic_ref", "103-2\n"),
        ("extrinsic_ref", "103 2"),
        ("error_code", ""),
        ("error_code", "x" * 65),
        ("error_code", "submission_timeout\n"),
        ("error_code", "Submission_timeout"),
        ("request_id", "a" * 63),
        ("request_id", "a" * 65),
        ("request_id", "a" * 64 + "\n"),
        ("request_id", "g" * 64),
    ],
    ids=lambda value: repr(value),
)
def test_response_schema_and_parser_reject_the_same_invalid_strings(
    field: str,
    value: str,
) -> None:
    schema = json.loads(
        (ROOT / "contracts/schemas/weight-signer-response.v2.schema.json").read_text()
    )
    document = _response_for(field, value)
    assert not _parser_accepts(document)
    assert not Draft202012Validator(schema).is_valid(document)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("extrinsic_ref", "!"),
        ("extrinsic_ref", "~" * 256),
        ("error_code", "a"),
        ("error_code", "a" * 64),
        ("request_id", "0" * 64),
        ("request_id", "f" * 64),
    ],
)
def test_response_schema_and_parser_accept_the_same_boundary_strings(
    field: str,
    value: str,
) -> None:
    schema = json.loads(
        (ROOT / "contracts/schemas/weight-signer-response.v2.schema.json").read_text()
    )
    document = _response_for(field, value)
    assert _parser_accepts(document)
    Draft202012Validator(schema).validate(document)
