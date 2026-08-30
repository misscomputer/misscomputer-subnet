# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator, Callable
from pathlib import Path
from typing import Any

import bittensor as bt
import httpx
import pytest
from fastapi import HTTPException
from starlette.requests import Request

from misscomputer_subnet.auth import BRIDGE_MAX_BODY, SQLiteNonceStore
from misscomputer_subnet.chain import MockChain, MockPeer
from misscomputer_subnet.ingress import read_request_body
from misscomputer_subnet.miner import MinerNeuron
from misscomputer_subnet.protocol import LocalCapabilities

VALIDATOR = bt.sp_core.Keypair.create_from_uri("//IngressValidator")
MINER = bt.sp_core.Keypair.create_from_uri("//IngressMiner")


class CapabilityBridge:
    secret = b"i" * 32
    base_url = "http://go.invalid"
    timeout = 1.0
    transport = None

    async def request(
        self,
        method: str,
        path: str,
        *,
        value: Any = None,
        response_model: type[Any] | None = None,
    ) -> LocalCapabilities:
        assert method == "GET" and path == "/v1/capabilities"
        return LocalCapabilities(
            protocol="subnet-synapse.v2",
            network="local",
            netuid=24,
            miner_hotkey=MINER.ss58_address,
            miner_uid=1,
            service_public_key="22" * 32,
            transport="http",
            transport_certificate_sha256=None,
            features=["deploy"],
            max_body_bytes=BRIDGE_MAX_BODY,
        )


class CountingStream(httpx.AsyncByteStream):
    def __init__(self, chunks: list[bytes]) -> None:
        self.chunks = chunks
        self.yielded = 0
        self.closed = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        for chunk in self.chunks:
            self.yielded += 1
            yield chunk

    async def aclose(self) -> None:
        self.closed = True


def raw_request(
    receive: Callable[[], Any], *, headers: list[tuple[bytes, bytes]] | None = None
) -> Request:
    return Request(
        {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": "POST",
            "scheme": "https",
            "path": "/api/v1/deploy",
            "raw_path": b"/api/v1/deploy",
            "query_string": b"",
            "headers": headers or [],
            "client": ("203.0.113.7", 12345),
            "server": ("8.8.8.8", 8091),
        },
        receive,
    )


def ingress_neuron(tmp_path: Path) -> tuple[MinerNeuron, int]:
    peers = (
        MockPeer("//IngressValidator", 0, None, True, 2_000),
        MockPeer("//IngressMiner", 1, "http://miner.invalid", False, 10),
    )
    chain = MockChain(network="local", netuid=24, own_uri="//IngressMiner", peers=peers)
    neuron = MinerNeuron(
        chain=chain,
        hotkey_signer=chain.hotkey_signer,
        network="local",
        netuid=24,
        configured_uid=1,
        bridge=CapabilityBridge(),  # type: ignore[arg-type]
        nonce_store=SQLiteNonceStore(str(tmp_path / "ingress.db")),
        min_validator_stake=1_000,
        sync_interval=10,
        max_concurrency=1,
        mock_http=True,
        tls_config=None,
    )
    return neuron, chain.block


@pytest.mark.asyncio
async def test_content_length_over_limit_is_rejected_without_receive() -> None:
    calls = 0

    async def receive() -> Any:
        nonlocal calls
        calls += 1
        raise AssertionError("oversized declared body was read")

    request = raw_request(receive, headers=[(b"content-length", str(BRIDGE_MAX_BODY + 1).encode())])
    with pytest.raises(HTTPException) as caught:
        await read_request_body(request, max_bytes=BRIDGE_MAX_BODY)
    assert caught.value.status_code == 413
    assert caught.value.headers == {"Connection": "close"}
    assert calls == 0


@pytest.mark.asyncio
async def test_chunked_overflow_stops_after_detection_byte() -> None:
    chunks = [b"x" * BRIDGE_MAX_BODY, b"!", b"secret-must-not-be-consumed"]
    calls = 0

    async def receive() -> Any:
        nonlocal calls
        chunk = chunks[calls]
        calls += 1
        return {"type": "http.request", "body": chunk, "more_body": calls < len(chunks)}

    with pytest.raises(HTTPException) as caught:
        await read_request_body(raw_request(receive), max_bytes=BRIDGE_MAX_BODY)
    assert caught.value.status_code == 413
    assert calls == 2


@pytest.mark.asyncio
async def test_idle_body_deadline_cancels_pending_receive_cleanly() -> None:
    entered = asyncio.Event()
    cancelled = asyncio.Event()

    async def receive() -> Any:
        entered.set()
        try:
            await asyncio.Future()
        finally:
            cancelled.set()

    task = asyncio.create_task(
        read_request_body(
            raw_request(receive), max_bytes=BRIDGE_MAX_BODY, idle_timeout=0.01, total_timeout=1
        )
    )
    await entered.wait()
    with pytest.raises(HTTPException) as caught:
        await task
    assert caught.value.status_code == 408
    assert "idle" in str(caught.value.detail)
    assert cancelled.is_set()


@pytest.mark.asyncio
async def test_total_body_deadline_stops_slow_cumulative_stream(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ticks = iter((0.0, 0.0, 2.0))
    monkeypatch.setattr("misscomputer_subnet.ingress.monotonic", lambda: next(ticks))
    calls = 0

    async def receive() -> Any:
        nonlocal calls
        calls += 1
        return {"type": "http.request", "body": b"x", "more_body": True}

    with pytest.raises(HTTPException) as caught:
        await read_request_body(
            raw_request(receive), max_bytes=BRIDGE_MAX_BODY, idle_timeout=1, total_timeout=1
        )
    assert caught.value.status_code == 408
    assert "total" in str(caught.value.detail)
    assert calls == 1


@pytest.mark.asyncio
async def test_body_reader_preserves_caller_cancellation() -> None:
    entered = asyncio.Event()
    cancelled = asyncio.Event()

    async def receive() -> Any:
        entered.set()
        try:
            await asyncio.Future()
        finally:
            cancelled.set()

    task = asyncio.create_task(
        read_request_body(
            raw_request(receive), max_bytes=BRIDGE_MAX_BODY, idle_timeout=10, total_timeout=10
        )
    )
    await entered.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert cancelled.is_set()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/capabilities",
        "/api/v1/deploy",
        "/api/v1/status",
        "/api/v1/deactivate",
        "/runtime/endpoint/file",
    ],
)
async def test_every_public_body_route_stops_chunked_overflow(
    tmp_path: Path, path: str, caplog: pytest.LogCaptureFixture
) -> None:
    neuron, _ = ingress_neuron(tmp_path)
    marker = b"private-body-marker-must-not-be-read-or-logged"
    stream = CountingStream([b"x" * BRIDGE_MAX_BODY, b"!", marker])
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=neuron.app), base_url="http://miner"
    ) as client:
        response = await client.post(path, content=stream)
    assert response.status_code == 413
    assert stream.yielded == 2
    assert marker not in response.content
    assert marker.decode() not in caplog.text
    assert response.headers["connection"] == "close"
    await stream.aclose()
    assert stream.closed


@pytest.mark.asyncio
async def test_exact_limit_signed_body_remains_valid(tmp_path: Path) -> None:
    neuron, _ = ingress_neuron(tmp_path)
    snapshot = await neuron.chain.sync()
    await neuron.state.set(snapshot)
    neuron.ready.set()
    value = {
        "protocol": "subnet-synapse.v2",
        "request_id": "exact-limit-capability",
        "network": "local",
        "netuid": 24,
        "chain_block": snapshot.block,
        "caller_hotkey": VALIDATOR.ss58_address,
        "challenge": "exact-limit-request",
    }
    compact = json.dumps(value, separators=(",", ":")).encode()
    body = compact + b" " * (BRIDGE_MAX_BODY - len(compact))
    assert len(body) == BRIDGE_MAX_BODY
    headers = bt.http_auth.sign(
        VALIDATOR,
        method="POST",
        path="/api/v1/capabilities",
        body=body,
        receiver_ss58=MINER.ss58_address,
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=neuron.app), base_url="http://miner"
    ) as client:
        response = await client.post("/api/v1/capabilities", content=body, headers=headers)
    assert response.status_code == 200, response.text
    assert response.json()["miner_hotkey"] == MINER.ss58_address
