# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import bittensor as bt
import httpx
import pytest

from misscomputer_subnet.auth import BridgeClient, SQLiteNonceStore, sign_service_binding
from misscomputer_subnet.chain import MockChain, MockPeer
from misscomputer_subnet.miner import RUNTIME_MAX_RESPONSE, MinerNeuron, PriorityGate
from misscomputer_subnet.protocol import LocalCapabilities, ServiceKeyBinding


class FakeBridge:
    secret = b"x" * 32
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
    ) -> Any:
        assert method == "GET"
        assert path == "/v1/capabilities"
        return LocalCapabilities(
            protocol="subnet-synapse.v2",
            network="local",
            netuid=24,
            miner_hotkey=MINER.ss58_address,
            miner_uid=1,
            service_public_key="22" * 32,
            transport="http",
            transport_certificate_sha256=None,
            features=["deploy", "status", "deactivate"],
            max_body_bytes=1 << 20,
        )


class ExpectedBridgeCall(RuntimeError):
    pass


class ChunkedResponse(httpx.AsyncByteStream):
    def __init__(self, chunks: list[bytes]) -> None:
        self.chunks = chunks
        self.yielded = 0
        self.closed = False

    async def __aiter__(self) -> Any:
        for chunk in self.chunks:
            self.yielded += 1
            yield chunk

    async def aclose(self) -> None:
        self.closed = True


class DeployRecordingBridge(FakeBridge):
    assignment: dict[str, Any] | None = None

    async def request(
        self,
        method: str,
        path: str,
        *,
        value: Any = None,
        response_model: type[Any] | None = None,
    ) -> Any:
        if method == "POST" and path == "/v1/assignments":
            assert isinstance(value, dict)
            self.assignment = value
            raise ExpectedBridgeCall
        return await super().request(method, path, value=value, response_model=response_model)


VALIDATOR = bt.sp_core.Keypair.create_from_uri("//Validator")
MINER = bt.sp_core.Keypair.create_from_uri("//Miner1")
UNAUTHORIZED = bt.sp_core.Keypair.create_from_uri("//Unpermitted")
DEPLOY_FIXTURE = json.loads(
    (Path(__file__).resolve().parents[2] / "contracts/fixtures/deploy.v2.json").read_text()
)["ticket"]


@pytest.mark.asyncio
async def test_btauth_capability_authorization_replay_and_priority_policy(tmp_path: Path) -> None:
    peers = (
        MockPeer("//Validator", 0, None, True, 2_000),
        MockPeer("//Miner1", 1, "http://miner.invalid", False, 10),
        MockPeer("//Unpermitted", 2, None, False, 10_000),
    )
    chain = MockChain(network="local", netuid=24, own_uri="//Miner1", peers=peers)
    neuron = MinerNeuron(
        chain=chain,
        hotkey_signer=chain.hotkey_signer,
        network="local",
        netuid=24,
        configured_uid=1,
        bridge=FakeBridge(),  # type: ignore[arg-type]
        nonce_store=SQLiteNonceStore(str(tmp_path / "state.db")),
        min_validator_stake=1_000,
        sync_interval=10,
        max_concurrency=1,
        mock_http=True,
        tls_config=None,
    )
    snapshot = await chain.sync()
    await neuron.state.set(snapshot)
    neuron.ready.set()
    value = {
        "protocol": "subnet-synapse.v2",
        "request_id": "capability-request",
        "network": "local",
        "netuid": 24,
        "chain_block": snapshot.block,
        "caller_hotkey": VALIDATOR.ss58_address,
        "challenge": "fresh-capability-challenge",
    }
    body = json.dumps(value, separators=(",", ":")).encode()
    headers = bt.http_auth.sign(
        VALIDATOR,
        method="POST",
        path="/api/v1/capabilities",
        body=body,
        receiver_ss58=MINER.ss58_address,
    )
    transport = httpx.ASGITransport(app=neuron.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://miner") as client:
        response = await client.post("/api/v1/capabilities", content=body, headers=headers)
        assert response.status_code == 200, response.text
        assert response.json()["service_binding"]["hotkey"] == MINER.ss58_address
        replay = await client.post("/api/v1/capabilities", content=body, headers=headers)
        assert replay.status_code == 401

        value["caller_hotkey"] = UNAUTHORIZED.ss58_address
        unauthorized_body = json.dumps(value, separators=(",", ":")).encode()
        unauthorized_headers = bt.http_auth.sign(
            UNAUTHORIZED,
            method="POST",
            path="/api/v1/capabilities",
            body=unauthorized_body,
            receiver_ss58=MINER.ss58_address,
        )
        unauthorized = await client.post(
            "/api/v1/capabilities",
            content=unauthorized_body,
            headers=unauthorized_headers,
        )
        assert unauthorized.status_code == 403

        wrong_receiver_headers = bt.http_auth.sign(
            VALIDATOR,
            method="POST",
            path="/api/v1/capabilities",
            body=body,
            receiver_ss58=VALIDATOR.ss58_address,
        )
        wrong_receiver = await client.post(
            "/api/v1/capabilities", content=body, headers=wrong_receiver_headers
        )
        assert wrong_receiver.status_code == 401

        malformed_body = b"{}"
        malformed_headers = bt.http_auth.sign(
            VALIDATOR,
            method="POST",
            path="/api/v1/capabilities",
            body=malformed_body,
            receiver_ss58=MINER.ss58_address,
        )
        malformed = await client.post(
            "/api/v1/capabilities", content=malformed_body, headers=malformed_headers
        )
        assert malformed.status_code == 400


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["wrong_uid", "wrong_hotkey", "expired"])
async def test_deploy_rejects_cross_identity_and_expired_ticket(
    tmp_path: Path, failure: str
) -> None:
    peers = (
        MockPeer("//Validator", 0, None, True, 2_000),
        MockPeer("//Miner1", 1, "http://miner.invalid", False, 10),
    )
    chain = MockChain(network="local", netuid=24, own_uri="//Miner1", peers=peers)
    neuron = MinerNeuron(
        chain=chain,
        hotkey_signer=chain.hotkey_signer,
        network="local",
        netuid=24,
        configured_uid=1,
        bridge=FakeBridge(),  # type: ignore[arg-type]
        nonce_store=SQLiteNonceStore(str(tmp_path / "state.db")),
        min_validator_stake=1_000,
        sync_interval=10,
        max_concurrency=1,
        mock_http=True,
        tls_config=None,
    )
    snapshot = await chain.sync()
    await neuron.state.set(snapshot)
    neuron.ready.set()
    service_key = "11" * 32
    validator_binding = sign_service_binding(
        ServiceKeyBinding(
            role="validator",
            transport="local",
            transport_certificate_sha256=None,
            network="local",
            netuid=24,
            hotkey=VALIDATOR.ss58_address,
            uid=0,
            service_public_key=service_key,
            generation=snapshot.epoch + 1,
            valid_from_block=snapshot.block,
            expires_at_block=snapshot.block + 24,
            challenge="validator-service:" + service_key,
        ),
        VALIDATOR,
    )
    ticket = json.loads(json.dumps(DEPLOY_FIXTURE))
    ticket["miner_id"] = MINER.ss58_address
    ticket["subnet"].update(
        {
            "validator_hotkey": VALIDATOR.ss58_address,
            "miner_hotkey": MINER.ss58_address,
            "miner_uid": 1,
            "miner_transport": "http",
            "miner_tls_certificate_sha256": None,
            "chain_block": snapshot.block,
            "epoch": snapshot.epoch,
            "expires_at_block": snapshot.block + 12,
            "validator_service_public_key": service_key,
            "miner_service_public_key": "22" * 32,
        }
    )
    if failure == "wrong_uid":
        ticket["subnet"]["miner_uid"] = 2
    elif failure == "wrong_hotkey":
        ticket["miner_id"] = UNAUTHORIZED.ss58_address
        ticket["subnet"]["miner_hotkey"] = UNAUTHORIZED.ss58_address
    else:
        ticket["subnet"]["chain_block"] = snapshot.block - 12
        ticket["subnet"]["epoch"] = (snapshot.block - 12) // snapshot.tempo
        ticket["subnet"]["expires_at_block"] = snapshot.block
    value = {
        "protocol": "subnet-synapse.v2",
        "request_id": f"deploy-{failure}",
        "current_block": snapshot.block,
        "caller_hotkey": VALIDATOR.ss58_address,
        "validator_binding": validator_binding.model_dump(mode="json"),
        "ticket": ticket,
    }
    body = json.dumps(value, separators=(",", ":")).encode()
    headers = bt.http_auth.sign(
        VALIDATOR,
        method="POST",
        path="/api/v1/deploy",
        body=body,
        receiver_ss58=MINER.ss58_address,
    )
    transport = httpx.ASGITransport(app=neuron.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://miner") as client:
        response = await client.post("/api/v1/deploy", content=body, headers=headers)
    assert response.status_code == 403, response.text


@pytest.mark.asyncio
async def test_deploy_accepts_validator_binding_one_block_ahead(tmp_path: Path) -> None:
    peers = (
        MockPeer("//Validator", 0, None, True, 2_000),
        MockPeer("//Miner1", 1, "http://miner.invalid", False, 10),
    )
    chain = MockChain(network="local", netuid=24, own_uri="//Miner1", peers=peers)
    bridge = DeployRecordingBridge()
    neuron = MinerNeuron(
        chain=chain,
        hotkey_signer=chain.hotkey_signer,
        network="local",
        netuid=24,
        configured_uid=1,
        bridge=bridge,  # type: ignore[arg-type]
        nonce_store=SQLiteNonceStore(str(tmp_path / "skew.db")),
        min_validator_stake=1_000,
        sync_interval=10,
        max_concurrency=1,
        mock_http=True,
        tls_config=None,
    )
    snapshot = await chain.sync()
    await neuron.state.set(snapshot)
    neuron.ready.set()
    request_block = snapshot.block + 1
    service_key = "11" * 32
    validator_binding = sign_service_binding(
        ServiceKeyBinding(
            role="validator",
            transport="local",
            transport_certificate_sha256=None,
            network="local",
            netuid=24,
            hotkey=VALIDATOR.ss58_address,
            uid=0,
            service_public_key=service_key,
            generation=request_block // snapshot.tempo + 1,
            valid_from_block=request_block,
            expires_at_block=request_block + 24,
            challenge="validator-service:" + service_key,
        ),
        VALIDATOR,
    )
    ticket = json.loads(json.dumps(DEPLOY_FIXTURE))
    ticket["miner_id"] = MINER.ss58_address
    ticket["subnet"].update(
        {
            "validator_hotkey": VALIDATOR.ss58_address,
            "miner_hotkey": MINER.ss58_address,
            "miner_uid": 1,
            "miner_transport": "http",
            "miner_tls_certificate_sha256": None,
            "chain_block": request_block,
            "epoch": request_block // snapshot.tempo,
            "expires_at_block": request_block + 12,
            "validator_service_public_key": service_key,
            "miner_service_public_key": "22" * 32,
        }
    )
    value = {
        "protocol": "subnet-synapse.v2",
        "request_id": "deploy-one-block-skew",
        "current_block": request_block,
        "caller_hotkey": VALIDATOR.ss58_address,
        "validator_binding": validator_binding.model_dump(mode="json"),
        "ticket": ticket,
    }
    body = json.dumps(value, separators=(",", ":")).encode()
    headers = bt.http_auth.sign(
        VALIDATOR,
        method="POST",
        path="/api/v1/deploy",
        body=body,
        receiver_ss58=MINER.ss58_address,
    )
    transport = httpx.ASGITransport(app=neuron.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://miner") as client:
        with pytest.raises(ExpectedBridgeCall):
            await client.post("/api/v1/deploy", content=body, headers=headers)
    assert bridge.assignment is not None
    assert bridge.assignment["current_block"] == request_block


@pytest.mark.asyncio
async def test_priority_gate_cancellation_does_not_leak_capacity() -> None:
    gate = PriorityGate(1)
    release_first = asyncio.Event()

    async def holder() -> None:
        async with gate.slot(1):
            await release_first.wait()

    async def waiter() -> None:
        async with gate.slot(2):
            return

    first = asyncio.create_task(holder())
    await asyncio.sleep(0)
    cancelled = asyncio.create_task(waiter())
    await asyncio.sleep(0)
    cancelled.cancel()
    with pytest.raises(asyncio.CancelledError):
        await cancelled
    release_first.set()
    await first
    await asyncio.wait_for(waiter(), timeout=1)
    assert gate.active == 0


def runtime_neuron(tmp_path: Path, transport: httpx.AsyncBaseTransport) -> MinerNeuron:
    peers = (MockPeer("//Miner1", 1, "http://miner.invalid", False, 10),)
    chain = MockChain(network="local", netuid=24, own_uri="//Miner1", peers=peers)
    return MinerNeuron(
        chain=chain,
        hotkey_signer=chain.hotkey_signer,
        network="local",
        netuid=24,
        configured_uid=1,
        bridge=BridgeClient(
            "http://127.0.0.1:9101",
            b"x" * 32,
            retries=0,
            transport=transport,
        ),
        nonce_store=SQLiteNonceStore(str(tmp_path / "runtime.db")),
        min_validator_stake=1_000,
        sync_interval=10,
        max_concurrency=1,
        mock_http=True,
        tls_config=None,
    )


@pytest.mark.asyncio
async def test_runtime_proxy_allows_exact_response_limit_and_filters_headers(
    tmp_path: Path,
) -> None:
    expected = b"x" * RUNTIME_MAX_RESPONSE
    stream = ChunkedResponse([expected])

    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/runtime/endpoint/index.html"
        return httpx.Response(
            200,
            stream=stream,
            headers={
                "Content-Type": "application/octet-stream",
                "Cache-Control": "no-store",
                "X-Build-ID": "build",
                "X-Untrusted": "drop-me",
            },
        )

    neuron = runtime_neuron(tmp_path, httpx.MockTransport(handler))
    transport = httpx.ASGITransport(app=neuron.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://miner") as client:
        response = await client.get("/runtime/endpoint/index.html")
    assert response.status_code == 200
    assert response.content == expected
    assert response.headers["x-build-id"] == "build"
    assert "x-untrusted" not in response.headers
    assert stream.closed


@pytest.mark.asyncio
async def test_runtime_proxy_rejects_declared_oversized_response(tmp_path: Path) -> None:
    stream = ChunkedResponse([b"must-not-be-read"])

    async def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"Content-Length": str(RUNTIME_MAX_RESPONSE + 1)},
            stream=stream,
        )

    neuron = runtime_neuron(tmp_path, httpx.MockTransport(handler))
    transport = httpx.ASGITransport(app=neuron.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://miner") as client:
        response = await client.get("/runtime/endpoint/file")
    assert response.status_code == 502
    assert response.json() == {"detail": "runtime response exceeds one MiB"}
    assert stream.yielded == 0
    assert stream.closed


@pytest.mark.asyncio
async def test_runtime_proxy_rejects_encoded_response_before_reading(tmp_path: Path) -> None:
    stream = ChunkedResponse([b"encoded-untrusted-marker"])

    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["accept-encoding"] == "identity"
        return httpx.Response(200, headers={"Content-Encoding": "gzip"}, stream=stream)

    neuron = runtime_neuron(tmp_path, httpx.MockTransport(handler))
    transport = httpx.ASGITransport(app=neuron.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://miner") as client:
        response = await client.get("/runtime/endpoint/file")
    assert response.status_code == 502
    assert response.json() == {"detail": "encoded runtime responses are not supported"}
    assert stream.yielded == 0
    assert stream.closed


@pytest.mark.asyncio
async def test_runtime_proxy_rejects_oversized_chunked_response(tmp_path: Path) -> None:
    stream = ChunkedResponse([b"x" * RUNTIME_MAX_RESPONSE, b"untrusted-marker"])

    async def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"Transfer-Encoding": "chunked"}, stream=stream)

    neuron = runtime_neuron(tmp_path, httpx.MockTransport(handler))
    transport = httpx.ASGITransport(app=neuron.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://miner") as client:
        response = await client.get("/runtime/endpoint/file")
    assert response.status_code == 502
    assert response.json() == {"detail": "runtime response exceeds one MiB"}
    assert b"untrusted-marker" not in response.content
    assert stream.yielded == 2
    assert stream.closed


@pytest.mark.asyncio
async def test_runtime_proxy_preserves_request_body_limit(tmp_path: Path) -> None:
    async def handler(_: httpx.Request) -> httpx.Response:
        raise AssertionError("oversized request reached the runtime")

    neuron = runtime_neuron(tmp_path, httpx.MockTransport(handler))
    transport = httpx.ASGITransport(app=neuron.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://miner") as client:
        response = await client.post(
            "/runtime/endpoint/file", content=b"x" * (RUNTIME_MAX_RESPONSE + 1)
        )
    assert response.status_code == 413
