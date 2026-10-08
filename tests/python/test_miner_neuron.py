# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import asyncio
import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import bittensor as bt
import httpx
import pytest

from misscomputer_subnet.auth import (
    BRIDGE_MAX_BODY,
    BridgeClient,
    SQLiteBridgeReplay,
    SQLiteNonceStore,
    sign_service_binding,
    verify_bridge_headers,
)
from misscomputer_subnet.chain import MetagraphSnapshot, MockChain, MockPeer
from misscomputer_subnet.miner import (
    RUNTIME_MAX_RESPONSE,
    AuthorizationPolicy,
    MinerNeuron,
    PriorityGate,
)
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
FIXTURES = Path(__file__).resolve().parents[2] / "contracts/fixtures"
DEPLOY_FIXTURE = json.loads((FIXTURES / "deploy.v3.json").read_text())["ticket"]


@pytest.mark.asyncio
async def test_registered_inactive_miner_and_validator_keep_serving(tmp_path: Path) -> None:
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
    stale_weights = replace(
        snapshot,
        neurons=tuple(replace(record, active=False) for record in snapshot.neurons),
    )

    async def one_sync() -> MetagraphSnapshot:
        neuron.stop.set()
        return stale_weights

    chain.sync = one_sync  # type: ignore[method-assign]
    await neuron._sync_loop()
    assert neuron.ready.is_set()
    caller = await AuthorizationPolicy(neuron.state, min_validator_stake=1_000).authorize(
        VALIDATOR.ss58_address
    )
    assert caller.hotkey == VALIDATOR.ss58_address


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
@pytest.mark.parametrize("failure", ["wrong_uid", "wrong_hotkey", "expired", "synthetic_envelope"])
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
    elif failure == "synthetic_envelope":
        ticket["version"] = "deployment.v3"
    else:
        ticket["subnet"]["chain_block"] = snapshot.block - 12
        ticket["subnet"]["epoch"] = (snapshot.block - 12) // snapshot.tempo
        ticket["subnet"]["expires_at_block"] = snapshot.block
    value = {
        "protocol": "subnet-synapse.v2" if failure == "synthetic_envelope" else "subnet-synapse.v3",
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
    expected = 422 if failure == "synthetic_envelope" else 403
    assert response.status_code == expected, response.text


@pytest.mark.asyncio
async def test_deploy_accepts_validator_binding_one_block_ahead(tmp_path: Path) -> None:
    # The organic v3 envelope (deployment.v4 ticket) reaches the agent as a v3
    # loopback request when the binding is one block ahead of this miner.
    fixture, protocol = "deploy.v3.json", "subnet-synapse.v3"
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
    ticket = json.loads((FIXTURES / fixture).read_text())["ticket"]
    ticket["miner_id"] = MINER.ss58_address
    ticket["subnet"].update(
        {
            "network": "local",
            "netuid": 24,
            "miner_axon_url": "http://127.0.0.1:8091",
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
        "protocol": protocol,
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
    assert bridge.assignment["protocol"] == protocol
    assert bridge.assignment["ticket"] == ticket


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


EDGE_AUTH = "v1 ts=1,nonce=" + "0" * 32 + ",sig=" + "0" * 128


async def call_runtime_app(
    neuron: MinerNeuron,
    *,
    method: str,
    raw_path: bytes,
    query: bytes = b"",
    headers: list[tuple[bytes, bytes]],
    body: bytes = b"",
) -> tuple[int, list[tuple[bytes, bytes]], bytes]:
    """Drive the ASGI app with exact raw target bytes, as uvicorn delivers them."""

    sent: list[dict[str, Any]] = []
    delivered = False

    async def receive() -> dict[str, Any]:
        nonlocal delivered
        if delivered:
            await asyncio.sleep(3600)
        delivered = True
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    decoded = bytes(raw_path).decode("ascii")
    await neuron.app(
        {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": method,
            "scheme": "https",
            "path": httpx.URL("http://x" + decoded).path,
            "raw_path": raw_path,
            "query_string": query,
            "root_path": "",
            "headers": [(b"host", b"route.on.miss.computer"), *headers],
            "client": ("198.51.100.4", 443),
            "server": ("203.0.113.9", 8091),
        },
        receive,
        send,
    )
    start = next(message for message in sent if message["type"] == "http.response.start")
    content = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    return start["status"], list(start["headers"]), content


@pytest.mark.asyncio
@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
async def test_runtime_proxy_forwards_exact_target_body_and_end_to_end_headers(
    tmp_path: Path, method: str
) -> None:
    seen: list[httpx.Request] = []
    raw_path = b"/runtime/ep-1/a%2Fb//c/./d/../e;f"
    query = b"x=1;y=%zz&z=%7C&q=a+b"
    target = "/v1/runtime/ep-1/a%2Fb//c/./d/../e;f?x=1;y=%zz&z=%7C&q=a+b"

    async def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(204, stream=ChunkedResponse([]))

    neuron = runtime_neuron(tmp_path, httpx.MockTransport(handler))
    status, _, _ = await call_runtime_app(
        neuron,
        method=method,
        raw_path=raw_path,
        query=query,
        body=b'{"k":1}',
        headers=[
            (b"x-miss-edge-authorization", EDGE_AUTH.encode()),
            (b"cookie", b"a=1; b=2"),
            (b"authorization", b"Bearer app-token"),
            (b"content-type", b"application/json"),
            (b"accept-encoding", b"gzip"),
            (b"x-forwarded-for", b"203.0.113.50"),
            (b"connection", b"keep-alive, x-hop"),
            (b"x-hop", b"drop-me"),
            (b"te", b"trailers"),
            (b"x-miss-bridge-signature", b"spoofed"),
            (b"x-miss-internal-probe-token", b"leak"),
        ],
    )
    assert status == 204
    (request,) = seen
    # The exact escaped bytes the edge signed reach the agent unnormalized
    # (no dot-segment removal or re-encoding) and carry a valid bridge HMAC.
    assert request.extensions["target"] == target.encode()
    assert request.method == method
    assert request.content == b'{"k":1}'
    verify_bridge_headers(
        neuron.bridge.secret,
        {k: v for k, v in request.headers.items() if k.startswith("x-miss-bridge-")},
        method=method,
        target=target,
        body=b'{"k":1}',
        replay=SQLiteBridgeReplay(str(tmp_path / "bridge-replay.db")),
    )
    headers = request.headers
    assert headers["x-miss-edge-authorization"] == EDGE_AUTH
    assert headers["cookie"] == "a=1; b=2"
    assert headers["authorization"] == "Bearer app-token"
    assert headers["content-type"] == "application/json"
    assert headers["accept-encoding"] == "gzip"
    assert headers["x-forwarded-for"] == "203.0.113.50"
    assert len(headers.get_list("x-miss-bridge-signature")) == 1
    for dropped in ("x-hop", "te", "x-miss-internal-probe-token", "user-agent", "accept"):
        assert dropped not in headers


@pytest.mark.asyncio
async def test_runtime_proxy_passes_response_headers_encoding_and_exact_limit(
    tmp_path: Path,
) -> None:
    expected = b"\x1f\x8b" + b"x" * (RUNTIME_MAX_RESPONSE - 2)
    stream = ChunkedResponse([expected])

    async def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            302,
            stream=stream,
            headers=[
                ("Content-Type", "application/octet-stream"),
                ("Content-Encoding", "gzip"),
                ("Set-Cookie", "a=1; Path=/"),
                ("Set-Cookie", "b=2; Path=/"),
                ("Location", "/next?x=1"),
                ("ETag", '"v1"'),
                ("Vary", "Accept-Encoding"),
                ("X-Miss-Probe-Attestation", "c2lnbmVk"),
                ("X-Miss-Edge-Upstream", "forged"),
                ("Connection", "close"),
            ],
        )

    neuron = runtime_neuron(tmp_path, httpx.MockTransport(handler))
    status, raw_headers, content = await call_runtime_app(
        neuron,
        method="GET",
        raw_path=b"/runtime/ep-1/archive",
        headers=[(b"x-miss-edge-authorization", EDGE_AUTH.encode())],
    )
    headers = httpx.Headers(raw_headers)
    assert status == 302
    # Encoded bytes pass through undecoded, and the bound is on encoded bytes.
    assert content == expected
    assert headers["content-encoding"] == "gzip"
    assert headers["content-length"] == str(RUNTIME_MAX_RESPONSE)
    assert headers.get_list("set-cookie") == ["a=1; Path=/", "b=2; Path=/"]
    assert headers["location"] == "/next?x=1"
    assert headers["etag"] == '"v1"'
    assert headers["vary"] == "Accept-Encoding"
    assert headers["x-miss-probe-attestation"] == "c2lnbmVk"
    assert "x-miss-edge-upstream" not in headers
    assert "connection" not in headers
    assert stream.closed


@pytest.mark.asyncio
async def test_runtime_proxy_head_keeps_declared_entity_length(tmp_path: Path) -> None:
    async def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"Content-Length": "4096"}, stream=ChunkedResponse([]))

    neuron = runtime_neuron(tmp_path, httpx.MockTransport(handler))
    status, raw_headers, content = await call_runtime_app(
        neuron,
        method="HEAD",
        raw_path=b"/runtime/ep-1/file",
        headers=[(b"x-miss-edge-authorization", EDGE_AUTH.encode())],
    )
    assert status == 200
    assert content == b""
    assert httpx.Headers(raw_headers).get_list("content-length") == ["4096"]


@pytest.mark.asyncio
@pytest.mark.parametrize("authorizations", [[], [EDGE_AUTH, EDGE_AUTH]])
async def test_runtime_proxy_rejects_unauthorizable_requests_without_agent_contact(
    tmp_path: Path, authorizations: list[str]
) -> None:
    async def handler(_: httpx.Request) -> httpx.Response:
        raise AssertionError("an unauthorizable request reached the agent")

    neuron = runtime_neuron(tmp_path, httpx.MockTransport(handler))
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=neuron.app), base_url="http://miner"
    ) as client:
        response = await client.post(
            "/runtime/endpoint/file",
            content=b"body",
            headers=[("X-Miss-Edge-Authorization", value) for value in authorizations],
        )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_runtime_proxy_returns_only_the_agent_attestation_header(
    tmp_path: Path,
) -> None:
    forwarded: list[list[str]] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        forwarded.append([name for name in request.headers if name.lower().startswith("x-miss-")])
        return httpx.Response(
            200,
            stream=ChunkedResponse([b"organic-ready"]),
            headers={
                "Content-Type": "text/plain",
                "X-Build-ID": "build",
                "X-Miss-Probe-Attestation": "c2lnbmVk",
                "X-Miss-Internal": "forged",
            },
        )

    neuron = runtime_neuron(tmp_path, httpx.MockTransport(handler))
    transport = httpx.ASGITransport(app=neuron.app)
    auth = ("X-Miss-Edge-Authorization", EDGE_AUTH)
    async with httpx.AsyncClient(transport=transport, base_url="http://miner") as client:
        response = await client.get(
            "/runtime/endpoint/",
            headers=[auth, ("X-Miss-Probe-Nonce", "ab" * 32), ("X-Miss-Anything", "x")],
        )
    # Only the edge authorization crosses the bridge (the retired synthetic
    # probe nonce does not), and the agent-set attestation is the only
    # X-Miss-* header allowed back out.
    assert len(forwarded) == 1 and "x-miss-edge-authorization" in forwarded[0]
    assert "x-miss-probe-nonce" not in forwarded[0] and "x-miss-anything" not in forwarded[0]
    assert response.status_code == 200
    assert response.headers["x-miss-probe-attestation"] == "c2lnbmVk"
    assert response.headers["x-build-id"] == "build"
    assert "x-miss-internal" not in response.headers


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status_code", "agent_state", "expected"),
    [
        (404, ["unavailable-v1"], ["unavailable-v1"]),
        (200, ["unavailable-v1"], []),
        (404, ["forged"], []),
        (404, ["unavailable-v1", "unavailable-v1"], []),
    ],
)
async def test_runtime_proxy_forwards_only_agent_inactive_endpoint_signal(
    tmp_path: Path, status_code: int, agent_state: list[str], expected: list[str]
) -> None:
    async def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status_code,
            stream=ChunkedResponse([b"endpoint is inactive\n"]),
            headers=[
                *(("X-Miss-Agent-Endpoint-State", value) for value in agent_state),
                ("X-Miss-Internal", "forged"),
            ],
        )

    neuron = runtime_neuron(tmp_path, httpx.MockTransport(handler))
    status, raw_headers, content = await call_runtime_app(
        neuron,
        method="GET",
        raw_path=b"/runtime/ep-1/",
        headers=[(b"x-miss-edge-authorization", EDGE_AUTH.encode())],
    )
    headers = httpx.Headers(raw_headers)
    assert status == status_code
    assert content == b"endpoint is inactive\n"
    assert headers.get_list("x-miss-agent-endpoint-state") == expected
    assert "x-miss-internal" not in headers


@pytest.mark.asyncio
async def test_runtime_proxy_forwards_edge_signed_request_byte_exact(tmp_path: Path) -> None:
    # The Go agent verifies X-Miss-Edge-Authorization over the escaped path,
    # raw query and body, so the Python hop must not decode or drop any of them.
    seen: list[tuple[str, list[str], list[str]]] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        seen.append(
            (
                request.url.raw_path.decode(),
                request.headers.get_list("x-miss-edge-authorization"),
                request.headers.get_list("x-miss-organic-probe-authorization"),
            )
        )
        return httpx.Response(200, stream=ChunkedResponse([b"ok"]))

    neuron = runtime_neuron(tmp_path, httpx.MockTransport(handler))
    transport = httpx.ASGITransport(app=neuron.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://miner") as client:
        response = await client.request(
            "OPTIONS",
            "/runtime/endpoint/items/a%2Fb?x=1&y=%20",
            headers=[
                ("X-Miss-Edge-Authorization", "v1 ts=1,nonce=a,sig=b"),
                ("X-Miss-Organic-Probe-Authorization", "e30="),
            ],
        )
    assert response.status_code == 200
    assert seen == [
        ("/v1/runtime/endpoint/items/a%2Fb?x=1&y=%20", ["v1 ts=1,nonce=a,sig=b"], ["e30="])
    ]


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
        response = await client.get(
            "/runtime/endpoint/file", headers={"X-Miss-Edge-Authorization": EDGE_AUTH}
        )
    assert response.status_code == 502
    assert response.json() == {"detail": "runtime response exceeds the miner limit"}
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
        response = await client.get(
            "/runtime/endpoint/file", headers={"X-Miss-Edge-Authorization": EDGE_AUTH}
        )
    assert response.status_code == 502
    assert response.json() == {"detail": "runtime response exceeds the miner limit"}
    assert b"untrusted-marker" not in response.content
    assert stream.yielded == 2
    assert stream.closed


@pytest.mark.asyncio
async def test_runtime_proxy_maps_agent_transport_failure_to_502(tmp_path: Path) -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("agent down", request=request)

    neuron = runtime_neuron(tmp_path, httpx.MockTransport(handler))
    transport = httpx.ASGITransport(app=neuron.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://miner") as client:
        response = await client.get(
            "/runtime/endpoint/file", headers={"X-Miss-Edge-Authorization": EDGE_AUTH}
        )
    assert response.status_code == 502


@pytest.mark.asyncio
async def test_runtime_proxy_preserves_request_body_limit(tmp_path: Path) -> None:
    async def handler(_: httpx.Request) -> httpx.Response:
        raise AssertionError("oversized request reached the runtime")

    neuron = runtime_neuron(tmp_path, httpx.MockTransport(handler))
    transport = httpx.ASGITransport(app=neuron.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://miner") as client:
        response = await client.post(
            "/runtime/endpoint/file",
            content=b"x" * (BRIDGE_MAX_BODY + 1),
            headers={"X-Miss-Edge-Authorization": EDGE_AUTH},
        )
    assert response.status_code == 413
