# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import asyncio
import contextlib
import json
import ssl
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC
from pathlib import Path
from typing import Any

import bittensor as bt
import httpx
import pytest

from misscomputer_subnet import tls as tls_module
from misscomputer_subnet.auth import BridgeError, sign_service_binding
from misscomputer_subnet.chain import MockChain, MockPeer
from misscomputer_subnet.protocol import (
    CapabilitiesResponse,
    DeactivateResponse,
    DeactivateSynapse,
    MinerRegistration,
    ServiceKeyBinding,
    StatusResponse,
    StatusSynapse,
)
from misscomputer_subnet.tls import tls_leaf_preflight
from misscomputer_subnet.validator import ValidatorNeuron

CertificateFactory = Callable[..., tuple[Path, Path, bytes, str]]
ResponseFactory = Callable[[str, dict[str, str], bytes], tuple[int, dict[str, str], bytes]]


class RecordingBridge:
    def __init__(self) -> None:
        self.registrations: list[MinerRegistration] = []
        self.published: dict[str, MinerRegistration] = {}
        self.fail_registration = False
        self.drop_committed_response = False

    async def request(
        self,
        method: str,
        path: str,
        *,
        value: Any | None = None,
        response_model: Any | None = None,
    ) -> dict[str, Any]:
        if method == "GET":
            assert path.startswith("/v1/miners/")
            assert value is None
            registration = self.published[path.removeprefix("/v1/miners/")]
            return registration.model_dump(mode="json")
        assert method == "POST"
        assert path == "/v1/miners"
        assert response_model is None
        assert isinstance(value, MinerRegistration)
        if self.fail_registration:
            raise BridgeError(
                "binding_rollback",
                "injected pre-commit registration rejection",
                False,
                409,
            )
        self.registrations.append(value)
        self.published[value.hotkey] = value
        if self.drop_committed_response:
            raise RuntimeError("injected lost post-commit response")
        return {}


class LoopbackTLSServer:
    def __init__(
        self,
        cert_file: Path,
        key_file: Path,
        response_factory: ResponseFactory,
    ) -> None:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(cert_file, key_file)
        self.context = context
        self.response_factory = response_factory
        self.server: asyncio.Server | None = None
        self.requests: list[tuple[str, bytes]] = []

    async def start(self, port: int = 0) -> int:
        self.server = await asyncio.start_server(
            self._handle,
            "127.0.0.1",
            port,
            ssl=self.context,
            reuse_address=True,
        )
        socket = self.server.sockets[0]
        return int(socket.getsockname()[1])

    async def close(self) -> None:
        if self.server is None:
            return
        self.server.close()
        await self.server.wait_closed()
        self.server = None
        await asyncio.sleep(0)

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            try:
                head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=2)
            except (TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
                return
            lines = head.decode("latin-1").split("\r\n")
            method, path, _ = lines[0].split(" ", 2)
            assert method == "POST"
            headers = {
                key.lower(): value.strip()
                for line in lines[1:]
                if line and (key_value := line.split(":", 1))
                for key, value in [key_value]
            }
            length = int(headers.get("content-length", "0"))
            body = await reader.readexactly(length)
            self.requests.append((path, body))
            status, response_headers, payload = self.response_factory(path, headers, body)
            reason = {200: "OK", 307: "Temporary Redirect"}.get(status, "Error")
            response_headers = {
                "Content-Type": "application/json",
                "Content-Length": str(len(payload)),
                "Connection": "close",
                **response_headers,
            }
            encoded_headers = "".join(
                f"{key}: {value}\r\n" for key, value in response_headers.items()
            )
            writer.write(
                f"HTTP/1.1 {status} {reason}\r\n{encoded_headers}\r\n".encode("ascii") + payload
            )
            await writer.drain()
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()


class MinerResponder:
    def __init__(
        self,
        signer: Any,
        *,
        uid: int,
        certificate_pin: str,
        signed_pin: str | None = None,
        tamper_to_pin: str | None = None,
    ) -> None:
        self.signer = signer
        self.uid = uid
        self.certificate_pin = certificate_pin
        self.signed_pin = signed_pin or certificate_pin
        self.tamper_to_pin = tamper_to_pin
        self.nonces = bt.http_auth.InMemoryNonceStore()
        self.verified_callers: list[str] = []
        self.redirect_status_to: str | None = None

    def __call__(
        self, path: str, headers: dict[str, str], body: bytes
    ) -> tuple[int, dict[str, str], bytes]:
        verified = bt.http_auth.verify(
            headers,
            body,
            method="POST",
            path=path,
            self_hotkey_ss58=str(self.signer.ss58_address),
            nonce_store=self.nonces,
        )
        self.verified_callers.append(str(verified.hotkey_ss58))
        request = json.loads(body)
        if path == "/api/v1/capabilities":
            binding = sign_service_binding(
                ServiceKeyBinding(
                    role="miner",
                    transport="https",
                    transport_certificate_sha256=self.signed_pin,
                    network=request["network"],
                    netuid=request["netuid"],
                    hotkey=str(self.signer.ss58_address),
                    uid=self.uid,
                    service_public_key="ab" * 32,
                    generation=request["chain_block"] + 1,
                    valid_from_block=request["chain_block"],
                    expires_at_block=request["chain_block"] + 24,
                    challenge=request["challenge"],
                ),
                self.signer,
            )
            if self.tamper_to_pin is not None:
                binding = binding.model_copy(
                    update={"transport_certificate_sha256": self.tamper_to_pin}
                )
            response = CapabilitiesResponse(
                request_id=request["request_id"],
                miner_hotkey=str(self.signer.ss58_address),
                miner_uid=self.uid,
                features=["deploy", "status", "deactivate"],
                max_body_bytes=1 << 20,
                service_binding=binding,
            )
        elif path == "/api/v1/status":
            if self.redirect_status_to is not None:
                return 307, {"Location": self.redirect_status_to}, b"{}"
            response = StatusResponse(
                request_id=request["request_id"], status="ready", receipt=None
            )
        elif path == "/api/v1/deactivate":
            response = DeactivateResponse(request_id=request["request_id"], status="deactivated")
        else:
            raise AssertionError(f"unexpected request path: {path}")
        return 200, {}, response.model_dump_json().encode()


def live_validator(
    tmp_path: Path,
    *,
    port: int,
    bridge: RecordingBridge | None = None,
    timeout: float = 1,
) -> tuple[ValidatorNeuron, MockChain, MockPeer, RecordingBridge]:
    validator_peer = MockPeer("//Validator", 0, None, True, 2_000)
    miner_peer = MockPeer("//Miner", 1, f"127.0.0.1:{port}", False, 10)
    chain = MockChain(
        network="local",
        netuid=24,
        own_uri=validator_peer.uri,
        peers=(validator_peer, miner_peer),
        initial_block=100,
        tempo=12,
    )
    recording_bridge = bridge or RecordingBridge()
    neuron = ValidatorNeuron(
        chain=chain,
        hotkey_signer=chain.hotkey_signer,
        network="local",
        netuid=24,
        bridge=recording_bridge,  # type: ignore[arg-type]
        bridge_secret=b"t" * 32,
        state_db=str(tmp_path / "validator-tls.db"),
        bridge_url="http://127.0.0.1:9200",
        sync_interval=12,
        dendrite_timeout=timeout,
        dendrite_retries=0,
        weight_interval=360,
        version_key=2,
        allow_private_axons=True,
        mock_http_axons=False,
        discovery_concurrency=1,
        discovery_max_attempts=1,
        discovery_attempt_timeout=timeout,
        discovery_refresh_timeout=timeout,
    )
    return neuron, chain, miner_peer, recording_bridge


@pytest.mark.asyncio
async def test_self_signed_bootstrap_and_pinned_workload_ignore_proxy(
    certificate_factory: CertificateFactory,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cert, key, der, pin = certificate_factory("valid-loopback")
    signer = MockPeer("//Miner", 1, None, False, 10).keypair
    responder = MinerResponder(signer, uid=1, certificate_pin=pin)
    server = LoopbackTLSServer(cert, key, responder)
    port = await server.start()
    try:
        neuron, chain, miner_peer, _ = live_validator(tmp_path, port=port)
        monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:1")
        monkeypatch.setenv("ALL_PROXY", "http://127.0.0.1:1")
        monkeypatch.delenv("NO_PROXY", raising=False)
        snapshot = await chain.sync()
        record = snapshot.by_hotkey(miner_peer.hotkey)
        assert record is not None

        remote = await neuron._handshake(snapshot, record)

        assert remote.axon_url == f"https://127.0.0.1:{port}"
        assert remote.certificate_der == der
        assert remote.binding.transport_certificate_sha256 == pin
        assert responder.verified_callers == [chain.hotkey]
        assert [path for path, _ in server.requests] == ["/api/v1/capabilities"]
        capability_body = json.loads(server.requests[0][1])
        assert set(capability_body) == {
            "protocol",
            "request_id",
            "network",
            "netuid",
            "chain_block",
            "caller_hotkey",
            "challenge",
        }

        status = await neuron._signed_post(
            remote.axon_url,
            remote.neuron.hotkey,
            "/api/v1/status",
            StatusSynapse(
                request_id="status-request",
                current_block=snapshot.block,
                caller_hotkey=chain.hotkey,
                endpoint_id="endpoint-1",
            ),
            StatusResponse,
            certificate_der=remote.certificate_der,
        )
        deactivated = await neuron._signed_post(
            remote.axon_url,
            remote.neuron.hotkey,
            "/api/v1/deactivate",
            DeactivateSynapse(
                request_id="deactivate-request",
                current_block=snapshot.block,
                caller_hotkey=chain.hotkey,
                endpoint_id="endpoint-1",
                deployment_id="deployment-1",
            ),
            DeactivateResponse,
            certificate_der=remote.certificate_der,
        )

        assert status.status == "ready"
        assert deactivated.status == "deactivated"
        assert responder.verified_callers == [chain.hotkey] * 3
    finally:
        await server.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("tampered", [False, True])
async def test_relay_or_tampered_signed_fingerprint_is_rejected(
    certificate_factory: CertificateFactory,
    tmp_path: Path,
    tampered: bool,
) -> None:
    cert, key, _, served_pin = certificate_factory("served-relay")
    _, _, _, other_pin = certificate_factory("real-miner")
    signer = MockPeer("//Miner", 1, None, False, 10).keypair
    responder = MinerResponder(
        signer,
        uid=1,
        certificate_pin=served_pin,
        signed_pin=other_pin,
        tamper_to_pin=served_pin if tampered else None,
    )
    server = LoopbackTLSServer(cert, key, responder)
    port = await server.start()
    try:
        neuron, chain, miner_peer, _ = live_validator(tmp_path, port=port)
        snapshot = await chain.sync()
        record = snapshot.by_hotkey(miner_peer.hotkey)
        assert record is not None

        with pytest.raises(ValueError, match="transport mismatch|signature is invalid"):
            await neuron._handshake(snapshot, record)
    finally:
        await server.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("when", ["expired", "not-yet-valid"])
async def test_preflight_rejects_noncurrent_certificate_before_http(
    certificate_factory: CertificateFactory,
    tmp_path: Path,
    when: str,
) -> None:
    from datetime import datetime, timedelta

    current = datetime.now(UTC)
    if when == "expired":
        before, after = current - timedelta(days=2), current - timedelta(days=1)
    else:
        before, after = current + timedelta(days=1), current + timedelta(days=2)
    cert, key, _, pin = certificate_factory(f"preflight-{when}", not_before=before, not_after=after)
    signer = MockPeer("//Miner", 1, None, False, 10).keypair
    responder = MinerResponder(signer, uid=1, certificate_pin=pin)
    server = LoopbackTLSServer(cert, key, responder)
    port = await server.start()
    try:
        neuron, chain, miner_peer, _ = live_validator(tmp_path, port=port)
        snapshot = await chain.sync()
        record = snapshot.by_hotkey(miner_peer.hotkey)
        assert record is not None

        with pytest.raises(ValueError, match="expired|not yet valid"):
            await neuron._handshake(snapshot, record)
        assert server.requests == []
    finally:
        await server.close()


@pytest.mark.asyncio
async def test_wrong_leaf_blocks_workload_before_http_body(
    certificate_factory: CertificateFactory,
    tmp_path: Path,
) -> None:
    cert_a, key_a, _, pin_a = certificate_factory("workload-a")
    cert_b, key_b, _, pin_b = certificate_factory("workload-b")
    signer = MockPeer("//Miner", 1, None, False, 10).keypair
    first = LoopbackTLSServer(cert_a, key_a, MinerResponder(signer, uid=1, certificate_pin=pin_a))
    port = await first.start()
    neuron, chain, miner_peer, _ = live_validator(tmp_path, port=port)
    snapshot = await chain.sync()
    record = snapshot.by_hotkey(miner_peer.hotkey)
    assert record is not None
    remote = await neuron._handshake(snapshot, record)
    await first.close()

    relay_responder = MinerResponder(signer, uid=1, certificate_pin=pin_b)
    relay = LoopbackTLSServer(cert_b, key_b, relay_responder)
    await relay.start(port)
    try:
        with pytest.raises(RuntimeError, match="signed miner request failed"):
            await neuron._signed_post(
                remote.axon_url,
                remote.neuron.hotkey,
                "/api/v1/status",
                StatusSynapse(
                    request_id="wrong-leaf",
                    current_block=snapshot.block,
                    caller_hotkey=chain.hotkey,
                    endpoint_id="endpoint-1",
                ),
                StatusResponse,
                certificate_der=remote.certificate_der,
            )
        assert relay.requests == []
    finally:
        await relay.close()


@pytest.mark.asyncio
async def test_redirect_is_not_followed(
    certificate_factory: CertificateFactory,
    tmp_path: Path,
) -> None:
    cert, key, _, pin = certificate_factory("redirect-source")
    signer = MockPeer("//Miner", 1, None, False, 10).keypair
    responder = MinerResponder(signer, uid=1, certificate_pin=pin)
    target_hits: list[bytes] = []

    async def target(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        target_hits.append(await reader.read(4096))
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()

    target_server = await asyncio.start_server(target, "127.0.0.1", 0)
    target_port = int(target_server.sockets[0].getsockname()[1])
    responder.redirect_status_to = f"http://127.0.0.1:{target_port}/stolen"
    source = LoopbackTLSServer(cert, key, responder)
    source_port = await source.start()
    try:
        neuron, chain, miner_peer, _ = live_validator(tmp_path, port=source_port)
        snapshot = await chain.sync()
        record = snapshot.by_hotkey(miner_peer.hotkey)
        assert record is not None
        remote = await neuron._handshake(snapshot, record)

        with pytest.raises(httpx.HTTPStatusError):
            await neuron._signed_post(
                remote.axon_url,
                remote.neuron.hotkey,
                "/api/v1/status",
                StatusSynapse(
                    request_id="redirect",
                    current_block=snapshot.block,
                    caller_hotkey=chain.hotkey,
                    endpoint_id="endpoint-1",
                ),
                StatusResponse,
                certificate_der=remote.certificate_der,
            )
        await asyncio.sleep(0)
        assert target_hits == []
    finally:
        await source.close()
        target_server.close()
        await target_server.wait_closed()


@pytest.mark.asyncio
@pytest.mark.parametrize("cancel", [False, True])
async def test_preflight_timeout_or_cancellation_closes_socket(cancel: bool) -> None:
    accepted = asyncio.Event()
    closed = asyncio.Event()

    async def stalled(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        accepted.set()
        try:
            await reader.read()
        finally:
            closed.set()
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    server = await asyncio.start_server(stalled, "127.0.0.1", 0)
    port = int(server.sockets[0].getsockname()[1])
    try:
        task = asyncio.create_task(
            tls_leaf_preflight("127.0.0.1", port, timeout=1 if cancel else 0.05)
        )
        await asyncio.wait_for(accepted.wait(), timeout=1)
        if cancel:
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        else:
            with pytest.raises(TimeoutError, match="TLS preflight connection timed out") as caught:
                await task
            assert type(caught.value) is TimeoutError
            assert isinstance(caught.value.__cause__, asyncio.TimeoutError)
        await asyncio.wait_for(closed.wait(), timeout=1)
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
@pytest.mark.parametrize("cancel", [False, True])
async def test_preflight_normalizes_only_internal_timeout(
    monkeypatch: pytest.MonkeyPatch,
    cancel: bool,
) -> None:
    entered = asyncio.Event()
    cleaned = asyncio.Event()
    inner_timeout = TimeoutError("injected handshake timeout")

    async def controlled_connection(*_args: Any, **_kwargs: Any) -> Any:
        entered.set()
        if not cancel:
            raise inner_timeout
        try:
            await asyncio.Event().wait()
        finally:
            cleaned.set()

    monkeypatch.setattr(asyncio, "open_connection", controlled_connection)
    task = asyncio.create_task(tls_leaf_preflight("127.0.0.1", 443, timeout=1))
    await asyncio.wait_for(entered.wait(), timeout=1)

    if cancel:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert cleaned.is_set()
    else:
        with pytest.raises(TimeoutError, match="TLS preflight connection timed out") as caught:
            await task
        assert type(caught.value) is TimeoutError
        assert caught.value.__cause__ is inner_timeout


@pytest.mark.asyncio
async def test_preflight_cancellation_during_post_der_wait_closed_is_preserved(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    der = b"validated-leaf-der"
    cleanup_entered = asyncio.Event()
    writer_closed = False

    class FakeSSLObject:
        def getpeercert(self, *, binary_form: bool = False) -> bytes:
            assert binary_form
            return der

    class FakeWriter:
        def get_extra_info(self, name: str) -> Any:
            assert name == "ssl_object"
            return FakeSSLObject()

        def close(self) -> None:
            nonlocal writer_closed
            writer_closed = True

        async def wait_closed(self) -> None:
            cleanup_entered.set()
            await asyncio.Future()

    async def connected(*_args: Any, **_kwargs: Any) -> tuple[object, FakeWriter]:
        return object(), FakeWriter()

    monkeypatch.setattr(tls_module.ssl, "SSLObject", FakeSSLObject)
    monkeypatch.setattr(tls_module, "validate_leaf_certificate", lambda value: value)
    monkeypatch.setattr(asyncio, "open_connection", connected)

    task = asyncio.create_task(tls_leaf_preflight("8.8.8.8", 443, timeout=1))
    await cleanup_entered.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert writer_closed


@pytest.mark.asyncio
async def test_rotation_publishes_only_fresh_matching_pin(
    certificate_factory: CertificateFactory,
    tmp_path: Path,
) -> None:
    cert_a, key_a, der_a, pin_a = certificate_factory("rotation-a")
    cert_b, key_b, der_b, pin_b = certificate_factory("rotation-b")
    signer = MockPeer("//Miner", 1, None, False, 10).keypair
    responder_a = MinerResponder(signer, uid=1, certificate_pin=pin_a)
    server_a = LoopbackTLSServer(cert_a, key_a, responder_a)
    port = await server_a.start()
    bridge = RecordingBridge()
    neuron, chain, miner_peer, _ = live_validator(tmp_path, port=port, bridge=bridge)
    first_snapshot = await chain.sync()
    first = await neuron._discover_miners(first_snapshot)
    assert first[miner_peer.hotkey].certificate_der == der_a
    assert neuron._cleanup_miners[miner_peer.hotkey].certificate_der == der_a
    assert len(bridge.registrations) == 1
    async with neuron._lock:
        neuron._miners = first
    await server_a.close()

    mismatched = MinerResponder(
        signer,
        uid=1,
        certificate_pin=pin_b,
        signed_pin=pin_a,
    )
    server_b = LoopbackTLSServer(cert_b, key_b, mismatched)
    await server_b.start(port)
    try:
        failed_snapshot = replace(first_snapshot, block=first_snapshot.block + 1)
        failed = await neuron._discover_miners(failed_snapshot)
        assert failed == {}
        assert neuron._cleanup_miners[miner_peer.hotkey].certificate_der == der_a
        assert len(bridge.registrations) == 1

        mismatched.signed_pin = pin_b
        neuron._discovery_backoff.clear()
        bridge.fail_registration = True
        registration_failure_snapshot = replace(failed_snapshot, block=failed_snapshot.block + 1)
        registration_failure = await neuron._discover_miners(registration_failure_snapshot)
        assert registration_failure == {}
        assert neuron._cleanup_miners[miner_peer.hotkey].certificate_der == der_a
        assert len(bridge.registrations) == 1

        bridge.fail_registration = False
        neuron._discovery_backoff.clear()
        bridge.drop_committed_response = True
        successful_snapshot = replace(
            registration_failure_snapshot, block=registration_failure_snapshot.block + 1
        )
        successful = await neuron._discover_miners(successful_snapshot)
        bridge.drop_committed_response = False

        rotated = successful[miner_peer.hotkey]
        assert rotated.certificate_der == der_b
        assert rotated.binding.transport_certificate_sha256 == pin_b
        assert neuron._cleanup_miners[miner_peer.hotkey] == rotated
        assert len(bridge.registrations) == 2
        registration = bridge.registrations[-1]
        assert registration.service_binding.transport_certificate_sha256 == pin_b
        assert registration.transport_certificate_der_base64
    finally:
        await server_b.close()
