# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import asyncio
import gzip
import json
import sys
from pathlib import Path
from typing import Any

import bittensor as bt
import httpx
import pytest
from fastapi import HTTPException
from starlette.requests import Request

from misscomputer_subnet import validator as validator_module
from misscomputer_subnet.auth import BRIDGE_MAX_BODY, HotkeySigningFacade
from misscomputer_subnet.chain import BittensorChain, MockChain, MockPeer
from misscomputer_subnet.netpolicy import canonical_public_address, regression_cases
from misscomputer_subnet.protocol import (
    CapabilitiesResponse,
    CapabilitiesSynapse,
    ControlCapabilities,
)
from misscomputer_subnet.validator import ValidatorNeuron, _axon_url, _http_host, _loopback_bind

MINER_PEER = MockPeer("//Miner1", 1, "http://miner.invalid", False, 10)
MINER_HOTKEY = MINER_PEER.hotkey


def test_chain_query_and_hotkey_facade_block_raw_execution_bypass() -> None:
    adapter = BittensorChain(network="finney", netuid=24)
    signer = HotkeySigningFacade(bt.sp_core.Keypair.create_from_uri("//Validator"))

    for attribute in ("client", "wallet", "signer"):
        assert not hasattr(adapter, attribute)
    for attribute in ("client", "wallet", "signer", "sign", "ss58_address"):
        assert not hasattr(signer, attribute)
    with pytest.raises(AttributeError):
        adapter.client.execute(  # type: ignore[attr-defined]
            bt.SetWeights(netuid=24, uids=[1], weights=[1.0], version_key=2),
            adapter.wallet,  # type: ignore[attr-defined]
        )
    with pytest.raises(AttributeError):
        adapter.client = object()  # type: ignore[attr-defined]
    with pytest.raises(TypeError):
        bt.resolve_signer(signer, role="hotkey")


class BlockLoopBridge:
    """Answers one block-loop iteration and records every Go control request."""

    def __init__(self) -> None:
        self.requests: list[tuple[str, str]] = []

    async def request(self, method: str, path: str, *, value: Any | None = None, **_: Any) -> Any:
        self.requests.append((method, path))
        if path == "/v1/capabilities":
            return ControlCapabilities(
                protocol="subnet-synapse.v2",
                service_public_key="11" * 32,
                features=[],
                weights_enabled=True,
            )
        if path == "/v1/miners/snapshot":
            assert value is not None
            return {
                "block": value.block,
                "miners": 0,
                "publication_id": validator_module._miner_set_publication_id(value.block, []),
            }
        if method == "GET" and path.startswith("/v1/weights"):
            raise AssertionError("the neuron polled Go weight aggregation")
        return {}


@pytest.mark.asyncio
async def test_block_loop_never_reads_go_weight_aggregation(tmp_path: Path) -> None:
    """A fully synchronized block leaves no path from Go observations to a weight plan.

    Before the organic replacement, the loop polled ``GET /v1/weights`` right
    after publication and wrote a WeightPlan from Go observation/latency
    aggregation. Weight plans now come only from organic availability.
    """

    peers = (
        MockPeer("//Validator", 0, None, True, 2_000),
        MockPeer("//Miner1", 1, None, False, 10),
    )
    chain = MockChain(network="local", netuid=24, own_uri="//Validator", peers=peers)
    bridge = BlockLoopBridge()
    neuron = ValidatorNeuron(
        chain=chain,
        hotkey_signer=chain.hotkey_signer,
        network="local",
        netuid=24,
        bridge=bridge,  # type: ignore[arg-type]
        bridge_secret=b"x" * 32,
        state_db=str(tmp_path / "loop.db"),
        bridge_url="http://127.0.0.1:9200",
        sync_interval=0.01,
        dendrite_timeout=1,
        dendrite_retries=0,
    )
    task = asyncio.create_task(neuron._block_loop())
    try:
        await asyncio.wait_for(neuron.fully_synced.wait(), timeout=10)
        await asyncio.sleep(0.1)
    finally:
        neuron.stop.set()
        await asyncio.wait_for(task, timeout=10)
    assert ("POST", "/v1/miners/snapshot") in bridge.requests
    assert not any(path.startswith("/v1/weights") for _, path in bridge.requests)
    assert not hasattr(neuron, "_prepare_weight_plan")


@pytest.mark.parametrize(
    "argv",
    [
        ["--weight-plan-path", "/var/lib/plan.json"],
        ["--weight-interval=360"],
        ["--version-key", "2"],
    ],
)
def test_removed_weight_flags_fail_loudly_with_the_organic_route(
    monkeypatch: pytest.MonkeyPatch, argv: list[str]
) -> None:
    monkeypatch.setattr(sys, "argv", ["misscomputer-validator", "--netuid", "24", *argv])
    with pytest.raises(SystemExit, match="validator-weight-decision v2"):
        validator_module.main()


def test_live_axon_url_policy_rejects_ssrf_targets() -> None:
    with pytest.raises(ValueError, match="private or local"):
        _axon_url("127.0.0.1:8091")
    with pytest.raises(ValueError, match="numeric IP"):
        _axon_url("metadata.internal:8091")
    for value in (
        "http://user@8.8.8.8:8091",
        "http://8.8.8.8:8091/admin",
        "http://8.8.8.8:8091?target=internal",
        "http://8.8.8.8:8091?",
        "http://8.8.8.8:8091#",
        "http://8.8.8.8:8091/",
        "http://[2606:4700:4700::1111%25eth0]:8091",
        "8.8.8.8:\t8091",
        "8.8.8.8:\n8091",
        "8.8.8.8:\r8091",
    ):
        with pytest.raises(ValueError, match="metagraph axon"):
            _axon_url(value)
    assert _axon_url("8.8.8.8:8091") == "https://8.8.8.8:8091"
    assert _axon_url("http://8.8.8.8:8091") == "https://8.8.8.8:8091"
    assert _axon_url("https://8.8.8.8:8091") == "https://8.8.8.8:8091"
    assert (
        _axon_url("http://[2606:4700:4700:0000:0000:0000:0000:1111]:8091")
        == "https://[2606:4700:4700::1111]:8091"
    )
    assert _axon_url("miner-1:8091", allow_private=True, mock_http=True) == "http://miner-1:8091"
    assert _loopback_bind("127.0.0.1")
    assert _loopback_bind("::1")
    assert not _loopback_bind("0.0.0.0")  # noqa: S104 - rejection is the assertion
    assert not _loopback_bind("localhost")
    assert _http_host("127.0.0.1") == "127.0.0.1"
    assert _http_host("::1") == "[::1]"


def test_python_uses_shared_versioned_special_purpose_corpus() -> None:
    for case in regression_cases():
        address = case["address"]
        if case["allowed"]:
            canonical = canonical_public_address(address)
            assert canonical == case["canonical"]
            rendered = f"[{address}]:8091" if ":" in address else f"{address}:8091"
            expected_host = f"[{canonical}]" if ":" in canonical else canonical
            assert _axon_url(rendered) == f"https://{expected_host}:8091"
        else:
            with pytest.raises(ValueError):
                canonical_public_address(address)


@pytest.mark.parametrize(
    "address",
    ["64:ff9b::7f00:1", "64:ff9b::c0a8:1", "fec0::1", "::ffff:8.8.8.8"],
)
def test_axon_rejects_translation_site_local_and_mapped_before_socket(address: str) -> None:
    with pytest.raises(ValueError, match="special-purpose|IPv4-mapped"):
        _axon_url(f"[{address}]:8091")


def test_live_validator_startup_rejects_insecure_axon_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "misscomputer-validator",
            "--netuid",
            "24",
            "--bridge-secret-file",
            "/unused/bridge-secret",
            "--state-db",
            "/unused/state.db",
            "--allow-insecure-mock-http",
        ],
    )
    with pytest.raises(SystemExit, match="requires --mock-uri"):
        validator_module.main()


def test_legacy_weight_submission_flag_fails_before_secret_or_chain_access(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ALLOW_WEIGHT_SUBMISSION", "I_UNDERSTAND_THIS_WRITES_CHAIN")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "misscomputer-validator",
            "--netuid",
            "24",
            "--bridge-secret-file",
            "/must-not-be-read",
            "--state-db",
            "/must-not-be-opened",
            "--enable-weight-submission",
            "--confirm-network",
            "finney",
            "--confirm-netuid",
            "24",
        ],
    )
    with pytest.raises(SystemExit, match="neither executes nor prepares weights"):
        validator_module.main()


def validator_for_transport(tmp_path: Path, transport: httpx.AsyncBaseTransport) -> ValidatorNeuron:
    chain = MockChain(
        network="local",
        netuid=24,
        own_uri="//Validator",
        peers=(MockPeer("//Validator", 0, None, True, 2_000), MINER_PEER),
    )
    return ValidatorNeuron(
        chain=chain,
        hotkey_signer=chain.hotkey_signer,
        network="local",
        netuid=24,
        bridge=BlockLoopBridge(),  # type: ignore[arg-type]
        bridge_secret=b"x" * 32,
        state_db=str(tmp_path / "transport.db"),
        bridge_url="http://127.0.0.1:9200",
        sync_interval=1,
        dendrite_timeout=1,
        dendrite_retries=2,
        allow_private_axons=True,
        mock_http_axons=True,
        dendrite_transport=transport,
    )


@pytest.mark.asyncio
async def test_dendrite_does_not_retry_semantic_4xx(tmp_path: Path) -> None:
    attempts = 0

    def reject(_: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        return httpx.Response(403, json={"detail": "not permitted"})

    neuron = validator_for_transport(tmp_path, httpx.MockTransport(reject))
    synapse = CapabilitiesSynapse(
        request_id="request",
        network="local",
        netuid=24,
        chain_block=100,
        caller_hotkey=neuron.chain.hotkey,
        challenge="challenge",
    )
    with pytest.raises(httpx.HTTPStatusError):
        await neuron._signed_post(
            "http://miner.invalid",
            MINER_HOTKEY,
            "/api/v1/capabilities",
            synapse,
            CapabilitiesResponse,
        )
    assert attempts == 1


@pytest.mark.asyncio
async def test_dendrite_bridge_preserves_semantic_status_and_error_envelope(
    tmp_path: Path,
) -> None:
    def reject(_: httpx.Request) -> httpx.Response:
        return httpx.Response(403, json={"detail": "ticket identity mismatch"})

    neuron = validator_for_transport(tmp_path, httpx.MockTransport(reject))
    synapse = CapabilitiesSynapse(
        request_id="request",
        network="local",
        netuid=24,
        chain_block=100,
        caller_hotkey=neuron.chain.hotkey,
        challenge="challenge",
    )
    with pytest.raises(HTTPException) as caught:
        await neuron._forward_signed_post(
            "http://miner.invalid",
            MINER_HOTKEY,
            "/api/v1/capabilities",
            synapse,
            CapabilitiesResponse,
        )
    assert caught.value.status_code == 403
    request = Request({"type": "http", "method": "POST", "path": "/", "headers": []})
    response = await neuron._http_error(request, caught.value)
    assert response.status_code == 403
    assert json.loads(response.body) == {
        "error": {
            "code": "identity_mismatch",
            "message": "ticket identity mismatch",
            "retryable": False,
        }
    }


@pytest.mark.asyncio
async def test_dendrite_transport_retries_are_bounded(tmp_path: Path) -> None:
    attempts = 0

    def timeout(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        raise httpx.ReadTimeout("timed out", request=request)

    neuron = validator_for_transport(tmp_path, httpx.MockTransport(timeout))
    synapse = CapabilitiesSynapse(
        request_id="request",
        network="local",
        netuid=24,
        chain_block=100,
        caller_hotkey=neuron.chain.hotkey,
        challenge="challenge",
    )
    with pytest.raises(RuntimeError, match="signed miner request failed"):
        await neuron._signed_post(
            "http://miner.invalid",
            MINER_HOTKEY,
            "/api/v1/capabilities",
            synapse,
            CapabilitiesResponse,
        )
    assert attempts == 3


@pytest.mark.asyncio
async def test_dendrite_streaming_rejects_oversize_response(tmp_path: Path) -> None:
    def oversize(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"x" * (BRIDGE_MAX_BODY + 1))

    neuron = validator_for_transport(tmp_path, httpx.MockTransport(oversize))
    neuron.dendrite_retries = 0
    synapse = CapabilitiesSynapse(
        request_id="request",
        network="local",
        netuid=24,
        chain_block=100,
        caller_hotkey=neuron.chain.hotkey,
        challenge="challenge",
    )
    with pytest.raises(RuntimeError, match="signed miner request failed") as caught:
        await neuron._signed_post(
            "http://miner.invalid",
            MINER_HOTKEY,
            "/api/v1/capabilities",
            synapse,
            CapabilitiesResponse,
        )
    assert isinstance(caught.value.__cause__, RuntimeError)
    assert "exceeds one MiB" in str(caught.value.__cause__)


@pytest.mark.asyncio
async def test_dendrite_streaming_rejects_encoded_response(tmp_path: Path) -> None:
    def encoded(request: httpx.Request) -> httpx.Response:
        assert request.headers["Accept-Encoding"] == "identity"
        return httpx.Response(
            200,
            headers={"Content-Encoding": "gzip"},
            content=gzip.compress(b"{}"),
        )

    neuron = validator_for_transport(tmp_path, httpx.MockTransport(encoded))
    neuron.dendrite_retries = 0
    synapse = CapabilitiesSynapse(
        request_id="request",
        network="local",
        netuid=24,
        chain_block=100,
        caller_hotkey=neuron.chain.hotkey,
        challenge="challenge",
    )
    with pytest.raises(RuntimeError, match="signed miner request failed") as caught:
        await neuron._signed_post(
            "http://miner.invalid",
            MINER_HOTKEY,
            "/api/v1/capabilities",
            synapse,
            CapabilitiesResponse,
        )
    assert isinstance(caught.value.__cause__, RuntimeError)
    assert "encoded miner responses" in str(caught.value.__cause__)


@pytest.mark.asyncio
async def test_dendrite_bridge_maps_bounded_timeout_to_retryable_504(tmp_path: Path) -> None:
    def timeout(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timed out", request=request)

    neuron = validator_for_transport(tmp_path, httpx.MockTransport(timeout))
    synapse = CapabilitiesSynapse(
        request_id="request",
        network="local",
        netuid=24,
        chain_block=100,
        caller_hotkey=neuron.chain.hotkey,
        challenge="challenge",
    )
    with pytest.raises(HTTPException) as caught:
        await neuron._forward_signed_post(
            "http://miner.invalid",
            MINER_HOTKEY,
            "/api/v1/capabilities",
            synapse,
            CapabilitiesResponse,
        )
    assert caught.value.status_code == 504
    request = Request({"type": "http", "method": "POST", "path": "/", "headers": []})
    response = await neuron._http_error(request, caught.value)
    payload = json.loads(response.body)
    assert payload["error"]["code"] == "dendrite_timeout"
    assert payload["error"]["retryable"] is True
