# SPDX-License-Identifier: AGPL-3.0-only
"""Miner axon handling of subnet-static-synapse.v1.

The axon accepts a static ticket only on its static route, applies the same
btauth and Bittensor identity checks as organic assignments before any agent
contact, forwards the exact ticket to the Go agent's static bridge, and keeps
the agent's stable refusal code so a static-disabled miner reads as
ineligible rather than faulty.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import bittensor as bt
import httpx
import pytest
from test_miner_neuron import MINER, VALIDATOR, FakeBridge

from misscomputer_subnet.auth import BridgeError, SQLiteNonceStore, sign_service_binding
from misscomputer_subnet.chain import MockChain, MockPeer
from misscomputer_subnet.miner import MinerNeuron
from misscomputer_subnet.protocol import ServiceKeyBinding
from misscomputer_subnet.static_contracts import (
    LocalStaticAssignRequestV1,
    StaticDeployResponseV1,
)

FIXTURES = Path(__file__).resolve().parents[2] / "contracts/fixtures"
STATIC_TICKET = json.loads((FIXTURES / "static-deployment-ticket.v1.json").read_text())
V4_TICKET = json.loads((FIXTURES / "deployment-ticket.v4.json").read_text())
STATIC_RESPONSE = (FIXTURES / "static-deploy-response.v1.json").read_bytes()
SERVICE_KEY = "11" * 32


class StaticBridge(FakeBridge):
    """Go agent stand-in: records static assignments, optionally refuses."""

    def __init__(self, refusal: BridgeError | None = None) -> None:
        self.refusal = refusal
        self.assignments: list[LocalStaticAssignRequestV1] = []

    async def request(
        self,
        method: str,
        path: str,
        *,
        value: Any = None,
        response_model: type[Any] | None = None,
    ) -> Any:
        if method == "POST" and path == "/v1/static/assignments":
            assert isinstance(value, LocalStaticAssignRequestV1)
            self.assignments.append(value)
            if self.refusal is not None:
                raise self.refusal
            assert response_model is StaticDeployResponseV1
            return StaticDeployResponseV1.model_validate_json(STATIC_RESPONSE)
        return await super().request(method, path, value=value, response_model=response_model)


async def _neuron(tmp_path: Path, bridge: FakeBridge) -> tuple[MinerNeuron, Any]:
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
        bridge=bridge,  # type: ignore[arg-type]
        nonce_store=SQLiteNonceStore(str(tmp_path / "static.db")),
        min_validator_stake=1_000,
        sync_interval=10,
        max_concurrency=1,
        mock_http=True,
        tls_config=None,
    )
    snapshot = await chain.sync()
    await neuron.state.set(snapshot)
    neuron.ready.set()
    return neuron, snapshot


def _envelope(snapshot: Any, protocol: str, ticket: dict[str, Any]) -> dict[str, Any]:
    binding = sign_service_binding(
        ServiceKeyBinding(
            role="validator",
            transport="local",
            transport_certificate_sha256=None,
            network="local",
            netuid=24,
            hotkey=VALIDATOR.ss58_address,
            uid=0,
            service_public_key=SERVICE_KEY,
            generation=snapshot.epoch + 1,
            valid_from_block=snapshot.block,
            expires_at_block=snapshot.block + 24,
            challenge="validator-service:" + SERVICE_KEY,
        ),
        VALIDATOR,
    )
    ticket = json.loads(json.dumps(ticket))
    ticket["miner_id"] = MINER.ss58_address
    ticket["subnet"].update(
        {
            "network": "local",
            "netuid": 24,
            "validator_hotkey": VALIDATOR.ss58_address,
            "miner_hotkey": MINER.ss58_address,
            "miner_uid": 1,
            "miner_transport": "http",
            "miner_tls_certificate_sha256": None,
            "chain_block": snapshot.block,
            "epoch": snapshot.epoch,
            "expires_at_block": snapshot.block + 12,
            "validator_service_public_key": SERVICE_KEY,
            "miner_service_public_key": "22" * 32,
        }
    )
    return {
        "protocol": protocol,
        "request_id": "static-assign-1",
        "current_block": snapshot.block,
        "caller_hotkey": VALIDATOR.ss58_address,
        "validator_binding": binding.model_dump(mode="json"),
        "ticket": ticket,
    }


async def _post(neuron: MinerNeuron, path: str, value: dict[str, Any]) -> httpx.Response:
    body = json.dumps(value, separators=(",", ":")).encode()
    headers = bt.http_auth.sign(
        VALIDATOR, method="POST", path=path, body=body, receiver_ss58=MINER.ss58_address
    )
    transport = httpx.ASGITransport(app=neuron.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://miner") as client:
        return await client.post(path, content=body, headers=headers)


@pytest.mark.asyncio
async def test_static_deploy_forwards_the_exact_ticket_to_the_static_bridge(
    tmp_path: Path,
) -> None:
    bridge = StaticBridge()
    neuron, snapshot = await _neuron(tmp_path, bridge)
    value = _envelope(snapshot, "subnet-static-synapse.v1", STATIC_TICKET)
    response = await _post(neuron, "/api/v1/static/deploy", value)
    assert response.status_code == 200, response.text
    assert json.loads(response.content) == json.loads(STATIC_RESPONSE)
    [forwarded] = bridge.assignments
    # The bridge client serializes with model_dump(mode="json").
    sent = forwarded.model_dump(mode="json")
    assert sent["protocol"] == "subnet-static-synapse.v1"
    assert sent["binding_verified"] is True
    assert sent["current_block"] == snapshot.block
    assert sent["ticket"] == value["ticket"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("path", "protocol", "ticket", "change", "status"),
    [
        ("/api/v1/static/deploy", "subnet-synapse.v3", STATIC_TICKET, None, 422),
        ("/api/v1/static/deploy", "subnet-static-synapse.v1", V4_TICKET, None, 422),
        ("/api/v1/deploy", "subnet-static-synapse.v1", STATIC_TICKET, None, 422),
        ("/api/v1/deploy", "subnet-synapse.v3", STATIC_TICKET, None, 422),
        ("/api/v1/static/deploy", "subnet-static-synapse.v1", STATIC_TICKET, "uid", 403),
        ("/api/v1/static/deploy", "subnet-static-synapse.v1", STATIC_TICKET, "expired", 403),
    ],
    ids=["v3-envelope", "v4-ticket", "organic-route", "organic-route-v3", "wrong-uid", "expired"],
)
async def test_static_deploy_refuses_before_agent_contact(
    tmp_path: Path,
    path: str,
    protocol: str,
    ticket: dict[str, Any],
    change: str | None,
    status: int,
) -> None:
    bridge = StaticBridge()
    neuron, snapshot = await _neuron(tmp_path, bridge)
    value = _envelope(snapshot, protocol, ticket)
    if change == "uid":
        value["ticket"]["subnet"]["miner_uid"] = 2
    elif change == "expired":
        value["ticket"]["subnet"].update(
            {
                "chain_block": snapshot.block - 12,
                "epoch": (snapshot.block - 12) // snapshot.tempo,
                "expires_at_block": snapshot.block,
            }
        )
    response = await _post(neuron, path, value)
    assert response.status_code == status, response.text
    assert bridge.assignments == []


@pytest.mark.asyncio
async def test_static_disabled_agent_refusal_keeps_its_stable_code(tmp_path: Path) -> None:
    refusal = BridgeError("static_disabled", "static sites are not enabled", False, 501)
    bridge = StaticBridge(refusal)
    neuron, snapshot = await _neuron(tmp_path, bridge)
    value = _envelope(snapshot, "subnet-static-synapse.v1", STATIC_TICKET)
    response = await _post(neuron, "/api/v1/static/deploy", value)
    assert response.status_code == 501
    assert response.json()["detail"] == "static_disabled"
