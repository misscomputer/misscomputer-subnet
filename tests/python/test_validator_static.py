# SPDX-License-Identifier: AGPL-3.0-only
"""Validator bridge placement of static-site-v1 tickets.

A static ticket reaches a miner only in ``subnet-static-synapse.v1`` and only
when that exact miner advertises ``organic-static-v1``. A miner without the
capability is refused before any contact with a stable neutral detail, so the
scheduler can place elsewhere without penalizing it, and organic placement is
unaffected.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest
from test_validator_cleanup import (
    BRIDGE_SECRET,
    MINER_A,
    SERVICE_KEY_HEX,
    V4_TICKET_FIXTURE,
    DendriteSim,
    make_harness,
    refresh,
)

from misscomputer_subnet.auth import bridge_headers
from misscomputer_subnet.static_contracts import StaticDeploySynapseV1
from misscomputer_subnet.validator import STATIC_CAPABILITY_UNSUPPORTED

FIXTURES = Path(__file__).resolve().parents[2] / "contracts/fixtures"
STATIC_TICKET = json.loads((FIXTURES / "static-deployment-ticket.v1.json").read_text())
STATIC_RESPONSE = json.loads((FIXTURES / "static-deploy-response.v1.json").read_text())


class StaticDendrite:
    """Wrap the cleanup simulator with the static capability and route."""

    def __init__(self, sim: DendriteSim) -> None:
        self.inner = sim.handler
        self.static_capable: set[str] = set()
        self.static_deploys: list[StaticDeploySynapseV1] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/static/deploy":
            self.static_deploys.append(StaticDeploySynapseV1.model_validate_json(request.content))
            return httpx.Response(200, json=STATIC_RESPONSE)
        response = self.inner(request)
        if request.url.path == "/api/v1/capabilities":
            document = json.loads(response.content)
            if document["miner_hotkey"] in self.static_capable:
                document["features"].append("organic-static-v1")
            return httpx.Response(200, json=document)
        return response


def _subnet(chain: Any, snapshot: Any) -> dict[str, Any]:
    return {
        "network": "local",
        "netuid": 24,
        "validator_hotkey": chain.hotkey,
        "miner_hotkey": MINER_A.hotkey,
        "miner_uid": MINER_A.uid,
        "miner_axon_url": "http://miner-a:8091",
        "miner_transport": "http",
        "miner_tls_certificate_sha256": None,
        "chain_block": snapshot.block,
        "epoch": snapshot.epoch,
        "expires_at_block": snapshot.block + 12,
        "validator_service_public_key": SERVICE_KEY_HEX,
        "miner_service_public_key": SERVICE_KEY_HEX,
    }


async def _post(neuron: Any, target: str, document: dict[str, Any]) -> httpx.Response:
    body = json.dumps(document, separators=(",", ":")).encode()
    headers = bridge_headers(BRIDGE_SECRET, method="POST", target=target, body=body)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=neuron.app), base_url="http://bridge.local"
    ) as client:
        return await client.post(target, content=body, headers=headers)


@pytest.mark.asyncio
async def test_static_ticket_reaches_only_static_capable_miners(tmp_path: Path) -> None:
    neuron, chain, sim = make_harness(tmp_path)
    dendrite = StaticDendrite(sim)
    neuron.dendrite_transport = httpx.MockTransport(dendrite.handler)
    snapshot = await refresh(neuron, chain, sim)
    ticket = {**STATIC_TICKET, "miner_id": MINER_A.hotkey, "subnet": _subnet(chain, snapshot)}
    static_target = f"/v1/miners/{MINER_A.hotkey}/static-deploy"
    request = {"protocol": "subnet-static-synapse.v1", "request_id": "static-1", "ticket": ticket}

    # An old (or static-disabled) miner is refused before any contact, with
    # the neutral detail, and keeps receiving organic work.
    refused = await _post(neuron, static_target, request)
    assert refused.status_code == 409, refused.text
    assert refused.json()["error"] == {
        "code": STATIC_CAPABILITY_UNSUPPORTED,
        "message": STATIC_CAPABILITY_UNSUPPORTED,
        "retryable": False,
    }
    assert dendrite.static_deploys == []
    v4_ticket = {
        **V4_TICKET_FIXTURE,
        "miner_id": MINER_A.hotkey,
        "subnet": _subnet(chain, snapshot),
    }
    organic = await _post(
        neuron,
        f"/v1/miners/{MINER_A.hotkey}/deploy",
        {"protocol": "subnet-synapse.v3", "request_id": "organic-1", "ticket": v4_ticket},
    )
    assert organic.status_code == 502 and sim.deploy_protocols == ["subnet-synapse.v3"]

    # Neither envelope carries the other's ticket.
    for target, document in (
        (static_target, {**request, "protocol": "subnet-synapse.v3"}),
        (f"/v1/miners/{MINER_A.hotkey}/deploy", {**request, "protocol": "subnet-synapse.v3"}),
    ):
        response = await _post(neuron, target, document)
        assert response.status_code == 422, response.text
    assert dendrite.static_deploys == []

    dendrite.static_capable.add(MINER_A.hotkey)
    await refresh(neuron, chain, sim)
    forwarded = await _post(neuron, static_target, request)
    assert forwarded.status_code == 200, forwarded.text
    assert forwarded.json() == STATIC_RESPONSE
    [sent] = dendrite.static_deploys
    assert sent.protocol == "subnet-static-synapse.v1"
    assert sent.caller_hotkey == chain.hotkey
    assert sent.ticket.model_dump(mode="json") == ticket

    # A static ticket whose signed binding differs from the handshake is
    # never delivered, even to a capable miner.
    moved = {**ticket, "subnet": {**ticket["subnet"], "miner_axon_url": "http://elsewhere:8091"}}
    response = await _post(neuron, static_target, {**request, "ticket": moved})
    assert response.status_code == 403, response.text
    assert len(dendrite.static_deploys) == 1
