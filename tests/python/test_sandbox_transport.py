# SPDX-License-Identifier: AGPL-3.0-only
"""subnet-sandbox-synapse.v1 forwarding in the miner axon and validator bridge.

Off by default: neither neuron exposes a sandbox route unless started with
``--sandbox-leases on``. When on, the axon applies the static-ticket btauth and
Bittensor identity checks to a sandbox document before agent contact and
forwards the document object unchanged; the validator sends a runtime-signed
document only to a miner whose handshake matches its binding and that
advertises ``sandbox-lease-v1``. Documents are the Go contract's golden
vectors re-bound to the test identities; their signatures are the Go agent's
and runtime's concern, not this hop's.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import httpx
import pytest
from test_miner_neuron import MINER, VALIDATOR, FakeBridge
from test_static_miner_neuron import STATIC_TICKET, V4_TICKET, _neuron
from test_static_miner_neuron import _post as _post_miner
from test_validator_cleanup import BRIDGE_SECRET, MINER_A, SERVICE_KEY_HEX, make_harness, refresh

from misscomputer_subnet import miner, validator
from misscomputer_subnet.auth import BridgeError, bridge_headers, sign_service_binding
from misscomputer_subnet.protocol import ServiceKeyBinding
from misscomputer_subnet.sandbox_transport import (
    SANDBOX_CAPABILITY_UNSUPPORTED,
    LocalSandboxRequestV1,
    SandboxResponseV1,
    SandboxSynapseV1,
)

VECTORS = json.loads(
    (
        Path(__file__).resolve().parents[2] / "pkg/protocol/testdata/sandbox-lease-v1-vectors.json"
    ).read_text()
)
KINDS = {
    "reservations": "reservation",
    "leases": "lease",
    "renewals": "renewal",
    "releases": "release",
}
SANDBOX_ROUTES = [f"/api/v1/sandbox/{kind}" for kind in KINDS]
SANDBOX = "subnet-sandbox-synapse.v1"
LEASES = "/api/v1/sandbox/leases"
RESERVATIONS = "/api/v1/sandbox/reservations"
SERVICE_KEY = "11" * 32


def _document(kind: str, miner_hotkey: str, subnet: dict[str, Any]) -> dict[str, Any]:
    document = copy.deepcopy(VECTORS[KINDS[kind]])
    document["miner_id"] = miner_hotkey
    document["subnet"] = subnet
    return document


def _receipt(document: dict[str, Any]) -> dict[str, Any]:
    receipt = copy.deepcopy(VECTORS["receipt"])
    receipt.update(
        document_schema=document["schema"],
        sandbox_id=document["sandbox_id"],
        generation=document["generation"],
        miner_id=document["miner_id"],
        subnet=document["subnet"],
    )
    return receipt


# --------------------------------------------------------------------------
# Miner axon
# --------------------------------------------------------------------------


class SandboxAgent(FakeBridge):
    """Go agent stand-in: records sandbox documents and answers a receipt."""

    def __init__(self, refusal: BridgeError | None = None) -> None:
        self.refusal = refusal
        self.requests: list[tuple[str, LocalSandboxRequestV1]] = []
        self.answer: dict[str, Any] | None = None

    async def request(
        self,
        method: str,
        path: str,
        *,
        value: Any = None,
        response_model: type[Any] | None = None,
    ) -> Any:
        if method == "POST" and path.startswith("/v1/sandbox/"):
            assert isinstance(value, LocalSandboxRequestV1)
            self.requests.append((path, value))
            if self.refusal is not None:
                raise self.refusal
            assert response_model is SandboxResponseV1
            receipt = self.answer if self.answer is not None else _receipt(value.document)
            return SandboxResponseV1(
                protocol="subnet-sandbox-synapse.v1", request_id=value.request_id, receipt=receipt
            )
        return await super().request(method, path, value=value, response_model=response_model)


def _miner_subnet(snapshot: Any) -> dict[str, Any]:
    return {
        **VECTORS["reservation"]["subnet"],
        "network": "local",
        "netuid": 24,
        "validator_hotkey": VALIDATOR.ss58_address,
        "miner_hotkey": MINER.ss58_address,
        "miner_uid": 1,
        "miner_axon_url": "http://miner.invalid",
        "miner_transport": "http",
        "miner_tls_certificate_sha256": None,
        "chain_block": snapshot.block,
        "epoch": snapshot.epoch,
        "expires_at_block": snapshot.block + 12,
        "validator_service_public_key": SERVICE_KEY,
    }


def _synapse(snapshot: Any, document: dict[str, Any], protocol: str) -> dict[str, Any]:
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
    return {
        "protocol": protocol,
        "request_id": "sandbox-1",
        "current_block": snapshot.block,
        "caller_hotkey": VALIDATOR.ss58_address,
        "validator_binding": binding.model_dump(mode="json"),
        "document": document,
    }


@pytest.mark.asyncio
async def test_sandbox_lane_is_absent_by_default(tmp_path: Path) -> None:
    """Flag off: no sandbox route on either neuron, so a sandbox document is
    answered exactly as before this lane existed, and nothing reaches Go."""

    agent = SandboxAgent()
    neuron, snapshot = await _neuron(tmp_path, agent)
    value = _synapse(
        snapshot, _document("leases", MINER.ss58_address, _miner_subnet(snapshot)), "x"
    )
    value["protocol"] = "subnet-sandbox-synapse.v1"
    for route in SANDBOX_ROUTES:
        response = await _post_miner(neuron, route, value)
        assert response.status_code == 404, response.text
    assert agent.requests == []
    assert (
        miner.build_parser()
        .parse_args(["--netuid", "1", "--bridge-secret-file", "s", "--state-db", "d"])
        .sandbox_leases
        == "off"
    )

    (tmp_path / "validator").mkdir()
    bridge, _, _ = make_harness(tmp_path / "validator")
    for kind in KINDS:
        target = f"/v1/miners/{MINER_A.hotkey}/sandbox-{kind}"
        assert (await _post_bridge(bridge, target, {"protocol": "x"})).status_code == 404
    assert (
        validator.build_parser()
        .parse_args(["--netuid", "1", "--bridge-secret-file", "s", "--state-db", "d"])
        .sandbox_leases
        == "off"
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", list(KINDS))
async def test_axon_forwards_the_exact_document_to_its_agent_route(
    tmp_path: Path, kind: str
) -> None:
    agent = SandboxAgent()
    neuron, snapshot = await _neuron(tmp_path, agent, sandbox_leases=True)
    document = _document(kind, MINER.ss58_address, _miner_subnet(snapshot))
    response = await _post_miner(
        neuron, f"/api/v1/sandbox/{kind}", _synapse(snapshot, document, "subnet-sandbox-synapse.v1")
    )
    assert response.status_code == 200, response.text
    assert response.json()["receipt"] == _receipt(document)
    [(path, forwarded)] = agent.requests
    assert path == f"/v1/sandbox/{kind}"
    sent = forwarded.model_dump(mode="json")
    assert sent["binding_verified"] is True
    assert sent["caller_hotkey"] == VALIDATOR.ss58_address
    assert sent["current_block"] == snapshot.block
    assert sent["document"] == document


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("route", "protocol", "change", "status", "detail"),
    [
        (LEASES, "subnet-static-synapse.v1", None, 422, "only subnet-sandbox-synapse.v1"),
        (RESERVATIONS, SANDBOX, None, 422, "sandbox_document_kind_mismatch"),
        (LEASES, SANDBOX, "static-ticket", 422, "sandbox_document_kind_mismatch"),
        (LEASES, SANDBOX, "v4-ticket", 422, "sandbox_document_kind_mismatch"),
        (LEASES, SANDBOX, "miner-id", 422, "sandbox_document_invalid"),
        (LEASES, SANDBOX, "caller", 403, "body caller differs"),
        (LEASES, SANDBOX, "uid", 403, "ticket Bittensor identity mismatch"),
        (LEASES, SANDBOX, "expired", 403, "ticket Bittensor identity mismatch"),
        ("/api/v1/static/deploy", SANDBOX, None, 422, "only subnet-static-synapse.v1"),
        ("/api/v1/deploy", SANDBOX, None, 422, "only subnet-synapse.v3"),
    ],
    ids=[
        "static-envelope",
        "lease-on-reservation-route",
        "static-ticket",
        "v4-ticket",
        "miner-id-not-bound",
        "body-caller",
        "wrong-uid",
        "expired-binding",
        "static-route",
        "organic-route",
    ],
)
async def test_axon_refuses_before_agent_contact(
    tmp_path: Path, route: str, protocol: str, change: str | None, status: int, detail: str
) -> None:
    agent = SandboxAgent()
    neuron, snapshot = await _neuron(tmp_path, agent, sandbox_leases=True)
    value = _synapse(
        snapshot, _document("leases", MINER.ss58_address, _miner_subnet(snapshot)), protocol
    )
    document = value["document"]
    if change in {"static-ticket", "v4-ticket"}:
        ticket = copy.deepcopy(STATIC_TICKET if change == "static-ticket" else V4_TICKET)
        ticket["subnet"] = document["subnet"]
        value["document"] = ticket
    elif change == "miner-id":
        document["miner_id"] = VALIDATOR.ss58_address
    elif change == "caller":
        value["caller_hotkey"] = MINER.ss58_address
    elif change == "uid":
        document["subnet"]["miner_uid"] = 2
    elif change == "expired":
        document["subnet"].update(
            chain_block=snapshot.block - 12,
            epoch=(snapshot.block - 12) // snapshot.tempo,
            expires_at_block=snapshot.block,
        )
    response = await _post_miner(neuron, route, value)
    assert response.status_code == status, response.text
    assert response.json()["detail"].startswith(detail)
    assert agent.requests == []


@pytest.mark.asyncio
async def test_axon_keeps_the_agent_refusal_code_and_rejects_a_foreign_receipt(
    tmp_path: Path,
) -> None:
    refusal = BridgeError("sandbox_disabled", "sandbox leases are not enabled", False, 501)
    neuron, snapshot = await _neuron(tmp_path, SandboxAgent(refusal), sandbox_leases=True)
    document = _document("leases", MINER.ss58_address, _miner_subnet(snapshot))
    value = _synapse(snapshot, document, "subnet-sandbox-synapse.v1")
    refused = await _post_miner(neuron, "/api/v1/sandbox/leases", value)
    assert refused.status_code == 501
    assert refused.json()["detail"] == "sandbox_disabled"

    (tmp_path / "miswired").mkdir()
    miswired = SandboxAgent()
    miswired.answer = {**_receipt(document), "document_schema": VECTORS["reservation"]["schema"]}
    neuron, snapshot = await _neuron(tmp_path / "miswired", miswired, sandbox_leases=True)
    response = await _post_miner(neuron, "/api/v1/sandbox/leases", value)
    assert response.status_code == 502
    assert response.json()["detail"] == "sandbox_receipt_mismatch"


# --------------------------------------------------------------------------
# Validator bridge
# --------------------------------------------------------------------------


class SandboxDendrite:
    """Wrap the cleanup miner simulator with the sandbox capability and routes."""

    def __init__(self, sim: Any) -> None:
        self.inner = sim.handler
        self.capable: set[str] = set()
        self.sent: list[tuple[str, SandboxSynapseV1]] = []
        self.receipt_override: dict[str, Any] | None = None

    def handler(self, request: httpx.Request) -> httpx.Response:
        if request.url.path.startswith("/api/v1/sandbox/"):
            synapse = SandboxSynapseV1.model_validate_json(request.content)
            self.sent.append((request.url.path, synapse))
            receipt = self.receipt_override or _receipt(synapse.document)
            return httpx.Response(
                200,
                json={
                    "protocol": "subnet-sandbox-synapse.v1",
                    "request_id": synapse.request_id,
                    "receipt": receipt,
                },
            )
        response = self.inner(request)
        if request.url.path == "/api/v1/capabilities":
            document = json.loads(response.content)
            if document["miner_hotkey"] in self.capable:
                document["features"].append("sandbox-lease-v1")
            return httpx.Response(200, json=document)
        return response


def _validator_subnet(chain: Any, snapshot: Any) -> dict[str, Any]:
    return {
        **VECTORS["reservation"]["subnet"],
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


async def _post_bridge(neuron: Any, target: str, document: dict[str, Any]) -> httpx.Response:
    body = json.dumps(document, separators=(",", ":")).encode()
    headers = bridge_headers(BRIDGE_SECRET, method="POST", target=target, body=body)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=neuron.app), base_url="http://bridge.local"
    ) as client:
        return await client.post(target, content=body, headers=headers)


@pytest.mark.asyncio
async def test_validator_sends_documents_only_to_capable_bound_miners(tmp_path: Path) -> None:
    neuron, chain, sim = make_harness(tmp_path, sandbox_leases=True)
    dendrite = SandboxDendrite(sim)
    neuron.dendrite_transport = httpx.MockTransport(dendrite.handler)
    snapshot = await refresh(neuron, chain, sim)
    subnet = _validator_subnet(chain, snapshot)
    target = f"/v1/miners/{MINER_A.hotkey}/sandbox-reservations"
    request = {
        "protocol": "subnet-sandbox-synapse.v1",
        "request_id": "sandbox-1",
        "document": _document("reservations", MINER_A.hotkey, subnet),
    }

    # A miner without the lane is refused before contact with a neutral code.
    refused = await _post_bridge(neuron, target, request)
    assert refused.status_code == 409, refused.text
    assert refused.json()["error"]["code"] == SANDBOX_CAPABILITY_UNSUPPORTED
    assert dendrite.sent == []

    dendrite.capable.add(MINER_A.hotkey)
    await refresh(neuron, chain, sim)
    for kind in KINDS:
        document = _document(kind, MINER_A.hotkey, subnet)
        response = await _post_bridge(
            neuron,
            f"/v1/miners/{MINER_A.hotkey}/sandbox-{kind}",
            {**request, "document": document},
        )
        assert response.status_code == 200, response.text
        assert response.json()["receipt"] == _receipt(document)
        path, sent = dendrite.sent[-1]
        assert path == f"/api/v1/sandbox/{kind}"
        assert sent.caller_hotkey == chain.hotkey
        assert sent.document == document
    assert len(dendrite.sent) == len(KINDS)

    # Never delivered: a binding that differs from the handshake, a document
    # on another kind's route, or a static envelope.
    moved = {**subnet, "miner_axon_url": "http://elsewhere:8091"}
    for route, value, status in (
        (target, {**request, "document": _document("reservations", MINER_A.hotkey, moved)}, 403),
        (target, {**request, "document": _document("leases", MINER_A.hotkey, subnet)}, 422),
        (target, {**request, "protocol": "subnet-static-synapse.v1"}, 422),
    ):
        response = await _post_bridge(neuron, route, value)
        assert response.status_code == status, response.text
    assert len(dendrite.sent) == len(KINDS)

    # A miner answer that is not a receipt for this document is not relayed.
    dendrite.receipt_override = {**_receipt(request["document"]), "generation": 9}
    response = await _post_bridge(neuron, target, request)
    assert response.status_code == 502, response.text
    assert response.json()["error"]["message"] == "sandbox_receipt_mismatch"
