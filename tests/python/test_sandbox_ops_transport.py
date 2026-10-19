# SPDX-License-Identifier: AGPL-3.0-only
"""subnet-sandbox-ops-synapse.v1 forwarding in the miner axon and validator bridge.

Off by default and only together with the lease lane: neither neuron exposes
an ops route unless started with ``--sandbox-ops on``. When on, the axon
applies the lease route's btauth and identity checks and forwards the op
document and its payload unchanged; the validator sends an op only to a miner
whose handshake matches its binding and that advertises both
``sandbox-lease-v1`` and ``sandbox-ops-v1``. Documents are the Go contract's
op vectors re-bound to the test identities; their signatures and the payload
binding are the Go agent's and runtime's concern, not this hop's.
"""

from __future__ import annotations

import base64
import copy
import json
from pathlib import Path
from typing import Any

import httpx
import pytest
from test_miner_neuron import MINER
from test_sandbox_transport import (
    VECTORS as LEASE_VECTORS,
)
from test_sandbox_transport import (
    SandboxAgent,
    SandboxDendrite,
    _miner_subnet,
    _post_bridge,
    _synapse,
    _validator_subnet,
)
from test_static_miner_neuron import _neuron
from test_static_miner_neuron import _post as _post_miner
from test_validator_cleanup import MINER_A, make_harness, refresh

from misscomputer_subnet import miner, validator
from misscomputer_subnet.sandbox_transport import (
    SANDBOX_OPS_CAPABILITY_UNSUPPORTED,
    LocalSandboxOpsRequestV1,
    SandboxOpsResponseV1,
    SandboxOpsSynapseV1,
)

OPS_VECTORS = json.loads(
    (
        Path(__file__).resolve().parents[2] / "pkg/protocol/testdata/sandbox-ops-v1-vectors.json"
    ).read_text()
)
OPS = "subnet-sandbox-ops-synapse.v1"
ROUTE = "/api/v1/sandbox/ops"
PAYLOAD = base64.b64encode(b"print('hello')\n").decode()


def _op(miner_hotkey: str, subnet: dict[str, Any]) -> dict[str, Any]:
    document = copy.deepcopy(OPS_VECTORS["file_write"])
    document["miner_id"] = miner_hotkey
    document["subnet"] = subnet
    return document


def _op_receipt(document: dict[str, Any]) -> dict[str, Any]:
    receipt = copy.deepcopy(OPS_VECTORS["file_write_receipt"])
    receipt.update(
        sandbox_id=document["sandbox_id"],
        generation=document["generation"],
        miner_id=document["miner_id"],
        subnet=document["subnet"],
    )
    return receipt


class OpsAgent(SandboxAgent):
    """Go agent stand-in that also answers op requests."""

    def __init__(self) -> None:
        super().__init__()
        self.ops: list[LocalSandboxOpsRequestV1] = []
        self.op_answer: dict[str, Any] | None = None

    async def request(
        self,
        method: str,
        path: str,
        *,
        value: Any = None,
        response_model: type[Any] | None = None,
    ) -> Any:
        if method == "POST" and path == "/v1/sandbox/ops":
            assert isinstance(value, LocalSandboxOpsRequestV1)
            assert response_model is SandboxOpsResponseV1
            self.ops.append(value)
            receipt = self.op_answer if self.op_answer is not None else _op_receipt(value.document)
            return SandboxOpsResponseV1(
                protocol=OPS, request_id=value.request_id, receipt=receipt, result_b64=None
            )
        return await super().request(method, path, value=value, response_model=response_model)


def _ops_synapse(snapshot: Any, document: dict[str, Any]) -> dict[str, Any]:
    return {**_synapse(snapshot, document, OPS), "payload_b64": PAYLOAD}


@pytest.mark.asyncio
async def test_ops_routes_exist_only_with_ops_on(tmp_path: Path) -> None:
    agent = OpsAgent()
    neuron, snapshot = await _neuron(tmp_path, agent, sandbox_leases=True)
    value = _ops_synapse(snapshot, _op(MINER.ss58_address, _miner_subnet(snapshot)))
    assert (await _post_miner(neuron, ROUTE, value)).status_code == 404
    assert agent.ops == []
    (tmp_path / "ops-only").mkdir()
    with pytest.raises(ValueError, match="sandbox ops require sandbox leases"):
        await _neuron(tmp_path / "ops-only", OpsAgent(), sandbox_ops=True)
    args = ["--netuid", "1", "--bridge-secret-file", "s", "--state-db", "d"]
    assert miner.build_parser().parse_args(args).sandbox_ops == "off"
    assert validator.build_parser().parse_args(args).sandbox_ops == "off"

    (tmp_path / "validator").mkdir()
    bridge, _, _ = make_harness(tmp_path / "validator", sandbox_leases=True)
    target = f"/v1/miners/{MINER_A.hotkey}/sandbox-ops"
    assert (await _post_bridge(bridge, target, {"protocol": OPS})).status_code == 404


@pytest.mark.asyncio
async def test_axon_forwards_the_exact_op_and_payload(tmp_path: Path) -> None:
    agent = OpsAgent()
    neuron, snapshot = await _neuron(tmp_path, agent, sandbox_leases=True, sandbox_ops=True)
    document = _op(MINER.ss58_address, _miner_subnet(snapshot))
    response = await _post_miner(neuron, ROUTE, _ops_synapse(snapshot, document))
    assert response.status_code == 200, response.text
    assert response.json()["receipt"] == _op_receipt(document)
    [forwarded] = agent.ops
    sent = forwarded.model_dump(mode="json")
    assert sent["binding_verified"] is True
    assert sent["document"] == document
    assert sent["payload_b64"] == PAYLOAD

    # Never forwarded: a lease document on the ops route, or the lease envelope.
    lease = copy.deepcopy(LEASE_VECTORS["lease"])
    lease.update(miner_id=MINER.ss58_address, subnet=_miner_subnet(snapshot))
    for value, detail in (
        (_ops_synapse(snapshot, lease), "sandbox_document_kind_mismatch"),
        ({**_ops_synapse(snapshot, document), "protocol": "subnet-sandbox-synapse.v1"}, "only"),
    ):
        refused = await _post_miner(neuron, ROUTE, value)
        assert refused.status_code == 422, refused.text
        assert refused.json()["detail"].startswith(detail)
    assert len(agent.ops) == 1

    # An answer that is not an op receipt for this request is not relayed.
    agent.op_answer = {**_op_receipt(document), "generation": 9}
    response = await _post_miner(neuron, ROUTE, _ops_synapse(snapshot, document))
    assert response.status_code == 502
    assert response.json()["detail"] == "sandbox_receipt_mismatch"


class OpsDendrite(SandboxDendrite):
    """Miner simulator that also answers ops and advertises sandbox-ops-v1."""

    def __init__(self, sim: Any) -> None:
        super().__init__(sim)
        self.ops_capable: set[str] = set()
        self.sent_ops: list[SandboxOpsSynapseV1] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        if request.url.path == ROUTE:
            synapse = SandboxOpsSynapseV1.model_validate_json(request.content)
            self.sent_ops.append(synapse)
            return httpx.Response(
                200,
                json={
                    "protocol": OPS,
                    "request_id": synapse.request_id,
                    "receipt": _op_receipt(synapse.document),
                    "result_b64": None,
                },
            )
        response = super().handler(request)
        if request.url.path == "/api/v1/capabilities":
            document = json.loads(response.content)
            if document["miner_hotkey"] in self.ops_capable:
                document["features"].append("sandbox-ops-v1")
            return httpx.Response(200, json=document)
        return response


@pytest.mark.asyncio
async def test_validator_sends_ops_only_to_ops_capable_bound_miners(tmp_path: Path) -> None:
    neuron, chain, sim = make_harness(tmp_path, sandbox_leases=True, sandbox_ops=True)
    dendrite = OpsDendrite(sim)
    neuron.dendrite_transport = httpx.MockTransport(dendrite.handler)
    await refresh(neuron, chain, sim)
    snapshot = await refresh(neuron, chain, sim)
    subnet = _validator_subnet(chain, snapshot)
    target = f"/v1/miners/{MINER_A.hotkey}/sandbox-ops"
    request = {
        "protocol": OPS,
        "request_id": "op-1",
        "document": _op(MINER_A.hotkey, subnet),
        "payload_b64": PAYLOAD,
    }

    # The lease lane alone is not enough: refused before contact.
    dendrite.capable.add(MINER_A.hotkey)
    await refresh(neuron, chain, sim)
    refused = await _post_bridge(neuron, target, request)
    assert refused.status_code == 409, refused.text
    assert refused.json()["error"]["code"] == SANDBOX_OPS_CAPABILITY_UNSUPPORTED
    assert dendrite.sent_ops == []

    dendrite.ops_capable.add(MINER_A.hotkey)
    await refresh(neuron, chain, sim)
    response = await _post_bridge(neuron, target, request)
    assert response.status_code == 200, response.text
    assert response.json()["receipt"] == _op_receipt(request["document"])
    [sent] = dendrite.sent_ops
    assert sent.caller_hotkey == chain.hotkey
    assert sent.document == request["document"]
    assert sent.payload_b64 == PAYLOAD

    moved = {**subnet, "miner_axon_url": "http://elsewhere:8091"}
    response = await _post_bridge(
        neuron, target, {**request, "document": _op(MINER_A.hotkey, moved)}
    )
    assert response.status_code == 403, response.text
    assert len(dendrite.sent_ops) == 1
