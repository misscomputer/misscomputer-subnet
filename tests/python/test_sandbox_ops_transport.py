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

import asyncio
import base64
import copy
import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import bittensor as bt
import httpx
import pytest
from test_miner_neuron import MINER, UNAUTHORIZED, VALIDATOR
from test_sandbox_transport import (
    SANDBOX,
    SandboxAgent,
    SandboxDendrite,
    _document,
    _miner_subnet,
    _post_bridge,
    _receipt,
    _synapse,
    _validator_subnet,
)
from test_sandbox_transport import (
    VECTORS as LEASE_VECTORS,
)
from test_static_miner_neuron import _neuron
from test_static_miner_neuron import _post as _post_miner
from test_validator_cleanup import MINER_A, make_harness, refresh

from misscomputer_subnet import miner, validator
from misscomputer_subnet.auth import BRIDGE_MAX_BODY, BridgeClient, SQLiteNonceStore
from misscomputer_subnet.chain import MockChain, MockPeer
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


# --------------------------------------------------------------------------
# Admission: tenant ops never consume what lease lifecycle and the capability
# handshake need from the same validator (R23-C-01, DR-01, DR-03).
# --------------------------------------------------------------------------


def _cancel(miner_hotkey: str, subnet: dict[str, Any]) -> dict[str, Any]:
    document = copy.deepcopy(OPS_VECTORS["exec_read"])
    document.update(op="exec_cancel", stream=None, offset=None, limit=None)
    document["miner_id"] = miner_hotkey
    document["subnet"] = subnet
    return document


def _capability(snapshot: Any) -> dict[str, Any]:
    return {
        "protocol": "subnet-synapse.v2",
        "request_id": "capability-after-ops",
        "network": "local",
        "netuid": 24,
        "chain_block": snapshot.block,
        "caller_hotkey": VALIDATOR.ss58_address,
        "challenge": "fresh-capability-challenge",
    }


def _renewal(snapshot: Any) -> dict[str, Any]:
    document = _document("renewals", MINER.ss58_address, _miner_subnet(snapshot))
    return _synapse(snapshot, document, SANDBOX)


async def _until(condition: Callable[[], bool]) -> None:
    for _ in range(500):
        if condition():
            return
        await asyncio.sleep(0.01)
    raise AssertionError("condition not reached within 5 s")


@pytest.mark.asyncio
async def test_exhausted_ops_rate_leaves_lifecycle_and_handshake_authorized(
    tmp_path: Path,
) -> None:
    agent = OpsAgent()
    neuron, snapshot = await _neuron(tmp_path, agent, sandbox_leases=True, sandbox_ops=True)
    op = _ops_synapse(snapshot, _op(MINER.ss58_address, _miner_subnet(snapshot)))
    refused: httpx.Response | None = None
    sent = 0
    while refused is None and sent < 1_000:
        sent += 1
        response = await _post_miner(neuron, ROUTE, op)
        if response.status_code == 429:
            refused = response
        else:
            assert response.status_code == 200, response.text
    assert refused is not None, "the ops request budget was never exhausted"

    # The same validator's renewal and capability handshake are still admitted.
    renewal = await _post_miner(neuron, "/api/v1/sandbox/renewals", _renewal(snapshot))
    assert renewal.status_code == 200, (
        f"renewal after {sent} ops ({refused.json()['detail']}): {renewal.status_code} "
        f"{renewal.text}"
    )
    capability = await _post_miner(neuron, "/api/v1/capabilities", _capability(snapshot))
    assert capability.status_code == 200, capability.text

    # The ops refusal is definitive and pre-agent: a stable code, a retry
    # hint, and the refused request never reached the agent.
    assert refused.json()["detail"] == "sandbox_ops_rate_exceeded"
    assert int(refused.headers["retry-after"]) >= 1
    assert len(agent.ops) == sent - 1


class BlockingOpsAgent(OpsAgent):
    """Holds every op except exec_cancel at the agent until released, as a
    guest that stops its own helper does."""

    def __init__(self) -> None:
        super().__init__()
        self.held = 0
        self.release = asyncio.Event()

    async def request(
        self,
        method: str,
        path: str,
        *,
        value: Any = None,
        response_model: type[Any] | None = None,
    ) -> Any:
        if path == "/v1/sandbox/ops" and value.document.get("op") != "exec_cancel":
            self.held += 1
            await self.release.wait()
        return await super().request(method, path, value=value, response_model=response_model)


@pytest.mark.asyncio
async def test_held_ops_never_queue_lifecycle_and_overflow_is_refused(tmp_path: Path) -> None:
    agent = BlockingOpsAgent()
    neuron, snapshot = await _neuron(tmp_path, agent, sandbox_leases=True, sandbox_ops=True)
    op = _ops_synapse(snapshot, _op(MINER.ss58_address, _miner_subnet(snapshot)))
    held = [asyncio.create_task(_post_miner(neuron, ROUTE, op)) for _ in range(8)]
    more: list[asyncio.Task[httpx.Response]] = []
    try:
        await _until(lambda: agent.held >= 1)
        await asyncio.sleep(0.2)
        try:
            renewal = await asyncio.wait_for(
                _post_miner(neuron, "/api/v1/sandbox/renewals", _renewal(snapshot)), timeout=5
            )
        except TimeoutError:
            pytest.fail(f"lease renewal queued behind {agent.held} held op(s)")
        assert renewal.status_code == 200, renewal.text

        # Fill the ops capacity: one more op is refused at once without agent
        # contact, while an exec_cancel still enters through its headroom.
        capacity = miner.SANDBOX_OPS_CONCURRENCY
        more = [asyncio.create_task(_post_miner(neuron, ROUTE, op)) for _ in range(capacity - 8)]
        await _until(lambda: agent.held == capacity)
        overflow = await asyncio.wait_for(_post_miner(neuron, ROUTE, op), timeout=5)
        assert overflow.status_code == 429, overflow.text
        assert overflow.json()["detail"] == "sandbox_ops_capacity_exhausted"
        assert int(overflow.headers["retry-after"]) >= 1
        cancel = _cancel_synapse(snapshot)
        answered = await asyncio.wait_for(_post_miner(neuron, ROUTE, cancel), timeout=5)
        assert answered.status_code == 200, answered.text
        assert agent.held == capacity
    finally:
        agent.release.set()
        results = await asyncio.gather(*held, *more)
    assert all(result.status_code == 200 for result in results)
    # Every admission slot came back: a new op is admitted.
    after = await asyncio.wait_for(_post_miner(neuron, ROUTE, op), timeout=5)
    assert after.status_code == 200, after.text


@pytest.mark.asyncio
async def test_ops_admission_keeps_ingress_for_other_work(tmp_path: Path) -> None:
    peers = (
        MockPeer("//Validator", 0, None, True, 2_000),
        MockPeer("//Miner1", 1, "http://miner.invalid", False, 10),
    )
    chain = MockChain(network="local", netuid=24, own_uri="//Miner1", peers=peers)
    options: dict[str, Any] = {
        "chain": chain,
        "hotkey_signer": chain.hotkey_signer,
        "network": "local",
        "netuid": 24,
        "configured_uid": 1,
        "bridge": OpsAgent(),
        "nonce_store": SQLiteNonceStore(str(tmp_path / "ingress.db")),
        "min_validator_stake": 1_000,
        "operator_hotkeys": (VALIDATOR.ss58_address,),
        "sync_interval": 10,
        "mock_http": True,
        "tls_config": None,
        "sandbox_leases": True,
    }
    # Ops plus their cancel headroom and the assignment gate must leave room
    # at the uvicorn ingress bound for lease lifecycle, handshakes and the
    # runtime proxy; with ops off the assignment gate is unconstrained as before.
    with pytest.raises(ValueError, match="ingress"):
        miner.MinerNeuron(**options, max_concurrency=40, sandbox_ops=True)
    miner.MinerNeuron(**options, max_concurrency=4, sandbox_ops=True)
    miner.MinerNeuron(**options, max_concurrency=40)


class _Clock:
    """The miner neuron's monotonic clock, moved only by the test, so window
    counts and Retry-After values are exact however long a request takes."""

    def __init__(self) -> None:
        self.now = 1_000.0

    def monotonic(self) -> float:
        return self.now


def _cancel_synapse(snapshot: Any) -> dict[str, Any]:
    # exec_cancel has no payload; the agent refuses one (sandbox_op_payload_unexpected).
    return {
        **_synapse(snapshot, _cancel(MINER.ss58_address, _miner_subnet(snapshot)), OPS),
        "payload_b64": None,
    }


async def _post_signed(
    neuron: Any, value: dict[str, Any], *, signer: Any, sent: dict[str, Any] | None = None
) -> httpx.Response:
    """Post ``sent`` (default ``value``) with btauth headers ``signer`` made over ``value``."""

    body = json.dumps(value, separators=(",", ":")).encode()
    headers = bt.http_auth.sign(
        signer, method="POST", path=ROUTE, body=body, receiver_ss58=MINER.ss58_address
    )
    if sent is not None:
        body = json.dumps(sent, separators=(",", ":")).encode()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=neuron.app), base_url="http://miner"
    ) as client:
        return await client.post(ROUTE, content=body, headers=headers)


async def _fill_ordinary_ops_window(neuron: Any, snapshot: Any) -> None:
    op = _ops_synapse(snapshot, _op(MINER.ss58_address, _miner_subnet(snapshot)))
    for count in range(miner.SANDBOX_OPS_MAX_REQUESTS_PER_WINDOW):
        response = await _post_miner(neuron, ROUTE, op)
        assert response.status_code == 200, f"ordinary op {count + 1}: {response.text}"
    refused = await _post_miner(neuron, ROUTE, op)
    assert refused.status_code == 429, refused.text
    assert refused.json()["detail"] == "sandbox_ops_rate_exceeded"
    assert refused.headers["retry-after"] == str(int(miner.SANDBOX_OPS_WINDOW_SECONDS))


@pytest.mark.asyncio
async def test_exec_cancel_has_a_bounded_rate_reserve_ordinary_ops_cannot_spend(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = _Clock()
    monkeypatch.setattr(miner, "time", clock)
    agent = OpsAgent()
    neuron, snapshot = await _neuron(tmp_path, agent, sandbox_leases=True, sandbox_ops=True)
    ordinary = miner.SANDBOX_OPS_MAX_REQUESTS_PER_WINDOW
    await _fill_ordinary_ops_window(neuron, snapshot)

    # Ordinary ops have spent their whole window while concurrency is free:
    # a tenant can still stop an exec.
    cancel = _cancel_synapse(snapshot)
    stopped = await _post_miner(neuron, ROUTE, cancel)
    assert stopped.status_code == 200, (
        f"exec_cancel after {ordinary} ordinary ops: {stopped.status_code} {stopped.text}"
    )
    assert agent.ops[-1].document["op"] == "exec_cancel"

    # The reserve is finite and refuses its own flood definitively.
    reserve = miner.SANDBOX_OPS_CANCEL_MAX_REQUESTS_PER_WINDOW
    for count in range(1, reserve):
        response = await _post_miner(neuron, ROUTE, cancel)
        assert response.status_code == 200, f"cancel {count + 1}: {response.text}"
    flooded = await _post_miner(neuron, ROUTE, cancel)
    assert flooded.status_code == 429, flooded.text
    assert flooded.json()["detail"] == "sandbox_ops_rate_exceeded"
    assert flooded.headers["retry-after"] == str(int(miner.SANDBOX_OPS_WINDOW_SECONDS))
    assert len(agent.ops) == ordinary + reserve

    # Cancels did not return ordinary budget, and neither ops window touches
    # the default budget lease lifecycle and the handshake use.
    op = _ops_synapse(snapshot, _op(MINER.ss58_address, _miner_subnet(snapshot)))
    assert (await _post_miner(neuron, ROUTE, op)).status_code == 429
    renewal = await _post_miner(neuron, "/api/v1/sandbox/renewals", _renewal(snapshot))
    assert renewal.status_code == 200, renewal.text
    capability = await _post_miner(neuron, "/api/v1/capabilities", _capability(snapshot))
    assert capability.status_code == 200, capability.text
    assert len(agent.ops) == ordinary + reserve

    # Both windows refill independently once their entries age out.
    clock.now += miner.SANDBOX_OPS_WINDOW_SECONDS
    assert (await _post_miner(neuron, ROUTE, cancel)).status_code == 200
    assert (await _post_miner(neuron, ROUTE, op)).status_code == 200


@pytest.mark.asyncio
async def test_only_authenticated_well_formed_exec_cancel_reaches_the_reserve(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(miner, "time", _Clock())
    agent = OpsAgent()
    neuron, snapshot = await _neuron(tmp_path, agent, sandbox_leases=True, sandbox_ops=True)
    await _fill_ordinary_ops_window(neuron, snapshot)
    cancel = _cancel_synapse(snapshot)

    # Refused before any rate accounting: an unknown caller and a body that
    # does not match its btauth signature.
    foreign = await _post_signed(neuron, cancel, signer=UNAUTHORIZED)
    assert foreign.status_code == 403, foreign.text
    assert foreign.json()["detail"] == "caller is not a configured operator"
    tampered = await _post_signed(
        neuron, cancel, signer=VALIDATOR, sent={**cancel, "request_id": "sandbox-2"}
    )
    assert tampered.status_code == 401, tampered.text

    # Authenticated but not a well-formed exec_cancel for this caller: counted
    # as an ordinary op, so the full ordinary window refuses it.
    document = cancel["document"]
    for name, value in (
        ("lease envelope", {**cancel, "protocol": "subnet-sandbox-synapse.v1"}),
        ("not an op request", {**cancel, "document": {**document, "schema": "x"}}),
        ("unbound miner", {**cancel, "document": {**document, "miner_id": VALIDATOR.ss58_address}}),
        ("body caller", {**cancel, "caller_hotkey": MINER.ss58_address}),
        ("with payload", {**cancel, "payload_b64": PAYLOAD}),
        ("op case", {**cancel, "document": {**document, "op": "EXEC_CANCEL"}}),
        ("op type", {**cancel, "document": {**document, "op": ["exec_cancel"]}}),
        ("not json", None),
    ):
        if value is None:
            refused = await _post_signed_raw(neuron, b'{"op":"exec_cancel"')
        else:
            refused = await _post_miner(neuron, ROUTE, value)
        assert refused.status_code == 429, f"{name}: {refused.status_code} {refused.text}"
        assert refused.json()["detail"] == "sandbox_ops_rate_exceeded", name
    assert len(agent.ops) == miner.SANDBOX_OPS_MAX_REQUESTS_PER_WINDOW

    # None of them spent the reserve: it still admits exactly its bound.
    first = await _post_miner(neuron, ROUTE, cancel)
    assert first.status_code == 200, f"well-formed exec_cancel: {first.status_code} {first.text}"
    reserve = miner.SANDBOX_OPS_CANCEL_MAX_REQUESTS_PER_WINDOW
    for count in range(1, reserve):
        response = await _post_miner(neuron, ROUTE, cancel)
        assert response.status_code == 200, f"cancel {count + 1}: {response.text}"
    assert (await _post_miner(neuron, ROUTE, cancel)).status_code == 429


async def _post_signed_raw(neuron: Any, body: bytes) -> httpx.Response:
    headers = bt.http_auth.sign(
        VALIDATOR, method="POST", path=ROUTE, body=body, receiver_ss58=MINER.ss58_address
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=neuron.app), base_url="http://miner"
    ) as client:
        return await client.post(ROUTE, content=body, headers=headers)


class RefusingOpsDendrite(OpsDendrite):
    """Miner simulator answering one route with a fixed refusal before its agent."""

    def __init__(self, sim: Any, path: str, refusal: httpx.Response) -> None:
        super().__init__(sim)
        self.path = path
        self.refusal = refusal
        self.refused = 0

    def handler(self, request: httpx.Request) -> httpx.Response:
        if request.url.path == self.path:
            self.refused += 1
            return httpx.Response(
                self.refusal.status_code,
                content=self.refusal.content,
                headers=self.refusal.headers,
            )
        return super().handler(request)


RATE = miner.SANDBOX_OPS_RATE_EXCEEDED
CAPACITY = miner.SANDBOX_OPS_CAPACITY_EXHAUSTED
FOREIGN_HEADERS = {"X-Miner-Debug": "1", "Set-Cookie": "session=miner"}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("route", "status", "detail", "retry_after", "code", "relayed_retry_after"),
    [
        # The miner neuron's own definitive admission refusals.
        ("ops", 429, CAPACITY, "1", CAPACITY, "1"),
        ("ops", 429, RATE, "10", RATE, "10"),
        ("ops", 429, RATE, "60", RATE, "60"),
        # An allowlisted code keeps its code; an invalid hint is dropped.
        ("ops", 429, RATE, "0", RATE, None),
        ("ops", 429, RATE, "61", RATE, None),
        ("ops", 429, RATE, "-1", RATE, None),
        ("ops", 429, RATE, "1.5", RATE, None),
        ("ops", 429, RATE, "01", RATE, None),
        ("ops", 429, RATE, "+5", RATE, None),
        ("ops", 429, RATE, "\u0661", RATE, None),
        ("ops", 429, RATE, "Wed, 21 Oct 2026 07:28:00 GMT", RATE, None),
        ("ops", 429, RATE, "9" * 4096, RATE, None),
        ("ops", 429, RATE, ("1", "1"), RATE, None),
        ("ops", 429, RATE, "1, 2", RATE, None),
        ("ops", 429, RATE, None, RATE, None),
        # Any other code, or the allowlisted code on another status or route,
        # keeps the generic behaviour and never carries a hint.
        ("ops", 429, "sandbox_ops_busy", "1", "rate_limited", None),
        ("ops", 429, "validator request rate exceeded", "1", "rate_limited", None),
        ("ops", 429, RATE.upper(), "1", "rate_limited", None),
        ("ops", 429, RATE + " ", "1", "rate_limited", None),
        ("ops", 403, RATE, "1", "identity_mismatch", None),
        ("ops", 409, CAPACITY, "1", "stale_or_replayed", None),
        ("renewals", 429, CAPACITY, "1", "rate_limited", None),
    ],
    ids=[
        "capacity",
        "rate",
        "rate-max",
        "hint-zero",
        "hint-over-max",
        "hint-negative",
        "hint-fraction",
        "hint-leading-zero",
        "hint-signed",
        "hint-non-ascii-digit",
        "hint-http-date",
        "hint-oversized",
        "hint-duplicated",
        "hint-list",
        "hint-absent",
        "foreign-code-busy",
        "foreign-code-default-window",
        "foreign-code-case",
        "foreign-code-space",
        "allowlisted-code-403",
        "allowlisted-code-409",
        "lease-route",
    ],
)
async def test_validator_relays_only_the_neuron_ops_refusal_code_and_retry_hint(
    tmp_path: Path,
    route: str,
    status: int,
    detail: str,
    retry_after: str | tuple[str, ...] | None,
    code: str,
    relayed_retry_after: str | None,
) -> None:
    neuron, chain, sim = make_harness(tmp_path, sandbox_leases=True, sandbox_ops=True)
    # The production default: one dendrite resend for a transport or 5xx failure.
    neuron.dendrite_retries = validator.build_parser().get_default("dendrite_retries")
    assert neuron.dendrite_retries >= 1
    headers: list[tuple[str, str | bytes]] = list(FOREIGN_HEADERS.items())
    for value in (retry_after,) if isinstance(retry_after, str) else retry_after or ():
        # Raw bytes, so a non-ASCII hint reaches the validator as sent.
        headers.append(("Retry-After", value.encode()))
    miner_path = ROUTE if route == "ops" else f"/api/v1/sandbox/{route}"
    dendrite = RefusingOpsDendrite(
        sim, miner_path, httpx.Response(status, json={"detail": detail}, headers=headers)
    )
    dendrite.capable.add(MINER_A.hotkey)
    dendrite.ops_capable.add(MINER_A.hotkey)
    neuron.dendrite_transport = httpx.MockTransport(dendrite.handler)
    await refresh(neuron, chain, sim)
    snapshot = await refresh(neuron, chain, sim)
    subnet = _validator_subnet(chain, snapshot)
    if route == "ops":
        target = f"/v1/miners/{MINER_A.hotkey}/sandbox-ops"
        request: dict[str, Any] = {
            "protocol": OPS,
            "request_id": "op-refused",
            "document": _op(MINER_A.hotkey, subnet),
            "payload_b64": PAYLOAD,
        }
    else:
        target = f"/v1/miners/{MINER_A.hotkey}/sandbox-{route}"
        request = {
            "protocol": "subnet-sandbox-synapse.v1",
            "request_id": "lease-refused",
            "document": _document(route, MINER_A.hotkey, subnet),
        }
    response = await _post_bridge(neuron, target, request)
    assert response.status_code == status, response.text
    error = response.json()["error"]
    assert error["code"] == code
    assert error["message"] == detail
    assert error["retryable"] is (status == 429)
    assert response.headers.get("retry-after") == relayed_retry_after
    for name in FOREIGN_HEADERS:
        assert name.lower() not in response.headers
    # A refusal below 500 is definitive: the validator never resends it.
    assert dendrite.refused == 1


class ScriptedDendrite(OpsDendrite):
    """Miner simulator answering one route from a script, one entry per contact.

    An entry is an ``httpx.Response``, an ``httpx.TransportError`` subclass to
    raise (a lost or cut answer), or ``"receipt"`` for the normal signed
    answer. Every request body that reached the miner is kept.
    """

    def __init__(self, sim: Any, path: str, script: list[Any]) -> None:
        super().__init__(sim)
        self.path = path
        self.script = list(script)
        self.bodies: list[bytes] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        if request.url.path != self.path:
            return super().handler(request)
        self.bodies.append(request.content)
        entry = self.script.pop(0)
        if entry == "receipt":
            return super().handler(request)
        if isinstance(entry, type) and issubclass(entry, httpx.TransportError):
            raise entry("injected: answer lost after the request was sent", request=request)
        assert isinstance(entry, httpx.Response)
        return httpx.Response(entry.status_code, content=entry.content, headers=entry.headers)


async def _validator_with(
    tmp_path: Path, path: str, script: list[Any]
) -> tuple[Any, ScriptedDendrite, dict[str, Any]]:
    neuron, chain, sim = make_harness(tmp_path, sandbox_leases=True, sandbox_ops=True)
    # The production default: one dendrite resend for a transport or 5xx failure.
    neuron.dendrite_retries = validator.build_parser().get_default("dendrite_retries")
    assert neuron.dendrite_retries >= 1
    dendrite = ScriptedDendrite(sim, path, script)
    dendrite.capable.add(MINER_A.hotkey)
    dendrite.ops_capable.add(MINER_A.hotkey)
    neuron.dendrite_transport = httpx.MockTransport(dendrite.handler)
    await refresh(neuron, chain, sim)
    snapshot = await refresh(neuron, chain, sim)
    return neuron, dendrite, _validator_subnet(chain, snapshot)


def _refusal(status: int, detail: str, retry_after: str | None = None) -> httpx.Response:
    headers = {"Retry-After": retry_after} if retry_after is not None else {}
    return httpx.Response(status, json={"detail": detail}, headers=headers)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("first", "then", "status", "code"),
    [
        (_refusal(500, "sandbox_ops_internal"), _refusal(429, RATE, "1"), 502, "dendrite_upstream"),
        (_refusal(503, "sandbox_ops_busy"), _refusal(429, CAPACITY, "1"), 502, "dendrite_upstream"),
        (httpx.ReadTimeout, _refusal(429, RATE, "10"), 504, "dendrite_timeout"),
        (httpx.RemoteProtocolError, _refusal(403, "identity"), 502, "dendrite_upstream"),
        (
            httpx.Response(200, content=b"not json"),
            _refusal(409, "sandbox_conflict"),
            502,
            "dendrite_upstream",
        ),
        (
            httpx.Response(200, content=b"x" * (BRIDGE_MAX_BODY + 1)),
            _refusal(429, RATE, "1"),
            502,
            "dendrite_upstream",
        ),
    ],
    ids=[
        "agent-500-then-rate-429",
        "agent-503-then-capacity-429",
        "answer-timeout-then-rate-429",
        "connection-cut-then-403",
        "unusable-answer-then-409",
        "oversized-answer-then-429",
    ],
)
async def test_validator_never_reports_a_possibly_delivered_op_as_refused(
    tmp_path: Path, first: Any, then: httpx.Response, status: int, code: str
) -> None:
    """R23-CTRL-AR-01: once an op may have reached the miner, no later answer
    may turn it into a definitive refusal at this hop. The validator sends
    each op once; only the runtime resends it, with the same signed op."""

    neuron, dendrite, subnet = await _validator_with(tmp_path, ROUTE, [first, then])
    request = {
        "protocol": OPS,
        "request_id": "op-ambiguous",
        "document": _op(MINER_A.hotkey, subnet),
        "payload_b64": PAYLOAD,
    }
    response = await _post_bridge(neuron, f"/v1/miners/{MINER_A.hotkey}/sandbox-ops", request)
    assert response.status_code == status, (
        f"possibly delivered op answered {response.status_code} {response.text} "
        f"after {len(dendrite.bodies)} miner contact(s)"
    )
    assert response.json()["error"]["code"] == code
    assert "retry-after" not in response.headers
    assert len(dendrite.bodies) == 1


@pytest.mark.asyncio
async def test_runtime_resend_of_the_same_op_recovers_its_signed_outcome(
    tmp_path: Path,
) -> None:
    """Control: an unknown outcome is resolved by resending the exact same
    signed op (same op_nonce), never by a new one; the miner's receipt then
    reaches the runtime unchanged."""

    neuron, dendrite, subnet = await _validator_with(
        tmp_path, ROUTE, [_refusal(503, "sandbox_ops_busy"), "receipt"]
    )
    request = {
        "protocol": OPS,
        "request_id": "op-resent",
        "document": _op(MINER_A.hotkey, subnet),
        "payload_b64": PAYLOAD,
    }
    target = f"/v1/miners/{MINER_A.hotkey}/sandbox-ops"
    # The runtime's exact-resend loop: the same request while the answer is >= 500.
    for _ in range(3):
        response = await _post_bridge(neuron, target, request)
        if response.status_code < 500:
            break
    assert response.status_code == 200, response.text
    assert response.json()["receipt"] == _op_receipt(request["document"])
    assert len(dendrite.bodies) == 2
    sent = [SandboxOpsSynapseV1.model_validate_json(body) for body in dendrite.bodies]
    assert all(s.document == request["document"] for s in sent)
    assert all(s.payload_b64 == PAYLOAD for s in sent)


@pytest.mark.asyncio
async def test_validator_keeps_default_resends_for_lease_documents(tmp_path: Path) -> None:
    """Positive control: outside the ops route the production dendrite resend
    is unchanged, with the exact same body, and a 5xx never gains a hint."""

    renewals = "/api/v1/sandbox/renewals"
    neuron, dendrite, subnet = await _validator_with(
        tmp_path,
        renewals,
        [_refusal(503, "busy", "1"), _refusal(503, "busy", "1")],
    )
    request = {
        "protocol": "subnet-sandbox-synapse.v1",
        "request_id": "lease-upstream",
        "document": _document("renewals", MINER_A.hotkey, subnet),
    }
    response = await _post_bridge(neuron, f"/v1/miners/{MINER_A.hotkey}/sandbox-renewals", request)
    assert response.status_code == 502, response.text
    assert response.json()["error"]["code"] == "dendrite_upstream"
    assert "retry-after" not in response.headers
    assert len(dendrite.bodies) == neuron.dendrite_retries + 1
    assert all(body == dendrite.bodies[0] for body in dendrite.bodies)


# --------------------------------------------------------------------------
# Agent answers after dispatch (R23-PYGAP-01). An answer the agent sends after
# it may have executed the op must never reach the tenant as a 400. These run
# the real BridgeClient parser over an httpx.MockTransport at the neuron app
# boundary: no fake returns a typed model, and every agent dispatch is counted.
# --------------------------------------------------------------------------

AGENT_URL = "http://127.0.0.1:9101"
LEASE_ROUTE = "/api/v1/sandbox/leases"
ANSWER_INVALID = "sandbox_agent_answer_invalid"


def _agent(answer: Callable[[dict[str, Any]], bytes], status: int = 200) -> tuple[Any, list[str]]:
    """A real bridge client whose agent answers ``status`` with ``answer(request)``."""

    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        return httpx.Response(
            status,
            content=answer(json.loads(request.content)),
            headers={"Content-Type": "application/json"},
        )

    bridge = BridgeClient(AGENT_URL, b"x" * 32, retries=0, transport=httpx.MockTransport(handler))
    return bridge, seen


def _ops_reply(request: dict[str, Any], **changes: Any) -> bytes:
    reply = {
        "protocol": OPS,
        "request_id": request["request_id"],
        "receipt": _op_receipt(request["document"]),
        "result_b64": None,
        **changes,
    }
    return json.dumps(reply).encode()


def _lease_reply(request: dict[str, Any], **changes: Any) -> bytes:
    reply = {
        "protocol": SANDBOX,
        "request_id": request["request_id"],
        "receipt": _receipt(request["document"]),
        **changes,
    }
    return json.dumps(reply).encode()


# Answers the agent sends with status 200 after it has received the request.
# Each one fails SandboxOpsResponseV1 or SandboxResponseV1 validation.
BROKEN_OPS_ANSWERS: dict[str, Callable[[dict[str, Any]], bytes]] = {
    "malformed-json": lambda request: b"{not json",
    "extra-member": lambda request: _ops_reply(request, unexpected=True),
    "receipt-not-object": lambda request: _ops_reply(request, receipt="receipt"),
}
BROKEN_LEASE_ANSWERS: dict[str, Callable[[dict[str, Any]], bytes]] = {
    "malformed-json": lambda request: b"{not json",
    "extra-member": lambda request: _lease_reply(request, unexpected=True),
    "receipt-not-object": lambda request: _lease_reply(request, receipt="receipt"),
}


@pytest.mark.asyncio
@pytest.mark.parametrize("answer", list(BROKEN_OPS_ANSWERS))
async def test_op_answer_failing_validation_after_dispatch_is_unknown_not_a_400(
    tmp_path: Path, answer: str
) -> None:
    agent, seen = _agent(BROKEN_OPS_ANSWERS[answer])
    neuron, snapshot = await _neuron(tmp_path, agent, sandbox_leases=True, sandbox_ops=True)
    value = _ops_synapse(snapshot, _op(MINER.ss58_address, _miner_subnet(snapshot)))
    response = await _post_miner(neuron, ROUTE, value)
    # The agent may already have executed the op, so the answer is an upstream
    # failure (>= 500, possibly delivered), never a definitive refusal.
    assert response.status_code == 502, response.text
    assert response.json()["detail"] == ANSWER_INVALID
    assert seen == ["/v1/sandbox/ops"], "the op must be dispatched exactly once"
    assert neuron.ops_admission.active == 0, "the admission slot must be returned"


@pytest.mark.asyncio
@pytest.mark.parametrize("answer", list(BROKEN_LEASE_ANSWERS))
async def test_lease_answer_failing_validation_after_dispatch_is_unknown_not_a_400(
    tmp_path: Path, answer: str
) -> None:
    agent, seen = _agent(BROKEN_LEASE_ANSWERS[answer])
    neuron, snapshot = await _neuron(tmp_path, agent, sandbox_leases=True)
    document = _document("leases", MINER.ss58_address, _miner_subnet(snapshot))
    response = await _post_miner(
        neuron, LEASE_ROUTE, _synapse(snapshot, document, "subnet-sandbox-synapse.v1")
    )
    assert response.status_code == 502, response.text
    assert response.json()["detail"] == ANSWER_INVALID
    assert seen == ["/v1/sandbox/leases"], "the document must be dispatched exactly once"


@pytest.mark.asyncio
async def test_valid_op_answer_is_relayed_unchanged(tmp_path: Path) -> None:
    agent, seen = _agent(lambda request: _ops_reply(request))
    neuron, snapshot = await _neuron(tmp_path, agent, sandbox_leases=True, sandbox_ops=True)
    document = _op(MINER.ss58_address, _miner_subnet(snapshot))
    response = await _post_miner(neuron, ROUTE, _ops_synapse(snapshot, document))
    assert response.status_code == 200, response.text
    assert response.json()["receipt"] == _op_receipt(document)
    assert seen == ["/v1/sandbox/ops"]


@pytest.mark.asyncio
async def test_agent_refusal_of_an_op_keeps_its_status_and_code(tmp_path: Path) -> None:
    refusal = {"error": {"code": "sandbox_conflict", "message": "op refused", "retryable": False}}
    agent, seen = _agent(lambda _request: json.dumps(refusal).encode(), status=409)
    neuron, snapshot = await _neuron(tmp_path, agent, sandbox_leases=True, sandbox_ops=True)
    value = _ops_synapse(snapshot, _op(MINER.ss58_address, _miner_subnet(snapshot)))
    response = await _post_miner(neuron, ROUTE, value)
    assert response.status_code == 409, response.text
    assert response.json()["detail"] == "sandbox_conflict"
    assert seen == ["/v1/sandbox/ops"]


@pytest.mark.asyncio
async def test_malformed_inbound_op_is_refused_before_dispatch(tmp_path: Path) -> None:
    agent, seen = _agent(lambda request: _ops_reply(request))
    neuron, snapshot = await _neuron(tmp_path, agent, sandbox_leases=True, sandbox_ops=True)
    document = _op(MINER.ss58_address, _miner_subnet(snapshot))
    document["schema"] = LEASE_VECTORS["reservation"]["schema"]
    response = await _post_miner(neuron, ROUTE, _ops_synapse(snapshot, document))
    assert response.status_code == 422, response.text
    assert response.json()["detail"].startswith("sandbox_document_kind_mismatch")
    assert seen == []


def test_startup_refuses_ops_capacity_with_a_clean_exit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    secret = tmp_path / "secret"
    secret.write_bytes(b"s" * 32)
    peers = json.dumps([{"uri": "//Miner1", "uid": 1}])
    argv = [
        "misscomputer-miner",
        "--netuid",
        "24",
        "--bridge-secret-file",
        str(secret),
        "--state-db",
        str(tmp_path / "miner.db"),
        "--mock-uri",
        "//Miner1",
        "--mock-peers",
        peers,
        "--allow-insecure-mock-http",
        "--operator-hotkey",
        VALIDATOR.ss58_address,
        "--sandbox-leases",
        "on",
        "--sandbox-ops",
        "on",
        "--max-concurrency",
        "13",
    ]
    monkeypatch.setattr(sys, "argv", argv)
    # An accepted configuration must never reach a listener from this test.
    monkeypatch.setattr(miner.uvicorn, "run", lambda *_, **__: pytest.fail("server started"))
    with pytest.raises(SystemExit, match="ingress"):
        miner.main()
