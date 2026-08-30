# SPDX-License-Identifier: AGPL-3.0-only
"""Regressions for discovery-omission cleanup authority (PR #5 finding PR5-F1).

A transient capability-handshake failure removes a miner from the current
schedulable snapshot, while Go intentionally retains its Assigner for active
assignments. Exact ticket-bound deactivation must keep working through the
retained authenticated handle, without ever letting stale state authorize new
work or survive identity changes, metagraph disappearance, or binding expiry.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import HTTPException

from misscomputer_subnet.auth import BridgeError, bridge_headers, sign_service_binding
from misscomputer_subnet.chain import MetagraphSnapshot, MockChain, MockPeer
from misscomputer_subnet.protocol import (
    SYNAPSE_VERSION,
    CapabilitiesResponse,
    CapabilitiesSynapse,
    DeactivateResponse,
    DeactivateSynapse,
    MinerRegistration,
    ServiceKeyBinding,
    SubnetBinding,
)
from misscomputer_subnet.validator import (
    MAX_PERSISTED_PUBLICATIONS,
    RemoteMiner,
    ValidatorNeuron,
    _AmbiguousMinerRegistration,
    _miner_set_publication_id,
)

BRIDGE_SECRET = b"cleanup-regression-secret-32bytes!!"
SERVICE_KEY_HEX = "ab" * 32

VALIDATOR_PEER = MockPeer("//Validator", 0, None, True, 10_000)
MINER_A = MockPeer("//CleanupMinerA", 1, "http://miner-a:8091", False, 100)
MINER_B = MockPeer("//CleanupMinerB", 2, "http://miner-b:8091", False, 100)


class DendriteSim:
    """Deterministic miner axon simulator for the validator dendrite."""

    def __init__(self, peers: tuple[MockPeer, ...]) -> None:
        self.peers_by_host = {
            httpx.URL(peer.axon).host: peer for peer in peers if peer.axon is not None
        }
        self.failing: set[str] = set()
        self.service_keys: dict[str, str] = {}
        self.deactivations: list[tuple[str, str]] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        peer = self.peers_by_host.get(request.url.host)
        if peer is None:
            raise httpx.ConnectError("unknown axon host")
        if request.url.path == "/api/v1/capabilities":
            if peer.hotkey in self.failing:
                raise httpx.ConnectError("injected transient handshake failure")
            synapse = CapabilitiesSynapse.model_validate_json(request.content)
            binding = sign_service_binding(
                ServiceKeyBinding(
                    role="miner",
                    transport="http",
                    transport_certificate_sha256=None,
                    network=synapse.network,
                    netuid=synapse.netuid,
                    hotkey=peer.hotkey,
                    uid=peer.uid,
                    service_public_key=self.service_keys.get(peer.hotkey, SERVICE_KEY_HEX),
                    generation=1,
                    valid_from_block=synapse.chain_block,
                    expires_at_block=synapse.chain_block + 24,
                    challenge=synapse.challenge,
                ),
                peer.keypair,
            )
            response = CapabilitiesResponse(
                request_id=synapse.request_id,
                miner_hotkey=peer.hotkey,
                miner_uid=peer.uid,
                features=["scheduler"],
                max_body_bytes=1 << 20,
                service_binding=binding,
            )
            return httpx.Response(200, json=response.model_dump(mode="json"))
        if request.url.path == "/api/v1/deploy":
            # Reaching the axon at all proves the bridge identity gate
            # passed; a transport failure keeps the simulator minimal.
            return httpx.Response(500)
        if request.url.path == "/api/v1/deactivate":
            synapse = DeactivateSynapse.model_validate_json(request.content)
            self.deactivations.append((request.url.host, synapse.endpoint_id))
            return httpx.Response(
                200,
                json=DeactivateResponse(
                    request_id=synapse.request_id, status="deactivated"
                ).model_dump(mode="json"),
            )
        raise AssertionError(f"unexpected dendrite path {request.url.path}")


class RecordingBridge:
    async def request(
        self,
        method: str,
        path: str,
        *,
        value: Any | None = None,
        response_model: Any | None = None,
    ) -> Any:
        return {}


def make_harness(tmp_path: Path) -> tuple[ValidatorNeuron, MockChain, DendriteSim]:
    peers = (VALIDATOR_PEER, MINER_A, MINER_B)
    chain = MockChain(network="local", netuid=24, own_uri="//Validator", peers=peers)
    sim = DendriteSim(peers)
    neuron = ValidatorNeuron(
        chain=chain,
        hotkey_signer=chain.hotkey_signer,
        network="local",
        netuid=24,
        bridge=RecordingBridge(),  # type: ignore[arg-type]
        bridge_secret=BRIDGE_SECRET,
        state_db=str(tmp_path / "cleanup.db"),
        bridge_url="http://127.0.0.1:9200",
        sync_interval=1,
        dendrite_timeout=1,
        dendrite_retries=0,
        weight_interval=1,
        version_key=2,
        allow_private_axons=True,
        mock_http_axons=True,
        dendrite_transport=httpx.MockTransport(sim.handler),
    )
    return neuron, chain, sim


def validator_binding(
    chain: MockChain,
    snapshot: MetagraphSnapshot,
    *,
    service_public_key: str = SERVICE_KEY_HEX,
    generation: int | None = None,
    lifetime: int = 10_000,
) -> ServiceKeyBinding:
    return sign_service_binding(
        ServiceKeyBinding(
            role="validator",
            transport="local",
            transport_certificate_sha256=None,
            network="local",
            netuid=24,
            hotkey=chain.hotkey,
            uid=0,
            service_public_key=service_public_key,
            generation=snapshot.block + 1 if generation is None else generation,
            valid_from_block=snapshot.block,
            expires_at_block=snapshot.block + lifetime,
            challenge="validator-service:" + service_public_key,
        ),
        chain.hotkey_signer,
    )


async def refresh(
    neuron: ValidatorNeuron,
    chain: MockChain,
    sim: DendriteSim,
    failing: set[str] | None = None,
) -> Any:
    """Run one discovery cycle exactly as the block loop publishes it."""
    sim.failing = set(failing or set())
    snapshot = await chain.sync()
    await neuron.state.set(snapshot)
    neuron._validator_binding = validator_binding(chain, snapshot, generation=1)
    neuron.ready.set()
    discovered = await neuron._discover_miners(snapshot)
    async with neuron._lock:
        # Model the production publication transaction for direct helper tests.
        assert neuron._validator_binding is not None
        neuron._commit_miner_view_locked(
            snapshot,
            discovered,
            neuron._validator_binding,
            inventory_drain=False,
        )
    neuron.fully_synced.set()
    return snapshot


# Exact authenticated assignment identities as Go's retained Assigner
# handles carry them: (UID, normalized axon URL, service-key fingerprint).
IDENTITY_BY_HOTKEY = {
    MINER_A.hotkey: (MINER_A.uid, "http://miner-a:8091", SERVICE_KEY_HEX),
    MINER_B.hotkey: (MINER_B.uid, "http://miner-b:8091", SERVICE_KEY_HEX),
}


async def bridge_deactivate(
    neuron: ValidatorNeuron,
    hotkey: str,
    endpoint_id: str = "endpoint-1",
    *,
    uid: int | None = None,
    axon_url: str | None = None,
    service_key: str | None = None,
) -> httpx.Response:
    default_uid, default_axon, default_key = IDENTITY_BY_HOTKEY.get(
        hotkey, (0, "http://unknown:1", SERVICE_KEY_HEX)
    )
    body = json.dumps(
        {
            "protocol": SYNAPSE_VERSION,
            "request_id": endpoint_id,
            "endpoint_id": endpoint_id,
            "deployment_id": "cleanup-regression",
            "miner_hotkey": hotkey,
            "miner_uid": uid if uid is not None else default_uid,
            "axon_url": axon_url if axon_url is not None else default_axon,
            "miner_service_public_key": service_key if service_key is not None else default_key,
            "miner_transport": "http",
            "miner_tls_certificate_sha256": None,
        },
        separators=(",", ":"),
    ).encode()
    target = f"/v1/miners/{hotkey}/deactivate"
    headers = bridge_headers(BRIDGE_SECRET, method="POST", target=target, body=body)
    headers["Content-Type"] = "application/json"
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=neuron.app), base_url="http://bridge.local"
    ) as client:
        return await client.post(target, content=body, headers=headers)


@pytest.mark.asyncio
async def test_transiently_omitted_miner_still_supports_exact_cleanup(tmp_path: Path) -> None:
    """The exact CI sequence: discovery success, omission, health deactivation."""
    neuron, chain, sim = make_harness(tmp_path)
    await refresh(neuron, chain, sim)
    assert MINER_A.hotkey in neuron._miners

    await refresh(neuron, chain, sim, failing={MINER_A.hotkey})
    assert MINER_A.hotkey not in neuron._miners
    assert MINER_B.hotkey in neuron._miners

    # Omitted miners are not schedulable for new work.
    with pytest.raises(HTTPException) as denied:
        await neuron._remote(MINER_A.hotkey)
    assert denied.value.status_code == 404

    # But cleanup of an existing assignment still reaches the exact miner.
    response = await bridge_deactivate(neuron, MINER_A.hotkey, endpoint_id="assignment-a")
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "deactivated"
    assert sim.deactivations == [("miner-a", "assignment-a")]


@pytest.mark.asyncio
async def test_duplicate_axon_quarantine_preserves_exact_victim_cleanup(
    tmp_path: Path,
) -> None:
    neuron, chain, sim = make_harness(tmp_path)
    await refresh(neuron, chain, sim)

    # A third party copies the victim's public axon. Both records must be
    # quarantined for new scheduling, but the victim's unique hotkey/UID and
    # unchanged exact chain record still authorize its retained cleanup path.
    duplicate = MockPeer("//DuplicateAxon", 9, MINER_A.axon, False, 1)
    chain.peers = (VALIDATOR_PEER, MINER_A, MINER_B, duplicate)
    await refresh(neuron, chain, sim)
    assert MINER_A.hotkey not in neuron._miners
    assert duplicate.hotkey not in neuron._miners
    assert MINER_A.hotkey in neuron._cleanup_miners

    response = await bridge_deactivate(neuron, MINER_A.hotkey, endpoint_id="duplicate-axon-cleanup")
    assert response.status_code == 200, response.text
    assert sim.deactivations == [("miner-a", "duplicate-axon-cleanup")]


@pytest.mark.asyncio
async def test_validator_permit_flip_does_not_revoke_exact_cleanup(tmp_path: Path) -> None:
    neuron, chain, sim = make_harness(tmp_path)
    await refresh(neuron, chain, sim)

    permitted = MockPeer(MINER_A.uri, MINER_A.uid, MINER_A.axon, True, MINER_A.tao_stake)
    chain.peers = (VALIDATOR_PEER, permitted, MINER_B)
    await refresh(neuron, chain, sim, failing={MINER_A.hotkey})
    assert MINER_A.hotkey not in neuron._miners
    assert MINER_A.hotkey in neuron._cleanup_miners

    response = await bridge_deactivate(neuron, MINER_A.hotkey, "permit-flip-cleanup")
    assert response.status_code == 200, response.text
    assert sim.deactivations == [("miner-a", "permit-flip-cleanup")]


@pytest.mark.asyncio
async def test_repeated_omissions_then_recovery(tmp_path: Path) -> None:
    neuron, chain, sim = make_harness(tmp_path)
    await refresh(neuron, chain, sim)
    first_expiry = neuron._cleanup_miners[MINER_A.hotkey].binding.expires_at_block

    for attempt in range(2):
        await refresh(neuron, chain, sim, failing={MINER_A.hotkey})
        response = await bridge_deactivate(neuron, MINER_A.hotkey, f"assignment-{attempt}")
        assert response.status_code == 200, response.text

    await refresh(neuron, chain, sim)
    assert MINER_A.hotkey in neuron._miners
    assert neuron._cleanup_miners[MINER_A.hotkey].binding.expires_at_block > first_expiry
    response = await bridge_deactivate(neuron, MINER_A.hotkey, "assignment-final")
    assert response.status_code == 200, response.text
    assert [entry[0] for entry in sim.deactivations] == ["miner-a"] * 3


@pytest.mark.asyncio
async def test_discovery_publishes_atomically(tmp_path: Path) -> None:
    """Discovery must not mutate the schedulable map before the Go commit."""
    neuron, chain, sim = make_harness(tmp_path)
    await refresh(neuron, chain, sim)
    published = dict(neuron._miners)

    sim.failing = set()
    snapshot = await chain.sync()
    await neuron.state.set(snapshot)
    discovered = await neuron._discover_miners(snapshot)
    assert set(discovered) == {MINER_A.hotkey, MINER_B.hotkey}
    assert neuron._miners == published


@pytest.mark.asyncio
async def test_metagraph_disappearance_fails_closed(tmp_path: Path) -> None:
    neuron, chain, sim = make_harness(tmp_path)
    await refresh(neuron, chain, sim)
    retained = neuron._cleanup_miners[MINER_A.hotkey]

    chain.peers = (VALIDATOR_PEER, MINER_B)
    await refresh(neuron, chain, sim)
    response = await bridge_deactivate(neuron, MINER_A.hotkey)
    assert response.status_code == 404

    # Even a lingering handle cannot deactivate a deregistered identity.
    neuron._cleanup_miners[MINER_A.hotkey] = retained
    response = await bridge_deactivate(neuron, MINER_A.hotkey)
    assert response.status_code == 404
    assert sim.deactivations == []


@pytest.mark.asyncio
async def test_identity_change_fails_closed(tmp_path: Path) -> None:
    neuron, chain, sim = make_harness(tmp_path)
    await refresh(neuron, chain, sim)
    retained = neuron._cleanup_miners[MINER_A.hotkey]

    moved = MockPeer(MINER_A.uri, 9, MINER_A.axon, False, MINER_A.tao_stake)
    chain.peers = (VALIDATOR_PEER, moved, MINER_B)
    # The axon still answers with the previously bound UID, so the handshake
    # fails and pruning must drop the handle whose identity no longer matches.
    await refresh(neuron, chain, sim)
    assert MINER_A.hotkey not in neuron._cleanup_miners
    response = await bridge_deactivate(neuron, MINER_A.hotkey)
    assert response.status_code == 404

    neuron._cleanup_miners[MINER_A.hotkey] = retained
    response = await bridge_deactivate(neuron, MINER_A.hotkey)
    assert response.status_code == 403
    assert sim.deactivations == []


@pytest.mark.asyncio
async def test_axon_change_fails_closed(tmp_path: Path) -> None:
    neuron, chain, sim = make_harness(tmp_path)
    await refresh(neuron, chain, sim)
    retained = neuron._cleanup_miners[MINER_A.hotkey]

    moved = MockPeer(MINER_A.uri, MINER_A.uid, "http://miner-elsewhere:8091", False, 100)
    chain.peers = (VALIDATOR_PEER, moved, MINER_B)
    await refresh(neuron, chain, sim)
    assert MINER_A.hotkey not in neuron._cleanup_miners
    response = await bridge_deactivate(neuron, MINER_A.hotkey)
    assert response.status_code == 404

    neuron._cleanup_miners[MINER_A.hotkey] = retained
    response = await bridge_deactivate(neuron, MINER_A.hotkey)
    assert response.status_code == 403
    assert sim.deactivations == []


@pytest.mark.asyncio
@pytest.mark.parametrize("ambiguity", ["hotkey", "uid"])
async def test_duplicate_hotkey_or_uid_ambiguity_blocks_cleanup(
    tmp_path: Path, ambiguity: str
) -> None:
    neuron, chain, sim = make_harness(tmp_path)
    await refresh(neuron, chain, sim)
    retained = neuron._cleanup_miners[MINER_A.hotkey]

    if ambiguity == "hotkey":
        duplicate = MockPeer(MINER_A.uri, 9, "http://miner-a-shadow:8091", False, 1)
    else:
        duplicate = MockPeer("//DuplicateUID", MINER_A.uid, "http://uid-shadow:8091", False, 1)
    chain.peers = (VALIDATOR_PEER, MINER_A, MINER_B, duplicate)
    await refresh(neuron, chain, sim)
    assert MINER_A.hotkey not in neuron._cleanup_miners

    # A stale map entry cannot bypass current-chain ambiguity checks.
    neuron._cleanup_miners[MINER_A.hotkey] = retained
    response = await bridge_deactivate(neuron, MINER_A.hotkey, f"duplicate-{ambiguity}")
    assert response.status_code in {403, 409}
    assert sim.deactivations == []


@pytest.mark.asyncio
async def test_expired_binding_fails_closed(tmp_path: Path) -> None:
    neuron, chain, sim = make_harness(tmp_path)
    await refresh(neuron, chain, sim)
    retained = neuron._cleanup_miners[MINER_A.hotkey]

    chain.block += 10_000
    await refresh(neuron, chain, sim, failing={MINER_A.hotkey})
    assert MINER_A.hotkey not in neuron._cleanup_miners
    response = await bridge_deactivate(neuron, MINER_A.hotkey)
    assert response.status_code == 404

    neuron._cleanup_miners[MINER_A.hotkey] = retained
    response = await bridge_deactivate(neuron, MINER_A.hotkey)
    assert response.status_code == 409
    assert sim.deactivations == []


@pytest.mark.asyncio
async def test_invalid_retained_binding_signature_fails_closed(tmp_path: Path) -> None:
    neuron, chain, sim = make_harness(tmp_path)
    await refresh(neuron, chain, sim)
    retained = neuron._cleanup_miners[MINER_A.hotkey]
    tampered = RemoteMiner(
        neuron=retained.neuron,
        axon_url=retained.axon_url,
        binding=retained.binding.model_copy(update={"signature": "00" * 64}),
        certificate_der=None,
    )
    async with neuron._lock:
        neuron._miners[MINER_A.hotkey] = tampered
        neuron._cleanup_miners[MINER_A.hotkey] = tampered

    response = await bridge_deactivate(neuron, MINER_A.hotkey, "tampered-binding")
    assert response.status_code == 409
    assert sim.deactivations == []


@pytest.mark.asyncio
async def test_unknown_hotkey_cannot_be_cleaned_up(tmp_path: Path) -> None:
    neuron, chain, sim = make_harness(tmp_path)
    await refresh(neuron, chain, sim)
    response = await bridge_deactivate(neuron, VALIDATOR_PEER.hotkey)
    assert response.status_code == 404
    assert sim.deactivations == []


@pytest.mark.asyncio
async def test_same_hotkey_rebind_cannot_authorize_cleanup_of_old_assignment(
    tmp_path: Path,
) -> None:
    """PR5-SOL-F1: cleanup keyed only by hotkey could reach a rebound miner.

    After a successful same-hotkey rebind to a new UID/axon/service identity,
    a deactivation for the old assignment must fail closed instead of being
    delivered to the new miner, whose false "absent" answer would retire
    durable state while the old runtime remains.
    """
    neuron, chain, sim = make_harness(tmp_path)
    await refresh(neuron, chain, sim)

    rebound = MockPeer(MINER_A.uri, 9, "http://miner-a-rebound:8091", False, 100)
    rebound_key = "cd" * 32
    chain.peers = (VALIDATOR_PEER, rebound, MINER_B)
    sim.peers_by_host["miner-a-rebound"] = rebound
    sim.service_keys[rebound.hotkey] = rebound_key
    await refresh(neuron, chain, sim)

    # The rebound identity handshakes successfully and is fully published.
    assert neuron._miners[MINER_A.hotkey].neuron.uid == 9
    assert neuron._cleanup_miners[MINER_A.hotkey].neuron.uid == 9

    # Go's retained handle for the old assignment carries the old exact
    # identity; the new same-hotkey identity must never receive its cleanup.
    response = await bridge_deactivate(
        neuron,
        MINER_A.hotkey,
        endpoint_id="old-assignment",
        uid=MINER_A.uid,
        axon_url="http://miner-a:8091",
        service_key=SERVICE_KEY_HEX,
    )
    assert response.status_code == 403, response.text
    assert sim.deactivations == []

    # The rebound identity still cleans up its own assignments exactly.
    response = await bridge_deactivate(
        neuron,
        MINER_A.hotkey,
        endpoint_id="new-assignment",
        uid=9,
        axon_url="http://miner-a-rebound:8091",
        service_key=rebound_key,
    )
    assert response.status_code == 200, response.text
    assert sim.deactivations == [("miner-a-rebound", "new-assignment")]


@pytest.mark.asyncio
async def test_old_exact_handle_cleans_up_only_while_identity_still_authorized(
    tmp_path: Path,
) -> None:
    """The old exact identity keeps cleanup authority until the rebind lands."""
    neuron, chain, sim = make_harness(tmp_path)
    await refresh(neuron, chain, sim)
    response = await bridge_deactivate(
        neuron,
        MINER_A.hotkey,
        endpoint_id="pre-rebind",
        uid=MINER_A.uid,
        axon_url="http://miner-a:8091",
        service_key=SERVICE_KEY_HEX,
    )
    assert response.status_code == 200, response.text
    assert sim.deactivations == [("miner-a", "pre-rebind")]

    # A request whose identity differs from every capability-bound handle
    # fails closed even though the hotkey itself is bound.
    response = await bridge_deactivate(
        neuron,
        MINER_A.hotkey,
        endpoint_id="forged-identity",
        uid=MINER_A.uid,
        axon_url="http://miner-a:8091",
        service_key="ef" * 32,
    )
    assert response.status_code == 403
    assert sim.deactivations == [("miner-a", "pre-rebind")]


async def bridge_deploy(
    neuron: ValidatorNeuron,
    chain: MockChain,
    snapshot: Any,
    *,
    miner_axon_url: str | None,
    include_axon: bool = True,
) -> httpx.Response:
    subnet: dict[str, Any] = {
        "network": "local",
        "netuid": 24,
        "validator_hotkey": chain.hotkey,
        "miner_hotkey": MINER_A.hotkey,
        "miner_uid": MINER_A.uid,
        "miner_transport": "http",
        "miner_tls_certificate_sha256": None,
        "chain_block": snapshot.block,
        "epoch": snapshot.block // snapshot.tempo,
        "expires_at_block": snapshot.block + 12,
        "validator_service_public_key": SERVICE_KEY_HEX,
        "miner_service_public_key": SERVICE_KEY_HEX,
    }
    if include_axon:
        subnet["miner_axon_url"] = miner_axon_url
    body = json.dumps(
        {
            "protocol": SYNAPSE_VERSION,
            "request_id": "0123456789abcdef0123456789abcdef",
            "ticket": {
                "version": "deployment.v3",
                "deployment_id": "axon-binding",
                "generation": 1,
                "image_digest": "sha256:" + "a" * 64,
                "manifest_key": "v1/manifests/" + "a" * 64 + ".json",
                "miner_id": MINER_A.hotkey,
                "route_host": "axon-binding.mock.local",
                "assignment_nonce": "0123456789abcdef0123456789abcdef",
                "challenge_path": "/__challenge/axon-binding",
                "challenge_sha256": "b" * 64,
                "resources": {"cpu_millis": 1000, "memory_mb": 512, "disk_mb": 2048},
                "health": {
                    "path": "/healthz",
                    "expected_status": 200,
                    "interval_millis": 1000,
                    "timeout_millis": 3000,
                    "consecutive_failure": 2,
                },
                "issued_at": "2026-08-22T08:00:00Z",
                "expires_at": "2026-08-22T08:05:00Z",
                "subnet": subnet,
                "signature": "3" * 128,
            },
        },
        separators=(",", ":"),
    ).encode()
    target = f"/v1/miners/{MINER_A.hotkey}/deploy"
    headers = bridge_headers(BRIDGE_SECRET, method="POST", target=target, body=body)
    headers["Content-Type"] = "application/json"
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=neuron.app), base_url="http://bridge.local"
    ) as client:
        return await client.post(target, content=body, headers=headers)


def ticket_binding(chain: MockChain, snapshot: Any, remote: RemoteMiner) -> SubnetBinding:
    return SubnetBinding(
        network="local",
        netuid=24,
        validator_hotkey=chain.hotkey,
        miner_hotkey=remote.neuron.hotkey,
        miner_uid=remote.neuron.uid,
        miner_axon_url=remote.axon_url,
        miner_transport=remote.binding.transport,
        miner_tls_certificate_sha256=remote.binding.transport_certificate_sha256,
        chain_block=snapshot.block,
        epoch=snapshot.epoch,
        expires_at_block=snapshot.block + max(snapshot.tempo, 12),
        validator_service_public_key=SERVICE_KEY_HEX,
        miner_service_public_key=remote.binding.service_public_key,
    )


def historical_remotes(neuron: ValidatorNeuron, hotkey: str) -> list[RemoteMiner]:
    return [
        remote
        for publication in neuron._historical_publications
        for remote in (publication.miner(hotkey),)
        if remote is not None
    ]


def install_legacy_publication(database: Path, row: tuple[Any, ...]) -> None:
    with sqlite3.connect(database) as connection:
        connection.execute(
            """CREATE TABLE validator_publication_lanes (
            publication_id TEXT PRIMARY KEY,
            block INTEGER NOT NULL,
            authorized_expires_at_block INTEGER NOT NULL,
            committed INTEGER NOT NULL CHECK(committed IN (0, 1)),
            payload TEXT NOT NULL)"""
        )
        connection.execute(
            "INSERT INTO validator_publication_lanes VALUES(?,?,?,?,?)",
            row,
        )


def test_miner_set_publication_digest_matches_go_wire_identity() -> None:
    pin = "a" * 64
    registrations = [
        MinerRegistration.model_construct(
            hotkey=hotkey,
            uid=uid,
            axon_url=f"https://8.8.8.{uid}:8091",
            service_binding=ServiceKeyBinding.model_construct(
                service_public_key=service_digit * 64,
                transport="https",
                transport_certificate_sha256=pin,
            ),
        )
        for hotkey, uid, service_digit in (("two", 2, "2"), ("one", 1, "1"))
    ]
    assert (
        _miner_set_publication_id(100, registrations)
        == "4bcfe37e60c812d7e5248fb68bc31bba5f43fa00bcd26c31d56e4de070f33f81"
    )


@pytest.mark.asyncio
async def test_durable_publication_store_migrates_legacy_exact_rows(tmp_path: Path) -> None:
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    source, source_chain, source_sim = make_harness(source_dir)
    snapshot = await refresh(source, source_chain, source_sim)
    with sqlite3.connect(source_dir / "cleanup.db") as connection:
        legacy_row = connection.execute(
            """SELECT publication_id, block, authorized_expires_at_block,
            committed, payload FROM validator_publication_lanes"""
        ).fetchone()
    assert legacy_row is not None

    legacy_dir = tmp_path / "legacy"
    legacy_dir.mkdir()
    install_legacy_publication(legacy_dir / "cleanup.db", legacy_row)

    restarted, restarted_chain, _ = make_harness(legacy_dir)
    assert restarted._historical_publications == []
    assert set(restarted._quarantined_publications) == {legacy_row[0]}
    with sqlite3.connect(legacy_dir / "cleanup.db") as connection:
        columns = {
            row[1] for row in connection.execute("PRAGMA table_info(validator_publication_lanes)")
        }
        migrated = connection.execute(
            """SELECT schema_version, committed, drain_only,
            payload_sha256, record_mac, payload FROM validator_publication_lanes"""
        ).fetchone()
    assert {"schema_version", "drain_only", "payload_sha256", "record_mac"} <= columns
    assert migrated is not None
    assert migrated[:3] == (1, 1, 1)
    assert migrated[3] == hashlib.sha256(migrated[5].encode("ascii")).hexdigest()
    assert migrated[4] == ""

    registrations = source._stage_registrations(source._miners)

    class InventoryBridge:
        async def request(self, method: str, path: str, **_: Any) -> dict[str, Any]:
            assert method == "GET" and path == "/v1/miners"
            return {
                "protocol": SYNAPSE_VERSION,
                "block": snapshot.block,
                "ready": True,
                "publication_id": legacy_row[0],
                "miners": [item.model_dump(mode="json") for item in registrations],
            }

    restarted.bridge = InventoryBridge()  # type: ignore[assignment]
    await restarted.state.set(snapshot)
    restarted.ready.set()
    remote = source._miners[MINER_A.hotkey]
    resolved, _, _ = await restarted._remote_for_ticket(
        MINER_A.hotkey,
        ticket_binding(restarted_chain, snapshot, remote),
    )
    assert resolved.binding == remote.binding
    assert restarted._quarantined_publications == {}
    assert restarted._committed_publication is not None
    assert restarted._committed_publication.drain_only
    with sqlite3.connect(legacy_dir / "cleanup.db") as connection:
        authenticated = connection.execute(
            "SELECT committed, drain_only, record_mac FROM validator_publication_lanes"
        ).fetchone()
    assert authenticated is not None
    assert authenticated[:2] == (1, 1)
    assert len(authenticated[2]) == 64


@pytest.mark.asyncio
async def test_legacy_publication_remains_quarantined_when_inventory_is_unavailable(
    tmp_path: Path,
) -> None:
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    source, source_chain, source_sim = make_harness(source_dir)
    snapshot = await refresh(source, source_chain, source_sim)
    with sqlite3.connect(source_dir / "cleanup.db") as connection:
        legacy_row = connection.execute(
            """SELECT publication_id, block, authorized_expires_at_block,
            committed, payload FROM validator_publication_lanes"""
        ).fetchone()
    assert legacy_row is not None
    legacy_dir = tmp_path / "legacy"
    legacy_dir.mkdir()
    install_legacy_publication(legacy_dir / "cleanup.db", legacy_row)

    class UnavailableInventoryBridge:
        async def request(self, method: str, path: str, **_: Any) -> dict[str, Any]:
            assert method == "GET" and path == "/v1/miners"
            raise httpx.ConnectError("Go inventory is unavailable")

    restarted, restarted_chain, _ = make_harness(legacy_dir)
    restarted.bridge = UnavailableInventoryBridge()  # type: ignore[assignment]
    await restarted.state.set(snapshot)
    restarted.ready.set()
    remote = source._miners[MINER_A.hotkey]
    with pytest.raises(HTTPException) as denied:
        await restarted._remote_for_ticket(
            MINER_A.hotkey,
            ticket_binding(restarted_chain, snapshot, remote),
        )
    assert denied.value.status_code == 503
    assert restarted._historical_publications == []
    assert set(restarted._quarantined_publications) == {legacy_row[0]}


@pytest.mark.asyncio
async def test_durable_publication_checksum_corruption_fails_closed(tmp_path: Path) -> None:
    neuron, chain, sim = make_harness(tmp_path)
    await refresh(neuron, chain, sim)
    database = tmp_path / "cleanup.db"
    with sqlite3.connect(database) as connection:
        row = connection.execute(
            "SELECT publication_id, payload FROM validator_publication_lanes"
        ).fetchone()
        assert row is not None
        payload = json.loads(row[1])
        payload["snapshot"]["tempo"] += 1
        corrupted = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        connection.execute(
            "UPDATE validator_publication_lanes SET payload=? WHERE publication_id=?",
            (corrupted, row[0]),
        )

    with pytest.raises(RuntimeError, match="checksum"):
        make_harness(tmp_path)


@pytest.mark.asyncio
async def test_rechecks_durable_binding_signature_after_checksum_rewrite(tmp_path: Path) -> None:
    neuron, chain, sim = make_harness(tmp_path)
    await refresh(neuron, chain, sim)
    database = tmp_path / "cleanup.db"
    with sqlite3.connect(database) as connection:
        row = connection.execute(
            """SELECT publication_id, block, authorized_expires_at_block,
            committed, drain_only, payload FROM validator_publication_lanes"""
        ).fetchone()
        assert row is not None
        payload = json.loads(row[5])
        payload["validator_binding"]["signature"] = "00" * 64
        corrupted = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        connection.execute(
            "DELETE FROM validator_publication_lanes WHERE publication_id=?",
            (row[0],),
        )
    # Simulate a writer that possesses the local MAC key: service-binding
    # signatures remain an independent integrity layer.
    neuron._publication_store.save(
        publication_id=row[0],
        block=row[1],
        authorized_expires_at_block=row[2],
        payload=corrupted,
        committed=bool(row[3]),
        drain_only=bool(row[4]),
    )

    with pytest.raises(RuntimeError, match="binding signature"):
        make_harness(tmp_path)


@pytest.mark.asyncio
async def test_sol_005_r2_f1_committed_marker_tamper_cannot_promote_staged_lane(
    tmp_path: Path,
) -> None:
    """Fail-before regression: committed=0→1 previously bypassed reconciliation."""

    neuron, chain, _ = make_harness(tmp_path)
    snapshot = await chain.sync()
    await neuron.state.set(snapshot)
    binding = validator_binding(chain, snapshot)
    neuron._validator_binding = binding
    neuron.ready.set()
    miners = await neuron._discover_miners(snapshot)
    async with neuron._lock:
        staged = neuron._stage_publication_locked(snapshot, miners, binding)
    with sqlite3.connect(tmp_path / "cleanup.db") as connection:
        before = connection.execute(
            """SELECT committed, drain_only, record_mac
            FROM validator_publication_lanes WHERE publication_id=?""",
            (staged.publication_id,),
        ).fetchone()
        assert before is not None
        assert before[:2] == (0, 0)
        assert len(before[2]) == 64
        connection.execute(
            """UPDATE validator_publication_lanes SET committed=1
            WHERE publication_id=?""",
            (staged.publication_id,),
        )

    with pytest.raises(RuntimeError, match="record authenticator is invalid"):
        make_harness(tmp_path)


@pytest.mark.asyncio
async def test_sol_005_r2_f1_drain_marker_tamper_cannot_restore_new_work_authority(
    tmp_path: Path,
) -> None:
    """Fail-before regression: drain_only=1→0 was not covered by the checksum."""

    neuron, chain, sim = make_harness(tmp_path)
    retired_snapshot = await refresh(neuron, chain, sim)
    await refresh(neuron, chain, sim)
    with sqlite3.connect(tmp_path / "cleanup.db") as connection:
        retired = connection.execute(
            """SELECT publication_id, committed, drain_only, record_mac
            FROM validator_publication_lanes WHERE block=?""",
            (retired_snapshot.block,),
        ).fetchone()
        assert retired is not None
        assert retired[1:3] == (1, 1)
        assert len(retired[3]) == 64
        connection.execute(
            """UPDATE validator_publication_lanes SET drain_only=0
            WHERE publication_id=?""",
            (retired[0],),
        )

    with pytest.raises(RuntimeError, match="record authenticator is invalid"):
        make_harness(tmp_path)


@pytest.mark.asyncio
async def test_publication_record_mac_tracks_stage_commit_and_drain_transitions(
    tmp_path: Path,
) -> None:
    neuron, chain, sim = make_harness(tmp_path)
    original_snapshot = await refresh(neuron, chain, sim)
    original = neuron._committed_publication
    assert original is not None
    with sqlite3.connect(tmp_path / "cleanup.db") as connection:
        original_before = connection.execute(
            """SELECT committed, drain_only, record_mac
            FROM validator_publication_lanes WHERE publication_id=?""",
            (original.publication_id,),
        ).fetchone()
    assert original_before is not None
    assert original_before[:2] == (1, 0)
    assert len(original_before[2]) == 64

    next_snapshot = await chain.sync()
    assert next_snapshot.block > original_snapshot.block
    await neuron.state.set(next_snapshot)
    next_binding = validator_binding(chain, next_snapshot)
    miners = dict(neuron._miners)
    async with neuron._lock:
        staged = neuron._stage_publication_locked(next_snapshot, miners, next_binding)
    with sqlite3.connect(tmp_path / "cleanup.db") as connection:
        staged_before = connection.execute(
            """SELECT committed, drain_only, record_mac
            FROM validator_publication_lanes WHERE publication_id=?""",
            (staged.publication_id,),
        ).fetchone()
    assert staged_before is not None
    assert staged_before[:2] == (0, 0)
    assert len(staged_before[2]) == 64

    async with neuron._lock:
        neuron._commit_miner_view_locked(
            next_snapshot,
            miners,
            next_binding,
            inventory_drain=False,
            publication=staged,
        )
    with sqlite3.connect(tmp_path / "cleanup.db") as connection:
        original_after = connection.execute(
            """SELECT committed, drain_only, record_mac
            FROM validator_publication_lanes WHERE publication_id=?""",
            (original.publication_id,),
        ).fetchone()
        staged_after = connection.execute(
            """SELECT committed, drain_only, record_mac
            FROM validator_publication_lanes WHERE publication_id=?""",
            (staged.publication_id,),
        ).fetchone()
    assert original_after is not None
    assert original_after[:2] == (1, 1)
    assert original_after[2] != original_before[2]
    assert staged_after is not None
    assert staged_after[:2] == (1, 0)
    assert staged_after[2] != staged_before[2]

    restarted, _, _ = make_harness(tmp_path)
    assert restarted._quarantined_publications == {}
    assert {lane.publication_id for lane in restarted._historical_publications} == {
        original.publication_id,
        staged.publication_id,
    }


@pytest.mark.asyncio
async def test_publication_state_and_mac_transition_roll_back_as_one_transaction(
    tmp_path: Path,
) -> None:
    neuron, chain, sim = make_harness(tmp_path)
    await refresh(neuron, chain, sim)
    original = neuron._committed_publication
    assert original is not None
    next_snapshot = await chain.sync()
    await neuron.state.set(next_snapshot)
    next_binding = validator_binding(chain, next_snapshot)
    miners = dict(neuron._miners)
    async with neuron._lock:
        staged = neuron._stage_publication_locked(next_snapshot, miners, next_binding)

    def durable_state(publication_id: str) -> tuple[Any, ...]:
        with sqlite3.connect(tmp_path / "cleanup.db") as connection:
            row = connection.execute(
                """SELECT committed, drain_only, record_mac
                FROM validator_publication_lanes WHERE publication_id=?""",
                (publication_id,),
            ).fetchone()
        assert row is not None
        return row

    original_before = durable_state(original.publication_id)
    staged_before = durable_state(staged.publication_id)
    with sqlite3.connect(tmp_path / "cleanup.db") as connection:
        connection.execute(
            """CREATE TRIGGER reject_publication_drain_auth
            BEFORE UPDATE OF record_mac ON validator_publication_lanes
            WHEN OLD.drain_only=0 AND NEW.drain_only=1
            BEGIN
                SELECT RAISE(ABORT, 'injected drain authenticator failure');
            END"""
        )
    with pytest.raises(sqlite3.IntegrityError, match="injected drain authenticator failure"):
        async with neuron._lock:
            neuron._commit_miner_view_locked(
                next_snapshot,
                miners,
                next_binding,
                inventory_drain=False,
                publication=staged,
            )
    assert durable_state(original.publication_id) == original_before
    assert durable_state(staged.publication_id) == staged_before
    assert neuron._committed_publication is original
    assert neuron._staged_publication is staged

    with sqlite3.connect(tmp_path / "cleanup.db") as connection:
        connection.execute("DROP TRIGGER reject_publication_drain_auth")
    async with neuron._lock:
        neuron._commit_miner_view_locked(
            next_snapshot,
            miners,
            next_binding,
            inventory_drain=False,
            publication=staged,
        )
    assert durable_state(original.publication_id)[:2] == (1, 1)
    assert durable_state(staged.publication_id)[:2] == (1, 0)


def test_durable_publication_row_count_is_fail_closed_and_bounded(tmp_path: Path) -> None:
    make_harness(tmp_path)
    payload = "{}"
    payload_sha256 = hashlib.sha256(payload.encode("ascii")).hexdigest()
    rows = [
        (f"{index:064x}", 1, index, index + 1, 1, 1, payload_sha256, payload)
        for index in range(MAX_PERSISTED_PUBLICATIONS + 1)
    ]
    with sqlite3.connect(tmp_path / "cleanup.db") as connection:
        connection.executemany(
            """INSERT INTO validator_publication_lanes(
            publication_id, schema_version, block, authorized_expires_at_block,
            committed, drain_only, payload_sha256, payload) VALUES(?,?,?,?,?,?,?,?)""",
            rows,
        )
    with pytest.raises(RuntimeError, match="history exceeds"):
        make_harness(tmp_path)


@pytest.mark.asyncio
async def test_previous_publication_ticket_keeps_exact_tempo_snapshot_pair(
    tmp_path: Path,
) -> None:
    """SOL-005-R2-HISTORICAL-PAIR deterministic fail-before regression."""

    neuron, chain, sim = make_harness(tmp_path)
    seed = await chain.sync()
    old_snapshot = MetagraphSnapshot(
        network="local",
        netuid=24,
        block=1_787_558_681,
        tempo=12,
        neurons=seed.neurons,
        finalized=True,
    )
    await neuron.state.set(old_snapshot)
    old_validator_binding = validator_binding(chain, old_snapshot, lifetime=100)
    neuron._validator_binding = old_validator_binding
    neuron.ready.set()
    discovered = await neuron._discover_miners(old_snapshot)
    async with neuron._lock:
        neuron._commit_miner_view_locked(
            old_snapshot,
            discovered,
            old_validator_binding,
            inventory_drain=False,
        )

    # Renew only the coherent Go publication. The miner transport envelope is
    # intentionally unchanged while the exact snapshot tempo changes.
    new_snapshot = MetagraphSnapshot(
        network="local",
        netuid=24,
        block=1_787_558_682,
        tempo=13,
        neurons=seed.neurons,
        finalized=True,
    )
    await neuron.state.set(new_snapshot)
    new_validator_binding = validator_binding(chain, new_snapshot, lifetime=100)
    async with neuron._lock:
        neuron._validator_binding = new_validator_binding
        neuron._commit_miner_view_locked(
            new_snapshot,
            dict(discovered),
            new_validator_binding,
            inventory_drain=False,
        )

    # The old Go ticket remains unexpired and must reach the exact old miner.
    # The simulated miner deliberately answers 500, which the bridge maps to
    # 502. Pairing the old miner with the new tempo instead fails here with
    # HTTP 403 identity_mismatch: "Go ticket binding differs from handshake".
    response = await bridge_deploy(
        neuron,
        chain,
        old_snapshot,
        miner_axon_url="http://miner-a:8091",
    )
    assert response.status_code == 502, response.text


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["removed", "rebound"])
async def test_go_committed_ticket_uses_paired_snapshot_during_delayed_discovery(
    tmp_path: Path, change: str
) -> None:
    """Go's old committed ticket remains usable until exact publication ack."""

    neuron, chain, sim = make_harness(tmp_path)
    committed = await refresh(neuron, chain, sim)
    old = neuron._miners[MINER_A.hotkey]
    ticket = ticket_binding(chain, committed, old)

    if change == "removed":
        chain.peers = (VALIDATOR_PEER, MINER_B)
    else:
        rebound = MockPeer(MINER_A.uri, 9, "http://miner-a-rebound:8091", False, 100)
        chain.peers = (VALIDATOR_PEER, rebound, MINER_B)
    staged = await chain.sync()
    await neuron.state.set(staged)

    resolved, _, resolved_snapshot = await neuron._remote_for_ticket(MINER_A.hotkey, ticket)
    assert resolved is old
    assert resolved_snapshot is committed


@pytest.mark.asyncio
async def test_deploy_binds_signed_assignment_time_axon(tmp_path: Path) -> None:
    """PR5-SOL-F4: every delivered assignment pins its assignment-time axon.

    The bridge must only deliver work whose signed ticket names the exact
    handshake axon that will run it, so later exact-identity cleanup and
    restart recovery always have a provable assignment-time axon. Tickets
    naming another axon, or legacy tickets without the field, fail closed.
    """
    neuron, chain, sim = make_harness(tmp_path)
    snapshot = await refresh(neuron, chain, sim)

    # Control: the exact handshake axon passes the identity gate and reaches
    # the axon transport (the simulator then fails it deliberately).
    response = await bridge_deploy(neuron, chain, snapshot, miner_axon_url="http://miner-a:8091")
    assert response.status_code == 502, response.text

    # A ticket signed for a different axon must never be delivered here.
    response = await bridge_deploy(
        neuron, chain, snapshot, miner_axon_url="http://miner-elsewhere:8091"
    )
    assert response.status_code == 403, response.text

    # Legacy tickets without an assignment-time axon fail closed.
    response = await bridge_deploy(neuron, chain, snapshot, miner_axon_url=None, include_axon=False)
    assert response.status_code == 400, response.text


@pytest.mark.asyncio
async def test_concurrent_go_publication_resolves_ticket_from_python_stage(tmp_path: Path) -> None:
    """Go may issue the new ticket as soon as snapshot commit returns internally."""

    neuron, chain, sim = make_harness(tmp_path)
    snapshot = await refresh(neuron, chain, sim)
    staged = neuron._miners[MINER_A.hotkey]
    async with neuron._lock:
        neuron._stage_publication_locked(snapshot, {MINER_A.hotkey: staged})

    # A 502 proves the exact staged handle passed every bridge identity check
    # and reached the simulated miner, which intentionally returns HTTP 500.
    response = await bridge_deploy(neuron, chain, snapshot, miner_axon_url="http://miner-a:8091")
    assert response.status_code == 502, response.text


@pytest.mark.asyncio
async def test_ticket_reconciliation_can_commit_stage_before_post_response(
    tmp_path: Path,
) -> None:
    neuron, chain, sim = make_harness(tmp_path)
    await refresh(neuron, chain, sim)
    snapshot = await chain.sync()
    await neuron.state.set(snapshot)
    binding = validator_binding(chain, snapshot)
    miners = dict(neuron._miners)
    registrations = neuron._stage_registrations(miners)
    committed_inside_go = asyncio.Event()
    release_response = asyncio.Event()

    class CommitBeforeResponseBridge:
        async def request(self, method: str, path: str, **_: Any) -> dict[str, Any]:
            if method == "GET":
                assert path == "/v1/miners" and committed_inside_go.is_set()
                return {
                    "protocol": SYNAPSE_VERSION,
                    "block": snapshot.block,
                    "ready": True,
                    "publication_id": _miner_set_publication_id(snapshot.block, registrations),
                    "miners": [item.model_dump(mode="json") for item in registrations],
                }
            assert method == "POST" and path == "/v1/miners/snapshot"
            committed_inside_go.set()
            await release_response.wait()
            return {
                "protocol": SYNAPSE_VERSION,
                "status": "replaced",
                "block": snapshot.block,
                "miners": len(miners),
                "publication_id": _miner_set_publication_id(snapshot.block, registrations),
            }

    neuron.bridge = CommitBeforeResponseBridge()  # type: ignore[assignment]
    publication = asyncio.create_task(
        neuron._publish_miner_snapshot(
            snapshot,
            miners,
            validator_binding=binding,
        )
    )
    await committed_inside_go.wait()
    remote = miners[MINER_A.hotkey]
    try:
        resolved, resolved_binding, resolved_snapshot = await neuron._remote_for_ticket(
            MINER_A.hotkey,
            ticket_binding(chain, snapshot, remote),
        )
        assert resolved is remote
        assert resolved_binding == binding
        assert resolved_snapshot == snapshot
        assert neuron._staged_publication is None
    finally:
        release_response.set()
    await publication
    assert neuron._committed_publication is not None
    assert neuron._committed_publication.snapshot == snapshot
    with sqlite3.connect(tmp_path / "cleanup.db") as connection:
        states = connection.execute(
            "SELECT block, committed, drain_only FROM validator_publication_lanes ORDER BY block"
        ).fetchall()
    assert states[-1] == (snapshot.block, 1, 0)
    assert all(state[2] == 1 for state in states[:-1])


@pytest.mark.asyncio
async def test_concurrent_refreshes_keep_exact_validator_binding_and_tempo_pairs(
    tmp_path: Path,
) -> None:
    neuron, chain, sim = make_harness(tmp_path)
    original_snapshot = await refresh(neuron, chain, sim)
    original_remote = neuron._miners[MINER_A.hotkey]
    original_ticket = ticket_binding(chain, original_snapshot, original_remote)

    first_snapshot = MetagraphSnapshot(
        network="local",
        netuid=24,
        block=original_snapshot.block + 1,
        tempo=13,
        neurons=original_snapshot.neurons,
        finalized=True,
    )
    second_snapshot = MetagraphSnapshot(
        network="local",
        netuid=24,
        block=original_snapshot.block + 2,
        tempo=17,
        neurons=original_snapshot.neurons,
        finalized=True,
    )
    await neuron.state.set(first_snapshot)
    await neuron.state.set(second_snapshot)
    first_binding = validator_binding(chain, first_snapshot)
    second_binding = validator_binding(
        chain,
        second_snapshot,
        service_public_key="cd" * 32,
    )
    miners = dict(neuron._miners)
    first_post_entered = asyncio.Event()
    release_first_post = asyncio.Event()

    class OrderedAckBridge:
        def __init__(self) -> None:
            self.posts = 0

        async def request(self, method: str, path: str, **_: Any) -> dict[str, Any]:
            assert method == "POST" and path == "/v1/miners/snapshot"
            self.posts += 1
            if self.posts == 1:
                first_post_entered.set()
                await release_first_post.wait()
            lane = neuron._staged_publication
            assert lane is not None
            return {
                "protocol": SYNAPSE_VERSION,
                "status": "replaced",
                "block": lane.snapshot.block,
                "miners": len(lane.miners),
                "publication_id": lane.publication_id,
            }

    bridge = OrderedAckBridge()
    neuron.bridge = bridge  # type: ignore[assignment]
    first_publish = asyncio.create_task(
        neuron._publish_miner_snapshot(
            first_snapshot,
            miners,
            validator_binding=first_binding,
        )
    )
    await first_post_entered.wait()
    second_publish = asyncio.create_task(
        neuron._publish_miner_snapshot(
            second_snapshot,
            miners,
            validator_binding=second_binding,
        )
    )
    release_first_post.set()
    await asyncio.gather(first_publish, second_publish)
    assert bridge.posts == 2

    first_ticket = ticket_binding(chain, first_snapshot, original_remote)
    second_ticket = ticket_binding(chain, second_snapshot, original_remote).model_copy(
        update={"validator_service_public_key": second_binding.service_public_key}
    )
    old_result = await neuron._remote_for_ticket(MINER_A.hotkey, original_ticket)
    first_result = await neuron._remote_for_ticket(MINER_A.hotkey, first_ticket)
    second_result = await neuron._remote_for_ticket(MINER_A.hotkey, second_ticket)
    assert old_result[2] == original_snapshot
    assert first_result[1:] == (first_binding, first_snapshot)
    assert second_result[1:] == (second_binding, second_snapshot)

    mixed = first_ticket.model_copy(
        update={"validator_service_public_key": second_binding.service_public_key}
    )
    with pytest.raises(HTTPException) as rejected:
        await neuron._remote_for_ticket(MINER_A.hotkey, mixed)
    assert rejected.value.status_code == 403


@pytest.mark.asyncio
async def test_snapshot_acknowledgement_commits_or_rolls_back_stage_exactly(tmp_path: Path) -> None:
    neuron, chain, sim = make_harness(tmp_path)
    snapshot = await refresh(neuron, chain, sim)
    discovered = dict(neuron._miners)
    prior = {MINER_B.hotkey: discovered[MINER_B.hotkey]}
    async with neuron._lock:
        assert neuron._validator_binding is not None
        neuron._commit_miner_view_locked(
            snapshot,
            prior,
            neuron._validator_binding,
            inventory_drain=False,
        )

    class AckBridge:
        async def request(self, method: str, path: str, **_: Any) -> dict[str, Any]:
            assert method == "POST" and path == "/v1/miners/snapshot"
            assert neuron._staged_miners == discovered
            return {
                "protocol": SYNAPSE_VERSION,
                "status": "replaced",
                "block": snapshot.block,
                "miners": len(discovered),
                "publication_id": _miner_set_publication_id(
                    snapshot.block, neuron._stage_registrations(discovered)
                ),
            }

    neuron.bridge = AckBridge()  # type: ignore[assignment]
    await neuron._publish_miner_snapshot(snapshot, discovered)
    assert neuron._miners == discovered
    assert neuron._staged_miners is None

    class RejectBridge:
        async def request(self, method: str, path: str, **_: Any) -> dict[str, Any]:
            assert method == "POST" and path == "/v1/miners/snapshot"
            raise BridgeError("stale_miner_set", "rejected", False, 409)

    async with neuron._lock:
        assert neuron._validator_binding is not None
        neuron._commit_miner_view_locked(
            snapshot,
            prior,
            neuron._validator_binding,
            inventory_drain=False,
        )
    neuron.bridge = RejectBridge()  # type: ignore[assignment]
    with pytest.raises(BridgeError):
        await neuron._publish_miner_snapshot(snapshot, discovered)
    assert neuron._miners == prior
    assert neuron._staged_miners is None


@pytest.mark.asyncio
async def test_cancelled_snapshot_keeps_ticket_exact_stage_until_reconciliation(
    tmp_path: Path,
) -> None:
    neuron, chain, sim = make_harness(tmp_path)
    snapshot = await refresh(neuron, chain, sim)
    discovered = dict(neuron._miners)
    entered = asyncio.Event()

    class CancelBridge:
        async def request(self, method: str, path: str, **_: Any) -> dict[str, Any]:
            assert method == "POST" and path == "/v1/miners/snapshot"
            entered.set()
            await asyncio.Future()

    neuron.bridge = CancelBridge()  # type: ignore[assignment]
    publication = asyncio.create_task(neuron._publish_miner_snapshot(snapshot, discovered))
    await entered.wait()
    publication.cancel()
    with pytest.raises(asyncio.CancelledError):
        await publication
    assert neuron._staged_miners == discovered
    remote = discovered[MINER_A.hotkey]
    ticket = ticket_binding(chain, snapshot, remote)
    resolved, _, _ = await neuron._remote_for_ticket(MINER_A.hotkey, ticket)
    assert resolved is remote


@pytest.mark.asyncio
async def test_cancelled_removal_publication_keeps_both_possible_go_ticket_lanes(
    tmp_path: Path,
) -> None:
    neuron, chain, sim = make_harness(tmp_path)
    committed = await refresh(neuron, chain, sim)
    removed = neuron._miners[MINER_A.hotkey]
    old_ticket = ticket_binding(chain, committed, removed)

    chain.peers = (VALIDATOR_PEER, MINER_B)
    staged_snapshot = await chain.sync()
    await neuron.state.set(staged_snapshot)
    staged = await neuron._discover_miners(staged_snapshot)
    entered = asyncio.Event()

    class CancelBridge:
        async def request(self, method: str, path: str, **_: Any) -> dict[str, Any]:
            assert method == "POST" and path == "/v1/miners/snapshot"
            entered.set()
            await asyncio.Future()

    neuron.bridge = CancelBridge()  # type: ignore[assignment]
    publication = asyncio.create_task(neuron._publish_miner_snapshot(staged_snapshot, staged))
    await entered.wait()

    # Before and after cancellation, Python cannot know whether Go committed
    # before its response was lost. The exact old committed and new staged
    # lanes must therefore remain independently usable.
    old_resolved, _, old_snapshot = await neuron._remote_for_ticket(MINER_A.hotkey, old_ticket)
    assert old_resolved is removed
    assert old_snapshot is committed
    new_remote = staged[MINER_B.hotkey]
    new_resolved, _, new_snapshot = await neuron._remote_for_ticket(
        MINER_B.hotkey, ticket_binding(chain, staged_snapshot, new_remote)
    )
    assert new_resolved is new_remote
    assert new_snapshot is staged_snapshot

    publication.cancel()
    with pytest.raises(asyncio.CancelledError):
        await publication
    old_resolved, _, old_snapshot = await neuron._remote_for_ticket(MINER_A.hotkey, old_ticket)
    assert old_resolved is removed
    assert old_snapshot is committed


@pytest.mark.asyncio
async def test_rejected_removal_publication_rolls_back_to_exact_committed_view(
    tmp_path: Path,
) -> None:
    neuron, chain, sim = make_harness(tmp_path)
    committed = await refresh(neuron, chain, sim)
    removed = neuron._miners[MINER_A.hotkey]
    old_ticket = ticket_binding(chain, committed, removed)
    committed_miners = neuron._miners

    chain.peers = (VALIDATOR_PEER, MINER_B)
    staged_snapshot = await chain.sync()
    await neuron.state.set(staged_snapshot)
    staged = await neuron._discover_miners(staged_snapshot)

    class RejectBridge:
        async def request(self, method: str, path: str, **_: Any) -> dict[str, Any]:
            assert method == "POST" and path == "/v1/miners/snapshot"
            raise BridgeError("stale_miner_set", "rejected", False, 409)

    neuron.bridge = RejectBridge()  # type: ignore[assignment]
    with pytest.raises(BridgeError):
        await neuron._publish_miner_snapshot(staged_snapshot, staged)
    assert neuron._miners is committed_miners
    assert neuron._committed_snapshot is committed
    assert neuron._staged_miners is None
    assert neuron._staged_snapshot is None
    resolved, _, resolved_snapshot = await neuron._remote_for_ticket(MINER_A.hotkey, old_ticket)
    assert resolved is removed
    assert resolved_snapshot is committed


@pytest.mark.asyncio
async def test_python_restart_reconciles_exact_go_committed_handle(tmp_path: Path) -> None:
    neuron, chain, sim = make_harness(tmp_path)
    snapshot = await refresh(neuron, chain, sim)
    remotes = dict(neuron._miners)
    rebuilt = {
        hotkey: RemoteMiner(
            neuron=remote.neuron,
            axon_url=remote.axon_url,
            binding=remote.binding.model_copy(
                update={
                    "generation": remote.binding.generation + 1,
                    "valid_from_block": snapshot.block + 1,
                    "expires_at_block": remote.binding.expires_at_block + 1,
                }
            ),
            certificate_der=remote.certificate_der,
        )
        for hotkey, remote in remotes.items()
    }
    registrations = neuron._stage_registrations(remotes)

    class InventoryBridge:
        async def request(self, method: str, path: str, **_: Any) -> dict[str, Any]:
            assert method == "GET" and path == "/v1/miners"
            return {
                "protocol": SYNAPSE_VERSION,
                "block": snapshot.block,
                "ready": True,
                "publication_id": _miner_set_publication_id(snapshot.block, registrations),
                "miners": [registration.model_dump(mode="json") for registration in registrations],
            }

    # Construct a fresh Python neuron over the same durable state DB while Go
    # retains its exact committed inventory.
    restarted, restarted_chain, _ = make_harness(tmp_path)
    restarted.bridge = InventoryBridge()  # type: ignore[assignment]
    await restarted.state.set(snapshot)
    restarted.ready.set()
    restarted._cleanup_miners = rebuilt
    ticket = ticket_binding(restarted_chain, snapshot, remotes[MINER_A.hotkey])
    resolved, _, _ = await restarted._remote_for_ticket(MINER_A.hotkey, ticket)
    assert resolved.binding == remotes[MINER_A.hotkey].binding
    assert restarted._miners[MINER_A.hotkey].binding == remotes[MINER_A.hotkey].binding
    assert restarted._committed_snapshot == snapshot
    assert restarted._committed_validator_binding == neuron._committed_validator_binding
    assert restarted._inventory_committed_handles == {
        id(remote) for remote in restarted._miners.values()
    }


@pytest.mark.asyncio
async def test_restart_reconciles_current_without_losing_exact_historical_pair(
    tmp_path: Path,
) -> None:
    neuron, chain, sim = make_harness(tmp_path)
    old_snapshot = await refresh(neuron, chain, sim)
    old_remote = neuron._miners[MINER_A.hotkey]
    old_ticket = ticket_binding(chain, old_snapshot, old_remote)

    new_snapshot = MetagraphSnapshot(
        network="local",
        netuid=24,
        block=old_snapshot.block + 1,
        tempo=19,
        neurons=old_snapshot.neurons,
        finalized=True,
    )
    await neuron.state.set(new_snapshot)
    new_binding = validator_binding(
        chain,
        new_snapshot,
        service_public_key="ef" * 32,
    )
    new_miners = dict(neuron._miners)
    async with neuron._lock:
        neuron._commit_miner_view_locked(
            new_snapshot,
            new_miners,
            new_binding,
            inventory_drain=False,
        )
    registrations = neuron._stage_registrations(new_miners)

    class InventoryBridge:
        async def request(self, method: str, path: str, **_: Any) -> dict[str, Any]:
            assert method == "GET" and path == "/v1/miners"
            return {
                "protocol": SYNAPSE_VERSION,
                "block": new_snapshot.block,
                "ready": True,
                "publication_id": _miner_set_publication_id(new_snapshot.block, registrations),
                "miners": [registration.model_dump(mode="json") for registration in registrations],
            }

    restarted, _, _ = make_harness(tmp_path)
    restarted.bridge = InventoryBridge()  # type: ignore[assignment]
    await restarted.state.set(new_snapshot)
    restarted.ready.set()
    old_result = await restarted._remote_for_ticket(MINER_A.hotkey, old_ticket)
    assert old_result[0].binding == old_remote.binding
    assert old_result[1] == neuron._historical_publications[0].validator_binding
    assert old_result[2] == old_snapshot

    new_ticket = ticket_binding(chain, new_snapshot, new_miners[MINER_A.hotkey]).model_copy(
        update={"validator_service_public_key": new_binding.service_public_key}
    )
    new_result = await restarted._remote_for_ticket(MINER_A.hotkey, new_ticket)
    assert new_result[1:] == (new_binding, new_snapshot)
    assert restarted._committed_publication is not None
    assert restarted._committed_publication.drain_only


@pytest.mark.asyncio
async def test_removal_ack_drains_exact_old_inflight_ticket(tmp_path: Path) -> None:
    neuron, chain, sim = make_harness(tmp_path)
    snapshot = await refresh(neuron, chain, sim)
    removed = neuron._miners[MINER_A.hotkey]
    discovered = {MINER_B.hotkey: neuron._miners[MINER_B.hotkey]}

    class AckBridge:
        async def request(self, method: str, path: str, **_: Any) -> dict[str, Any]:
            assert method == "POST" and path == "/v1/miners/snapshot"
            return {
                "block": snapshot.block,
                "miners": len(discovered),
                "publication_id": _miner_set_publication_id(
                    snapshot.block, neuron._stage_registrations(discovered)
                ),
            }

    neuron.bridge = AckBridge()  # type: ignore[assignment]
    await neuron._publish_miner_snapshot(snapshot, discovered)
    assert MINER_A.hotkey not in neuron._miners
    assert historical_remotes(neuron, MINER_A.hotkey) == [removed]
    resolved, _, _ = await neuron._remote_for_ticket(
        MINER_A.hotkey, ticket_binding(chain, snapshot, removed)
    )
    assert resolved is removed


@pytest.mark.asyncio
async def test_replaced_empty_publication_is_retained_as_an_exact_lane(tmp_path: Path) -> None:
    neuron, chain, sim = make_harness(tmp_path)
    original = await refresh(neuron, chain, sim)
    first_empty = MetagraphSnapshot(
        network="local",
        netuid=24,
        block=original.block + 1,
        tempo=12,
        neurons=original.neurons,
        finalized=True,
    )
    second_empty = MetagraphSnapshot(
        network="local",
        netuid=24,
        block=original.block + 2,
        tempo=12,
        neurons=original.neurons,
        finalized=True,
    )
    first_binding = validator_binding(chain, first_empty)
    second_binding = validator_binding(chain, second_empty)
    async with neuron._lock:
        neuron._commit_miner_view_locked(
            first_empty,
            {},
            first_binding,
            inventory_drain=False,
        )
        neuron._commit_miner_view_locked(
            second_empty,
            {},
            second_binding,
            inventory_drain=False,
        )
    retained = [
        publication
        for publication in neuron._historical_publications
        if publication.snapshot.block == first_empty.block
    ]
    assert len(retained) == 1
    assert retained[0].miners == ()
    assert retained[0].drain_only
    with sqlite3.connect(tmp_path / "cleanup.db") as connection:
        durable = connection.execute(
            """SELECT committed, drain_only FROM validator_publication_lanes
            WHERE block=?""",
            (first_empty.block,),
        ).fetchone()
    assert durable == (1, 1)


@pytest.mark.asyncio
async def test_rotation_ack_resolves_old_and_new_ticket_to_exact_handle(tmp_path: Path) -> None:
    neuron, chain, sim = make_harness(tmp_path)
    snapshot = await refresh(neuron, chain, sim)
    old = neuron._miners[MINER_A.hotkey]
    rotated = RemoteMiner(
        neuron=old.neuron,
        axon_url=old.axon_url,
        binding=old.binding.model_copy(
            update={"service_public_key": "cd" * 32, "generation": old.binding.generation + 1}
        ),
        certificate_der=old.certificate_der,
    )
    discovered = dict(neuron._miners)
    discovered[MINER_A.hotkey] = rotated

    class AckBridge:
        async def request(self, method: str, path: str, **_: Any) -> dict[str, Any]:
            assert method == "POST" and path == "/v1/miners/snapshot"
            return {
                "block": snapshot.block,
                "miners": len(discovered),
                "publication_id": _miner_set_publication_id(
                    snapshot.block, neuron._stage_registrations(discovered)
                ),
            }

    neuron.bridge = AckBridge()  # type: ignore[assignment]
    await neuron._publish_miner_snapshot(snapshot, discovered)
    old_resolved, _, _ = await neuron._remote_for_ticket(
        MINER_A.hotkey, ticket_binding(chain, snapshot, old)
    )
    new_resolved, _, _ = await neuron._remote_for_ticket(
        MINER_A.hotkey, ticket_binding(chain, snapshot, rotated)
    )
    assert old_resolved is old
    assert new_resolved is rotated


@pytest.mark.asyncio
async def test_chain_rebind_ack_atomically_retires_old_identity_and_commits_new(
    tmp_path: Path,
) -> None:
    neuron, chain, sim = make_harness(tmp_path)
    committed = await refresh(neuron, chain, sim)
    old = neuron._miners[MINER_A.hotkey]
    old_ticket = ticket_binding(chain, committed, old)

    rebound_peer = MockPeer(MINER_A.uri, 9, "http://miner-a-rebound:8091", False, 100)
    chain.peers = (VALIDATOR_PEER, rebound_peer, MINER_B)
    staged_snapshot = await chain.sync()
    await neuron.state.set(staged_snapshot)
    rebound_record = staged_snapshot.by_hotkey(MINER_A.hotkey)
    assert rebound_record is not None
    rebound = RemoteMiner(
        neuron=rebound_record,
        axon_url=rebound_record.axon or "",
        binding=old.binding.model_copy(
            update={
                "uid": rebound_record.uid,
                "service_public_key": "ef" * 32,
                "generation": old.binding.generation + 1,
                "valid_from_block": staged_snapshot.block,
                "expires_at_block": staged_snapshot.block + 24,
            }
        ),
        certificate_der=None,
    )
    staged = {MINER_B.hotkey: neuron._miners[MINER_B.hotkey], MINER_A.hotkey: rebound}

    class AckBridge:
        async def request(self, method: str, path: str, **_: Any) -> dict[str, Any]:
            assert method == "POST" and path == "/v1/miners/snapshot"
            return {
                "block": staged_snapshot.block,
                "miners": len(staged),
                "publication_id": _miner_set_publication_id(
                    staged_snapshot.block, neuron._stage_registrations(staged)
                ),
            }

    neuron.bridge = AckBridge()  # type: ignore[assignment]
    await neuron._publish_miner_snapshot(staged_snapshot, staged)
    assert neuron._committed_snapshot is staged_snapshot
    assert neuron._miners[MINER_A.hotkey] is rebound
    assert historical_remotes(neuron, MINER_A.hotkey) == [old]

    old_resolved, _, old_snapshot = await neuron._remote_for_ticket(MINER_A.hotkey, old_ticket)
    new_resolved, _, new_snapshot = await neuron._remote_for_ticket(
        MINER_A.hotkey, ticket_binding(chain, staged_snapshot, rebound)
    )
    assert old_resolved is old
    assert old_snapshot is committed
    assert new_resolved is rebound
    assert new_snapshot is staged_snapshot


@pytest.mark.asyncio
async def test_recovery_prefers_fresh_handle_over_expired_published(tmp_path: Path) -> None:
    """PR5-SOL-F2: an expired published handle must not shadow a fresh one.

    After a long Go/control outage the published schedulable map still holds
    an expired handle, while the in-flight discovery cycle has already
    completed a fresh successful handshake for the exact same identity.
    Registration-time recovery cleanup must use the fresh valid handle rather
    than looping on binding expiry, without weakening fail-closed checks.
    """
    neuron, chain, sim = make_harness(tmp_path)
    await refresh(neuron, chain, sim)
    stale = neuron._miners[MINER_A.hotkey]

    # Long outage: blocks advance far past the published binding expiry while
    # the schedulable map cannot be replaced (Go never commits a snapshot).
    chain.block += 10_000
    snapshot = await chain.sync()
    await neuron.state.set(snapshot)
    assert snapshot.block >= stale.binding.expires_at_block

    # Mid-recovery discovery: fresh handshakes refreshed the retained cleanup
    # handles, but Go has not yet committed the matching miner snapshot, so
    # the published map still holds the expired handle.
    discovered = await neuron._discover_miners(snapshot)
    assert MINER_A.hotkey in discovered
    assert neuron._miners[MINER_A.hotkey] is stale
    fresh = neuron._cleanup_miners[MINER_A.hotkey]
    assert snapshot.block < fresh.binding.expires_at_block

    response = await bridge_deactivate(neuron, MINER_A.hotkey, "recovered-assignment")
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "deactivated"
    assert sim.deactivations == [("miner-a", "recovered-assignment")]

    # The preference never weakens fail-closed expiry: with no fresh handle,
    # the same identity is still rejected as expired.
    sim.deactivations.clear()
    async with neuron._lock:
        neuron._cleanup_miners[MINER_A.hotkey] = stale
    response = await bridge_deactivate(neuron, MINER_A.hotkey, "expired-only")
    assert response.status_code == 409
    assert sim.deactivations == []


@pytest.mark.asyncio
async def test_same_transport_binding_refresh_drains_each_exact_window(
    tmp_path: Path,
) -> None:
    neuron, chain, sim = make_harness(tmp_path)
    first_snapshot = await refresh(neuron, chain, sim)
    first = neuron._miners[MINER_A.hotkey]
    first_ticket = ticket_binding(chain, first_snapshot, first)

    second_snapshot = await chain.sync()
    await neuron.state.set(second_snapshot)
    second = RemoteMiner(
        neuron=first.neuron,
        axon_url=first.axon_url,
        binding=first.binding.model_copy(
            update={
                "generation": first.binding.generation + 1,
                "valid_from_block": second_snapshot.block,
                "expires_at_block": second_snapshot.block + 24,
            }
        ),
        certificate_der=first.certificate_der,
    )
    second_miners = dict(neuron._miners)
    second_miners[MINER_A.hotkey] = second
    async with neuron._lock:
        assert neuron._validator_binding is not None
        neuron._commit_miner_view_locked(
            second_snapshot,
            second_miners,
            neuron._validator_binding,
            inventory_drain=False,
        )

    # The new handshake has the same hotkey/UID/axon/key/pin, but its envelope
    # begins one block later. The Go ticket issued from the previous publication
    # must resolve through that exact historical binding, never the fresh one.
    resolved, _, _ = await neuron._remote_for_ticket(MINER_A.hotkey, first_ticket)
    assert resolved is first
    assert historical_remotes(neuron, MINER_A.hotkey) == [first]

    second_ticket = ticket_binding(chain, second_snapshot, second)
    third_snapshot = await chain.sync()
    await neuron.state.set(third_snapshot)
    third = RemoteMiner(
        neuron=second.neuron,
        axon_url=second.axon_url,
        binding=second.binding.model_copy(
            update={
                "generation": second.binding.generation + 1,
                "valid_from_block": third_snapshot.block,
                "expires_at_block": third_snapshot.block + 24,
            }
        ),
        certificate_der=second.certificate_der,
    )
    third_miners = dict(second_miners)
    third_miners[MINER_A.hotkey] = third
    async with neuron._lock:
        assert neuron._validator_binding is not None
        neuron._commit_miner_view_locked(
            third_snapshot,
            third_miners,
            neuron._validator_binding,
            inventory_drain=False,
        )
    assert (await neuron._remote_for_ticket(MINER_A.hotkey, first_ticket))[0] is first
    assert (await neuron._remote_for_ticket(MINER_A.hotkey, second_ticket))[0] is second

    # Drain authority ends at the exact Go-authorized ticket window. A later
    # commit prunes all expired historical lane objects.
    chain.block = first_ticket.expires_at_block - 1
    expired_snapshot = await chain.sync()
    await neuron.state.set(expired_snapshot)
    with pytest.raises(HTTPException) as expired:
        await neuron._remote_for_ticket(MINER_A.hotkey, first_ticket)
    assert expired.value.status_code == 409
    async with neuron._lock:
        assert neuron._validator_binding is not None
        neuron._commit_miner_view_locked(
            expired_snapshot,
            third_miners,
            neuron._validator_binding,
            inventory_drain=False,
        )
    assert all(
        publication.authorized_expires_at_block > expired_snapshot.block
        for publication in neuron._historical_publications
    )


@pytest.mark.asyncio
async def test_ambiguous_publication_is_reconciled_before_later_supersede(
    tmp_path: Path,
) -> None:
    neuron, chain, sim = make_harness(tmp_path)
    await refresh(neuron, chain, sim)
    original = neuron._miners[MINER_A.hotkey]

    first_snapshot = await chain.sync()
    await neuron.state.set(first_snapshot)
    first = RemoteMiner(
        neuron=original.neuron,
        axon_url=original.axon_url,
        binding=original.binding.model_copy(
            update={
                "service_public_key": "cd" * 32,
                "generation": original.binding.generation + 1,
                "valid_from_block": first_snapshot.block,
                "expires_at_block": first_snapshot.block + 24,
            }
        ),
        certificate_der=original.certificate_der,
    )
    first_stage = dict(neuron._miners)
    first_stage[MINER_A.hotkey] = first
    first_registrations = neuron._stage_registrations(first_stage)
    first_ticket = ticket_binding(chain, first_snapshot, first)

    second_snapshot = await chain.sync()
    await neuron.state.set(second_snapshot)
    second = RemoteMiner(
        neuron=original.neuron,
        axon_url=original.axon_url,
        binding=first.binding.model_copy(
            update={
                "service_public_key": "ef" * 32,
                "generation": first.binding.generation + 1,
                "valid_from_block": second_snapshot.block,
                "expires_at_block": second_snapshot.block + 24,
            }
        ),
        certificate_der=original.certificate_der,
    )
    second_stage = dict(first_stage)
    second_stage[MINER_A.hotkey] = second

    class LostThenRecoveredBridge:
        def __init__(self) -> None:
            self.posts = 0
            self.gets = 0

        async def request(self, method: str, path: str, **_: Any) -> dict[str, Any]:
            if method == "GET" and path == "/v1/miners":
                self.gets += 1
                if self.gets == 1:
                    raise httpx.ConnectError("inventory temporarily unavailable")
                return {
                    "protocol": SYNAPSE_VERSION,
                    "block": first_snapshot.block,
                    "ready": True,
                    "publication_id": _miner_set_publication_id(
                        first_snapshot.block, first_registrations
                    ),
                    "miners": [
                        registration.model_dump(mode="json") for registration in first_registrations
                    ],
                }
            assert method == "POST" and path == "/v1/miners/snapshot"
            self.posts += 1
            if self.posts == 1:
                raise httpx.ReadTimeout("publication response was lost")
            return {
                "protocol": SYNAPSE_VERSION,
                "status": "replaced",
                "block": second_snapshot.block,
                "miners": len(second_stage),
                "publication_id": _miner_set_publication_id(
                    second_snapshot.block, neuron._stage_registrations(second_stage)
                ),
            }

    bridge = LostThenRecoveredBridge()
    neuron.bridge = bridge  # type: ignore[assignment]
    with pytest.raises(_AmbiguousMinerRegistration):
        await neuron._publish_miner_snapshot(first_snapshot, first_stage)
    assert neuron._staged_miners == first_stage
    assert (await neuron._remote_for_ticket(MINER_A.hotkey, first_ticket))[0] is first

    # Before staging the later publication, Python must digest-reconcile the
    # unresolved lane. If Go committed it, the lane becomes a paired committed
    # view and then an exact drain lane when the next publication succeeds.
    await neuron._publish_miner_snapshot(second_snapshot, second_stage)
    assert bridge.gets == 2
    assert neuron._miners[MINER_A.hotkey] is second
    assert (await neuron._remote_for_ticket(MINER_A.hotkey, first_ticket))[0] is first
    assert first in historical_remotes(neuron, MINER_A.hotkey)
    assert neuron._staged_miners is None

    chain.block = first_ticket.expires_at_block - 1
    expired_snapshot = await chain.sync()
    await neuron.state.set(expired_snapshot)
    with pytest.raises(HTTPException) as expired:
        await neuron._remote_for_ticket(MINER_A.hotkey, first_ticket)
    assert expired.value.status_code == 409
    async with neuron._lock:
        assert neuron._validator_binding is not None
        neuron._commit_miner_view_locked(
            expired_snapshot,
            second_stage,
            neuron._validator_binding,
            inventory_drain=False,
        )
    with pytest.raises(HTTPException) as pruned:
        await neuron._remote_for_ticket(MINER_A.hotkey, first_ticket)
    assert pruned.value.status_code == 403
    assert first not in historical_remotes(neuron, MINER_A.hotkey)


@pytest.mark.asyncio
async def test_lost_publication_response_rolls_back_only_to_exact_prior_digest(
    tmp_path: Path,
) -> None:
    neuron, chain, sim = make_harness(tmp_path)
    committed_snapshot = await refresh(neuron, chain, sim)
    committed = dict(neuron._miners)
    committed_registrations = neuron._stage_registrations(committed)
    old_ticket = ticket_binding(chain, committed_snapshot, committed[MINER_A.hotkey])

    staged_snapshot = await chain.sync()
    await neuron.state.set(staged_snapshot)
    old = committed[MINER_A.hotkey]
    rotated = RemoteMiner(
        neuron=old.neuron,
        axon_url=old.axon_url,
        binding=old.binding.model_copy(
            update={
                "service_public_key": "de" * 32,
                "generation": old.binding.generation + 1,
                "valid_from_block": staged_snapshot.block,
                "expires_at_block": staged_snapshot.block + 24,
            }
        ),
        certificate_der=old.certificate_der,
    )
    stage = dict(committed)
    stage[MINER_A.hotkey] = rotated

    class PriorDigestBridge:
        async def request(self, method: str, path: str, **_: Any) -> dict[str, Any]:
            if method == "POST":
                raise httpx.ReadTimeout("response lost before commit")
            assert path == "/v1/miners"
            return {
                "protocol": SYNAPSE_VERSION,
                "block": committed_snapshot.block,
                "ready": True,
                "publication_id": _miner_set_publication_id(
                    committed_snapshot.block, committed_registrations
                ),
                "miners": [
                    registration.model_dump(mode="json") for registration in committed_registrations
                ],
            }

    neuron.bridge = PriorDigestBridge()  # type: ignore[assignment]
    with pytest.raises(RuntimeError, match="not acknowledged"):
        await neuron._publish_miner_snapshot(staged_snapshot, stage)
    assert neuron._staged_miners is None
    assert neuron._miners == committed
    assert (await neuron._remote_for_ticket(MINER_A.hotkey, old_ticket))[0] is old
    with pytest.raises(HTTPException) as uncommitted:
        await neuron._remote_for_ticket(
            MINER_A.hotkey, ticket_binding(chain, staged_snapshot, rotated)
        )
    assert uncommitted.value.status_code == 403


@pytest.mark.asyncio
async def test_binding_drain_lane_memory_is_bounded_by_expiry(tmp_path: Path) -> None:
    neuron, chain, sim = make_harness(tmp_path)
    await refresh(neuron, chain, sim)
    current = neuron._miners[MINER_A.hotkey]
    for generation in range(2, 34):
        snapshot = await chain.sync()
        await neuron.state.set(snapshot)
        current = RemoteMiner(
            neuron=current.neuron,
            axon_url=current.axon_url,
            binding=current.binding.model_copy(
                update={
                    "generation": generation,
                    "valid_from_block": snapshot.block,
                    "expires_at_block": snapshot.block + 4,
                    "challenge": f"renewal-{generation}",
                    "signature": f"{generation:0128x}"[-128:],
                }
            ),
            certificate_der=current.certificate_der,
        )
        miners = {MINER_A.hotkey: current}
        async with neuron._lock:
            assert neuron._validator_binding is not None
            neuron._commit_miner_view_locked(
                snapshot,
                miners,
                neuron._validator_binding,
                inventory_drain=False,
            )
        retained = historical_remotes(neuron, MINER_A.hotkey)
        assert len(retained) <= max(snapshot.tempo, 12)
        assert all(
            publication.authorized_expires_at_block > snapshot.block
            for publication in neuron._historical_publications
        )
