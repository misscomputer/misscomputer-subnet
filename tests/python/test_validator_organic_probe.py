# SPDX-License-Identifier: AGPL-3.0-only
"""Validator bridge hop that authorizes organic probes for the Go edge (§17.2).

The Go edge has neither sr25519 nor the metagraph, so it delegates exactly
those two decisions to the validator neuron over the authenticated loopback
bridge; freshness, nonce and routing stay in the edge.
"""

from __future__ import annotations

import secrets
from pathlib import Path
from typing import Any

import httpx
import pytest

from misscomputer_subnet import organic_contracts as oc
from misscomputer_subnet.auth import bridge_headers
from misscomputer_subnet.chain import MockChain, MockPeer
from misscomputer_subnet.validator import ValidatorNeuron

BRIDGE_SECRET = b"organic-probe-bridge-secret-32b!!"
SELF = MockPeer("//ProbeHost", 0, None, True, 10_000)
PEER_VALIDATOR = MockPeer("//ProbePeerValidator", 1, None, True, 5_000)
MINER = MockPeer("//ProbeMiner", 2, "http://miner.invalid:8091", False, 100)
TARGET = "/v1/organic-probes/authorize"


class NoBridge:
    async def request(self, *args: Any, **kwargs: Any) -> Any:
        raise AssertionError("the authorization hop must not call the Go bridge")


def neuron(tmp_path: Path) -> tuple[ValidatorNeuron, MockChain]:
    chain = MockChain(
        network="local", netuid=24, own_uri="//ProbeHost", peers=(SELF, PEER_VALIDATOR, MINER)
    )
    return (
        ValidatorNeuron(
            chain=chain,
            hotkey_signer=chain.hotkey_signer,
            network="local",
            netuid=24,
            bridge=NoBridge(),  # type: ignore[arg-type]
            bridge_secret=BRIDGE_SECRET,
            state_db=str(tmp_path / "validator.db"),
            bridge_url="http://127.0.0.1:9200",
            sync_interval=1,
            dendrite_timeout=1,
            dendrite_retries=0,
            allow_private_axons=True,
            mock_http_axons=True,
        ),
        chain,
    )


def authorization(signer: MockPeer, **overrides: Any) -> bytes:
    document: dict[str, Any] = {
        "endpoint_id": "hello-world-k3j9x0q2ab-5Fminer-g1-" + "ab" * 16,
        "generation": 1,
        "issued_at": "2026-09-26T00:17:12Z",
        "method": "GET",
        "nonce": secrets.token_hex(32),
        "path": "/",
        "schema": "miss.computer/misscomputer-subnet/organic-probe-authorization",
        "schema_version": 1,
        "signature": "00" * 64,
        "validator_hotkey": signer.keypair.ss58_address,
    }
    unsigned = oc.OrganicProbeAuthorization.model_validate(document)
    document["signature"] = signer.keypair.sign(oc.organic_probe_message(unsigned)).hex()
    document.update(overrides)
    return oc.document_bytes(oc.OrganicProbeAuthorization.model_validate(document))


async def post(validator: ValidatorNeuron, body: bytes) -> httpx.Response:
    headers = bridge_headers(BRIDGE_SECRET, method="POST", target=TARGET, body=body)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=validator.app), base_url="http://127.0.0.1"
    ) as client:
        return await client.post(TARGET, content=body, headers=headers)


@pytest.mark.asyncio
async def test_bridge_authorizes_only_permitted_validator_signatures(tmp_path: Path) -> None:
    validator, chain = neuron(tmp_path)
    assert (await post(validator, authorization(PEER_VALIDATOR))).status_code == 503
    await validator.state.set(await chain.sync())

    accepted = await post(validator, authorization(PEER_VALIDATOR))
    assert accepted.status_code == 200, accepted.text
    assert accepted.json() == {"authorized": True}
    # Re-targeting a signed authorization, signing as a non-validator, or
    # skipping the bridge HMAC is refused.
    moved = await post(validator, authorization(PEER_VALIDATOR, path="/admin"))
    assert moved.status_code == 403
    assert (await post(validator, authorization(MINER))).status_code == 403
    unsigned = authorization(PEER_VALIDATOR)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=validator.app), base_url="http://127.0.0.1"
    ) as client:
        assert (await client.post(TARGET, content=unsigned)).status_code == 401
