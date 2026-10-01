# SPDX-License-Identifier: AGPL-3.0-only
"""Capability features reach the runtime in miner-registration.v3.

The validator registers each miner with the normalized features of the same
capability response that carried its hotkey-signed binding, but only while
the runtime advertises ``miner-registration-v3``; an older runtime keeps
receiving the exact v2 registration. After a Python restart the features are
restored from Go's committed v3 inventory, never invented.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from test_validator_cleanup import (
    MINER_A,
    MINER_B,
    RecordingBridge,
    make_harness,
    refresh,
)

from misscomputer_subnet.protocol import (
    SYNAPSE_VERSION,
    MinerRegistration,
    MinerRegistrationV3,
)
from misscomputer_subnet.validator import RemoteMiner, _miner_set_publication_id


class RegistrationRecorder(RecordingBridge):
    def __init__(self) -> None:
        self.registrations: list[MinerRegistration] = []

    async def request(
        self,
        method: str,
        path: str,
        *,
        value: Any | None = None,
        response_model: Any | None = None,
    ) -> Any:
        if method == "POST" and path == "/v1/miners":
            assert isinstance(value, MinerRegistration)
            self.registrations.append(value)
        return {}


@pytest.mark.asyncio
@pytest.mark.parametrize("runtime_v3", [False, True])
async def test_registration_carries_handshake_features_only_for_a_v3_runtime(
    tmp_path: Path, runtime_v3: bool
) -> None:
    neuron, chain, sim = make_harness(tmp_path)
    sim.organic_capable.discard(MINER_B.hotkey)
    recorder = RegistrationRecorder()
    neuron.bridge = recorder  # type: ignore[assignment]
    neuron._registration_v3 = runtime_v3
    await refresh(neuron, chain, sim)
    by_hotkey = {item.hotkey: item for item in recorder.registrations}
    assert set(by_hotkey) == {MINER_A.hotkey, MINER_B.hotkey}
    for hotkey, registration in by_hotkey.items():
        wire = registration.model_dump(mode="json")
        if not runtime_v3:
            assert type(registration) is MinerRegistration
            assert wire["protocol"] == SYNAPSE_VERSION and "features" not in wire
            continue
        assert isinstance(registration, MinerRegistrationV3)
        expected = ["organic-oci-v1", "scheduler"] if hotkey == MINER_A.hotkey else ["scheduler"]
        assert wire["protocol"] == "subnet-synapse.v3"
        assert wire["features"] == expected


@pytest.mark.asyncio
async def test_python_restart_restores_features_from_go_committed_v3_inventory(
    tmp_path: Path,
) -> None:
    neuron, chain, sim = make_harness(tmp_path)
    neuron._registration_v3 = True
    snapshot = await refresh(neuron, chain, sim)
    remotes = dict(neuron._miners)
    registrations = neuron._stage_registrations(remotes)
    assert all(isinstance(item, MinerRegistrationV3) for item in registrations)

    class InventoryBridge:
        async def request(self, method: str, path: str, **_: Any) -> dict[str, Any]:
            assert method == "GET" and path == "/v1/miners"
            return {
                "protocol": SYNAPSE_VERSION,
                "block": snapshot.block,
                "ready": True,
                "publication_id": _miner_set_publication_id(snapshot.block, registrations),
                "miners": [item.model_dump(mode="json") for item in registrations],
            }

    # A fresh Python state DB: nothing durable remains on the Python side.
    fresh = tmp_path / "restarted"
    fresh.mkdir()
    restarted, _, _ = make_harness(fresh)
    restarted._registration_v3 = True
    restarted.bridge = InventoryBridge()  # type: ignore[assignment]
    await restarted.state.set(snapshot)
    restarted.ready.set()
    # Retained cleanup handles carry no features: only Go's committed v3
    # registrations may supply them.
    restarted._cleanup_miners = {
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
    restarted._validator_binding = neuron._committed_validator_binding
    inventory = await InventoryBridge().request("GET", "/v1/miners")
    recovered = await restarted._reconcile_committed_inventory(inventory, snapshot)
    assert recovered is not None
    assert recovered[MINER_A.hotkey].features == frozenset({"organic-oci-v1", "scheduler"})
    assert restarted._stage_registrations(recovered) == registrations
