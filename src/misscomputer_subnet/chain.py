# SPDX-License-Identifier: AGPL-3.0-only
"""Small current-SDK chain adapter and deterministic mock metagraph."""

from __future__ import annotations

import asyncio
import json
import math
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

import bittensor as bt

from .auth import HotkeySigningFacade


@dataclass(frozen=True, slots=True)
class NeuronRecord:
    uid: int
    hotkey: str
    validator_permit: bool
    tao_stake: float
    axon: str | None
    active: bool = True


@dataclass(frozen=True, slots=True)
class MetagraphSnapshot:
    network: str
    netuid: int
    block: int
    tempo: int
    neurons: tuple[NeuronRecord, ...]
    # Bittensor v11.1 exposes the finalized head through its substrate
    # transport. Live reads are pinned to that block when the capability is
    # present; older/alternate clients fall back to a head read guarded by the
    # same conservative monotonic admission used by MetagraphState.
    finalized: bool = False

    @property
    def epoch(self) -> int:
        return self.block // max(self.tempo, 1)

    def by_hotkey(self, hotkey: str) -> NeuronRecord | None:
        return next((neuron for neuron in self.neurons if neuron.hotkey == hotkey), None)

    def identity_fingerprint(self) -> tuple[Any, ...]:
        """Comparable scheduling identity for same-height reorg detection."""
        neurons = tuple(
            sorted(
                (
                    neuron.uid,
                    neuron.hotkey,
                    neuron.validator_permit,
                    repr(neuron.tao_stake),
                    neuron.axon or "",
                    neuron.active,
                )
                for neuron in self.neurons
            )
        )
        return (self.network, self.netuid, self.block, self.tempo, neurons)


class ChainQuery(Protocol):
    """Read-only metagraph lifecycle exposed to neuron application code."""

    async def open(self) -> None: ...

    async def close(self) -> None: ...

    async def sync(self) -> MetagraphSnapshot: ...


class BittensorChain:
    """Narrow metagraph query adapter with no public wallet or raw client."""

    __slots__ = ("__client", "network", "netuid", "rpc_endpoint")

    def __init__(
        self,
        *,
        network: str,
        netuid: int,
        rpc_endpoint: str | None = None,
    ) -> None:
        self.network = network
        self.netuid = netuid
        self.rpc_endpoint = rpc_endpoint
        self.__client: Any = None

    async def open(self) -> None:
        if self.rpc_endpoint is None:
            self.__client = await bt.Subtensor(self.network)
            return
        self.__client = await bt.Subtensor(
            self.rpc_endpoint,
            fallback_endpoints=[],
            archive_endpoints=[],
        )

    async def close(self) -> None:
        client = self.__client
        if client is None:
            return
        close = getattr(client, "close", None) or getattr(client, "aclose", None)
        if close is not None:
            result = close()
            if hasattr(result, "__await__"):
                await result
        self.__client = None

    async def sync(self) -> MetagraphSnapshot:
        client = self.__client
        if client is None:
            raise RuntimeError("chain is not open")
        finalized_block = await self._finalized_block()
        return await self._read_metagraph(finalized_block)

    async def latest_finalized_block(self) -> int:
        """Return an exact finalized height or fail when the RPC lacks support."""

        finalized_block = await self._finalized_block()
        if finalized_block is None:
            raise RuntimeError("RPC does not expose finalized-head reads")
        return finalized_block

    async def sync_at_finalized(self, block: int) -> MetagraphSnapshot:
        """Read one caller-proven finalized height from this RPC."""

        if block < 0:
            raise RuntimeError("finalized block is invalid")
        return await self._read_metagraph(block)

    async def _read_metagraph(self, block: int | None) -> MetagraphSnapshot:
        client = self.__client
        if client is None:
            raise RuntimeError("chain is not open")
        if block is None:
            graph = await client.subnets.metagraph(netuid=self.netuid, commitments=False)
        else:
            graph = await client.subnets.metagraph(
                netuid=self.netuid,
                block=block,
                commitments=False,
            )
        if graph is None:
            raise RuntimeError(f"netuid {self.netuid} does not exist on {self.network}")
        graph_block = int(graph.block)
        graph_tempo = int(graph.tempo)
        if graph_block < 0 or graph_tempo < 1:
            raise RuntimeError("metagraph returned an invalid block or tempo")
        if block is not None and graph_block != block:
            raise RuntimeError("finalized metagraph read returned a different block")
        neurons = tuple(
            NeuronRecord(
                uid=int(neuron.uid),
                hotkey=str(neuron.hotkey),
                validator_permit=bool(neuron.validator_permit),
                tao_stake=_tao_value(neuron.tao_stake),
                axon=str(neuron.axon) if neuron.axon else None,
                active=bool(neuron.active),
            )
            for neuron in graph.neurons
        )
        return MetagraphSnapshot(
            network=self.network,
            netuid=self.netuid,
            block=graph_block,
            tempo=graph_tempo,
            neurons=neurons,
            finalized=block is not None,
        )

    async def commit_reveal_enabled(self, block: int) -> bool:
        """Read the subnet's weight mode at one exact finalized block."""

        client = self.__client
        if client is None:
            raise RuntimeError("chain is not open")
        return bool(await client.subnets.commit_reveal_enabled(self.netuid, block=block))

    async def validator_weights(self, block: int, validator_uid: int) -> dict[int, float]:
        """Read one validator's normalized weight row at an exact block."""

        client = self.__client
        if client is None:
            raise RuntimeError("chain is not open")
        if block < 0 or not 0 <= validator_uid <= 65_535:
            raise RuntimeError("weight-row identity is invalid")
        rows = await client.weights.weights(self.netuid, block=block)
        if not isinstance(rows, dict):
            raise RuntimeError("weight row response is invalid")
        raw_row = rows.get(validator_uid, {})
        if not isinstance(raw_row, dict):
            raise RuntimeError("validator weight row is invalid")
        row: dict[int, float] = {}
        for raw_uid, raw_weight in raw_row.items():
            if (
                isinstance(raw_uid, bool)
                or not isinstance(raw_uid, int)
                or isinstance(raw_weight, bool)
                or not isinstance(raw_weight, (int, float))
            ):
                raise RuntimeError("validator weight row contains an invalid value")
            uid = raw_uid
            weight = float(raw_weight)
            if not 0 <= uid <= 65_535 or not math.isfinite(weight) or not 0.0 < weight <= 1.0:
                raise RuntimeError("validator weight row contains an invalid value")
            if uid in row:
                raise RuntimeError("validator weight row contains a duplicate UID")
            row[uid] = weight
        if row and not math.isclose(math.fsum(row.values()), 1.0, rel_tol=0.0, abs_tol=1e-12):
            raise RuntimeError("validator weight row is not normalized")
        return dict(sorted(row.items()))

    async def _finalized_block(self) -> int | None:
        """Return the finalized height exposed by the pinned Bittensor v11 SDK.

        ``Client`` does not publish a one-shot finalized-height method, but its
        v11.1 substrate transport does publish the two exact RPC helpers used
        here. Capability detection keeps this adapter compatible with clients
        that omit them; those clients remain protected by MetagraphState's
        monotonic/same-height-conflict checks instead of silently accepting a
        rollback.
        """
        substrate = getattr(self.__client, "_substrate", None)
        raw = getattr(substrate, "raw", None)
        finalized_head = getattr(raw, "get_chain_finalised_head", None)
        block_number = getattr(raw, "get_block_number", None)
        if not callable(finalized_head) or not callable(block_number):
            return None
        block_hash = await finalized_head()
        return int(await block_number(block_hash))


def _tao_value(value: Any) -> float:
    raw = getattr(value, "tao", value)
    try:
        return float(raw)
    except (TypeError, ValueError):
        return 0.0


@dataclass(frozen=True, slots=True)
class MockPeer:
    uri: str
    uid: int
    axon: str | None
    validator_permit: bool
    tao_stake: float

    @property
    def keypair(self) -> Any:
        return bt.sp_core.Keypair.create_from_uri(self.uri)

    @property
    def hotkey(self) -> str:
        return str(self.keypair.ss58_address)


def load_mock_peers(value: str) -> tuple[MockPeer, ...]:
    # Avoid treating an inline JSON document as an OS path (long documents can
    # exceed platform pathname limits before Path.exists returns).
    if value.lstrip().startswith("["):
        raw = json.loads(value)
    else:
        raw = json.loads(Path(value).read_text())
    return tuple(
        MockPeer(
            uri=str(item["uri"]),
            uid=int(item["uid"]),
            axon=str(item["axon"]) if item.get("axon") else None,
            validator_permit=bool(item.get("validator_permit", False)),
            tao_stake=float(item.get("tao_stake", 0)),
        )
        for item in raw
    )


class MockChain:
    def __init__(
        self,
        *,
        network: str,
        netuid: int,
        own_uri: str,
        peers: tuple[MockPeer, ...],
        initial_block: int = 100,
        tempo: int = 12,
    ) -> None:
        self.network = network
        self.netuid = netuid
        self.hotkey_signer = HotkeySigningFacade(bt.sp_core.Keypair.create_from_uri(own_uri))
        self.hotkey = self.hotkey_signer.hotkey
        self.peers = peers
        self.block = initial_block
        self.tempo = tempo
        self._lock = asyncio.Lock()

    async def open(self) -> None:
        return None

    async def close(self) -> None:
        return None

    async def sync(self) -> MetagraphSnapshot:
        async with self._lock:
            # All mock processes derive a common monotonically increasing
            # block clock without a coordinator or live chain.
            self.block = max(self.block + 1, int(time.time()))
            return MetagraphSnapshot(
                network=self.network,
                netuid=self.netuid,
                block=self.block,
                tempo=self.tempo,
                neurons=tuple(
                    NeuronRecord(
                        uid=peer.uid,
                        hotkey=peer.hotkey,
                        validator_permit=peer.validator_permit,
                        tao_stake=peer.tao_stake,
                        axon=peer.axon,
                    )
                    for peer in self.peers
                ),
                # The deterministic mock has no competing fork-choice or RPC
                # head. Each serialized tick is therefore its finalized view.
                finalized=True,
            )

    async def commit_reveal_enabled(self, block: int) -> bool:
        del block
        return False


class MetagraphState:
    def __init__(self) -> None:
        self._snapshot: MetagraphSnapshot | None = None
        self._lock = asyncio.Lock()

    async def set(self, snapshot: MetagraphSnapshot) -> None:
        async with self._lock:
            if (
                not snapshot.network
                or not 0 <= snapshot.netuid <= 65_535
                or snapshot.block < 0
                or snapshot.tempo < 1
            ):
                raise RuntimeError("invalid metagraph snapshot identity")
            current = self._snapshot
            if current is not None:
                if snapshot.network != current.network or snapshot.netuid != current.netuid:
                    raise RuntimeError("metagraph subnet identity changed")
                if snapshot.block < current.block:
                    raise RuntimeError("metagraph block rollback rejected")
                if (
                    snapshot.block == current.block
                    and snapshot.identity_fingerprint() != current.identity_fingerprint()
                ):
                    raise RuntimeError("conflicting metagraph snapshot at committed block")
            self._snapshot = snapshot

    async def get(self) -> MetagraphSnapshot:
        async with self._lock:
            if self._snapshot is None:
                raise RuntimeError("metagraph has not synchronized")
            return self._snapshot
