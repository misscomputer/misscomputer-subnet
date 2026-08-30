# SPDX-License-Identifier: AGPL-3.0-only
"""Fail-closed agreement across independent finalized Bittensor RPC views."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import sys
from collections.abc import Callable, Sequence
from contextlib import suppress
from dataclasses import dataclass
from typing import Protocol, cast
from urllib.parse import urlsplit

from .chain import BittensorChain, MetagraphSnapshot


class FinalizedChainQuery(Protocol):
    async def open(self) -> None: ...

    async def close(self) -> None: ...

    async def latest_finalized_block(self) -> int: ...

    async def sync_at_finalized(self, block: int) -> MetagraphSnapshot: ...

    async def commit_reveal_enabled(self, block: int) -> bool: ...

    async def validator_weights(self, block: int, validator_uid: int) -> dict[int, float]: ...


@dataclass(frozen=True, slots=True)
class RpcAgreementAlert:
    """Credential-free alert suitable for logs and monitoring adapters."""

    code: str
    phase: str
    rpc_count: int
    observed_blocks: tuple[int, ...] = ()

    def document(self) -> dict[str, object]:
        return {
            "alert_code": self.code,
            "observed_blocks": list(self.observed_blocks),
            "phase": self.phase,
            "rpc_count": self.rpc_count,
            "severity": "critical",
        }


class RpcAgreementError(RuntimeError):
    """A sanitized redundant-read failure that must stop the caller."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


AlertSink = Callable[[RpcAgreementAlert], None]


def json_stderr_alert(alert: RpcAgreementAlert) -> None:
    print(json.dumps(alert.document(), sort_keys=True, separators=(",", ":")), file=sys.stderr)


class FinalizedRpcQuorum:
    """Use the newest common finalized height and require exact view agreement."""

    def __init__(
        self,
        chains: Sequence[FinalizedChainQuery],
        *,
        max_finalized_lag: int = 8,
        alert_sink: AlertSink | None = None,
    ) -> None:
        if len(chains) < 2:
            raise ValueError("finalized RPC agreement requires at least two RPCs")
        if isinstance(max_finalized_lag, bool) or not 0 <= max_finalized_lag <= 1_024:
            raise ValueError("maximum finalized RPC lag is invalid")
        self._chains = tuple(chains)
        self._max_finalized_lag = max_finalized_lag
        self._alert_sink = alert_sink
        self._opened = False
        self._last_agreed_block: int | None = None

    def _fail(
        self,
        code: str,
        phase: str,
        message: str,
        *,
        observed_blocks: tuple[int, ...] = (),
    ) -> RpcAgreementError:
        if self._alert_sink is not None:
            with suppress(Exception):
                self._alert_sink(
                    RpcAgreementAlert(
                        code=code,
                        phase=phase,
                        rpc_count=len(self._chains),
                        observed_blocks=observed_blocks,
                    )
                )
        return RpcAgreementError(code, message)

    async def open(self) -> None:
        results = await asyncio.gather(
            *(chain.open() for chain in self._chains), return_exceptions=True
        )
        if any(isinstance(result, BaseException) for result in results):
            await asyncio.gather(*(chain.close() for chain in self._chains), return_exceptions=True)
            raise self._fail("rpc_open_failed", "open", "redundant RPC set is unavailable")
        self._opened = True

    async def close(self) -> None:
        if not self._opened:
            return
        self._opened = False
        results = await asyncio.gather(
            *(chain.close() for chain in self._chains), return_exceptions=True
        )
        if any(isinstance(result, BaseException) for result in results):
            raise self._fail("rpc_close_failed", "close", "redundant RPC close failed")

    async def sync(self) -> MetagraphSnapshot:
        heights_raw = await asyncio.gather(
            *(chain.latest_finalized_block() for chain in self._chains),
            return_exceptions=True,
        )
        if any(isinstance(value, BaseException) for value in heights_raw):
            raise self._fail(
                "rpc_finalized_head_unavailable",
                "finalized_head",
                "a finalized RPC head is unavailable",
            )
        if any(isinstance(value, bool) or not isinstance(value, int) for value in heights_raw):
            raise self._fail(
                "rpc_finalized_head_invalid",
                "finalized_head",
                "a finalized RPC head is invalid",
            )
        heights = tuple(cast(int, value) for value in heights_raw)
        if any(height < 0 for height in heights):
            raise self._fail(
                "rpc_finalized_head_invalid",
                "finalized_head",
                "a finalized RPC head is invalid",
                observed_blocks=heights,
            )
        common_block = min(heights)
        if max(heights) - common_block > self._max_finalized_lag:
            raise self._fail(
                "rpc_finalized_lag_exceeded",
                "finalized_head",
                "finalized RPC lag exceeds the configured bound",
                observed_blocks=heights,
            )
        if self._last_agreed_block is not None and common_block < self._last_agreed_block:
            raise self._fail(
                "rpc_finalized_rollback",
                "finalized_head",
                "the agreed finalized height moved backwards",
                observed_blocks=heights,
            )
        snapshots_raw = await asyncio.gather(
            *(chain.sync_at_finalized(common_block) for chain in self._chains),
            return_exceptions=True,
        )
        if any(isinstance(value, BaseException) for value in snapshots_raw):
            raise self._fail(
                "rpc_snapshot_unavailable",
                "metagraph",
                "a finalized metagraph view is unavailable",
                observed_blocks=heights,
            )
        if any(not isinstance(value, MetagraphSnapshot) for value in snapshots_raw):
            raise self._fail(
                "rpc_snapshot_unavailable",
                "metagraph",
                "a finalized metagraph view is unavailable",
                observed_blocks=heights,
            )
        snapshots = tuple(cast(MetagraphSnapshot, value) for value in snapshots_raw)
        if any(not snapshot.finalized or snapshot.block != common_block for snapshot in snapshots):
            raise self._fail(
                "rpc_snapshot_not_finalized",
                "metagraph",
                "an RPC did not return the agreed finalized height",
                observed_blocks=heights,
            )
        fingerprint = snapshots[0].identity_fingerprint()
        if any(snapshot.identity_fingerprint() != fingerprint for snapshot in snapshots[1:]):
            raise self._fail(
                "rpc_snapshot_disagreement",
                "metagraph",
                "finalized RPC metagraph views disagree",
                observed_blocks=heights,
            )
        self._last_agreed_block = common_block
        return snapshots[0]

    async def commit_reveal_enabled(self, block: int) -> bool:
        values_raw = await asyncio.gather(
            *(chain.commit_reveal_enabled(block) for chain in self._chains),
            return_exceptions=True,
        )
        if any(isinstance(value, BaseException) for value in values_raw):
            raise self._fail(
                "rpc_weight_mode_unavailable",
                "weight_mode",
                "a finalized weight-mode view is unavailable",
                observed_blocks=(block,),
            )
        if any(not isinstance(value, bool) for value in values_raw):
            raise self._fail(
                "rpc_weight_mode_unavailable",
                "weight_mode",
                "a finalized weight-mode view is unavailable",
                observed_blocks=(block,),
            )
        values = tuple(cast(bool, value) for value in values_raw)
        if len(set(values)) != 1:
            raise self._fail(
                "rpc_weight_mode_disagreement",
                "weight_mode",
                "finalized RPC weight-mode views disagree",
                observed_blocks=(block,),
            )
        return values[0]

    async def validator_weights(self, block: int, validator_uid: int) -> dict[int, float]:
        rows_raw = await asyncio.gather(
            *(chain.validator_weights(block, validator_uid) for chain in self._chains),
            return_exceptions=True,
        )
        if any(isinstance(value, BaseException) for value in rows_raw):
            raise self._fail(
                "rpc_weight_row_unavailable",
                "weight_row",
                "a finalized validator-weight view is unavailable",
                observed_blocks=(block,),
            )
        if any(not isinstance(value, dict) for value in rows_raw):
            raise self._fail(
                "rpc_weight_row_unavailable",
                "weight_row",
                "a finalized validator-weight view is unavailable",
                observed_blocks=(block,),
            )
        rows = tuple(cast(dict[int, float], value) for value in rows_raw)
        fingerprint = tuple((uid, weight.hex()) for uid, weight in rows[0].items())
        if any(
            tuple((uid, weight.hex()) for uid, weight in row.items()) != fingerprint
            for row in rows[1:]
        ):
            raise self._fail(
                "rpc_weight_row_disagreement",
                "weight_row",
                "finalized RPC validator-weight views disagree",
                observed_blocks=(block,),
            )
        return rows[0]


def build_chain_query(
    *,
    network: str,
    netuid: int,
    rpc_endpoints: Sequence[str],
    max_finalized_lag: int = 8,
    alert_sink: AlertSink | None = None,
) -> BittensorChain | FinalizedRpcQuorum:
    """Build the legacy single read or an explicitly independent RPC quorum."""

    endpoints = tuple(rpc_endpoints)
    if not endpoints:
        return BittensorChain(network=network, netuid=netuid)
    if len(endpoints) < 2:
        raise ValueError("configure at least two RPC endpoints or none")
    endpoint_identities = tuple(_rpc_endpoint_identity(endpoint) for endpoint in endpoints)
    if any(identity is None for identity in endpoint_identities) or len(
        set(endpoint_identities)
    ) != len(endpoint_identities):
        raise ValueError("RPC endpoint set is invalid")
    return FinalizedRpcQuorum(
        tuple(
            BittensorChain(network=network, netuid=netuid, rpc_endpoint=endpoint)
            for endpoint in endpoints
        ),
        max_finalized_lag=max_finalized_lag,
        alert_sink=alert_sink,
    )


def _rpc_endpoint_identity(endpoint: str) -> tuple[str, str, int] | None:
    """Return one credential-free identity for a root WebSocket authority."""

    if (
        not endpoint
        or endpoint != endpoint.strip()
        or any(ord(character) < 0x21 or ord(character) > 0x7E for character in endpoint)
    ):
        return None
    try:
        parsed = urlsplit(endpoint)
        port = parsed.port
    except ValueError:
        return None
    hostname = parsed.hostname
    if (
        parsed.scheme not in {"ws", "wss"}
        or hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or (port is not None and not 1 <= port <= 65_535)
    ):
        return None
    try:
        canonical_hostname = ipaddress.ip_address(hostname).compressed
    except ValueError:
        canonical_hostname = hostname.lower().rstrip(".")
    if not canonical_hostname:
        return None
    effective_port = port if port is not None else {"ws": 80, "wss": 443}[parsed.scheme]
    return (parsed.scheme, canonical_hostname, effective_port)
