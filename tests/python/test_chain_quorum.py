# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

from dataclasses import replace
from typing import Any

import pytest

from misscomputer_subnet import chain as chain_module
from misscomputer_subnet.chain import BittensorChain, MetagraphSnapshot, NeuronRecord
from misscomputer_subnet.chain_quorum import (
    FinalizedRpcQuorum,
    RpcAgreementAlert,
    RpcAgreementError,
    build_chain_query,
)


def snapshot(block: int = 100) -> MetagraphSnapshot:
    return MetagraphSnapshot(
        network="finney",
        netuid=24,
        block=block,
        tempo=20,
        neurons=(NeuronRecord(0, "validator", True, 100.0, None),),
        finalized=True,
    )


class FakeFinalizedChain:
    def __init__(
        self,
        *,
        height: int = 100,
        view: MetagraphSnapshot | None = None,
        commit_reveal: bool = False,
        open_error: BaseException | None = None,
        head_error: BaseException | None = None,
        weight_row: dict[int, float] | None = None,
    ) -> None:
        self.height = height
        self.view = view or snapshot(height)
        self.commit_reveal = commit_reveal
        self.open_error = open_error
        self.head_error = head_error
        self.weight_row = weight_row or {3: 0.4, 9: 0.6}
        self.open_count = 0
        self.close_count = 0
        self.requested_blocks: list[int] = []

    async def open(self) -> None:
        self.open_count += 1
        if self.open_error is not None:
            raise self.open_error

    async def close(self) -> None:
        self.close_count += 1

    async def latest_finalized_block(self) -> int:
        if self.head_error is not None:
            raise self.head_error
        return self.height

    async def sync_at_finalized(self, block: int) -> MetagraphSnapshot:
        self.requested_blocks.append(block)
        return replace(self.view, block=block)

    async def commit_reveal_enabled(self, _block: int) -> bool:
        return self.commit_reveal

    async def validator_weights(self, _block: int, _validator_uid: int) -> dict[int, float]:
        return self.weight_row


class InvalidFinalizedChain(FakeFinalizedChain):
    async def latest_finalized_block(self) -> int:
        return True  # type: ignore[return-value]

    async def commit_reveal_enabled(self, _block: int) -> bool:
        return "false"  # type: ignore[return-value]

    async def validator_weights(self, _block: int, _validator_uid: int) -> dict[int, float]:
        return []  # type: ignore[return-value]


async def test_quorum_reads_newest_common_finalized_height() -> None:
    first = FakeFinalizedChain(height=105, view=snapshot(100))
    second = FakeFinalizedChain(height=103, view=snapshot(100))
    quorum = FinalizedRpcQuorum((first, second), max_finalized_lag=3)

    await quorum.open()
    agreed = await quorum.sync()
    await quorum.close()

    assert agreed.block == 103
    assert first.requested_blocks == [103]
    assert second.requested_blocks == [103]
    assert first.close_count == second.close_count == 1


async def test_quorum_rejects_finalized_view_disagreement() -> None:
    first = FakeFinalizedChain(view=snapshot())
    conflicting = replace(
        snapshot(), neurons=(NeuronRecord(0, "other-validator", True, 100.0, None),)
    )
    second = FakeFinalizedChain(view=conflicting)
    alerts: list[RpcAgreementAlert] = []
    quorum = FinalizedRpcQuorum((first, second), alert_sink=alerts.append)

    with pytest.raises(RpcAgreementError) as error:
        await quorum.sync()

    assert error.value.code == "rpc_snapshot_disagreement"
    assert alerts[0].document() == {
        "alert_code": "rpc_snapshot_disagreement",
        "observed_blocks": [100, 100],
        "phase": "metagraph",
        "rpc_count": 2,
        "severity": "critical",
    }


async def test_quorum_rejects_excess_finalized_lag_before_snapshot_read() -> None:
    first = FakeFinalizedChain(height=100)
    second = FakeFinalizedChain(height=109)
    quorum = FinalizedRpcQuorum((first, second), max_finalized_lag=8)

    with pytest.raises(RpcAgreementError) as error:
        await quorum.sync()

    assert error.value.code == "rpc_finalized_lag_exceeded"
    assert first.requested_blocks == second.requested_blocks == []


async def test_quorum_rejects_finalized_rollback() -> None:
    first = FakeFinalizedChain(height=100)
    second = FakeFinalizedChain(height=100)
    quorum = FinalizedRpcQuorum((first, second))
    assert (await quorum.sync()).block == 100
    first.height = second.height = 99

    with pytest.raises(RpcAgreementError) as error:
        await quorum.sync()

    assert error.value.code == "rpc_finalized_rollback"


async def test_quorum_rejects_weight_mode_disagreement() -> None:
    quorum = FinalizedRpcQuorum(
        (FakeFinalizedChain(commit_reveal=False), FakeFinalizedChain(commit_reveal=True))
    )

    with pytest.raises(RpcAgreementError) as error:
        await quorum.commit_reveal_enabled(100)

    assert error.value.code == "rpc_weight_mode_disagreement"


async def test_quorum_rejects_weight_row_disagreement() -> None:
    quorum = FinalizedRpcQuorum(
        (
            FakeFinalizedChain(weight_row={3: 0.4, 9: 0.6}),
            FakeFinalizedChain(weight_row={3: 0.5, 9: 0.5}),
        )
    )

    with pytest.raises(RpcAgreementError) as error:
        await quorum.validator_weights(100, 0)

    assert error.value.code == "rpc_weight_row_disagreement"


async def test_quorum_rejects_wrong_typed_rpc_values() -> None:
    invalid = InvalidFinalizedChain()
    valid = FakeFinalizedChain()
    quorum = FinalizedRpcQuorum((invalid, valid))

    with pytest.raises(RpcAgreementError) as error:
        await quorum.sync()
    assert error.value.code == "rpc_finalized_head_invalid"

    with pytest.raises(RpcAgreementError) as error:
        await quorum.commit_reveal_enabled(100)
    assert error.value.code == "rpc_weight_mode_unavailable"

    with pytest.raises(RpcAgreementError) as error:
        await quorum.validator_weights(100, 0)
    assert error.value.code == "rpc_weight_row_unavailable"


async def test_quorum_sanitizes_endpoint_failure_and_closes_opened_set() -> None:
    sensitive_value = "wss://user:secret@example.invalid"  # noqa: S105
    first = FakeFinalizedChain()
    second = FakeFinalizedChain(open_error=RuntimeError(sensitive_value))
    alerts: list[RpcAgreementAlert] = []
    quorum = FinalizedRpcQuorum((first, second), alert_sink=alerts.append)

    with pytest.raises(RpcAgreementError) as error:
        await quorum.open()

    assert error.value.code == "rpc_open_failed"
    assert sensitive_value not in str(error.value)
    assert sensitive_value not in str(alerts[0].document())
    assert first.close_count == second.close_count == 1


async def test_quorum_sanitizes_finalized_head_failure() -> None:
    sensitive_value = "https://token@example.invalid"  # noqa: S105
    quorum = FinalizedRpcQuorum(
        (FakeFinalizedChain(), FakeFinalizedChain(head_error=RuntimeError(sensitive_value)))
    )

    with pytest.raises(RpcAgreementError) as error:
        await quorum.sync()

    assert error.value.code == "rpc_finalized_head_unavailable"
    assert sensitive_value not in str(error.value)


def test_factory_requires_distinct_redundant_endpoints() -> None:
    with pytest.raises(ValueError, match="at least two"):
        build_chain_query(network="finney", netuid=24, rpc_endpoints=("wss://one",))
    with pytest.raises(ValueError, match="invalid"):
        build_chain_query(
            network="finney",
            netuid=24,
            rpc_endpoints=("wss://same", "wss://same"),
        )


@pytest.mark.parametrize(
    ("first", "second"),
    [
        ("wss://RPC.example.invalid", "wss://rpc.example.invalid/"),
        ("wss://rpc.example.invalid", "wss://rpc.example.invalid:443"),
        ("ws://rpc.example.invalid", "ws://rpc.example.invalid:80/"),
        ("wss://[2001:0DB8::1]", "wss://[2001:db8:0:0:0:0:0:1]:443/"),
    ],
)
def test_factory_rejects_canonical_duplicate_endpoints(first: str, second: str) -> None:
    with pytest.raises(ValueError, match="RPC endpoint set is invalid") as error:
        build_chain_query(
            network="finney",
            netuid=24,
            rpc_endpoints=(first, second),
        )
    assert first not in str(error.value)
    assert second not in str(error.value)


def test_factory_does_not_echo_invalid_endpoint() -> None:
    sensitive_value = "wss://user:password@example.invalid\n"  # noqa: S105
    with pytest.raises(ValueError) as error:
        build_chain_query(
            network="finney",
            netuid=24,
            rpc_endpoints=(sensitive_value, "wss://other"),
        )
    assert sensitive_value.strip() not in str(error.value)


def test_factory_rejects_endpoint_credentials_without_echoing_them() -> None:
    sensitive_value = "wss://user:password@example.invalid"  # noqa: S105
    with pytest.raises(ValueError) as error:
        build_chain_query(
            network="finney",
            netuid=24,
            rpc_endpoints=(sensitive_value, "wss://other.example.invalid"),
        )
    assert sensitive_value not in str(error.value)


@pytest.mark.asyncio
async def test_bittensor_adapter_pins_explicit_rpc_without_sdk_rotation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, dict[str, object]]] = []

    class Client:
        async def close(self) -> None:
            return None

    async def make_client(endpoint: str, **kwargs: object) -> Client:
        calls.append((endpoint, kwargs))
        return Client()

    monkeypatch.setattr(chain_module.bt, "Subtensor", make_client)
    chain = BittensorChain(
        network="finney",
        netuid=24,
        rpc_endpoint="wss://rpc.example.invalid",
    )

    await chain.open()
    await chain.close()

    assert calls == [
        (
            "wss://rpc.example.invalid",
            {"archive_endpoints": [], "fallback_endpoints": []},
        )
    ]


@pytest.mark.asyncio
async def test_bittensor_adapter_preserves_legacy_named_network_behavior(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, dict[str, Any]]] = []

    class Client:
        async def close(self) -> None:
            return None

    async def make_client(network: str, **kwargs: Any) -> Client:
        calls.append((network, kwargs))
        return Client()

    monkeypatch.setattr(chain_module.bt, "Subtensor", make_client)
    chain = BittensorChain(network="finney", netuid=24)

    await chain.open()
    await chain.close()

    assert calls == [("finney", {})]


class FakeWeightNamespace:
    def __init__(self, rows: object) -> None:
        self.rows = rows

    async def weights(self, _netuid: int, *, block: int) -> object:
        assert block == 100
        return self.rows


class FakeWeightClient:
    def __init__(self, rows: object) -> None:
        self.weights = FakeWeightNamespace(rows)


async def test_bittensor_adapter_validates_normalized_weight_row_types() -> None:
    chain = BittensorChain(network="finney", netuid=24)
    chain._BittensorChain__client = FakeWeightClient({0: {3: 0.4, 9: 0.6}})  # type: ignore[attr-defined]
    assert await chain.validator_weights(100, 0) == {3: 0.4, 9: 0.6}

    chain._BittensorChain__client = FakeWeightClient({0: {True: 1.0}})  # type: ignore[attr-defined]
    with pytest.raises(RuntimeError, match="invalid value"):
        await chain.validator_weights(100, 0)
