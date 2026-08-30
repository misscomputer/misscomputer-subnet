# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi import HTTPException

from misscomputer_subnet.chain import (
    BittensorChain,
    MetagraphSnapshot,
    MetagraphState,
    NeuronRecord,
)
from misscomputer_subnet.protocol import MinerRegistration, ServiceKeyBinding
from misscomputer_subnet.validator import RemoteMiner, ValidatorNeuron, build_parser

VALIDATOR_HOTKEY = "validator-hotkey"


class HarnessChain:
    hotkey = VALIDATOR_HOTKEY
    hotkey_signer = SimpleNamespace(hotkey=VALIDATOR_HOTKEY)

    async def open(self) -> None:
        return None

    async def close(self) -> None:
        return None

    async def sync(self) -> MetagraphSnapshot:
        raise AssertionError("tests provide snapshots directly")


class RecordingBridge:
    def __init__(self) -> None:
        self.registrations: list[MinerRegistration] = []

    async def request(
        self,
        method: str,
        path: str,
        *,
        value: Any | None = None,
        response_model: Any | None = None,
    ) -> dict[str, Any]:
        assert method == "POST"
        assert path == "/v1/miners"
        assert response_model is None
        assert isinstance(value, MinerRegistration)
        self.registrations.append(value)
        return {}


def miner(
    uid: int,
    *,
    hotkey: str | None = None,
    axon: str | None = None,
    validator_permit: bool = False,
) -> NeuronRecord:
    return NeuronRecord(
        uid=uid,
        hotkey=hotkey or f"miner-{uid:03d}",
        validator_permit=validator_permit,
        tao_stake=1.0,
        axon=axon if axon is not None else f"http://8.8.8.8:{10_000 + uid}",
    )


def metagraph(records: list[NeuronRecord], block: int = 100) -> MetagraphSnapshot:
    validator = NeuronRecord(
        uid=0,
        hotkey=VALIDATOR_HOTKEY,
        validator_permit=True,
        tao_stake=10_000,
        axon=None,
    )
    return MetagraphSnapshot(
        network="finney",
        netuid=24,
        block=block,
        tempo=360,
        neurons=(validator, *records),
        finalized=True,
    )


def validator(tmp_path: Path, bridge: RecordingBridge, **discovery: Any) -> ValidatorNeuron:
    return ValidatorNeuron(
        chain=HarnessChain(),  # type: ignore[arg-type]
        hotkey_signer=HarnessChain.hotkey_signer,  # type: ignore[arg-type]
        network="finney",
        netuid=24,
        bridge=bridge,  # type: ignore[arg-type]
        bridge_secret=b"d" * 32,
        state_db=str(tmp_path / "validator.db"),
        bridge_url="http://127.0.0.1:9200",
        sync_interval=12,
        dendrite_timeout=130,
        dendrite_retries=1,
        weight_interval=360,
        version_key=2,
        mock_http_axons=True,
        **discovery,
    )


def remote(snapshot: MetagraphSnapshot, record: NeuronRecord) -> RemoteMiner:
    return RemoteMiner(
        neuron=record,
        axon_url=record.axon or "",
        binding=ServiceKeyBinding(
            role="miner",
            transport="http",
            transport_certificate_sha256=None,
            network=snapshot.network,
            netuid=snapshot.netuid,
            hotkey=record.hotkey,
            uid=record.uid,
            service_public_key=f"{record.uid:064x}",
            generation=max(snapshot.epoch + 1, 1),
            valid_from_block=snapshot.block,
            expires_at_block=snapshot.block + 1_000,
            challenge="test-capability-challenge",
        ),
        certificate_der=None,
    )


async def publish(neuron: ValidatorNeuron, snapshot: MetagraphSnapshot) -> dict[str, RemoteMiner]:
    discovered = await neuron._discover_miners(snapshot)
    async with neuron._lock:
        neuron._miners = discovered
        neuron._committed_snapshot = snapshot
        neuron._committed_validator_binding = neuron._validator_binding
    return discovered


def enable_remote_resolution(neuron: ValidatorNeuron) -> None:
    neuron._validator_binding = ServiceKeyBinding(
        role="validator",
        transport="local",
        transport_certificate_sha256=None,
        network="finney",
        netuid=24,
        hotkey=VALIDATOR_HOTKEY,
        uid=0,
        service_public_key="ab" * 32,
        generation=1,
        valid_from_block=100,
        expires_at_block=1_000,
        challenge="validator-service:test",
    )
    neuron._committed_validator_binding = neuron._validator_binding
    neuron.ready.set()


@pytest.mark.asyncio
async def test_large_open_metagraph_bounds_concurrency_without_wide_outage(
    tmp_path: Path,
) -> None:
    records = [miner(uid) for uid in range(1, 129)]
    snapshot = metagraph(records)
    bridge = RecordingBridge()
    neuron = validator(
        tmp_path,
        bridge,
        discovery_concurrency=7,
        discovery_max_attempts=128,
        discovery_attempt_timeout=0.2,
        discovery_refresh_timeout=1.0,
    )
    active = 0
    maximum_active = 0
    attempted: list[int] = []
    finished: set[int] = set()
    handshake_tasks: set[asyncio.Task[Any]] = set()
    stalled = asyncio.Event()
    stalled_entered = asyncio.Event()
    stalled_cancelled = asyncio.Event()

    async def handshake(current: MetagraphSnapshot, record: NeuronRecord) -> RemoteMiner:
        nonlocal active, maximum_active
        task = asyncio.current_task()
        assert task is not None
        handshake_tasks.add(task)
        active += 1
        maximum_active = max(maximum_active, active)
        attempted.append(record.uid)
        try:
            if record.uid == 1:
                stalled_entered.set()
                try:
                    await stalled.wait()
                except asyncio.CancelledError:
                    stalled_cancelled.set()
                    raise
            else:
                await asyncio.sleep(0)
            return remote(current, record)
        finally:
            active -= 1
            finished.add(record.uid)

    neuron._handshake = handshake  # type: ignore[method-assign]
    discovered = await publish(neuron, snapshot)
    healthy_hotkeys = {record.hotkey for record in records[1:]}

    assert stalled_entered.is_set()
    assert stalled_cancelled.is_set()
    assert not stalled.is_set()
    assert active == 0
    assert maximum_active <= 7
    assert sorted(attempted) == list(range(1, 129))
    assert finished == set(attempted)
    assert all(task.done() for task in handshake_tasks)
    assert neuron._discovery_inflight == set()
    assert len(discovered) == 127
    assert set(discovered) == healthy_hotkeys
    assert records[0].hotkey not in discovered
    assert len(bridge.registrations) == 127
    assert {registration.hotkey for registration in bridge.registrations} == healthy_hotkeys


@pytest.mark.asyncio
async def test_inflight_refresh_and_global_cancellation_keep_exact_prior_binding(
    tmp_path: Path,
) -> None:
    prior_record = miner(1)
    new_record = miner(2)
    bridge = RecordingBridge()
    neuron = validator(
        tmp_path,
        bridge,
        discovery_concurrency=2,
        discovery_max_attempts=2,
        discovery_attempt_timeout=10,
        discovery_refresh_timeout=10,
    )

    async def healthy(current: MetagraphSnapshot, candidate: NeuronRecord) -> RemoteMiner:
        return remote(current, candidate)

    neuron._handshake = healthy  # type: ignore[method-assign]
    first_snapshot = metagraph([prior_record], block=100)
    await neuron.state.set(first_snapshot)
    await publish(neuron, first_snapshot)
    enable_remote_resolution(neuron)

    entered = asyncio.Event()
    attempted: set[str] = set()

    async def blocked(_: MetagraphSnapshot, candidate: NeuronRecord) -> RemoteMiner:
        attempted.add(candidate.hotkey)
        if attempted == {prior_record.hotkey, new_record.hotkey}:
            entered.set()
        await asyncio.Future()
        raise AssertionError("cancelled discovery attempt continued")

    neuron._handshake = blocked  # type: ignore[method-assign]
    second_snapshot = metagraph([prior_record, new_record], block=101)
    await neuron.state.set(second_snapshot)
    refresh = asyncio.create_task(neuron._discover_miners(second_snapshot))
    await entered.wait()

    resolved, _, _ = await neuron._remote(prior_record.hotkey)
    assert resolved.neuron == prior_record
    with pytest.raises(HTTPException) as unavailable:
        await neuron._remote(new_record.hotkey)
    assert unavailable.value.status_code == 404

    refresh.cancel()
    with pytest.raises(asyncio.CancelledError):
        await refresh
    assert neuron._discovery_inflight == set()
    assert neuron._discovery_backoff == {}

    resolved, _, _ = await neuron._remote(prior_record.hotkey)
    assert resolved.neuron == prior_record
    with pytest.raises(HTTPException) as unavailable:
        await neuron._remote(new_record.hotkey)
    assert unavailable.value.status_code == 404


@pytest.mark.asyncio
async def test_explicit_refresh_failure_evicts_prior_binding_and_applies_backoff(
    tmp_path: Path,
) -> None:
    record = miner(1)
    bridge = RecordingBridge()
    neuron = validator(
        tmp_path,
        bridge,
        discovery_concurrency=1,
        discovery_max_attempts=1,
        discovery_attempt_timeout=10,
        discovery_refresh_timeout=10,
    )

    async def healthy(current: MetagraphSnapshot, candidate: NeuronRecord) -> RemoteMiner:
        return remote(current, candidate)

    neuron._handshake = healthy  # type: ignore[method-assign]
    first_snapshot = metagraph([record], block=100)
    await neuron.state.set(first_snapshot)
    await publish(neuron, first_snapshot)
    enable_remote_resolution(neuron)

    entered = asyncio.Event()
    release = asyncio.Event()

    async def invalid(_: MetagraphSnapshot, __: NeuronRecord) -> RemoteMiner:
        entered.set()
        await release.wait()
        raise ValueError("invalid capability response")

    neuron._handshake = invalid  # type: ignore[method-assign]
    second_snapshot = metagraph([record], block=101)
    await neuron.state.set(second_snapshot)
    refresh = asyncio.create_task(neuron._discover_miners(second_snapshot))
    await entered.wait()

    resolved, _, _ = await neuron._remote(record.hotkey)
    assert resolved.neuron == record
    release.set()
    discovered = await refresh
    assert discovered == {}

    identity = (record.hotkey, record.uid, record.axon or "")
    assert neuron._discovery_backoff[identity].failures == 1
    with pytest.raises(HTTPException) as denied:
        await neuron._remote(record.hotkey)
    assert denied.value.status_code == 409

    async with neuron._lock:
        neuron._miners = discovered
    with pytest.raises(HTTPException) as unavailable:
        await neuron._remote(record.hotkey)
    assert unavailable.value.status_code == 404


@pytest.mark.asyncio
async def test_timeout_rotation_and_immediate_retry_do_not_starve_later_hotkeys(
    tmp_path: Path,
) -> None:
    records = [miner(uid) for uid in range(1, 129)]
    bridge = RecordingBridge()
    neuron = validator(
        tmp_path,
        bridge,
        discovery_concurrency=4,
        discovery_max_attempts=128,
        discovery_attempt_timeout=1.0,
        discovery_refresh_timeout=0.02,
        discovery_backoff_base_rounds=1,
        discovery_backoff_max_rounds=4,
    )
    block_first = True
    attempts_by_round: list[list[int]] = [[], [], []]
    round_index = 0

    async def handshake(current: MetagraphSnapshot, record: NeuronRecord) -> RemoteMiner:
        attempts_by_round[round_index].append(record.uid)
        if block_first and record.uid <= 4:
            await asyncio.sleep(10)
        return remote(current, record)

    neuron._handshake = handshake  # type: ignore[method-assign]
    first = await publish(neuron, metagraph(records, block=100))
    assert first == {}
    assert sorted(attempts_by_round[0]) == [1, 2, 3, 4]

    block_first = False
    round_index = 1
    neuron.discovery_refresh_timeout = 1.0
    second = await publish(neuron, metagraph(records, block=101))
    assert attempts_by_round[1][0] == 5
    assert attempts_by_round[1][-4:] == [1, 2, 3, 4]
    assert len(second) == 128
    assert all(record.hotkey in second for record in records[4:])

    round_index = 2
    neuron.discovery_max_attempts = 4
    third = await publish(neuron, metagraph(records, block=102))
    assert attempts_by_round[2] == [5, 6, 7, 8]
    assert len(third) == 128


@pytest.mark.asyncio
async def test_refresh_deadline_cancellation_is_not_a_miner_failure(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    prior_record = miner(1)
    new_record = miner(2)
    bridge = RecordingBridge()
    neuron = validator(
        tmp_path,
        bridge,
        discovery_concurrency=2,
        discovery_max_attempts=2,
        discovery_attempt_timeout=10,
        discovery_refresh_timeout=1,
    )

    async def healthy(current: MetagraphSnapshot, candidate: NeuronRecord) -> RemoteMiner:
        return remote(current, candidate)

    neuron._handshake = healthy  # type: ignore[method-assign]
    first_snapshot = metagraph([prior_record], block=100)
    await neuron.state.set(first_snapshot)
    await publish(neuron, first_snapshot)
    enable_remote_resolution(neuron)

    cancelled: set[str] = set()

    async def blocked(_: MetagraphSnapshot, candidate: NeuronRecord) -> RemoteMiner:
        try:
            await asyncio.Future()
        finally:
            cancelled.add(candidate.hotkey)

    neuron._handshake = blocked  # type: ignore[method-assign]
    neuron.discovery_refresh_timeout = 0.02
    caplog.set_level(logging.INFO, logger="misscomputer_subnet.validator")
    second_snapshot = metagraph([prior_record, new_record], block=101)
    await neuron.state.set(second_snapshot)
    second = await publish(neuron, second_snapshot)
    assert set(second) == {prior_record.hotkey}
    assert cancelled == {prior_record.hotkey, new_record.hotkey}
    assert neuron._discovery_backoff == {}
    assert not any(
        entry.getMessage() == "miner capability refresh failed" for entry in caplog.records
    )
    summary = next(
        entry
        for entry in reversed(caplog.records)
        if entry.getMessage() == "miner discovery refresh completed"
    )
    assert summary.failure_count == 0
    assert summary.refresh_timed_out is True

    resolved, _, _ = await neuron._remote(prior_record.hotkey)
    assert resolved.neuron == prior_record
    with pytest.raises(HTTPException) as unavailable:
        await neuron._remote(new_record.hotkey)
    assert unavailable.value.status_code == 404

    # Deadline cancellation is retried on the next refresh without waiting
    # through exponential failure backoff.
    neuron._handshake = healthy  # type: ignore[method-assign]
    neuron.discovery_refresh_timeout = 1
    third_snapshot = metagraph([prior_record, new_record], block=102)
    await neuron.state.set(third_snapshot)
    third = await publish(neuron, third_snapshot)
    assert set(third) == {prior_record.hotkey, new_record.hotkey}


@pytest.mark.asyncio
async def test_fair_rotation_join_deregistration_and_identity_churn(
    tmp_path: Path,
) -> None:
    records = [miner(uid) for uid in range(1, 129)]
    bridge = RecordingBridge()
    neuron = validator(
        tmp_path,
        bridge,
        discovery_concurrency=4,
        discovery_max_attempts=16,
        discovery_attempt_timeout=0.2,
        discovery_refresh_timeout=1.0,
    )
    attempted: list[str] = []

    async def handshake(current: MetagraphSnapshot, record: NeuronRecord) -> RemoteMiner:
        attempted.append(record.hotkey)
        return remote(current, record)

    neuron._handshake = handshake  # type: ignore[method-assign]
    for offset in range(8):
        discovered = await publish(neuron, metagraph(records, block=100 + offset))
    assert len(discovered) == 128
    assert attempted == [record.hotkey for record in records]

    removed = records[9]
    old_identity = records[19]
    rebound = miner(
        200,
        hotkey=old_identity.hotkey,
        axon="http://8.8.4.4:12000",
    )
    joined = miner(129)
    churned = [
        record for record in records if record.hotkey not in {removed.hotkey, old_identity.hotkey}
    ] + [joined, rebound]

    discovered = await publish(neuron, metagraph(churned, block=108))
    assert removed.hotkey not in discovered
    assert old_identity.hotkey not in discovered
    assert joined.hotkey not in discovered
    assert removed.hotkey not in neuron._cleanup_miners
    assert old_identity.hotkey not in neuron._cleanup_miners

    for offset in range(1, 9):
        discovered = await publish(neuron, metagraph(churned, block=108 + offset))
        if joined.hotkey in discovered and old_identity.hotkey in discovered:
            break
    assert joined.hotkey in discovered
    assert discovered[old_identity.hotkey].neuron.uid == rebound.uid
    assert removed.hotkey not in discovered


@pytest.mark.asyncio
async def test_validator_permit_is_not_a_miner_role_filter(tmp_path: Path) -> None:
    ordinary = miner(1)
    permit_holder = miner(2, validator_permit=True)
    invalid_missing = NeuronRecord(3, "permit-no-axon", True, 1.0, None)
    invalid_private = miner(
        4,
        hotkey="permit-private-axon",
        axon="http://127.0.0.1:8091",
        validator_permit=True,
    )
    snapshot = metagraph([ordinary, permit_holder, invalid_missing, invalid_private])
    bridge = RecordingBridge()
    neuron = validator(tmp_path, bridge, discovery_max_attempts=16)
    attempted: list[str] = []

    async def handshake(current: MetagraphSnapshot, record: NeuronRecord) -> RemoteMiner:
        attempted.append(record.hotkey)
        return remote(current, record)

    neuron._handshake = handshake  # type: ignore[method-assign]
    _, candidates, admission = neuron._admit_snapshot(snapshot)
    discovered = await publish(neuron, snapshot)

    assert {candidate.neuron.hotkey for candidate in candidates} == {
        ordinary.hotkey,
        permit_holder.hotkey,
    }
    assert admission.candidate_count == 2
    assert admission.invalid_axon == 2
    assert attempted == [ordinary.hotkey, permit_holder.hotkey]
    assert set(discovered) == {ordinary.hotkey, permit_holder.hotkey}


def test_configured_validator_still_requires_unique_permitted_identity(tmp_path: Path) -> None:
    bridge = RecordingBridge()
    neuron = validator(tmp_path, bridge)
    snapshot = metagraph([miner(1)])
    unpermitted_validator = NeuronRecord(
        uid=0,
        hotkey=VALIDATOR_HOTKEY,
        validator_permit=False,
        tao_stake=10_000,
        axon=None,
    )
    invalid = MetagraphSnapshot(
        network=snapshot.network,
        netuid=snapshot.netuid,
        block=snapshot.block,
        tempo=snapshot.tempo,
        neurons=(unpermitted_validator, *snapshot.neurons[1:]),
        finalized=True,
    )
    with pytest.raises(RuntimeError, match="validator permit"):
        neuron._admit_snapshot(invalid)


@pytest.mark.asyncio
async def test_conflicting_miner_records_fail_closed_without_global_outage(
    tmp_path: Path,
) -> None:
    shared_axon = "http://8.8.4.4:12000"
    healthy = miner(1)
    records = [
        healthy,
        miner(2, hotkey="duplicate-hotkey"),
        miner(3, hotkey="duplicate-hotkey"),
        miner(4, hotkey="duplicate-uid-a"),
        miner(4, hotkey="duplicate-uid-b"),
        miner(5, hotkey="duplicate-axon-a", axon=shared_axon),
        miner(6, hotkey="duplicate-axon-b", axon=shared_axon),
        miner(7, hotkey="invalid-axon", axon="http://127.0.0.1:8091"),
        miner(8, hotkey="other-validator", validator_permit=True),
        miner(
            9,
            hotkey="validator-axon-collision",
            axon=healthy.axon,
            validator_permit=True,
        ),
    ]
    bridge = RecordingBridge()
    neuron = validator(tmp_path, bridge, discovery_max_attempts=128)
    attempted: list[str] = []

    async def handshake(current: MetagraphSnapshot, record: NeuronRecord) -> RemoteMiner:
        attempted.append(record.hotkey)
        return remote(current, record)

    neuron._handshake = handshake  # type: ignore[method-assign]
    discovered = await publish(neuron, metagraph(records))
    assert attempted == ["other-validator"]
    assert set(discovered) == {"other-validator"}

    # Removing the axon collision restores the otherwise healthy miner;
    # other conflict groups remain quarantined rather than causing an outage
    # for either unique identity. A validator permit changes neither result.
    records.pop()
    discovered = await publish(neuron, metagraph(records, block=101))
    assert attempted == ["other-validator", "other-validator", healthy.hotkey]
    assert set(discovered) == {healthy.hotkey, "other-validator"}

    duplicate_validator = metagraph(records)
    duplicate_validator = MetagraphSnapshot(
        network=duplicate_validator.network,
        netuid=duplicate_validator.netuid,
        block=duplicate_validator.block + 1,
        tempo=duplicate_validator.tempo,
        neurons=(
            *duplicate_validator.neurons,
            NeuronRecord(99, VALIDATOR_HOTKEY, True, 10_000, None),
        ),
    )
    with pytest.raises(RuntimeError, match="validator hotkey identity"):
        await neuron._discover_miners(duplicate_validator)


@pytest.mark.asyncio
async def test_discovery_failure_telemetry_is_bounded_and_sanitized(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    records = [miner(uid) for uid in range(1, 129)]
    bridge = RecordingBridge()
    neuron = validator(
        tmp_path,
        bridge,
        discovery_concurrency=8,
        discovery_max_attempts=128,
        discovery_attempt_timeout=0.2,
        discovery_refresh_timeout=1.0,
    )

    async def reject(_: MetagraphSnapshot, __: NeuronRecord) -> RemoteMiner:
        raise ValueError("captured-signed-payload-must-not-be-logged")

    neuron._handshake = reject  # type: ignore[method-assign]
    caplog.set_level(logging.INFO, logger="misscomputer_subnet.validator")
    discovered = await neuron._discover_miners(metagraph(records))
    assert discovered == {}
    failure_records = [
        record
        for record in caplog.records
        if record.getMessage() == "miner capability refresh failed"
    ]
    assert len(failure_records) == 8
    assert "captured-signed-payload" not in caplog.text
    summary = next(
        record
        for record in caplog.records
        if record.getMessage() == "miner discovery refresh completed"
    )
    assert summary.failure_count == 128
    assert summary.attempt_count == 128


@pytest.mark.asyncio
async def test_metagraph_state_rejects_rollback_and_same_height_conflict() -> None:
    state = MetagraphState()
    current = metagraph([miner(1)], block=200)
    await state.set(current)
    with pytest.raises(RuntimeError, match="rollback"):
        await state.set(metagraph([miner(1)], block=199))
    with pytest.raises(RuntimeError, match="conflicting"):
        await state.set(metagraph([miner(1, axon="http://8.8.4.4:12000")], block=200))
    wrong_subnet = MetagraphSnapshot(
        network="test",
        netuid=current.netuid,
        block=201,
        tempo=current.tempo,
        neurons=current.neurons,
    )
    with pytest.raises(RuntimeError, match="subnet identity"):
        await state.set(wrong_subnet)
    assert await state.get() == current


class FakeFinalizedRaw:
    async def get_chain_finalised_head(self) -> str:
        return "0xfinalized"

    async def get_block_number(self, block_hash: str) -> int:
        assert block_hash == "0xfinalized"
        return 777


class RaisingFinalizedRaw:
    def __init__(self, *, fail_number: bool = False) -> None:
        self.fail_number = fail_number

    async def get_chain_finalised_head(self) -> str:
        if not self.fail_number:
            raise ConnectionError("finalized head disconnected")
        return "0xfinalized"

    async def get_block_number(self, _: str) -> int:
        raise ConnectionError("finalized block lookup disconnected")


class FakeSubnets:
    def __init__(self, graph: Any) -> None:
        self.graph = graph
        self.calls: list[dict[str, Any]] = []

    async def metagraph(self, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        return self.graph


def fake_graph(block: int) -> Any:
    return SimpleNamespace(
        block=block,
        tempo=360,
        neurons=[
            SimpleNamespace(
                uid=1,
                hotkey="miner",
                validator_permit=False,
                tao_stake=1.0,
                axon="8.8.8.8:10001",
                active=True,
            )
        ],
    )


@pytest.mark.asyncio
async def test_bittensor_v11_finalized_read_and_monotonic_fallback() -> None:
    finalized = BittensorChain(network="finney", netuid=24)
    finalized_subnets = FakeSubnets(fake_graph(777))
    finalized._BittensorChain__client = SimpleNamespace(  # type: ignore[attr-defined]
        _substrate=SimpleNamespace(raw=FakeFinalizedRaw()),
        subnets=finalized_subnets,
    )
    snapshot = await finalized.sync()
    assert snapshot.finalized is True
    assert snapshot.block == 777
    assert finalized_subnets.calls == [{"netuid": 24, "block": 777, "commitments": False}]

    fallback = BittensorChain(network="finney", netuid=24)
    fallback_subnets = FakeSubnets(fake_graph(778))
    fallback._BittensorChain__client = SimpleNamespace(  # type: ignore[attr-defined]
        _substrate=SimpleNamespace(raw=object()),
        subnets=fallback_subnets,
    )
    snapshot = await fallback.sync()
    assert snapshot.finalized is False
    assert snapshot.block == 778
    assert fallback_subnets.calls == [{"netuid": 24, "commitments": False}]


@pytest.mark.asyncio
@pytest.mark.parametrize("fail_number", [False, True])
async def test_finalized_rpc_failure_is_fail_closed(fail_number: bool) -> None:
    chain = BittensorChain(network="finney", netuid=24)
    subnets = FakeSubnets(fake_graph(778))
    chain._BittensorChain__client = SimpleNamespace(  # type: ignore[attr-defined]
        _substrate=SimpleNamespace(raw=RaisingFinalizedRaw(fail_number=fail_number)),
        subnets=subnets,
    )
    with pytest.raises(ConnectionError, match="disconnected"):
        await chain.sync()
    assert subnets.calls == []


def test_mainnet_discovery_cli_defaults_are_bounded_and_execution_is_absent() -> None:
    args = build_parser().parse_args(
        [
            "--netuid",
            "24",
            "--bridge-secret-file",
            "/run/secrets/validator-bridge",
            "--state-db",
            "/var/lib/misscomputer-subnet/validator.db",
        ]
    )
    assert args.discovery_concurrency == 16
    assert args.discovery_max_attempts_per_refresh == 64
    assert args.discovery_attempt_timeout == 10.0
    assert args.discovery_refresh_timeout == 30.0
    assert args.discovery_backoff_base_rounds == 1
    assert args.discovery_backoff_max_rounds == 16
    assert args.enable_weight_submission is False
    assert args.weight_plan_path is None
