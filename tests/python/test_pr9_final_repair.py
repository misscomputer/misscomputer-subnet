# SPDX-License-Identifier: AGPL-3.0-only
"""Acceptance cases from the final exact-SHA review, including resealed inputs."""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any

import httpcore
import pytest
from assignment_probe_context import BASE_EPOCH, canonical, digest, make_context
from contract_checkpoint_context import build_snapshot
from pydantic import ValidationError

from misscomputer_subnet import assignment_probe as probe
from misscomputer_subnet import assignment_snapshot as snapshot
from misscomputer_subnet import probe_transport as transport


def lineage_pair() -> tuple[snapshot.SnapshotLineage, snapshot.ActiveAssignmentSnapshot]:
    first = build_snapshot()
    initial = snapshot.build_initial_snapshot_lineage(
        central_authority_fingerprint_sha256=first.central_authority_fingerprint_sha256
    )
    return snapshot.advance_snapshot_lineage(initial, first), build_snapshot(
        snapshot_sequence=2, state_revision=8
    )


def test_boundary_dry_runs_rewritten_incarnation() -> None:
    lineage, candidate = lineage_pair()
    document = candidate.model_dump(mode="json", by_alias=True)
    document["deployments"][0]["replicas"][0]["route_activated_at_epoch"] += 1
    document["snapshot_digest_sha256"] = digest(
        {k: v for k, v in document.items() if k != "snapshot_digest_sha256"}
    )
    candidate = snapshot.ActiveAssignmentSnapshot.model_validate(document)
    with pytest.raises(snapshot.AssignmentSnapshotError, match="snapshot_incarnation_rewritten"):
        snapshot.begin_snapshot_lineage_era(lineage, retain_for=candidate)


def test_replay_can_stop_at_candidate_boundary() -> None:
    lineage, candidate = lineage_pair()
    pending = snapshot.begin_snapshot_lineage_era(lineage, retain_for=candidate)
    restored = snapshot.replay_snapshot_lineage(
        lineage, [], era_boundaries=pending.era_boundaries, pending_candidate=candidate
    )
    assert restored == pending


def test_replay_does_not_ignore_forged_prefix() -> None:
    lineage, candidate = lineage_pair()
    pending = snapshot.begin_snapshot_lineage_era(lineage)
    current = snapshot.advance_snapshot_lineage(pending, candidate)
    forged = pending.era_boundaries[0].model_copy(update={"dropped_ticket_digests": 1})
    with pytest.raises(snapshot.AssignmentSnapshotError, match="snapshot_lineage_replay_mismatch"):
        snapshot.replay_snapshot_lineage(current, [], era_boundaries=[forged])


@pytest.mark.parametrize("field", ["assignment_nonces", "ticket_digests", "receipt_digests"])
def test_pending_parser_combined_fact_cap(field: str) -> None:
    lineage, _ = lineage_pair()
    pending = snapshot.begin_snapshot_lineage_era(lineage)
    doc = pending.model_dump(mode="json", by_alias=True)
    doc["era_boundaries"][-1]["dropped_" + field] = snapshot.MAX_LINEAGE_FACTS
    doc["lineage_digest_sha256"] = digest(
        {k: v for k, v in doc.items() if k != "lineage_digest_sha256"}
    )
    with pytest.raises(ValidationError, match="lineage_era_invalid"):
        snapshot.SnapshotLineage.model_validate(doc)
    with pytest.raises(ValueError, match="document_invalid"):
        snapshot.parse_snapshot_lineage(canonical(doc) + b"\n")


def test_report_parser_refuses_foreign_observation_policy() -> None:
    root = Path(__file__).resolve().parents[2]
    doc = json.loads((root / "contracts/fixtures/validator-probe-report.v1.json").read_bytes())
    obs = doc["observations"][0]
    obs["trust_policy_digest_sha256"] = "0" * 64
    obs["observation_digest_sha256"] = digest(
        {k: v for k, v in obs.items() if k != "observation_digest_sha256"}
    )
    doc["observation_vector_digest_sha256"] = digest(doc["observations"])
    doc["report_digest_sha256"] = digest(
        {k: v for k, v in doc.items() if k != "report_digest_sha256"}
    )
    with pytest.raises(ValidationError, match="observation_policy_violation"):
        probe.ValidatorProbeReport.model_validate(doc)
    with pytest.raises(ValueError, match="document_invalid"):
        probe.parse_validator_probe_report(canonical(doc) + b"\n")


def test_historical_verification_is_not_reportable() -> None:
    ctx = make_context()
    verified = probe.verify_historical_active_assignment_manifest(
        ctx.manifest,
        ctx.signatures,
        ctx.policy,
        ctx.state,
        evaluation_epoch=BASE_EPOCH + 4000,
    )
    with pytest.raises(probe.AssignmentProbeError, match="historical_verification_not_reportable"):
        probe.build_validator_probe_report(
            verified,
            ctx.policy,
            ctx.state,
            ctx.observations,
            validator_uid=99,
            validator_hotkey="Validator",
            evaluation_epoch=BASE_EPOCH + 4000,
            edge_origin_override=False,
        )


def test_dns_event_allocation_failure_does_not_leak(monkeypatch: pytest.MonkeyPatch) -> None:
    slots = threading.BoundedSemaphore(1)

    def fail() -> Any:
        raise MemoryError("event allocation")

    monkeypatch.setattr(transport.threading, "Event", fail)
    backend = transport.DeadlineNetworkBackend(lambda: 1.0, resolution_slots=slots)
    with pytest.raises(MemoryError):
        backend._resolve_within_budget("invalid", 1)
    assert slots.acquire(blocking=False)
    slots.release()


def test_dns_started_then_interrupted_keeps_slot(monkeypatch: pytest.MonkeyPatch) -> None:
    slots = threading.BoundedSemaphore(1)
    entered, release = threading.Event(), threading.Event()
    original = threading.Thread.start
    workers: list[threading.Thread] = []

    def resolver(host: str, port: int) -> list[transport.ResolvedAddress]:
        entered.set()
        release.wait(2)
        return []

    def start(worker: threading.Thread) -> None:
        workers.append(worker)
        original(worker)
        assert entered.wait(1)
        raise KeyboardInterrupt

    monkeypatch.setattr(threading.Thread, "start", start)
    backend = transport.DeadlineNetworkBackend(
        lambda: 1.0, resolver=resolver, resolution_slots=slots
    )
    try:
        with pytest.raises(KeyboardInterrupt):
            backend._resolve_within_budget("invalid", 1)
        assert not slots.acquire(blocking=False)
    finally:
        release.set()
        for worker in workers:
            worker.join(2)


def test_dns_startup_consumes_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    original = threading.Thread.start
    release = threading.Event()
    workers: list[threading.Thread] = []

    def start(worker: threading.Thread) -> None:
        workers.append(worker)
        original(worker)
        time.sleep(0.12)

    def resolver(host: str, port: int) -> list[transport.ResolvedAddress]:
        release.wait(2)
        return []

    monkeypatch.setattr(threading.Thread, "start", start)
    started = time.monotonic()
    backend = transport.DeadlineNetworkBackend(
        lambda: max(0.0, started + 0.1 - time.monotonic()), resolver=resolver
    )
    try:
        with pytest.raises(httpcore.ConnectTimeout):
            backend._resolve_within_budget("invalid", 1)
        assert time.monotonic() - started < 0.18
    finally:
        release.set()
        for worker in workers:
            worker.join(2)


def test_httpcore_reviewed_version_is_direct_pin() -> None:
    root = Path(__file__).resolve().parents[2]
    assert '"httpcore==1.0.9"' in (root / "pyproject.toml").read_text()


def churn_history(count: int) -> list[snapshot.ActiveAssignmentSnapshot]:
    from assignment_probe_context import label_digest

    first = build_snapshot()
    deployment = first.deployments[0].model_dump(mode="json")
    original = deployment["replicas"][0]
    captures = []
    for index in range(1, count + 1):
        nonce = label_digest(f"churn-nonce-{index}")[:32]
        replica = {
            **original,
            "generation": index,
            "assignment_nonce": nonce,
            "endpoint_id": f"{original['replica_id']}-g{index}-{nonce}",
            "ticket_digest_sha256": label_digest(f"churn-ticket-{index}"),
            "receipt_digest_sha256": label_digest(f"churn-receipt-{index}"),
        }
        captures.append(
            build_snapshot(
                snapshot_sequence=index,
                state_revision=index + 7,
                snapshot_deployments=[
                    snapshot.SnapshotDeployment.model_validate(
                        {**deployment, "replicas": [replica]}
                    )
                ],
            )
        )
    return captures


def test_growing_replay_work_is_bounded_and_batches_are_exact() -> None:
    captures = churn_history(1200)
    initial = snapshot.build_initial_snapshot_lineage(
        central_authority_fingerprint_sha256=captures[0].central_authority_fingerprint_sha256
    )
    short = snapshot.replay_snapshot_lineage(initial, captures[:300])
    assert len(short.used_ticket_digests) == 300
    with pytest.raises(
        snapshot.AssignmentSnapshotError, match="snapshot_lineage_replay_work_exceeded"
    ):
        snapshot.replay_snapshot_lineage(initial, captures)
    # Batching is explicit, cannot reset the history, and preserves exact hashes.
    current = initial
    for offset in range(0, len(captures), 100):
        current = snapshot.replay_snapshot_lineage(
            current, captures[offset : offset + 100], boundary_mode="suffix"
        )
    sequential = initial
    for capture in captures:
        sequential = snapshot.advance_snapshot_lineage(sequential, capture)
    assert current == sequential and len(current.used_ticket_digests) == 1200
    with pytest.raises(
        snapshot.AssignmentSnapshotError, match="snapshot_lineage_replay_work_exceeded"
    ):
        snapshot.replay_snapshot_lineage(current, [], max_work=100)


def test_replay_full_suffix_and_pending_targets_are_unambiguous() -> None:
    lineage, candidate = lineage_pair()
    first_boundary = snapshot.begin_snapshot_lineage_era(lineage)
    current = snapshot.advance_snapshot_lineage(first_boundary, candidate)
    second_boundary = snapshot.begin_snapshot_lineage_era(current)
    assert (
        snapshot.replay_snapshot_lineage(current, [], era_boundaries=second_boundary.era_boundaries)
        == second_boundary
    )
    assert (
        snapshot.replay_snapshot_lineage(
            current, [], era_boundaries=second_boundary.era_boundaries[1:], boundary_mode="suffix"
        )
        == second_boundary
    )
    for mode, events in (
        ("full", second_boundary.era_boundaries[1:]),
        ("suffix", second_boundary.era_boundaries),
        ("suffix", [second_boundary.era_boundaries[1]] * 2),
    ):
        with pytest.raises(
            snapshot.AssignmentSnapshotError, match="snapshot_lineage_replay_mismatch"
        ):
            snapshot.replay_snapshot_lineage(current, [], era_boundaries=events, boundary_mode=mode)
    pending = snapshot.begin_snapshot_lineage_era(lineage, retain_for=candidate)
    assert (
        snapshot.replay_snapshot_lineage(
            pending, [], era_boundaries=pending.era_boundaries, pending_candidate=candidate
        )
        == pending
    )
    with pytest.raises(snapshot.AssignmentSnapshotError, match="snapshot_lineage_replay_mismatch"):
        snapshot.replay_snapshot_lineage(
            current, [], boundary_mode="suffix", pending_candidate=candidate
        )


@pytest.mark.parametrize(
    "attack,code",
    [
        ("generation", "snapshot_generation_not_increasing"),
        ("reused", "snapshot_incarnation_facts_reused"),
        ("cap", "snapshot_lineage_overflow"),
    ],
)
def test_boundary_full_candidate_rejection_keeps_old_head(attack: str, code: str) -> None:
    captures = churn_history(2)
    initial = snapshot.build_initial_snapshot_lineage(
        central_authority_fingerprint_sha256=captures[0].central_authority_fingerprint_sha256
    )
    current = snapshot.advance_snapshot_lineage(initial, captures[0])
    original_bytes = snapshot.snapshot_lineage_bytes(current)
    deployment = captures[1].deployments[0].model_dump(mode="json")
    replica = deployment["replicas"][0]
    if attack == "generation":
        replica["generation"] = 1
        replica["endpoint_id"] = f"{replica['replica_id']}-g1-{replica['assignment_nonce']}"
    if attack == "reused":
        replica["ticket_digest_sha256"] = (
            captures[0].deployments[0].replicas[0].ticket_digest_sha256
        )
    candidate = build_snapshot(
        snapshot_sequence=2,
        state_revision=9,
        snapshot_deployments=[snapshot.SnapshotDeployment.model_validate(deployment)],
    )
    with pytest.raises(snapshot.AssignmentSnapshotError, match=code):
        snapshot.begin_snapshot_lineage_era(
            current,
            retain_for=candidate,
            max_facts=1 if attack == "cap" else snapshot.MAX_LINEAGE_FACTS,
        )
    assert snapshot.snapshot_lineage_bytes(current) == original_bytes
    good = snapshot.begin_snapshot_lineage_era(current, retain_for=captures[1])
    assert snapshot.advance_snapshot_lineage(good, captures[1]).last_snapshot_sequence == 2


@pytest.mark.parametrize("stage", ["construct", "start", "late_start"])
def test_dns_failure_before_worker_claim_cancels_lease(
    monkeypatch: pytest.MonkeyPatch, stage: str
) -> None:
    slots = threading.BoundedSemaphore(1)
    called = False
    targets: list[Any] = []

    class Worker:
        def __init__(self, *, target: Any, **kwargs: Any) -> None:
            targets.append(target)
            if stage == "construct":
                raise MemoryError("construct")

        def start(self) -> None:
            raise KeyboardInterrupt

    def resolver(host: str, port: int) -> list[transport.ResolvedAddress]:
        nonlocal called
        called = True
        return []

    monkeypatch.setattr(transport.threading, "Thread", Worker)
    backend = transport.DeadlineNetworkBackend(
        lambda: 1.0, resolver=resolver, resolution_slots=slots
    )
    with pytest.raises((MemoryError, KeyboardInterrupt)):
        backend._resolve_within_budget("invalid", 1)
    if stage == "late_start":
        targets[0]()  # launched thread reaches Python only after creator cancellation
    assert not called
    assert slots.acquire(blocking=False)
    assert not slots.acquire(blocking=False)
    slots.release()


def test_dns_signaling_failure_still_releases_once(monkeypatch: pytest.MonkeyPatch) -> None:
    slots = threading.BoundedSemaphore(1)
    real_event = threading.Event
    event = real_event()

    class BrokenSignal:
        def set(self) -> None:
            raise RuntimeError("signal")

        def wait(self, timeout: float) -> bool:
            return False

    class InlineWorker:
        def __init__(self, *, target: Any, **kwargs: Any) -> None:
            self.target = target

        def start(self) -> None:
            self.target()

    monkeypatch.setattr(transport.threading, "Event", BrokenSignal)
    monkeypatch.setattr(transport.threading, "Thread", InlineWorker)
    backend = transport.DeadlineNetworkBackend(
        lambda: 1.0, resolver=lambda host, port: [], resolution_slots=slots
    )
    with pytest.raises(RuntimeError, match="signal"):
        backend._resolve_within_budget("invalid", 1)
    assert slots.acquire(blocking=False)
    assert not slots.acquire(blocking=False)
    slots.release()
    assert not event.is_set()


def test_standalone_scorer_refuses_mutated_policy_report() -> None:
    from misscomputer_subnet.probe_scoring import (
        ProbeRound,
        ProbeScoringError,
        accumulate_scoring_window,
    )

    ctx = make_context()
    report = ctx.report.model_copy(deep=True)
    obs = report.observations[0].model_dump(mode="json", by_alias=True)
    obs["trust_policy_digest_sha256"] = "0" * 64
    obs["observation_digest_sha256"] = digest(
        {key: value for key, value in obs.items() if key != "observation_digest_sha256"}
    )
    report.observations[0] = probe.ProbeObservation.model_validate(obs)
    document = report.model_dump(mode="json", by_alias=True)
    document["observation_vector_digest_sha256"] = digest(document["observations"])
    document["report_digest_sha256"] = digest(
        {key: value for key, value in document.items() if key != "report_digest_sha256"}
    )
    report = report.model_copy(
        update={
            key: document[key]
            for key in ("observation_vector_digest_sha256", "report_digest_sha256")
        }
    )
    with pytest.raises(ProbeScoringError, match="scoring_round_invalid"):
        accumulate_scoring_window(
            [ProbeRound(ctx.manifest, report)],
            validator_uid=ctx.report.validator_uid,
            validator_hotkey=ctx.report.validator_hotkey,
            window_start_epoch=BASE_EPOCH,
            window_end_epoch=BASE_EPOCH + 1000,
        )


def test_default_resolver_pool_is_fresh_in_fork_child() -> None:
    import os

    backend = transport.DeadlineNetworkBackend(lambda: 1.0, resolver=lambda host, port: [])
    pool = transport._RESOLUTION_SLOTS
    for _ in range(transport.MAX_OUTSTANDING_RESOLUTIONS):
        assert pool.acquire(blocking=False)
    try:
        pid = os.fork()
        if pid == 0:
            try:
                backend._resolve_within_budget("invalid", 1)
            except httpcore.ConnectError as error:
                os._exit(0 if str(error) == "name resolved to no addresses" else 1)
            except BaseException:
                os._exit(2)
            os._exit(3)
        _, status = os.waitpid(pid, 0)
        assert os.waitstatus_to_exitcode(status) == 0
        assert not pool.acquire(blocking=False)  # child never releases parent permits
    finally:
        for _ in range(transport.MAX_OUTSTANDING_RESOLUTIONS):
            pool.release()


def test_socket_option_failure_closes_new_socket(monkeypatch: pytest.MonkeyPatch) -> None:
    import socket

    sender, receiver = socket.socketpair()
    backend = transport.DeadlineNetworkBackend(
        lambda: 1.0,
        resolver=lambda host, port: [(socket.AF_INET, socket.SOCK_STREAM, 0, ("127.0.0.1", 1))],
        dialer=lambda address, timeout, local: sender,
    )
    try:
        with pytest.raises(OSError):
            backend.connect_tcp("invalid", 1, socket_options=[(-1, -1, 0)])
        assert sender.fileno() == -1
    finally:
        sender.close()
        receiver.close()


def test_migration_does_not_offer_unsupported_old_report_reprocessing() -> None:
    root = Path(__file__).resolve().parents[2]
    text = (root / "docs/api-migrations.md").read_text()
    assert "reprocess by re-running `decide_weight_submission`" not in text
    assert "Reprocessing retained old-form reports with the new decision API is" in text
    assert "unsupported." in text


def test_sigint_after_admission_cannot_leak_accounting() -> None:
    import os
    import signal

    class InterruptingSlots(threading.BoundedSemaphore):
        def acquire(self, blocking: bool = True, timeout: float | None = None) -> bool:
            acquired = super().acquire(blocking, timeout)
            if acquired:
                os.kill(os.getpid(), signal.SIGINT)
            return acquired

    slots = InterruptingSlots(1)
    backend = transport.DeadlineNetworkBackend(lambda: 1.0, resolution_slots=slots)
    with pytest.raises(KeyboardInterrupt):
        backend._resolve_within_budget("invalid", 1)
    # Use the base method for inspection, without generating another signal.
    assert threading.BoundedSemaphore.acquire(slots, blocking=False)
    assert not threading.BoundedSemaphore.acquire(slots, blocking=False)
    slots.release()
