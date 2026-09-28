# SPDX-License-Identifier: AGPL-3.0-only
"""Probe transport acceptance cases from the final exact-SHA review."""

from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Any

import httpcore
import pytest

from misscomputer_subnet import probe_transport as transport


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
