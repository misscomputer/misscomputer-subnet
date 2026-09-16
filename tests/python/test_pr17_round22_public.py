# SPDX-License-Identifier: AGPL-3.0-only
"""PR17 round-22 writer, source-binding, and cleanup regressions."""

from __future__ import annotations

import errno
import fcntl
import hashlib
import os
import stat
import threading
from collections import Counter
from pathlib import Path

import pytest
from test_weight_plan import plan

import misscomputer_subnet.weight_plan as weight_plan


def _lock_name(target_name: str) -> str:
    digest = hashlib.sha256(os.fsencode(target_name)).hexdigest()
    return f".weight-plan.lock-{digest}"


def _open_lock(directory_fd: int, target_name: str) -> int:
    return os.open(
        _lock_name(target_name),
        os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW,
        weight_plan.WEIGHT_PLAN_FILE_MODE,
        dir_fd=directory_fd,
    )


def test_late_cleanup_replacement_waits_for_writer_ownership(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """RACE-1: a cooperating replacement cannot enter a final check/unlink gap."""

    target = tmp_path / "weight-plan.json"
    original = plan(block=101)
    candidate = plan(block=102)
    assert weight_plan.write_weight_plan_atomic(original, target) is True

    real_matches = weight_plan._temporary_name_matches
    source_observations: Counter[str] = Counter()
    replacement_start = threading.Event()
    lock_decided = threading.Event()
    replacement_ready = threading.Event()
    state: dict[str, object] = {}
    thread_errors: list[BaseException] = []
    foreign_descriptor = -1

    def cooperating_replacement() -> None:
        nonlocal foreign_descriptor
        directory_fd = -1
        lock_descriptor = -1
        try:
            assert replacement_start.wait(timeout=5)
            source = state["source"]
            assert isinstance(source, str)
            directory_fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            lock_descriptor = _open_lock(directory_fd, target.name)
            try:
                fcntl.flock(lock_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                if exc.errno not in {errno.EACCES, errno.EAGAIN}:
                    raise
                state["blocked"] = True
                lock_decided.set()
                fcntl.flock(lock_descriptor, fcntl.LOCK_EX)
            else:
                state["blocked"] = False
                lock_decided.set()

            try:
                os.unlink(source, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
            foreign_descriptor = os.open(
                source,
                os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                weight_plan.WEIGHT_PLAN_FILE_MODE,
                dir_fd=directory_fd,
            )
            os.write(foreign_descriptor, b"cooperating late replacement\n")
            replacement_ready.set()
        except BaseException as exc:
            thread_errors.append(exc)
            lock_decided.set()
            replacement_ready.set()
        finally:
            if lock_descriptor >= 0:
                os.close(lock_descriptor)
            if directory_fd >= 0:
                os.close(directory_fd)

    worker = threading.Thread(target=cooperating_replacement, daemon=True)
    worker.start()

    def match_then_contend(
        directory_fd: int,
        name: str,
        identity: tuple[int, int],
    ) -> bool:
        matched = real_matches(directory_fd, name, identity)
        if name.startswith(".weight-plan.tmp-"):
            source_observations[name] += 1
            if matched and source_observations[name] == 1 and not replacement_start.is_set():
                state["source"] = name
                replacement_start.set()
                assert lock_decided.wait(timeout=5)
                if state.get("blocked") is False:
                    assert replacement_ready.wait(timeout=5)
        return matched

    try:
        monkeypatch.setattr(weight_plan, "_temporary_name_matches", match_then_contend)
        assert weight_plan.write_weight_plan_atomic(candidate, target) is True
        worker.join(timeout=5)

        assert not worker.is_alive()
        assert not thread_errors
        assert state["blocked"] is True
        assert replacement_ready.is_set()
        assert foreign_descriptor >= 0
        foreign_stat = os.fstat(foreign_descriptor)
        replacement = tmp_path / str(state["source"])
        assert foreign_stat.st_nlink == 1
        assert replacement.read_bytes() == b"cooperating late replacement\n"
        assert replacement.stat().st_ino == foreign_stat.st_ino
        lock_stat = (tmp_path / _lock_name(target.name)).stat()
        assert stat.S_IMODE(lock_stat.st_mode) == weight_plan.WEIGHT_PLAN_FILE_MODE
        assert lock_stat.st_nlink == 1
    finally:
        replacement_start.set()
        worker.join(timeout=5)
        if foreign_descriptor >= 0:
            os.close(foreign_descriptor)


def test_completed_concurrent_writer_is_not_undone_by_stale_rollback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """RACE-2: rollback completes before a cooperating successor can install."""

    target = tmp_path / "weight-plan.json"
    original = plan(block=101)
    candidate_a = plan(block=102)
    candidate_b = plan(block=103)
    assert weight_plan.write_weight_plan_atomic(original, target) is True

    main_thread = threading.get_ident()
    primary = weight_plan.WeightPlanTargetError("writer A post-exchange verification failure")
    real_exchange = weight_plan._rename_exchange
    real_target_stat = weight_plan._target_stat
    real_unvalidated_stat = weight_plan._unvalidated_target_stat
    installed_a = False
    fault_fired = False
    writer_started = False
    lock_decided = threading.Event()
    writer_done = threading.Event()
    state: dict[str, object] = {}
    thread_errors: list[BaseException] = []

    def writer_b() -> None:
        directory_fd = -1
        lock_descriptor = -1
        try:
            directory_fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            lock_descriptor = _open_lock(directory_fd, target.name)
            try:
                fcntl.flock(lock_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                if exc.errno not in {errno.EACCES, errno.EAGAIN}:
                    raise
                state["blocked"] = True
            else:
                state["blocked"] = False
            finally:
                lock_decided.set()
                if lock_descriptor >= 0:
                    os.close(lock_descriptor)
                    lock_descriptor = -1
            state["writer_result"] = weight_plan.write_weight_plan_atomic(candidate_b, target)
        except BaseException as exc:
            thread_errors.append(exc)
        finally:
            if lock_descriptor >= 0:
                os.close(lock_descriptor)
            if directory_fd >= 0:
                os.close(directory_fd)
            writer_done.set()

    worker = threading.Thread(target=writer_b, daemon=True)

    def exchange(directory_fd: int, source: str, destination: str) -> None:
        nonlocal installed_a
        real_exchange(directory_fd, source, destination)
        if threading.get_ident() == main_thread and destination == target.name:
            installed_a = True

    def target_stat(directory_fd: int, name: str) -> os.stat_result | None:
        nonlocal fault_fired
        if threading.get_ident() == main_thread and installed_a and not fault_fired:
            fault_fired = True
            raise primary
        return real_target_stat(directory_fd, name)

    def unvalidated_stat(directory_fd: int, name: str) -> os.stat_result | None:
        nonlocal writer_started
        value = real_unvalidated_stat(directory_fd, name)
        if threading.get_ident() == main_thread and name == target.name and not writer_started:
            writer_started = True
            worker.start()
            assert lock_decided.wait(timeout=5)
            if state.get("blocked") is False:
                assert writer_done.wait(timeout=5)
        return value

    try:
        monkeypatch.setattr(weight_plan, "_rename_exchange", exchange)
        monkeypatch.setattr(weight_plan, "_target_stat", target_stat)
        monkeypatch.setattr(weight_plan, "_unvalidated_target_stat", unvalidated_stat)
        with pytest.raises(weight_plan.WeightPlanTargetError) as caught:
            weight_plan.write_weight_plan_atomic(candidate_a, target)

        assert caught.value is primary
        assert writer_started is True
        assert writer_done.wait(timeout=5)
        worker.join(timeout=5)
        assert not worker.is_alive()
        assert not thread_errors
        assert state["blocked"] is True
        assert state["writer_result"] is True
        assert target.read_bytes() == candidate_b.canonical_bytes()
        assert not any(
            path.is_file()
            and path.name.startswith(".weight-plan.tmp-")
            and path.read_bytes() == candidate_b.canonical_bytes()
            for path in tmp_path.iterdir()
        )
    finally:
        if worker.ident is not None:
            worker.join(timeout=5)


def test_source_substitution_is_rejected_and_original_target_is_restored(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """RACE-3: a substituted exchange source never remains installed."""

    target = tmp_path / "weight-plan.json"
    original = plan(block=101)
    candidate = plan(block=102)
    assert weight_plan.write_weight_plan_atomic(original, target) is True

    real_exchange = weight_plan._rename_exchange
    foreign_descriptor = -1
    source_name: str | None = None
    raced = False

    def substitute_source(directory_fd: int, source: str, destination: str) -> None:
        nonlocal foreign_descriptor, source_name, raced
        if destination == target.name and not raced:
            raced = True
            source_name = source
            os.unlink(source, dir_fd=directory_fd)
            foreign_descriptor = os.open(
                source,
                os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                weight_plan.WEIGHT_PLAN_FILE_MODE,
                dir_fd=directory_fd,
            )
            os.write(foreign_descriptor, b"foreign substituted source\n")
        real_exchange(directory_fd, source, destination)

    try:
        monkeypatch.setattr(weight_plan, "_rename_exchange", substitute_source)
        with pytest.raises(weight_plan.WeightPlanTargetError) as caught:
            weight_plan.write_weight_plan_atomic(candidate, target)

        assert raced is True
        assert "rollback_failed" not in " ".join(getattr(caught.value, "__notes__", ()))
        assert target.read_bytes() == original.canonical_bytes()
        assert source_name is not None
        replacement = tmp_path / source_name
        assert replacement.read_bytes() == b"foreign substituted source\n"
        assert foreign_descriptor >= 0
        foreign_stat = os.fstat(foreign_descriptor)
        assert foreign_stat.st_nlink == 1
        assert replacement.stat().st_ino == foreign_stat.st_ino
        assert stat.S_IMODE(replacement.stat().st_mode) == weight_plan.WEIGHT_PLAN_FILE_MODE
    finally:
        if foreign_descriptor >= 0:
            os.close(foreign_descriptor)


def test_capability_limited_cleanup_retires_displaced_plan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """RACE-4: ``ENOENT`` from capability-limited linkat is not retirement."""

    target = tmp_path / "weight-plan.json"
    original = plan(block=101)
    replacement = plan(block=102)
    assert weight_plan.write_weight_plan_atomic(original, target) is True
    proc_links: list[str] = []

    def capability_limited_link(
        _descriptor: int,
        _directory_fd: int,
        name: str,
    ) -> None:
        raise OSError(errno.ENOENT, os.strerror(errno.ENOENT), name)

    def record_proc_link(descriptor: int, directory_fd: int, name: str) -> None:
        proc_links.append(name)

    monkeypatch.setattr(weight_plan, "_link_unnamed_temporary", capability_limited_link)
    monkeypatch.setattr(weight_plan, "_link_temporary_through_proc", record_proc_link)

    assert weight_plan.write_weight_plan_atomic(replacement, target) is True
    assert not proc_links
    assert target.read_bytes() == replacement.canonical_bytes()
    assert stat.S_IMODE(target.stat().st_mode) == weight_plan.WEIGHT_PLAN_FILE_MODE
    assert target.stat().st_nlink == 1
    assert not list(tmp_path.glob(".weight-plan.tmp-*"))
    assert list(tmp_path.glob(".weight-plan.cleanup-*"))


def test_unavailable_descriptor_linking_does_not_block_private_retirement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A live displaced inode is never mistaken for an already-retired inode."""

    target = tmp_path / "weight-plan.json"
    original = plan(block=101)
    replacement = plan(block=102)
    assert weight_plan.write_weight_plan_atomic(original, target) is True

    def capability_limited_link(
        _descriptor: int,
        _directory_fd: int,
        name: str,
    ) -> None:
        raise OSError(errno.ENOENT, os.strerror(errno.ENOENT), name)

    def unavailable_fallback(
        _descriptor: int,
        _directory_fd: int,
        _name: str,
    ) -> None:
        raise OSError(errno.EACCES, "procfs descriptor link denied")

    monkeypatch.setattr(weight_plan, "_link_unnamed_temporary", capability_limited_link)
    monkeypatch.setattr(weight_plan, "_link_temporary_through_proc", unavailable_fallback)

    assert weight_plan.write_weight_plan_atomic(replacement, target) is True
    assert target.read_bytes() == replacement.canonical_bytes()
    assert not list(tmp_path.glob(".weight-plan.tmp-*"))
    assert list(tmp_path.glob(".weight-plan.cleanup-*"))
