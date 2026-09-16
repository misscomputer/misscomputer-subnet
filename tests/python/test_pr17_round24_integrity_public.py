# SPDX-License-Identifier: AGPL-3.0-only
"""PR17 round-24 candidate-byte and rollback-integrity regressions."""

from __future__ import annotations

import errno
import os
import stat
from pathlib import Path
from typing import Literal

import pytest
from test_weight_plan import plan

import misscomputer_subnet.weight_plan as weight_plan


def _overwrite(descriptor: int, body: bytes) -> None:
    os.ftruncate(descriptor, 0)
    offset = 0
    while offset < len(body):
        offset += os.pwrite(descriptor, body[offset:], offset)


@pytest.mark.parametrize("temporary_kind", ["native", "visible"])
@pytest.mark.parametrize("target_existed", [False, True])
@pytest.mark.parametrize("mutate", [False, True], ids=["control", "same-size-mutation"])
def test_candidate_bytes_are_bound_through_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    temporary_kind: Literal["native", "visible"],
    target_existed: bool,
    mutate: bool,
) -> None:
    """CANDIDATE-BYTES: final name validation is not a content boundary."""

    target = tmp_path / "weight-plan.json"
    original = plan(block=101)
    candidate = plan(block=102)
    attacker = plan(block=103)
    original_bytes = original.canonical_bytes()
    candidate_bytes = candidate.canonical_bytes()
    attacker_bytes = attacker.canonical_bytes()
    assert len(candidate_bytes) == len(attacker_bytes)
    if target_existed:
        assert weight_plan.write_weight_plan_atomic(original, target) is True

    if temporary_kind == "visible":
        monkeypatch.setattr(weight_plan, "_open_unnamed_temporary", lambda _fd: None)
    else:
        real_open_unnamed = weight_plan._open_unnamed_temporary

        def require_unnamed(directory_fd: int) -> int | None:
            descriptor = real_open_unnamed(directory_fd)
            if descriptor is None:
                pytest.skip("O_TMPFILE is unavailable on this filesystem")
            return descriptor

        monkeypatch.setattr(weight_plan, "_open_unnamed_temporary", require_unnamed)

    real_validate = weight_plan._validate_temporary_name
    candidate_validations = 0
    mutated = False

    def mutate_after_final_name_validation(
        temporary: weight_plan._TemporaryPlan,
        directory_fd: int,
        *,
        expected_size: int,
    ) -> None:
        nonlocal candidate_validations, mutated
        real_validate(temporary, directory_fd, expected_size=expected_size)
        if os.pread(temporary.descriptor, len(candidate_bytes), 0) != candidate_bytes:
            return
        candidate_validations += 1
        if mutate and candidate_validations == 2:
            _overwrite(temporary.descriptor, attacker_bytes)
            mutated = True

    monkeypatch.setattr(
        weight_plan,
        "_validate_temporary_name",
        mutate_after_final_name_validation,
    )

    if mutate:
        with pytest.raises(weight_plan.WeightPlanTargetError):
            weight_plan.write_weight_plan_atomic(candidate, target)
        assert mutated is True
        if target_existed:
            assert target.read_bytes() == original_bytes
        else:
            assert not target.exists()
    else:
        assert weight_plan.write_weight_plan_atomic(candidate, target) is True
        assert target.read_bytes() == candidate_bytes


@pytest.mark.parametrize("attack", ["same-inode", "substitution"])
def test_late_direct_rollback_source_change_uses_pristine_copy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    attack: Literal["same-inode", "substitution"],
) -> None:
    """ROLLBACK-1: a change at the restoring exchange cannot become canonical."""

    target = tmp_path / "weight-plan.json"
    original = plan(block=101)
    candidate = plan(block=102)
    attacker_bytes = plan(block=103).canonical_bytes()
    assert len(original.canonical_bytes()) == len(attacker_bytes)
    assert weight_plan.write_weight_plan_atomic(original, target) is True

    primary = weight_plan.WeightPlanTargetError("post-exchange verification failed")
    real_exchange = weight_plan._rename_exchange
    exchange_calls = 0
    attacked = False

    def attack_restoring_source(directory_fd: int, source: str, destination: str):
        nonlocal exchange_calls, attacked
        exchange_calls += 1
        if exchange_calls == 2:
            attacked = True
            if attack == "same-inode":
                descriptor = os.open(
                    source,
                    os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW,
                    dir_fd=directory_fd,
                )
                try:
                    _overwrite(descriptor, attacker_bytes)
                finally:
                    os.close(descriptor)
            else:
                os.unlink(source, dir_fd=directory_fd)
                descriptor = os.open(
                    source,
                    os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                    weight_plan.WEIGHT_PLAN_FILE_MODE,
                    dir_fd=directory_fd,
                )
                try:
                    _overwrite(descriptor, attacker_bytes)
                finally:
                    os.close(descriptor)
        return real_exchange(directory_fd, source, destination)

    installed = False
    real_target_stat = weight_plan._target_stat

    def mark_initial_exchange(directory_fd: int, source: str, destination: str):
        nonlocal installed
        identity = attack_restoring_source(directory_fd, source, destination)
        if destination == target.name and exchange_calls == 1:
            installed = True
        return identity

    def fail_post_exchange(
        directory_fd: int,
        name: str,
    ) -> os.stat_result | None:
        if installed:
            raise primary
        return real_target_stat(directory_fd, name)

    monkeypatch.setattr(weight_plan, "_rename_exchange", mark_initial_exchange)
    monkeypatch.setattr(weight_plan, "_target_stat", fail_post_exchange)
    with pytest.raises(weight_plan.WeightPlanTargetError) as caught:
        weight_plan.write_weight_plan_atomic(candidate, target)

    assert caught.value is primary
    assert attacked is True
    assert target.read_bytes() == original.canonical_bytes()


@pytest.mark.parametrize("attack", ["same-inode", "substitution"])
def test_late_backup_rollback_source_change_is_recovered(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    attack: Literal["same-inode", "substitution"],
) -> None:
    """ROLLBACK-1: the independent rollback source is verified after exchange."""

    target = tmp_path / "weight-plan.json"
    original = plan(block=101)
    candidate = plan(block=102)
    attacker_bytes = plan(block=103).canonical_bytes()
    assert len(original.canonical_bytes()) == len(attacker_bytes)
    assert weight_plan.write_weight_plan_atomic(original, target) is True

    primary = weight_plan.WeightPlanTargetError("post-exchange verification failed")
    real_exchange = weight_plan._rename_exchange
    real_target_stat = weight_plan._target_stat
    exchange_calls = 0
    installed = False
    attacked = False

    def exchange(directory_fd: int, source: str, destination: str):
        nonlocal exchange_calls, installed, attacked
        exchange_calls += 1
        if exchange_calls == 2:
            attacked = True
            if attack == "same-inode":
                descriptor = os.open(
                    source,
                    os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW,
                    dir_fd=directory_fd,
                )
                try:
                    _overwrite(descriptor, attacker_bytes)
                finally:
                    os.close(descriptor)
            else:
                os.unlink(source, dir_fd=directory_fd)
                descriptor = os.open(
                    source,
                    os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                    weight_plan.WEIGHT_PLAN_FILE_MODE,
                    dir_fd=directory_fd,
                )
                try:
                    _overwrite(descriptor, attacker_bytes)
                finally:
                    os.close(descriptor)
        identity = real_exchange(directory_fd, source, destination)
        if exchange_calls == 1:
            installed = True
            descriptor = os.open(
                source,
                os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=directory_fd,
            )
            try:
                _overwrite(descriptor, b"x" * len(original.canonical_bytes()))
            finally:
                os.close(descriptor)
        return identity

    def fail_post_exchange(
        directory_fd: int,
        name: str,
    ) -> os.stat_result | None:
        if installed:
            raise primary
        return real_target_stat(directory_fd, name)

    monkeypatch.setattr(weight_plan, "_rename_exchange", exchange)
    monkeypatch.setattr(weight_plan, "_target_stat", fail_post_exchange)
    with pytest.raises(weight_plan.WeightPlanTargetError) as caught:
        weight_plan.write_weight_plan_atomic(candidate, target)

    assert caught.value is primary
    assert attacked is True
    assert target.read_bytes() == original.canonical_bytes()


def test_restoring_exchange_is_followed_by_directory_fsync(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ROLLBACK-2: rejection durably restores the pre-install directory entry."""

    target = tmp_path / "weight-plan.json"
    original = plan(block=101)
    candidate = plan(block=102)
    assert weight_plan.write_weight_plan_atomic(original, target) is True

    primary = weight_plan.WeightPlanTargetError("post-exchange verification failed")
    real_exchange = weight_plan._rename_exchange
    real_target_stat = weight_plan._target_stat
    real_fsync = os.fsync
    exchange_calls = 0
    installed = False
    rollback_exchange_seen = False
    rollback_directory_fsync_seen = False

    def exchange(directory_fd: int, source: str, destination: str) -> None:
        nonlocal exchange_calls, installed, rollback_exchange_seen
        exchange_calls += 1
        real_exchange(directory_fd, source, destination)
        if exchange_calls == 1:
            installed = True
        elif destination == target.name:
            rollback_exchange_seen = True

    def fail_post_exchange(
        directory_fd: int,
        name: str,
    ) -> os.stat_result | None:
        if installed:
            raise primary
        return real_target_stat(directory_fd, name)

    def fsync(descriptor: int) -> None:
        nonlocal rollback_directory_fsync_seen
        if rollback_exchange_seen and stat.S_ISDIR(os.fstat(descriptor).st_mode):
            rollback_directory_fsync_seen = True
        real_fsync(descriptor)

    monkeypatch.setattr(weight_plan, "_rename_exchange", exchange)
    monkeypatch.setattr(weight_plan, "_target_stat", fail_post_exchange)
    monkeypatch.setattr(os, "fsync", fsync)
    with pytest.raises(weight_plan.WeightPlanTargetError) as caught:
        weight_plan.write_weight_plan_atomic(candidate, target)

    assert caught.value is primary
    assert rollback_exchange_seen is True
    assert rollback_directory_fsync_seen is True
    assert target.read_bytes() == original.canonical_bytes()


def test_backup_restoring_exchange_is_followed_by_directory_fsync(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ROLLBACK-2: recovery-copy exchange is durable before later inspection."""

    target = tmp_path / "weight-plan.json"
    original = plan(block=101)
    candidate = plan(block=102)
    assert weight_plan.write_weight_plan_atomic(original, target) is True

    primary = weight_plan.WeightPlanTargetError("post-exchange verification failed")
    real_exchange = weight_plan._rename_exchange
    real_target_stat = weight_plan._target_stat
    real_fsync = os.fsync
    exchange_calls = 0
    installed = False
    rollback_exchange_seen = False
    rollback_directory_fsync_seen = False

    def exchange(directory_fd: int, source: str, destination: str) -> None:
        nonlocal exchange_calls, installed, rollback_exchange_seen
        exchange_calls += 1
        real_exchange(directory_fd, source, destination)
        if exchange_calls == 1:
            installed = True
            descriptor = os.open(
                source,
                os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=directory_fd,
            )
            try:
                _overwrite(descriptor, b"x" * len(original.canonical_bytes()))
            finally:
                os.close(descriptor)
        elif destination == target.name:
            rollback_exchange_seen = True

    def fail_post_exchange(
        directory_fd: int,
        name: str,
    ) -> os.stat_result | None:
        if installed:
            raise primary
        return real_target_stat(directory_fd, name)

    def fsync(descriptor: int) -> None:
        nonlocal rollback_directory_fsync_seen
        if rollback_exchange_seen and stat.S_ISDIR(os.fstat(descriptor).st_mode):
            rollback_directory_fsync_seen = True
        real_fsync(descriptor)

    monkeypatch.setattr(weight_plan, "_rename_exchange", exchange)
    monkeypatch.setattr(weight_plan, "_target_stat", fail_post_exchange)
    monkeypatch.setattr(os, "fsync", fsync)
    with pytest.raises(weight_plan.WeightPlanTargetError) as caught:
        weight_plan.write_weight_plan_atomic(candidate, target)

    assert caught.value is primary
    assert rollback_exchange_seen is True
    assert rollback_directory_fsync_seen is True
    assert target.read_bytes() == original.canonical_bytes()


def test_replaced_destination_restoring_exchange_is_followed_by_directory_fsync(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ROLLBACK-2: restoring a raced foreign destination is also durable."""

    target = tmp_path / "weight-plan.json"
    original = plan(block=101)
    candidate = plan(block=102)
    victim = tmp_path / "victim"
    victim.write_bytes(b"foreign victim\n")
    assert weight_plan.write_weight_plan_atomic(original, target) is True

    real_exchange = weight_plan._rename_exchange
    real_fsync = os.fsync
    exchange_calls = 0
    rollback_exchange_seen = False
    rollback_directory_fsync_seen = False

    def exchange(directory_fd: int, source: str, destination: str) -> None:
        nonlocal exchange_calls, rollback_exchange_seen
        exchange_calls += 1
        if exchange_calls == 1:
            os.unlink(destination, dir_fd=directory_fd)
            os.symlink(victim, destination, dir_fd=directory_fd)
        result = real_exchange(directory_fd, source, destination)
        if exchange_calls == 2:
            rollback_exchange_seen = True
        return result

    def fsync(descriptor: int) -> None:
        nonlocal rollback_directory_fsync_seen
        if rollback_exchange_seen and stat.S_ISDIR(os.fstat(descriptor).st_mode):
            rollback_directory_fsync_seen = True
        real_fsync(descriptor)

    monkeypatch.setattr(weight_plan, "_rename_exchange", exchange)
    monkeypatch.setattr(os, "fsync", fsync)
    with pytest.raises(weight_plan.WeightPlanTargetError):
        weight_plan.write_weight_plan_atomic(candidate, target)

    assert rollback_exchange_seen is True
    assert rollback_directory_fsync_seen is True
    assert target.read_bytes() == original.canonical_bytes()
    assert victim.read_bytes() == b"foreign victim\n"


def test_rollback_fsync_failure_preserves_exact_primary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ROLLBACK-2 control: durability diagnostics cannot replace the rejection."""

    target = tmp_path / "weight-plan.json"
    original = plan(block=101)
    candidate = plan(block=102)
    assert weight_plan.write_weight_plan_atomic(original, target) is True

    primary = weight_plan.WeightPlanTargetError("post-exchange verification failed")
    secondary = OSError(errno.EIO, "rollback directory fsync failed")
    real_exchange = weight_plan._rename_exchange
    real_target_stat = weight_plan._target_stat
    real_fsync = os.fsync
    exchange_calls = 0
    installed = False
    rollback_exchange_seen = False

    def exchange(directory_fd: int, source: str, destination: str) -> None:
        nonlocal exchange_calls, installed, rollback_exchange_seen
        exchange_calls += 1
        real_exchange(directory_fd, source, destination)
        if exchange_calls == 1:
            installed = True
        elif destination == target.name:
            rollback_exchange_seen = True

    def fail_post_exchange(
        directory_fd: int,
        name: str,
    ) -> os.stat_result | None:
        if installed:
            raise primary
        return real_target_stat(directory_fd, name)

    def fsync(descriptor: int) -> None:
        if rollback_exchange_seen and stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise secondary
        real_fsync(descriptor)

    monkeypatch.setattr(weight_plan, "_rename_exchange", exchange)
    monkeypatch.setattr(weight_plan, "_target_stat", fail_post_exchange)
    monkeypatch.setattr(os, "fsync", fsync)
    with pytest.raises(weight_plan.WeightPlanTargetError) as caught:
        weight_plan.write_weight_plan_atomic(candidate, target)

    assert caught.value is primary
    assert "atomic_replacement_rollback_fsync_failed" in getattr(primary, "__notes__", ())
    assert target.read_bytes() == original.canonical_bytes()
