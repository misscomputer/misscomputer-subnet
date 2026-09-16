# SPDX-License-Identifier: AGPL-3.0-only
"""PR17 round-26 rollback publication-state regressions."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

import pytest
from test_weight_plan import plan

import misscomputer_subnet.weight_plan as weight_plan


def _overwrite_name(
    directory_fd: int,
    name: str,
    body: bytes,
    *,
    substitute: bool = False,
) -> None:
    if substitute:
        os.unlink(name, dir_fd=directory_fd)
    flags = os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC
    if substitute:
        flags |= os.O_CREAT | os.O_EXCL
    descriptor = os.open(
        name,
        flags,
        weight_plan.WEIGHT_PLAN_FILE_MODE,
        dir_fd=directory_fd,
    )
    try:
        os.ftruncate(descriptor, 0)
        offset = 0
        while offset < len(body):
            offset += os.pwrite(descriptor, body[offset:], offset)
    finally:
        os.close(descriptor)


def _select_temporary_kind(
    monkeypatch: pytest.MonkeyPatch,
    temporary_kind: Literal["native", "visible"],
) -> None:
    if temporary_kind == "visible":
        monkeypatch.setattr(weight_plan, "_open_unnamed_temporary", lambda _fd: None)
        return

    real_open_unnamed = weight_plan._open_unnamed_temporary

    def require_unnamed(directory_fd: int) -> int | None:
        descriptor = real_open_unnamed(directory_fd)
        if descriptor is None:
            pytest.skip("O_TMPFILE is unavailable on this filesystem")
        return descriptor

    monkeypatch.setattr(weight_plan, "_open_unnamed_temporary", require_unnamed)


@pytest.mark.parametrize("temporary_kind", ["native", "visible"])
@pytest.mark.parametrize("attack", ["control", "same-inode", "substitution"])
def test_missing_backup_late_change_is_recovered(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    temporary_kind: Literal["native", "visible"],
    attack: Literal["control", "same-inode", "substitution"],
) -> None:
    """R25-INTEGRITY-1: recovery repairs only its last published entry."""

    target = tmp_path / "weight-plan.json"
    original = plan(block=101)
    candidate = plan(block=102)
    attacker = plan(block=103)
    original_bytes = original.canonical_bytes()
    attacker_bytes = attacker.canonical_bytes()
    assert len(original_bytes) == len(attacker_bytes)
    assert weight_plan.write_weight_plan_atomic(original, target) is True
    _select_temporary_kind(monkeypatch, temporary_kind)

    primary = weight_plan.WeightPlanTargetError("post-exchange verification failed")
    real_exchange = weight_plan._rename_exchange
    real_noreplace = weight_plan._rename_noreplace
    real_target_stat = weight_plan._target_stat
    installed = False
    attacked = False

    def remove_candidate_and_corrupt_displaced(
        directory_fd: int,
        source: str,
        destination: str,
    ):
        nonlocal installed
        identity = real_exchange(directory_fd, source, destination)
        if not installed and destination == target.name:
            installed = True
            _overwrite_name(
                directory_fd,
                source,
                b"x" * len(original_bytes),
            )
            os.unlink(destination, dir_fd=directory_fd)
        return identity

    def fail_after_install(directory_fd: int, name: str) -> os.stat_result | None:
        if installed:
            raise primary
        return real_target_stat(directory_fd, name)

    def change_backup_before_missing_publication(
        directory_fd: int,
        source: str,
        destination: str,
    ):
        nonlocal attacked
        if installed and destination == target.name and not attacked:
            attacked = True
            if attack != "control":
                _overwrite_name(
                    directory_fd,
                    source,
                    attacker_bytes,
                    substitute=attack == "substitution",
                )
        return real_noreplace(directory_fd, source, destination)

    monkeypatch.setattr(weight_plan, "_rename_exchange", remove_candidate_and_corrupt_displaced)
    monkeypatch.setattr(
        weight_plan,
        "_rename_noreplace",
        change_backup_before_missing_publication,
    )
    monkeypatch.setattr(weight_plan, "_target_stat", fail_after_install)
    with pytest.raises(weight_plan.WeightPlanTargetError) as caught:
        weight_plan.write_weight_plan_atomic(candidate, target)

    assert caught.value is primary
    assert attacked is True
    assert target.read_bytes() == original_bytes


@pytest.mark.parametrize("temporary_kind", ["native", "visible"])
def test_newly_missing_copy_restore_collision_is_preserved(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    temporary_kind: Literal["native", "visible"],
) -> None:
    """R25-INTEGRITY-2: an EEXIST collision revokes stale exchange authority."""

    target = tmp_path / "weight-plan.json"
    original = plan(block=101)
    candidate = plan(block=102)
    assert weight_plan.write_weight_plan_atomic(original, target) is True
    _select_temporary_kind(monkeypatch, temporary_kind)

    primary = weight_plan.WeightPlanTargetError("post-exchange verification failed")
    foreign_bytes = b"concurrently recreated destination\n"
    real_exchange = weight_plan._rename_exchange
    real_noreplace = weight_plan._rename_noreplace
    real_target_stat = weight_plan._target_stat
    exchange_calls = 0
    installed = False
    collided = False

    def remove_before_direct_rollback_exchange(
        directory_fd: int,
        source: str,
        destination: str,
    ) -> None:
        nonlocal exchange_calls, installed
        exchange_calls += 1
        if exchange_calls == 2:
            os.unlink(destination, dir_fd=directory_fd)
        real_exchange(directory_fd, source, destination)
        if exchange_calls == 1:
            installed = True

    def fail_after_install(directory_fd: int, name: str) -> os.stat_result | None:
        if installed:
            raise primary
        return real_target_stat(directory_fd, name)

    def collide_with_missing_restore(
        directory_fd: int,
        source: str,
        destination: str,
    ) -> None:
        nonlocal collided
        if installed and destination == target.name and not collided:
            descriptor = os.open(
                destination,
                os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                weight_plan.WEIGHT_PLAN_FILE_MODE,
                dir_fd=directory_fd,
            )
            try:
                os.write(descriptor, foreign_bytes)
            finally:
                os.close(descriptor)
            collided = True
        real_noreplace(directory_fd, source, destination)

    monkeypatch.setattr(
        weight_plan,
        "_rename_exchange",
        remove_before_direct_rollback_exchange,
    )
    monkeypatch.setattr(weight_plan, "_rename_noreplace", collide_with_missing_restore)
    monkeypatch.setattr(weight_plan, "_target_stat", fail_after_install)
    with pytest.raises(weight_plan.WeightPlanTargetError) as caught:
        weight_plan.write_weight_plan_atomic(candidate, target)

    assert caught.value is primary
    assert collided is True
    assert target.read_bytes() == foreign_bytes
