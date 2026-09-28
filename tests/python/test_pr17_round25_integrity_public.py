# SPDX-License-Identifier: AGPL-3.0-only
"""PR17 round-25 terminal publication and missing-target rollback regressions."""

from __future__ import annotations

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
@pytest.mark.parametrize("target_existed", [False, True], ids=["creation", "replacement"])
def test_final_validation_failure_rolls_back_candidate_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    temporary_kind: Literal["native", "visible"],
    target_existed: bool,
) -> None:
    """INTEGRITY-1: rollback state survives the caller's final validation."""

    target = tmp_path / "weight-plan.json"
    original = plan(block=101)
    candidate = plan(block=102)
    attacker_bytes = plan(block=103).canonical_bytes()
    candidate_bytes = candidate.canonical_bytes()
    assert len(candidate_bytes) == len(attacker_bytes)
    if target_existed:
        assert weight_plan.write_weight_plan_atomic(original, target) is True

    _select_temporary_kind(monkeypatch, temporary_kind)
    real_validate = weight_plan._validate_installed_temporary
    successful_internal_validations = 0
    mutated = False

    def mutate_after_second_internal_validation(
        temporary: weight_plan._TemporaryPlan,
        directory_fd: int,
        name: str,
        *,
        expected: bytes,
    ) -> None:
        nonlocal successful_internal_validations, mutated
        real_validate(
            temporary,
            directory_fd,
            name,
            expected=expected,
        )
        if expected != candidate_bytes:
            return
        successful_internal_validations += 1
        if successful_internal_validations == 2:
            _overwrite(temporary.descriptor, attacker_bytes)
            mutated = True

    monkeypatch.setattr(
        weight_plan,
        "_validate_installed_temporary",
        mutate_after_second_internal_validation,
    )

    with pytest.raises(weight_plan.WeightPlanTargetError):
        weight_plan.write_weight_plan_atomic(candidate, target)

    assert mutated is True
    if target_existed:
        assert target.read_bytes() == original.canonical_bytes()
    else:
        assert not target.exists()


@pytest.mark.parametrize("temporary_kind", ["native", "visible"])
def test_removed_replacement_destination_is_restored_without_replace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    temporary_kind: Literal["native", "visible"],
) -> None:
    """INTEGRITY-2: a missing destination is durably restored from pristine state."""

    target = tmp_path / "weight-plan.json"
    original = plan(block=101)
    candidate = plan(block=102)
    assert weight_plan.write_weight_plan_atomic(original, target) is True
    _select_temporary_kind(monkeypatch, temporary_kind)

    primary = weight_plan.WeightPlanTargetError("post-exchange verification failed")
    real_exchange = weight_plan._rename_exchange
    real_target_stat = weight_plan._target_stat
    real_fsync = os.fsync
    removed = False
    rollback_directory_fsync_seen = False

    def remove_installed_destination(
        directory_fd: int,
        source: str,
        destination: str,
    ) -> None:
        nonlocal removed
        real_exchange(directory_fd, source, destination)
        if destination == target.name and not removed:
            os.unlink(destination, dir_fd=directory_fd)
            removed = True

    def fail_after_removal(directory_fd: int, name: str) -> os.stat_result | None:
        if removed:
            raise primary
        return real_target_stat(directory_fd, name)

    def fsync(descriptor: int) -> None:
        nonlocal rollback_directory_fsync_seen
        if removed and stat.S_ISDIR(os.fstat(descriptor).st_mode):
            rollback_directory_fsync_seen = True
        real_fsync(descriptor)

    monkeypatch.setattr(weight_plan, "_rename_exchange", remove_installed_destination)
    monkeypatch.setattr(weight_plan, "_target_stat", fail_after_removal)
    monkeypatch.setattr(os, "fsync", fsync)
    with pytest.raises(weight_plan.WeightPlanTargetError) as caught:
        weight_plan.write_weight_plan_atomic(candidate, target)

    assert caught.value is primary
    assert removed is True
    assert rollback_directory_fsync_seen is True
    assert target.read_bytes() == original.canonical_bytes()


@pytest.mark.parametrize("temporary_kind", ["native", "visible"])
def test_missing_destination_rollback_does_not_replace_collision(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    temporary_kind: Literal["native", "visible"],
) -> None:
    """INTEGRITY-2: no-replace recovery preserves a concurrently recreated name."""

    target = tmp_path / "weight-plan.json"
    original = plan(block=101)
    candidate = plan(block=102)
    assert weight_plan.write_weight_plan_atomic(original, target) is True
    _select_temporary_kind(monkeypatch, temporary_kind)

    primary = weight_plan.WeightPlanTargetError("post-exchange verification failed")
    foreign_bytes = b"concurrent foreign destination\n"
    real_exchange = weight_plan._rename_exchange
    real_noreplace = weight_plan._rename_noreplace
    real_target_stat = weight_plan._target_stat
    removed = False
    collided = False
    foreign_descriptor = -1

    def remove_installed_destination(
        directory_fd: int,
        source: str,
        destination: str,
    ) -> None:
        nonlocal removed
        real_exchange(directory_fd, source, destination)
        if destination == target.name and not removed:
            os.unlink(destination, dir_fd=directory_fd)
            removed = True

    def fail_after_removal(directory_fd: int, name: str) -> os.stat_result | None:
        if removed:
            raise primary
        return real_target_stat(directory_fd, name)

    def collide_with_missing_restore(
        directory_fd: int,
        source: str,
        destination: str,
    ) -> None:
        nonlocal collided, foreign_descriptor
        if removed and destination == target.name and not collided:
            foreign_descriptor = os.open(
                destination,
                os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                weight_plan.WEIGHT_PLAN_FILE_MODE,
                dir_fd=directory_fd,
            )
            os.write(foreign_descriptor, foreign_bytes)
            collided = True
        real_noreplace(directory_fd, source, destination)

    try:
        monkeypatch.setattr(weight_plan, "_rename_exchange", remove_installed_destination)
        monkeypatch.setattr(weight_plan, "_rename_noreplace", collide_with_missing_restore)
        monkeypatch.setattr(weight_plan, "_target_stat", fail_after_removal)
        with pytest.raises(weight_plan.WeightPlanTargetError) as caught:
            weight_plan.write_weight_plan_atomic(candidate, target)

        assert caught.value is primary
        assert removed is True
        assert collided is True
        assert target.read_bytes() == foreign_bytes
    finally:
        if foreign_descriptor >= 0:
            os.close(foreign_descriptor)
