# SPDX-License-Identifier: AGPL-3.0-only
"""PR17 round-27 rollback authority and durability regressions."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest
from test_weight_plan import plan

import misscomputer_subnet.weight_plan as weight_plan


def _replace_name(directory_fd: int, name: str, body: bytes) -> None:
    os.unlink(name, dir_fd=directory_fd)
    descriptor = os.open(
        name,
        os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        weight_plan.WEIGHT_PLAN_FILE_MODE,
        dir_fd=directory_fd,
    )
    try:
        os.write(descriptor, body)
    finally:
        os.close(descriptor)


def test_rollback_does_not_adopt_and_exchange_foreign_canonical_entry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R26-INTEGRITY-1: exchange authority comes only from our publication."""

    target = tmp_path / "weight-plan.json"
    original = plan(block=101)
    candidate = plan(block=102)
    foreign_bytes = plan(block=103).canonical_bytes()
    assert weight_plan.write_weight_plan_atomic(original, target) is True

    primary = weight_plan.WeightPlanTargetError("post-publication observation failed")
    real_exchange = weight_plan._rename_exchange
    real_target_stat = weight_plan._target_stat
    installed = False

    def substitute_after_install(directory_fd: int, source: str, destination: str) -> None:
        nonlocal installed
        real_exchange(directory_fd, source, destination)
        if destination == target.name and not installed:
            installed = True
            _replace_name(directory_fd, destination, foreign_bytes)

    def fail_after_substitution(directory_fd: int, name: str) -> os.stat_result | None:
        if installed:
            raise primary
        return real_target_stat(directory_fd, name)

    monkeypatch.setattr(weight_plan, "_rename_exchange", substitute_after_install)
    monkeypatch.setattr(weight_plan, "_target_stat", fail_after_substitution)

    with pytest.raises(weight_plan.WeightPlanTargetError) as caught:
        weight_plan.write_weight_plan_atomic(candidate, target)

    assert caught.value is primary
    assert target.read_bytes() == foreign_bytes


def test_restoring_mutation_fsync_survives_publication_bookkeeping_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R26-INTEGRITY-2: every successful restoring mutation reaches fsync."""

    target = tmp_path / "weight-plan.json"
    original = plan(block=101)
    candidate = plan(block=102)
    assert weight_plan.write_weight_plan_atomic(original, target) is True

    primary = weight_plan.WeightPlanTargetError("force rollback")
    bookkeeping = RuntimeError("publication bookkeeping failed")
    real_exchange = weight_plan._rename_exchange
    real_validate = weight_plan._validate_installed_temporary
    real_fsync = os.fsync
    exchange_count = 0
    rollback_mutated = False
    rollback_fsync_seen = False

    def count_exchange(directory_fd: int, source: str, destination: str) -> None:
        nonlocal exchange_count, rollback_mutated
        real_exchange(directory_fd, source, destination)
        exchange_count += 1
        if exchange_count == 2:
            rollback_mutated = True

    def fail_candidate_validation(*args: object, expected: bytes, **kwargs: object) -> None:
        if expected == candidate.canonical_bytes():
            raise primary
        real_validate(*args, expected=expected, **kwargs)  # type: ignore[arg-type]

    def fail_bookkeeping(*_args: object, **_kwargs: object) -> None:
        raise bookkeeping

    def observe_fsync(descriptor: int) -> None:
        nonlocal rollback_fsync_seen
        if rollback_mutated and stat.S_ISDIR(os.fstat(descriptor).st_mode):
            rollback_fsync_seen = True
        real_fsync(descriptor)

    monkeypatch.setattr(weight_plan, "_rename_exchange", count_exchange)
    monkeypatch.setattr(weight_plan, "_validate_installed_temporary", fail_candidate_validation)
    monkeypatch.setattr(weight_plan, "_record_rollback_publication", fail_bookkeeping)
    monkeypatch.setattr(os, "fsync", observe_fsync)

    with pytest.raises(weight_plan.WeightPlanTargetError) as caught:
        weight_plan.write_weight_plan_atomic(candidate, target)

    assert caught.value is primary
    assert rollback_mutated is True
    assert rollback_fsync_seen is True
    assert target.read_bytes() == original.canonical_bytes()


def test_invalid_rollback_publication_is_replaced_by_pristine_recovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R26-INTEGRITY-3: final validation retains identity-bound recovery state."""

    target = tmp_path / "weight-plan.json"
    original = plan(block=101)
    candidate = plan(block=102)
    original_bytes = original.canonical_bytes()
    invalid_bytes = b"x" * len(original_bytes)
    assert weight_plan.write_weight_plan_atomic(original, target) is True

    primary = weight_plan.WeightPlanTargetError("force rollback")
    real_validate = weight_plan._validate_installed_temporary
    rollback_validations = 0
    corrupted = False

    def reject_direct_restoration(*_args: object, **_kwargs: object) -> None:
        raise weight_plan.WeightPlanTargetError("force rollback-copy recovery")

    def corrupt_first_rollback_publication(
        temporary: weight_plan._TemporaryPlan,
        directory_fd: int,
        name: str,
        *,
        expected: bytes,
    ) -> None:
        nonlocal rollback_validations, corrupted
        if expected == candidate.canonical_bytes():
            raise primary
        rollback_validations += 1
        if rollback_validations == 1:
            os.ftruncate(temporary.descriptor, 0)
            os.pwrite(temporary.descriptor, invalid_bytes, 0)
            corrupted = True
        real_validate(temporary, directory_fd, name, expected=expected)

    monkeypatch.setattr(weight_plan, "_validate_restored_original", reject_direct_restoration)
    monkeypatch.setattr(
        weight_plan,
        "_validate_installed_temporary",
        corrupt_first_rollback_publication,
    )

    with pytest.raises(weight_plan.WeightPlanTargetError) as caught:
        weight_plan.write_weight_plan_atomic(candidate, target)

    assert caught.value is primary
    assert corrupted is True
    assert rollback_validations >= 2
    assert target.read_bytes() == original_bytes
