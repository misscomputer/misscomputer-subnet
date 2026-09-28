# SPDX-License-Identifier: AGPL-3.0-only
"""PR17 round-28 publication-identity and rollback regressions."""

from __future__ import annotations

import errno
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
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def test_replacement_rollback_never_publishes_unproven_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R27-INTEGRITY-1: restore only from the identity-bound rollback copy."""

    target = tmp_path / "weight-plan.json"
    original = plan(block=101)
    candidate = plan(block=102)
    foreign = b"FOREIGN CONTENT\n"
    assert weight_plan.write_weight_plan_atomic(original, target) is True

    real_exchange = weight_plan._rename_exchange
    real_validate = weight_plan._validate_installed_temporary
    installed = False

    def replace_displaced_source(directory_fd: int, source: str, destination: str):
        nonlocal installed
        identity = real_exchange(directory_fd, source, destination)
        if destination == target.name and not installed:
            installed = True
            _replace_name(directory_fd, source, foreign)
        return identity

    def reject_candidate(*args: object, expected: bytes, **kwargs: object) -> None:
        if expected == candidate.canonical_bytes():
            raise weight_plan.WeightPlanTargetError("force rollback")
        real_validate(*args, expected=expected, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(weight_plan, "_rename_exchange", replace_displaced_source)
    monkeypatch.setattr(weight_plan, "_validate_installed_temporary", reject_candidate)

    with pytest.raises(weight_plan.WeightPlanTargetError):
        weight_plan.write_weight_plan_atomic(candidate, target)

    assert target.read_bytes() == original.canonical_bytes()


def test_exchange_identity_observation_failure_is_non_faulting_and_fsynced(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R27-INTEGRITY-2: a completed exchange survives identity-observation faults."""

    target = tmp_path / "weight-plan.json"
    original = plan(block=101)
    candidate = plan(block=102)
    assert weight_plan.write_weight_plan_atomic(original, target) is True

    real_stat = weight_plan._unvalidated_target_stat
    real_fsync = os.fsync
    armed = False
    injected = False
    directory_fsyncs_after_fault = 0

    def fail_post_exchange_observation(directory_fd: int, name: str):
        nonlocal armed, injected
        result = real_stat(directory_fd, name)
        if name.startswith(".weight-plan.tmp-") and not injected:
            armed = True
        elif name == target.name and armed and not injected:
            injected = True
            raise OSError(errno.EIO, "injected post-exchange observation failure")
        return result

    def observe_fsync(descriptor: int) -> None:
        nonlocal directory_fsyncs_after_fault
        if injected and stat.S_ISDIR(os.fstat(descriptor).st_mode):
            directory_fsyncs_after_fault += 1
        real_fsync(descriptor)

    monkeypatch.setattr(weight_plan, "_unvalidated_target_stat", fail_post_exchange_observation)
    monkeypatch.setattr(os, "fsync", observe_fsync)

    assert weight_plan.write_weight_plan_atomic(candidate, target) is True
    assert injected is True
    assert directory_fsyncs_after_fault >= 1
    assert target.read_bytes() == candidate.canonical_bytes()


def test_creation_rollback_preserves_foreign_canonical_entry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R27-INTEGRITY-3: creation rollback is bound to this attempt's inode."""

    target = tmp_path / "weight-plan.json"
    candidate = plan(block=102)
    foreign = b"FOREIGN CONTENT\n"
    real_rename = weight_plan._rename_noreplace
    published = False

    def replace_after_publish(directory_fd: int, source: str, destination: str) -> None:
        nonlocal published
        real_rename(directory_fd, source, destination)
        if destination == target.name and not published:
            published = True
            _replace_name(directory_fd, destination, foreign)

    monkeypatch.setattr(weight_plan, "_rename_noreplace", replace_after_publish)

    with pytest.raises(weight_plan.WeightPlanTargetError):
        weight_plan.write_weight_plan_atomic(candidate, target)

    assert published is True
    assert target.read_bytes() == foreign


def test_exchange_identity_is_per_call_under_nested_writer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R27-INTEGRITY-4: another writer cannot clobber rollback authority."""

    target_a = tmp_path / "weight-plan-a.json"
    target_b = tmp_path / "weight-plan-b.json"
    original_a = plan(block=101)
    candidate_a = plan(block=102)
    original_b = plan(block=201)
    candidate_b = plan(block=202)
    assert weight_plan.write_weight_plan_atomic(original_a, target_a) is True
    assert weight_plan.write_weight_plan_atomic(original_b, target_b) is True

    real_exchange = weight_plan._rename_exchange
    real_validate = weight_plan._validate_installed_temporary
    nested = False

    def interleave_writer(directory_fd: int, source: str, destination: str):
        nonlocal nested
        identity = real_exchange(directory_fd, source, destination)
        if destination == target_a.name and not nested:
            nested = True
            assert weight_plan.write_weight_plan_atomic(candidate_b, target_b) is True
        return identity

    def reject_outer_candidate(*args: object, expected: bytes, **kwargs: object) -> None:
        if expected == candidate_a.canonical_bytes():
            raise weight_plan.WeightPlanTargetError("force outer rollback")
        real_validate(*args, expected=expected, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(weight_plan, "_rename_exchange", interleave_writer)
    monkeypatch.setattr(weight_plan, "_validate_installed_temporary", reject_outer_candidate)

    with pytest.raises(weight_plan.WeightPlanTargetError, match="force outer rollback"):
        weight_plan.write_weight_plan_atomic(candidate_a, target_a)

    assert nested is True
    assert target_a.read_bytes() == original_a.canonical_bytes()
    assert target_b.read_bytes() == candidate_b.canonical_bytes()
