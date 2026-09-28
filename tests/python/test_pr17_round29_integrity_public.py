# SPDX-License-Identifier: AGPL-3.0-only
"""PR17 round-29 rollback-publication identity regression."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest
from test_weight_plan import plan

import misscomputer_subnet.weight_plan as weight_plan


def test_rollback_authority_ignores_foreign_entry_created_during_fsync(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R28-INTEGRITY-1: bind recovery to mutation-confirmed identity only."""

    target = tmp_path / "weight-plan.json"
    original = plan(block=101)
    candidate = plan(block=102)
    foreign = b"FOREIGN CONTENT\n"
    assert weight_plan.write_weight_plan_atomic(original, target) is True

    real_validate = weight_plan._validate_installed_temporary
    real_fsync = os.fsync
    armed = False
    swapped = False

    def reject_candidate(*args: object, expected: bytes, **kwargs: object) -> None:
        nonlocal armed
        if expected == candidate.canonical_bytes():
            armed = True
            raise weight_plan.WeightPlanTargetError("force rollback")
        real_validate(*args, expected=expected, **kwargs)  # type: ignore[arg-type]

    def replace_during_rollback_fsync(descriptor: int) -> None:
        nonlocal swapped
        if armed and not swapped and stat.S_ISDIR(os.fstat(descriptor).st_mode):
            swapped = True
            os.unlink(target.name, dir_fd=descriptor)
            replacement = os.open(
                target.name,
                os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                weight_plan.WEIGHT_PLAN_FILE_MODE,
                dir_fd=descriptor,
            )
            try:
                os.write(replacement, foreign)
                real_fsync(replacement)
            finally:
                os.close(replacement)
        real_fsync(descriptor)

    monkeypatch.setattr(weight_plan, "_validate_installed_temporary", reject_candidate)
    monkeypatch.setattr(os, "fsync", replace_during_rollback_fsync)

    with pytest.raises(weight_plan.WeightPlanTargetError, match="force rollback"):
        weight_plan.write_weight_plan_atomic(candidate, target)

    assert swapped is True
    assert target.read_bytes() == foreign
