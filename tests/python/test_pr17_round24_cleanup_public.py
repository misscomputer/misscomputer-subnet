# SPDX-License-Identifier: AGPL-3.0-only
"""PR17 round-24 cleanup ownership and error-precedence regressions."""

from __future__ import annotations

import asyncio
import errno
import os
import stat
from pathlib import Path

import pytest
from test_weight_plan import plan

import misscomputer_subnet.weight_plan as weight_plan


class CleanupAbort(BaseException):
    """Cancellation-grade cleanup failure with stable object identity."""


def _owned_temporary(directory_fd: int) -> weight_plan._TemporaryPlan:
    name = ".weight-plan.tmp-owned"
    descriptor = os.open(
        name,
        os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        weight_plan.WEIGHT_PLAN_FILE_MODE,
        dir_fd=directory_fd,
    )
    os.write(descriptor, b"owned bytes\n")
    value = os.fstat(descriptor)
    return weight_plan._TemporaryPlan(
        descriptor=descriptor,
        identity=(value.st_dev, value.st_ino),
        name=name,
    )


def test_private_cleanup_file_replacement_after_identity_stat_is_preserved(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CLEANUP-1: stale private-name metadata never authorizes foreign unlink."""

    target = tmp_path / "weight-plan.json"
    original = plan(block=101)
    replacement = plan(block=102)
    assert weight_plan.write_weight_plan_atomic(original, target) is True

    real_stat = os.stat
    foreign_descriptor = -1
    raced = False

    def replace_after_private_stat(
        path: int | str | bytes,
        *args: object,
        **kwargs: object,
    ) -> os.stat_result:
        nonlocal foreign_descriptor, raced
        value = real_stat(path, *args, **kwargs)  # type: ignore[arg-type]
        if path == ".weight-plan.cleanup-retired" and not raced:
            cleanup_path = next(tmp_path.glob(".weight-plan.cleanup-*"))
            cleanup_fd = os.open(
                cleanup_path,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC,
            )
            try:
                os.rename(
                    path,
                    "owned-moved",
                    src_dir_fd=cleanup_fd,
                    dst_dir_fd=cleanup_fd,
                )
                foreign_descriptor = os.open(
                    path,
                    os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                    weight_plan.WEIGHT_PLAN_FILE_MODE,
                    dir_fd=cleanup_fd,
                )
                os.write(foreign_descriptor, b"foreign important file\n")
                raced = True
            finally:
                os.close(cleanup_fd)
        return value

    try:
        monkeypatch.setattr(os, "stat", replace_after_private_stat)
        assert weight_plan.write_weight_plan_atomic(replacement, target) is True

        assert raced is True
        assert foreign_descriptor >= 0
        assert os.fstat(foreign_descriptor).st_nlink == 1
        assert target.read_bytes() == replacement.canonical_bytes()
    finally:
        if foreign_descriptor >= 0:
            os.close(foreign_descriptor)


def test_cleanup_directory_acquisition_preserves_foreign_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CLEANUP-2: failed acquisition does not rmdir a substituted directory."""

    directory_fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    real_fstat = os.fstat
    foreign_descriptor = -1
    foreign_name: str | None = None
    raced = False

    def replace_after_open(descriptor: int) -> os.stat_result:
        nonlocal foreign_descriptor, foreign_name, raced
        value = real_fstat(descriptor)
        if stat.S_ISDIR(value.st_mode) and descriptor != directory_fd and not raced:
            cleanup_path = next(tmp_path.glob(".weight-plan.cleanup-*"))
            foreign_name = cleanup_path.name
            cleanup_path.rename(tmp_path / "owned-cleanup-moved")
            cleanup_path.mkdir(mode=weight_plan.WEIGHT_PLAN_PRIVATE_DIRECTORY_MODE)
            foreign_descriptor = os.open(
                cleanup_path,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC,
            )
            raced = True
        return value

    try:
        monkeypatch.setattr(os, "fstat", replace_after_open)
        with pytest.raises(weight_plan.WeightPlanTargetError):
            weight_plan._open_private_cleanup_directory(directory_fd)

        assert raced is True
        assert foreign_name is not None
        assert (tmp_path / foreign_name).is_dir()
        assert foreign_descriptor >= 0
        assert os.fstat(foreign_descriptor).st_nlink > 0
        assert (tmp_path / "owned-cleanup-moved").is_dir()
    finally:
        if foreign_descriptor >= 0:
            os.close(foreign_descriptor)
        os.close(directory_fd)


def test_cleanup_directory_retirement_preserves_foreign_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CLEANUP-2: retirement does not rmdir a post-validation replacement."""

    directory_fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    cleanup = weight_plan._open_private_cleanup_directory(directory_fd)
    real_stat = os.stat
    foreign_descriptor = -1
    raced = False

    def replace_after_mapping_stat(
        path: int | str | bytes,
        *args: object,
        **kwargs: object,
    ) -> os.stat_result:
        nonlocal foreign_descriptor, raced
        value = real_stat(path, *args, **kwargs)  # type: ignore[arg-type]
        if path == cleanup.name and not raced:
            os.rename(
                cleanup.name,
                "owned-cleanup-moved",
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
            )
            os.mkdir(
                cleanup.name,
                weight_plan.WEIGHT_PLAN_PRIVATE_DIRECTORY_MODE,
                dir_fd=directory_fd,
            )
            foreign_descriptor = os.open(
                cleanup.name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC,
                dir_fd=directory_fd,
            )
            raced = True
        return value

    try:
        monkeypatch.setattr(os, "stat", replace_after_mapping_stat)
        with pytest.raises(weight_plan.WeightPlanTargetError):
            weight_plan._close_private_cleanup_directory(cleanup, directory_fd, None)

        assert raced is True
        assert (tmp_path / cleanup.name).is_dir()
        assert foreign_descriptor >= 0
        assert os.fstat(foreign_descriptor).st_nlink > 0
        assert (tmp_path / "owned-cleanup-moved").is_dir()
    finally:
        if foreign_descriptor >= 0:
            os.close(foreign_descriptor)
        os.close(directory_fd)


@pytest.mark.parametrize(
    "secondary",
    [
        CleanupAbort("rmdir abort"),
        asyncio.CancelledError("rmdir cancellation"),
        RuntimeError("rmdir runtime failure"),
    ],
)
def test_private_cleanup_directory_retirement_is_deferred(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    secondary: BaseException,
) -> None:
    """CLEANUP-3: an unowned pathname is never passed to rmdir."""

    directory_fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    primary = OSError(errno.EIO, "original unlink failure")
    cleanup = weight_plan._open_private_cleanup_directory(directory_fd)
    rmdir_called = False

    def fail_rmdir(*_args: object, **_kwargs: object) -> None:
        nonlocal rmdir_called
        rmdir_called = True
        raise secondary

    try:
        monkeypatch.setattr(os, "rmdir", fail_rmdir)
        weight_plan._close_private_cleanup_directory(cleanup, directory_fd, primary)

        assert rmdir_called is False
        assert (tmp_path / cleanup.name).is_dir()
        with pytest.raises(OSError) as closed:
            os.fstat(cleanup.descriptor)
        assert closed.value.errno == errno.EBADF
    finally:
        monkeypatch.undo()
        os.rmdir(tmp_path / cleanup.name)
        os.close(directory_fd)
