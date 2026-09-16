# SPDX-License-Identifier: AGPL-3.0-only
"""PR17 round-26 cleanup namespace-ownership regressions."""

from __future__ import annotations

import errno
import os
import stat
from pathlib import Path

import pytest

import misscomputer_subnet.weight_plan as weight_plan


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


def _remove_residue(root: Path) -> None:
    for directory, children, files in os.walk(root, topdown=False):
        for name in files:
            os.unlink(Path(directory, name))
        for name in children:
            os.rmdir(Path(directory, name))


def test_final_captured_fstat_swap_preserves_foreign_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CLEANUP-R25-1: a post-fstat replacement is never path-unlinked."""

    directory_fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    temporary = _owned_temporary(directory_fd)
    real_open = os.open
    real_fstat = os.fstat
    captured_descriptor = -1
    cleanup_descriptor = -1
    foreign_descriptor = -1
    injected = False

    def capture_open(
        path: int | str | bytes,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal captured_descriptor, cleanup_descriptor
        descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
        if path == ".weight-plan.cleanup-retired":
            captured_descriptor = descriptor
            assert dir_fd is not None
            cleanup_descriptor = dir_fd
        return descriptor

    def fstat_then_replace(descriptor: int) -> os.stat_result:
        nonlocal foreign_descriptor, injected
        value = real_fstat(descriptor)
        if descriptor == captured_descriptor and not injected:
            os.rename(
                ".weight-plan.cleanup-retired",
                "owned-moved",
                src_dir_fd=cleanup_descriptor,
                dst_dir_fd=cleanup_descriptor,
            )
            foreign_descriptor = real_open(
                ".weight-plan.cleanup-retired",
                os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                weight_plan.WEIGHT_PLAN_FILE_MODE,
                dir_fd=cleanup_descriptor,
            )
            os.write(foreign_descriptor, b"foreign important bytes\n")
            injected = True
        return value

    try:
        monkeypatch.setattr(os, "open", capture_open)
        monkeypatch.setattr(os, "fstat", fstat_then_replace)
        weight_plan._cleanup_temporary_plan(temporary, directory_fd)

        assert injected is True
        assert foreign_descriptor >= 0
        assert real_fstat(foreign_descriptor).st_nlink == 1
    finally:
        monkeypatch.undo()
        if foreign_descriptor >= 0:
            os.close(foreign_descriptor)
        _remove_residue(tmp_path)
        os.close(directory_fd)


def test_post_scan_cleanup_directory_swap_preserves_foreign_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CLEANUP-R25-2: a post-scan replacement is never path-rmdir'd."""

    directory_fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    cleanup = weight_plan._open_private_cleanup_directory(directory_fd)
    real_scan = weight_plan._scanned_target_stat
    foreign_descriptor = -1
    injected = False

    def scan_then_replace(fd: int, name: str) -> os.stat_result | None:
        nonlocal foreign_descriptor, injected
        value = real_scan(fd, name)
        if fd == directory_fd and name == cleanup.name and not injected:
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
            injected = True
        return value

    try:
        monkeypatch.setattr(weight_plan, "_scanned_target_stat", scan_then_replace)
        with pytest.raises(weight_plan.WeightPlanTargetError):
            weight_plan._close_private_cleanup_directory(cleanup, directory_fd, None)

        assert injected is True
        assert foreign_descriptor >= 0
        assert os.fstat(foreign_descriptor).st_nlink > 0
        assert (tmp_path / cleanup.name).is_dir()
        assert (tmp_path / "owned-cleanup-moved").is_dir()
    finally:
        monkeypatch.undo()
        if foreign_descriptor >= 0:
            os.close(foreign_descriptor)
        _remove_residue(tmp_path)
        os.close(directory_fd)


def test_same_mode_cleanup_directory_substitution_is_not_acquired(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CLEANUP-R25-3: mkdir success alone never proves directory ownership."""

    directory_fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    real_mkdir = os.mkdir
    foreign_descriptor = -1
    cleanup_name: str | None = None

    def mkdir_then_replace(
        path: int | str | bytes,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> None:
        nonlocal cleanup_name, foreign_descriptor
        real_mkdir(path, mode, dir_fd=dir_fd)
        if not isinstance(path, str) or not path.startswith(".weight-plan.cleanup-"):
            return
        cleanup_name = path
        os.rename(
            path,
            "owned-cleanup-moved",
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
        )
        real_mkdir(path, mode, dir_fd=directory_fd)
        foreign_descriptor = os.open(
            path,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC,
            dir_fd=directory_fd,
        )

    try:
        monkeypatch.setattr(os, "mkdir", mkdir_then_replace)
        with pytest.raises(weight_plan.WeightPlanTargetError):
            weight_plan._open_private_cleanup_directory(directory_fd)

        assert cleanup_name is not None
        assert foreign_descriptor >= 0
        foreign = os.fstat(foreign_descriptor)
        assert foreign.st_nlink > 0
        assert stat.S_IMODE(foreign.st_mode) == (
            weight_plan._WEIGHT_PLAN_PRIVATE_DIRECTORY_ACQUISITION_MODE
        )
        assert (tmp_path / cleanup_name).is_dir()
        assert (tmp_path / "owned-cleanup-moved").is_dir()
    finally:
        monkeypatch.undo()
        if foreign_descriptor >= 0:
            os.close(foreign_descriptor)
        _remove_residue(tmp_path)
        try:
            os.close(directory_fd)
        except OSError as exc:
            assert exc.errno == errno.EBADF
