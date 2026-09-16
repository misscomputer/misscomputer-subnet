# SPDX-License-Identifier: AGPL-3.0-only
"""PR17 round-25 cleanup namespace and descriptor regressions."""

from __future__ import annotations

import asyncio
import errno
import os
from pathlib import Path

import pytest

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


def _remove_residue(root: Path) -> None:
    for directory, children, files in os.walk(root, topdown=False):
        for name in files:
            os.unlink(Path(directory, name))
        for name in children:
            os.rmdir(Path(directory, name))


def test_captured_file_swap_during_descriptor_close_is_preserved(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CLEANUP-R24-1: descriptor retirement precedes no mutable-path unlink."""

    directory_fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    temporary = _owned_temporary(directory_fd)
    real_open = os.open
    real_close = os.close
    captured_descriptor = -1
    cleanup_descriptor = -1
    foreign_descriptor = -1

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

    def close_then_replace(descriptor: int) -> None:
        nonlocal foreign_descriptor
        real_close(descriptor)
        if descriptor != captured_descriptor or foreign_descriptor >= 0:
            return
        try:
            os.rename(
                ".weight-plan.cleanup-retired",
                "owned-moved",
                src_dir_fd=cleanup_descriptor,
                dst_dir_fd=cleanup_descriptor,
            )
        except FileNotFoundError:
            pass
        foreign_descriptor = real_open(
            ".weight-plan.cleanup-retired",
            os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            weight_plan.WEIGHT_PLAN_FILE_MODE,
            dir_fd=cleanup_descriptor,
        )
        os.write(foreign_descriptor, b"foreign important bytes\n")

    try:
        monkeypatch.setattr(os, "open", capture_open)
        monkeypatch.setattr(os, "close", close_then_replace)
        weight_plan._cleanup_temporary_plan(temporary, directory_fd)

        assert captured_descriptor >= 0
        assert foreign_descriptor >= 0
        assert os.fstat(foreign_descriptor).st_nlink == 1
    finally:
        monkeypatch.undo()
        if foreign_descriptor >= 0:
            real_close(foreign_descriptor)
        _remove_residue(tmp_path)
        real_close(directory_fd)


def test_cleanup_directory_substitution_during_creation_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CLEANUP-R24-2: acquisition remains bound to the created directory."""

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
        real_mkdir(
            path,
            weight_plan.WEIGHT_PLAN_PRIVATE_DIRECTORY_MODE,
            dir_fd=directory_fd,
        )
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
        assert os.fstat(foreign_descriptor).st_nlink > 0
        assert (tmp_path / cleanup_name).is_dir()
        assert (tmp_path / "owned-cleanup-moved").is_dir()
    finally:
        monkeypatch.undo()
        if foreign_descriptor >= 0:
            os.close(foreign_descriptor)
        _remove_residue(tmp_path)
        os.close(directory_fd)


def test_cleanup_directory_swap_during_descriptor_close_is_preserved(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CLEANUP-R24-2: retirement keeps the pinned directory through rmdir."""

    directory_fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    cleanup = weight_plan._open_private_cleanup_directory(directory_fd)
    real_close = os.close
    real_mkdir = os.mkdir
    foreign_descriptor = -1

    def close_then_replace(descriptor: int) -> None:
        nonlocal foreign_descriptor
        real_close(descriptor)
        if descriptor != cleanup.descriptor or foreign_descriptor >= 0:
            return
        try:
            os.rename(
                cleanup.name,
                "owned-cleanup-moved",
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
            )
        except FileNotFoundError:
            pass
        real_mkdir(
            cleanup.name,
            weight_plan.WEIGHT_PLAN_PRIVATE_DIRECTORY_MODE,
            dir_fd=directory_fd,
        )
        foreign_descriptor = os.open(
            cleanup.name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC,
            dir_fd=directory_fd,
        )

    try:
        monkeypatch.setattr(os, "close", close_then_replace)
        weight_plan._close_private_cleanup_directory(cleanup, directory_fd, None)

        assert foreign_descriptor >= 0
        assert os.fstat(foreign_descriptor).st_nlink > 0
        assert (tmp_path / cleanup.name).is_dir()
    finally:
        monkeypatch.undo()
        if foreign_descriptor >= 0:
            real_close(foreign_descriptor)
        _remove_residue(tmp_path)
        real_close(directory_fd)


@pytest.mark.parametrize(
    "primary",
    [
        OSError(errno.EIO, "captured fstat failed"),
        asyncio.CancelledError("captured fstat cancelled"),
        CleanupAbort("captured fstat aborted"),
    ],
)
def test_captured_fstat_primary_survives_descriptor_close_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    primary: BaseException,
) -> None:
    """CLEANUP-R24-3: close failure cannot replace the captured fstat failure."""

    directory_fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    temporary = _owned_temporary(directory_fd)
    real_open = os.open
    real_close = os.close
    real_fstat = os.fstat
    captured_descriptor = -1
    secondary = RuntimeError("captured descriptor close failed")

    def capture_open(
        path: int | str | bytes,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal captured_descriptor
        descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
        if path == ".weight-plan.cleanup-retired":
            captured_descriptor = descriptor
        return descriptor

    def fail_captured_fstat(descriptor: int) -> os.stat_result:
        if descriptor == captured_descriptor:
            raise primary
        return real_fstat(descriptor)

    def close_then_fail(descriptor: int) -> None:
        real_close(descriptor)
        if descriptor == captured_descriptor:
            raise secondary

    try:
        monkeypatch.setattr(os, "open", capture_open)
        monkeypatch.setattr(os, "fstat", fail_captured_fstat)
        monkeypatch.setattr(os, "close", close_then_fail)
        with pytest.raises(type(primary)) as caught:
            weight_plan._cleanup_temporary_plan(temporary, directory_fd)

        assert caught.value is primary
        assert "captured_descriptor_close_failed" in getattr(primary, "__notes__", ())
        with pytest.raises(OSError) as closed:
            real_fstat(temporary.descriptor)
        assert closed.value.errno == errno.EBADF
    finally:
        monkeypatch.undo()
        _remove_residue(tmp_path)
        real_close(directory_fd)


def test_fifo_substitution_uses_nonblocking_metadata_descriptor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CLEANUP-R24-4: capturing a substituted FIFO cannot perform a blocking open."""

    directory_fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    temporary = _owned_temporary(directory_fd)
    real_open = os.open
    real_stat = os.stat
    injected = False

    def stat_then_fifo(
        path: int | str | bytes,
        *args: object,
        **kwargs: object,
    ) -> os.stat_result:
        nonlocal injected
        value = real_stat(path, *args, **kwargs)  # type: ignore[arg-type]
        if path == ".weight-plan.cleanup-retired" and not injected:
            cleanup_descriptor = kwargs.get("dir_fd")
            assert isinstance(cleanup_descriptor, int)
            os.rename(
                path,
                "owned-moved",
                src_dir_fd=cleanup_descriptor,
                dst_dir_fd=cleanup_descriptor,
            )
            os.mkfifo(path, weight_plan.WEIGHT_PLAN_FILE_MODE, dir_fd=cleanup_descriptor)
            injected = True
        return value

    def bounded_open(
        path: int | str | bytes,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        if path == ".weight-plan.cleanup-retired":
            safe_flags = getattr(os, "O_PATH", 0) | os.O_NONBLOCK
            assert flags & safe_flags
        return real_open(path, flags, mode, dir_fd=dir_fd)

    try:
        monkeypatch.setattr(os, "stat", stat_then_fifo)
        monkeypatch.setattr(os, "open", bounded_open)
        weight_plan._cleanup_temporary_plan(temporary, directory_fd)

        assert injected is True
        source = tmp_path / ".weight-plan.tmp-owned"
        assert source.is_fifo()
    finally:
        monkeypatch.undo()
        _remove_residue(tmp_path)
        os.close(directory_fd)
