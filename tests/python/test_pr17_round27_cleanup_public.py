# SPDX-License-Identifier: AGPL-3.0-only
"""PR17 round-27 terminal cleanup ownership regressions."""

from __future__ import annotations

import asyncio
import ctypes
import errno
import os
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


def test_post_monitor_drain_substitution_preserves_foreign_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CLEANUP-R26-1: a final-drain race cannot delete a foreign inode."""

    directory_fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    temporary = _owned_temporary(directory_fd)
    real_open = os.open
    real_read = os.read
    cleanup_descriptor = -1
    captured = False
    foreign_descriptor = -1
    injected = False

    def capture_open(
        path: int | str | bytes,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal cleanup_descriptor, captured
        descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
        if path == ".weight-plan.cleanup-retired":
            assert dir_fd is not None
            cleanup_descriptor = dir_fd
            captured = True
        return descriptor

    def replace_after_final_drain(descriptor: int, count: int) -> bytes:
        nonlocal foreign_descriptor, injected
        try:
            return real_read(descriptor, count)
        except BlockingIOError:
            if captured and not injected:
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
            raise

    try:
        monkeypatch.setattr(os, "open", capture_open)
        monkeypatch.setattr(os, "read", replace_after_final_drain)
        weight_plan._cleanup_temporary_plan(temporary, directory_fd)

        assert injected is True
        assert foreign_descriptor >= 0
        assert os.fstat(foreign_descriptor).st_nlink > 0
    finally:
        monkeypatch.undo()
        if foreign_descriptor >= 0:
            os.close(foreign_descriptor)
        _remove_residue(tmp_path)
        os.close(directory_fd)


def test_post_monitor_drain_substitution_preserves_foreign_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CLEANUP-R26-2: a final-drain race cannot rmdir a foreign directory."""

    directory_fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    cleanup = weight_plan._open_private_cleanup_directory(directory_fd)
    real_read = os.read
    foreign_descriptor = -1
    injected = False

    def replace_after_final_drain(descriptor: int, count: int) -> bytes:
        nonlocal foreign_descriptor, injected
        try:
            return real_read(descriptor, count)
        except BlockingIOError:
            if descriptor == cleanup.monitor.descriptor and not injected:
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
            raise

    try:
        monkeypatch.setattr(os, "read", replace_after_final_drain)
        weight_plan._close_private_cleanup_directory(cleanup, directory_fd, None)

        assert injected is True
        assert foreign_descriptor >= 0
        assert os.fstat(foreign_descriptor).st_nlink > 0
        assert (tmp_path / cleanup.name).is_dir()
    finally:
        monkeypatch.undo()
        if foreign_descriptor >= 0:
            os.close(foreign_descriptor)
        _remove_residue(tmp_path)
        os.close(directory_fd)


def test_monitor_watch_cancellation_closes_descriptor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CLEANUP-R26-3: cancellation during add-watch cannot leak the monitor."""

    descriptor = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
    primary = asyncio.CancelledError("watch acquisition cancelled")

    class Libc:
        def inotify_init1(self, _flags: int) -> int:
            return descriptor

        def inotify_add_watch(self, *_args: object) -> int:
            raise primary

    monkeypatch.setattr(weight_plan.ctypes, "CDLL", lambda *_args, **_kwargs: Libc())
    with pytest.raises(asyncio.CancelledError) as caught:
        weight_plan._open_private_cleanup_namespace_monitor(0)

    assert caught.value is primary
    with pytest.raises(OSError) as closed:
        os.fstat(descriptor)
    assert closed.value.errno == errno.EBADF


def test_monitor_watch_error_survives_close_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CLEANUP-R26-3: close diagnostics cannot replace the watch errno."""

    descriptor = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
    real_close = os.close
    secondary = RuntimeError("monitor close failed")

    class Libc:
        def inotify_init1(self, _flags: int) -> int:
            return descriptor

        def inotify_add_watch(self, *_args: object) -> int:
            ctypes.set_errno(errno.ENOSPC)
            return -1

    def close_then_fail(value: int) -> None:
        real_close(value)
        if value == descriptor:
            raise secondary

    monkeypatch.setattr(weight_plan.ctypes, "CDLL", lambda *_args, **_kwargs: Libc())
    monkeypatch.setattr(os, "close", close_then_fail)
    with pytest.raises(OSError) as caught:
        weight_plan._open_private_cleanup_namespace_monitor(0)

    assert caught.value.errno == errno.ENOSPC
    assert "private_cleanup_monitor_close_failed" in getattr(caught.value, "__notes__", ())
    with pytest.raises(OSError) as closed:
        os.fstat(descriptor)
    assert closed.value.errno == errno.EBADF
