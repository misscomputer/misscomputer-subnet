# SPDX-License-Identifier: AGPL-3.0-only
"""PR13 round-14 visible-temporary identity recovery regressions."""

from __future__ import annotations

import asyncio
import errno
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

import misscomputer_subnet.weight_plan as weight_plan


class MetadataAbort(BaseException):
    """Cancellation-grade metadata failure with stable object identity."""


def _metadata_failures(kind: str) -> tuple[BaseException, BaseException]:
    if kind == "oserror":
        return (
            OSError(errno.EIO, "initial temporary fstat failed"),
            OSError(errno.EIO, "cleanup temporary fstat failed"),
        )
    if kind == "cancelled":
        return (
            asyncio.CancelledError("initial temporary fstat cancelled"),
            asyncio.CancelledError("cleanup temporary fstat cancelled"),
        )
    return (
        MetadataAbort("initial temporary fstat aborted"),
        MetadataAbort("cleanup temporary fstat aborted"),
    )


def _capture_temporary_opens(
    real_open: Callable[..., int],
    opened: list[int],
) -> Callable[..., int]:
    def open_file(*args: Any, **kwargs: Any) -> int:
        descriptor = real_open(*args, **kwargs)
        if isinstance(args[0], str) and args[0].startswith(".weight-plan.tmp-"):
            opened.append(descriptor)
        return descriptor

    return open_file


@pytest.mark.parametrize("kind", ["oserror", "base_exception", "cancelled"])
def test_repeated_initial_metadata_fault_recovers_owned_name(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
) -> None:
    """Independent descriptor stat removes the owned name after two fstat faults."""

    directory_fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    baseline_fds = set(os.listdir("/proc/self/fd"))
    opened: list[int] = []
    recovered: list[int] = []
    failures = list(_metadata_failures(kind))
    primary = failures[0]
    real_open, real_fstat, real_stat = os.open, os.fstat, os.stat

    def fstat(descriptor: int) -> os.stat_result:
        if descriptor in opened and failures:
            raise failures.pop(0)
        return real_fstat(descriptor)

    def stat_value(path: int | str | bytes, *args: Any, **kwargs: Any) -> os.stat_result:
        if isinstance(path, int) and path in opened:
            recovered.append(path)
        return real_stat(path, *args, **kwargs)

    try:
        with monkeypatch.context() as patch:
            patch.setattr(weight_plan, "_open_unnamed_temporary", lambda _: None)
            patch.setattr(os, "open", _capture_temporary_opens(real_open, opened))
            patch.setattr(os, "fstat", fstat)
            patch.setattr(os, "stat", stat_value)
            with pytest.raises(type(primary)) as caught:
                weight_plan._prepare_temporary_plan(directory_fd, b"round-14\n")

        assert caught.value is primary
        assert len(failures) == 0
        assert recovered == opened
        assert not list(tmp_path.glob(".weight-plan.tmp-*"))
        for descriptor in opened:
            with pytest.raises(OSError) as closed:
                os.fstat(descriptor)
            assert closed.value.errno == errno.EBADF
        assert set(os.listdir("/proc/self/fd")) == baseline_fds
    finally:
        os.close(directory_fd)


def test_recovered_identity_preserves_replacement_name(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Identity recovery never turns cleanup into deletion of a replacement inode."""

    directory_fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    baseline_fds = set(os.listdir("/proc/self/fd"))
    opened: list[int] = []
    real_open, real_fstat = os.open, os.fstat
    failures = [
        OSError(errno.EIO, "initial temporary fstat failed"),
        OSError(errno.EIO, "cleanup temporary fstat failed"),
    ]
    primary = failures[0]
    temporary_identity: tuple[int, int] | None = None
    replacement_identity: tuple[int, int] | None = None
    replacement: Path | None = None

    def fstat(descriptor: int) -> os.stat_result:
        nonlocal replacement, replacement_identity, temporary_identity
        if descriptor in opened and failures:
            if len(failures) == 2:
                temporary = real_fstat(descriptor)
                temporary_identity = (temporary.st_dev, temporary.st_ino)
                replacement = next(tmp_path.glob(".weight-plan.tmp-*"))
                replacement.unlink()
                replacement.write_bytes(b"replacement\n")
                replacement.chmod(weight_plan.WEIGHT_PLAN_FILE_MODE)
                value = replacement.stat()
                replacement_identity = (value.st_dev, value.st_ino)
            raise failures.pop(0)
        return real_fstat(descriptor)

    try:
        with monkeypatch.context() as patch:
            patch.setattr(weight_plan, "_open_unnamed_temporary", lambda _: None)
            patch.setattr(os, "open", _capture_temporary_opens(real_open, opened))
            patch.setattr(os, "fstat", fstat)
            with pytest.raises(OSError) as caught:
                weight_plan._prepare_temporary_plan(directory_fd, b"round-14\n")

        assert caught.value is primary
        assert len(failures) == 0
        assert replacement is not None and replacement.read_bytes() == b"replacement\n"
        assert temporary_identity is not None and temporary_identity != replacement_identity
        for descriptor in opened:
            with pytest.raises(OSError) as closed:
                os.fstat(descriptor)
            assert closed.value.errno == errno.EBADF
        assert set(os.listdir("/proc/self/fd")) == baseline_fds
    finally:
        if replacement is not None:
            replacement.unlink(missing_ok=True)
        os.close(directory_fd)


def test_unverifiable_identity_preserves_name_but_closes_descriptor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Cleanup closes its descriptor without unlinking an unverifiable name."""

    directory_fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    baseline_fds = set(os.listdir("/proc/self/fd"))
    opened: list[int] = []
    real_open, real_fstat, real_stat = os.open, os.fstat, os.stat
    fstat_failures = [
        OSError(errno.EIO, "initial temporary fstat failed"),
        OSError(errno.EIO, "cleanup temporary fstat failed"),
    ]
    primary = fstat_failures[0]
    recovery_failure = MetadataAbort("independent descriptor stat failed")

    def fstat(descriptor: int) -> os.stat_result:
        if descriptor in opened and fstat_failures:
            raise fstat_failures.pop(0)
        return real_fstat(descriptor)

    def stat_value(path: int | str | bytes, *args: Any, **kwargs: Any) -> os.stat_result:
        if isinstance(path, int) and path in opened:
            raise recovery_failure
        return real_stat(path, *args, **kwargs)

    residue: list[Path] = []
    try:
        with monkeypatch.context() as patch:
            patch.setattr(weight_plan, "_open_unnamed_temporary", lambda _: None)
            patch.setattr(os, "open", _capture_temporary_opens(real_open, opened))
            patch.setattr(os, "fstat", fstat)
            patch.setattr(os, "stat", stat_value)
            with pytest.raises(OSError) as caught:
                weight_plan._prepare_temporary_plan(directory_fd, b"round-14\n")

        assert caught.value is primary
        residue = list(tmp_path.glob(".weight-plan.tmp-*"))
        assert len(residue) == 1
        for descriptor in opened:
            with pytest.raises(OSError) as closed:
                os.fstat(descriptor)
            assert closed.value.errno == errno.EBADF
        assert set(os.listdir("/proc/self/fd")) == baseline_fds
    finally:
        for path in residue:
            path.unlink(missing_ok=True)
        os.close(directory_fd)
