# SPDX-License-Identifier: AGPL-3.0-only
"""PR17 round-20 filesystem ownership and exception-precedence regressions."""

from __future__ import annotations

import asyncio
import errno
import os
from pathlib import Path
from typing import Any

import pytest
from test_weight_plan import plan

import misscomputer_subnet.weight_plan as weight_plan


class PersistenceAbort(BaseException):
    """Cancellation-grade persistence failure with stable object identity."""


def _owned_temporary(directory_fd: int, name: str) -> weight_plan._TemporaryPlan:
    descriptor = os.open(
        name,
        os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        weight_plan.WEIGHT_PLAN_FILE_MODE,
        dir_fd=directory_fd,
    )
    value = os.fstat(descriptor)
    return weight_plan._TemporaryPlan(
        descriptor=descriptor,
        identity=(value.st_dev, value.st_ino),
        name=name,
    )


def test_cleanup_never_unlinks_replacement_after_owned_identity_stat(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A stale successful pathname stat cannot authorize unlinking a new inode."""

    directory_fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    name = ".weight-plan.tmp-owned"
    temporary = _owned_temporary(directory_fd, name)
    descriptor = temporary.descriptor
    replacement = tmp_path / name
    real_stat, real_unlink = os.stat, os.unlink
    raced = False

    def stat_then_replace(path: int | str | bytes, *args: Any, **kwargs: Any) -> os.stat_result:
        nonlocal raced
        result = real_stat(path, *args, **kwargs)
        if path == name and kwargs.get("dir_fd") == directory_fd and not raced:
            raced = True
            real_unlink(name, dir_fd=directory_fd)
            replacement.write_bytes(b"foreign replacement\n")
            replacement.chmod(weight_plan.WEIGHT_PLAN_FILE_MODE)
        return result

    try:
        with monkeypatch.context() as patch:
            patch.setattr(os, "stat", stat_then_replace)
            weight_plan._cleanup_temporary_plan(temporary, directory_fd)

        assert raced is True
        assert replacement.read_bytes() == b"foreign replacement\n"
    finally:
        replacement.unlink(missing_ok=True)
        try:
            os.close(descriptor)
        except OSError as exc:
            assert exc.errno == errno.EBADF
        os.close(directory_fd)


def test_cleanup_never_unlinks_replacement_after_owned_scandir_observation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The atomic quarantine fence catches a swap after directory enumeration."""

    directory_fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    name = ".weight-plan.tmp-owned"
    temporary = _owned_temporary(directory_fd, name)
    descriptor = temporary.descriptor
    replacement = tmp_path / name
    real_scan, real_unlink = weight_plan._scanned_target_stat, os.unlink
    raced = False

    def scan_then_replace(fd: int, scanned_name: str) -> os.stat_result | None:
        nonlocal raced
        result = real_scan(fd, scanned_name)
        if scanned_name == name and not raced:
            raced = True
            real_unlink(name, dir_fd=directory_fd)
            replacement.write_bytes(b"foreign replacement\n")
            replacement.chmod(weight_plan.WEIGHT_PLAN_FILE_MODE)
        return result

    try:
        with monkeypatch.context() as patch:
            patch.setattr(weight_plan, "_scanned_target_stat", scan_then_replace)
            weight_plan._cleanup_temporary_plan(temporary, directory_fd)

        assert raced is True
        assert replacement.read_bytes() == b"foreign replacement\n"
        assert not list(tmp_path.glob(".weight-plan.cleanup-*"))
    finally:
        replacement.unlink(missing_ok=True)
        try:
            os.close(descriptor)
        except OSError as exc:
            assert exc.errno == errno.EBADF
        os.close(directory_fd)


def _metadata_failure(kind: str, operation: str) -> BaseException:
    if kind == "oserror":
        return OSError(errno.EIO, f"{operation} cleanup failed")
    if kind == "cancelled":
        return asyncio.CancelledError(f"{operation} cleanup cancelled")
    return PersistenceAbort(f"{operation} cleanup aborted")


@pytest.mark.parametrize("kind", ["oserror", "base_exception", "cancelled"])
@pytest.mark.parametrize("operation", ["stat", "fstat", "scandir", "unlink"])
def test_cleanup_metadata_faults_preserve_the_exact_owned_inode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
    operation: str,
) -> None:
    """Every metadata/unlink fault closes the fd without deleting another inode."""

    directory_fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    name = ".weight-plan.tmp-owned"
    temporary = _owned_temporary(directory_fd, name)
    descriptor = temporary.descriptor
    expected_identity = temporary.identity
    failure = _metadata_failure(kind, operation)
    real_stat, real_fstat = os.stat, os.fstat
    real_scandir, real_unlink = os.scandir, os.unlink

    def stat_value(path: int | str | bytes, *args: Any, **kwargs: Any) -> os.stat_result:
        if operation == "stat" and path == name:
            raise failure
        return real_stat(path, *args, **kwargs)

    def fstat(descriptor_value: int) -> os.stat_result:
        if operation == "fstat" and descriptor_value == descriptor:
            raise failure
        return real_fstat(descriptor_value)

    def scandir(path: int | str | bytes) -> os.ScandirIterator[str]:
        if operation == "scandir" and path == directory_fd:
            raise failure
        return real_scandir(path)

    def unlink(path: int | str | bytes, *args: Any, **kwargs: Any) -> None:
        if (
            operation == "unlink"
            and isinstance(path, str)
            and path.startswith(".weight-plan.cleanup-")
        ):
            raise failure
        real_unlink(path, *args, **kwargs)

    try:
        with monkeypatch.context() as patch:
            patch.setattr(os, "stat", stat_value)
            patch.setattr(os, "fstat", fstat)
            patch.setattr(os, "scandir", scandir)
            patch.setattr(os, "unlink", unlink)
            with pytest.raises(type(failure)) as caught:
                weight_plan._cleanup_temporary_plan(temporary, directory_fd)

        assert caught.value is failure
        residue = list(tmp_path.iterdir())
        assert len(residue) == 1
        value = residue[0].stat()
        assert (value.st_dev, value.st_ino) == expected_identity
        with pytest.raises(OSError) as closed:
            os.fstat(descriptor)
        assert closed.value.errno == errno.EBADF
    finally:
        for residue in tmp_path.iterdir():
            residue.unlink(missing_ok=True)
        try:
            os.close(descriptor)
        except OSError as exc:
            assert exc.errno == errno.EBADF
        os.close(directory_fd)


def test_repeated_cleanup_faults_keep_first_failure_and_owned_residue(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failed quarantine restore cannot replace the first metadata abort."""

    directory_fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    name = ".weight-plan.tmp-owned"
    temporary = _owned_temporary(directory_fd, name)
    descriptor = temporary.descriptor
    expected_identity = temporary.identity
    primary = PersistenceAbort("post-quarantine fstat aborted")
    restore_failure = OSError(errno.EIO, "quarantine restore failed")
    real_fstat = os.fstat
    real_rename = weight_plan._rename_exchange
    rename_calls = 0

    def fstat(descriptor_value: int) -> os.stat_result:
        if descriptor_value == descriptor:
            raise primary
        return real_fstat(descriptor_value)

    def rename(fd: int, source: str, destination: str) -> None:
        nonlocal rename_calls
        rename_calls += 1
        if rename_calls == 2:
            raise restore_failure
        real_rename(fd, source, destination)

    try:
        with monkeypatch.context() as patch:
            patch.setattr(os, "fstat", fstat)
            patch.setattr(weight_plan, "_rename_exchange", rename)
            with pytest.raises(PersistenceAbort) as caught:
                weight_plan._cleanup_temporary_plan(temporary, directory_fd)

        assert caught.value is primary
        assert "temporary_quarantine_restore_failed" in getattr(primary, "__notes__", ())
        residue = list(tmp_path.iterdir())
        assert len(residue) == 1
        value = residue[0].stat()
        assert (value.st_dev, value.st_ino) == expected_identity
        with pytest.raises(OSError) as closed:
            os.fstat(descriptor)
        assert closed.value.errno == errno.EBADF
    finally:
        for residue in tmp_path.iterdir():
            residue.unlink(missing_ok=True)
        try:
            os.close(descriptor)
        except OSError as exc:
            assert exc.errno == errno.EBADF
        os.close(directory_fd)


@pytest.mark.parametrize("primary_kind", ["typed_error", "base_exception"])
def test_primary_persistence_abort_survives_cleanup_unlink_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    primary_kind: str,
) -> None:
    """Cleanup diagnostics never replace an active persistence BaseException."""

    target = tmp_path / "weight-plan.json"
    primary: BaseException
    if primary_kind == "typed_error":
        primary = weight_plan.WeightPlanTargetError("primary typed persistence failure")
    else:
        primary = PersistenceAbort("primary persistence aborted")
    cleanup = OSError(errno.EIO, "temporary unlink failed")
    real_unlink = os.unlink

    def abort_replace(*_args: Any, **_kwargs: Any) -> None:
        raise primary

    def fail_temporary_unlink(
        path: int | str | bytes,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        if isinstance(path, str) and path.startswith(
            (".weight-plan.tmp-", ".weight-plan.cleanup-")
        ):
            raise cleanup
        real_unlink(path, *args, **kwargs)

    try:
        with monkeypatch.context() as patch:
            patch.setattr(weight_plan, "_open_unnamed_temporary", lambda _: None)
            patch.setattr(weight_plan, "_rename_noreplace", abort_replace)
            patch.setattr(os, "unlink", fail_temporary_unlink)
            with pytest.raises(type(primary)) as caught:
                weight_plan.write_weight_plan_atomic(plan(), target)

        assert caught.value is primary
        assert "temporary_cleanup_failed" in getattr(primary, "__notes__", ())
    finally:
        for residue in tmp_path.iterdir():
            residue.unlink(missing_ok=True)


def test_primary_persistence_error_survives_directory_close_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Adjacent directory cleanup also preserves the active typed failure."""

    target = tmp_path / "weight-plan.json"
    primary = weight_plan.WeightPlanTargetError("primary typed persistence failure")
    cleanup = OSError(errno.EIO, "directory close failed")
    real_close = weight_plan._PinnedDirectoryChain.close

    def abort_replace(*_args: Any, **_kwargs: Any) -> None:
        monkeypatch.setattr(weight_plan._PinnedDirectoryChain, "close", close_then_fail)
        raise primary

    def close_then_fail(chain: weight_plan._PinnedDirectoryChain) -> None:
        real_close(chain)
        raise cleanup

    with monkeypatch.context() as patch:
        patch.setattr(weight_plan, "_open_unnamed_temporary", lambda _: None)
        patch.setattr(weight_plan, "_rename_noreplace", abort_replace)
        with pytest.raises(weight_plan.WeightPlanTargetError) as caught:
            weight_plan.write_weight_plan_atomic(plan(), target)

    assert caught.value is primary
    assert "directory_cleanup_failed" in getattr(primary, "__notes__", ())
