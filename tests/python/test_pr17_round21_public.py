# SPDX-License-Identifier: AGPL-3.0-only
"""PR17 round-21 terminal filesystem and exception regressions."""

from __future__ import annotations

import asyncio
import errno
import os
import stat
from pathlib import Path
from typing import Any

import pytest
from test_weight_plan import plan

import misscomputer_subnet.weight_plan as weight_plan


class PersistenceAbort(BaseException):
    """Cancellation-grade persistence failure with stable object identity."""


class BrokenNoteAbort(BaseException):
    """A primary failure whose diagnostic-note hook is itself broken."""

    def add_note(self, note: str) -> None:
        raise RuntimeError(f"could not retain note: {note}")


def _remove_residue(root: Path) -> None:
    for directory, children, files in os.walk(root, topdown=False):
        for name in files:
            os.unlink(Path(directory, name))
        for name in children:
            os.rmdir(Path(directory, name))


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


def test_cleanup_does_not_unlink_replacement_after_quarantine_validation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    directory_fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    temporary = _owned_temporary(directory_fd, ".weight-plan.tmp-owned")
    descriptor = temporary.descriptor
    real_move = weight_plan._rename_noreplace_between
    raced = False

    def replace_after_move(
        source_fd: int,
        name: str,
        destination_fd: int,
        destination: str,
    ) -> None:
        nonlocal raced
        real_move(source_fd, name, destination_fd, destination)
        if source_fd == directory_fd and name == ".weight-plan.tmp-owned" and not raced:
            raced = True
            replacement = tmp_path / name
            replacement.write_bytes(b"foreign quarantine replacement\n")
            replacement.chmod(weight_plan.WEIGHT_PLAN_FILE_MODE)

    try:
        with monkeypatch.context() as patch:
            patch.setattr(weight_plan, "_rename_noreplace_between", replace_after_move)
            weight_plan._cleanup_temporary_plan(temporary, directory_fd)

        assert raced is True
        assert (tmp_path / ".weight-plan.tmp-owned").read_bytes() == (
            b"foreign quarantine replacement\n"
        )
    finally:
        _remove_residue(tmp_path)
        try:
            os.close(descriptor)
        except OSError as exc:
            assert exc.errno == errno.EBADF
        os.close(directory_fd)


def test_cleanup_never_captures_foreign_source_on_restore_collision(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    directory_fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    source = ".weight-plan.tmp-owned"
    temporary = _owned_temporary(directory_fd, source)
    descriptor = temporary.descriptor
    real_matches = weight_plan._temporary_name_matches
    real_noreplace = weight_plan._rename_noreplace
    real_unlink = os.unlink
    raced = False

    def replace_source_after_match(fd: int, name: str, identity: tuple[int, int]) -> bool:
        nonlocal raced
        matched = real_matches(fd, name, identity)
        if name == source and matched and not raced:
            raced = True
            real_unlink(source, dir_fd=directory_fd)
            replacement = tmp_path / source
            replacement.write_bytes(b"foreign source\n")
            replacement.chmod(weight_plan.WEIGHT_PLAN_FILE_MODE)
        return matched

    def collide_with_restore(fd: int, old: str, new: str) -> None:
        if old.startswith(".weight-plan.cleanup-") and new == source:
            collision = tmp_path / source
            collision.write_bytes(b"foreign collision\n")
            collision.chmod(weight_plan.WEIGHT_PLAN_FILE_MODE)
        real_noreplace(fd, old, new)

    try:
        with monkeypatch.context() as patch:
            patch.setattr(weight_plan, "_temporary_name_matches", replace_source_after_match)
            patch.setattr(weight_plan, "_rename_noreplace", collide_with_restore)
            weight_plan._cleanup_temporary_plan(temporary, directory_fd)

        assert raced is True
        assert (tmp_path / source).read_bytes() == b"foreign source\n"
        assert list(tmp_path.glob(".weight-plan.cleanup-*"))
    finally:
        _remove_residue(tmp_path)
        try:
            os.close(descriptor)
        except OSError as exc:
            assert exc.errno == errno.EBADF
        os.close(directory_fd)


@pytest.mark.parametrize("target_existed", [False, True])
def test_install_preserves_destination_created_after_validation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    target_existed: bool,
) -> None:
    target = tmp_path / "weight-plan.json"
    if target_existed:
        target.write_bytes(b"validated target\n")
        target.chmod(weight_plan.WEIGHT_PLAN_FILE_MODE)
    real_target_stat = weight_plan._target_stat
    real_unlink = os.unlink
    observations = 0
    raced = False

    def replace_after_validation(directory_fd: int, name: str) -> os.stat_result | None:
        nonlocal observations, raced
        value = real_target_stat(directory_fd, name)
        if name != target.name:
            return value
        observations += 1
        race_at = 3 if target_existed else 2
        if observations == race_at:
            if value is not None:
                real_unlink(name, dir_fd=directory_fd)
            target.write_bytes(b"foreign destination\n")
            target.chmod(weight_plan.WEIGHT_PLAN_FILE_MODE)
            raced = True
        return value

    monkeypatch.setattr(weight_plan, "_target_stat", replace_after_validation)
    with pytest.raises(weight_plan.WeightPlanTargetError):
        weight_plan.write_weight_plan_atomic(plan(), target)

    assert raced is True
    assert target.read_bytes() == b"foreign destination\n"


def test_exchange_rollback_restores_foreign_symlink_destination(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "weight-plan.json"
    target.write_bytes(b"validated target\n")
    target.chmod(weight_plan.WEIGHT_PLAN_FILE_MODE)
    victim = tmp_path / "foreign-victim"
    victim.write_bytes(b"foreign victim\n")
    real_unlink = os.unlink
    raced = False

    def replace_before_exchange(directory_fd: int, source: str, destination: str) -> None:
        nonlocal raced
        if destination == target.name and not raced:
            raced = True
            real_unlink(destination, dir_fd=directory_fd)
            target.symlink_to(victim)
        real_exchange(directory_fd, source, destination)

    def replace_before_legacy_install(
        source: str,
        destination: str,
        *,
        src_dir_fd: int | None = None,
        dst_dir_fd: int | None = None,
    ) -> None:
        nonlocal raced
        assert dst_dir_fd is not None
        if destination == target.name and not raced:
            raced = True
            real_unlink(destination, dir_fd=dst_dir_fd)
            target.symlink_to(victim)
        real_replace(
            source,
            destination,
            src_dir_fd=src_dir_fd,
            dst_dir_fd=dst_dir_fd,
        )

    real_exchange = getattr(weight_plan, "_rename_exchange", None)
    if real_exchange is None:
        real_replace = os.replace
        monkeypatch.setattr(os, "replace", replace_before_legacy_install)
    else:
        monkeypatch.setattr(weight_plan, "_rename_exchange", replace_before_exchange)
    with pytest.raises(weight_plan.WeightPlanTargetError):
        weight_plan.write_weight_plan_atomic(plan(), target)

    assert raced is True
    assert target.is_symlink()
    assert target.resolve() == victim
    assert victim.read_bytes() == b"foreign victim\n"


@pytest.mark.parametrize(
    "cleanup",
    [
        OSError(errno.EIO, "cleanup failed"),
        asyncio.CancelledError("cleanup cancelled"),
        PersistenceAbort("cleanup aborted"),
    ],
)
def test_successful_write_does_not_swallow_cleanup_failure_from_ambient_handler(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    cleanup: BaseException,
) -> None:
    real_cleanup = weight_plan._cleanup_temporary_plan

    def cleanup_then_fail(temporary: weight_plan._TemporaryPlan, directory_fd: int) -> None:
        real_cleanup(temporary, directory_fd)
        raise cleanup

    monkeypatch.setattr(weight_plan, "_cleanup_temporary_plan", cleanup_then_fail)
    try:
        raise LookupError("ambient caller exception")
    except LookupError:
        with pytest.raises(type(cleanup)) as caught:
            weight_plan.write_weight_plan_atomic(plan(), tmp_path / "weight-plan.json")

    assert caught.value is cleanup


def test_broken_add_note_preserves_primary_and_still_closes_directory_chain(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    primary = BrokenNoteAbort("primary persistence abort")
    close_attempted = False
    real_close = weight_plan._PinnedDirectoryChain.close

    def abort_install(*_args: Any, **_kwargs: Any) -> None:
        raise primary

    def fail_cleanup(_temporary: weight_plan._TemporaryPlan, _directory_fd: int) -> None:
        raise OSError(errno.EIO, "temporary cleanup failed")

    def close(chain: weight_plan._PinnedDirectoryChain) -> None:
        nonlocal close_attempted
        close_attempted = True
        real_close(chain)

    with monkeypatch.context() as patch:
        patch.setattr(weight_plan, "_open_unnamed_temporary", lambda _: None)
        patch.setattr(weight_plan, "_rename_noreplace", abort_install)
        patch.setattr(weight_plan, "_cleanup_temporary_plan", fail_cleanup)
        patch.setattr(weight_plan._PinnedDirectoryChain, "close", close)
        with pytest.raises(BrokenNoteAbort) as caught:
            weight_plan.write_weight_plan_atomic(plan(), tmp_path / "weight-plan.json")

    assert caught.value is primary
    assert close_attempted is True
    for residue in tmp_path.iterdir():
        residue.unlink(missing_ok=True)


def test_verifier_cleanup_cannot_mask_typed_persistence_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "weight-plan.json"
    rendered = plan().canonical_bytes()
    target.write_bytes(rendered)
    target.chmod(weight_plan.WEIGHT_PLAN_FILE_MODE)
    target_stat = target.stat()
    chain = weight_plan._pin_directory_chain(str(tmp_path))
    primary = weight_plan.WeightPlanTargetError("typed verifier failure")
    cleanup = PersistenceAbort("target descriptor close failed")
    real_close = os.close
    reopened_descriptors: list[int] = []
    real_pin = weight_plan._pin_directory_chain

    def pin(parent: str) -> weight_plan._PinnedDirectoryChain:
        reopened = real_pin(parent)
        reopened_descriptors.extend(reopened.descriptors)
        return reopened

    def fail_read(_descriptor: int) -> bytes:
        raise primary

    def close(descriptor: int) -> None:
        regular = stat.S_ISREG(os.fstat(descriptor).st_mode)
        real_close(descriptor)
        if regular:
            raise cleanup

    try:
        with monkeypatch.context() as patch:
            patch.setattr(weight_plan, "_pin_directory_chain", pin)
            patch.setattr(weight_plan, "_read_descriptor", fail_read)
            patch.setattr(os, "close", close)
            with pytest.raises(weight_plan.WeightPlanTargetError) as caught:
                weight_plan._verify_configured_target(
                    chain,
                    target.name,
                    identity=(target_stat.st_dev, target_stat.st_ino),
                    rendered=rendered,
                )
        assert caught.value is primary
        assert "target_cleanup_failed" in getattr(primary, "__notes__", ())
        for descriptor in set(reopened_descriptors):
            with pytest.raises(OSError) as closed:
                os.fstat(descriptor)
            assert closed.value.errno == errno.EBADF
    finally:
        chain.close()
