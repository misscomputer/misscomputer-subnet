# SPDX-License-Identifier: AGPL-3.0-only
"""PR17 round-23 terminal install and cleanup ownership regressions."""

from __future__ import annotations

import errno
import os
from pathlib import Path
from typing import Any

import pytest
from test_weight_plan import plan

import misscomputer_subnet.weight_plan as weight_plan


def _write_foreign(directory_fd: int, name: str, body: bytes) -> int:
    descriptor = os.open(
        name,
        os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        weight_plan.WEIGHT_PLAN_FILE_MODE,
        dir_fd=directory_fd,
    )
    os.write(descriptor, body)
    return descriptor


def _owned_temporary(directory_fd: int, name: str) -> weight_plan._TemporaryPlan:
    descriptor = _write_foreign(directory_fd, name, b"owned temporary\n")
    value = os.fstat(descriptor)
    return weight_plan._TemporaryPlan(
        descriptor=descriptor,
        identity=(value.st_dev, value.st_ino),
        name=name,
    )


def test_move_aside_substitution_restores_original_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """INSTALL-1: a post-exchange source substitution cannot become canonical."""

    target = tmp_path / "weight-plan.json"
    original = plan(block=101)
    candidate = plan(block=102)
    assert weight_plan.write_weight_plan_atomic(original, target) is True
    real_exchange = weight_plan._rename_exchange
    foreign_descriptor = -1
    source_name: str | None = None
    moved_name = ".attacker-moved-original"
    raced = False

    def move_aside(directory_fd: int, source: str, destination: str) -> None:
        nonlocal foreign_descriptor, source_name, raced
        real_exchange(directory_fd, source, destination)
        if destination == target.name and not raced:
            raced = True
            source_name = source
            os.rename(
                source,
                moved_name,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
            )
            foreign_descriptor = _write_foreign(
                directory_fd,
                source,
                b"foreign move-aside substitution\n",
            )

    try:
        monkeypatch.setattr(weight_plan, "_rename_exchange", move_aside)
        with pytest.raises(weight_plan.WeightPlanTargetError):
            weight_plan.write_weight_plan_atomic(candidate, target)

        assert raced is True
        assert target.read_bytes() == original.canonical_bytes()
        assert source_name is not None
        assert (tmp_path / source_name).read_bytes() == b"foreign move-aside substitution\n"
    finally:
        if foreign_descriptor >= 0:
            os.close(foreign_descriptor)


def test_same_inode_overwrite_after_exchange_restores_original_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """INSTALL-2: rollback never publishes a content-mutated displaced inode."""

    target = tmp_path / "weight-plan.json"
    original = plan(block=101)
    candidate = plan(block=102)
    assert weight_plan.write_weight_plan_atomic(original, target) is True
    real_exchange = weight_plan._rename_exchange
    raced = False

    def overwrite_displaced(directory_fd: int, source: str, destination: str) -> None:
        nonlocal raced
        real_exchange(directory_fd, source, destination)
        if destination == target.name and not raced:
            raced = True
            descriptor = os.open(
                source,
                os.O_WRONLY | os.O_TRUNC | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=directory_fd,
            )
            try:
                os.write(descriptor, b"same inode, foreign bytes\n")
            finally:
                os.close(descriptor)

    monkeypatch.setattr(weight_plan, "_rename_exchange", overwrite_displaced)
    with pytest.raises(weight_plan.WeightPlanTargetError):
        weight_plan.write_weight_plan_atomic(candidate, target)

    assert raced is True
    assert target.read_bytes() == original.canonical_bytes()


def test_initial_creation_source_substitution_is_rolled_back(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """INSTALL-3: creation never leaves substituted source bytes at the target."""

    target = tmp_path / "weight-plan.json"
    real_noreplace = weight_plan._rename_noreplace
    foreign_descriptor = -1
    source_name: str | None = None
    raced = False

    def substitute_source(directory_fd: int, source: str, destination: str) -> None:
        nonlocal foreign_descriptor, source_name, raced
        if destination == target.name and not raced:
            raced = True
            source_name = source
            os.unlink(source, dir_fd=directory_fd)
            foreign_descriptor = _write_foreign(
                directory_fd,
                source,
                b"foreign initial source\n",
            )
        real_noreplace(directory_fd, source, destination)

    try:
        monkeypatch.setattr(weight_plan, "_rename_noreplace", substitute_source)
        with pytest.raises(weight_plan.WeightPlanTargetError):
            weight_plan.write_weight_plan_atomic(plan(), target)

        assert raced is True
        assert target.read_bytes() == b"foreign initial source\n"
        assert source_name is not None
        assert not (tmp_path / source_name).exists()
    finally:
        if foreign_descriptor >= 0:
            os.close(foreign_descriptor)


@pytest.mark.parametrize(
    "race_point",
    ["before_move", "after_move", "private_validation", "exception_restore"],
)
def test_all_terminal_retirement_paths_preserve_late_foreign_replacements(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    race_point: str,
) -> None:
    """UNLINK-1/2/3/4: shared names are never destructively unlinked after a check."""

    directory_fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    source = ".weight-plan.tmp-owned"
    temporary = _owned_temporary(directory_fd, source)
    descriptor = temporary.descriptor
    body = f"late foreign replacement at {race_point}\n".encode()
    real_move = weight_plan._rename_noreplace_between
    real_stat = os.stat
    real_fstat = os.fstat
    moved = False
    injected = False
    primary = OSError(errno.EIO, "post-move ownership validation failed")

    def replace_source() -> None:
        nonlocal injected
        if injected:
            return
        injected = True
        try:
            os.unlink(source, dir_fd=directory_fd)
        except FileNotFoundError:
            pass
        foreign = _write_foreign(directory_fd, source, body)
        os.close(foreign)

    def move(
        source_fd: int,
        source_name: str,
        destination_fd: int,
        destination_name: str,
    ) -> None:
        nonlocal moved
        installing = source_fd == directory_fd and source_name == source and not moved
        if installing and race_point == "before_move":
            replace_source()
        real_move(source_fd, source_name, destination_fd, destination_name)
        if installing:
            moved = True
            if race_point in {"after_move", "exception_restore"}:
                replace_source()

    def stat_value(path: int | str | bytes, *args: Any, **kwargs: Any) -> os.stat_result:
        nonlocal injected
        if (
            race_point == "private_validation"
            and moved
            and path == ".weight-plan.cleanup-retired"
            and not injected
        ):
            private_fd = kwargs.get("dir_fd")
            assert isinstance(private_fd, int)
            os.unlink(path, dir_fd=private_fd)
            foreign = _write_foreign(private_fd, str(path), body)
            os.close(foreign)
            injected = True
            # The captured foreign entry is restored to the now-empty source.
        return real_stat(path, *args, **kwargs)

    def fstat_value(descriptor_value: int) -> os.stat_result:
        if race_point == "exception_restore" and moved and descriptor_value == descriptor:
            raise primary
        return real_fstat(descriptor_value)

    try:
        monkeypatch.setattr(weight_plan, "_rename_noreplace_between", move)
        monkeypatch.setattr(os, "stat", stat_value)
        monkeypatch.setattr(os, "fstat", fstat_value)
        if race_point == "exception_restore":
            with pytest.raises(OSError) as caught:
                weight_plan._cleanup_temporary_plan(temporary, directory_fd)
            assert caught.value is primary
        else:
            weight_plan._cleanup_temporary_plan(temporary, directory_fd)
        assert injected is True
        assert (tmp_path / source).read_bytes() == body
    finally:
        for residue in tmp_path.iterdir():
            if residue.is_dir():
                for child in residue.iterdir():
                    child.unlink(missing_ok=True)
                residue.rmdir()
            else:
                residue.unlink(missing_ok=True)
        try:
            os.close(descriptor)
        except OSError as exc:
            assert exc.errno == errno.EBADF
        os.close(directory_fd)


def test_cleanup_fallback_enoent_is_not_mistaken_for_retirement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CLEANUP-ENOENT: nested fallback ENOENT cannot be blanket-suppressed."""

    target = tmp_path / "weight-plan.json"
    original = plan(block=101)
    replacement = plan(block=102)
    assert weight_plan.write_weight_plan_atomic(original, target) is True

    def unavailable_link(_descriptor: int, _directory_fd: int, name: str) -> None:
        raise OSError(errno.ENOENT, os.strerror(errno.ENOENT), name)

    monkeypatch.setattr(weight_plan, "_link_unnamed_temporary", unavailable_link)

    assert weight_plan.write_weight_plan_atomic(replacement, target) is True
    assert target.read_bytes() == replacement.canonical_bytes()
    assert not list(tmp_path.glob(".weight-plan.tmp-*"))
    assert list(tmp_path.glob(".weight-plan.cleanup-*"))
