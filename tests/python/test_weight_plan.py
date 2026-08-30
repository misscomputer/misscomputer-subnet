# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import errno
import hashlib
import json
import math
import os
import stat
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

import misscomputer_subnet.weight_plan as weight_plan_module
from misscomputer_subnet.chain import MetagraphSnapshot, NeuronRecord
from misscomputer_subnet.weight_plan import (
    WEIGHT_PLAN_SCHEMA,
    WEIGHT_PLAN_SCHEMA_VERSION,
    WeightPlan,
    WeightPlanError,
    WeightPlanTargetError,
    build_weight_plan,
    conservative_expiry_block,
    write_weight_plan_atomic,
)

VALIDATOR = "validator-hotkey"
MINER_A = "miner-a-hotkey"
MINER_B = "miner-b-hotkey"
ROOT = Path(__file__).resolve().parents[2]


def snapshot(
    *,
    block: int = 101,
    tempo: int = 20,
    neurons: tuple[NeuronRecord, ...] | None = None,
    finalized: bool = True,
) -> MetagraphSnapshot:
    records = neurons or (
        NeuronRecord(0, VALIDATOR, True, 2_000.0, None),
        NeuronRecord(9, MINER_A, False, 10.0, "8.8.8.8:8091"),
        NeuronRecord(3, MINER_B, False, 11.0, "1.1.1.1:8091"),
    )
    return MetagraphSnapshot(
        network="finney",
        netuid=24,
        block=block,
        tempo=tempo,
        neurons=records,
        finalized=finalized,
    )


def rows() -> list[dict[str, object]]:
    return [
        {"miner_hotkey": MINER_A, "weight": 0.2, "samples": 8},
        {"miner_hotkey": MINER_B, "weight": 0.3, "samples": 9},
    ]


def plan(*, block: int = 101, tempo: int = 20) -> WeightPlan:
    return build_weight_plan(
        snapshot=snapshot(block=block, tempo=tempo),
        validator_hotkey=VALIDATOR,
        rows=rows(),
        version_key=2,
    )


def test_canonical_digest_is_stable_and_covers_the_unsigned_document() -> None:
    first = build_weight_plan(
        snapshot=snapshot(),
        validator_hotkey=VALIDATOR,
        rows=rows(),
        version_key=2,
    )
    second = build_weight_plan(
        snapshot=replace(snapshot(), neurons=tuple(reversed(snapshot().neurons))),
        validator_hotkey=VALIDATOR,
        rows=list(reversed(rows())),
        version_key=2,
    )

    assert first == second
    assert first.canonical_bytes() == second.canonical_bytes()
    with pytest.raises(FrozenInstanceError):
        first.network = "tampered"  # type: ignore[misc]
    assert [entry.uid for entry in first.weights] == [3, 9]
    assert [entry.hotkey for entry in first.weights] == [MINER_B, MINER_A]
    assert [entry.weight for entry in first.weights] == pytest.approx([0.6, 0.4])
    assert math.fsum(entry.weight for entry in first.weights) == pytest.approx(1.0)

    document = first.document()
    assert set(document) == {
        "created_block",
        "digest_sha256",
        "expires_at_block",
        "netuid",
        "network",
        "schema",
        "schema_version",
        "snapshot",
        "validator_hotkey",
        "version_key",
        "weights",
    }
    digest = document.pop("digest_sha256")
    unsigned = json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    assert digest == hashlib.sha256(unsigned).hexdigest()
    assert json.loads(first.canonical_bytes()) == first.document()


def test_weight_plan_v1_schema_and_canonical_digest_golden_fixture() -> None:
    schema = json.loads((ROOT / "contracts" / "schemas" / "weight-plan.v1.schema.json").read_text())
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    fixture_bytes = (ROOT / "contracts" / "fixtures" / "weight-plan.v1.json").read_bytes()
    expected = plan()

    assert fixture_bytes == expected.canonical_bytes()
    assert fixture_bytes.endswith(b"\n") and fixture_bytes.count(b"\n") == 1
    document = json.loads(fixture_bytes)
    validator.validate(document)
    assert document["digest_sha256"] == (
        "f50cc12a7e6db2743346d54c3c1b7d287607389bbe35057cdc4d983b6353e67b"
    )
    assert document["snapshot"]["identity_fingerprint"] == (
        "a27381e4ea7408ebce0f02f84143ea538e860a09a7401e7e6f647d3d60f2f5f9"
    )
    invalid = dict(document)
    invalid["unexpected"] = True
    assert list(validator.iter_errors(invalid))


def test_plan_binds_finalized_snapshot_identity_and_conservative_expiry() -> None:
    base = plan()
    assert base.schema == WEIGHT_PLAN_SCHEMA
    assert base.schema_version == WEIGHT_PLAN_SCHEMA_VERSION
    assert base.network == "finney"
    assert base.netuid == 24
    assert base.validator_hotkey == VALIDATOR
    assert base.snapshot.block == 101
    assert base.snapshot.tempo == 20
    assert base.snapshot.epoch == 5
    assert base.snapshot.finalized is True
    assert len(base.snapshot.identity_fingerprint) == 64
    assert base.created_block == 101
    assert base.expires_at_block == 106
    assert conservative_expiry_block(snapshot(block=118, tempo=20)) == 120

    later = plan(block=102)
    changed_identity = replace(
        snapshot(),
        neurons=(
            snapshot().neurons[0],
            replace(snapshot().neurons[1], tao_stake=10.5),
            snapshot().neurons[2],
        ),
    )
    rebound = build_weight_plan(
        snapshot=changed_identity,
        validator_hotkey=VALIDATOR,
        rows=rows(),
        version_key=2,
    )
    assert later.digest_sha256 != base.digest_sha256
    assert rebound.snapshot.identity_fingerprint != base.snapshot.identity_fingerprint
    assert rebound.digest_sha256 != base.digest_sha256


@pytest.mark.parametrize("bad_weight", [float("nan"), float("inf"), -0.1, 1.1, "0.5", True])
def test_invalid_nonfinite_or_out_of_range_weights_fail_closed(bad_weight: object) -> None:
    with pytest.raises(WeightPlanError):
        build_weight_plan(
            snapshot=snapshot(),
            validator_hotkey=VALIDATOR,
            rows=[{"miner_hotkey": MINER_A, "weight": bad_weight}],
            version_key=2,
        )


@pytest.mark.parametrize(
    "bad_rows",
    [
        [],
        [{"miner_hotkey": MINER_A, "weight": 0.0}],
        [
            {"miner_hotkey": MINER_A, "weight": 0.5},
            {"miner_hotkey": MINER_A, "weight": 0.5},
        ],
        [{"miner_hotkey": "unknown-hotkey", "weight": 1.0}],
        [{"miner_hotkey": VALIDATOR, "weight": 1.0}],
    ],
)
def test_empty_ambiguous_or_unbound_weight_rows_fail_closed(
    bad_rows: list[dict[str, object]],
) -> None:
    with pytest.raises(WeightPlanError):
        build_weight_plan(
            snapshot=snapshot(),
            validator_hotkey=VALIDATOR,
            rows=bad_rows,
            version_key=2,
        )


def test_unfinalized_or_duplicate_snapshot_identity_fails_closed() -> None:
    with pytest.raises(WeightPlanError, match="finalized"):
        build_weight_plan(
            snapshot=snapshot(finalized=False),
            validator_hotkey=VALIDATOR,
            rows=rows(),
            version_key=2,
        )

    unpermitted_validator = replace(snapshot().neurons[0], validator_permit=False)
    with pytest.raises(WeightPlanError, match="lacks a permit"):
        build_weight_plan(
            snapshot=replace(snapshot(), neurons=(unpermitted_validator, *snapshot().neurons[1:])),
            validator_hotkey=VALIDATOR,
            rows=rows(),
            version_key=2,
        )

    duplicate_uid = replace(snapshot().neurons[2], uid=9)
    with pytest.raises(WeightPlanError, match="duplicate UIDs"):
        build_weight_plan(
            snapshot=replace(snapshot(), neurons=(*snapshot().neurons[:2], duplicate_uid)),
            validator_hotkey=VALIDATOR,
            rows=rows(),
            version_key=2,
        )

    duplicate_hotkey = replace(snapshot().neurons[2], hotkey=MINER_A)
    with pytest.raises(WeightPlanError, match="duplicate hotkeys"):
        build_weight_plan(
            snapshot=replace(snapshot(), neurons=(*snapshot().neurons[:2], duplicate_hotkey)),
            validator_hotkey=VALIDATOR,
            rows=rows(),
            version_key=2,
        )


def test_atomic_plan_write_is_private_idempotent_and_replaces_new_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "plans" / "weight-plan.json"
    target.parent.mkdir(mode=0o700)
    fsync_kinds: list[str] = []
    real_fsync = os.fsync

    def recording_fsync(descriptor: int) -> None:
        fsync_kinds.append("directory" if stat.S_ISDIR(os.fstat(descriptor).st_mode) else "file")
        real_fsync(descriptor)

    monkeypatch.setattr(os, "fsync", recording_fsync)
    first = plan()
    assert write_weight_plan_atomic(first, target) is True
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert target.read_bytes() == first.canonical_bytes()
    assert fsync_kinds == ["file", "directory"]
    first_inode = target.stat().st_ino
    first_mtime = target.stat().st_mtime_ns

    fsync_kinds.clear()
    assert write_weight_plan_atomic(first, target) is False
    assert target.stat().st_ino == first_inode
    assert target.stat().st_mtime_ns == first_mtime
    assert fsync_kinds == []

    fsync_kinds.clear()
    replacement = plan(block=102)
    assert write_weight_plan_atomic(replacement, target) is True
    assert target.read_bytes() == replacement.canonical_bytes()
    assert target.stat().st_ino != first_inode
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert fsync_kinds == ["file", "directory"]


def test_unnamed_temporary_materialization_enoent_uses_visible_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "plans" / "weight-plan.json"
    target.parent.mkdir(mode=0o700)
    candidate = plan()

    def simulated_unnamed_open(directory_fd: int) -> int:
        name = ".simulated-unnamed-source"
        descriptor = os.open(
            name,
            os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
            0o600,
            dir_fd=directory_fd,
        )
        os.unlink(name, dir_fd=directory_fd)
        return descriptor

    def capability_limited_link(_descriptor: int, _directory_fd: int, name: str) -> None:
        raise OSError(errno.ENOENT, os.strerror(errno.ENOENT), name)

    monkeypatch.setattr(weight_plan_module, "_open_unnamed_temporary", simulated_unnamed_open)
    monkeypatch.setattr(weight_plan_module, "_link_unnamed_temporary", capability_limited_link)

    assert write_weight_plan_atomic(candidate, target) is True
    assert target.read_bytes() == candidate.canonical_bytes()
    assert stat.S_IMODE(target.stat().st_mode) == 0o600


def test_atomic_plan_write_rejects_symlink_nonregular_and_unsafe_targets(
    tmp_path: Path,
) -> None:
    candidate = plan()

    with pytest.raises(WeightPlanTargetError, match="must name a file"):
        write_weight_plan_atomic(candidate, tmp_path / "unused" / ".." / "plan.json")

    victim = tmp_path / "victim"
    victim.write_text("do not replace")
    victim.chmod(0o600)
    symlink = tmp_path / "symlink-plan"
    symlink.symlink_to(victim)
    with pytest.raises(WeightPlanTargetError):
        write_weight_plan_atomic(candidate, symlink)
    assert symlink.is_symlink()
    assert victim.read_text() == "do not replace"

    directory = tmp_path / "directory-plan"
    directory.mkdir()
    with pytest.raises(WeightPlanTargetError):
        write_weight_plan_atomic(candidate, directory)

    permissive = tmp_path / "permissive-plan"
    permissive.write_text("old")
    permissive.chmod(0o644)
    with pytest.raises(WeightPlanTargetError, match="mode 0600"):
        write_weight_plan_atomic(candidate, permissive)
    assert permissive.read_text() == "old"

    linked = tmp_path / "linked-plan"
    linked_source = tmp_path / "linked-source"
    linked_source.write_text("old")
    linked_source.chmod(0o600)
    os.link(linked_source, linked)
    with pytest.raises(WeightPlanTargetError, match="hard links"):
        write_weight_plan_atomic(candidate, linked)
    assert linked_source.read_text() == "old"

    real_parent = tmp_path / "real-parent"
    real_parent.mkdir()
    linked_parent = tmp_path / "linked-parent"
    linked_parent.symlink_to(real_parent, target_is_directory=True)
    with pytest.raises(WeightPlanTargetError, match="parent"):
        write_weight_plan_atomic(candidate, linked_parent / "plan.json")

    writable_parent = tmp_path / "writable-parent"
    writable_parent.mkdir(mode=0o700)
    writable_parent.chmod(0o777)
    with pytest.raises(WeightPlanTargetError, match="writable by group or other"):
        write_weight_plan_atomic(candidate, writable_parent / "plan.json")

    writable_ancestor = tmp_path / "writable-ancestor"
    writable_ancestor.mkdir(mode=0o700)
    safe_child = writable_ancestor / "safe-child"
    safe_child.mkdir(mode=0o700)
    writable_ancestor.chmod(0o777)
    with pytest.raises(WeightPlanTargetError, match="ancestor.*writable by group or other"):
        write_weight_plan_atomic(candidate, safe_child / "plan.json")


def test_intermediate_symlink_race_cannot_redirect_install(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    trusted = tmp_path / "trusted"
    component = trusted / "component"
    parent = component / "plans"
    parent.mkdir(parents=True, mode=0o700)
    trusted.chmod(0o700)
    component.chmod(0o700)
    parent.chmod(0o700)

    victim_root = tmp_path / "victim-root"
    victim_parent = victim_root / "plans"
    victim_parent.mkdir(parents=True, mode=0o700)
    victim = victim_parent / "weight-plan.json"
    victim.write_bytes(b"qualifying victim")
    victim.chmod(0o600)

    moved_component = trusted / "component-original"
    raced = False
    real_fsync = os.fsync

    def replace_component_with_symlink(descriptor: int) -> None:
        nonlocal raced
        real_fsync(descriptor)
        if raced or not stat.S_ISREG(os.fstat(descriptor).st_mode):
            return
        raced = True
        component.rename(moved_component)
        component.symlink_to(victim_root, target_is_directory=True)

    monkeypatch.setattr(os, "fsync", replace_component_with_symlink)
    with pytest.raises(WeightPlanTargetError, match="chain|directory|symlink"):
        write_weight_plan_atomic(plan(), parent / "weight-plan.json")

    assert raced is True
    assert component.is_symlink()
    assert victim.read_bytes() == b"qualifying victim"
    assert not (moved_component / "plans" / "weight-plan.json").exists()


def test_parent_rename_race_fails_if_configured_path_does_not_receive_plan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent = tmp_path / "plans"
    parent.mkdir(mode=0o700)
    target = parent / "weight-plan.json"
    target.write_bytes(b"original plan")
    target.chmod(0o600)
    moved_parent = tmp_path / "plans-original"
    candidate = plan(block=102)
    real_replace = os.replace
    raced = False

    def rename_parent_before_install(
        source: str,
        destination: str,
        *,
        src_dir_fd: int | None = None,
        dst_dir_fd: int | None = None,
    ) -> None:
        nonlocal raced
        assert raced is False
        raced = True
        parent.rename(moved_parent)
        parent.mkdir(mode=0o700)
        replacement = parent / "weight-plan.json"
        replacement.write_bytes(b"qualifying replacement")
        replacement.chmod(0o600)
        real_replace(
            source,
            destination,
            src_dir_fd=src_dir_fd,
            dst_dir_fd=dst_dir_fd,
        )

    monkeypatch.setattr(os, "replace", rename_parent_before_install)
    with pytest.raises(WeightPlanTargetError, match="configured weight plan directory changed"):
        write_weight_plan_atomic(candidate, target)

    assert raced is True
    assert target.read_bytes() == b"qualifying replacement"
    assert (moved_parent / "weight-plan.json").read_bytes() == candidate.canonical_bytes()


def test_visible_temporary_hardlink_during_fsync_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent = tmp_path / "plans"
    parent.mkdir(mode=0o700)
    target = parent / "weight-plan.json"
    stolen = parent / "stolen-plan"
    candidate = plan()
    real_fsync = os.fsync
    linked = False

    monkeypatch.setattr(weight_plan_module, "_open_unnamed_temporary", lambda _: None)

    def hardlink_during_fsync(descriptor: int) -> None:
        nonlocal linked
        if not linked and stat.S_ISREG(os.fstat(descriptor).st_mode):
            temporary = next(parent.glob(".weight-plan.tmp-*"))
            os.link(temporary, stolen)
            linked = True
        real_fsync(descriptor)

    monkeypatch.setattr(os, "fsync", hardlink_during_fsync)
    with pytest.raises(WeightPlanTargetError, match="unexpected hard link"):
        write_weight_plan_atomic(candidate, target)

    assert linked is True
    assert not target.exists()
    assert stolen.read_bytes() == candidate.canonical_bytes()
    assert stolen.stat().st_nlink == 1
