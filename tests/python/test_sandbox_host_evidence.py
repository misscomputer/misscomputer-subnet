# SPDX-License-Identifier: AGPL-3.0-only
"""Synthetic files prove evidence lifetime and failure handling, never real OOM attribution."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts/sandbox-host/evidence.py"


def invoke(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed repository CLI, local fixture paths
        [sys.executable, "-I", str(SCRIPT), *args],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )


def ready(path: Path, process: subprocess.Popen[str]) -> None:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if path.exists():
            return
        if process.poll() is not None:
            pytest.fail(f"sampler exited before readiness: {process.communicate()}")
        time.sleep(0.01)
    pytest.fail("sampler did not become ready")


@pytest.mark.parametrize("kind", ["pids", "memory"])
@pytest.mark.parametrize("fault", ["disappearance", "read-error", "replacement"])
def test_sampler_retains_complete_samples_and_distinguishes_disappearance(
    tmp_path: Path,
    kind: str,
    fault: str,
) -> None:
    child, work = tmp_path / "child", tmp_path / "work"
    child.mkdir()
    work.mkdir()
    values = {"pids.events": "max 1\n", "pids.current": "56\n", "pids.max": "64\n"}
    prefix, counter, retained = "pids", "pids.current", "pids.events"
    if kind == "memory":
        values = {
            "memory.events.local": "max 0\noom 0\noom_kill 0\n",
            "memory.peak": "30035968\n",
            "memory.max": "268435456\n",
            "memory.swap.max": "0\n",
        }
        prefix, counter, retained = "tmp", "memory.peak", "tmp.events"
    for name, raw in values.items():
        (child / name).write_text(raw)
    process = subprocess.Popen(  # noqa: S603 - fixed CLI and local fixtures
        [sys.executable, "-I", str(SCRIPT), "sample", kind, str(child), str(work)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        ready(work / f"{prefix}-ready.json", process)
        first = json.loads((work / f"{prefix}-ready.json").read_text())
        assert first["cgroup"] == str(child)
        original = (work / retained).read_bytes()
        if fault == "disappearance":
            shutil.rmtree(child)
        elif fault == "read-error":
            (child / counter).unlink()
            (child / counter).mkdir()
        else:
            child.rename(tmp_path / "old-child")
            child.mkdir()
        _, stderr = process.communicate(timeout=5)
        assert process.returncode == (0 if fault == "disappearance" else 1), stderr
        status = json.loads((work / f"{prefix}-status.json").read_text())
        assert status["reason"] == (
            "cgroup_disappeared" if fault == "disappearance" else "read_error"
        )
        assert status["samples"] >= 1
        assert (work / retained).read_bytes() == original
        history = [
            json.loads(line) for line in (work / f"{prefix}-samples.jsonl").read_text().splitlines()
        ]
        assert history[0] == first["first_sample"]
        assert all(row["monotonic_ns"] >= first["first_sample"]["monotonic_ns"] for row in history)
        # Export survives deletion of work; unknown material is never traversed.
        (work / "private-secret").write_text("must not export")
        output = tmp_path / "raw.json"
        result = invoke("export", str(work), str(output))
        assert result.returncode == 0, result.stderr
        shutil.rmtree(work)
        bundle = json.loads(output.read_text())
        assert bundle["files"][retained]["text"].encode() == original
        assert "private-secret" not in bundle["files"]
        assert bundle["files"][f"{prefix}-status.json"]["status"] == "captured"
    finally:
        if process.poll() is None:
            process.terminate()
            process.communicate(timeout=5)


def test_raw_export_reports_unsafe_known_file_without_reading_target(tmp_path: Path) -> None:
    work = tmp_path / "work"
    work.mkdir()
    secret = tmp_path / "secret"
    secret.write_text("must never be exported")
    (work / "tmp.log").symlink_to(secret)
    output = tmp_path / "raw.json"
    result = invoke("export", str(work), str(output))
    assert result.returncode != 0
    bundle = json.loads(output.read_text())
    assert bundle["errors"] == ["tmp.log"]
    assert bundle["files"]["tmp.log"]["status"] == "error"
    assert secret.read_text() not in output.read_text()


def test_ancestor_snapshots_retain_before_after_limits_and_local_events(tmp_path: Path) -> None:
    root = tmp_path / "cgroup"
    parent = root / "lease"
    child = parent / "child"
    child.mkdir(parents=True)
    for name, raw in {
        "memory.events": "oom 0\n",
        "memory.events.local": "oom 0\n",
        "memory.current": "100\n",
        "memory.max": "2048\n",
        "memory.swap.max": "0\n",
    }.items():
        (parent / name).write_text(raw)
    before, after = tmp_path / "before.json", tmp_path / "after.json"
    assert invoke("ancestors", str(root), str(child), str(before)).returncode == 0
    shutil.rmtree(child)
    (parent / "memory.events.local").write_text("oom 1\n")
    assert invoke("ancestors", str(root), str(child), str(after)).returncode == 0
    baseline, terminal = json.loads(before.read_text()), json.loads(after.read_text())
    assert baseline["ancestors"][0]["values"]["memory.events.local"] == "oom 0\n"
    assert terminal["ancestors"][0]["values"]["memory.events.local"] == "oom 1\n"
    assert terminal["ancestors"][0]["inode"] == baseline["ancestors"][0]["inode"]
    assert terminal["use"].startswith("diagnostic only")
