# SPDX-License-Identifier: AGPL-3.0-only
"""sandbox-host-preflight.v1 reports cannot relabel evidence, drop gaps or claim a verdict."""

from __future__ import annotations

import copy
import importlib.util
from pathlib import Path
from typing import Any

import pytest

_SPEC = importlib.util.spec_from_file_location(
    "sandbox_host_report",
    Path(__file__).resolve().parents[2] / "scripts" / "sandbox-host" / "report.py",
)
assert _SPEC and _SPEC.loader
report = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(report)

ROOT = "/run/mcsbx"
PROFILE: dict[str, Any] = {
    "schema": report.PROFILE_SCHEMA,
    "schema_version": 1,
    "docker_host": f"unix://{ROOT}/run/docker/docker.sock",
    "containerd": {
        "address": f"{ROOT}/run/containerd/containerd.sock",
        "namespace": "mc-sandbox",
        "plugins_namespace": "mc-sandbox-plugins",
    },
    "data_root": f"{ROOT}/data",
    "docker_data_root": f"{ROOT}/data/docker",
    "run_root": f"{ROOT}/run",
    "runtime": {
        "name": "runsc",
        "path": f"{ROOT}/bin/runsc",
        "sha256": "a" * 64,
        "sentry_path": f"{ROOT}/bin/gvisor-bin/gvisor_sentry",
        "sentry_sha256": "b" * 64,
        "args": ["--systemd-cgroup", "--overlay2=none"],
        "release": "release-20261005.0",
    },
    "engine": {"docker_version": "28.0.4"},
    "cgroup_root": "/sys/fs/cgroup",
    "lease_slice": "mcsbxlease.slice",
    "engine_slice": "mcsbxengine.slice",
    "aggregate": {
        "cpu_millis": 2000,
        "memory_mib": 1024,
        "pids": 1024,
        "data_fs_mib": 4096,
        "run_tmpfs_mib": 64,
        "image_reserve_mib": 512,
        "engine_overhead_mib": 512,
        "image_max_mib": 256,
        "log_mib": 16,
        "disk_mib": 1984,
        "sandboxes": 4,
    },
    "per_lease": {
        "default_writable_mib": 64,
        "log_max_size_mib": 8,
        "log_max_file": 2,
        "pids_max": 64,
        "mounts": "none",
        "image_volumes": "refuse",
        "network_modes": ["none"],
        "isolation": ["gvisor"],
    },
}


def _complete(mode: str) -> list[dict[str, Any]]:
    entries = []
    for cid, known in report.load_catalog().items():
        if mode in known["modes"]:
            status = "gap" if known["class"] == "unenforced" else "pass"
            entries.append(
                {"id": cid, "class": known["class"], "status": status, "evidence": "observed"}
            )
    return entries


@pytest.mark.parametrize("mode", report.MODES)
def test_complete_ledger_passes_and_names_every_gap(mode: str) -> None:
    built = report.build_report(_complete(mode), PROFILE, mode, {"source_sha": "0" * 40})
    report.validate(built)
    assert built["verdict"] == "pass"
    gaps = sorted(
        c
        for c, k in report.load_catalog().items()
        if mode in k["modes"] and k["class"] == "unenforced"
    )
    assert built["unenforced"] == gaps
    if mode != "instance":
        assert "storage.images_cache_unreserved" in built["unenforced"]


def test_unreached_check_is_not_run_and_fails_the_verdict() -> None:
    entries = [e for e in _complete("conformance") if e["id"] != "effect.writable_layer_quota"]
    built = report.build_report(entries, PROFILE, "conformance", {})
    assert built["verdict"] == "fail"
    assert {
        "id": "effect.writable_layer_quota",
        "class": "observed_effect",
        "status": "not_run",
        "evidence": "not reached",
    } in built["checks"]


@pytest.mark.parametrize(
    ("mode", "cid", "field", "value"),
    [
        # observation relabelled as a setting, setting as observation, gap as enforcement
        ("conformance", "effect.writable_layer_quota", "class", "configured"),
        ("conformance", "engine.firewall_management_off", "class", "observed_state"),
        ("conformance", "storage.images_cache_unreserved", "status", "pass"),
        ("conformance", "lease.child_limits_match", "status", "gap"),
    ],
)
def test_relabelled_evidence_is_rejected(mode: str, cid: str, field: str, value: str) -> None:
    entries = _complete(mode)
    next(e for e in entries if e["id"] == cid)[field] = value
    with pytest.raises(report.ReportError):
        report.build_report(entries, PROFILE, mode, {})


def test_effect_check_cannot_appear_in_live_preflight() -> None:
    entries = _complete("preflight") + [
        {
            "id": "effect.writable_layer_quota",
            "class": "observed_effect",
            "status": "pass",
            "evidence": "x",
        }
    ]
    with pytest.raises(report.ReportError, match="not part of mode preflight"):
        report.build_report(entries, PROFILE, "preflight", {})


@pytest.mark.parametrize(
    "tamper",
    [
        lambda r: r.update(verdict="pass") or r["checks"][0].update(status="fail"),
        lambda r: r.update(unenforced=r["unenforced"][1:]),
        lambda r: r["checks"].pop(),
    ],
)
def test_validate_rejects_tampered_reports(tamper: Any) -> None:
    built = report.build_report(_complete("conformance"), PROFILE, "conformance", {})
    tamper(built)
    with pytest.raises(report.ReportError):
        report.validate(built)


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("docker_host",), "unix:///var/run/docker.sock"),
        (("containerd", "namespace"), "moby"),
        (("runtime", "args"), ["--systemd-cgroup"]),
        # D7: lane disk + per-sandbox image/log + reserves would exceed the data fs
        (("aggregate", "disk_mib"), 1985),
        (("aggregate", "log_mib"), 8),
        (("per_lease", "pids_max"), 512),  # 4 x 512 > aggregate pids 1024
        (("per_lease", "network_modes"), ["none", "public"]),
        (("lease_slice",), "mc-sandbox.slice"),
    ],
)
def test_profile_rejects_unprovable_or_shared_configuration(
    path: tuple[str, ...], value: Any
) -> None:
    profile = copy.deepcopy(PROFILE)
    target = profile
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    with pytest.raises(report.ReportError):
        report.check_profile(profile)
