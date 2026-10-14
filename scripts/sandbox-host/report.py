#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Ledger and report tool for sandbox-host-preflight.v1.

The check catalog (pkg/sandboxhost/check-catalog.v1.json) is the single
source of check IDs and their evidence class. A report is valid only if every
catalog check of its mode appears exactly once with the catalog class, so an
observation cannot be relabelled and a gap cannot be dropped. The verdict is
derived, never supplied: pass only when every check passed and every
unenforced check is reported as a gap.

Commands:
  record LEDGER ID CLASS STATUS EVIDENCE
  finalize LEDGER PROFILE MODE OUT [KEY=VALUE ...]
  validate REPORT
  check-profile PROFILE
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

CATALOG_PATH = Path(__file__).resolve().parents[2] / "pkg" / "sandboxhost" / "check-catalog.v1.json"
REPORT_SCHEMA = "miss.computer/misscomputer-subnet/sandbox-host-preflight"
PROFILE_SCHEMA = "miss.computer/misscomputer-subnet/sandbox-host-profile"
MODES = ("conformance", "preflight", "instance")
CLASSES = ("observed_effect", "observed_state", "configured", "unenforced")
ENV_KEYS = (
    "source_sha",
    "github_run_id",
    "runner_image",
    "kernel",
    "systemd",
    "docker",
    "containerd",
    "runsc",
)
_EVIDENCE = re.compile(r"[\x20-\x7e]{0,512}")
_ID = re.compile(r"[a-z0-9]+(\.[a-z0-9_]+)+")


class ReportError(ValueError):
    """A ledger, profile or report violates the contract."""


def load_catalog(path: Path = CATALOG_PATH) -> dict[str, dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema_version") != 1:
        raise ReportError("unsupported catalog version")
    checks: dict[str, dict[str, Any]] = {}
    for entry in data["checks"]:
        cid = entry["id"]
        if cid in checks or not _ID.fullmatch(cid) or entry["class"] not in CLASSES:
            raise ReportError(f"invalid catalog entry {cid!r}")
        if not entry["modes"] or set(entry["modes"]) - set(MODES):
            raise ReportError(f"invalid catalog modes for {cid!r}")
        if entry.get("owner") not in ("lane1", "lane2"):
            raise ReportError(f"catalog entry {cid!r} has no owner")
        if entry["class"] == "observed_effect" and entry["modes"] != ["conformance"]:
            raise ReportError(f"observed_effect check {cid!r} must be conformance-only")
        checks[cid] = entry
    return checks


def _check_entry(entry: dict[str, Any], catalog: dict[str, dict[str, Any]], mode: str) -> None:
    if set(entry) != {"id", "class", "status", "evidence"}:
        raise ReportError(f"check entry has fields {sorted(entry)}")
    cid = entry["id"]
    known = catalog.get(cid)
    if known is None:
        raise ReportError(f"unknown check {cid!r}")
    if mode not in known["modes"]:
        raise ReportError(f"check {cid!r} is not part of mode {mode}")
    if entry["class"] != known["class"]:
        raise ReportError(f"check {cid!r} is class {known['class']}, not {entry['class']}")
    status = entry["status"]
    allowed = ("gap", "not_run") if known["class"] == "unenforced" else ("pass", "fail", "not_run")
    if status not in allowed:
        raise ReportError(
            f"check {cid!r} of class {known['class']} cannot report status {status!r}"
        )
    if not isinstance(entry["evidence"], str) or not _EVIDENCE.fullmatch(entry["evidence"]):
        raise ReportError(f"check {cid!r} evidence must be printable ASCII of at most 512 bytes")


def record(ledger: Path, cid: str, klass: str, status: str, evidence: str) -> None:
    catalog = load_catalog()
    if cid not in catalog:
        raise ReportError(f"unknown check {cid!r}")
    entry = {"id": cid, "class": klass, "status": status, "evidence": evidence[:512]}
    _check_entry(entry, catalog, catalog[cid]["modes"][0])
    with ledger.open("a", encoding="utf-8") as out:
        out.write(json.dumps(entry, sort_keys=True) + "\n")


def _canonical_digest(document: dict[str, Any]) -> str:
    raw = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def build_report(
    entries: list[dict[str, Any]], profile: dict[str, Any], mode: str, environment: dict[str, str]
) -> dict[str, Any]:
    if mode not in MODES:
        raise ReportError(f"unknown mode {mode!r}")
    check_profile(profile)
    catalog = load_catalog()
    by_id: dict[str, dict[str, Any]] = {}
    for entry in entries:
        _check_entry(entry, catalog, mode)
        if entry["id"] in by_id:
            raise ReportError(f"check {entry['id']!r} recorded twice")
        by_id[entry["id"]] = entry
    checks = []
    for cid, known in catalog.items():
        if mode not in known["modes"]:
            continue
        checks.append(
            by_id.get(cid)
            or {"id": cid, "class": known["class"], "status": "not_run", "evidence": "not reached"}
        )
    unknown_env = set(environment) - set(ENV_KEYS)
    if unknown_env:
        raise ReportError(f"unknown environment keys {sorted(unknown_env)}")
    report = {
        "schema": REPORT_SCHEMA,
        "schema_version": 1,
        "mode": mode,
        "environment": {key: environment.get(key) for key in ENV_KEYS},
        "profile_digest": _canonical_digest(profile),
        "checks": checks,
        "unenforced": sorted(c["id"] for c in checks if c["class"] == "unenforced"),
        "verdict": derive_verdict(checks),
    }
    return report


def derive_verdict(checks: list[dict[str, Any]]) -> str:
    for check in checks:
        expected = "gap" if check["class"] == "unenforced" else "pass"
        if check["status"] != expected:
            return "fail"
    return "pass"


def validate(report: dict[str, Any]) -> None:
    fields = {
        "schema",
        "schema_version",
        "mode",
        "environment",
        "profile_digest",
        "checks",
        "unenforced",
        "verdict",
    }
    if set(report) != fields or report["schema"] != REPORT_SCHEMA or report["schema_version"] != 1:
        raise ReportError("not a sandbox-host-preflight.v1 report")
    mode = report["mode"]
    if mode not in MODES:
        raise ReportError(f"unknown mode {mode!r}")
    catalog = load_catalog()
    seen = []
    for entry in report["checks"]:
        _check_entry(entry, catalog, mode)
        seen.append(entry["id"])
    expected = [cid for cid, known in catalog.items() if mode in known["modes"]]
    if seen != expected:
        raise ReportError("report checks do not match the catalog for its mode")
    if report["unenforced"] != sorted(
        c["id"] for c in report["checks"] if c["class"] == "unenforced"
    ):
        raise ReportError("unenforced list does not name every unenforced check")
    if report["verdict"] != derive_verdict(report["checks"]):
        raise ReportError("verdict is not derived from the checks")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", str(report["profile_digest"])):
        raise ReportError("profile_digest is malformed")


def _abs(value: Any, name: str) -> str:
    if (
        not isinstance(value, str)
        or not value.startswith("/")
        or "//" in value
        or "/../" in value
        or value.endswith("/..")
    ):
        raise ReportError(f"profile {name} must be a clean absolute path")
    return value


def _pos(value: Any, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ReportError(f"profile {name} must be a positive integer")
    return value


def disk_required_mib(aggregate: dict[str, int]) -> int:
    """Shared-contract D7: lease writable quota is disk_mib; logs and images are overhead."""
    return (
        aggregate["disk_mib"]
        + aggregate["sandboxes"] * (aggregate["image_max_mib"] + aggregate["log_mib"])
        + aggregate["engine_overhead_mib"]
        + aggregate["image_reserve_mib"]
    )


def check_profile(profile: dict[str, Any]) -> None:
    required = {
        "schema",
        "schema_version",
        "docker_host",
        "containerd",
        "data_root",
        "docker_data_root",
        "run_root",
        "runtime",
        "engine",
        "cgroup_root",
        "lease_slice",
        "engine_slice",
        "aggregate",
        "per_lease",
    }
    if (
        set(profile) != required
        or profile["schema"] != PROFILE_SCHEMA
        or profile["schema_version"] != 1
    ):
        raise ReportError("not a sandbox-host-profile.v1 document")
    host = profile["docker_host"]
    if (
        not isinstance(host, str)
        or not host.startswith("unix:///")
        or host == "unix:///var/run/docker.sock"
        or host == "unix:///run/docker.sock"
    ):
        raise ReportError("docker_host must be a dedicated unix socket")
    _abs(host[len("unix://") :], "docker_host")
    for name in ("data_root", "docker_data_root", "run_root", "cgroup_root"):
        _abs(profile[name], name)
    if not profile["docker_data_root"].startswith(profile["data_root"] + "/"):
        raise ReportError("docker_data_root must be below data_root")
    containerd = profile["containerd"]
    if (
        set(containerd) != {"address", "namespace", "plugins_namespace"}
        or containerd["address"] == "/run/containerd/containerd.sock"
    ):
        raise ReportError("containerd must name a dedicated address and namespaces")
    _abs(containerd["address"], "containerd.address")
    if containerd["namespace"] in ("", "moby", "default") or containerd["plugins_namespace"] in (
        "",
        "plugins.moby",
        containerd["namespace"],
    ):
        raise ReportError("containerd namespaces must be dedicated")
    runtime = profile["runtime"]
    if (
        set(runtime)
        != {"name", "path", "sha256", "sentry_path", "sentry_sha256", "args", "release"}
        or runtime["name"] != "runsc"
    ):
        raise ReportError("runtime must be the pinned runsc")
    _abs(runtime["path"], "runtime.path")
    _abs(runtime["sentry_path"], "runtime.sentry_path")
    if not all(
        re.fullmatch(r"[0-9a-f]{64}", str(runtime[k])) for k in ("sha256", "sentry_sha256")
    ) or runtime["args"] != ["--systemd-cgroup", "--overlay2=none"]:
        raise ReportError(
            "runtime must carry a sha256 and exactly --systemd-cgroup --overlay2=none"
        )
    for name in ("lease_slice", "engine_slice"):
        slice_name = profile[name]
        if not isinstance(slice_name, str) or not re.fullmatch(r"[a-z0-9]+\.slice", slice_name):
            raise ReportError(f"{name} must be a top-level slice name without '-'")
    if profile["lease_slice"] == profile["engine_slice"]:
        raise ReportError("lease and engine slices must differ")
    aggregate = profile["aggregate"]
    keys = {
        "cpu_millis",
        "memory_mib",
        "pids",
        "data_fs_mib",
        "run_tmpfs_mib",
        "image_reserve_mib",
        "engine_overhead_mib",
        "disk_mib",
        "sandboxes",
        "image_max_mib",
        "log_mib",
    }
    if set(aggregate) != keys:
        raise ReportError("aggregate has unexpected members")
    for key in keys:
        _pos(aggregate[key], "aggregate." + key)
    if disk_required_mib(aggregate) > aggregate["data_fs_mib"]:
        raise ReportError(
            "data_fs_mib is below disk_mib + sandboxes x (image_max_mib + log_mib)"
            " + engine_overhead_mib + image_reserve_mib"
        )
    per_lease = profile["per_lease"]
    if set(per_lease) != {
        "default_writable_mib",
        "log_max_size_mib",
        "log_max_file",
        "pids_max",
        "mounts",
        "image_volumes",
        "network_modes",
        "isolation",
    }:
        raise ReportError("per_lease has unexpected members")
    for key in ("default_writable_mib", "log_max_size_mib", "log_max_file", "pids_max"):
        _pos(per_lease[key], "per_lease." + key)
    if aggregate["log_mib"] != per_lease["log_max_size_mib"] * per_lease["log_max_file"]:
        raise ReportError("aggregate log_mib must equal per_lease log_max_size_mib x log_max_file")
    if aggregate["pids"] < aggregate["sandboxes"] * per_lease["pids_max"]:
        raise ReportError("aggregate pids must cover sandboxes x per_lease pids_max")
    if (
        per_lease["mounts"] != "none"
        or per_lease["image_volumes"] != "refuse"
        or per_lease["network_modes"] != ["none"]
        or per_lease["isolation"] != ["gvisor"]
    ):
        raise ReportError(
            "per_lease policy must be mounts none, image volumes refused, network none, gvisor only"
        )


def main(argv: list[str]) -> int:
    try:
        if len(argv) == 6 and argv[0] == "record":
            record(Path(argv[1]), argv[2], argv[3], argv[4], argv[5])
        elif len(argv) >= 5 and argv[0] == "finalize":
            ledger = Path(argv[1])
            lines = ledger.read_text(encoding="utf-8").splitlines() if ledger.exists() else []
            entries = [json.loads(line) for line in lines if line.strip()]
            profile = json.loads(Path(argv[2]).read_text(encoding="utf-8"))
            environment = dict(item.split("=", 1) for item in argv[5:])
            report = build_report(entries, profile, argv[3], environment)
            validate(report)
            Path(argv[4]).write_text(
                json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            print(f"verdict={report['verdict']} unenforced={','.join(report['unenforced'])}")
            return 0 if report["verdict"] == "pass" else 3
        elif len(argv) == 2 and argv[0] == "validate":
            validate(json.loads(Path(argv[1]).read_text(encoding="utf-8")))
        elif len(argv) == 2 and argv[0] == "check-profile":
            check_profile(json.loads(Path(argv[1]).read_text(encoding="utf-8")))
        else:
            print(__doc__, file=sys.stderr)
            return 2
    except (ReportError, KeyError, TypeError, json.JSONDecodeError) as exc:
        print(f"sandbox-host report error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
