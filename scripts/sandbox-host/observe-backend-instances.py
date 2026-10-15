#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Independently observe every sandbox a backend creates on the disposable host.

Runs as root beside the backend's integration test. For each container that
appears on the dedicated daemon it records, while the sandbox is alive: the
engine settings, the sentry's executable and actual cgroup, the cgroup limit
files, the pkg/sandboxhost ObserveInstance checks (runtime processes in
finite cgroups, sentry netns lo-only with no routes) and the XFS project
quotas. It never changes the host. `summarize` checks the records.

  observe-backend-instances.py watch PROFILE OBSERVER OUT STOPFILE
  observe-backend-instances.py summarize PROFILE OUT
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from typing import Any

STATE_KEYS = ("Status", "Running", "Pid", "ExitCode", "Error", "StartedAt", "FinishedAt")
HOST_KEYS = (
    "Runtime",
    "NetworkMode",
    "CgroupParent",
    "NanoCpus",
    "CpuQuota",
    "CpuPeriod",
    "Memory",
    "MemorySwap",
    "PidsLimit",
    "StorageOpt",
    "CapAdd",
    "CapDrop",
    "SecurityOpt",
    "IpcMode",
    "Init",
    "Privileged",
    "ReadonlyRootfs",
    "LogConfig",
    "Binds",
)


def run(*args: str) -> subprocess.CompletedProcess[str]:
    # Fixed tools (docker, the observer, xfs_quota) with arguments from the profile.
    return subprocess.run(args, capture_output=True, text=True, timeout=15, check=False)  # noqa: S603


def sentry_cgroups(sentry_path: str, lease_prefix: str) -> dict[str, int]:
    """Live sentry processes below the lease slice, keyed by their cgroup."""
    found: dict[str, int] = {}
    for pid in filter(str.isdigit, os.listdir("/proc")):
        try:
            if os.readlink(f"/proc/{pid}/exe") != sentry_path:
                continue
            with open(f"/proc/{pid}/cgroup", encoding="utf-8") as handle:
                cgroup = next(ln.strip()[3:] for ln in handle if ln.startswith("0::"))
        except (OSError, StopIteration):
            continue
        if cgroup.startswith(lease_prefix):
            found.setdefault(cgroup, int(pid))
    return found


def observe(
    profile_path: str, profile: dict[str, Any], observer: str, cgroup: str, pid: int
) -> dict[str, Any]:
    """Read the kernel first (the sandbox may be short-lived), then the engine."""
    record: dict[str, Any] = {"observed_at": time.time(), "pid": pid, "cgroup": cgroup}
    try:
        record["exe"] = os.readlink(f"/proc/{pid}/exe")
        for name in ("cpu.max", "memory.max", "memory.swap.max", "pids.max"):
            with open(profile["cgroup_root"] + cgroup + "/" + name, encoding="utf-8") as limit:
                record[name] = limit.read().strip()
        checks = run(observer, "-profile", profile_path, "instance", "-pid", str(pid))
        record["observer"] = json.loads(checks.stdout or "[]")
        record["xfs_projects"] = run(
            "xfs_quota", "-x", "-c", "report -p -b -N", profile["data_root"]
        ).stdout
    except (OSError, ValueError) as exc:
        record["error"] = f"{type(exc).__name__}: {exc}"
    # A sentry that is gone by the end of the kernel reads makes those reads
    # meaningless: record that, never a mismatch.
    if not os.path.exists(f"/proc/{pid}"):
        record["disappeared"] = True
    scope = cgroup.rsplit("/", 1)[-1]
    cid = scope.removeprefix("docker-").removesuffix(".scope")
    record["id"] = cid
    inspected = run("docker", "-H", profile["docker_host"], "inspect", cid)
    try:
        item = json.loads(inspected.stdout)[0]
        record["state"] = {key: item["State"].get(key) for key in STATE_KEYS}
        record["image"] = item["Config"]["Image"]
        record["labels"] = item["Config"].get("Labels") or {}
        record["mounts"] = item["Mounts"]
        record["host"] = {key: item["HostConfig"].get(key) for key in HOST_KEYS}
    except (ValueError, IndexError, KeyError):
        record["state"] = {"inspect": "container no longer exists"}
        record.setdefault("image", "?")
        record.setdefault("host", {})
        record["engine_gone"] = True
    return record


def watch(profile_path: str, observer: str, out: str, stop: str) -> None:
    with open(profile_path, encoding="utf-8") as handle:
        profile = json.load(handle)
    sentry, lease_prefix = profile["runtime"]["sentry_path"], "/" + profile["lease_slice"] + "/"
    seen: set[str] = set()
    with open(out, "a", encoding="utf-8") as sink:
        while not os.path.exists(stop):
            for cgroup, pid in sentry_cgroups(sentry, lease_prefix).items():
                if cgroup in seen:
                    continue
                seen.add(cgroup)
                sink.write(
                    json.dumps(
                        observe(profile_path, profile, observer, cgroup, pid), sort_keys=True
                    )
                    + "\n"
                )
                sink.flush()
            time.sleep(0.01)


def summarize(profile_path: str, out: str) -> int:
    with open(profile_path, encoding="utf-8") as handle:
        profile = json.load(handle)
    records = []
    if os.path.exists(out):
        with open(out, encoding="utf-8") as handle:
            records = [json.loads(line) for line in handle if line.strip()]
    for record in records:
        if record.get("disappeared") or record.get("engine_gone"):
            print(
                f"DISAPPEARED sandbox {record['id'][:12]} image={record['image'][:60]} "
                f"pid={record['pid']} state={record.get('state')} "
                f"state_after={record.get('state_after')} captured exe={record.get('exe')} "
                f"cgroup={record.get('cgroup')} error={record.get('error')}"
            )
    records = [r for r in records if not r.get("disappeared") and not r.get("engine_gone")]
    if not records:
        print("FAIL: no backend sandbox stayed alive for a complete observation")
        return 1
    failures = 0
    lease_cgroup = "/" + profile["lease_slice"] + "/"
    for record in records:
        host, problems = record["host"], []
        if "error" in record:
            problems.append(record["error"])
        millis = (host.get("NanoCpus") or 0) // 1_000_000
        quota, _, period = record.get("cpu.max", "").partition(" ")
        observed_millis = (
            int(quota) * 1000 // int(period) if quota.isdigit() and period.isdigit() else None
        )
        expect = {
            "runtime runsc": host.get("Runtime") == "runsc",
            "network none": host.get("NetworkMode") == "none",
            "exe is the pinned sentry": record.get("exe") == profile["runtime"]["sentry_path"],
            "cgroup below the lease slice": str(record.get("cgroup", "")).startswith(lease_cgroup),
            "cpu.max equals the lease (no systemd rounding)": millis > 0
            and observed_millis == millis,
            "memory.max equals the lease": record.get("memory.max") == str(host.get("Memory")),
            "memory.swap.max is 0": record.get("memory.swap.max") == "0"
            and host.get("MemorySwap") == host.get("Memory"),
            "pids.max equals the lease": record.get("pids.max") == str(host.get("PidsLimit")),
            "no mounts": not record.get("mounts") and not host.get("Binds"),
            "pkg/sandboxhost ObserveInstance passes": bool(record.get("observer"))
            and all(c["status"] == "pass" for c in record.get("observer", [])),
        }
        size = (host.get("StorageOpt") or {}).get("size", "")
        if size.endswith("m") and size[:-1].isdigit():
            hard_kib = int(size[:-1]) * 1024
            expect[f"XFS project with a {size} hard limit"] = any(
                len(fields) >= 4 and fields[3] == str(hard_kib)
                for fields in (line.split() for line in record.get("xfs_projects", "").splitlines())
            )
        else:
            expect["writable-layer size set"] = False
        problems += [name for name, ok in expect.items() if not ok]
        status = "FAIL" if problems else "PASS"
        failures += bool(problems)
        observed = [c["id"] + ":" + c["status"] for c in record.get("observer", [])]
        fields = [
            f"{status} sandbox {record['id'][:12]} image={record['image'][:60]}",
            f"pid={record['pid']} exe={record.get('exe')} cgroup={record.get('cgroup')}",
            f"cpu.max={record.get('cpu.max')} (lease {millis} millis)",
            f"memory.max={record.get('memory.max')} swap={record.get('memory.swap.max')}",
            f"pids.max={record.get('pids.max')} storage={size} observer={observed}",
        ]
        if problems:
            fields.append(f"problems={problems}")
        print(" ".join(fields))
    return 1 if failures else 0


def main(argv: list[str]) -> int:
    if len(argv) == 5 and argv[0] == "watch":
        watch(*argv[1:])
        return 0
    if len(argv) == 3 and argv[0] == "summarize":
        return summarize(*argv[1:])
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
