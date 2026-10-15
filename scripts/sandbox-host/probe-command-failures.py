#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Record how the engine and runsc report sandboxes whose workload cannot run or ends.

Lab observation for the backend's start-failure and exited-workload
attribution (contract D11/D19, lane 6 ACT-PID-1). For each case it creates a
container with the backend's create flags on the dedicated daemon, at the
lease minimum (1 CPU, 1024 MiB, 64 pids), and records, without interpreting
any text:
- the engine's create/start response;
- State (Status, Running, Pid, ExitCode, Error, StartedAt, FinishedAt,
  OOMKilled);
- every gVisor process seen while it ran, with its cgroup;
- the sandbox cgroup's last pids.events and memory.events.local;
- whether any process remains below the lease slice after the exit (the
  merged backend's sliceQuiet condition);
- the conditions of the merged backend's workloadExited predicate
  (pkg/sandboxbackend/gvisor.go at 1f396ff), evaluated by this script on the
  recorded state. This is not the backend's own classification.
Cases: missing command, non-executable command, wrong-architecture ELF, a
command that runs and exits, a fork storm at start and a memory exhaustion at
start; the last two run three times each. Runs as root on the disposable host
only.

  probe-command-failures.py PROFILE IMAGE OUT [CASE,CASE...]
"""

from __future__ import annotations

import io
import json
import os
import struct
import subprocess
import sys
import tarfile
import threading
import time
from datetime import datetime
from typing import Any

STATE_KEYS = (
    "Status",
    "Running",
    "Pid",
    "ExitCode",
    "Error",
    "StartedAt",
    "FinishedAt",
    "OOMKilled",
)
STORM = "i=0; while [ $i -lt 300 ]; do sleep 300 & i=$((i+1)); done; wait"
MEMORY_HOG = "dd if=/dev/zero of=/tmp/fill bs=1048576 count=2048; sleep 300"


def run(*args: str, stdin: bytes | None = None) -> subprocess.CompletedProcess[bytes]:
    # Fixed tools (docker) with arguments from the profile and this script.
    return subprocess.run(args, input=stdin, capture_output=True, timeout=120, check=False)  # noqa: S603


def aarch64_elf() -> bytes:
    """A minimal ELF64 header for EM_AARCH64 (183); not runnable on x86_64."""
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    header = struct.pack("<HHIQQQIHHHHHH", 2, 183, 1, 0x400078, 64, 0, 0, 64, 56, 1, 0, 0, 0)
    program = struct.pack("<IIQQQQQQ", 1, 5, 0, 0x400000, 0x400000, 0x80, 0x80, 0x1000)
    return (ident + header + program).ljust(0x80, b"\0")


def layer(name: str, data: bytes, mode: int) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        info = tarfile.TarInfo(name)
        info.size, info.mode = len(data), mode
        tar.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def rfc3339(text: Any) -> datetime | None:
    """Parse Docker's RFC 3339 nanosecond timestamps (Go time.RFC3339Nano)."""
    if not isinstance(text, str) or not text:
        return None
    value = text.replace("Z", "+00:00")
    if "." in value:
        head, rest = value.split(".", 1)
        digits = rest[: len(rest) - len(rest.lstrip("0123456789"))]
        zone = rest[len(digits) :]
        value = f"{head}.{digits[:6].ljust(6, '0')}{zone}"
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def merged_workload_exited(state: dict[str, Any]) -> dict[str, bool]:
    """The conditions of workloadExited at 1f396ff, evaluated on recorded state."""
    started, finished = rfc3339(state.get("StartedAt")), rfc3339(state.get("FinishedAt"))
    conditions = {
        "not_running": state.get("Running") is False,
        "pid_zero": state.get("Pid") == 0,
        "status_exited": state.get("Status") == "exited",
        "error_empty": state.get("Error") == "",
        "started_valid": started is not None and started.year > 1,
        "finished_after_started": started is not None
        and finished is not None
        and finished > started,
    }
    conditions["all"] = all(conditions.values())
    return conditions


class Sampler(threading.Thread):
    """Records gVisor processes with their cgroups and the sandbox cgroup events."""

    def __init__(self, bindir: str, cgroup_root: str, lease_prefix: str) -> None:
        super().__init__(daemon=True)
        self.bindir, self.cgroup_root, self.lease_prefix = bindir, cgroup_root, lease_prefix
        self.stop = threading.Event()
        self.seen: dict[tuple[str, str], dict[str, Any]] = {}
        self.events: dict[str, dict[str, str]] = {}

    def run(self) -> None:
        while not self.stop.is_set():
            for pid in filter(str.isdigit, os.listdir("/proc")):
                try:
                    exe = os.readlink(f"/proc/{pid}/exe")
                    if not exe.startswith(self.bindir):
                        continue
                    with open(f"/proc/{pid}/cgroup", encoding="utf-8") as handle:
                        cgroup = next(
                            (ln.strip()[3:] for ln in handle if ln.startswith("0::")), "?"
                        )
                except (OSError, StopIteration):
                    continue
                key = (pid, exe)
                entry = self.seen.setdefault(
                    key,
                    {
                        "pid": int(pid),
                        "exe": os.path.basename(exe),
                        "first": time.time(),
                        "cgroups": [],
                    },
                )
                entry["last"] = time.time()
                if cgroup not in entry["cgroups"]:
                    entry["cgroups"].append(cgroup)
                if cgroup.startswith(self.lease_prefix):
                    sample = {}
                    for name in (
                        "pids.events",
                        "pids.current",
                        "memory.events.local",
                        "memory.peak",
                    ):
                        try:
                            with open(
                                self.cgroup_root + cgroup + "/" + name, encoding="utf-8"
                            ) as handle:
                                sample[name] = " ".join(handle.read().split())
                        except OSError:
                            continue
                    if sample:
                        previous = self.events.setdefault(cgroup, {})
                        previous.update(sample)
                        current = sample.get("pids.current", "0")
                        if current.isdigit() and int(current) > int(
                            previous.get("pids.current.peak", "0")
                        ):
                            previous["pids.current.peak"] = current
            time.sleep(0.02)


def leftovers(bindir: str, lease_dir: str, cid: str) -> dict[str, Any]:
    procs = []
    for pid in filter(str.isdigit, os.listdir("/proc")):
        try:
            if os.readlink(f"/proc/{pid}/exe").startswith(bindir):
                with open(f"/proc/{pid}/cmdline", "rb") as handle:
                    if cid.encode() in handle.read():
                        procs.append(int(pid))
        except OSError:
            continue
    cgroups = sorted(name for name in os.listdir(lease_dir) if cid[:12] in name) if cid else []
    return {"runtime_processes_naming_container": procs, "lease_cgroups_naming_container": cgroups}


def slice_quiet(lease_dir: str) -> dict[str, Any]:
    """Non-empty cgroup.procs anywhere below the lease slice (no other sandbox runs here)."""
    busy = []
    for directory, _subdirs, files in os.walk(lease_dir):
        if "cgroup.procs" in files:
            try:
                with open(os.path.join(directory, "cgroup.procs"), encoding="utf-8") as handle:
                    if handle.read().strip():
                        busy.append(directory[len(lease_dir) :] or "/")
            except OSError:
                continue
    # The provisioner's anchor service is the slice's only resident outside sandboxes.
    busy = [cg for cg in busy if not cg.startswith("/mcsbxleaseanchor.service")]
    return {"quiet": not busy, "busy_cgroups": busy}


def stability(attempts: list[dict[str, Any]]) -> dict[str, Any]:
    """Which recorded fields were identical across attempts (no interpretation)."""

    def zero_time(value: Any) -> bool:
        return isinstance(value, str) and value.startswith("0001-01-01")

    columns = {
        "Status": [a["state"].get("Status") for a in attempts],
        "Pid": [a["state"].get("Pid") for a in attempts],
        "StartedAt_zero": [zero_time(a["state"].get("StartedAt")) for a in attempts],
        "FinishedAt_zero": [zero_time(a["state"].get("FinishedAt")) for a in attempts],
        "ExitCode": [a["state"].get("ExitCode") for a in attempts],
        "Error": [a["state"].get("Error") for a in attempts],
        "run_rc": [a["run_rc"] for a in attempts],
        "no_process_before_removal": [
            not a["before_removal"]["runtime_processes_naming_container"] for a in attempts
        ],
        "no_cgroup_before_removal": [
            not a["before_removal"]["lease_cgroups_naming_container"] for a in attempts
        ],
    }
    return {
        name: {"values": values, "stable": len({json.dumps(v) for v in values}) <= 1}
        for name, values in columns.items()
    }


def main(argv: list[str]) -> int:
    if len(argv) not in (3, 4):
        print(__doc__, file=sys.stderr)
        return 2
    with open(argv[0], encoding="utf-8") as handle:
        profile = json.load(handle)
    image, out = argv[1], argv[2]
    docker = ("docker", "-H", profile["docker_host"])
    bindir = os.path.dirname(profile["runtime"]["path"]) + "/"
    lease_dir = profile["cgroup_root"] + "/" + profile["lease_slice"]
    lease_prefix = "/" + profile["lease_slice"] + "/"
    # case: (extra file, ENTRYPOINT json, repeats, seconds to wait for an exit)
    cases: dict[str, tuple[tuple[str, bytes, int] | None, str, int, int]] = {
        "missing_command": (None, '["/no/such/command"]', 3, 3),
        "non_executable_command": (
            ("probe-noexec", b"#!/bin/sh\necho never\n", 0o644),
            '["/probe-noexec"]',
            3,
            3,
        ),
        "wrong_architecture_elf": (("probe-arm64", aarch64_elf(), 0o755), '["/probe-arm64"]', 3, 3),
        "missing_interpreter": (
            ("probe-interp", b"#!/no/such/interpreter\necho never\n", 0o755),
            '["/probe-interp"]',
            3,
            3,
        ),
        "unresolvable_config_user": (None, '["/bin/true"]', 3, 3),
        "unresolvable_config_group": (None, '["/bin/true"]', 3, 3),
        "control_runs_and_exits": (None, '["/bin/true"]', 1, 5),
        "fork_storm_at_start": (None, json.dumps(["sh", "-c", STORM]), 3, 40),
        "memory_exhaustion_at_start": (None, json.dumps(["sh", "-c", MEMORY_HOG]), 3, 40),
    }
    # Config.User set on the committed image; the backend runs the image's own user.
    users = {
        "unresolvable_config_user": "nosuchuser",
        "unresolvable_config_group": "65534:nosuchgroup",
    }
    if len(argv) == 4:
        wanted = set(argv[3].split(","))
        unknown = wanted - set(cases)
        if unknown:
            print(f"unknown cases {sorted(unknown)}", file=sys.stderr)
            return 2
        cases = {name: spec for name, spec in cases.items() if name in wanted}
    results: dict[str, Any] = {
        "image": image,
        "flags": "backend create flags at the lease minimum: runsc, network none, lease slice, "
        "1 CPU, 1024 MiB with equal swap limit, 64 pids, 5120 MiB writable layer, CapDrop ALL, "
        "no-new-privileges, ipc private, restart no, json-file 2 x 1m",
        "predicate_source": "pkg/sandboxbackend/gvisor.go workloadExited and sliceQuiet at "
        "1f396ff, evaluated by this script on recorded state (not the backend's own "
        "classification)",
        "cases": {},
    }
    for case, (extra, entrypoint, repeats, wait_seconds) in cases.items():
        slug = case.replace("_", "-")
        base = f"mcsbx-probe-{slug}"
        tag = f"mcsbx/probe:{slug}"
        run(*docker, "rm", "-f", base + "-base")
        run(*docker, "create", "--name", base + "-base", image, "true")
        if extra:
            name, data, mode = extra
            run(*docker, "cp", "-", base + "-base:/", stdin=layer(name, data, mode))
        changes = ["--change", f"ENTRYPOINT {entrypoint}", "--change", "CMD []"]
        if case in users:
            changes += ["--change", f"USER {users[case]}"]
        commit = run(*docker, "commit", *changes, base + "-base", tag)
        run(*docker, "rm", base + "-base")
        attempts = []
        for attempt in range(repeats):
            container = f"{base}-{attempt}"
            run(*docker, "rm", "-f", container)
            sampler = Sampler(bindir, profile["cgroup_root"], lease_prefix)
            sampler.start()
            started = time.time()
            created = run(
                *docker,
                "run",
                "--detach",
                "--name",
                container,
                "--runtime",
                "runsc",
                "--network",
                "none",
                "--cgroup-parent",
                profile["lease_slice"],
                "--cpus",
                "1",
                "--memory",
                "1024m",
                "--memory-swap",
                "1024m",
                "--pids-limit",
                "64",
                "--storage-opt",
                "size=5120m",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                "--ipc",
                "private",
                "--restart",
                "no",
                "--log-driver",
                "json-file",
                "--log-opt",
                "max-size=1m",
                "--log-opt",
                "max-file=2",
                tag,
            )
            state: dict[str, Any] = {}
            cid = ""
            deadline = time.time() + wait_seconds
            while True:
                inspected = run(*docker, "inspect", container)
                try:
                    item = json.loads(inspected.stdout)[0]
                    state = {k: item["State"].get(k) for k in STATE_KEYS}
                    cid = item["Id"]
                except (ValueError, IndexError, KeyError):
                    state = {"inspect_error": inspected.stderr.decode(errors="replace")[:300]}
                    break
                if not state.get("Running") or time.time() > deadline:
                    break
                time.sleep(0.5)
            time.sleep(1)
            quiet = slice_quiet(lease_dir)
            before_removal = leftovers(bindir, lease_dir, cid)
            removed = run(*docker, "rm", "-f", container)
            time.sleep(1)
            sampler.stop.set()
            sampler.join(timeout=5)
            attempts.append(
                {
                    "run_rc": created.returncode,
                    "run_stderr": created.stderr.decode(errors="replace").strip()[:600],
                    "state": state,
                    "still_running_at_deadline": bool(state.get("Running")),
                    "merged_workload_exited_conditions": merged_workload_exited(state),
                    "slice_quiet_after_exit": quiet,
                    "sandbox_cgroup_events": sampler.events,
                    "runtime_processes_seen": [
                        {
                            "exe": e["exe"],
                            "cgroups": e["cgroups"],
                            "first": round(e["first"] - started, 3),
                            "last": round(e["last"] - started, 3),
                        }
                        for e in sampler.seen.values()
                    ],
                    "before_removal": before_removal,
                    "remove_rc": removed.returncode,
                    "after_removal": leftovers(bindir, lease_dir, cid),
                }
            )
        results["cases"][case] = {
            "entrypoint": entrypoint,
            "config_user": users.get(case),
            "image_commit_rc": commit.returncode,
            "attempts": attempts,
            "stability": stability(attempts),
        }
        run(*docker, "image", "rm", tag)
    with open(out, "w", encoding="utf-8") as handle:
        json.dump(results, handle, indent=2, sort_keys=True)
    for case, result in results["cases"].items():
        for index, attempt in enumerate(result["attempts"]):
            state = attempt["state"]
            events = {
                k: v for cg in attempt["sandbox_cgroup_events"].values() for k, v in cg.items()
            }
            line = [
                f"{case}[{index}]: run_rc={attempt['run_rc']}",
                f"Status={state.get('Status')} ExitCode={state.get('ExitCode')}",
                f"OOMKilled={state.get('OOMKilled')} Pid={state.get('Pid')}",
                f"StartedAt={state.get('StartedAt')} FinishedAt={state.get('FinishedAt')}",
                f"Error={state.get('Error')!r}",
                f"workloadExited(lane2 eval)={attempt['merged_workload_exited_conditions']['all']}",
                f"sliceQuiet={attempt['slice_quiet_after_exit']['quiet']}",
                f"pids.events={events.get('pids.events')}",
                f"pids.peak={events.get('pids.current.peak')}",
                f"memory.events.local={events.get('memory.events.local')}",
            ]
            print(" ".join(line))
        if "stability" in result:
            stable = {name: column["stable"] for name, column in result["stability"].items()}
            print(f"{case} stability across {len(result['attempts'])} attempts: {stable}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
