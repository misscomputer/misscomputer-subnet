#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Record what the engine and runsc report when a sandbox command cannot run.

Lab observation for the backend's start-failure and exited-workload
attribution (contract D11/D19). For each case (missing command, non-executable
command, wrong-architecture ELF, and a command that runs and exits as a
control) it creates a container with the backend's create flags on the
dedicated daemon and records, without interpreting any text: the engine's
create/start response, State (Status, Running, Pid, ExitCode, Error,
StartedAt, FinishedAt, OOMKilled), every gVisor process seen while it was
being created with its cgroup, and the processes and cgroups left before and
after removal. Runs as root on the disposable host only.

  probe-command-failures.py PROFILE IMAGE OUT
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
from typing import Any


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


class Sampler(threading.Thread):
    """Records every process executing from the runtime directory and its cgroup."""

    def __init__(self, bindir: str) -> None:
        super().__init__(daemon=True)
        self.bindir, self.stop = bindir, threading.Event()
        self.seen: dict[tuple[str, str], dict[str, Any]] = {}

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
                    with open(f"/proc/{pid}/cmdline", "rb") as handle:
                        args = handle.read().replace(b"\0", b" ").decode(errors="replace")
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
                        "args": args[:300],
                    },
                )
                entry["last"] = time.time()
                if cgroup not in entry["cgroups"]:
                    entry["cgroups"].append(cgroup)
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


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    with open(argv[0], encoding="utf-8") as handle:
        profile = json.load(handle)
    image, out = argv[1], argv[2]
    host = profile["docker_host"]
    bindir = os.path.dirname(profile["runtime"]["path"]) + "/"
    lease_dir = profile["cgroup_root"] + "/" + profile["lease_slice"]
    docker = ("docker", "-H", host)
    cases = {
        "missing_command": (None, '["/no/such/command"]'),
        "non_executable_command": (
            ("probe-noexec", b"#!/bin/sh\necho never\n", 0o644),
            '["/probe-noexec"]',
        ),
        "wrong_architecture_elf": (("probe-arm64", aarch64_elf(), 0o755), '["/probe-arm64"]'),
        "control_runs_and_exits": (None, '["/bin/true"]'),
    }
    results: dict[str, Any] = {
        "image": image,
        "flags": "backend create flags (runsc, network none, lease slice, 1 CPU, 256 MiB, "
        "64 pids, 64 MiB writable layer, CapDrop ALL, no-new-privileges, ipc private)",
        "cases": {},
    }
    for case, (extra, entrypoint) in cases.items():
        base = f"mcsbx-cmdprobe-{case.replace('_', '-')}"
        run(*docker, "rm", "-f", base + "-base", base)
        run(*docker, "create", "--name", base + "-base", image, "true")
        if extra:
            name, data, mode = extra
            run(*docker, "cp", "-", base + "-base:/", stdin=layer(name, data, mode))
        tag = f"mcsbx/cmdprobe:{case.replace('_', '-')}"
        commit = run(
            *docker,
            "commit",
            "--change",
            f"ENTRYPOINT {entrypoint}",
            "--change",
            "CMD []",
            base + "-base",
            tag,
        )
        run(*docker, "rm", base + "-base")
        sampler = Sampler(bindir)
        sampler.start()
        started = time.time()
        created = run(
            *docker,
            "run",
            "--detach",
            "--name",
            base,
            "--runtime",
            "runsc",
            "--network",
            "none",
            "--cgroup-parent",
            profile["lease_slice"],
            "--cpus",
            "1",
            "--memory",
            "256m",
            "--memory-swap",
            "256m",
            "--pids-limit",
            "64",
            "--storage-opt",
            "size=64m",
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
        time.sleep(2)
        inspected = run(*docker, "inspect", base)
        try:
            item = json.loads(inspected.stdout)[0]
            state = {
                k: item["State"].get(k)
                for k in (
                    "Status",
                    "Running",
                    "Pid",
                    "ExitCode",
                    "Error",
                    "StartedAt",
                    "FinishedAt",
                    "OOMKilled",
                )
            }
            cid = item["Id"]
        except (ValueError, IndexError, KeyError):
            state, cid = {"inspect_error": inspected.stderr.decode(errors="replace")[:300]}, ""
        before_removal = leftovers(bindir, lease_dir, cid)
        removed = run(*docker, "rm", "-f", base)
        time.sleep(1)
        sampler.stop.set()
        sampler.join(timeout=5)
        results["cases"][case] = {
            "entrypoint": entrypoint,
            "image_commit_rc": commit.returncode,
            "run_rc": created.returncode,
            "run_stdout": created.stdout.decode(errors="replace").strip()[:200],
            "run_stderr": created.stderr.decode(errors="replace").strip()[:600],
            "state": state,
            "runtime_processes_seen_during_create": [
                {
                    **entry,
                    "first": round(entry["first"] - started, 3),
                    "last": round(entry["last"] - started, 3),
                }
                for entry in sampler.seen.values()
            ],
            "before_removal": before_removal,
            "remove_rc": removed.returncode,
            "after_removal": leftovers(bindir, lease_dir, cid),
        }
        run(*docker, "image", "rm", tag)
    with open(out, "w", encoding="utf-8") as handle:
        json.dump(results, handle, indent=2, sort_keys=True)
    for case, result in results["cases"].items():
        seen = [(p["exe"], p["cgroups"]) for p in result["runtime_processes_seen_during_create"]]
        state_text = json.dumps(result["state"], sort_keys=True)
        print(
            f"{case}: run_rc={result['run_rc']} state={state_text} processes_seen={seen} "
            f"before_removal={result['before_removal']} after_removal={result['after_removal']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
