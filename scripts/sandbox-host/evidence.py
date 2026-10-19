#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Bounded cgroup observations and raw evidence retention, never OOM attribution.

A vanished child is an explicit terminal observation, not a replacement for its
missing counters. Ancestor snapshots are diagnostic only; they cannot prove a
sole changing descendant or turn Docker OOMKilled into child-limit evidence.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import stat
import time
from pathlib import Path

MAX_READ = 16384
MAX_SAMPLES = 4096
RAW_NAMES = (
    "conformance-exit.txt",
    "pids-ready.json",
    "pids-status.json",
    "pids-samples.jsonl",
    "pids.events",
    "pids.current",
    "pids.log",
    "pids-control.txt",
    "tmp-ready.json",
    "tmp-status.json",
    "tmp-samples.jsonl",
    "tmp.events",
    "tmp.peak",
    "tmp.log",
    "tmp-control.txt",
    "tmp-ancestors-before.json",
    "tmp-ancestors-after.json",
)


def open_directory(path: Path) -> int:
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("absolute path without parent traversal required")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return fd
    except BaseException:
        os.close(fd)
        raise


def read_at(fd: int, name: str, limit: int = MAX_READ) -> str:
    child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    try:
        info = os.fstat(child)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError(f"not a single-link regular file: {name}")
        with os.fdopen(child, "rb", closefd=False) as stream:
            raw = stream.read(limit + 1)
        if len(raw) > limit:
            raise ValueError(f"read exceeds bound: {name}")
        return raw.decode("utf-8")
    finally:
        os.close(child)


def write_json(path: Path, value: object) -> None:
    temporary = path.with_suffix(path.suffix + ".partial")
    with temporary.open("w", encoding="utf-8") as stream:
        json.dump(value, stream, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)


def identity(path: Path) -> tuple[int, int]:
    info = path.stat(follow_symlinks=False)
    if not stat.S_ISDIR(info.st_mode):
        raise ValueError("cgroup path is no longer a directory")
    return info.st_dev, info.st_ino


def sample(path: Path, work: Path, kind: str) -> int:
    prefix = "pids" if kind == "pids" else "tmp"
    stopped = False

    def stop(_signum: int, _frame: object) -> None:
        nonlocal stopped
        stopped = True

    signal.signal(signal.SIGTERM, stop)
    count = 0
    reason, error = "stopped", ""
    initial: tuple[int, int] | None = None
    try:
        fd = open_directory(path)
        try:
            info = os.fstat(fd)
            initial = (info.st_dev, info.st_ino)
            fields = (
                ("pids.events", "pids.current")
                if kind == "pids"
                else (
                    "memory.events.local",
                    "memory.peak",
                )
            )
            limits = ("pids.max",) if kind == "pids" else ("memory.max", "memory.swap.max")
            configured = {name: read_at(fd, name).strip() for name in limits}
            with (work / f"{prefix}-samples.jsonl").open("w", encoding="utf-8") as history:
                while not stopped:
                    try:
                        if identity(path) != initial:
                            raise ValueError("cgroup identity changed")
                        values = {name: read_at(fd, name) for name in fields}
                        if identity(path) != initial:
                            raise ValueError("cgroup identity changed during sample")
                    except FileNotFoundError:
                        # Missing one counter in a still-present scope is NOT disappearance.
                        try:
                            identity(path)
                        except FileNotFoundError:
                            reason = "cgroup_disappeared"
                            break
                        raise
                    for name, raw in values.items():
                        if name.endswith("events") or name.endswith("events.local"):
                            rows = [line.split() for line in raw.splitlines()]
                            if not rows or any(
                                len(row) != 2 or not row[1].isdigit() for row in rows
                            ):
                                raise ValueError(f"invalid counter: {name}")
                        elif not raw.strip().isdigit():
                            raise ValueError(f"invalid counter: {name}")
                    observation = {"monotonic_ns": time.monotonic_ns(), "values": values}
                    history.write(json.dumps(observation, sort_keys=True) + "\n")
                    history.flush()
                    # Preserve compatibility with the existing strict child checks.
                    if kind == "pids":
                        (work / "pids.events").write_text(values["pids.events"])
                        with (work / "pids.current").open("a", encoding="utf-8") as current:
                            current.write(values["pids.current"].strip() + "\n")
                    else:
                        (work / "tmp.events").write_text(values["memory.events.local"])
                        (work / "tmp.peak").write_text(values["memory.peak"])
                    count += 1
                    if count == 1:
                        write_json(
                            work / f"{prefix}-ready.json",
                            {
                                "cgroup": str(path),
                                "device": initial[0],
                                "inode": initial[1],
                                "limits": configured,
                                "first_sample": observation,
                            },
                        )
                    if count >= MAX_SAMPLES:
                        raise ValueError("sample bound reached")
                    time.sleep(0.05 if kind == "pids" else 0.1)
        finally:
            os.close(fd)
        if count == 0:
            raise ValueError("no complete sample before termination")
    except (OSError, ValueError) as exc:
        reason, error = "read_error", str(exc)
    write_json(
        work / f"{prefix}-status.json",
        {
            "reason": reason,
            "error": error,
            "samples": count,
            "cgroup": str(path),
            "identity": initial,
            "monotonic_ns": time.monotonic_ns(),
        },
    )
    return 1 if error else 0


def ancestors(root: Path, child: Path, output: Path) -> None:
    if child == root or not child.is_relative_to(root):
        raise ValueError("child must be below cgroup root")
    rows = []
    current = child.parent
    errors = []
    while True:
        row: dict[str, object] = {"path": str(current), "monotonic_ns": time.monotonic_ns()}
        try:
            fd = open_directory(current)
            try:
                info = os.fstat(fd)
                row.update(device=info.st_dev, inode=info.st_ino)
                # Root has no memory controller limits/events. Record its identity,
                # and the global OOM count separately below (diagnostic, not attribution).
                if current != root:
                    row["values"] = {
                        name: read_at(fd, name)
                        for name in (
                            "memory.events",
                            "memory.events.local",
                            "memory.current",
                            "memory.max",
                            "memory.swap.max",
                        )
                    }
            finally:
                os.close(fd)
        except (OSError, ValueError) as exc:
            row["error"] = str(exc)
            errors.append(str(exc))
        rows.append(row)
        if current == root:
            break
        current = current.parent
    try:
        global_oom = [
            line
            for line in Path("/proc/vmstat").read_text().splitlines()
            if line.startswith("oom_kill ")
        ]
        if len(global_oom) != 1:
            raise ValueError("global oom_kill counter unavailable")
    except (OSError, ValueError) as exc:
        global_oom = []
        errors.append(str(exc))
    write_json(
        output,
        {
            "ancestors": rows,
            "global_oom": global_oom,
            "errors": errors,
            "use": "diagnostic only; not sole-descendant or OOM attribution proof",
        },
    )
    if errors:
        raise ValueError("ancestor capture incomplete: " + "; ".join(errors))


def export(work: Path, output: Path) -> None:
    files: dict[str, object] = {}
    errors = []
    fd = open_directory(work)
    try:
        for name in RAW_NAMES:
            try:
                files[name] = {"status": "captured", "text": read_at(fd, name, 1024 * 1024)}
            except FileNotFoundError:
                files[name] = {"status": "not_produced"}
            except (OSError, ValueError) as exc:
                files[name] = {"status": "error", "error": str(exc)}
                errors.append(name)
    finally:
        os.close(fd)
    write_json(output, {"schema": "sandbox-host-raw-evidence.v1", "files": files, "errors": errors})
    if errors:
        raise ValueError("raw evidence export failed: " + ", ".join(errors))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    sampler = commands.add_parser("sample")
    sampler.add_argument("kind", choices=("pids", "memory"))
    sampler.add_argument("cgroup", type=Path)
    sampler.add_argument("work", type=Path)
    snapshot = commands.add_parser("ancestors")
    snapshot.add_argument("root", type=Path)
    snapshot.add_argument("child", type=Path)
    snapshot.add_argument("output", type=Path)
    exporter = commands.add_parser("export")
    exporter.add_argument("work", type=Path)
    exporter.add_argument("output", type=Path)
    args = parser.parse_args()
    if args.command == "sample":
        raise SystemExit(sample(args.cgroup, args.work, args.kind))
    if args.command == "ancestors":
        ancestors(args.root, args.child, args.output)
    else:
        export(args.work, args.output)


if __name__ == "__main__":
    main()
