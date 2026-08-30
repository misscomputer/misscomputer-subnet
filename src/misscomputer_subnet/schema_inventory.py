# SPDX-License-Identifier: AGPL-3.0-only
"""Validate a public contract tree and emit its canonical content manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path


def canonical_bytes(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        + b"\n"
    )


def expected_bytes(path: Path, value: object) -> bytes:
    if path.parent.name == "schemas":
        rendered = json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
        return rendered.encode("ascii")
    if path.name == "pr15-campaign-evidence-golden.v1.json":
        rendered = json.dumps(value, separators=(",", ":"), ensure_ascii=True) + "\n"
        return rendered.encode("ascii")
    return canonical_bytes(value)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--contracts-root", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    arguments = parser.parse_args()
    root = arguments.contracts_root
    manifest = arguments.manifest
    if not root.is_absolute() or root.resolve() != root or not root.is_dir():
        raise SystemExit("contracts root must be an existing resolved absolute directory")
    if not manifest.is_absolute() or manifest.parent.resolve() != manifest.parent:
        raise SystemExit("manifest must have a resolved absolute parent")
    entries: list[dict[str, object]] = []
    for group in ("fixtures", "schemas"):
        directory = root / group
        if not directory.is_dir() or directory.is_symlink():
            raise SystemExit(f"missing canonical public {group} directory")
        for path in sorted(directory.glob("*.json")):
            if path.is_symlink() or not path.is_file():
                raise SystemExit(f"unsafe public contract path: {path}")
            payload = path.read_bytes()
            value = json.loads(payload)
            if expected_bytes(path, value) != payload:
                raise SystemExit(f"non-canonical public contract: {path.name}")
            entries.append(
                {
                    "bytes": len(payload),
                    "path": f"{group}/{path.name}",
                    "sha256": hashlib.sha256(payload).hexdigest(),
                }
            )
    document = {
        "entries": entries,
        "protocol": "misscomputer.python-boundary.v1",
        "schema": "miss.computer/misscomputer-subnet/contract-inventory",
        "schema_version": 1,
    }
    temporary = manifest.with_name(f".{manifest.name}.{os.getpid()}.tmp")
    descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(canonical_bytes(document))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, manifest)
    finally:
        temporary.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
