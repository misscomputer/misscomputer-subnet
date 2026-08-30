# SPDX-License-Identifier: AGPL-3.0-only
"""One-shot canonical-file boundary for public Python operations.

Private operator code invokes this executable as a separate process and
exchanges only versioned JSON documents. It is deliberately not an importable
plugin API and accepts only a fixed operation allowlist.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Final

MAX_DOCUMENT_BYTES: Final = 4 << 20
PROTOCOL: Final = "misscomputer.python-boundary.v1"
OPERATIONS: Final = {
    "checkpoint-relay": "misscomputer_subnet.score_checkpoint_relay_cli",
    "release-verify": "misscomputer_subnet.production_release_verifier",
    "schema-inventory": "misscomputer_subnet.schema_inventory",
    "weight-execute": "misscomputer_subnet.weight_executor",
    "weight-reconcile": "misscomputer_subnet.weight_reconciliation",
}


class BoundaryError(ValueError):
    """Safe input or execution failure."""


def canonical_bytes(value: object) -> bytes:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return encoded.encode() + b"\n"


def _read_canonical(path: Path) -> dict[str, object]:
    payload = path.read_bytes()
    if len(payload) > MAX_DOCUMENT_BYTES:
        raise BoundaryError("request exceeds size limit")
    value = json.loads(payload)
    if not isinstance(value, dict) or canonical_bytes(value) != payload:
        raise BoundaryError("request must be canonical JSON object with one trailing newline")
    return value


def execute(request: dict[str, object]) -> dict[str, object]:
    if set(request) != {"arguments", "operation", "protocol"} or request["protocol"] != PROTOCOL:
        raise BoundaryError("invalid boundary request")
    operation = request["operation"]
    arguments = request["arguments"]
    if not isinstance(operation, str) or operation not in OPERATIONS:
        raise BoundaryError("unsupported boundary operation")
    if not isinstance(arguments, list) or not all(
        isinstance(value, str) and "\x00" not in value for value in arguments
    ):
        raise BoundaryError("arguments must be strings")
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    environment.pop("PYTHONHOME", None)
    result = subprocess.run(  # noqa: S603 - executable module is selected from fixed allowlist
        [sys.executable, "-I", "-m", OPERATIONS[operation], *arguments],
        check=False,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        env=environment,
        timeout=300,
    )
    stdout_digest = hashlib.sha256(result.stdout).hexdigest()
    stderr_digest = hashlib.sha256(result.stderr).hexdigest()
    return {
        "operation": operation,
        "protocol": PROTOCOL,
        "returncode": result.returncode,
        "stderr_sha256": stderr_digest,
        "stdout_sha256": stdout_digest,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--response", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        response = execute(_read_canonical(arguments.request))
    except (BoundaryError, OSError, json.JSONDecodeError, subprocess.TimeoutExpired) as error:
        response = {"error": type(error).__name__, "protocol": PROTOCOL, "status": "rejected"}
    target = arguments.response
    if not target.is_absolute() or target.parent.resolve() != target.parent:
        raise SystemExit("response path must have a resolved absolute parent")
    temporary = target.with_name(f".{target.name}.{os.getpid()}.tmp")
    descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(canonical_bytes(response))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
    finally:
        temporary.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
