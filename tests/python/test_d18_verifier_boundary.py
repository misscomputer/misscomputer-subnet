# SPDX-License-Identifier: AGPL-3.0-only
"""The D18 command refuses malformed transport bytes without publishing metrics."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from misscomputer_subnet.d18_verifier_boundary import PROTOCOL


@pytest.mark.parametrize(
    "payload",
    [
        b'{"protocol":"misscomputer.d18-verifier-boundary.v1","protocol":"misscomputer.d18-verifier-boundary.v1"}\n',
        (4 << 20) + 1,
    ],
    ids=("duplicate-keys", "oversized"),
)
def test_d18_boundary_refuses_noncanonical_or_oversized_request(
    tmp_path: Path, payload: bytes | int
) -> None:
    request = tmp_path / "request.json"
    response = tmp_path / "response.json"
    request.write_bytes(b"x" * payload if isinstance(payload, int) else payload)
    completed = subprocess.run(  # noqa: S603 -- fixed module and interpreter
        [
            sys.executable,
            "-I",
            "-m",
            "misscomputer_subnet.d18_verifier_boundary",
            "--request",
            str(request),
            "--response",
            str(response),
        ],
        check=False,
        capture_output=True,
        timeout=10,
    )
    assert completed.returncode == 0
    result = json.loads(response.read_bytes())
    assert set(result) == {"code", "protocol", "status"}
    assert result["protocol"] == PROTOCOL
    assert result["status"] == "rejected"
    assert result["code"] in {"request_invalid", "request_too_large"}
