# SPDX-License-Identifier: AGPL-3.0-only

from __future__ import annotations

import json

import pytest

from misscomputer_subnet.process_boundary import PROTOCOL, BoundaryError, canonical_bytes, execute


def test_boundary_rejects_unallowlisted_operation() -> None:
    with pytest.raises(BoundaryError, match="unsupported"):
        execute({"protocol": PROTOCOL, "operation": "python-eval", "arguments": []})


def test_boundary_response_is_canonical() -> None:
    value = {"z": 1, "a": [True]}
    payload = canonical_bytes(value)
    assert payload == b'{"a":[true],"z":1}\n'
    assert json.loads(payload) == value


def test_release_verifier_runs_through_the_isolated_canonical_boundary() -> None:
    response = execute(
        {"arguments": ["--help"], "operation": "release-verify", "protocol": PROTOCOL}
    )
    assert response["operation"] == "release-verify"
    assert response["protocol"] == PROTOCOL
    assert response["returncode"] == 0
    assert response["stdout_sha256"] != "0" * 64
