#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Pinned Bittensor 11.1.0 + localhost WebSocket close-error barrier reproduction.
set -eu

repository=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repository"
test_case=tests/python/test_sdk_resource_lifecycle.py::test_quorum_close_failure_waits_for_public_open_completion
exec .venv/bin/python -m pytest -q \
    "$test_case" \
    "$@"
