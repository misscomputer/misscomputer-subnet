#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Pinned Bittensor 11.1.0 + localhost WebSocket lifecycle reproduction.
set -eu

repository=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repository"
test_case=tests/python/test_sdk_resource_lifecycle.py::test_quorum_close_joins_delayed_real_sdk_initialization
exec .venv/bin/python -m pytest -q \
    "$test_case" \
    "$@"
