#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Offline/localhost executed review regressions; use this checkout's own dev venv.
set -eu
repository=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repository"
exec .venv/bin/python -m pytest -q \
    tests/python/test_executor_lifecycle_repair.py \
    tests/python/test_pr10_terminal_repair.py \
    tests/python/test_sdk_resource_lifecycle.py "$@"
