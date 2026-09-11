#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Standalone, offline reproduction; run from this checkout with its own dev venv.
set -eu
repository=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repository"
exec .venv/bin/python -m pytest -q tests/python/test_executor_lifecycle_repair.py "$@"
