#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
set -eu

cd "$(dirname "$0")/.."
exec .venv/bin/python -m pytest -q \
  tests/python/test_sdk_resource_lifecycle.py::test_close_rejects_read_reconnect_after_ownership_snapshot \
  "$@"
