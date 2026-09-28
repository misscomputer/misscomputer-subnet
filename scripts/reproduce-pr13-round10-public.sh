#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

exec .venv/bin/python -m pytest \
  -p no:cacheprovider \
  -q \
  -s \
  --tb=short \
  tests/python/test_pr13_open_schema_round10.py \
  tests/python/test_pr13_lifecycle_schema_round9.py \
  tests/python/test_pr13_protocol_close_round8.py \
  "$@"
