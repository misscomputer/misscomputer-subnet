#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

python_binary="${PYTHON_BINARY:-.venv/bin/python}"

exec "$python_binary" -m pytest \
  -p no:cacheprovider \
  -q \
  --tb=short \
  tests/python/test_pr17_round20_public.py \
  tests/python/test_pr13_round14_public.py \
  tests/python/test_weight_plan.py \
  "$@"
