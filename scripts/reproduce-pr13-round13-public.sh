#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

exec .venv/bin/python -m pytest \
  -p no:cacheprovider \
  -q \
  --tb=short \
  tests/python/test_pr13_round13_public.py \
  tests/python/test_pr13_round12_public.py \
  "$@"
