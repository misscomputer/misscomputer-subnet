#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

go_binary="${GO_BINARY:-go}"
python_binary="${PYTHON_BINARY:-.venv/bin/python}"

"$go_binary" test -race ./pkg/control \
  -run '^TestSchedulerCancellationAcrossForwardingBoundaryCannotStrandMinerRuntime$' \
  -count=100

exec "$python_binary" -m pytest \
  -p no:cacheprovider \
  -q \
  --tb=short \
  tests/python/test_pr13_round15_public.py \
  "$@"
