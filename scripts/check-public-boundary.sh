#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Fail closed: any scanner error (missing tool, unreadable tree) is a failure,
# never a clean result. Only an explicit "no match" (grep exit 1) passes.
set -eu

command -v grep >/dev/null 2>&1 || { echo "grep is required for the public boundary guard" >&2; exit 2; }

scan() {
  set +e
  grep -r -n -I -E --exclude-dir=.git --exclude-dir=.venv --exclude-dir=__pycache__ \
    --exclude-dir=node_modules --exclude=check-public-boundary.sh "$@" .
  status=$?
  set -e
  case "$status" in
    0) return 0 ;;
    1) return 1 ;;
    *) echo "public boundary scanner failed with exit status $status" >&2; exit 2 ;;
  esac
}

provider_pattern='cloud''flare|r''2\.cloudflarestorage|artifact-backend.*r''2|ARTIFACT_BACKEND.*"r''2"|s3/r''2|r''2/s3'
if scan -i "$provider_pattern"; then
  echo "provider-specific behavior escaped into the public repository" >&2
  exit 1
fi
if scan --include='*.py' --include='*.go' 'misscomputer_infra|github\.com/misscomputer/misscomputer-infra'; then
  echo "private implementation dependency escaped into the public repository" >&2
  exit 1
fi
echo "public boundary guard passed"
