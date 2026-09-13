#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Public v2 signer compatibility + pinned Bittensor close-gate reproduction.
set -eu

repository=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repository"
exec .venv/bin/python -m pytest -q \
    tests/python/test_pr13_protocol_close_round8.py \
    "$@"
