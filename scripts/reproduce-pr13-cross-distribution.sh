#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Build/install the public wheel away from the checkout, then exchange canonical
# v2 bytes with an independent stdlib Unix producer.
set -eu

repository=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
temporary=$(mktemp -d /tmp/mc-pr13-round8-distribution.XXXXXX)
case "$temporary" in
    /tmp/mc-pr13-round8-distribution.*) ;;
    *) exit 1 ;;
esac
cleanup() {
    rm -rf -- "$temporary"
}
trap cleanup EXIT HUP INT TERM

"$repository/.venv/bin/python" -m pip wheel \
    --disable-pip-version-check \
    --no-deps \
    --wheel-dir "$temporary/dist" \
    "$repository"
python3.12 -m venv "$temporary/venv"
wheel=$(find "$temporary/dist" -maxdepth 1 -type f -name 'misscomputer_subnet-*.whl')
test -n "$wheel"
"$temporary/venv/bin/python" -m pip install \
    --disable-pip-version-check \
    "$wheel[dev]"
cd "$temporary"
MISSCOMPUTER_REQUIRE_INSTALLED_WHEEL=1 \
    "$temporary/venv/bin/python" -m pytest -q \
    "$repository/tests/python/test_pr13_protocol_close_round8.py" \
    -k independent_v2_producer_reference_reaches_audit_and_cli \
    "$@"
