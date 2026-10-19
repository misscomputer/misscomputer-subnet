#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
#
# Builds the sandbox-ops-v1 in-sandbox helper reproducibly
# (helper_B_conditions B-8): static, CGO_ENABLED=0, -trimpath,
# -buildvcs=false, an empty build ID, and the toolchain pinned by go.mod.
# Writes the binary to $1 and prints "<sha256>  <path>". Two builds of the
# same commit with the same toolchain must print the same digest.
set -eu
if [ "$#" -ne 1 ]; then
	echo "usage: $0 <output path>" >&2
	exit 2
fi
output=$1
repository=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd -P)
toolchain=$(sed -n 's/^toolchain //p' "$repository/go.mod")
if [ -z "$toolchain" ]; then
	echo "go.mod pins no toolchain" >&2
	exit 1
fi
cd "$repository"
GOTOOLCHAIN=$toolchain CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOFLAGS= \
	go build -trimpath -buildvcs=false -ldflags='-s -w -buildid=' -o "$output" ./cmd/sandbox-ops-helper
if [ "$(GOTOOLCHAIN=$toolchain go env GOVERSION)" != "$toolchain" ]; then
	echo "built with $(GOTOOLCHAIN=$toolchain go env GOVERSION), not $toolchain" >&2
	exit 1
fi
sha256sum "$output"
