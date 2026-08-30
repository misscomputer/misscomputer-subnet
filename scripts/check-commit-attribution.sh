#!/bin/sh
set -eu

script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
repository=$(CDPATH= cd -- "$script_directory/.." && pwd -P)
git -C "$repository" rev-parse --git-dir >/dev/null
metadata=$(git -C "$repository" log --all --format='%H%n%an <%ae>%n%cn <%ce>%n%B')
if printf '%s\n' "$metadata" | grep -Eiq 'claude|anthropic'; then
    echo 'commit attribution check failed: Claude/Anthropic metadata is present' >&2
    exit 1
fi
