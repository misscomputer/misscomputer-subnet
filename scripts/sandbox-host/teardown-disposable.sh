#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Undo provision-disposable.sh from <root>/state.env and verify that no unit,
# slice, mount, loop device or directory of the dedicated engine remains.
# Exits non-zero on incomplete cleanup.
set -Euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=scripts/sandbox-host/lib.sh
source "$here/lib.sh"
mcsbx_require_disposable

root=$(mcsbx_root)
[[ -f $root/state.env ]] || { echo "nothing to tear down at $root"; exit 0; }
loop_device=
# shellcheck disable=SC1091
source "$root/state.env"
failed=0
export DOCKER_HOST="unix://$root/run/docker/docker.sock"

# Remove sandboxes through the engine first so runsc deletes its own state,
# then stop daemons. KillMode=control-group reaps shims and gofers.
if systemctl is-active --quiet "$MCSBX_DOCKERD_UNIT"; then
  mapfile -t ids < <(timeout 30 docker ps -aq 2>/dev/null)
  if (( ${#ids[@]} )); then timeout 60 docker rm -f -v "${ids[@]}" >/dev/null 2>&1; fi
fi
for unit in "$MCSBX_DOCKERD_UNIT" "$MCSBX_CONTAINERD_UNIT" mcsbxleaseanchor.service; do
  systemctl stop "$unit" >/dev/null 2>&1
  systemctl reset-failed "$unit" >/dev/null 2>&1
done
if nft list table inet "$MCSBX_EGRESS_TABLE" >/dev/null 2>&1; then nft delete table inet "$MCSBX_EGRESS_TABLE" || failed=1; fi
for slice in "$MCSBX_LEASE_SLICE" "$MCSBX_ENGINE_SLICE"; do
  systemctl stop "$slice" >/dev/null 2>&1
done
# Docker may leave its null-netns bind mounts below exec-root. Unmount this
# root's descendants only, deepest first.
while IFS= read -r target; do
  [[ $target == "$root/"* ]] || continue
  umount "$target" || failed=1
done < <(findmnt -rn -o TARGET | sort -r)
if [[ -n $loop_device ]]; then
  if losetup "$loop_device" >/dev/null 2>&1; then losetup -d "$loop_device" || failed=1; fi
fi

for unit in "$MCSBX_DOCKERD_UNIT" "$MCSBX_CONTAINERD_UNIT" mcsbxleaseanchor.service "$MCSBX_LEASE_SLICE" "$MCSBX_ENGINE_SLICE"; do
  if systemctl is-active --quiet "$unit"; then echo "still active: $unit" >&2; failed=1; fi
done
for path in /sys/fs/cgroup/$MCSBX_LEASE_SLICE /sys/fs/cgroup/$MCSBX_ENGINE_SLICE; do
  if [[ -e $path ]]; then echo "cgroup remains: $path" >&2; failed=1; fi
done
if nft list table inet "$MCSBX_EGRESS_TABLE" >/dev/null 2>&1; then echo "nft table $MCSBX_EGRESS_TABLE remains" >&2; failed=1; fi
if findmnt -rn -o TARGET | grep -Fq "$root/"; then echo "mount remains below $root" >&2; failed=1; fi
if [[ -n $loop_device ]] && losetup "$loop_device" >/dev/null 2>&1 &&
   losetup -n -O BACK-FILE "$loop_device" | grep -Fq "$root/"; then
  echo "loop device remains: $loop_device" >&2; failed=1
fi
if (( ! failed )); then rm -rf -- "$root" || failed=1; fi
if (( failed )); then
  mcsbx_report "INCOMPLETE TEARDOWN: inspect disposable runner path $root"
  exit 1
fi
mcsbx_report "teardown: dedicated units, slices, cgroups, egress table, mounts, loop device and $root removed"
