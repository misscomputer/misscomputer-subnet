#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Manual, disposable GitHub-hosted proof. Never run against the default Docker
# daemon or a miner host. This does not implement or enable SandboxBackend.
set -Eeuo pipefail

[[ ${MC_GVISOR_DISPOSABLE_RUNNER:-} == 1 && ${GITHUB_ACTIONS:-} == true && $EUID == 0 ]] || {
  echo 'This gate requires the contained GitHub-hosted workflow as root.' >&2
  exit 1
}

readonly RUNSC_RELEASE=release-20261005.0
readonly RUNSC_SHA256=bd4eb2ca0ee74f0fbbb5f5273ba011e79c56a29fbb047393b88b981cd3230ede
readonly IMAGE=docker.io/library/busybox@sha256:b7f3d86d6e84fc17718c48bcde1450807faa2d56704205c697b4bd5df7b9e29f
readonly QUOTA_BYTES=$((64 * 1024 * 1024))

die() { echo "GATE FAILED: $*" >&2; exit 1; }
report() {
  echo "$*"
  if [[ -n ${GITHUB_STEP_SUMMARY:-} ]]; then echo "$*" >> "$GITHUB_STEP_SUMMARY"; fi
}

for tool in curl tar sha256sum docker dockerd losetup mkfs.xfs mount umount findmnt xfs_quota systemd-run systemctl python3 du timeout awk sed readlink truncate; do
  command -v "$tool" >/dev/null || die "missing $tool"
done
[[ $(findmnt -n -o FSTYPE /sys/fs/cgroup) == cgroup2 ]] || die 'host is not cgroup v2'
[[ $(uname -m) == x86_64 ]] || die 'pinned runsc and image require x86_64'
[[ $(docker --version) == 'Docker version 28.0.4,'* ]] || die 'unreviewed Docker client version'
[[ $(dockerd --version) == 'Docker version 28.0.4,'* ]] || die 'unreviewed Docker daemon version'

gate_dir=$(mktemp -d "${RUNNER_TEMP:-/tmp}/mc-gvisor-gate.XXXXXXXX")
loop_device=
daemon_pid=
container=mc-gvisor-gate-${GITHUB_RUN_ID:-manual}
slice=mc-gvisor-gate-${GITHUB_RUN_ID:-manual}.slice
anchor=mc-gvisor-anchor-${GITHUB_RUN_ID:-manual}.service
mounted=0
daemon_ready=0
cleanup() {
  local result=$?
  local cleanup_failed=0
  trap - EXIT
  set +e
  if (( daemon_ready )); then
    docker rm -f "$container" >/dev/null 2>&1
    docker image rm "$IMAGE" >/dev/null 2>&1
  fi
  if [[ -n $daemon_pid ]]; then
    kill "$daemon_pid" >/dev/null 2>&1
    wait "$daemon_pid" >/dev/null 2>&1
  fi
  systemctl stop "$anchor" >/dev/null 2>&1
  if (( mounted )); then
    if umount "$gate_dir/xfs"; then mounted=0; else cleanup_failed=1; fi
  fi
  if [[ -n $loop_device && $mounted == 0 ]]; then
    if losetup -d "$loop_device"; then loop_device=; else cleanup_failed=1; fi
  fi
  if (( ! mounted )) && [[ -z $loop_device && -d $gate_dir ]]; then rm -rf -- "$gate_dir"; fi
  if (( cleanup_failed )); then
    report "INCOMPLETE CLEANUP: inspect disposable runner path $gate_dir and loop device $loop_device"
    result=1
  fi
  if (( result == 0 )); then report 'PASS: isolated runsc writable-layer quota and cleanup proof; image/cache/log bytes remain outside per-container quota.'
  else report "FAIL: disposable gVisor proof exited $result; no backend or activation claim."; fi
  exit "$result"
}
trap cleanup EXIT

mkdir -p "$gate_dir/bin" "$gate_dir/xfs" "$gate_dir/exec"
curl --fail --silent --show-error --location --max-time 90 \
  "https://github.com/google/gvisor/releases/download/$RUNSC_RELEASE/gvisor-x86_64.tar.bz2" \
  -o "$gate_dir/gvisor.tar.bz2"
printf '%s  %s\n' "$RUNSC_SHA256" "$gate_dir/gvisor.tar.bz2" | sha256sum --check --status || die 'runsc archive checksum mismatch'
tar -xjf "$gate_dir/gvisor.tar.bz2" -C "$gate_dir/bin"
chmod 0755 "$gate_dir/bin/runsc"
report "runsc: $($gate_dir/bin/runsc --version | head -1); archive sha256=$RUNSC_SHA256"

# Both the daemon and its image/cache/log data are confined to a disposable
# finite XFS filesystem; project quota is needed for Docker overlay2 size.
truncate -s 3G "$gate_dir/docker.xfs"
loop_device=$(losetup --find --show "$gate_dir/docker.xfs")
mkfs.xfs -f "$loop_device" >/dev/null
mount -t xfs -o pquota "$loop_device" "$gate_dir/xfs"
mounted=1
findmnt -n -o OPTIONS "$gate_dir/xfs" | grep -Eq '(^|,)(pquota|prjquota)(,|$)' || die 'XFS project quota mount option absent'
project_state=$(xfs_quota -x -c state "$gate_dir/xfs" | sed -n '/Project quota state/,+2p')
grep -q 'Accounting: ON' <<< "$project_state" && grep -q 'Enforcement: ON' <<< "$project_state" || die "XFS project quota is not enforced: $project_state"
mkdir -p "$gate_dir/xfs/docker"

python3 - "$gate_dir/daemon.json" "$gate_dir" <<'PY'
import json, sys
path, root = sys.argv[1:]
with open(path, 'w', encoding='utf-8') as out:
    json.dump({
        'data-root': root + '/xfs/docker', 'exec-root': root + '/exec',
        'hosts': ['unix://' + root + '/docker.sock'],
        'storage-driver': 'overlay2', 'bridge': 'none', 'iptables': False,
        'ip-forward': False, 'ip-masq': False,
        'exec-opts': ['native.cgroupdriver=systemd'],
        'runtimes': {'runsc': {'path': root + '/bin/runsc',
                               'runtimeArgs': ['--systemd-cgroup', '--overlay2=none']}},
    }, out)
PY

export DOCKER_HOST="unix://$gate_dir/docker.sock"
dockerd --config-file "$gate_dir/daemon.json" --pidfile "$gate_dir/dockerd.pid" >"$gate_dir/dockerd.log" 2>&1 &
daemon_pid=$!
for _ in {1..60}; do
  if docker info >/dev/null 2>&1; then daemon_ready=1; break; fi
  if ! kill -0 "$daemon_pid" 2>/dev/null; then break; fi
  sleep 1
done
if (( ! daemon_ready )); then tail -80 "$gate_dir/dockerd.log" >&2; die 'isolated Docker daemon did not start'; fi
[[ $(docker info --format '{{.DockerRootDir}} {{.Driver}} {{.CgroupDriver}}') == "$gate_dir/xfs/docker overlay2 systemd" ]] || die 'wrong Docker root, storage, or cgroup driver'
[[ $(docker version --format '{{.Server.Version}}') == 28.0.4 ]] || die 'unreviewed isolated Docker server version'
report "Docker: $(docker version --format '{{.Server.Version}}'); data root=$gate_dir/xfs/docker; storage=overlay2; cgroup=systemd"

systemd-run --unit "$anchor" --slice "$slice" --remain-after-exit /bin/true >/dev/null
systemctl set-property --runtime "$slice" CPUQuota=200% MemoryMax=1073741824 TasksMax=512
slice_path=$(systemctl show --property=ControlGroup --value "$slice")
[[ -n $slice_path && $slice_path != / ]] || die 'dedicated finite cgroup slice absent'
[[ $(cat "/sys/fs/cgroup$slice_path/memory.max") == 1073741824 ]] || die 'aggregate memory limit absent'
report "aggregate cgroup: $slice_path cpu.max=$(cat "/sys/fs/cgroup$slice_path/cpu.max") memory.max=$(cat "/sys/fs/cgroup$slice_path/memory.max")"

docker pull --platform linux/amd64 "$IMAGE" >/dev/null
image_id=$(docker image inspect --format '{{.Id}}' "$IMAGE")
docker image inspect "$IMAGE" --format '{{json .RepoDigests}}' | grep -F 'sha256:b7f3d86d6e84fc17718c48bcde1450807faa2d56704205c697b4bd5df7b9e29f' >/dev/null || die 'pulled image digest differs from pin'
report "image: $IMAGE; engine id=$image_id; image bytes=$(docker image inspect --format '{{.Size}}' "$IMAGE")"

docker run --detach --name "$container" --runtime runsc --platform linux/amd64 \
  --network none --cgroup-parent "$slice" --cpus 1 --memory 512m --memory-swap 512m \
  --pids-limit 64 --storage-opt size=64m --cap-drop ALL \
  --security-opt no-new-privileges --user 65534:65534 \
  --log-driver json-file --log-opt max-size=1m --log-opt max-file=2 \
  "$IMAGE" sh -c 'yes mc-gvisor-gate | head -c 4000000; touch /tmp/logs-done; sleep 180' >/dev/null
for _ in {1..30}; do
  if docker exec "$container" test -e /tmp/logs-done >/dev/null 2>&1; then break; fi
  sleep 1
done
docker exec "$container" test -e /tmp/logs-done || die 'benign log producer did not finish'
docker inspect "$container" > "$gate_dir/inspect.json"
python3 - "$gate_dir/inspect.json" "$slice" "$image_id" <<'PY'
import json, sys
item = json.load(open(sys.argv[1], encoding='utf-8'))[0]
host = item['HostConfig']
expected = {'Runtime': 'runsc', 'NetworkMode': 'none', 'CgroupParent': sys.argv[2],
            'Memory': 536870912, 'MemorySwap': 536870912, 'PidsLimit': 64,
            'NanoCpus': 1000000000}
for key, value in expected.items():
    if host[key] != value:
        raise SystemExit(f'{key}={host[key]!r}, want {value!r}')
if host['StorageOpt'].get('size') != '64m' or item['Image'] != sys.argv[3]:
    raise SystemExit('writable-layer quota or image identity mismatch')
if not item['State']['Running'] or item['Mounts'] or host['LogConfig']['Type'] != 'json-file':
    raise SystemExit('container not running, has extra mounts, or lacks bounded log driver')
networks = item['NetworkSettings']['Networks'] or {}
if set(networks) - {'none'} or any(n.get('IPAddress') or n.get('GlobalIPv6Address') or n.get('Gateway') for n in networks.values()):
    raise SystemExit('network=none container has an address or routed attachment')
if host['LogConfig']['Config'] != {'max-size': '1m', 'max-file': '2'}:
    raise SystemExit('log rotation configuration mismatch')
PY

pid=$(docker inspect --format '{{.State.Pid}}' "$container")
[[ $pid =~ ^[1-9][0-9]*$ ]] || die 'container has no host PID'
actual_exe=$(readlink -f "/proc/$pid/exe")
[[ $actual_exe == "$gate_dir/bin/runsc" ]] || die "container PID does not execute pinned runsc: $actual_exe"
child_path=$(awk -F: '$1 == "0" {print $3}' "/proc/$pid/cgroup")
[[ $child_path == "$slice_path"/* ]] || die "runsc process escaped dedicated cgroup: $child_path"
[[ $(cat "/sys/fs/cgroup$child_path/memory.max") == 536870912 ]] || die 'actual child memory limit mismatch'
[[ $(cat "/sys/fs/cgroup$child_path/pids.max") == 64 ]] || die 'actual child pids limit mismatch'
read -r cpu_quota cpu_period < "/sys/fs/cgroup$child_path/cpu.max"
[[ $cpu_quota =~ ^[1-9][0-9]*$ && $cpu_period =~ ^[1-9][0-9]*$ ]] || die 'actual child CPU quota is not finite'
(( cpu_quota * 1000 / cpu_period <= 1000 )) || die 'actual child CPU quota exceeds one CPU'
report "actual runsc PID=$pid cgroup=$child_path cpu.max=$(cat "/sys/fs/cgroup$child_path/cpu.max") memory.max=$(cat "/sys/fs/cgroup$child_path/memory.max") pids.max=$(cat "/sys/fs/cgroup$child_path/pids.max")"

for address in 169.254.169.254 1.1.1.1; do
  if timeout 8 docker exec "$container" wget -T 3 -q -O /dev/null "http://$address/" >/dev/null 2>&1; then
    die "network=none container reached $address"
  fi
done
docker exec "$container" true || die 'network negative control could not execute in a live container'
[[ $(docker inspect --format '{{.State.Running}}' "$container") == true ]] || die 'container stopped during network proof'
report 'network=none: metadata and public TCP attempts blocked'

# Docker overlay2 on XFS+pquota must return ENOSPC/EDQUOT before 192 MiB is
# written to the 64 MiB writable layer. A mere StorageOpt field is not proof.
docker exec "$container" sh -c '[ "$(stat -c %d /)" = "$(stat -c %d /tmp)" ]' || die '/tmp is not on the rootfs writable layer'
if docker exec "$container" dd if=/dev/zero of=/tmp/quota-proof bs=1048576 count=192 >"$gate_dir/dd.log" 2>&1; then
  die 'container wrote past its 64 MiB writable-layer quota'
fi
grep -Eiq 'No space left on device|Disk quota exceeded' "$gate_dir/dd.log" || { cat "$gate_dir/dd.log" >&2; die 'disk write failed for a reason other than quota'; }
written=$(docker exec "$container" stat -c '%s' /tmp/quota-proof)
(( written > 0 && written <= QUOTA_BYTES )) || die "writable-layer file size $written exceeds quota"
report "writable-layer quota: 64 MiB, dd stopped at $written bytes with ENOSPC/EDQUOT"

log_path=$(docker inspect --format '{{.LogPath}}' "$container")
[[ $log_path == "$gate_dir/xfs/docker/"* ]] || die 'container log escaped finite data root'
log_bytes=$(find "$(dirname "$log_path")" -maxdepth 1 -name "$(basename "$log_path")*" -type f -printf '%s\n' | awk '{s+=$1} END{print s+0}')
(( log_bytes > 0 && log_bytes <= 3 * 1024 * 1024 )) || die "bounded Docker logs absent or exceeded 3 MiB: $log_bytes"
report "disk classes: rootfs writable layer <=$QUOTA_BYTES bytes (proven); logs=$log_bytes bytes (rotated, outside per-container quota); image/cache=$(docker image inspect --format '{{.Size}}' "$IMAGE") logical bytes (outside per-container quota); all reside on finite 3 GiB XFS daemon data root. This does NOT prove an aggregate SandboxBudget.DiskMiB."

docker rm --force "$container" >/dev/null
if docker inspect "$container" >/dev/null 2>&1; then die 'container remains after destroy'; fi
for _ in {1..30}; do
  if [[ ! -e /proc/$pid && ! -e /sys/fs/cgroup$child_path ]]; then break; fi
  sleep 1
done
[[ ! -e /proc/$pid && ! -e /sys/fs/cgroup$child_path ]] || die 'runsc process or child cgroup remains after destroy'
docker image rm "$IMAGE" >/dev/null
if docker image inspect "$IMAGE" >/dev/null 2>&1; then die 'pinned image remains after cleanup'; fi
report "cleanup: container and pinned image absent; finite data-root used bytes=$(du -sb "$gate_dir/xfs/docker" | awk '{print $1}')"
