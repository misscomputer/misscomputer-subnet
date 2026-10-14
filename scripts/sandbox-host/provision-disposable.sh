#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Provision a dedicated sandbox engine on a DISPOSABLE GitHub-hosted VM:
# finite XFS data filesystem with project quota, size-limited tmpfs run root,
# a dedicated containerd and dockerd in a finite engine slice, the pinned runsc
# runtime and a finite aggregate lease slice. Writes sandbox-host-profile.v1 to
# <root>/profile.json. Never run on a miner, validator, origin or shared host.
# teardown-disposable.sh undoes everything recorded in <root>/state.env.
set -Eeuo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=scripts/sandbox-host/lib.sh
source "$here/lib.sh"
mcsbx_require_disposable

root=$(mcsbx_root)
data_fs_mib=${MC_SANDBOX_HOST_DATA_FS_MIB:-4096}
run_tmpfs_mib=${MC_SANDBOX_HOST_RUN_TMPFS_MIB:-64}
lease_cpu_millis=${MC_SANDBOX_HOST_LEASE_CPU_MILLIS:-2000}
lease_memory_mib=${MC_SANDBOX_HOST_LEASE_MEMORY_MIB:-1024}
lease_tasks=${MC_SANDBOX_HOST_LEASE_TASKS:-1024}
engine_memory_mib=${MC_SANDBOX_HOST_ENGINE_MEMORY_MIB:-1536}
engine_tasks=${MC_SANDBOX_HOST_ENGINE_TASKS:-4096}
image_reserve_mib=${MC_SANDBOX_HOST_IMAGE_RESERVE_MIB:-512}
image_max_mib=${MC_SANDBOX_HOST_IMAGE_MAX_MIB:-256}
lease_pids_max=${MC_SANDBOX_HOST_LEASE_PIDS_MAX:-64}
engine_overhead_mib=${MC_SANDBOX_HOST_ENGINE_OVERHEAD_MIB:-512}
default_writable_mib=${MC_SANDBOX_HOST_DEFAULT_WRITABLE_MIB:-64}
log_max_size_mib=${MC_SANDBOX_HOST_LOG_MAX_SIZE_MIB:-8}
log_max_file=${MC_SANDBOX_HOST_LOG_MAX_FILE:-2}
sandboxes=${MC_SANDBOX_HOST_SANDBOXES:-4}
for value in "$data_fs_mib" "$run_tmpfs_mib" "$lease_cpu_millis" "$lease_memory_mib" "$lease_tasks" \
  "$engine_memory_mib" "$engine_tasks" "$image_reserve_mib" "$image_max_mib" "$lease_pids_max" "$engine_overhead_mib" \
  "$default_writable_mib" "$log_max_size_mib" "$log_max_file" "$sandboxes"; do
  mcsbx_finite "$value" || mcsbx_die "sizing value $value is not a finite positive integer"
done
# Shared-contract D7: each lease's writable-layer quota is its disk_mib;
# per-sandbox image and log bytes, image reserve and engine overhead are
# operator overhead outside the lane disk budget.
log_mib=$((log_max_size_mib * log_max_file))
lane_disk_mib=$((data_fs_mib - sandboxes * (image_max_mib + log_mib) - engine_overhead_mib - image_reserve_mib))
(( lane_disk_mib > 0 )) || mcsbx_die 'data filesystem leaves no lane disk budget after overhead'
(( lease_tasks >= sandboxes * lease_pids_max )) || mcsbx_die 'lease slice tasks do not cover sandboxes x per-lease pids'

mcsbx_require_tools curl tar sha256sum docker dockerd losetup mkfs.xfs mount umount findmnt \
  xfs_quota systemd-run systemctl python3 truncate stat
[[ $(findmnt -n -o FSTYPE /sys/fs/cgroup) == cgroup2 ]] || mcsbx_die 'host is not cgroup v2'
[[ $(uname -m) == x86_64 ]] || mcsbx_die 'pinned runsc and image require x86_64'
[[ $(dockerd --version) == "Docker version $MCSBX_DOCKER_VERSION,"* ]] || mcsbx_die 'unreviewed dockerd version'
[[ $(docker --version) == "Docker version $MCSBX_DOCKER_VERSION,"* ]] || mcsbx_die 'unreviewed docker client version'
[[ ! -e $root ]] || mcsbx_die "$root already exists; provisioning is not re-entrant, run teardown first"
for unit in "$MCSBX_CONTAINERD_UNIT" "$MCSBX_DOCKERD_UNIT" "$MCSBX_LEASE_SLICE" "$MCSBX_ENGINE_SLICE"; do
  [[ $(systemctl show --property=LoadState --value "$unit") != loaded ]] || ! systemctl is-active --quiet "$unit" ||
    mcsbx_die "$unit is already active"
done

mkdir -m 0700 "$root"
state=$root/state.env
: > "$state"
note() { printf '%s=%q\n' "$1" "$2" >> "$state"; }
note root "$root"

# 1. Pinned runtime.
mkdir -m 0700 "$root/bin"
curl --fail --silent --show-error --location --max-time 90 \
  "https://github.com/google/gvisor/releases/download/$MCSBX_RUNSC_RELEASE/gvisor-x86_64.tar.bz2" -o "$root/gvisor.tar.bz2"
printf '%s  %s\n' "$MCSBX_RUNSC_ARCHIVE_SHA256" "$root/gvisor.tar.bz2" | sha256sum --check --status || mcsbx_die 'runsc archive checksum mismatch'
tar -xjf "$root/gvisor.tar.bz2" -C "$root/bin"
rm -f "$root/gvisor.tar.bz2"
chmod 0755 "$root/bin/runsc"
runsc_sha256=$(sha256sum "$root/bin/runsc" | awk '{print $1}')
mkdir -m 0700 "$root/bin/containerd"
curl --fail --silent --show-error --location --max-time 90 \
  "https://github.com/containerd/containerd/releases/download/v$MCSBX_CONTAINERD_VERSION/containerd-static-$MCSBX_CONTAINERD_VERSION-linux-amd64.tar.gz" \
  -o "$root/containerd.tar.gz"
printf '%s  %s\n' "$MCSBX_CONTAINERD_ARCHIVE_SHA256" "$root/containerd.tar.gz" | sha256sum --check --status || mcsbx_die 'containerd archive checksum mismatch'
tar -xzf "$root/containerd.tar.gz" -C "$root/bin/containerd" --strip-components=1 bin/containerd bin/containerd-shim-runc-v2 bin/ctr
rm -f "$root/containerd.tar.gz"
containerd_version=$("$root/bin/containerd/containerd" --version)
[[ $containerd_version == *" v$MCSBX_CONTAINERD_VERSION "* ]] || mcsbx_die "unexpected containerd build: $containerd_version"
runsc_version=$("$root/bin/runsc" --version | head -1)
# Newer releases execute a bundled sentry binary; older ones run runsc itself.
sentry_path=$root/bin/runsc
if [[ -f $root/bin/gvisor-bin/gvisor_sentry ]]; then sentry_path=$root/bin/gvisor-bin/gvisor_sentry; fi
sentry_sha256=$(sha256sum "$sentry_path" | awk '{print $1}')

# 2. Finite dedicated data filesystem (aggregate disk bound for every engine
#    byte class) and size-limited tmpfs run root (sockets and runtime state).
mkdir -m 0700 "$root/data" "$root/run"
truncate -s "${data_fs_mib}M" "$root/data.xfs"
loop_device=$(losetup --find --show "$root/data.xfs")
note loop_device "$loop_device"
mkfs.xfs -q -f "$loop_device"
# No nodev: Docker's overlay2 quota control opens a block-device node it
# creates under the data root (backingFsBlockDev) for quotactl.
mount -t xfs -o prjquota,nosuid "$loop_device" "$root/data"
note data_mounted 1
mount -t tmpfs -o "size=${run_tmpfs_mib}m,mode=0700,nodev,nosuid" mcsbx-run "$root/run"
note run_mounted 1
mkdir -m 0711 "$root/data/docker" "$root/data/containerd" "$root/run/docker" "$root/run/containerd" "$root/run/exec"

# 3. Dedicated containerd: own root on the data filesystem, own state and
#    socket on the run tmpfs, CRI disabled. Shim sockets still live in the
#    host-wide /run/containerd/s directory (containerd hardcodes it); the
#    names hash this daemon's socket path and are recorded as unenforced.
cat > "$root/containerd.toml" <<EOF
version = 3
root = "$root/data/containerd"
state = "$root/run/containerd/state"
disabled_plugins = ["io.containerd.grpc.v1.cri", "io.containerd.cri.v1.runtime", "io.containerd.cri.v1.images"]
[grpc]
  address = "$root/run/containerd/containerd.sock"
[ttrpc]
  address = "$root/run/containerd/containerd.sock.ttrpc"
[debug]
  address = ""
[metrics]
  address = ""
EOF
# PATH puts the pinned shim first; the host's containerd-shim-runc-v2 is
# never used by this daemon.
systemd-run --quiet --unit "$MCSBX_CONTAINERD_UNIT" --slice "$MCSBX_ENGINE_SLICE" \
  --property=KillMode=control-group --property=TasksMax=infinity \
  --setenv=PATH="$root/bin/containerd:/usr/sbin:/usr/bin:/sbin:/bin" \
  "$root/bin/containerd/containerd" --config "$root/containerd.toml"
note containerd_unit 1
for _ in {1..30}; do
  if "$root/bin/containerd/ctr" --address "$root/run/containerd/containerd.sock" version >/dev/null 2>&1; then break; fi
  sleep 1
done
"$root/bin/containerd/ctr" --address "$root/run/containerd/containerd.sock" version >/dev/null || mcsbx_die 'dedicated containerd did not start'

# 4. Dedicated dockerd on its own socket and data root. Defaults are chosen
#    to fail closed when a backend forgets a flag: runsc is the default
#    runtime, containers default into the lease slice with a bounded writable
#    layer and bounded logs, and the daemon creates no bridge or firewall
#    rules. Namespace flags cannot also appear in daemon.json.
python3 - "$root" "$default_writable_mib" "$log_max_size_mib" "$log_max_file" "$MCSBX_LEASE_SLICE" <<'PY'
import json, sys
root, writable, log_size, log_file, lease_slice = sys.argv[1:]
config = {
    'data-root': root + '/data/docker', 'exec-root': root + '/run/exec',
    'pidfile': root + '/run/docker/dockerd.pid',
    'hosts': ['unix://' + root + '/run/docker/docker.sock'], 'group': 'root',
    'storage-driver': 'overlay2', 'storage-opts': ['overlay2.size=' + writable + 'M'],
    'features': {'containerd-snapshotter': False, 'buildkit': False},
    'bridge': 'none', 'iptables': False, 'ip6tables': False, 'ip-forward': False,
    'ip-masq': False, 'userland-proxy': False, 'live-restore': False,
    'exec-opts': ['native.cgroupdriver=systemd'], 'cgroup-parent': lease_slice,
    'default-cgroupns-mode': 'private', 'no-new-privileges': True,
    'log-driver': 'json-file', 'log-opts': {'max-size': log_size + 'm', 'max-file': log_file},
    'default-runtime': 'runsc',
    'runtimes': {'runsc': {'path': root + '/bin/runsc',
                           'runtimeArgs': ['--systemd-cgroup', '--overlay2=none']}},
}
with open(root + '/daemon.json', 'w', encoding='utf-8') as out:
    json.dump(config, out, indent=2, sort_keys=True)
PY
systemd-run --quiet --unit "$MCSBX_DOCKERD_UNIT" --slice "$MCSBX_ENGINE_SLICE" \
  --property=KillMode=control-group --property=TasksMax=infinity \
  /usr/bin/dockerd --config-file "$root/daemon.json" \
  --containerd "$root/run/containerd/containerd.sock" \
  --containerd-namespace "$MCSBX_NAMESPACE" --containerd-plugins-namespace "$MCSBX_PLUGINS_NAMESPACE"
note dockerd_unit 1
export DOCKER_HOST="unix://$root/run/docker/docker.sock"
for _ in {1..60}; do
  if docker info >/dev/null 2>&1; then break; fi
  sleep 1
done
docker info >/dev/null 2>&1 || { journalctl -u "$MCSBX_DOCKERD_UNIT" --no-pager | tail -60 >&2; mcsbx_die 'dedicated dockerd did not start'; }

# 5. Finite slices. Engine overhead (daemons, shims, gofers) is charged to
#    the engine slice, customer sandboxes to the lease slice; both are
#    disjoint from the runner's own cgroup.
systemctl set-property --runtime "$MCSBX_ENGINE_SLICE" "MemoryMax=${engine_memory_mib}M" MemorySwapMax=0 "TasksMax=$engine_tasks"
systemd-run --quiet --unit mcsbxleaseanchor.service --slice "$MCSBX_LEASE_SLICE" --remain-after-exit /bin/true
note lease_anchor 1
systemctl set-property --runtime "$MCSBX_LEASE_SLICE" "CPUQuota=$((lease_cpu_millis / 10))%" \
  "MemoryMax=${lease_memory_mib}M" MemorySwapMax=0 "TasksMax=$lease_tasks"

# 6. Profile: configured values only. Conformance and live preflight
#    re-observe every one of them; nothing here is proof.
python3 - "$root" <<PY
import json, sys
root = sys.argv[1]
profile = {
    'schema': 'miss.computer/misscomputer-subnet/sandbox-host-profile', 'schema_version': 1,
    'docker_host': 'unix://' + root + '/run/docker/docker.sock',
    'containerd': {'address': root + '/run/containerd/containerd.sock',
                   'namespace': '$MCSBX_NAMESPACE', 'plugins_namespace': '$MCSBX_PLUGINS_NAMESPACE'},
    'data_root': root + '/data', 'docker_data_root': root + '/data/docker', 'run_root': root + '/run',
    'runtime': {'name': 'runsc', 'path': root + '/bin/runsc', 'sha256': '$runsc_sha256',
                'sentry_path': '$sentry_path', 'sentry_sha256': '$sentry_sha256',
                'args': ['--systemd-cgroup', '--overlay2=none'], 'release': '$MCSBX_RUNSC_RELEASE'},
    'engine': {'docker_version': '$MCSBX_DOCKER_VERSION'},
    'cgroup_root': '/sys/fs/cgroup',
    'lease_slice': '$MCSBX_LEASE_SLICE', 'engine_slice': '$MCSBX_ENGINE_SLICE',
    'aggregate': {'cpu_millis': $lease_cpu_millis, 'memory_mib': $lease_memory_mib, 'pids': $lease_tasks,
                  'data_fs_mib': $data_fs_mib, 'run_tmpfs_mib': $run_tmpfs_mib,
                  'image_reserve_mib': $image_reserve_mib, 'engine_overhead_mib': $engine_overhead_mib,
                  'image_max_mib': $image_max_mib, 'log_mib': $log_mib,
                  'disk_mib': $lane_disk_mib, 'sandboxes': $sandboxes},
    'per_lease': {'default_writable_mib': $default_writable_mib, 'log_max_size_mib': $log_max_size_mib,
                  'log_max_file': $log_max_file, 'pids_max': $lease_pids_max, 'mounts': 'none', 'image_volumes': 'refuse',
                  'network_modes': ['none'], 'isolation': ['gvisor']},
}
with open(root + '/profile.json', 'w', encoding='utf-8') as out:
    json.dump(profile, out, indent=2, sort_keys=True)
    out.write('\n')
PY
python3 "$here/report.py" check-profile "$root/profile.json"
mcsbx_report "provisioned: root=$root docker=$MCSBX_DOCKER_VERSION $containerd_version runsc=$runsc_version (sha256 $runsc_sha256)"
mcsbx_report "profile: $root/profile.json (configured values; see conformance report for observations)"
