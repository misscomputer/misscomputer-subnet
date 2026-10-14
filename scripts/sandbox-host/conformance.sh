#!/usr/bin/env bash
# shellcheck disable=SC2154 # p_* come from the profile eval below
# SPDX-License-Identifier: AGPL-3.0-only
# Conformance proof for a host provisioned by provision-disposable.sh, on a
# DISPOSABLE GitHub-hosted VM only. Every catalog check
# (pkg/sandboxhost/check-catalog.v1.json) is recorded with its evidence class;
# report.py derives the verdict and writes sandbox-host-preflight.v1. The
# first failed check stops the run; unreached checks are reported not_run.
# Configured values from profile.json are never accepted as observations.
set -Eeuo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd "$here/../.." && pwd)
# shellcheck source=scripts/sandbox-host/lib.sh
source "$here/lib.sh"
mcsbx_require_disposable
mcsbx_require_tools docker nft curl python3 findmnt xfs_quota systemctl nsenter ip stat df awk sha256sum readlink timeout git

root=$(mcsbx_root)
profile=$root/profile.json
[[ -f $profile ]] || mcsbx_die "no profile at $profile; run provision-disposable.sh first"
python3 "$here/report.py" check-profile "$profile" || mcsbx_die 'profile is invalid'
observer=${MC_SANDBOX_HOST_OBSERVER:-}
[[ -x $observer ]] || mcsbx_die 'MC_SANDBOX_HOST_OBSERVER must name the built cmd/sandbox-host-observe binary'
out_dir=${RUNNER_TEMP}/mcsbx-report
mkdir -p "$out_dir"
ledger=$out_dir/checks.jsonl
report_path=$out_dir/sandbox-host-preflight.conformance.json
: > "$ledger"
work=$(mktemp -d "${RUNNER_TEMP:-/tmp}/mcsbx-work.XXXXXX")

# The p_* variables are assigned by this eval of the validated profile.
eval "$(python3 - "$profile" <<'PY'
import json, shlex, sys
p = json.load(open(sys.argv[1], encoding='utf-8'))
flat = {
    'docker_host': p['docker_host'], 'containerd_address': p['containerd']['address'],
    'containerd_ns': p['containerd']['namespace'], 'containerd_plugins_ns': p['containerd']['plugins_namespace'],
    'data_root': p['data_root'], 'docker_root': p['docker_data_root'], 'run_root': p['run_root'],
    'runsc_path': p['runtime']['path'], 'runsc_sha256': p['runtime']['sha256'],
    'sentry_path': p['runtime']['sentry_path'], 'sentry_sha256': p['runtime']['sentry_sha256'],
    'runsc_args': json.dumps(p['runtime']['args']), 'docker_version': p['engine']['docker_version'],
    'engine_egress_table': p['engine']['egress_table'],
    'cgroup_root': p['cgroup_root'], 'lease_slice': p['lease_slice'], 'engine_slice': p['engine_slice'],
}
for key, value in p['aggregate'].items():
    flat['agg_' + key] = value
for key, value in p['per_lease'].items():
    if isinstance(value, int):
        flat['lease_' + key] = value
for key, value in flat.items():
    print(f'p_{key}={shlex.quote(str(value))}')
PY
)"
export DOCKER_HOST=$p_docker_host
readonly MIB=1048576

cid=
cls=
begin() { cid=$1; cls=$2; }
clean_text() { printf '%s' "$*" | tr '\n\t' '  ' | tr -cd '\40-\176' | cut -c1-500; }
ok() { python3 "$here/report.py" record "$ledger" "$cid" "$cls" pass "$(clean_text "$*")"; echo "PASS $cid: $*"; }
bad() {
  python3 "$here/report.py" record "$ledger" "$cid" "$cls" fail "$(clean_text "$*")" || true
  mcsbx_die "$cid: $*"
}
gap() { python3 "$here/report.py" record "$ledger" "$1" unenforced gap "$(clean_text "${*:2}")"; echo "GAP  $1: ${*:2}"; }

finish() {
  local result=$?
  trap - EXIT
  set +e
  mapfile -t leftovers < <(timeout 30 docker ps -aq --filter label=mcsbx.conformance=1 2>/dev/null)
  if (( ${#leftovers[@]} )); then timeout 60 docker rm -f -v "${leftovers[@]}" >/dev/null 2>&1; fi
  [[ -n ${sampler:-} ]] && kill "$sampler" >/dev/null 2>&1
  rm -rf -- "$work"
  local env_args=(
    "source_sha=$(git -C "$repo" rev-parse HEAD 2>/dev/null)"
    "github_run_id=${GITHUB_RUN_ID:-}"
    "runner_image=${ImageOS:-unknown} ${ImageVersion:-unknown}"
    "kernel=$(uname -r)" "systemd=$(systemctl --version | head -1)"
    "docker=$(timeout 10 docker version --format '{{.Server.Version}}' 2>/dev/null)"
    "containerd=$("$root/bin/containerd/containerd" --version 2>/dev/null)"
    "runsc=$("$p_runsc_path" --version 2>/dev/null | head -1)"
  )
  python3 "$here/report.py" finalize "$ledger" "$profile" conformance "$report_path" "${env_args[@]}"
  local verdict=$?
  python3 - "$report_path" <<'PY' | tee -a "${GITHUB_STEP_SUMMARY:-/dev/null}"
import json, sys
try:
    r = json.load(open(sys.argv[1], encoding='utf-8'))
except Exception as exc:  # report is absent only if finalize itself failed
    print(f'report unavailable: {exc}')
    raise SystemExit(0)
print(f"sandbox-host-preflight.v1 conformance verdict: {r['verdict']} (source {r['environment']['source_sha']})")
print('| check | class | status | evidence |')
print('| --- | --- | --- | --- |')
for c in r['checks']:
    print(f"| {c['id']} | {c['class']} | {c['status']} | {c['evidence'].replace('|', '/')} |")
PY
  if (( result == 0 && verdict != 0 )); then result=$verdict; fi
  exit "$result"
}
trap finish EXIT

lease_cg=$(systemctl show --property=ControlGroup --value "$p_lease_slice")
engine_cg=$(systemctl show --property=ControlGroup --value "$p_engine_slice")
cg() { cat "$p_cgroup_root$1/$2"; }
within() { [[ $1 == "$2" || $1 == "$2"/* ]]; }
proc_cgroup() { awk -F: '$1 == "0" {print $3}' "/proc/$1/cgroup"; }

# ---- Host and cgroup state -------------------------------------------------
begin host.cgroup2_mount_authentic observed_state
magic=$(stat -f -c %t "$p_cgroup_root")
mount_view=$(python3 - "$p_cgroup_root" <<'PY'
import sys
target = sys.argv[1]
rows = []
for line in open('/proc/self/mountinfo', encoding='utf-8'):
    left, right = line.rstrip('\n').split(' - ', 1)
    fields = left.split()
    if fields[4] == target:
        rows.append(f'root={fields[3]} fstype={right.split()[0]}')
print(';'.join(rows))
PY
)
[[ $magic == 63677270 && $mount_view == 'root=/ fstype=cgroup2' ]] || bad "magic=$magic mounts=$mount_view"
ok "statfs magic 0x$magic; single mount $mount_view"

begin cgroup.lease_slice_finite observed_state
[[ -n $lease_cg && $lease_cg != / && -d $p_cgroup_root$lease_cg ]] || bad "lease slice cgroup absent: $lease_cg"
read -r lq lp < <(cg "$lease_cg" cpu.max)
mcsbx_finite "$lq" && mcsbx_finite "$lp" && mcsbx_finite "$(cg "$lease_cg" memory.max)" && mcsbx_finite "$(cg "$lease_cg" pids.max)" ||
  bad "cpu.max=$lq $lp memory.max=$(cg "$lease_cg" memory.max) pids.max=$(cg "$lease_cg" pids.max)"
ok "$lease_cg cpu.max=$lq $lp memory.max=$(cg "$lease_cg" memory.max) pids.max=$(cg "$lease_cg" pids.max)"

begin cgroup.lease_slice_swap_zero observed_state
[[ $(cg "$lease_cg" memory.swap.max) == 0 ]] || bad "memory.swap.max=$(cg "$lease_cg" memory.swap.max)"
ok "$lease_cg memory.swap.max=0"

begin cgroup.engine_slice_finite observed_state
[[ -n $engine_cg && $engine_cg != / ]] || bad "engine slice cgroup absent: $engine_cg"
mcsbx_finite "$(cg "$engine_cg" memory.max)" && mcsbx_finite "$(cg "$engine_cg" pids.max)" && [[ $(cg "$engine_cg" memory.swap.max) == 0 ]] ||
  bad "memory.max=$(cg "$engine_cg" memory.max) pids.max=$(cg "$engine_cg" pids.max) swap=$(cg "$engine_cg" memory.swap.max)"
ok "$engine_cg memory.max=$(cg "$engine_cg" memory.max) pids.max=$(cg "$engine_cg" pids.max) memory.swap.max=0"

begin cgroup.pids_finite_covers_sum observed_state
slice_pids=$(cg "$lease_cg" pids.max)
mcsbx_finite "$slice_pids" && (( slice_pids >= p_agg_sandboxes * p_lease_pids_max )) || bad "pids.max=$slice_pids < $p_agg_sandboxes x $p_lease_pids_max"
ok "$lease_cg pids.max=$slice_pids >= sandboxes $p_agg_sandboxes x per-lease pids_max $p_lease_pids_max"

begin cgroup.engine_processes_member observed_state
member_evidence=
for unit_exe in "$MCSBX_CONTAINERD_UNIT:$root/bin/containerd/containerd" "$MCSBX_DOCKERD_UNIT:/usr/bin/dockerd"; do
  unit=${unit_exe%%:*}; exe=${unit_exe#*:}
  pid=$(systemctl show --property=MainPID --value "$unit")
  mcsbx_finite "$pid" || bad "$unit has no main PID"
  [[ $(readlink -f "/proc/$pid/exe") == "$exe" ]] || bad "$unit PID $pid executes $(readlink -f "/proc/$pid/exe")"
  path=$(proc_cgroup "$pid")
  within "$path" "$engine_cg" || bad "$unit PID $pid is in $path, not $engine_cg"
  member_evidence+="$unit pid=$pid cgroup=$path; "
done
ok "$member_evidence"

begin cgroup.disjoint_from_caller observed_state
caller_cg=$(proc_cgroup $$)
exclusive=("$caller_cg")
read -r -a declared <<< "${MC_SANDBOX_HOST_EXCLUSIVE_CGROUPS:-}"
exclusive+=("${declared[@]}")
for other in "${exclusive[@]}"; do
  for mine in "$lease_cg" "$engine_cg"; do
    if within "$other" "$mine" || within "$mine" "$other"; then bad "$mine overlaps $other"; fi
  done
done
if within "$lease_cg" "$engine_cg" || within "$engine_cg" "$lease_cg"; then bad 'lease and engine slices overlap'; fi
ok "caller=$caller_cg declared=${MC_SANDBOX_HOST_EXCLUSIVE_CGROUPS:-none (disposable host has no agent or deployment.v4 cgroups)}; lease/engine disjoint"

# ---- Engine state ----------------------------------------------------------
info=$work/info.json
docker info --format '{{json .}}' > "$info"
jq_info() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(eval(sys.argv[2], {"d": d, "json": json}))' "$info" "$1"; }

begin engine.socket_dedicated observed_state
sock=${p_docker_host#unix://}
[[ -S $sock && $sock == "$p_run_root"/* && $sock != /var/run/docker.sock && $sock != /run/docker.sock ]] || bad "socket $sock"
[[ $(stat -c '%a %U %G' "$sock") == '660 root root' ]] || bad "socket mode $(stat -c '%a %U %G' "$sock")"
mine_id=$(jq_info 'd["ID"]')
default_id=$(timeout 10 docker -H unix:///var/run/docker.sock info --format '{{.ID}} {{.DockerRootDir}}' 2>/dev/null || echo 'none')
[[ $default_id != "$mine_id "* ]] || bad "dedicated socket reaches the default engine $default_id"
ok "$sock mode 660 root:root engine id $mine_id; default engine: $default_id"

begin engine.version_pinned observed_state
server_version=$(docker version --format '{{.Server.Version}}')
[[ $server_version == "$p_docker_version" ]] || bad "server $server_version"
ok "server $server_version"

begin engine.data_root_on_data_fs observed_state
docker_root=$(jq_info 'd["DockerRootDir"]')
[[ $docker_root == "$p_docker_root" && $(findmnt -n -o TARGET -T "$docker_root") == "$p_data_root" ]] || bad "data root $docker_root on $(findmnt -n -o TARGET -T "$docker_root")"
ok "DockerRootDir=$docker_root on mount $p_data_root"

begin engine.storage_overlay2_xfs observed_state
driver=$(jq_info 'd["Driver"]')
driver_status=$(jq_info 'json.dumps(dict(d["DriverStatus"] or []), sort_keys=True)')
[[ $driver == overlay2 ]] && python3 -c 'import json,sys; s=json.loads(sys.argv[1]); sys.exit(0 if s.get("Backing Filesystem")=="xfs" and s.get("Supports d_type")=="true" else 1)' "$driver_status" ||
  bad "driver=$driver status=$driver_status"
ok "driver=overlay2 (classic store, snapshotter off) status=$driver_status"

begin engine.cgroup_driver_systemd_v2 observed_state
[[ $(jq_info 'd["CgroupDriver"] + " " + d["CgroupVersion"]') == 'systemd 2' ]] || bad "$(jq_info 'd["CgroupDriver"] + " " + d["CgroupVersion"]')"
ok 'CgroupDriver=systemd CgroupVersion=2'

begin engine.containerd_dedicated observed_state
ctd=$(jq_info 'd["Containerd"]["Address"] + " " + d["Containerd"]["Namespaces"]["Containers"] + " " + d["Containerd"]["Namespaces"]["Plugins"]')
[[ $ctd == "$p_containerd_address $p_containerd_ns $p_containerd_plugins_ns" ]] || bad "engine containerd: $ctd"
[[ -S $p_containerd_address && $p_containerd_address == "$p_run_root"/* ]] || bad "containerd socket $p_containerd_address"
[[ -f $p_data_root/containerd/io.containerd.metadata.v1.bolt/meta.db && $(findmnt -n -o TARGET -T "$p_data_root/containerd") == "$p_data_root" ]] ||
  bad 'dedicated containerd metadata is not on the data filesystem'
ok "engine containerd=$ctd; containerd metadata on $p_data_root"

begin engine.network_management_off observed_state
networks=$(docker network ls --format '{{.Name}}' | sort | tr '\n' ' ')
[[ $networks == 'host none ' ]] || bad "networks: $networks"
ok "networks: $networks(no bridge)"

begin engine.firewall_management_off configured
fw=$(python3 -c 'import json,sys; c=json.load(open(sys.argv[1])); print(" ".join(f"{k}={c[k]}" for k in ("iptables","ip6tables","ip-forward","ip-masq","bridge")))' "$root/daemon.json")
[[ $fw == 'iptables=False ip6tables=False ip-forward=False ip-masq=False bridge=none' ]] || bad "daemon.json $fw"
ok "daemon.json $fw (setting, not observed)"

begin engine.default_runtime_runsc observed_state
[[ $(jq_info 'd["DefaultRuntime"]') == runsc ]] || bad "DefaultRuntime=$(jq_info 'd["DefaultRuntime"]')"
ok 'DefaultRuntime=runsc'

begin engine.runtime_runsc_pinned observed_state
registered=$(jq_info 'json.dumps([d["Runtimes"]["runsc"]["path"], d["Runtimes"]["runsc"].get("runtimeArgs")])')
[[ $registered == "$(python3 -c 'import json,sys; print(json.dumps([sys.argv[1], json.loads(sys.argv[2])]))' "$p_runsc_path" "$p_runsc_args")" ]] || bad "registered $registered"
actual_sha=$(sha256sum "$p_runsc_path" | awk '{print $1}')
[[ $actual_sha == "$p_runsc_sha256" ]] || bad "runsc sha256 $actual_sha"
ok "registered $registered sha256=$actual_sha"

begin engine.default_bounded_logs configured
logcfg=$(python3 -c 'import json,sys; c=json.load(open(sys.argv[1])); print(c["log-driver"], json.dumps(c["log-opts"], sort_keys=True))' "$root/daemon.json")
[[ $(jq_info 'd["LoggingDriver"]') == json-file && $logcfg == "json-file {\"max-file\": \"$p_lease_log_max_file\", \"max-size\": \"${p_lease_log_max_size_mib}m\"}" ]] || bad "$logcfg"
ok "LoggingDriver=json-file (observed); default opts $logcfg (setting)"

begin engine.insecure_registries_empty observed_state
registry_view=$(jq_info 'json.dumps([sorted(d["RegistryConfig"].get("InsecureRegistryCIDRs") or []), {k: [v.get("Secure"), v.get("Mirrors") or []] for k, v in (d["RegistryConfig"].get("IndexConfigs") or {}).items()}, d["RegistryConfig"].get("Mirrors") or []], sort_keys=True)')
[[ $registry_view == '[["127.0.0.0/8", "::1/128"], {"docker.io": [true, []]}, []]' || $registry_view == '[[], {"docker.io": [true, []]}, []]' ]] || bad "registry config $registry_view"
ok "registry config $registry_view (Docker's built-in loopback CIDRs cannot be removed; loopback registries need the backend's pre-engine refusal)"

begin engine.no_unlabelled_containers observed_state
total=$(docker ps -aq | wc -l)
[[ $total == 0 ]] || bad "$total containers exist before conformance"
ok 'dedicated engine holds 0 containers before conformance (lab label: mcsbx.conformance)'

# ---- Storage state ---------------------------------------------------------
begin storage.data_fs_xfs_prjquota observed_state
[[ $(stat -f -c %t "$p_data_root") == 58465342 ]] || bad "data fs magic $(stat -f -c %t "$p_data_root")"
findmnt -n -o OPTIONS --target "$p_data_root" | grep -Eq '(^|,)(prjquota|pquota)(,|$)' || bad 'prjquota mount option absent'
project_state=$(xfs_quota -x -c state "$p_data_root" | sed -n '/Project quota state/,+2p' | tr -s ' \n' ' ')
grep -q 'Accounting: ON' <<< "$project_state" && grep -q 'Enforcement: ON' <<< "$project_state" || bad "project quota: $project_state"
ok "xfs magic; $project_state"

begin storage.data_fs_dedicated_finite observed_state
[[ $(findmnt -rn -o TARGET | grep -cxF "$p_data_root") == 1 ]] || bad 'data root is not exactly one mount'
data_source=$(findmnt -n -o SOURCE --mountpoint "$p_data_root")
data_size=$(df -B1 --output=size "$p_data_root" | awk 'NR == 2 {print $1}')
mcsbx_finite "$data_size" && (( data_size <= p_agg_data_fs_mib * MIB && data_size >= p_agg_data_fs_mib * MIB * 9 / 10 )) || bad "data fs size $data_size"
backing=$(losetup -n -O BACK-FILE "$data_source" 2>/dev/null || true)
ok "source=$data_source backing=${backing:-block device} size=$data_size bytes"

begin storage.run_root_tmpfs_finite observed_state
run_view=$(findmnt -n -o FSTYPE,OPTIONS --mountpoint "$p_run_root")
[[ $run_view == tmpfs* && $run_view =~ size=[0-9]+k ]] || bad "run root $run_view"
ok "run root $run_view"

begin budget.within_observed observed_state
slice_cpu_millis=$(( lq * 1000 / lp ))
slice_mem_mib=$(( $(cg "$lease_cg" memory.max) / MIB ))
slice_pids=$(cg "$lease_cg" pids.max)
# Shared-contract D7, against the OBSERVED filesystem size.
disk_required_mib=$(( p_agg_disk_mib + p_agg_sandboxes * (p_agg_image_max_mib + p_agg_log_mib) + p_agg_engine_overhead_mib + p_agg_image_reserve_mib ))
(( p_agg_cpu_millis <= slice_cpu_millis && p_agg_memory_mib <= slice_mem_mib && p_agg_pids <= slice_pids && disk_required_mib <= data_size / MIB )) ||
  bad "profile cpu=$p_agg_cpu_millis mem=$p_agg_memory_mib pids=$p_agg_pids disk+overhead=$disk_required_mib vs observed cpu=$slice_cpu_millis mem=$slice_mem_mib pids=$slice_pids fs=$((data_size / MIB))"
ok "profile cpu=$p_agg_cpu_millis mem=$p_agg_memory_mib pids=$p_agg_pids within observed slice cpu=$slice_cpu_millis mem=$slice_mem_mib pids=$slice_pids; disk $p_agg_disk_mib + $p_agg_sandboxes x ($p_agg_image_max_mib image + $p_agg_log_mib log) + $p_agg_engine_overhead_mib engine + $p_agg_image_reserve_mib reserve = $disk_required_mib <= observed fs $((data_size / MIB)) MiB"

# ---- Engine egress -----------------------------------------------------------
"$observer" -profile "$profile" preflight > "$work/observer-preflight.json"
observer_check() {  # id file -> "status<TAB>evidence"
  python3 -c 'import json,sys; c=[c for c in json.load(open(sys.argv[2])) if c["id"]==sys.argv[1]]; print(c[0]["status"] + "\t" + c[0]["evidence"] if c else "absent\t")' "$1" "$2"
}
begin network.engine_egress_restricted observed_state
IFS=$'\t' read -r egress_status egress_evidence < <(observer_check network.engine_egress_restricted "$work/observer-preflight.json")
[[ $egress_status == pass ]] || bad "pkg/sandboxhost: $egress_status $egress_evidence"
ok "pkg/sandboxhost read back: $egress_evidence"
gap network.engine_pull_egress_public_unrestricted 'engine sockets may reach any public unicast address; no registry hostname allowlist or egress proxy'

gap storage.images_cache_unreserved "image/layer/pull bytes share the ${p_agg_data_fs_mib} MiB data fs; ${p_agg_image_reserve_mib} MiB image reserve is arithmetic, not a quota"
gap network.public_allowlist_unsupported 'only network=none is provisioned and proven; backend must refuse public and allowlist'
gap lease.image_volumes_refused 'engine has no per-lease quota for image VOLUMEs (see effect.image_volume_bypasses_quota); backend must refuse such images'

# ---- One lease instance ----------------------------------------------------
docker pull --quiet --platform linux/amd64 "$MCSBX_IMAGE" >/dev/null
docker image inspect --format '{{json .RepoDigests}}' "$MCSBX_IMAGE" | grep -qF "$MCSBX_IMAGE_DIGEST" || mcsbx_die 'pulled image digest differs from pin'

# The backend (pkg/sandboxbackend) starts the image's own user and command
# with CapDrop ALL, no CapAdd, ipc private and no-new-privileges. The probe
# image is the pinned BusyBox with a default command, so lease containers
# below are created exactly that way, with no user or command override.
docker create --name mcsbx-probe-base --label mcsbx.conformance=1 "$MCSBX_IMAGE" true >/dev/null
docker commit --change 'CMD ["sh","-c","yes mcsbx-conformance | head -c 4000000; touch /tmp/logs-done; exec sleep 900"]' \
  mcsbx-probe-base mcsbx/lease-probe:conformance >/dev/null
docker rm mcsbx-probe-base >/dev/null
image_id=$(docker image inspect --format '{{.Id}}' mcsbx/lease-probe:conformance)

lease_run() {  # name memory_mib pids writable_mib: the backend's create flags, image default user and command
  local name=$1 mem=$2 pids=$3 writable=$4
  docker run --detach --name "$name" --label mcsbx.conformance=1 --runtime runsc --platform linux/amd64 \
    --network none --cgroup-parent "$p_lease_slice" --cpus 1 --memory "${mem}m" --memory-swap "${mem}m" \
    --pids-limit "$pids" --storage-opt "size=${writable}m" --cap-drop ALL --security-opt no-new-privileges \
    --ipc private --restart no --log-driver json-file --log-opt max-size=1m --log-opt max-file=2 \
    mcsbx/lease-probe:conformance >/dev/null
}
sentry_pid() {
  local pid
  pid=$(docker inspect --format '{{.State.Pid}}' "$1")
  mcsbx_finite "$pid" || mcsbx_die "$1 has no host PID"
  printf '%s\n' "$pid"
}

container=mcsbx-lease-main
lease_run "$container" 512 64 64
for _ in {1..30}; do docker exec "$container" test -e /tmp/logs-done >/dev/null 2>&1 && break; sleep 1; done

begin lease.engine_config_matches configured
docker inspect "$container" > "$work/inspect.json"
config_view=$(python3 - "$work/inspect.json" "$p_lease_slice" "$image_id" <<'PY'
import json, sys
item = json.load(open(sys.argv[1], encoding='utf-8'))[0]
host = item['HostConfig']
want = {'Runtime': 'runsc', 'NetworkMode': 'none', 'CgroupParent': sys.argv[2], 'Memory': 536870912,
        'MemorySwap': 536870912, 'PidsLimit': 64, 'NanoCpus': 1000000000, 'Privileged': False,
        'CapDrop': ['ALL'], 'Binds': None, 'StorageOpt': {'size': '64m'}, 'IpcMode': 'private',
        'LogConfig': {'Type': 'json-file', 'Config': {'max-file': '2', 'max-size': '1m'}}}
bad = [f'{k}={host.get(k)!r}' for k, v in want.items() if host.get(k) != v]
if 'no-new-privileges' not in (host.get('SecurityOpt') or []): bad.append('SecurityOpt')
if host.get('Devices') or host.get('DeviceRequests'): bad.append('Devices')
if item['Mounts'] or host.get('Mounts'): bad.append('Mounts')
if item['Image'] != sys.argv[3]: bad.append('Image')
if item['Config']['User'] != '' or item['Config']['Cmd'] is not None and item['Config']['Cmd'][:2] != ['sh', '-c']: bad.append('User/Cmd override')
if host.get('CapAdd'): bad.append('CapAdd')
print('BAD ' + ' '.join(bad) if bad else 'backend create flags: runtime=runsc network=none parent=%s cpu=1 mem=swap=512MiB pids=64 storage=64m logs=1m*2 ipc=private mounts=none CapDrop=ALL CapAdd=none nnp; image default user and command' % sys.argv[2])
PY
)
[[ $config_view != BAD* ]] || bad "$config_view"
ok "$config_view (engine-recorded settings)"

pid=$(sentry_pid "$container")
begin lease.sentry_pinned_exe observed_state
exe=$(readlink -f "/proc/$pid/exe")
[[ $exe == "$p_sentry_path" && $(sha256sum "$exe" | awk '{print $1}') == "$p_sentry_sha256" ]] || bad "PID $pid executes $exe"
ok "PID $pid executes $exe sha256=$p_sentry_sha256 (from sha256-pinned archive)"

begin lease.sentry_in_lease_child_cgroup observed_state
child_cg=$(proc_cgroup "$pid")
[[ $child_cg == "$lease_cg"/* ]] || bad "sentry cgroup $child_cg"
ok "sentry cgroup $child_cg below $lease_cg"

begin lease.child_limits_match observed_state
child_view="cpu.max=$(cg "$child_cg" cpu.max) memory.max=$(cg "$child_cg" memory.max) memory.swap.max=$(cg "$child_cg" memory.swap.max) pids.max=$(cg "$child_cg" pids.max)"
[[ $child_view == 'cpu.max=100000 100000 memory.max=536870912 memory.swap.max=0 pids.max=64' ]] || bad "$child_view"
ok "$child_view"

begin lease.runtime_processes_in_finite_cgroups observed_state
proc_view=
for proc in /proc/[0-9]*; do
  p=${proc#/proc/}
  pexe=$(readlink -f "$proc/exe" 2>/dev/null) || continue
  case $pexe in
    "$root"/bin/*) ;;
    */containerd-shim-runc-v2)
      if tr '\0' ' ' < "$proc/cmdline" 2>/dev/null | grep -qF -- "$p_containerd_address"; then bad "PID $p runs unpinned shim $pexe"; fi
      continue ;;
    *) continue ;;
  esac
  pcg=$(proc_cgroup "$p" 2>/dev/null) || continue
  within "$pcg" "$lease_cg" || within "$pcg" "$engine_cg" || bad "PID $p ($pexe) in unbounded cgroup $pcg"
  proc_view+="${pexe##*/}@$pcg "
done
[[ -n $proc_view ]] || bad 'no runtime processes found'
ok "$proc_view"

begin lease.host_netns_lo_only_no_routes observed_state
links=$(nsenter --net="/proc/$pid/ns/net" ip -o link show | awk -F': ' '{print $2}' | sed 's/@.*//' | tr '\n' ' ')
routes=$( { nsenter --net="/proc/$pid/ns/net" ip -4 route show table all; nsenter --net="/proc/$pid/ns/net" ip -6 route show table all; } | grep -v ' dev lo' || true)
[[ $links == 'lo ' && -z $routes ]] || bad "host netns links=$links non-lo routes=$routes"
ok "host-side netns of PID $pid: links=$links; no route off lo"

begin conformance.go_observer_matches observed_state
"$observer" -profile "$profile" instance -pid "$pid" > "$work/observer-instance.json"
disagree=$(python3 - "$work/observer-preflight.json" "$work/observer-instance.json" <<'PY'
import json, sys
bad = []
for path in sys.argv[1:]:
    for c in json.load(open(path)):
        if c['status'] not in ('pass', 'gap'):
            bad.append(f"{c['id']}={c['status']}:{c['evidence'][:160]}")
print('; '.join(bad))
PY
)
[[ -z $disagree ]] || bad "pkg/sandboxhost on this host: $disagree"
ok "pkg/sandboxhost Preflight ($(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))))' "$work/observer-preflight.json") checks) and ObserveInstance(PID $pid) pass every lane2-owned check on this host"

begin lease.sandbox_interfaces_lo_only observed_state
interfaces=$(docker exec "$container" awk 'NR > 2 {sub(/:.*/, ""); gsub(/ /, ""); print}' /proc/net/dev | tr '\n' ' ')
[[ $interfaces == 'lo ' ]] || bad "sandbox interfaces: $interfaces"
ok "sandbox /proc/net/dev: $interfaces"

begin lease.engine_socket_absent observed_state
socket_view=$(docker exec "$container" sh -c 'for p in "$@"; do [ -e "$p" ] && echo "present:$p"; done; grep -E "docker|containerd" /proc/mounts' sh \
  /var/run/docker.sock /run/docker.sock /run/containerd/containerd.sock "$sock" "$p_containerd_address" || true)
[[ -z $socket_view ]] || bad "guest sees $socket_view"
ok "guest has none of /var/run/docker.sock /run/docker.sock /run/containerd/containerd.sock or the dedicated sockets; no engine mounts"

begin effect.network_probes_no_route observed_effect
# Corroboration only: the host-side netns check above is the primary
# assertion. With no interface but lo there is no upstream router that could
# return ICMP network-unreachable, so ENETUNREACH is local. The full error
# line must match exactly; any other outcome means the address was reached
# or the probe failed for another reason.
probe_view=
for target in 169.254.169.254 1.1.1.1 '[2606:4700:4700::1111]'; do
  if [[ $target == \[* ]]; then expected="wget: can't connect to remote host: Network is unreachable"
  else expected="wget: can't connect to remote host ($target): Network is unreachable"; fi
  if probe=$(timeout 10 docker exec "$container" wget -T 3 -q -O /dev/null "http://$target/" 2>&1 >/dev/null); then bad "reached $target"; fi
  [[ $probe == "$expected" ]] || bad "probe $target: ${probe:-no output}"
  probe_view+="$target: $probe; "
done
docker exec "$container" true || bad 'liveness control failed after probes'
ok "$probe_view"

begin effect.udp_dns_no_route observed_effect
# BusyBox nc reports a failed UDP connect only with -v (without it, rc 1 and
# no output, which proves nothing). A UDP connect succeeds whenever a route
# exists, so only the exact local connect failure counts. Without an IPv6
# source address the kernel answers EADDRNOTAVAIL instead of ENETUNREACH;
# both mean the datagram cannot leave, and the host-side namespace check is
# the primary assertion. Lines were reproduced with the pinned BusyBox
# 1.36.1 in an unprivileged network-less namespace.
udp_view=
udp_probe() {  # expected-line... -- command...
  local expected=() out
  while [[ $1 != -- ]]; do expected+=("$1"); shift; done
  shift
  if out=$(timeout 15 docker exec "$container" "$@" 2>&1 </dev/null); then bad "udp probe succeeded: $* -> $out"; fi
  for line in "${expected[@]}"; do
    if [[ $out == "$line" ]]; then udp_view+="$out; "; return 0; fi
  done
  bad "udp probe $* failed otherwise: ${out:-no output}"
}
udp_probe 'nc: 1.1.1.1 (1.1.1.1:53): Network is unreachable' -- nc -v -u -w 2 1.1.1.1 53
udp_probe 'nc: 2606:4700:4700::1111 ([2606:4700:4700::1111]:53): Network is unreachable' \
  'nc: 2606:4700:4700::1111 ([2606:4700:4700::1111]:53): Cannot assign requested address' -- nc -v -u -w 2 2606:4700:4700::1111 53
udp_probe "nslookup: can't connect to remote host (1.1.1.1): Network is unreachable" -- nslookup -timeout=3 example.com 1.1.1.1
udp_probe "nslookup: can't connect to remote host: Network is unreachable" \
  "nslookup: can't connect to remote host: Cannot assign requested address" -- nslookup -timeout=3 example.com 2606:4700:4700::1111
ok "$udp_view"

begin effect.icmp_no_route_with_net_raw observed_effect
# NET_RAW is more than any lease gets, so a missing capability cannot be
# what stops the probe. runsc without --net-raw may still refuse the raw
# socket; the evidence says which guard stopped it.
icmp_view=
for family in -4 -6; do
  target=1.1.1.1; [[ $family == -6 ]] && target=2606:4700:4700::1111
  if icmp=$(timeout 20 docker run --rm --label mcsbx.conformance=1 --network none --cap-drop ALL --cap-add NET_RAW --user 0 \
      --memory 256m --memory-swap 256m --pids-limit 64 "$MCSBX_IMAGE" ping "$family" -c 1 -W 2 "$target" 2>&1); then
    bad "icmp $family reached $target: $icmp"
  fi
  # stdout (PING header) and stderr (the verdict) interleave in either
  # order, so match whole lines anywhere in the output.
  if grep -q 'bytes from' <<< "$icmp"; then bad "icmp $family got a reply: $icmp"
  elif grep -qxF 'ping: sendto: Network is unreachable' <<< "$icmp"; then icmp_view+="$family no route (sendto ENETUNREACH); "
  elif grep -qxF 'ping: permission denied (are you root?)' <<< "$icmp"; then icmp_view+="$family raw socket refused by runsc (no --net-raw), route not exercised by ICMP; "
  else bad "icmp $family failed otherwise: $icmp"; fi
done
ok "$icmp_view"

begin effect.host_loopback_unreachable observed_effect
host_addr=$(ip -o route get 1.1.1.1 | awk '{for (i=1; i<=NF; i++) if ($i == "src") print $(i+1)}')
[[ $host_addr =~ ^[0-9.]+$ ]] || bad "host primary address unknown: $host_addr"
python3 - "$work/listener.count" "$host_addr" <<'PY' &
import selectors, socket, sys, time
count_path, host_addr = sys.argv[1:]
sel = selectors.DefaultSelector()
for addr in ('127.0.0.1', host_addr):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((addr, 18089)); s.listen(8); s.setblocking(False); sel.register(s)
open(count_path, 'w').write('0\n')
seen, deadline = 0, time.time() + 60
while time.time() < deadline:
    for key, _ in sel.select(timeout=0.5):
        conn, _ = key.fileobj.accept(); conn.close(); seen += 1
        open(count_path, 'w').write(f'{seen}\n')
PY
listener=$!
for _ in {1..20}; do [[ -s $work/listener.count ]] && break; sleep 0.25; done
[[ $(curl -s -o /dev/null -w '%{http_code}' --max-time 2 http://127.0.0.1:18089/ || true) == 000 && $(cat "$work/listener.count") == 1 ]] ||
  bad 'host listener control connection was not counted'
loop_probe=$(timeout 10 docker exec "$container" wget -T 3 -q -O /dev/null http://127.0.0.1:18089/ 2>&1 >/dev/null || true)
host_probe=$(timeout 10 docker exec "$container" wget -T 3 -q -O /dev/null "http://$host_addr:18089/" 2>&1 >/dev/null || true)
sleep 1
seen=$(cat "$work/listener.count")
kill "$listener" >/dev/null 2>&1; wait "$listener" 2>/dev/null || true
[[ $loop_probe == "wget: can't connect to remote host (127.0.0.1): Connection refused" ]] || bad "sandbox 127.0.0.1 probe: $loop_probe"
[[ $host_probe == "wget: can't connect to remote host ($host_addr): Network is unreachable" ]] || bad "host address probe: $host_probe"
[[ $seen == 1 ]] || bad "host listener saw $seen connections (1 is the host-side control)"
ok "host listeners 127.0.0.1:18089 and $host_addr:18089 saw only the host control; sandbox 127.0.0.1 refused by its own loopback; host address had no route"

begin effect.engine_egress_blocked observed_effect
# The daemon itself pulls. Docker treats 127.0.0.0/8 as an insecure registry
# (plain HTTP), so without the egress rule this pull would reach the host
# listener. A caller-side control proves the listener counts connections.
reject_count() { nft list table inet "$p_engine_egress_table" | awk '/reject/ {for (i=1; i<=NF; i++) if ($i == "packets") s += $(i+1)} END {print s+0}'; }
python3 - "$work/egress.count" "$host_addr" <<'PY' &
import selectors, socket, sys, time
count_path, host_addr = sys.argv[1:]
sel = selectors.DefaultSelector()
for addr in ('127.0.0.1', host_addr):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((addr, 18090)); s.listen(16); s.setblocking(False); sel.register(s)
open(count_path, 'w').write('0\n')
seen, deadline = 0, time.time() + 120
while time.time() < deadline:
    for key, _ in sel.select(timeout=0.5):
        conn, _ = key.fileobj.accept(); conn.close(); seen += 1
        open(count_path, 'w').write(f'{seen}\n')
PY
egress_listener=$!
for _ in {1..20}; do [[ -s $work/egress.count ]] && break; sleep 0.25; done
curl -s -o /dev/null --max-time 2 http://127.0.0.1:18090/ || true
sleep 0.5
[[ $(cat "$work/egress.count") == 1 ]] || bad 'caller-side control connection to the listener was not counted'
rejects_before=$(reject_count)
pull_view=
for ref in 127.0.0.1:18090/mcsbx/probe:none "$host_addr:18090/mcsbx/probe:none" 169.254.169.254/mcsbx/probe:none; do
  if out=$(timeout 60 docker pull "$ref" 2>&1); then bad "engine pulled $ref"; fi
  pull_view+="$ref: $(tail -1 <<< "$out" | cut -c1-120); "
done
sleep 1
seen=$(cat "$work/egress.count")
kill "$egress_listener" >/dev/null 2>&1; wait "$egress_listener" 2>/dev/null || true
rejects_after=$(reject_count)
[[ $seen == 1 ]] || bad "engine pulls reached the host listeners ($((seen - 1)) connections)"
(( rejects_after > rejects_before )) || bad "egress reject counters did not move ($rejects_before -> $rejects_after); failures not attributable to the rule"
ok "engine pulls never connected (listeners saw only the control); reject counters $rejects_before -> $rejects_after; pinned docker.io pull succeeded; $pull_view"

begin effect.writable_layer_quota observed_effect
quota_bytes=$((64 * MIB))
if docker exec --user 0 "$container" dd if=/dev/zero of=/quota-proof bs=1048576 count=192 > "$work/dd.log" 2>&1; then bad 'wrote past the 64 MiB writable layer'; fi
grep -Eiq 'No space left on device|Disk quota exceeded' "$work/dd.log" || bad "dd failed otherwise: $(tail -2 "$work/dd.log")"
docker exec "$container" sh -c '[ "$(stat -c %d /)" = "$(stat -c %d /quota-proof)" ]' || bad 'write did not target the rootfs layer'
written=$(docker exec "$container" stat -c %s /quota-proof)
global_free=$(df -B1 --output=avail "$p_data_root" | awk 'NR == 2 {print $1}')
(( written >= quota_bytes - 4 * MIB && written <= quota_bytes && global_free > 1024 * MIB )) || bad "written=$written global_free=$global_free"
full_projects=$(xfs_quota -x -c 'report -p -b -N' "$p_data_root" | awk -v hard=$((quota_bytes / 1024)) '$4 == hard && $2 >= hard - 4096 {n++} END {print n+0}')
[[ $full_projects == 1 ]] || bad "full 64 MiB XFS projects: $full_projects"
ok "dd stopped at $written bytes (ENOSPC/EDQUOT) with $global_free bytes free on data fs; one full 64 MiB project"

begin effect.log_rotation observed_effect
log_path=$(docker inspect --format '{{.LogPath}}' "$container")
[[ $log_path == "$p_docker_root"/* ]] || bad "log path $log_path"
log_files=$(find "$(dirname "$log_path")" -maxdepth 1 -name "$(basename "$log_path")*" -type f | wc -l)
log_bytes=$(find "$(dirname "$log_path")" -maxdepth 1 -name "$(basename "$log_path")*" -type f -printf '%s\n' | awk '{s+=$1} END {print s+0}')
[[ -f $log_path.1 && $log_files == 2 ]] && (( log_bytes > 0 && log_bytes <= 3 * MIB )) || bad "files=$log_files bytes=$log_bytes"
ok "rotated to $log_files files, $log_bytes bytes, on data fs"
docker rm -f "$container" >/dev/null
main_pid=$pid main_cg=$child_cg

begin effect.guest_pids_limit observed_effect
container=mcsbx-lease-pids
lease_run "$container" 256 64 64
docker exec "$container" sh -c 'n=0; while [ $n -lt 200 ]; do sleep 120 & n=$((n+1)); done; wait' > "$work/pids.log" 2>&1 &
spawner=$!
sleep 8
# Count guest processes from outside the sandbox with runsc's own state, so
# the count needs no free slot inside a sandbox that is at its limit.
full_id=$(docker inspect --format '{{.Id}}' "$container")
state_dir=$(find "$p_run_root/exec" -maxdepth 3 -type d -path "*/runtime-runsc/$p_containerd_ns" 2>/dev/null | head -1)
guest_procs=unavailable
if [[ -n $state_dir ]]; then
  guest_procs=$(timeout 20 "$p_runsc_path" --root "$state_dir" ps --format json "$full_id" 2>/dev/null |
    python3 -c 'import json,sys; print(len(json.load(sys.stdin) or []))' 2>/dev/null || echo unavailable)
fi
kill "$spawner" >/dev/null 2>&1; wait "$spawner" 2>/dev/null || true
fork_errors=$(grep -Eci "can't fork|Resource temporarily unavailable|No child processes" "$work/pids.log" || true)
[[ $guest_procs =~ ^[0-9]+$ ]] && (( guest_procs <= 64 && fork_errors > 0 )) || bad "guest processes=$guest_procs (runsc root ${state_dir:-not found}) fork errors=$fork_errors"
ok "runsc ps: guest processes=$guest_procs <= 64 after 200 spawn attempts; fork errors=$fork_errors"
docker rm -f "$container" >/dev/null

begin effect.tmp_bounded_by_memory observed_effect
container=mcsbx-lease-tmp
lease_run "$container" 256 64 64
tpid=$(sentry_pid "$container")
tcg=$(proc_cgroup "$tpid")
tmp_rc=0
timeout 120 docker exec --user 0 "$container" dd if=/dev/zero of=/tmp/fill bs=1048576 count=512 > "$work/tmp.log" 2>&1 || tmp_rc=$?
running=$(docker inspect --format '{{.State.Running}} oom={{.State.OOMKilled}} exit={{.State.ExitCode}}' "$container")
events_raw=$(cat "$p_cgroup_root$tcg/memory.events.local" 2>/dev/null || echo 'cgroup gone')
events=$(tr '\n' ' ' <<< "$events_raw")
peak=$(cat "$p_cgroup_root$tcg/memory.peak" 2>/dev/null || echo 0)
tmp_written=$(timeout 10 docker exec "$container" stat -c %s /tmp/fill 2>/dev/null || echo 0)
if [[ $running == true* ]]; then
  (( tmp_rc != 0 && tmp_written < 512 * MIB )) || bad "512 MiB /tmp write completed under 256 MiB memory: rc=$tmp_rc size=$tmp_written"
  max_events=$(awk '$1 == "max" || $1 == "oom" {s+=$2} END {print s+0}' <<< "$events_raw")
  (( max_events > 0 || peak >= 256 * MIB * 9 / 10 )) || bad "write failed without reaching the memory limit: events=$events peak=$peak"
else
  [[ $running == *oom=true* || $running == *exit=137 ]] || [[ $events == *'oom_kill '[1-9]* ]] || bad "container stopped for another reason: $running events=$events"
fi
ok "dd rc=$tmp_rc written=$tmp_written state=$running memory.events.local=$events peak=$peak"
docker rm -f "$container" >/dev/null

begin effect.aggregate_memory_slice observed_effect
slice_max=$(cg "$lease_cg" memory.max)
child_mib=$(( slice_max * 3 / 4 / MIB ))
fill_mib=$(( slice_max * 55 / 100 / MIB ))
before=$(awk '$1 == "max" || $1 == "oom" {s+=$2} END {print s+0}' "$p_cgroup_root$lease_cg/memory.events.local")
lease_run mcsbx-lease-agg-a "$child_mib" 64 64
lease_run mcsbx-lease-agg-b "$child_mib" 64 64
cg_a=$(proc_cgroup "$(sentry_pid mcsbx-lease-agg-a)"); cg_b=$(proc_cgroup "$(sentry_pid mcsbx-lease-agg-b)")
peak_file=$work/agg-peaks
( while :; do
    printf '%s %s\n' "$(cat "$p_cgroup_root$cg_a/memory.peak" 2>/dev/null || echo 0)" "$(cat "$p_cgroup_root$cg_b/memory.peak" 2>/dev/null || echo 0)" >> "$peak_file"
    sleep 0.2
  done ) &
sampler=$!
rc_a=0; rc_b=0
timeout 120 docker exec --user 0 mcsbx-lease-agg-a dd if=/dev/zero of=/tmp/fill bs=1048576 count="$fill_mib" >/dev/null 2>&1 || rc_a=$?
timeout 120 docker exec --user 0 mcsbx-lease-agg-b dd if=/dev/zero of=/tmp/fill bs=1048576 count="$fill_mib" >/dev/null 2>&1 || rc_b=$?
sleep 1
kill "$sampler" >/dev/null 2>&1; wait "$sampler" 2>/dev/null || true; sampler=
after=$(awk '$1 == "max" || $1 == "oom" {s+=$2} END {print s+0}' "$p_cgroup_root$lease_cg/memory.events.local")
states=$(docker inspect --format '{{.Name}} {{.State.Running}}' mcsbx-lease-agg-a mcsbx-lease-agg-b | tr '\n' ' ')
max_peak=$(awk '{if ($1 > m) m = $1; if ($2 > m) m = $2} END {print m+0}' "$peak_file")
(( after > before )) || bad "slice limit never reached: events $before -> $after rc=$rc_a/$rc_b states=$states"
(( rc_a != 0 || rc_b != 0 )) || [[ $states == *false* ]] || bad "both ${fill_mib} MiB writes completed above the ${slice_max}-byte slice"
(( max_peak < child_mib * MIB * 95 / 100 )) || bad "a child reached its own ${child_mib} MiB limit (peak $max_peak); attribution ambiguous"
ok "children ${child_mib} MiB each, ${fill_mib} MiB writes: slice max/oom events $before -> $after, rc=$rc_a/$rc_b, states=$states, max child peak=$max_peak"
docker rm -f mcsbx-lease-agg-a mcsbx-lease-agg-b >/dev/null

# Image-declared volume: a container without explicit cgroup parent or size
# shows the daemon defaults; its anonymous volume is the negative control.
docker create --name mcsbx-volume-base --label mcsbx.conformance=1 "$MCSBX_IMAGE" true >/dev/null
docker commit --change 'VOLUME ["/data"]' mcsbx-volume-base mcsbx/volume-probe:conformance >/dev/null
docker rm mcsbx-volume-base >/dev/null
container=mcsbx-lease-volume
docker run --detach --name "$container" --label mcsbx.conformance=1 --network none --cpus 1 --memory 256m --memory-swap 256m \
  --pids-limit 64 --cap-drop ALL mcsbx/volume-probe:conformance sleep 900 >/dev/null

begin effect.default_lease_parent observed_effect
vpid=$(sentry_pid "$container")
vcg=$(proc_cgroup "$vpid")
[[ $vcg == "$lease_cg"/* && $(readlink -f "/proc/$vpid/exe") == "$root"/bin/* ]] || bad "default container cgroup $vcg exe $(readlink -f "/proc/$vpid/exe")"
if docker exec "$container" dd if=/dev/zero of=/default-proof bs=1048576 count=96 > "$work/default.log" 2>&1; then bad 'default writable layer accepted 96 MiB'; fi
grep -Eiq 'No space left on device|Disk quota exceeded' "$work/default.log" || bad "default write failed otherwise: $(tail -2 "$work/default.log")"
default_written=$(docker exec "$container" stat -c %s /default-proof)
(( default_written <= p_lease_default_writable_mib * MIB )) || bad "default write reached $default_written"
ok "no --runtime/--cgroup-parent/--storage-opt: runsc sentry in $vcg; rootfs write stopped at $default_written bytes (default ${p_lease_default_writable_mib} MiB)"

begin effect.image_volume_bypasses_quota observed_effect
volume_source=$(docker inspect --format '{{range .Mounts}}{{.Type}}:{{.Source}}:{{.Destination}}{{end}}' "$container")
[[ $volume_source == volume:"$p_docker_root"/volumes/*:/data ]] || bad "unexpected mounts $volume_source"
docker exec "$container" dd if=/dev/zero of=/data/bypass bs=1048576 count=96 > "$work/volume.log" 2>&1 || bad "volume write failed: $(tail -2 "$work/volume.log")"
volume_written=$(docker exec "$container" stat -c %s /data/bypass)
(( volume_written == 96 * MIB )) || bad "volume write $volume_written"
ok "anonymous volume $volume_source accepted $volume_written bytes past the ${p_lease_default_writable_mib} MiB writable quota: backend must refuse Volumes images"
docker rm -f -v "$container" >/dev/null
docker image rm mcsbx/volume-probe:conformance >/dev/null

begin effect.image_device_nodes_inert observed_effect
# The data filesystem is not nodev, so device nodes in an image layer become
# host device files under the data root. Put a layer with /dev/mem, /dev/kmsg,
# /dev/null and the data filesystem's own block device into a lease image
# (dockerd extracts it, as it would a pulled layer) and require every open
# from the guest to fail, as root and as nobody. A successful write to the
# block device would corrupt the data filesystem; that only fails this
# disposable run.
data_dev=$(findmnt -n -o SOURCE --mountpoint "$p_data_root")
read -r data_major data_minor < <(stat -L -c '%t %T' "$data_dev")
python3 - "$work/devnodes.tar" "$((16#$data_major))" "$((16#$data_minor))" <<'PY'
import sys, tarfile
out, major, minor = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
with tarfile.open(out, 'w') as tar:
    d = tarfile.TarInfo('devprobe'); d.type = tarfile.DIRTYPE; d.mode = 0o755; tar.addfile(d)
    for name, kind, maj, mnr in (('mem', tarfile.CHRTYPE, 1, 1), ('kmsg', tarfile.CHRTYPE, 1, 11),
                                 ('null', tarfile.CHRTYPE, 1, 3), ('datafs', tarfile.BLKTYPE, major, minor)):
        node = tarfile.TarInfo('devprobe/' + name); node.type = kind; node.mode = 0o666
        node.devmajor, node.devminor = maj, mnr
        tar.addfile(node)
PY
docker create --name mcsbx-devnode-base --label mcsbx.conformance=1 mcsbx/lease-probe:conformance >/dev/null
docker cp - mcsbx-devnode-base:/ < "$work/devnodes.tar"
docker commit mcsbx-devnode-base mcsbx/devnode-probe:conformance >/dev/null
docker rm mcsbx-devnode-base >/dev/null
host_nodes=$(find "$p_docker_root/overlay2" -path '*/diff/devprobe/*' \( -type c -o -type b \) | wc -l)
(( host_nodes >= 4 )) || bad "image layer did not materialize device nodes on the data filesystem ($host_nodes found)"
container=mcsbx-lease-devnode
docker run --detach --name "$container" --label mcsbx.conformance=1 --runtime runsc --platform linux/amd64 \
  --network none --cgroup-parent "$p_lease_slice" --cpus 1 --memory 256m --memory-swap 256m --pids-limit 64 \
  --storage-opt size=64m --cap-drop ALL --security-opt no-new-privileges --ipc private --restart no \
  --log-driver json-file --log-opt max-size=1m --log-opt max-file=2 mcsbx/devnode-probe:conformance >/dev/null
data_sum_before=$(dd if="$data_dev" bs=1M count=1 status=none | sha256sum | awk '{print $1}')
dev_view=
for user in 0 65534; do
  for op in read:mem read:kmsg read:datafs write:datafs write:null; do
    node=/devprobe/${op#*:}
    if [[ ${op%%:*} == read ]]; then cmd=(dd "if=$node" of=/dev/null bs=512 count=1)
    else cmd=(dd if=/dev/zero "of=$node" bs=512 count=1 seek=1 conv=notrunc); fi
    if out=$(timeout 15 docker exec --user "$user" "$container" "${cmd[@]}" 2>&1); then bad "uid $user $op succeeded: $out"; fi
    first=$(head -1 <<< "$out")
    refused=0
    for reason in 'Operation not permitted' 'Permission denied' 'No such device or address' 'No such device' 'Not supported' 'Function not implemented'; do
      [[ $first == "dd: can't open '$node': $reason" ]] && refused=1
    done
    (( refused )) || bad "uid $user $op failed otherwise: $first"
    dev_view+="uid$user $op: ${first#*: }; "
  done
done
data_sum_after=$(dd if="$data_dev" bs=1M count=1 status=none | sha256sum | awk '{print $1}')
[[ $data_sum_before == "$data_sum_after" ]] || bad 'data filesystem head changed during device-node probes'
docker rm -f "$container" >/dev/null
docker image rm mcsbx/devnode-probe:conformance >/dev/null
ok "$host_nodes host device nodes from the image layer; every guest open failed: $dev_view data fs head unchanged"

begin effect.cleanup_instance_absent observed_effect
docker image rm mcsbx/lease-probe:conformance "$MCSBX_IMAGE" >/dev/null
for _ in {1..30}; do [[ ! -e /proc/$main_pid && ! -e $p_cgroup_root$main_cg ]] && break; sleep 1; done
leftover="containers=$(docker ps -aq | wc -l) volumes=$(docker volume ls -q | wc -l) images=$(docker images -q | wc -l)"
children=$(find "$p_cgroup_root$lease_cg" -mindepth 1 -maxdepth 1 -type d -printf '%f ' | sed 's/mcsbxleaseanchor.service //')
[[ $leftover == 'containers=0 volumes=0 images=0' && -z $children && ! -e /proc/$main_pid ]] || bad "$leftover lease children=$children main sentry alive=$([[ -e /proc/$main_pid ]] && echo yes || echo no)"
gap storage.shim_socket_dir_shared "containerd shim sockets live in host-wide /run/containerd/s ($(find /run/containerd/s -maxdepth 1 -type s 2>/dev/null | wc -l) present after cleanup)"
ok "$leftover; no lease child cgroups; data root used $(du -sb "$p_docker_root" | awk '{print $1}') bytes"
