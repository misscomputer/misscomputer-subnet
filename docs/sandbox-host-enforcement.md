# Sandbox host enforcement: disposable provisioning and conformance

Status: **lab proof only.** This is not a `SandboxBackend` and does not
enable `--sandbox-leases on`. It defines the host a future gVisor backend
must run on, provisions it reproducibly on a disposable GitHub-hosted VM,
proves what that host enforces, and emits a machine-readable report.
Nothing here may run on a miner, validator, origin, CI runner host or any
shared machine.

Files:

| Path | Role |
| --- | --- |
| `scripts/sandbox-host/provision-disposable.sh` | creates the dedicated engine and writes `sandbox-host-profile.v1` |
| `scripts/sandbox-host/conformance.sh` | observes and exercises the host, writes `sandbox-host-preflight.v1` |
| `scripts/sandbox-host/teardown-disposable.sh` | removes everything and fails on incomplete cleanup |
| `scripts/sandbox-host/report.py` | ledger, profile check, report derivation and validation |
| `pkg/sandboxhost/check-catalog.v1.json` | the only list of check IDs, their evidence class, owner and modes |
| `.github/workflows/sandbox-host-conformance.yml` | label `run-sandbox-host-gate` on a same-repository PR |

## Trigger and containment

A maintainer applies `run-sandbox-host-gate` to a same-repository pull
request. The job runs on GitHub-hosted `ubuntu-24.04` with
`contents: read`, no secrets and `persist-credentials: false`, and checks out
the PR's exact head SHA (printed in the log and recorded in the report as
`environment.source_sha`). Evidence applies to that SHA only: after a push,
remove and re-apply the label. "Re-run" replays the original SHA.

Every script that runs as root refuses unless `MC_SANDBOX_HOST_DISPOSABLE=1`,
`GITHUB_ACTIONS=true`, `RUNNER_ENVIRONMENT=github-hosted`, `ImageOS` and
`ImageVersion` are set, and refuses if `/run/.containerenv`, `/.dockerenv`,
`/etc/misscomputer`, `/opt/misscomputer-*`, a `.bittensor` wallet directory
or any `misscomputer-*` systemd unit exists. This is an accident guard, not a
security boundary: all of it is caller-controlled.

## Provisioned host

| Component | Disposable lab | Why |
| --- | --- | --- |
| Data filesystem | 4 GiB XFS loop file, `prjquota,nosuid` (not `nodev`: overlay2 quota control needs its device node) | aggregate bound for images, pull temp, writable layers, logs, anonymous volumes and containerd content; project quota makes overlay2 `size` real |
| Run root | 64 MiB tmpfs | engine socket, exec-root, containerd state and socket, runsc state |
| containerd | dedicated instance, root on the data filesystem, state and socket on the run root, CRI disabled, namespaces `mc-sandbox`/`mc-sandbox-plugins` | no shared containerd metadata, content or socket with the host's default engine |
| dockerd | dedicated instance on `<run>/docker/docker.sock` (0660 root:root), Docker 28.0.4, overlay2 classic store (containerd snapshotter off) | own data root, socket and containerd |
| Daemon defaults | default runtime `runsc`, `cgroup-parent` = lease slice, `overlay2.size` default, json-file logs `8m` x `2`, `no-new-privileges`, private cgroupns, no bridge, iptables/ip6tables/ip-forward/ip-masq off, no live-restore | a container started without explicit flags still lands in gVisor, the lease slice and a bounded writable layer |
| Runtime | gVisor `release-20261005.0` by archive SHA-256, registered as `runsc --systemd-cgroup --overlay2=none` | the overlay2 quota holds only with these arguments |
| `mcsbxlease.slice` | `CPUQuota=200%`, `MemoryMax=1G`, `MemorySwapMax=0`, `TasksMax=1024` | aggregate lease CPU, memory, swap and host task budget |
| `mcsbxengine.slice` | containerd and dockerd units, finite memory and tasks, swap 0 | engine, shim and gofer overhead never borrows the lease budget and never runs unbounded |

Slice names contain no `-`, so systemd creates no implicit parent slices.

## Contracts

`sandbox-host-profile.v1` is what the provisioner **configured**: socket,
containerd, data and run roots, runtime and sentry path with SHA-256,
slices, aggregate sizing and per-lease policy. A backend uses it to find its
engine. It is never proof; `report.py check-profile` only rejects profiles
that could not be proven (default socket, shared containerd namespace,
other runsc arguments, disk or pids overcommit, network modes other than
`none`).

`sandbox-host-preflight.v1` is a report. Each check from the catalog appears
exactly once with its catalog class:

- `observed_effect`: the check caused the effect and measured the outcome
  (for example, a write that stopped at the quota with EDQUOT). Conformance
  mode only.
- `observed_state`: read back from the kernel, filesystem or engine without
  trusting configuration.
- `configured`: a setting the engine records whose effect this check did
  not measure.
- `unenforced`: a known gap, always reported as `gap`, listed in
  `unenforced` and never counted as enforcement.

The verdict is derived: `pass` only if every non-gap check passed. A check
that was not reached is `not_run` and fails the verdict. `report.py validate`
rejects a report whose classes, check list, gap list or verdict differ from
what the catalog and its checks imply.

Modes: `conformance` (this lab, every check), `preflight` (a live backend's
read-only startup checks) and `instance` (per sandbox after create). The
catalog `owner` says who implements the live check: lane 2 owns kernel,
cgroup, filesystem and process observation; the backend owns `engine.*`
through its Engine API client. A live backend may start only when every
`observed_state` check of the preflight mode passes; `configured` checks
are recorded, not accepted as startup evidence.

## Disk accounting

Per lease, the overlay2 writable-layer quota equals the lease's `disk_mib`.
Container logs (json-file `max-size` x `max-file`) and image bytes are
operator overhead outside the lane disk budget. The host can honestly
report a lane disk budget `disk_mib` only when the observed data filesystem
satisfies

    data_fs_mib >= disk_mib + sandboxes x (image_max_mib + log_mib)
                   + engine_overhead_mib + image_reserve_mib

Images and pull temp are shared and not charged to any lease. The reserve is
arithmetic, not a quota: a pull can fill the data filesystem and make a lease
hit ENOSPC below its own quota. That is an availability problem bounded by
the finite filesystem, not an escape, and stays `unenforced`
(`storage.images_cache_unreserved`). Image-declared `VOLUME`s get anonymous
volumes on the data filesystem with no per-lease quota; conformance
demonstrates the bypass and the backend must refuse such images
(`lease.image_volumes_refused` stays `unenforced` in host reports). gVisor's
`/tmp` is memory-backed and must be charged to the lease memory limit
(`effect.tmp_bounded_by_memory`).

## What conformance proves

Host state: the cgroup2 mount is the hierarchy root (superblock magic and
mountinfo root `/`), both slices are finite, swap is 0, lease pids cover
`sandboxes x pids_max`, the daemons actually run in the engine slice, and
both slices are disjoint from the caller's cgroup. The engine is the
dedicated one (socket, version, data root on the data filesystem, overlay2
on XFS with d_type, systemd cgroups v2, dedicated containerd and its
metadata on the data filesystem, no bridge network, default runtime
`runsc`, registered path and arguments, binary hash, only Docker's built-in
loopback insecure CIDRs, no foreign containers). Storage: XFS project quota
accounting and enforcement on, data filesystem dedicated and sized as
profiled, run root a sized tmpfs; profile budgets fit inside observed limits.

Per lease (`runsc`, `network=none`, 1 CPU, 512 MiB, 64 pids, 64 MiB writable
layer, logs 1m x 2, nonroot, no capabilities): the engine recorded settings;
the container PID executes the pinned sentry; its actual cgroup is a child
of the lease slice with exactly the lease's `cpu.max`, `memory.max`,
`memory.swap.max` and `pids.max`; every gVisor and shim process of the
instance is in the lease or engine slice; the sentry's host-side network
namespace has only `lo` and no route off it; the guest sees only `lo` and no
engine socket.

Effects: IPv4 metadata, IPv4 and IPv6 public TCP fail with exactly the
no-route line; UDP 53 and DNS fail for lack of a route; ICMP from a probe
granted `NET_RAW` cannot leave; host listeners on `127.0.0.1` and the host's
primary address see no sandbox connection; the writable layer stops at its
quota while the data filesystem has free space; logs rotate within the cap;
guest process creation stops at the pids limit; a `/tmp` write larger than
memory cannot complete and is attributed to the memory limit; two leases
below their own limits are stopped by the aggregate slice; a container with
no explicit flags still gets gVisor, the lease slice and the default
writable quota; an image `VOLUME` bypasses the quota (negative control);
after destroy no container, volume, image, sentry or child cgroup remains.
Teardown then proves no unit, slice, cgroup, mount, loop device or directory
remains.

## Not proven

- A production host. The lab uses a loop file, not a dedicated device, and
  its cgroup mount, kernel and Docker are GitHub's. Each live host needs its
  own preflight; this evidence is per SHA and per runner image.
- Image cache reservation, registry pull egress restriction (container
  `network=none` does not constrain the daemon's pulls), `public` and
  `allowlist` egress, secret delivery, exec and file transfer.
- containerd shim sockets in the host-wide `/run/containerd/s`
  directory (`storage.shim_socket_dir_shared`).
- Startup recovery and orphan reconciliation of a real backend, and any
  live miner path. No activation may be inferred from a green job.
