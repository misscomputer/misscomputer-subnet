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
| `pkg/sandboxhost` (Go) | live read-only implementation of the lane-2-owned preflight and instance checks, profile decoding and report building, for the backend to consume |
| `cmd/sandbox-host-observe` | prints `pkg/sandboxhost` observations as JSON; conformance runs it on the provisioned host |
| `.github/workflows/sandbox-host-conformance.yml` | label `run-sandbox-host-gate` on a same-repository PR |

## Trigger and containment

A maintainer applies `run-sandbox-host-gate` to a same-repository pull
request. The job runs on GitHub-hosted `ubuntu-24.04` with
`contents: read`, no secrets and `persist-credentials: false`, and checks out
the PR's exact head SHA (printed in the log and recorded in the report as
`environment.source_sha`). Evidence applies to that SHA only: after a push,
remove and re-apply the label. "Re-run" replays the original SHA.

The work root is always `$RUNNER_TEMP/mcsbx`; no caller-chosen path is
accepted, because teardown removes it recursively. Every script that runs as
root refuses unless `MC_SANDBOX_HOST_DISPOSABLE=1`,
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
| containerd | dedicated instance from the containerd 2.3.6 static release (archive SHA-256 pinned; the runner image's containerd varies and is not used), its own shim first on PATH, root on the data filesystem, state and socket on the run root, CRI disabled, namespaces `mc-sandbox`/`mc-sandbox-plugins` | no shared containerd metadata, content or socket with the host's default engine |
| dockerd | dedicated instance on `<run>/docker/docker.sock` (0660 root:root), Docker 28.0.4, overlay2 classic store (containerd snapshotter off) | own data root, socket and containerd |
| Daemon defaults | default runtime `runsc`, `cgroup-parent` = lease slice, `overlay2.size` default, json-file logs `8m` x `2`, `no-new-privileges`, private cgroupns, no bridge, iptables/ip6tables/ip-forward/ip-masq off, no live-restore | a container started without explicit flags still lands in gVisor, the lease slice and a bounded writable layer |
| Runtime | gVisor `release-20261005.0` by archive SHA-256, registered as `runsc --systemd-cgroup --overlay2=none` | the overlay2 quota holds only with these arguments |
| `mcsbxlease.slice` | `CPUQuota=200%`, `MemoryMax=1G`, `MemorySwapMax=0`, `TasksMax=1024` | aggregate lease CPU, memory, swap and host task budget |
| `mcsbxengine.slice` | containerd and dockerd units, finite memory and tasks, swap 0 | engine, shim and gofer overhead never borrows the lease budget and never runs unbounded |
| Engine egress | nft table `inet mcsbx_engine_egress`: sockets of the engine slice may reach the host resolver `127.0.0.53:53` and public unicast addresses only; every address of this host (`fib daddr type local`, both families, including a public address on an interface), loopback, this-network, RFC1918, CGNAT, link-local (metadata), benchmarking, multicast/reserved, IPv4-mapped, NAT64 (well-known and local-use), ULA and IPv6 link-local/multicast are rejected | `network=none` does not constrain the daemon's own pulls; Docker always treats loopback registries as plain-HTTP |

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
catalog `owner` says who implements the live check, exactly once: lane 2
(`pkg/sandboxhost`: `host.*`, `cgroup.*`, `storage.*`, `budget.*`,
`network.engine_egress_restricted`, `lease.runtime_processes_in_finite_cgroups`,
`lease.host_netns_lo_only_no_routes`); the backend (`engine.*` through its
Engine API client, and the sentry executable, cgroup and limit checks it
already performs). `lease.sandbox_interfaces_lo_only` and
`lease.engine_socket_absent` need a process in the guest and are lab-only. A live backend may start only when every
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

Per lease, created with the backend's flags (`runsc`, `network=none`, lease
cgroup parent, 1 CPU, 512 MiB with equal swap limit, 64 pids, 64 MiB writable
layer, logs 1m x 2, `CapDrop ALL` with no `CapAdd`, `no-new-privileges`, ipc
private, no restart) and the image's own user (root) and default command, as
`pkg/sandboxbackend` does: the engine recorded settings;
the container PID executes the pinned sentry; its actual cgroup is a child
of the lease slice with exactly the lease's `cpu.max`, `memory.max`,
`memory.swap.max` and `pids.max`; every gVisor and shim process of the
instance is in the lease or engine slice; the sentry's host-side network
namespace has only `lo` and no route off it; the guest sees only `lo` and no
engine socket.

`pkg/sandboxhost`, built from the checked-out source, then runs on the same
host (`conformance.go_observer_matches`) and must pass every check it owns,
so the live Go implementation, not only this script, is proven against a
real kernel.

Effects: the dedicated daemon's own pulls from `127.0.0.1`, the host's
primary address, `169.254.169.254` and a non-private address local to this
host (a dummy interface carrying `203.0.113.77` and `2001:db8::77`, which no
fixed prefix covers), and engine-slice sockets to those local addresses in
both families, never connect (listeners see only caller-side controls; the
reject and fib-local counters rise) while the pinned
`docker.io` pull succeeds. The data filesystem cannot be `nodev` (Docker's
overlay2 quota control opens a device node it creates there), so device
nodes in image layers become real host device files: an image layer with
`/dev/mem`, `/dev/kmsg`, `/dev/null` and the data filesystem's own block
device must stay unusable from the guest, as root and nonroot
(`effect.image_device_nodes_inert`). IPv4 metadata, IPv4 and IPv6 public TCP fail with exactly the
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
- Image cache reservation, registry hostname allowlisting (the engine may
  still reach any public unicast address:
  `network.engine_pull_egress_public_unrestricted`), `public` and
  `allowlist` sandbox egress, secret delivery, exec and file transfer.
- Effects for the backend's own `Create`: conformance uses the backend's
  flags, but a joint job running `pkg/sandboxbackend` on this host is still
  needed to prove the backend issues them.
- Host root processes other than the engine can open device nodes stored
  under the data root (it is not `nodev`); only the guest side is proven.
- containerd shim sockets in the host-wide `/run/containerd/s`
  directory (`storage.shim_socket_dir_shared`).
- Startup recovery and orphan reconciliation of a real backend, and any
  live miner path. No activation may be inferred from a green job.

## Engine egress readback (INT-27-07)

`network.engine_egress_restricted` parses `nft -j list table inet
mcsbx_engine_egress` structurally and accepts exactly the provisioned table:
one output filter chain with policy accept and four rules, in order, each
starting with the engine slice's `socket cgroupv2` match by name, namely the
resolver accept, the `fib daddr type local` reject, and the IPv4 and IPv6
prefix-set rejects. Any other table object, rule, statement, qualifier,
operator, verdict or comment fails, and the sets must contain every denied
prefix. nft 1.0.9 omits the cgroupv2 level from JSON, so the `nft -a` text
listing confirms `level 1` on all four rules; it may contain nothing but the
table and chain framing and those four rules, and their handles must equal
the JSON rule handles in order, which binds the two listings to the same
rules.

`scripts/sandbox-host/gen-egress-fixtures.py` renders the table from
`provision-disposable.sh`, derives the unsafe variants (lane 8's P1-P8,
level 2, missing prefixes, an extra chain, a fifth rule after the rejects, a
nat output chain, a rule comment, a named counter, policy drop and a dormant
table; nft 1.0.9 truncates the JSON listing of a dormant table, which the
parser refuses, so unit tests also exercise each dormant guard alone), loads each into a throwaway
network namespace with the real nft and records its JSON and text listings
under `pkg/sandboxhost/testdata/egress`. Unit tests read the recordings, and
a Python test fails if the recorded provisioned form drifts from the script.
Conformance (`effect.egress_readback_refuses_unsafe_tables`) loads the same
variants into a scratch table on the disposable host and requires the built
observer to refuse every unsafe one and to pass the provisioned form.

The IPv6 host-address probe now requires the engine-slice curl to exit 7
(connect failed) with the fib-local counter rising for that attempt alone,
after a positive control from the same slice connects to a permitted public
endpoint (SR-27-12).

These are lab proofs of the readback. They do not activate anything; a live
host must still pass its own preflight.

## Backend on this host (DEP-3)

`.github/workflows/sandbox-backend-host-proof.yml` (label
`run-sandbox-backend-gate`) provisions this host from the PR head, checks the
host with `pkg/sandboxhost`, and runs the backend's own env-gated
`TestGVisorLaneOnDisposableHost` from a pinned, reviewed source SHA
(`BACKEND_SHA`) with every `MC_SANDBOX_*` value derived from the emitted
profile. A skipped test fails the job. While the test runs,
`scripts/sandbox-host/observe-backend-instances.py` independently records
every live sandbox the backend creates (engine settings, sentry executable
and cgroup, cgroup limit files including exact `cpu.max`,
`pkg/sandboxhost.ObserveInstance` and the XFS project quota) and the job
requires them to match the lease; a sandbox whose sentry disappears during
observation is reported as disappeared with its engine state, never as a
mismatch. `scripts/sandbox-host/probe-command-failures.py` then records,
without interpreting any text, what the engine and runsc report for a
missing command, a non-executable command, a wrong-architecture ELF and a
command that runs and exits: the create/start response, `State` (`Error`,
`Pid`, `ExitCode`, `StartedAt`, `FinishedAt`), the gVisor processes and
their cgroups seen during creation, and what remains before and after
removal. It proves the backend's preflight,
create, idempotent replay, release-after-destroy and restart recovery on this
host for those two SHAs only; it does not wire `--sandbox-leases on`.
