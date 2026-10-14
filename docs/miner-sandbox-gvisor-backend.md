# gVisor sandbox backend (`pkg/sandboxbackend`)

Status: **implemented, off by default, not proven on a live miner, not
customer-ready.** This is the first `SandboxBackend` for
[`sandbox-lease-v1`](sandbox-lease-v1.md). It runs each sandbox as one
container under a pinned gVisor (`runsc`) runtime on a Docker daemon that is
dedicated to sandboxes. Unit tests drive it against a scripted Engine API and
scripted procfs/cgroupfs; they prove the backend's decisions, not that Docker
or gVisor enforce them. `TestGVisorLaneOnDisposableHost` drives the real lane
through the real backend and must run only on a disposable provisioned host
(see [Disposable-host proof](#disposable-host-proof)). Host provisioning is
not part of this package.

## Enabling it

`miner-agent --sandbox-leases on` requires every `--sandbox-*` setting:

| Flag | Meaning |
| --- | --- |
| `--sandbox-docker-host` | `unix://<socket>` of the dedicated daemon; the default `/var/run/docker.sock` / `/run/docker.sock` (after symlinks) is refused |
| `--sandbox-runtime` | name the daemon registers runsc under (`runc` is refused) |
| `--sandbox-runsc-path`, `--sandbox-runsc-sha256` | pinned runsc binary |
| `--sandbox-sentry-path`, `--sandbox-sentry-sha256` | pinned sentry binary, for runsc releases whose sandbox process is a separate sentry (as `release-20261005.0`) |
| `--sandbox-data-root` | the daemon's data root, on a filesystem dedicated to it |
| `--sandbox-slice` | systemd slice with finite `cpu.max`, `memory.max` and `pids.max` that every sandbox runs in |
| `--sandbox-deployment-cgroup` | cgroup v2 path of `deployment.v4` replicas, which the slice must not overlap |
| `--sandbox-cpu-millis`, `--sandbox-memory-mib`, `--sandbox-disk-mib`, `--sandbox-count` | the lane budget: holds are checked against it and receipts report it |
| `--sandbox-image-max-mib`, `--sandbox-log-mib` | per-sandbox image and container-log allowance |

With `--sandbox-leases off` (the default) any `--sandbox-*` setting is
refused, so a configured backend is never silently unused; without settings
the agent is unchanged. The agent's own cgroup is read from
`/proc/self/cgroup`, not configured. Any preflight failure stops the agent.

Before serving, the agent runs restart recovery: every lease whose sandbox
may exist answers `failed/miner_restart` and is destroyed, every other
sandbox container on the daemon is destroyed as an orphan, and images no
container uses are pruned.

## What Open verifies (no host changes)

- the socket is not the default daemon's, the server is Docker
  `28.0.4` (the version the [disposable gate](gvisor-disposable-gate.md)
  proved the quota on), its data root is `--sandbox-data-root`, storage is
  `overlay2`, the cgroup driver is `systemd` on cgroup v2, and its containerd
  namespaces are not the default engine's;
- the runtime is registered at the pinned runsc path with arguments drawn
  only from `--overlay2=none`, `--systemd-cgroup`, `--platform=systrap`,
  `--platform=kvm`, and including the first two (the quota holds only with
  them); any other argument, such as host networking, is refused;
- runsc and sentry binaries match their SHA-256 pins (opened without
  following symlinks);
- the data root's filesystem holds at least `disk + count × (image max +
  log)`;
- the slice directory is on cgroup v2 with a finite `pids.max`; the lane
  separately requires finite `cpu.max` and `memory.max` covering the budget,
  disjoint from the agent's and the deployment cgroup;
- the daemon runs no container without the sandbox label.

These checks run once at startup; a binary or daemon changed later is caught
only by the per-sandbox checks below.

## What one sandbox is

Refused before anything is pulled (non-fault receipt codes): isolation other
than `gvisor` (`isolation_unsupported`), network other than `none`
(`network_policy_unsupported`), more pids than the slice
(`resources_unsupported`), and, in the lane, any `secret_env`
(`secret_delivery_unsupported`).

Image: pulled by its exact digest for `linux/amd64`. The pull is stopped once
the compressed layer sizes the engine reports exceed `--sandbox-image-max-mib`
(`resources_unsupported`). The engine must record the image under the lease's
repository (after Docker normalization) and digest, for `linux/amd64`, with no
image-defined `VOLUME` (whose bytes no quota counts) and a stored size within
the limit; otherwise the image is removed. Registry not-found or
unauthorized is `image_unavailable`; any other pull failure is a miner fault.
No registry credentials are supported.

Container: created from the verified engine image ID with runtime runsc,
`NetworkMode=none`, cgroup parent the slice, the lease's CPU, memory (swap
equal, so none), pids and writable-layer quota (`StorageOpt size`),
`json-file` logs of two files within `--sandbox-log-mib`, `CapDrop ALL` plus
`CHOWN DAC_OVERRIDE FOWNER FSETID KILL SETGID SETUID`, `no-new-privileges`,
private IPC, no mounts, devices, privileges or restart policy, and labels
binding it to the lease ID, lease digest and image. The image's own
entrypoint and command run unchanged.

`Create` reports success only after inspecting the running container
(runtime, network, cgroup parent, every limit, logs, capabilities, mounts,
image ID) and the kernel's view of its process: `/proc/<pid>/exe` is the
pinned sentry (or runsc) and `/proc/<pid>/cgroup` lies below the slice with
`memory.max` and `pids.max` equal to the lease and `cpu.max` no larger.
Anything else is a miner fault and the lane destroys the container.

`Create` is idempotent per instance name: a container already made for the
same lease document is started if needed and verified again; one made for
any other document is never adopted. `Destroy` removes the container and its
anonymous volumes, waits until it is gone, then removes its image if no other
container uses it; a missing container is success.

## Known limits

- **Network:** only `none`. `public` and `allowlist` are refused, not
  weakened.
- **Liveness:** a sandbox whose own command exits (or that is OOM-killed)
  stays leased until expiry or release; receipts report the durable lease
  stage, not process liveness. An image whose command exits before the
  post-start check fails `Create` as `runtime_start_failed`, which the
  current contract attributes to the miner. Entrypoint/keepalive semantics
  must be fixed in the shared contract (and are required by any exec/files
  extension) before customer images can be relied on.
- **Disk:** writable layers are quota-limited per container only on an
  XFS project-quota data root (the engine refuses `StorageOpt size`
  otherwise). Images and logs are bounded per sandbox and reserved on the
  data root, but a pull can transiently exceed its allowance before the
  compressed-size stop or the post-pull size check; it cannot outgrow the
  dedicated data-root filesystem. gVisor's `/tmp` is memory-backed; whether
  its bytes are charged to the sandbox memory limit is not measured.
- **Exec, files, secrets, inbound access, GPUs, private registries:** not
  supported.
- **Trust:** the miner operator controls the host; gVisor isolates the host
  from customer code, not customer code from the operator.

## Disposable-host proof

`TestGVisorLaneOnDisposableHost` (skipped unless `MC_SANDBOX_BACKEND_IT=1`)
opens the backend against the real host, then drives the real lane with
signed documents: reserve, commit (real pull and gVisor container, verified
as above), idempotent re-create, release (acknowledged only after the
container is gone), commit again, and restart recovery (container destroyed,
lease `failed`). It needs a provisioned dedicated daemon, runsc registration,
slice and an XFS project-quota data root of at least 5.2 GiB, described by
`MC_SANDBOX_DOCKER_HOST`, `MC_SANDBOX_RUNTIME`, `MC_SANDBOX_RUNSC_PATH`,
`MC_SANDBOX_RUNSC_SHA256`, `MC_SANDBOX_SENTRY_PATH`,
`MC_SANDBOX_SENTRY_SHA256`, `MC_SANDBOX_DATA_ROOT`, `MC_SANDBOX_SLICE` and
`MC_SANDBOX_DEPLOYMENT_CGROUP`, and network access to `registry.k8s.io`. Run
it only on an explicitly disposable host, never on a miner, validator, CI
runner shared with production, or developer machine.
