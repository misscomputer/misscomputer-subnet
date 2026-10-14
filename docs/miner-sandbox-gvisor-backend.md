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

## Activation

Not wired yet. `miner-agent --sandbox-leases on` still refuses to start. The
agent will enable this backend only in a separate change, after the
host-preflight package for the dedicated daemon, slice and data root has
merged. Agent startup must then require every kernel, cgroup and filesystem
check, and every engine check below, to pass as an observed state. Until
then the backend runs only under `TestGVisorLaneOnDisposableHost`.

The lane's restart recovery already uses the backend contract. Every lease
whose sandbox may exist answers `failed/miner_restart` and is destroyed.
Every other sandbox container on the daemon is destroyed as an orphan, and
images no container uses are pruned.

## What Open verifies (no host changes)

- the socket is not the default daemon's, the server is Docker
  `28.0.4` (the version the [disposable gate](gvisor-disposable-gate.md)
  proved the quota on), its data root is the configured `DataRoot`, storage is
  `overlay2`, the cgroup driver is `systemd` on cgroup v2, and its containerd
  namespaces are not the default engine's;
- the runtime is registered at the pinned runsc path with arguments drawn
  only from `--overlay2=none`, `--systemd-cgroup`, `--platform=systrap`,
  `--platform=kvm`, and including the first two (the quota holds only with
  them); any other argument, such as host networking, is refused;
- runsc and sentry binaries match their SHA-256 pins (opened without
  following symlinks);
- the daemon trusts no insecure registry beyond the loopback prefixes Docker
  always lists, uses no mirror, and has Docker Hub as its only, secure index;
- the data root's filesystem holds at least `disk + count × (image max +
  log)` (the host-preflight check adds engine overhead and an image reserve);
- the slice directory is on cgroup v2 with a finite `pids.max`; the lane
  separately requires finite `cpu.max` and `memory.max` covering the budget,
  disjoint from the agent's and the deployment cgroup;
- the daemon runs no container without the sandbox label.

These checks run once at startup; a binary or daemon changed later is caught
only by the per-sandbox checks below. They do not yet require the data root
to be its own XFS project-quota filesystem or the slice to have swap
disabled; those are host-preflight checks, and activation waits for them.

## What one sandbox is

Refused before anything is pulled (non-fault receipt codes): isolation other
than `gvisor` (`isolation_unsupported`), network other than `none`
(`network_policy_unsupported`), more pids than the slice
(`resources_unsupported`), and, in the lane, any `secret_env`
(`secret_delivery_unsupported`).

Registry (`image_unavailable`, before any engine call): any IP literal, any
name that only resolves on the miner's own host or site (`localhost`,
single-label names, absolute names ending in `.`, and the `.localhost`,
`.local`, `.internal` and `.home.arpa` namespaces), and any registry host
(Docker Hub as `registry-1.docker.io`) that does not resolve, or that
resolves to any address in the `pkg/netpolicy` special-purpose prefixes: loopback, link-local and metadata, RFC 1918,
CGNAT, ULA, unspecified and the rest of that list. The daemon resolves the
name again and follows registry redirects, so this check keeps a signed
reference from naming a host-local service but does not replace host-level
pull egress policy.

Image: pulled by its exact digest for `linux/amd64`, only while the data
root has the per-image limit free (otherwise a miner fault). The pull is
stopped once the compressed layer sizes the engine reports exceed the
per-image limit (`image_unavailable`). The engine must record the image under the lease's
repository (after Docker normalization) and digest. A wrong record is a
miner fault. The image must be `linux/amd64` and within the stored-size
limit (otherwise `image_unavailable`). It must declare no `VOLUME`, whose
bytes no quota counts (otherwise `resources_unsupported`). A refused image
is removed. Every pull failure the engine reports is `image_unavailable`:
registry answers of any status, transport failures to the registry, a pull
that outlasts the create budget, and running out of space after the
headroom check passed, because the engine relays registry-chosen text and
only the headroom check is local evidence about the miner's disk. A daemon
that does not answer or breaks its progress stream is a miner fault. No
registry credentials are supported.
For an index digest the engine records the index digest and the image
(config) ID it ran; the chosen platform manifest digest is not recorded.

Container: created from the verified engine image ID with runtime runsc,
`NetworkMode=none`, cgroup parent the slice, the lease's CPU, memory (swap
equal, so none), pids and writable-layer quota (`StorageOpt size`),
`json-file` logs of two files within the per-sandbox log allowance,
`CapDrop ALL` with no capability added (any addition needs a security review),
`no-new-privileges`, private IPC, PID, UTS, user and cgroup namespaces,
`Init` explicitly false (so no daemon default init is added and the image's
own process is PID 1), no published ports, mounts, devices, privileges or
restart policy, and labels
binding it to the lease ID, lease digest and image. The image's own
entrypoint, command and default user run unchanged; that user may be root
inside the gVisor sentry but holds no capabilities.

`Create` reports success only after inspecting the container (runtime,
namespaces, ports, cgroup parent, every limit, logs, capabilities, mounts,
image ID, and no init process, sysctls, tmpfs, runtime annotations, device
rules or requests, volume sources, links, extra groups, hosts or DNS
settings) and the kernel's view of its process: `/proc/<pid>/exe` is the
pinned sentry (or runsc), the same file Open hashed, unchanged, and
`/proc/<pid>/cgroup` lies below the slice with `memory.max` and `pids.max`
equal to the lease, `memory.swap.max` zero and `cpu.max` no larger. Anything else is a miner fault
and the lane destroys the container.

A workload that exits by itself after the engine started it (the engine
records no start error), with any exit code and including an OOM kill
within the lease limit, is not a miner fault (contract D11). If it exits
before or during the kernel readback, `Create` succeeds once the engine
configuration above matches, the per-process checks are logged as
`not_run`, and the lease is served until release or expiry.

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
  stage, not process liveness. Lease v1 carries no command and the backend
  adds no init or keepalive process, so only images whose default command
  keeps running are useful.
- **Disk:** writable layers are quota-limited per container only on an
  XFS project-quota data root (the engine refuses `StorageOpt size`
  otherwise). Images and logs are bounded per sandbox and reserved on the
  data root, but a pull can transiently exceed its allowance before the
  compressed-size stop or the post-pull size check; it cannot outgrow the
  dedicated data-root filesystem. With more than one sandbox, such an
  overshoot can take space other sandboxes' writable layers were promised;
  the headroom check reserves the per-image limit only for the pull that
  makes it. gVisor's `/tmp` is memory-backed; whether
  its bytes are charged to the sandbox memory limit is not measured.
- **Exec, files, secrets, inbound access, GPUs, private registries:** not
  supported. With no capabilities, images that need root to change file
  ownership or switch users fail inside the sandbox.
- **Host network of the sandbox process:** not yet observed per sandbox. The
  container's recorded `NetworkMode=none` is checked; the observation that
  the sentry's host network namespace has only loopback and no routes
  belongs to the host-preflight package and is required before activation.
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
