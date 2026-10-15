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

## Activation wiring

`miner-agent --sandbox-leases on` is wired but stays opt-in: the default is
`off`, and with `off` any `--sandbox-*` setting is refused. Wired is not
activated: no production host runs it, and the gates below remain.

With `on`, the agent needs three inputs and starts only if all of the
following hold:

- `--sandbox-host-profile`: the `sandbox-host-profile.v1` document the
  host's provisioner wrote (see [host enforcement](sandbox-host-enforcement.md)).
  Every backend value comes from it: socket, runtime and sentry pins, data
  roots, slice, cgroup root, aggregate disk, sandbox count, image and log
  limits, per-lease pids limit, and the Docker version pin, which must be
  this backend's `28.0.4`.
- `--sandbox-deployment-cgroup`: the cgroup v2 path deployment.v4 replicas
  run in. It must be a clean absolute path that exists under the profile's
  cgroup root. It and the agent's own cgroup must be disjoint from the
  sandbox and engine slices. That replicas actually run in it is not
  observed.
- `--sandbox-daemon-config`: the dedicated daemon's configuration file,
  evidence for the two `configured` engine checks.
- **The preflight report passes.** The backend's engine checks (below) and
  `pkg/sandboxhost`'s host checks are merged into one
  `sandbox-host-preflight.v1` report. That report is logged once, and must
  pass: every check `pass`, every `unenforced` entry `gap`.
- **The lane accepts its budget.** The lane is then built with the
  profile's aggregate as its budget and verifies it against the slice.
- **Restart recovery** gets its own 5-minute budget.

The lane's restart recovery uses the backend contract. Every lease whose
sandbox may exist answers `failed/miner_restart` and is destroyed. Every
other sandbox container on the daemon is destroyed as an orphan, and images
no container uses are pruned.

Gates that remain before any activation:
- AG-SHIM (another containerd on the host);
- D20 (the containerd root location has no lane 2 catalog id; the backend
  checks the provisioning layout `<data_root>/containerd`);
- PID-ATTR-1 and ACT-PID-1/2 (process-limit exits);
- INT-B-08 (lease-only runtime socket);
- the real-host proof through `Create` (DEP-3, the never-started probe
  images, and the D11 settle path);
- that the agent shares the dedicated daemon's PID and network namespaces;
- INT-26-13 and INT-34-03 (capacity above 1);
- FG-9.

## Engine checks (no host changes)

The backend records the catalog's lane 1 preflight ids. `Open` refuses a
host on which any of them fails; checks that need the profile layout or the
daemon configuration are skipped there.

- `engine.socket_dedicated`: the socket is not the default daemon's. With
  the profile, it lies under `run_root` with mode 0660 owned by root, and
  the default daemon's socket (if any) answers with another engine ID.
- `engine.version_pinned`: the server is Docker `28.0.4`, the version the
  [disposable gate](gvisor-disposable-gate.md) proved the quota on.
- `engine.data_root_on_data_fs`: `DockerRootDir` is the profile's
  `docker_data_root`, on the device of `data_root`.
- `engine.storage_overlay2_xfs`: `overlay2` on an XFS backing filesystem
  with d_type.
- `engine.cgroup_driver_systemd_v2`: `systemd` on cgroup v2.
- `engine.containerd_dedicated`: a containerd socket other than the host's
  shared or the daemon-managed default, with namespaces other than the
  default engine's. With the profile, these are the profile's, and the
  metadata store `<data_root>/containerd/io.containerd.metadata.v1.bolt/meta.db`
  is on the data device.
- `engine.network_management_off`: no network beyond `host` and `none`.
- `engine.firewall_management_off` (configured): the daemon configuration
  sets `iptables`, `ip6tables`, `ip-forward` and `ip-masq` false and
  `bridge` to `none`.
- `engine.runtime_runsc_pinned`:
  - runsc is registered at the pinned path, with arguments drawn only from
    `--overlay2=none`, `--systemd-cgroup`, `--platform=systrap` and
    `--platform=kvm`, and including the first two; with the profile, the
    arguments are exactly the profile's;
  - the runsc and sentry binaries match their SHA-256 pins, opened without
    following symlinks.
- `engine.default_bounded_logs` (configured): `LoggingDriver` is
  `json-file`, and the daemon configuration's default log options equal the
  profile's per-lease sizes.
- `engine.insecure_registries_empty`: no insecure registry beyond the
  loopback prefixes Docker always lists, no mirror, and Docker Hub as the
  only, secure index.
- `engine.no_unlabelled_containers`: no container without the sandbox label.

The cgroup, storage, budget, network-egress and kernel checks belong to
`pkg/sandboxhost`, and this backend has no second implementation of them.
The per-lease pids refusal uses the profile's `per_lease.pids_max`. The
checks run once at startup; a binary or daemon changed later is caught only
by the per-sandbox checks below.

Every `Create` decision is also recorded:
- **instance report:** a `sandbox instance report`, a
  `sandbox-host-preflight.v1` report in instance mode, is logged. It holds
  the backend's per-process checks (`not_run` when there was no process to
  read) and `pkg/sandboxhost`'s observation of the live process.
- **lane 2 observation on a live process:**
  - a failing observation is a miner fault;
  - a failing observation of a process that ended during it takes the D11
    path.
- **timing:** `sandbox create timing` records the pull's time and share,
  and the local steps' time and reserve.

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
CGNAT, ULA, unspecified and the rest of that list, and any registry host
that resolves to an address assigned to one of this host's interfaces
(contract D8 item 2b), read fresh before every pull; if this host's
addresses cannot be read, the pull is refused as a miner fault. The daemon
resolves the name again and follows registry redirects, so this check keeps
a signed reference from naming a host-local service but does not replace
host-level pull egress policy (`network.engine_egress_restricted`, which
also rejects fib-local destinations).

Limits of the host-address check: it sees the interfaces of the agent's own
network namespace, which must be the host's (the dedicated daemon's)
namespace; a public address the host answers on without holding it on an
interface (for example a cloud provider's 1:1 NAT address) and addresses
reachable only through local routes are not listed; and a registry that
resolves differently when the daemon resolves it again is caught only by
the host egress rule.

Image: pulled by its exact digest for `linux/amd64`, only while the data
root has the per-image limit free (otherwise a miner fault). The pull is
stopped once the compressed layer sizes the engine reports exceed the
per-image limit (`image_unavailable`). The engine must record the image under the lease's
repository (after Docker normalization) and digest. A wrong record is a
miner fault. The image must be `linux/amd64` and within the stored-size
limit (otherwise `image_unavailable`). It must declare no `VOLUME`, whose
bytes no quota counts (otherwise `resources_unsupported`). It must name a
command: an entrypoint or a command whose first argument is not empty, after
an entrypoint of `[""]` is cleared as the engine clears it (otherwise
`image_unavailable`, decided before the container is created, contract
D19). A refused image is removed. Every pull failure the engine reports is `image_unavailable`:
registry answers of any status, transport failures to the registry, a pull
that outlasts the create budget, and running out of space after the
headroom check passed, because the engine relays registry-chosen text and
only the headroom check is local evidence about the miner's disk. Once the
engine has answered the pull, every failure of its progress stream is
`image_unavailable` too (contract D15(c)): a line longer than the 1 MiB
reader bound (the registry chooses the length of the error text the engine
relays), a line that does not decode, a stream that breaks off, and one that
ends before the engine's final `Status:` line. An image such a pull may have
stored is removed. A daemon that gives no answer to the pull request (no
HTTP status) is a miner fault. No
registry credentials are supported.
For an index digest the engine records the index digest and the image
(config) ID it ran; the chosen platform manifest digest is not recorded.

Deadlines (contract D15(d)): the lane gives `Create` one create budget.
The registry phase (resolving the registry host and the pull) runs until
that budget's deadline minus a fixed local-step reserve of 2 minutes;
running past that pull deadline is `image_unavailable`. dockerd sends a
pull's response headers only with its first progress line, after the
registry-controlled ping, token and manifest steps, so the pull request
waits for them until the pull deadline; every other Engine API call keeps
its 2-minute answer timeout. The steps after a
pull (image inspection, container create, the start slot and start, the
engine and kernel readbacks, and the D23 re-inspection, 2 s settle and
removal) run under their own deadline of the full reserve, started fresh
when the pull returns, so however long the registry makes the pull last it
cannot shorten them; running past that local deadline is a miner fault. The
pull share plus the reserve never exceed the budget, and a budget no larger
than the reserve is refused as a miner fault before any engine call. An
explicit cancellation of the lane's context still stops the local steps.

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
`/proc/<pid>/cgroup` lies below the slice with `cpu.max`, `memory.max` and
`pids.max` equal to the lease and `memory.swap.max` zero. Anything else is a miner fault
and the lane destroys the container.

A workload that exits by itself after the engine started it (the engine
records no start error), with any exit code and including an OOM kill
within the lease limit, is not a miner fault (contract D11). This applies
only when the kernel readback found no process to read (the engine reported
none running, or its `/proc` or cgroup entries were gone); any value read
from the live process that differs from the lease stays a miner fault even
if the process exits afterwards. `Create` then succeeds only when the engine
configuration above matches, a fresh inspection shows the container exited
with no start error, no PID and an exit time after its start time, and no
process remains anywhere below the slice except in the cgroups of other
sandboxes: those the engine reports running, and those an earlier readback
found a sandbox's process in, until that sandbox's container is removed.
Sandboxes start and are verified one at a time, so no other sandbox is
starting while this check runs. The engine records the exit, and the runtime
tears the sandbox's processes down, after the process is gone, so the
inspection and the slice check are repeated every 50 ms for at most 2 s:
while the engine still reports the sandbox running, its process is read
again (a passing readback serves it as running; any value that differs from
the lease is a miner fault), a stop that is not a clean exit is a miner
fault at once, and no clean, quiet exit within 2 s is a miner fault. Each
such decision is logged as one `sandbox exit attribution` record. The
per-process checks are logged as `not_run`, the
exited container is never restarted, and it keeps its lease, writable layer
and logs until release or expiry.

The engine configuration above is read back on the created container before
the start request is sent; a container the engine did not configure as asked
is never started. When the engine answers the start request with an error
status, the failure is the image's (`image_unavailable`, contract D23) only
when all of these hold: a fresh inspection is answered and shows the same
container never started (not running, PID 0, no start time); its engine
configuration still matches; no process remains below the slice outside
other sandboxes' cgroups, no process anywhere on the host has the
engine-assigned container ID in its cgroup path, and no runsc or sentry
process (identified by the files Open hashed, not by name) has it in its
arguments; other programs' arguments, such as an operator's `docker logs`,
are not evidence. Both checks run every 50 ms for at most 2 s, because the
runtime tears a failed start down asynchronously; a process entry that
cannot be read is retried within that window and faults only if the scan
never completes. Then removing the never-started container and its image
succeeds. The decision reads no message text, exit code or exit time, and
inspects no image layers. Anything else, including a start request the daemon
gives no answer to, is a miner fault. Each such decision is logged as one
`sandbox start attribution` record with every input it used; the per-instance
report entry follows with the host-preflight package.

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
- **Host network of the sandbox process:** observed per sandbox by
  `pkg/sandboxhost` (`lease.host_netns_lo_only_no_routes`) when the backend
  is opened from a host profile; the container's recorded `NetworkMode=none`
  is checked either way.
- **Trust:** the miner operator controls the host; gVisor isolates the host
  from customer code, not customer code from the operator.

## Disposable-host proof

`TestEnginePullOversizedRegistryErrorOnDisposableHost` (same gate) has the
real daemon pull from a loopback registry that answers every blob request
with a 600 KiB error body, and requires an engine-answered classification.
It needs the daemon to reach a registry on 127.0.0.1 over HTTP.

`TestGVisorLaneOnDisposableHost` (skipped unless `MC_SANDBOX_BACKEND_IT=1`)
opens the backend against the real host, then drives the real lane with
signed documents: reserve, commit (real pull and gVisor container, verified
as above), idempotent re-create, release (acknowledged only after the
container is gone), a workload that exits by itself (`ready`, kept until its
release), commit again, and restart recovery (container destroyed, lease
`failed`). It needs a provisioned dedicated daemon, runsc registration,
slice and an XFS project-quota data root of at least 5.2 GiB, described by
`MC_SANDBOX_DOCKER_HOST`, `MC_SANDBOX_RUNTIME`, `MC_SANDBOX_RUNSC_PATH`,
`MC_SANDBOX_RUNSC_SHA256`, `MC_SANDBOX_SENTRY_PATH`,
`MC_SANDBOX_SENTRY_SHA256`, `MC_SANDBOX_DATA_ROOT`, `MC_SANDBOX_SLICE` and
`MC_SANDBOX_DEPLOYMENT_CGROUP`, and network access to `registry.k8s.io`. Run
it only on an explicitly disposable host, never on a miner, validator, CI
runner shared with production, or developer machine.
