# Disposable gVisor technical gate

This is a **manual, hosted-runner experiment**, not a `SandboxBackend` and not
permission to enable `sandbox-lease-v1`. A maintainer applies the
`run-gvisor-gate` label to a same-repository pull request. The workflow checks
out that PR's exact head SHA on GitHub-hosted `ubuntu-24.04`, with a read-only
token and no secrets. A new workflow cannot be dispatched from a PR branch
before it exists on the default branch, so the label is the pre-merge trigger.
Evidence applies only to the checkout SHA printed in that run's log. A later
push does not rerun the gate, and "Re-run" replays the original event and
therefore the original SHA; after any push, remove and re-apply the label.

The gate downloads gVisor `release-20261005.0` by an embedded SHA-256 archive
pin and pulls the linux/amd64 BusyBox manifest by digest. BusyBox is the only
container image executed. The workflow pins XFS tooling to Ubuntu's
`xfsprogs=6.6.0-1ubuntu2.1` and refuses a Docker client or daemon other than
`28.0.4`; runner image, kernel and systemd versions are recorded in the job.
It creates a disposable 3 GiB XFS loop filesystem
with project quota and a separate Docker daemon whose data root is on that
filesystem. The daemon has no bridge, forwarding, or IPv4/IPv6 firewall
management, and the gate asserts it uses its own containerd container and
plugin namespaces; its exec-root and the runner's shared containerd state
remain on the disposable runner disk. The test creates a
dedicated finite systemd cgroup slice and one `runsc` container with
`network=none`, per-container CPU, memory and PID limits, a 64 MiB overlay2
writable-layer quota, and bounded JSON logs.

The proof checks the engine's runtime/image/config, the pinned runsc process's
actual cgroup, finite parent and child CPU, memory and PID limits, that the
sentry's host-side network namespace and the sandbox both have only a
loopback interface and no route off it (the primary network assertion,
observed from the host), that metadata and public TCP attempts fail with
exactly BusyBox's `can't connect to remote host (<addr>): Network is
unreachable` line (an HTTP error status, refusal or timeout counts as
reached; ENETUNREACH could also come from an upstream ICMP reply, so it only
corroborates the lo-only namespace), an actual write that
stops within 4 MiB of the quota with ENOSPC or EDQUOT, the matching full XFS
project limit, and that Docker logs actually rotated.
The long-lived probe process is nonroot; an administrator-controlled `exec`
as root writes at `/` specifically to exercise the rootfs layer. gVisor's
separate `/tmp` must report as tmpfs. It is outside the disk quota and, by
design, memory-backed; the gate checks the filesystem type but does not
measure that memory charge.

The quota result holds only for `runsc` registered with `--overlay2=none` and
`--systemd-cgroup`, as this script does. runsc's default rootfs overlay keeps
writable-layer bytes in sandbox-managed storage instead of Docker's overlay2
upper directory, so a backend using other runtime arguments must use these or
re-prove the quota.
It then removes the container and image and verifies they are absent. The
script cleans up its own daemon, unit, slice (with the implicit parent slices
systemd derives from its name), mount and loop device on success
or failure. Its refusal check (`MC_GVISOR_DISPOSABLE_RUNNER`, `GITHUB_ACTIONS`,
`RUNNER_ENVIRONMENT=github-hosted`, root) is an accident guard, not a security
boundary; never run the script on a self-hosted runner or miner host.
Missing XFS project quota, runtime registration, cgroup v2, actual limits,
network or disk failure attribution, log rotation or cleanup makes the job
fail.

**Disk boundary:** the 64 MiB proof covers the container's writable rootfs
layer only. The image/cache and rotated Docker logs are explicitly recorded
as outside the per-container quota. They reside on the finite 3 GiB test data
root, but this is not an enforceable per-lease or production aggregate disk
budget. A future backend must account for those bytes, image-defined volumes,
every writable mount and cleanup before `SandboxBackend.Budget` can truthfully
report `DiskMiB`. The gate does not prove cgroup mount authenticity on a
production host, public/allowlist egress, secret delivery, startup recovery,
or any live miner path.

The existing `TestDockerOCIRuntimeRunsVerifiedImageUnderSmallV1` covers the
organic runc runtime's separate image and deny-all-network contract. It does
not exercise runsc or storage quotas; this gate owns that real-engine proof.

The broader [sandbox-host conformance](sandbox-host-enforcement.md) adds a
dedicated containerd, per-lease and aggregate effect checks, and a
machine-readable report. This gate remains the narrow runsc/quota baseline.
