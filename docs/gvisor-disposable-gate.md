# Disposable gVisor technical gate

This is a **manual, hosted-runner experiment**, not a `SandboxBackend` and not
permission to enable `sandbox-lease-v1`. A maintainer applies the
`run-gvisor-gate` label to a same-repository pull request. The workflow checks
out that PR's exact head SHA on GitHub-hosted `ubuntu-24.04`, with a read-only
token and no secrets. A new workflow cannot be dispatched from a PR branch
before it exists on the default branch, so the label is the pre-merge trigger.

The gate downloads gVisor `release-20261005.0` by an embedded SHA-256 archive
pin and pulls the linux/amd64 BusyBox manifest by digest. BusyBox is the only
container image executed. The workflow pins XFS tooling to Ubuntu's
`xfsprogs=6.6.0-1ubuntu2.1` and refuses a Docker client or daemon other than
`28.0.4`; runner image, kernel and systemd versions are recorded in the job.
It creates a disposable 3 GiB XFS loop filesystem
with project quota and a separate Docker daemon whose data root is on that
filesystem. The daemon has no bridge or forwarding. The test creates a
dedicated finite systemd cgroup slice and one `runsc` container with
`network=none`, per-container CPU, memory and PID limits, a 64 MiB overlay2
writable-layer quota, and bounded JSON logs.

The proof checks the engine's runtime/image/config, the pinned runsc process's
actual cgroup, finite parent and child limits, failed metadata/public TCP
attempts, and an actual write that stops at the quota with ENOSPC or EDQUOT.
It then removes the container and image and verifies they are absent. The
script cleans up its own daemon, unit, mount and loop device on success or
failure. Missing XFS project quota, runtime registration, cgroup v2, actual
limits, disk failure attribution or cleanup makes the job fail.

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
