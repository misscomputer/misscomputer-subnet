# Sandbox ops: backend helper-mount hardening (XA-09, XA-08)

Status: **draft, ops off by default, not a contract decision.** This note
records what the gVisor backend's ops mode (`pkg/sandboxbackend/ops.go`) can
request of the engine and prove by readback, why it now refuses to enable
ops mode, and which choices remain with the contract owner. The contract is
[`sandbox-ops-v1`](sandbox-ops-v1.md); the code map is
[the lane document](sandbox-ops-v1-lane.md).

## What the contract requires of the helper mount

The delivery requirement asks for one read-only, `nosuid`, `nodev`,
`rprivate` bind of a root-owned `0555` directory holding only the pinned
helper, at `/.misscomputer`, only in ops mode, with an engine readback that
equals exactly that mount.

## What the backend can request and prove

| Property | Requested | Proven by readback | Where |
| --- | --- | --- | --- |
| Pinned directory, only the helper, root-owned `0555` file with the pinned SHA-256, root-owned non-writable ancestors, no symlink | n/a (host) | host `lstat` of the ancestors; the directory opened `O_NOFOLLOW` and matched to the checked path; its entries read and the helper opened `O_NOFOLLOW` from that descriptor, then hashed; at enable and before every create | `verifyHelper` |
| No extended attribute on the helper directory or the helper file | n/a (host) | `flistxattr` of the opened directory and the opened helper answers size 0; any error, including a filesystem that cannot list attributes, refuses | `verifyHelper`, `noExtendedAttributes` |
| `/.misscomputer` absent from the image | n/a (image) | archive stat of a never-started, mount-free probe container answers 404 while the probe still exists | `imageConflict` |
| Exactly one bind of that directory at `/.misscomputer` | `HostConfig.Mounts` | `HostConfig.Mounts` and the container's `Mounts` | `helperMount`, `verifyHelperMount` |
| Read-only | `ReadOnly: true` | `RW: false` | same |
| `rprivate` | `BindOptions.Propagation` | `Propagation` | same |
| `nosuid` | **cannot be requested** | **not reported** | none |
| `nodev` | **cannot be requested** | **not reported** | none |
| Ops off: no mount at all | no `Mounts` member | no mounts | `verifyEngine` |

The readback booleans prove only what they name. `RW: false` says the
engine recorded a read-only bind; it says nothing about `nosuid` or `nodev`.

### Why `nosuid` and `nodev` cannot be requested or proven

Each point below was checked in source; the pinned engine and runtime
versions still need the lab observation below.

- **Engine API.** A `bind` mount's `BindOptions` has only `Propagation`,
  `NonRecursive`, `CreateMountpoint`, `ReadOnlyNonRecursive` and
  `ReadOnlyForceRecursive`. The legacy `Binds` mode string accepts no
  `nosuid` or `nodev` either. The inspect `MountPoint` reports `Type`,
  `Name`, `Source`, `Destination`, `Driver`, `Mode`, `RW` and
  `Propagation`, and no mount flags. Source: `api/types/mount/mount.go` and
  `api/types/container/container.go` of `github.com/docker/docker`
  v28.4.0. The pinned daemon is 28.0.4.
- **What dockerd hands the runtime.** For a bind or volume mount, the OCI
  options are `rbind` (or `bind`), then `rro` or `ro`, then the
  propagation. `nosuid` and `nodev` are copied from the source mount only
  under user-namespace remapping or a rootless daemon
  (`daemon/oci_linux.go`, v28.4.0). `rro` is used only when the runtime's
  OCI features list it (`daemon/daemon_linux.go`), and runsc's known mount
  options do not, so the runtime receives `rbind`, `ro`, `rprivate`. A
  `local`-driver volume with `o=bind,nosuid,nodev` would set the flags on
  the host mount only. It still reaches the runtime as the same bind.
- **What runsc applies.** gVisor `release-20261005.0`
  (`runsc/boot/vfs.go`, `ParseMountOptions`) turns `ro`, `noatime`,
  `noexec` and `nosuid` into sentry mount flags and logs any other option,
  including `nodev`, as unknown and ignores it. The sentry's flags come
  from the OCI options, not from the host mount, so host-side flags do not
  carry into the guest. Even a runtime spec that named `nodev` would not
  set it on this release.

### Fail-closed gate

`EnableOps` therefore refuses, after argument validation and before reading
the helper: "sandbox ops stay off: the contract requires a nosuid, nodev
helper mount, which the engine can neither request nor read back (XA-09)".
The miner agent's `--sandbox-ops on` path calls `EnableOps` and stops
startup on that error, so ops mode cannot run with a mount that does not
meet the contract. With ops off, nothing changes: the create body and the
readback stay byte-identical.

The gate is declarative (`helperMountRequired`, `helperMountProven`). It
can open only through a reviewed change that delivers and proves the
missing properties, or that implements a contract amendment that changes
the required set. It has no flag, configuration member or lab profile that
bypasses it.

The ops-mode create, readback and exec code stays. Its root-only tests set
ops mode with a verified pin, as an approved delivery will.

## What exists today besides the mount flags

These are facts for the contract owner. They are not offered as proof of
`nosuid` or `nodev`.

- No set-ID file and no device node can be in the mount. The pin requires
  the directory to hold exactly one regular file of mode exactly `0555`.
  It is checked at enable and before every create. The mount is
  read-only, so the guest cannot add entries.
- No extended attributes on the pinned files (G1, MSR-03). The pin
  refuses a helper directory or helper file whose attribute list is not
  empty, so a file capability (`security.capability`) or an ACL cannot
  ride on the pinned bytes. It is checked on the opened descriptors, at
  enable and before every create. A host whose security module labels
  files through extended attributes (for example SELinux) cannot hold a
  pinned helper; that refusal is intended. The source trace that runsc
  forwards the host's attribute list to the guest (directfs and lisafs)
  is not a guest observation, and this backend claims no equality of
  guest and host attributes.
- No set-ID elevation and no file-capability gain (MCR-01). Three
  controls apply, not one. (1) All five capability sets of the sandbox
  process are empty: `CapDrop: ALL` with no added capabilities
  (`sandboxCapabilities` is empty), which `verifyEngine` reads back.
  (2) `no-new-privileges`, also read back. (3) runsc's `allow-suid`
  stays at its default, false; the runtime-argument allowlist cannot
  set it. A `docker exec` process spec starts from the container's
  process spec, so the helper inherits (1) and (2) (`daemon/exec.go`,
  v28.4.0). A separately reviewed source trace of the exact exec chain
  found that (1) and (2) propagate through it to runsc exec, and the
  exact runtime-spec v1.2.1 JSON fields it relies on are checksum-bound.
  That closes only the field-tag inference; it is a source trace, not a
  guest observation. Adding any capability to `sandboxCapabilities`
  removes control (1) and needs a new review of this list.
- The helper does not start with an empty environment. dockerd merges
  the image's `Env` into every exec (MCR-OBS-1), and the helper starts
  with that inherited environment. It re-executes itself with an empty
  environment after the Go runtime has started
  (`cmd/sandbox-ops-helper`). Those variables reach only the tenant's
  own helper instance.
- No host device passthrough. runsc is registered only with the allowed
  runtime arguments (`--overlay2=none`, `--systemd-cgroup`, a platform).
  The engine checks refuse every other argument, so no device or
  host-file passthrough flag can be configured. The default character
  device policy must still be observed in the lab.

## Identity of the runtime chain (P6: pending gate, not implemented)

Today the backend pins only the runsc binary (and the sentry, when
configured) by the SHA-256 of the file at its configured path when it
opens, and then identifies the sandbox process by that file's identity.
The rest of the chain that turns a stored container spec into a runsc
exec is not bound by identity (MCR-02, MSR-02). dockerd and containerd
are checked by version string only, and the provisioned dockerd has no
digest pin. Before any enablement, an evidence record reviewed separately
must bind, in distinct fields: the running-executable identity of
dockerd, containerd, the containerd shim and the sentry; and the pathname
and exact bytes of the runtime wrapper script dockerd writes, the shell
it resolves to, and the short-lived runsc exec. A pathname hash is not
the identity of the executable that runs. No signature is verified, no
release binary is reproduced, and no check closes a privileged host's
change between check and use. This lane implements none of it, and it
gives no defence against a dishonest root on the host.

## Future checks (pending gates, not implemented)

None of these exists in code. Each is a gate that a separately reviewed
change must add before ops can be enabled:

- Runtime features (MCR-03, R23-H-03). Decode the runsc features that
  dockerd caches (`/info`, runtime status) and refuse ops if they list
  `rro` while the reviewed runsc parser does not apply it. Record the
  features JSON in the evidence record. A features entry is never proof
  of enforcement.
- Bundle options (R23-H-03). In the lab, the OCI bundle's options for
  `/.misscomputer` must contain `ro`, and the guest must see
  `ST_RDONLY`; repeat on every engine or runtime re-pin.
- Host read-only (MCR-04). With today's `ro`, the reviewed source trace
  shows the sentry, the gofer and the host gofer mount all apply
  read-only layers. Losing read-only through a future `rro` is
  hypothetical, not a demonstrated bypass. As defence in depth, keep the
  helper directory on a read-only host mount and have the pin require
  `statfs` `ST_RDONLY` on it.
- Host-mount and runtime-identity changes (P6) depend on the exec-chain
  record above and are out of this lane's scope.

## Architecture alternatives (decision required, not taken here)

1. **Contract amendment (recommended for review).** Replace `nosuid` and
   `nodev` with properties this backend proves: the pinned single-file
   `0555` directory, a read-only `rprivate` bind read back exactly,
   `no-new-privileges` and no capabilities read back, and no device
   passthrough on the runtime registration. Add a D5-P9 guest
   observation of the sentry's mount table for `/.misscomputer`, bound to
   the pinned runsc and Docker versions. The gate's `helperMountRequired`
   then changes in the same reviewed change. This is the smallest change.
   It is a contract decision and must not be made by relabelling.
2. **Runtime-spec delivery of `nosuid`.** Register a wrapper instead of
   runsc that adds `nosuid` to the `/.misscomputer` mount in `config.json`.
   This breaks the pinned runtime registration and process-identity
   checks, adds a privileged component that needs its own review, and still
   cannot deliver `nodev` on the pinned release. Not recommended.
3. **User-namespace remapping or a rootless daemon.** dockerd would then
   copy a `nosuid,nodev` source mount's flags into the OCI options. This
   changes the uid model of every sandbox, conflicts with the engine
   readback (`UsernsMode` must be empty) and the qualified quota gate, and
   the pinned runsc still ignores `nodev`. Not recommended.
4. **Upstream runtime change.** A gVisor release that honours `nodev`,
   combined with alternative 2 or a Docker change. Long lead time, and it
   needs a new runtime pin and new gate evidence.

## Image-controlled mount target (B-11, DEC-06 input)

### Pre-create probe (D1)

In ops mode, after the image is verified and the helper pin re-checked,
and before the sandbox is created, `imageConflict` creates a container of
the verified image ID named `<instance>-image-probe`. It uses the
sandbox's own create body without the helper mount, so the probe has no
mount. It is never started and never execs anything. The probe asks the
engine's archive stat for `/.misscomputer`. That stat uses `lstat`, so a
final symlink is reported, not followed. With no mount in the probe it
sees the image's own layers (dockerd binds a container's mounts into the
view it stats). An image that declares any `VOLUME` is already refused as
`resources_unsupported` before this point.

| Engine answer | Decision |
| --- | --- |
| stat 404, and the same probe still exists and never started | absent: the probe is removed, then the sandbox is created |
| stat 2xx: any entry (symlink, directory, file, FIFO, anything) | `image_unavailable`, not the miner's fault |
| stat answered with another error, and the probe never started | `image_unavailable`; the engine may fail to stat layers it cannot mount, which would also fail the start (D23) |
| stat 404 but the probe vanished, was started, or cannot be inspected | miner fault |
| stat or probe create not answered; probe create refused; probe created without an ID | miner fault, as for the sandbox create itself |
| probe create 404 (image gone) | the caller pulls again, as for the sandbox create |
| probe create 409 | an earlier probe was left behind: it is removed and the probe created again |
| any probe that cannot be removed | miner fault, even when a conflict was found (the D23 cleanup rule) |

The probe is removed with its anonymous volumes (`force=1&v=1`), and the
removal waits until the engine no longer reports it. Removal runs even
after the caller's context is cancelled, bounded by the two-minute
removal timeout. A probe whose create went unanswered is removed by
name. A probe that cannot be removed is named, by ID and name, in the
error. The probe carries the sandbox and lease labels under the name
`<instance>-image-probe` (`miner.SandboxProbeSuffix`). The lane's orphan sweep
recognises it by that name and its lease label. It holds the lease lock while
it decides, and the Create that makes the probe holds the same lock, so the
sweep never destroys the probe of a create in progress (R23-COMP-04). A probe
left behind by a lease whose lock is free is destroyed.
There is no per-image cache: every ops-mode create probes.

`image_unavailable` is an existing non-attributed code. It already means
an image that cannot run as a lease (contract D19, D23). Using it here is
this lane's reasoned recommendation, following the user decision that a
customer's image must not penalize an honest miner. It is not an adopted
DEC-06 mapping; the contract owner decides. The receipt vocabulary and
the attribution table are unchanged.

What the probe does not prove: how the pinned dockerd 28.0.4 answers
(404 for a missing path, `lstat` semantics, a created container's rootfs
view). That needs the lab cases: absent, directory, file, FIFO,
symlink to a directory, and symlink to a file. Nothing stops a privileged
host process from changing the image between the probe and the create.
The probe also does not replace the canonicalised command and working
directory checks of DR-06 (S1), which remain open.

### Where a conflict surfaced before D1

Without the probe (and still, for an image the probe cannot see):

- The engine create succeeds; the destination is not examined then.
- The sentry creates or follows `/.misscomputer` when the container
  starts. It follows a final symlink (`FollowFinalSymlink`, gVisor
  `release-20261005.0`), resolving inside the container root.
- A destination that cannot become a mount point, such as a regular file,
  fails the start request. `startRefused` (contract D23) answers
  `image_unavailable` only when a fresh inspection shows the workload never
  started, the engine configuration still matches, no process of the
  instance remains, and the container is removed. Any other outcome is a
  miner fault, which the lane answers as `runtime_start_failed`.
- A symlink that resolves inside the root, such as to `/usr/bin`, does not
  fail the start. The helper is mounted at the resolved path, and
  `/.misscomputer/sandbox-ops-helper` resolves through the same link.
  Whether that is the pinned binary must be checked by hashing it in the
  guest (D5-P9). A link to `..` or `/proc/self/root` may mount the helper
  over the root and stop the entrypoint from resolving. That outcome is
  unobserved.
- The engine archive stat on the container cannot detect the image's own
  entry before start: dockerd binds the container's mounts, including the
  helper, into the view it stats (`daemon/containerfs_linux.go`). That is
  why D1 stats a separate container of the same image without mounts,
  created and removed before the real one.

The final code and detection point remain decisions for the contract
lane. This note changes neither the receipt vocabulary nor the attribution.

## Test coverage (XA-08)

| Test | Needs | Proves |
| --- | --- | --- |
| `TestEnableOpsFailsClosedWhileTheHelperMountIsUnproven` | nothing | the gate refuses before reading the helper |
| `TestHelperMountReadbackIsExactlyThePinnedMount` | nothing | the readback refuses every mount but the pinned one |
| `TestDemuxBoundsAndFraming` | nothing | exec stream bounds and framing |
| `TestImageProbeDecidesOnEveryEngineAnswerAndRemovesTheProbe` | nothing (in-process engine transport) | every D1 decision and the probe's removal, also after cancellation |
| `TestOpsHelperPinRefusesExtendedAttributes` | root, qualifying `TMPDIR` with user extended attributes | the pin refuses an attribute on the directory or the helper |
| `TestOpsCreateProbesTheHelperTargetBeforeCreating` | root, qualifying `TMPDIR` (in-process engine transport) | `Create` probes before the sandbox create in ops mode only, and refuses every entry type |
| `TestOpsModeMountsOnlyThePinnedHelperDirectory` | root, qualifying `TMPDIR`, unix-socket fake engine | create body and readback wiring through `Create` |
| `TestOpsHelperPinRefusesAnythingButThePinnedBinary` | same | the host pin |
| `TestRunHelperExecsTheFixedHelperAndClassifiesFailures` | same | exec request, bounds and attribution |

Every test that needs root skips unless it runs as root with a
root-owned, non-writable `TMPDIR`. The three that also need the
unix-socket fake engine have no hosted-CI proof yet.

Composed-candidate author run (uid 0, root-owned scratch `TMPDIR`; the
root-gated tests were not skipped): `TestEnableOpsFailsClosedWhileTheHelperMountIsUnproven`,
`TestHelperMountReadbackIsExactlyThePinnedMount`, `TestDemuxBoundsAndFraming`,
`TestOpsHelperPinRefusesExtendedAttributes`,
`TestOpsCreateProbesTheHelperTargetBeforeCreating` (which now also asserts
the probe's lease and sandbox labels) and
`TestImageProbeDecidesOnEveryEngineAnswerAndRemovesTheProbe` passed. The
three unix-socket tests above were not run, because the author lane executes
no listeners. Nothing here is a privileged backend proof. Running them, and
the real-engine probes, belongs to the isolated lab. A CI job that runs
them as root, or treats their skip as a failure, is a workflow change
outside this note. The in-process engine tests prove the backend's own
decisions on scripted engine answers, not Docker's behaviour. No test
sets `security.capability` or proves a guest view.
