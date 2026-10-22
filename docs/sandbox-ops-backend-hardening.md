# Sandbox ops: backend helper-mount hardening (XA-09, XA-08)

Status: **draft, ops off by default.** This note records what the gVisor
backend's ops mode (`pkg/sandboxbackend/ops.go`) can request of the engine
and prove by readback, the delivery amendment it implements (A1, adopted
conditionally), when it refuses to enable ops mode, and which checks
remain open. The contract is
[`sandbox-ops-v1`](sandbox-ops-v1.md); the code map is
[the lane document](sandbox-ops-v1-lane.md).

## What the contract requires of the helper mount

The delivery requirement, as amended by A1 (XA-09, adopted conditionally),
asks for one read-only, `rprivate` bind of a root-owned `0555` directory
holding only the pinned helper, on a read-only host mount, at
`/.misscomputer`, only in ops mode, with an engine readback that equals
exactly that mount. It replaces the `nosuid` and `nodev` mount flags of the
earlier text with properties this backend enforces or reads back on every
create, or, for the runtime registration, when the backend is opened and
when ops are enabled, and for the runtime's cached OCI features, when ops
are enabled ([below](#amendment-a1-properties-and-where-they-are-enforced)).

A1 rests on a guest observation (D5-P9) that does not exist yet: on the
pinned Docker 28.0.4 and runsc `release-20261005.0`, `/.misscomputer`
read-only and holding exactly the pinned helper, writes, `mknod` and
unmount refused there, and a set-ID binary run as a non-root user gaining
no privilege. It must be repeated on every engine or runtime re-pin. A1 is
adopted conditionally: this change merges, and ops mode is enabled on any
host, only after that observation passes on Docker 28.0.4 and runsc
`release-20261005.0` and is reviewed independently; MCR-04 lands in the
same change; and P6 and the other prerequisites close under their own
gates. Existing lab records are partial inputs only, not that observation.
Ops activation and advertisement stay separately gated (KB-1/KB-2,
fairness, per-host P6 evidence); nothing here activates or advertises ops.

## What the backend can request and prove

| Property | Requested | Proven by readback | Where |
| --- | --- | --- | --- |
| Pinned directory, only the helper, root-owned `0555` file with the pinned SHA-256, root-owned non-writable ancestors, no symlink | n/a (host) | host `lstat` of the ancestors; the directory opened `O_NOFOLLOW` and matched to the checked path; its entries read and the helper opened `O_NOFOLLOW` from that descriptor, then hashed; at enable and before every create | `verifyHelper` |
| No extended attribute on the helper directory or the helper file | n/a (host) | `flistxattr` of the opened directory and the opened helper answers size 0; any error, including a filesystem that cannot list attributes, refuses | `verifyHelper`, `noExtendedAttributes` |
| Helper directory and helper on a read-only host mount (MCR-04) | n/a (host) | `fstatfs` of the opened directory and the opened helper shows `ST_RDONLY`; any error refuses | `verifyHelper`, `readOnlyMount` |
| Runtime registered with reviewed arguments only, cached OCI features shown and without `rro` (MCR-03) | n/a (daemon) | one `/info` answer at enable | `verifyOpsRuntime`, `verifyRuntime` |
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

The gate is declarative (`helperMountRequired`, `helperMountProven`).
Before amendment A1 the required set named `nosuid` and `nodev`, and
`EnableOps` always refused: "sandbox ops stay off: the contract requires a
nosuid, nodev helper mount, which the engine can neither request nor read
back (XA-09)". This change implements A1: the required set is `ro` and
`rprivate`, which the backend requests and reads back. The gate still
refuses, after argument validation and before the daemon is asked
anything, whenever the required set names a property the backend does not
request and read back. `EnableOps` then refuses unless one fresh `/info`
answer shows the runtime registered with only the reviewed arguments and
its cached OCI features without `rro` (MCR-03), and unless the helper pin
holds, its read-only mount included (MCR-04). The miner agent's
`--sandbox-ops on` path calls `EnableOps` and stops startup on any of
these errors. With ops off, nothing changes: the create body and the
readback stay byte-identical.

The required set changes only through a reviewed change that delivers and
proves a property, or that implements a contract amendment, as this one
does for A1. Changing it changes it for every deployment. The gate has no
flag, configuration member or lab profile that bypasses it. While the
required set equals the proven set, the unproven-property refusal cannot
fire, and no test executes it; it is a static guard that acts only when a
later change adds a required property without its proof.

### Amendment A1 properties and where they are enforced

Each property A1 puts in place of `nosuid` and `nodev` is enforced or read
back in code; none is new except MCR-03 and MCR-04, and no earlier check is
weakened.

| A1 property | Enforced or read back | When |
| --- | --- | --- |
| Directory holds exactly one entry, the helper | `verifyHelper`: `Readdirnames` of the opened directory is exactly `sandbox-ops-helper` | enable and every create |
| Helper is a regular uid 0 file of mode exactly `0555`, opened without following a symlink | `verifyHelper`: `openat(O_NOFOLLOW)` from the directory descriptor, `fstat` | enable and every create |
| Directory is uid 0, mode exactly `0555`, opened without following a symlink and matched to the checked path | `verifyHelper` | enable and every create |
| No extended attribute on the directory or the helper | `verifyHelper`, `noExtendedAttributes` | enable and every create |
| Directory and helper on a read-only host mount (MCR-04, new) | `verifyHelper`, `readOnlyMount` (`fstatfs` `ST_RDONLY`) | enable and every create |
| Ancestors root-owned, not group- or other-writable | `verifyHelper` | enable and every create |
| Configured SHA-256 | `verifyHelper` | enable and every create |
| Readback: exactly one bind of the pinned directory at `/.misscomputer`, `RW: false`, `rprivate` | `verifyHelperMount` | every create |
| Readback: `CapDrop: [ALL]`, `CapAdd: []`, `no-new-privileges` | `verifyEngine` (`sandboxCapabilities` is empty) | every create |
| Runtime arguments within the reviewed allowlist (`--overlay2=none`, `--systemd-cgroup`, one platform): no set-ID, flag-override or passthrough argument | `verifyRuntime` | open (engine checks) and enable (`verifyOpsRuntime`) |
| Cached runtime OCI features shown and without `rro` (MCR-03, new) | `verifyOpsRuntime` | enable |
| Guest observation D5-P9 on the pinned Docker 28.0.4 and runsc `release-20261005.0`, repeated on every re-pin | none in code; lab evidence, not yet run | before this change merges and before ops are enabled on any host |

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

## Implemented checks (MCR-03 and MCR-04)

These two gates were listed here as future checks. This change adds them;
neither is guest evidence.

- Runtime features (MCR-03, R23-H-03). `EnableOps` reads `/info` once
  more and decodes the OCI features dockerd caches for the runtime
  (`Runtimes[<runtime>].status["org.opencontainers.runtime-spec.features"]`).
  It refuses ops if they list `rro`, which the reviewed runsc parser does
  not apply; if dockerd reports no features for the runtime; or if they do
  not decode. The same answer must show the runtime registered as the
  engine checks require. Source, moby `v28.0.4` (commit `6430e49a`), the
  pinned daemon's tag: dockerd runs `<runtime> features` once per runtime
  setup and caches the result (`daemon/runtime_unix.go:69-78`); `/info`
  marshals that cached struct into the member above, and sets the member
  only when the struct exists (`runtimeStatus`,
  `daemon/info_unix.go:509-524`); a read-only bind becomes `rro` instead
  of `ro` only when that struct exists and lists `rro`
  (`supportsRecursivelyReadOnly`, `daemon/daemon_linux.go:222-239`;
  `daemon/oci_linux.go:599-617`); the runtime `status` member is stripped
  below API 1.44 (`api/server/router/system/system_routes.go:93-97`), and
  the backend uses API 1.47. This is source at the tag; the running binary
  is assumed to correspond to it (P6). `github.com/docker/docker` v28.4.0
  has the same code. Refusing when dockerd reports no features is
  deliberately stricter than dockerd 28.0.4, which then hands the runtime
  `ro`: without the features, the options the runtime claims to parse are
  not shown. Limits: the check runs when ops are enabled, not before every
  create, so a daemon reloaded afterwards with another runtime registration
  or other features is not seen until the next start. A features entry is
  never proof of enforcement. The features JSON belongs in the evidence
  record. The pinned runsc `release-20261005.0` lists no `rro` among its
  mount options (`KnownMountOptions`, `runsc/specutils/fs.go` at that
  tag).
- Host read-only (MCR-04). The pin requires `fstatfs` `ST_RDONLY` on the
  opened helper directory and on the opened helper, so no path is
  resolved again. A file mounted over the helper from another mount is
  refused as well. `ST_RDONLY` is set for a read-only mount and for a
  read-only filesystem alike, so a read-only bind of the helper directory
  onto itself satisfies it. With today's `ro`, the reviewed source trace
  shows the sentry, the gofer and the host gofer mount all apply
  read-only layers. Losing read-only through a future `rro` is
  hypothetical, not a demonstrated bypass; this is defence in depth. The
  pin holds when it is checked; a privileged host process can remount
  afterwards, which is outside the trust model.

## Future checks (pending gates, not implemented)

None of these exists in code:

- Bundle options (R23-H-03). In the lab, the OCI bundle's options for
  `/.misscomputer` must contain `ro`, and the guest must see
  `ST_RDONLY`; repeat on every engine or runtime re-pin.
- Host-mount and runtime-identity changes (P6) depend on the exec-chain
  record above and are out of this lane's scope.

## Architecture alternatives (alternative 1 adopted, conditionally)

Alternative 1 is adopted as amendment A1, conditionally: this change
merges, and ops mode is enabled on any host, only after the D5-P9 guest
observation passes on the pinned Docker 28.0.4 and runsc
`release-20261005.0` and is reviewed independently; MCR-04 lands in the
same change; and the other prerequisites close under their own gates.
Alternatives 2 to 4 were not taken.

1. **Contract amendment (adopted as A1, conditionally).** Replace `nosuid`
   and `nodev` with properties this backend proves: the pinned single-file
   `0555` directory without extended attributes on a read-only host mount,
   a read-only `rprivate` bind read back exactly, `no-new-privileges` and
   no capabilities read back, and only reviewed runtime arguments, so no
   set-ID, flag-override or passthrough argument. Add a D5-P9 guest
   observation of `/.misscomputer`, bound to the pinned runsc and Docker
   versions and repeated on every re-pin. The gate's `helperMountRequired`
   changes in the same reviewed change, which this is. It is a contract
   decision, not a relabelling: the contract record's helper condition
   B-2 and `docs/sandbox-ops-v1.md` change with it.
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
| `TestEnableOpsChecksTheRuntimeAndTheHelperPin` | nothing (in-process engine transport); its two pin cases need root and a mount | `EnableOps` refuses a runtime with an unreviewed argument, cached features that list `rro`, are absent or do not decode, an unanswered `/info`, and a pin on a writable mount, each for its own reason with ops left off; it enables ops with the mount options the pinned runsc reports as its features and a pinned helper |
| `TestHelperMountReadbackIsExactlyThePinnedMount` | nothing | the readback refuses every mount but the pinned read-only `rprivate` one |
| `TestCreateRejectsSandboxesThatDoNotEnforceTheLease` | unix-socket fake engine | among its cases, the readback refuses a capability added, the default capabilities kept, and `no-new-privileges` dropped |
| `TestOpenRefusesUnverifiableHosts` | unix-socket fake engine | among its cases, `Open` refuses an unreviewed runtime argument |
| `TestDemuxBoundsAndFraming` | nothing | exec stream bounds and framing |
| `TestImageProbeDecidesOnEveryEngineAnswerAndRemovesTheProbe` | nothing (in-process engine transport) | every D1 decision and the probe's removal, also after cancellation |
| `TestOpsHelperPinRefusesExtendedAttributes` | root, a mount, qualifying `TMPDIR` with user extended attributes | the pin refuses an attribute on the directory or the helper |
| `TestOpsCreateProbesTheHelperTargetBeforeCreating` | root, a mount, qualifying `TMPDIR` (in-process engine transport) | `Create` probes before the sandbox create in ops mode only, and refuses every entry type |
| `TestOpsModeMountsOnlyThePinnedHelperDirectory` | root, a mount, qualifying `TMPDIR`, unix-socket fake engine | create body and readback wiring through `Create` |
| `TestOpsHelperPinRefusesAnythingButThePinnedBinary` | same | the host pin, read-only mount (MCR-04) included, at the pin and before `Create` |
| `TestRunHelperExecsTheFixedHelperAndClassifiesFailures` | same | exec request, bounds and attribution |

Every test that needs root skips unless it runs as root, may mount, runs
in a mount namespace of its own whose mount of `TMPDIR` does not share
propagation, and has a root-owned, non-writable `TMPDIR`. Its pinned
directory is a read-only bind mount of a writable source directory under
`TMPDIR`, which the test unmounts again; tests change the pinned files
through that source. The namespace requirement keeps a test that dies
before its cleanup from leaving a mount on the host. Run them as root
under `unshare -m --propagation private` with such a `TMPDIR`. The tests
that also need the unix-socket fake engine have no hosted-CI proof yet,
and no CI job runs the root-gated tests.

Nothing here is a privileged backend proof.
Running the real-engine probes belongs to the isolated lab. A CI job that
runs these tests as root, or treats their skip as a failure, is a workflow
change outside this note. The in-process and unix-socket engine tests prove
the backend's own decisions on scripted engine answers, not Docker's
behaviour. No test sets `security.capability` or proves a guest view.
