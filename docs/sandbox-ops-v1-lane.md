# Sandbox operations: helper, miner lane and transport (default-off draft)

Status: **draft, off by default, unactivated, not customer-ready.** This
document maps the [`sandbox-ops-v1`](sandbox-ops-v1.md) contract onto code
and lists every choice the code makes that the ops section of the shared
contract has not decided. None of these choices is a contract decision; each
is isolated so that a later ops-section version can replace it.

## Pieces

| Piece | Code | Off by default because |
| --- | --- | --- |
| Helper wire protocol | `pkg/sandboxops` | used only by the pieces below |
| In-sandbox helper | `cmd/sandbox-ops-helper` (+ `scripts/sandbox-ops-helper/build.sh`) | mounted only in ops mode |
| Backend ops mode | `pkg/sandboxbackend/ops.go` | `GVisor.EnableOps` is called only with `--sandbox-ops on` |
| Miner ops lane | `pkg/miner/sandbox_ops.go` | `SandboxLane.EnableOps` is called only with `--sandbox-ops on` |
| Agent route | `cmd/miner-agent/sandbox_ops.go` | `POST /v1/sandbox/ops` and the `sandbox-ops-v1` feature exist only once the lane has ops |
| Neuron transport | `src/misscomputer_subnet/sandbox_transport.py`, `miner.py`, `validator.py` | `--sandbox-ops on` (requires `--sandbox-leases on`) |

With `--sandbox-ops off` the create body and its readback, the routes, the
tables, the capabilities and the neuron routes are exactly what they are
without this code.

## Helper

- Invoked by `docker exec` at `/.misscomputer/sandbox-ops-helper`, image
  default user, `Privileged: false`, no added environment, no TTY, no
  arguments (B-4). Docker adds the image's own environment to every exec, so
  a helper started with any environment first re-executes itself through
  `/proc/self/exe` with an empty one. It reads one request of at most 1 MiB
  on stdin and writes one response of at most 1 MiB on stdout
  (`pkg/sandboxops`).
- File operations go through `fsroot` opened at `/` (B-9) with the 30 s
  budget.
- `exec_start` creates `/tmp/.misscomputer-ops/<exec_id>` (0700) and starts
  a supervisor (the helper re-executed through `/proc/self/exe` in its own
  session). The supervisor runs the command in its own process group with an
  empty environment and only its stdio (every other descriptor is
  close-on-exec), keeps each stream's first `max_output_bytes` in the
  capture directory, counts the rest, writes `status.json`, and on SIGTERM
  (cancel) or at its deadline sends SIGTERM to the group and SIGKILL after
  5 s. A second `exec_start` of the same exec ID never runs the command
  again. A missing `/tmp` or an unusable capture root is `ops_unsupported`.
  The supervisor's own deadline is the exec's own bound, `admitted_at +
  timeout_ms`; the lease expiry bound is the miner lane's, which renewals
  move.
- Build: `scripts/sandbox-ops-helper/build.sh <out>` (static, `CGO_ENABLED=0`,
  `-trimpath`, `-buildvcs=false`, empty build ID, `go.mod` toolchain). Two
  builds of one commit are byte-identical.

## Backend ops mode

- `EnableOps(OpsHelper{Dir, SHA256})` verifies the B-2 pin: the directory
  and every ancestor are root-owned and not group- or other-writable, the
  directory has mode 0555 and holds only the helper, and the helper (opened
  with `O_NOFOLLOW`) is a root-owned regular file of mode exactly 0555 with
  the pinned SHA-256. The pin is verified again before every create; a
  failure is a miner fault (`runtime_start_failed`).
- Ops mode adds one mount to the create body: bind, the pinned directory,
  target `/.misscomputer`, read-only, `rprivate`. The readback must show
  exactly that mount in both `HostConfig.Mounts` and the container's mounts.
- `RunHelper` creates an attached exec, writes the request, half-closes
  stdin, demultiplexes the raw stream (stdout kept up to 1 MiB, stderr
  dropped; more than either bound fails the call), and inspects the exit
  code, re-reading for up to 0.5 s while dockerd still reports the exec
  running after its stream closed; a nonzero exit is `sandbox_op_failed`. A missing or stopped container is
  `ErrSandboxNotRunning` (`sandbox_exited`). An engine call without an answer
  is a miner fault only when a `/_ping` of the same daemon also fails (D1);
  every engine-answered error is not (the allowlist is empty).

## Miner lane

- Shares the lease lane's `track`, `Close`, base context and gate (OPS-U6).
  Ops are enabled only after both startup Recover steps. No receipt is
  signed after Close (`sandbox_lane_closed`, 503, retryable).
- Every op: bound verification, miner identity, payload binding, strict
  exec payload decoding, the in-flight bound, then durable admission
  (`AdmitOp`) before any effect.
- `exec_start` answers `running` at once (R1, `B_exec = 0`); a start owner
  issues the one backend start. A start failure is recorded afterwards and
  answered on later exec ops as stage `failed` with the helper's code and an
  `exec` member in state `failed` (P-5). `exec_read` and `exec_cancel`
  answer `exec_not_found` with `observed_at` equal to the lookup's decision
  time.
- Kill path (B-7, DP-13): helper cancel, wait `ExecKillGrace` plus the kill
  grace for a terminal observation, a forced cancel if none came, then
  record the terminal state whatever the helper said. Guest code can stop
  the helper (B-5), so the cancel and status polls share the grace window as
  their deadline and the forced cancel has `ExecKillGrace`; an `exec_cancel`
  releases its in-flight slot before it waits. An `exec_read` helper call
  has the 30 s op budget.
- The exec deadline is `min(admitted_at + timeout_ms, lease expiry)` on the
  durable clock; renewals move it. When the deadline is the lease expiry and
  the lease reaches it unrenewed, the kill path still runs: the lease is
  past its expiry but still running, its teardown not begun, and the exec
  is SIGTERMed and recorded `timed_out` then, not at teardown. A released,
  failed or cleaning-up lease is left to its teardown.
- A durable exec-state step that runs out of `D_state` is retried (three
  tries). If the deadline's own read stays unknown, the deadline is tried
  again every `D_state`, until the store answers or lease teardown drops
  the exec. A start owner that could not read or record its exec's state
  hands it to a resolution that also tries every `D_state`: once the store
  answers, an exec still `admitted` ends `failed` (`sandbox_op_failed`),
  never started late; a started exec whose `running` record fails is
  killed by identity first. An admission that answered an error may have
  committed: its exact replay inside the request window starts it, once;
  when the window closes, the durable row decides: none, the in-memory
  entry is dropped; one that no owner took, it ends `failed`, never
  started. Each exec has at most one such timer; teardown stops it. A store
  that never answers again leaves such execs until lease teardown.
- An admitted op that fails in a way that is none of the lane's named
  answers is answered `500 sandbox_ops_internal` (retryable) by the agent,
  never a 4xx: it may follow an effect, and a 4xx is a refusal without one.
- Mutating file ops (`file_write`, `file_remove`, `file_mkdir`) keep their
  signed answer until `expires_at` plus the skew, so an exact replay is
  answered from it and never repeats the effect.

## Provisional choices (not contract decisions)

| Id | Choice in this draft | Why it is open |
| --- | --- | --- |
| P-1 | `D_start`, `D_state`, the kill grace, the in-flight op and byte bounds, and the retained-outcome bound are required `--sandbox-ops-config` members without defaults | OPS-U numeric gates: no value is adopted before a reviewed measurement |
| P-2 | `--sandbox-ops-config` carries the helper pin, outside the host profile | the host profile schema has no helper member |
| P-3 | Receipt stage: `sandbox_op_failed`, `sandbox_resources_exhausted` and `op_runtime_failed` are `failed`; every other code is `refused` | the contract names stages and codes but no mapping |
| P-4 | Beyond the in-flight bound, `exec_start` is refused `exec_limit_exceeded` with a receipt; every other op is `503 sandbox_ops_busy` (retryable, no receipt); so is a `D_state` expiry with the lane open | D14 says "retryable 503 (file)" without a code; U6-L8-5 names no code |
| P-5 | A command whose `argv[0]` or `cwd` cannot be used ends `failed` with `path_not_found`, `permission_denied` or `path_not_directory`; `argv[0]` without a slash resolves in the default Docker `PATH` | the contract does not say how a start failure is reported, and the exec environment is empty |
| P-6 | A signal-ended command is `exited` with 128 plus the signal | `exit_code` is 0..255 only |
| P-7 | After the command exits the supervisor reads its pipes for at most 1 s, then stops retention | retained output must stop growing once the exec is terminal |
| P-8 | Mutating file op answers are held in memory; a replay whose answer is not held is `sandbox_ops_busy` | U5 (file_write completion) is open |
| P-9 | Exec status is answered from durable state plus the latest helper observation; a helper-observed end is recorded by the op that observed it | U4 (who writes transitions) is open |
| P-10 | Capability refusal `sandbox_ops_capability_unsupported` (409) when a miner lacks `sandbox-lease-v1` or `sandbox-ops-v1` | named in the contract text only as `409 sandbox_ops_capability_unsupported` |

## Not done (activation blockers)

- Probes D5-P1..P3 and D5-P9 on the pinned runsc (`openat2` in the sentry,
  mount immutability from guest root, process-group kill, image-controlled
  mount target). Whether a supervisor started by a `docker exec` outlives it
  under runsc is part of these probes.
- The contract's delivery requires a `nosuid,nodev,rprivate` bind; this
  draft requests read-only `rprivate` only, because the Docker bind mount
  API offers no `nosuid`/`nodev` option. Either the guest mount flags are
  observed under runsc (D5-P9), or the delivery mechanism or the contract
  text changes. Not decided here.
- An image whose rootfs conflicts with `/.misscomputer` (B-11) fails create
  today with the backend's existing attribution; the non-fault lease code for
  it is a contract-owner decision.
- `N_ops`, pruning (U7, INT-OPS-01) and restart recovery of op rows (U6):
  op records grow until those land.
- Advertisement of the helper digest and execution profile with the feature
  (KB-1/KB-2); the private runtime's placement on it.
- The lane counts an exec as running until its end is observed or its
  deadline passes, so an exec that finished without being read keeps one of
  the 16 running slots until then.
