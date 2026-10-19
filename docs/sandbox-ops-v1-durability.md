# Sandbox operations: durable admission (development draft)

Status: **opt-in, provisional.** `pkg/durable/sandbox_ops_v1.go` adds an
opt-in durable admission store for [`sandbox-ops-v1`](sandbox-ops-v1.md).
Only the default-off miner ops lane calls it, when the agent runs with
`--sandbox-ops on` ([sandbox-ops-v1-lane.md](sandbox-ops-v1-lane.md)).
`durable.Open` never creates its tables. Its tables and semantics may change
freely until the ops contract freezes.

## What it guarantees

- **Opt-in schema.** `(*SandboxLeases).EnableSandboxOps(ctx, clock)` creates
  `sandbox_ops`, `sandbox_execs` and `sandbox_ops_clock` in a store whose
  lease lane is enabled.
  It is the only path that creates them. Every other table definition,
  including the lease tables, is unchanged, and the ops store only reads the
  lease tables.
- **Write-ahead (contract D13).** `AdmitOp` records each admitted op by
  `op_id` and document digest. For an `exec_start` it also records an exec
  row in state `admitted`. Both rows go in one transaction, before the
  caller may cause any effect. `Start` is true only on the first admission
  of an `exec_start`.
- **Decision time never goes back (DP-8).** Each transaction decides at
  the later of the wall clock and the durable high-water time in
  `sandbox_ops_clock`, and raises the high-water time to it in the same
  transaction. A refusal with no receipt (window closed, foreign lease,
  equivocation) still commits that time.

  A wall clock stepped backward, before or across a restart, therefore
  cannot:
  - re-open a request window an earlier decision closed;
  - admit an `exec_start` after a definitive `exec_not_found`;
  - move `DecidedAt` backwards.

  This is the prerequisite for `N_ops` counting and INT-OPS-01 pruning,
  neither of which is in this slice.
- **One atomic admission (SR-28-05).** The store takes its decision time
  inside the transaction, after taking the store's single database
  connection. With that one time it re-decides all of these, then inserts:
  - the request window (`now < expires_at`);
  - the lease fence (`SandboxOpTargetsLeaseV1` against the stored signed
    lease);
  - lease liveness (status `running` and `now < lease_expires_at`, which
    follows renewals);
  - the per-lease exec caps: 16 execs in `admitted` or `running`, and 1024
    exec sessions.

  Any failed check records nothing. A window that closed after the bound
  admission check passed is `ErrSandboxOpExpired`.
- **Replay and equivocation.** An exact replay never yields another
  `Start`. While the lease still runs ops, the replay is answered from the
  recorded admission. Once the lease has stopped (release, expiry, or
  failure after a miner restart), the replay is answered from the current
  lease state (`Replay` plus `Unavailable`). A replay can therefore never
  report a live exec on a stopped lease. The same `op_id` with a different
  document is `ErrSandboxConflict` whatever the lease state, and changes
  nothing. Every op kind is recorded, reads included, so equivocation
  detection is uniform.

  The order of checks is:
  1. lease fence;
  2. equivocation;
  3. exact replay;
  4. request window (unrecorded ops only);
  5. lease state;
  6. caps;
  7. insert.
- **Truthful `exec_not_found`.** `LookupExec` reports `Found` false exactly
  when no `exec_start` with that `exec_id` was admitted on the lease, and
  returns `DecidedAt`, its in-transaction clock reading. Admissions and
  lookups are serialized on one connection and use the same clock. A lookup
  that finds nothing at `DecidedAt >= expires_at + 30 s` of the start can
  therefore never be followed by that start's admission. **Wiring
  obligation:** a receipt answering `exec_not_found` from a lookup must
  carry `observed_at = DecidedAt`, never a later time. Only then is it
  definitive under `SandboxExecNeverStartedV1`.
- **Lease-state answers (U1).** The store reports the raw lease state
  (`Unavailable`), and `SandboxOpLeaseState.RefusalCode(at)` maps it to the
  non-fault op code:

  | Lease state at the decision time | Code |
  | --- | --- |
  | `running`, before expiry | none: the op proceeds |
  | `running`, at or after expiry | `lease_expired` |
  | `pending` | `lease_not_running` |
  | `released`, or `cleanup` towards released | `released` |
  | `expired`, or `cleanup` towards expired | `lease_expired` |
  | `failed` (including `miner_restart`), or `cleanup` towards failed | `lease_not_running` |

  The codes mean "no further ops on this lease"; during cleanup the sandbox
  may still be torn down. None is proof that an exec never started.
  `miner_restart` is not emitted for ops. An op naming no lease row of this
  miner, fenced or not, is `ErrSandboxOpForeign` and gets no receipt.
- **No content.** Rows hold identities, digests, states and times. No path,
  argv, payload, result or signed request JSON is stored.
- **Exec transitions are supplied by the caller.** `RecordExecState` stores
  `running`, `exited`, `cancelled`, `timed_out` or `failed` (with a known
  op code) and only enforces monotonicity: a terminal state never changes,
  and `running` never returns to `admitted`.

## What it deliberately does not decide

Each item stays with its owner until decided. The full rationale is in
the swarm readiness record.

| Id | Not decided here |
| --- | --- |
| U2 | Recording side-effect-free ops. They are recorded, for uniform equivocation detection. This choice is the draft's and can be reversed. |
| U3 | How an exact replay of an `exec_start` still in flight is answered. The store only reports `Replay`. |
| U4 | Who writes exec transitions and when, how races between them resolve, and re-capping of reported output. |
| U5 | `file_write` completion, partial writes after a crash, and the source of `offset_mismatch`. |
| U6 | Restart recovery of op and exec rows. No recovery method exists. Lease `Recover` already makes every lease non-running. |
| U7, INT-OPS-01, `N_ops` | Retention and the non-exec op cap. The design is accepted (terminal-lease and closed-window pruning in tracked batches, and an `N_ops` cap with `exec_cancel` headroom), but its parameters are not reviewed yet. This slice therefore has **no pruning and no `N_ops` cap**. Records grow until then, which is acceptable only on disposable lab hosts and blocks activation. |
| U8–U10 | Per-agent output budget, guest spawn-storm mapping, capability advertisement. These are outside the durable store. |

## Merge and activation

The parent may consider merging this inert schema before the ops contract
freezes. That requires two independent exact-head approvals and green CI.
Merging does not freeze ops semantics. Activation needs everything listed
in [sandbox-ops-v1.md](sandbox-ops-v1.md) plus the miner ops lane that
calls this store.
