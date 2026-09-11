# Executor post-send lifecycle repair evidence

The original sections below record the first bounded repair. The subsequent
exact-head review found additional uncovered cases; the **Second bounded
repair** section supersedes its finding-closure claims and SDK test limitation.
Historical evidence is retained rather than relabelled as second-round coverage.

## Immutable scope

Public PR: https://github.com/misscomputer/misscomputer-subnet/pull/10.
Repair input: `a471fb9bca1b8c4038f0af7af56d8c6952cf0bf3`.
Base/main/merge-base: `a5eb398317353e40d59d8357c11d9871fbb5b265`.
The writer checked clean local HEAD, upstream, live branch, live PR head/base,
and merge-base before edits. The previously absent local pull ref was fetched
and matched the same immutable head. Runtime session metadata attested OpenAI
`gpt-6-astra`, `xhigh`, in the OpenClaw Codex runtime. No push, PR metadata
edit, merge, private snapshot edit, deployment, wallet, or live chain action
belongs to this repair.

## Reproductions and disposition

- **PR13-SOL-002 (High):** repaired in the public executor/storage source.
  Real `main()` and atomic audit writes are driven through a deterministic
  chain/submitter boundary. After exactly one submission, inject final replace,
  unlink, directory-fsync, temporary-close, or timestamp failure for lost,
  timeout, missing-reference, confirmed, and definite-rejection results.
  Check truthful redacted CLI classification, descriptor retirement, and
  `idempotency_blocked` without any second submit. Additional tests cover
  unpublished named/unnamed result temporaries, lock/directory cleanup, and
  preservation of an original `BaseException` when cleanup also fails.
- **PR13-SOL-003 (Medium):** repaired by owning both adapters before open and
  draining a retained, shielded cleanup task across every cancellation. Both
  adapter closes and audit cleanup are attempted under `BaseException`, with
  safe diagnostics separate from the primary result. Real socket pairs prove
  descriptor closure and peer EOF; the production `UnixWeightSignerClient`
  also completes a real UID-checked Unix-socket protocol exchange, receives a
  confirmed response, and closes/drains after repeated cancellation.

The standalone offline reproduction command is:

```sh
bash scripts/reproduce-executor-lifecycle.sh --tb=short
```

Use this checkout's own development `.venv`. The script can run either finding
independently using pytest selectors (`-k persistence`, `-k cancellation`).
The first 28 cases were run before changing production source and all failed.
The final 52-case regression file was then run against source extracted by
`git archive` from the immutable input into an ignored worktree-local directory,
with `PYTHONPATH` explicitly selecting that source. Imported source identity was
checked. **52 failed on old source (1.33s); 52 passed on repaired source**, then
passed five consecutive runs (1.24–1.32s each). No old-source failure is counted
as evidence of a live network submission.

## Result and replay invariants

The submission outcome is captured before final audit persistence. Ordinary
persistence failures cannot replace `submission_ambiguous` with raw I/O or audit
errors. The CLI now reports `status: ambiguous` for that stable code.
Confirmed submission plus failed audit returns exit 2 with
`submission_confirmed_audit_failed`, `status: confirmed`, its public reference,
and `audit_persistence_failed`. Definite rejection keeps `submission_failed`.
Optional safe cleanup diagnostics do not change any of those classifications.
Successful CLI output is unchanged unless cleanup diagnostics must be reported.
Schema bytes and dependency versions are unchanged.

No final receipt is fabricated when persistence fails. The already durable
started marker, or the final record if replacement occurred, blocks replay.
The code does not retry an uncertain write, loosen inode checks, clear ledgers,
or turn current chain-row agreement into proof of a specific submission.
Shared temporary cleanup uses nested `finally` to attempt descriptor close
even if path cleanup fails; pinned-directory cleanup attempts every owned fd.

## Validation

- Complete Python suite: **841 passed**, 169.44 seconds.
- Repair regressions: 52 passed, five consecutive runs.
- Existing executor/public-boundary tests: 52 passed before the final added
  temporary-ownership regressions; included again in the full suite.
- Ruff check and format: pass, 68 source/test files.
- Strict mypy: pass, 33 source files.
- Go 1.23.12: vet, uncached `go test -race -count=1 ./...`, gofmt, and
  `go mod verify` pass.
- Both contract generators run twice: all 194 tracked contract files
  byte-identical before and after.
- Every direct runtime/development dependency matches its exact declared pin;
  `pip check` passes, including Bittensor 11.1.0.
- Public-boundary, release/SBOM, attribution, secret, and diff-hygiene guards
  pass. There is no tracked public vendor tree; private vendoring is explicitly
  excluded and must follow the separately approved public-source revision.

## Limits

These are offline production-code and local-transport tests, not live chain or
production-service validation. The chain oracle is deterministic; Bittensor's
network initialization and private SDK adapter are not exercised in this scope.
The real public signer client/protocol, real file operations, descriptor state,
and socket EOF are exercised. No cleanup task is deliberately abandoned or
timed out: an adapter whose close never returns can still delay shutdown.
Unrecoverable filesystem failure can leave an owner-only temporary path; a
failed initial fd identity read does not authorize unlinking an unverified
name. Closing a descriptor is attempted once, never retried after an ambiguous
close error because the descriptor number may already have been reused.
Process death/SIGKILL, power-loss durability, and external SIGINT escalation
are not simulated. Repeated task cancellation and escaping `BaseException`
preserve the primary result after cleanup has been drained.

This is a local writer handoff, not an independent review or hosted exact-head
CI claim. The controller owns subsequent review, publication, and merge gates.

## Second bounded repair

Input head: `9b9c7d5a52a11aab86a53a2385b629693e1ba9aa`; unchanged base:
`a5eb398317353e40d59d8357c11d9871fbb5b265`. The non-author repair lane
attested OpenAI `gpt-6-astra`, `xhigh`, from resolved runtime turn metadata.
Local HEAD/upstream/pull ref, live branch/PR head, base, and merge-base matched
before changes and immediately before the local-only commit.

### Executed failing-before evidence

With production source still at the input head, the expanded standalone matrix
produced **104 failed, 68 passed** (7.98 seconds):

- 80 final-persistence failures across `SimulatedCrash(BaseException)` and
  `CancelledError`, five submission outcomes, and eight fault sites: clock,
  write, file fsync, replace, directory fsync, verification, temp close, unlink.
  The old CLI leaked raw exceptions instead of safe outcome JSON, while the
  already durable replay barrier still prevented a second submit.
- Seven descriptor-cleanup failures: target close skipped reopened directory
  descriptors; plan unlink skipped temporary/directory closes; root/child
  acquisition failures leaked already-acquired descriptors.
- Ten real Bittensor 11.1.0 primary/archive initialization leaks, a quorum
  cancellation with child close counts `0, 0`, and two real Unix signer
  post-connect `BaseException` leaks.
- A mutated retained report with an unchanged digest was accepted despite its
  canonical parser rejecting `report_counts_invalid`.
- Three live-head persistence regressions initially failed because the old
  API lacked live-head arguments. The exact old documented composition was
  also executed separately and failed with `catch_up_state_mismatch`:

```sh
.venv/bin/python scripts/reproduce-pr10-history-handoff.py \
  --source-revision 9b9c7d5a52a11aab86a53a2385b629693e1ba9aa
```

That command reads the exact old handoff module from local git without editing
the checkout. Without `--source-revision`, the repaired composition succeeds
and persists the verifier's exact live-head state at sequence 3.

### Repairs and stable outcomes

- **PR13-SOL-002:** final persistence now contains `BaseException` after
  capturing effect certainty. Confirmed results retain
  `submission_confirmed_audit_failed`, definite rejection retains
  `submission_failed`, and unknown outcomes retain `submission_ambiguous`;
  each persistence fault reports `audit_persistence_failed`. All regression
  cases execute real `main()`, assert sanitized JSON, one submission, closed
  descriptors, and a blocked retry. Nested cleanup and acquisition unwinding
  attempt every owned directory/temp descriptor even when another close or
  unlink fails. The older confirmed-crash test now asserts the truthful
  confirmed result while preserving all of its replay-barrier assertions.
- **PR13-SOL-003:** `BittensorChain` owns the cold SDK `Client` before connect;
  a narrow backend adapter for pinned 11.1.0 independently owns each raw
  interface before primary or lazy archive initialization. SDK files are not
  modified. Quorum ownership is independent of successful-open state and its
  canceled initialization tasks are drained before child cleanup. The Unix
  signer publishes its connected writer before peer/inode validation.
  Cleanup tasks remain owned and drained across repeated cancellation.
- **PR13-SOL-004:** the locked handoff optionally takes the live manifest,
  signatures, and finalized height as an all-or-none group. It authenticates
  history, verifies the head live, compare-binds the exact next-state digest,
  and only then atomically persists it. Catch-up, direct-head, and reprobe
  compositions succeed; invalid signatures, expired head, incomplete input,
  or wrong expected state do not write. Existing history-only callers remain
  supported. The runbook uses the complete live-head handoff.
- **PR13-SOL-005:** independently retained reports are canonically reparsed
  and revalidated before their digests participate in equality checks.
  Mutated/stale-digest content rejects as `decision_probe_records_invalid`.

### Final validation

- `scripts/reproduce-pr10-terminal-review.sh`: **182 passed**, three consecutive
  runs (9.32, 9.67, 9.55 seconds).
- Complete Python suite: **971 passed**, 174.88 seconds. An initial full run
  exposed the older confirmed-crash expectation and an incorrect new test
  assumption that an expired assignment lease must invalidate the entire
  manifest state. The former was updated to the required effect semantics;
  the latter tests expired-head freshness instead. No validity rule was relaxed.
- The real SDK lifecycle file has 20 passing cases, including cancellation
  during websocket handshake and every metadata RPC await, malformed metadata,
  lazy archive acquisition, both transport-close failure orders, quorum cleanup,
  and real Unix peer EOF with repeated cancellation.
- Ruff check/format and strict mypy pass (35 source files); `pip check` passes.
- Go vet, uncached `go test -race -count=1 ./...`, gofmt, and module verification
  pass. Both contract generators run twice; all 194 tracked contract files
  remain byte-identical. Dependency/schema versions are unchanged.
- Release/SBOM, public-boundary, staged secret, attribution, and diff checks pass.

### Remaining operational limits

All network tests use localhost, with real pinned SDK/websocket/Unix transport
lifecycle. Successful primary/archive setup in archive/close-order tests stubs
codec warming and display-token metadata only; malformed metadata and canceled
RPC initialization use the real SDK path. This is not a live chain submission,
production-service validation, external SIGINT/SIGKILL test, or proof of
power-loss durability. A close operation that never returns can still delay
shutdown; no owned cleanup task is abandoned. A refused unlink can leave an
owner-only recoverable temporary artifact, and ambiguous descriptor closes are
not retried against potentially reused descriptor numbers.

No push, merge, PR metadata change, private snapshot/vendor change, or live
infrastructure effect was performed. Independent exact-SHA review and any
publication/merge remain the controller's next gates.
