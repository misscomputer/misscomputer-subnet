# Executor post-send lifecycle repair evidence

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
