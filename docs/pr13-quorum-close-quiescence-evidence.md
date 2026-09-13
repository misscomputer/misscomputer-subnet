# Quorum close quiescence repair evidence

## Immutable input and scope

Finding `PR13-ASTRA-016` was reproduced and repaired in the authoritative public
`misscomputer/misscomputer-subnet` source. The clean writer branch, `origin/main`,
starting `HEAD`, and merge-base were all pinned to
`07d914012d2b9bfb3ef60414882e9c4f5253c08f` before the first edit. The checkout's
editable Python 3.12 environment imported its own `src` tree and contained the
declared `bittensor==11.1.0` dependency.

This is a local source repair only. It does not modify or sync a private vendor,
publish a branch or pull request, use a live chain or wallet, alter CI runners,
or affect production, cloud resources, credentials, or services.

## Executed failing-before reproduction

Before production source was changed, the durable localhost reproducer was run
with:

```sh
bash scripts/reproduce-pr13-astra-016.sh --tb=short
```

Two real Bittensor clients connected to independent localhost WebSocket servers.
Both initializers entered a delayed codec operation that deliberately consumed
cancellation until released. On the pinned old source, `FinalizedRpcQuorum.close()`
completed during that delay. After release, the public `open()` task returned
success, so the old success path could publish `_opened = True` even though close
had already removed both child client owners. Pytest failed with:

```text
AssertionError: quorum.close returned while two SDK initializers and the quorum open were alive
```

The reproducer's `finally` block releases the artificial delay and reclaims every
test-owned client, transport, and peer even when run against the failing revision.

## Repair and protected invariants

The quorum now owns one internal initialization task and one shared close task.
A lifecycle lock protects only state transitions; no initializer or child cleanup
is awaited while that lock is held.

- `close()` first closes admission, advances the generation, and revokes open
  publication.
- It cancels and joins the admitted initializer. That initializer cancels and
  drains every child open and its collector, including cancellation-resistant
  child work.
- The internal initializer is joined before child cleanup, and the public open
  waiter must also unwind before an external close returns, so close cannot
  return with a live quorum-open task.
- Successful publication rechecks the exact generation, ownership, retirement
  gate, and owned initialization-task identity under the lock.
- Concurrent closes share one cleanup task; repeated caller cancellation cannot
  detach it. Every child close is attempted with `BaseException` collection, and
  state returns to a closed fixed point before a sanitized close error is raised.
- A later explicit reopen receives a new generation. A stale initializer can
  never publish into it.

The real-SDK regression verifies blocked close before codec release, refusal of a
second open during retirement, both client descriptors retired, both localhost
peers closed, both RPC supervisors stopped, child owners cleared, no quorum task
survivors, and no stale `_opened` publication. Unit regressions additionally
exercise child-open `BaseException`, three concurrent closes, repeated caller
cancellation, cancellation-resistant initializers, failure-independent child
cleanup, repeated close, and close/reopen generation turnover. Existing lifecycle
tests retain primary, archive, quorum, malformed/incomplete initialization,
reconnect, descriptor, peer, and supervisor coverage.

## Validation

- Durable reproducer: **1 passed** after repair; failed before repair as above.
- Focused quorum and pinned SDK lifecycle suites: **65 passed**.
- Close/open race stress: three adversarial cases passed in **20 consecutive runs**.
- Complete Python suite: **997 passed** in 176.40 seconds (final run).
- Ruff check and format: pass, 72 files; strict mypy: pass, 35 source files.
- All 12 declared runtime/development dependencies match their exact pins;
  `pip check` passes and Bittensor is 11.1.0.
- Go 1.23.12: gofmt clean, `go mod verify`, `go vet ./...`, and uncached
  `go test -race -count=1 ./...` pass.
- Both fixture/schema generators ran twice; all 194 contract files remained
  unchanged after each generator invocation.
- Release metadata/direct-pin SBOM parity, public-boundary, attribution,
  repository-secret, staged-secret, and diff-hygiene guards pass.

## Remaining limits

The network regression uses real pinned SDK and WebSocket transports against
localhost, not a live chain or production service. Codec completion is controlled
to make scheduling deterministic; initialization around it is the real Bittensor
11.1.0 client path. Quiescent close intentionally has no abandonment timeout: a
child initializer or close operation that never returns will continue to delay
shutdown rather than escape cleanup. Process death, `SIGKILL`, and OS failure are
outside this in-process lifecycle test.
