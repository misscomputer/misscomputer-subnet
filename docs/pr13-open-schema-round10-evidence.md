# PR13 public-open and schema round-10 repair evidence

## Immutable input and scope

Findings `PR13-ASTRA-023` and `PR13-ASTRA-024` were reproduced and repaired in
the authoritative public source. Before repository access, the task-bound
native rollout attested source `/root/public_pr13_round10_sol_repair`, provider
`openai`, model `gpt-5.6-sol`, and reasoning effort `xhigh`. The clean writer
`HEAD`, explicit remote feature branch, local `refs/pull/13/head`, and GitHub PR
#13 head were pinned to `11859d15f46d1b2b1a0035015c8365bf19db1590`.
Local and external `origin/main`, the GitHub base, and the merge base were
pinned to `8bb49b2d7dc194fcfdcb43fb91e84ba93267f43f`.

This is a local public-source repair. It does not publish a branch or pull
request, start CI, edit a private vendor snapshot, use a wallet or live chain,
access credentials, or alter production, cloud, or service state.

## Failing-before reproduction

The durable round-10 tests and executable reproducer were added before
production source changed. Running the new test file against the exact old SHA
produced **17 failures and 16 passing controls**:

- ten cancellations before the admitted child executed its first opcode
  retained the client/opener and prevented reopen or repeated close;
- five cancellations after a real Bittensor 11.1.0 `Client.connect()` acquired
  a localhost WebSocket, but before child-result delivery, returned while the
  client, descriptor, and RPC supervisor were still live; and
- Draft 2020-12 validation accepted terminal-newline `error_code` and
  `request_id` values rejected by the public parser.

Every failing-old lifecycle schedule reclaimed its test-owned client and peer
and restored descriptor, supervisor, and cleanup-task baselines.

## Repair and invariants

The public chain opener now owns failure cleanup outside its child task. Any
ordinary exception, custom `BaseException`, or cancellation starts or joins
the one chain retirement for the captured client generation and drains its
client and opener before propagating the original failure. Close admission
clears the captured opener itself, so cleanup does not depend on whether the
child reached its `finally` block. Generation comparison prevents an obsolete
public opener from touching a replacement, while concurrent and repeatedly
cancelled close callers continue to join the same retirement.

The response schema now expresses explicit character and length constraints
for `error_code` (one to 64 lowercase ASCII alphanumeric/underscore
characters) and `request_id` (exactly 64 lowercase hexadecimal characters),
matching parser `fullmatch` behavior. Together with the prior
`extrinsic_ref` repair, all constrained response strings reject the terminal
newline exception without changing protocol version or valid response forms.

## Validation

- Durable cumulative round-8/9/10 reproducer: **69 passed**.
- Focused repaired round-10 matrix: **33 passed**.
- Fresh separately installed public wheel, round-9/10 matrix: **51 passed**;
  import provenance was verified outside the checkout.
- Deterministic real-resource stress: **20 rounds / 640 cases passed**.
- Adjacent lifecycle, protocol, SDK-resource, executor, reconciliation, and
  quorum suites: **392 passed**.
- Complete public Python suite: **1,068 passed** in 177.77 seconds.
- Ruff check/format and strict mypy: pass (75 Python files; 35 source files).
- Python 3.12.3, Bittensor 11.1.0, all 12 exact direct runtime/development
  pins, and `pip check`: pass.
- Go 1.23.12: formatting, module verification, vet, and uncached race suite:
  pass.
- Both deterministic fixture/schema generators ran twice; all 194 tracked
  contract files retained hash
  `14bf3377b1d4250c57c4ffff0f1c4a8bd963cd0575ff167dc609f6567dbb222f`.
- Release/SBOM, public-boundary, attribution, repository-secret,
  staged-secret, and diff-hygiene guards: pass.

The exact schema-history comparison showed the base accepted terminal-newline
`extrinsic_ref`, `error_code`, and `request_id` while its parser rejected all
three. The old PR head rejected `extrinsic_ref` but still accepted the other
two. The repaired candidate schema and parser both reject all three.

## Remaining limits

Lifecycle evidence uses Python 3.12.3, Bittensor 11.1.0, and real localhost
WebSocket transports, not a live RPC provider. Quiescent shutdown intentionally
has no abandonment timeout: an SDK operation that never returns continues to
block close and reopening instead of escaping ownership. Process death,
`SIGKILL`, kernel failure, and remote-provider behavior remain outside this
in-process proof.
