# PR13 lifecycle and schema round-9 repair evidence

## Immutable input and scope

Findings `PR13-ASTRA-020`, `PR13-ASTRA-021`, and `PR13-ASTRA-022` were
reproduced and repaired in the authoritative public source. Before repository
access, the task-bound native rollout attested provider `openai`, model
`gpt-5.6-sol`, and reasoning effort `xhigh`. Before the first edit, local
`HEAD`, the explicit remote feature branch, `refs/pull/13/head`, and GitHub PR
#13 head were pinned to
`ee6410f1495ecdd60c908b10b692339bf6c5825a`. Local and external `main`, the
GitHub base, and the merge base were pinned to
`8bb49b2d7dc194fcfdcb43fb91e84ba93267f43f`. The writer was clean.

This is a local public-source repair. It does not publish a branch or pull
request, start CI, edit a private vendor snapshot, use a wallet or live chain,
access credentials, or alter production, cloud, or service state.

## Failing-before reproduction

The durable round-9 test and executable reproducer were added before production
source changed and run on the exact old SHA:

```sh
bash scripts/reproduce-pr13-round9-public.sh
```

All **18 cases failed** before the repair:

- eight real Bittensor 11.1.0/localhost schedules showed chain close returning
  while its admitted opener remained active, across successful initialization,
  ordinary exception, custom `BaseException`, and `CancelledError`, with both
  ordinary and repeatedly cancelled close callers;
- nine real-SDK cases showed external owner close returning while
  transport-initiated cleanup retained live descriptors, across primary,
  archive, and quorum ownership and ordinary exception, custom
  `BaseException`, and `CancelledError`; and
- the Draft 2020-12 schema accepted an ambiguous extrinsic reference ending in
  a newline even though the protocol parser rejected it.

Every failing-old lifecycle case released its controlled delay, joined all
owned tasks, and restored descriptor and `rpc-session` baselines.

## Repair and invariants

`BittensorChain` now retains an explicit opener task and monotonically increasing
client generation. Close atomically blocks admission and detaches the exact
client, begins its SDK retirement, and then drains the admitted opener before
releasing the gate. Initialization cleanup closes only the client captured for
that generation. An obsolete opener therefore cannot outlive a successful
close or retire a subsequently opened client.

`_OwnedRpcSubstrate` publishes one shared retirement task before moving its
owned-interface list. Cleanup initiated by primary connect or lazy archive
initialization and cleanup initiated by an external owner join that same task.
The retiring flag remains closed after retirement, so the old substrate cannot
reopen while or after its descriptors, supervisors, and logical session state
are being retired. Completed cleanup remains idempotent for later owner close.

The response schema retains the printable-ASCII reference pattern and also
explicitly rejects every character outside that class. This closes the regular
expression end-anchor exception for a terminal newline and matches both public
and private parser `fullmatch` semantics without changing the protocol version
or any valid response form.

## Validation

- Durable reproducer after repair: **18 passed**.
- Separately built, noneditable public wheel reran the same real-SDK/schema
  matrix: **18 passed**; import provenance was verified under its isolated
  target directory.
- Deterministic real-resource stress: **20 rounds / 360 cases passed**.
- Adjacent lifecycle, protocol, executor, and quorum matrix: **302 passed**.
- Complete public Python suite: **1,035 passed** in 178.10 seconds.
- Ruff check/format and strict mypy: pass.
- Python 3.12.3, Bittensor 11.1.0, all 12 exact direct runtime/development pins,
  and `pip check`: pass.
- Go 1.23.12: formatting, module verification, vet, and uncached race suite:
  pass.
- Both fixture/schema generators ran twice; the complete tracked-contract hash
  remained `6c44f9df1d633aa7d7d3376ace6da089a46944a59080f5f82de3c9be9f684df0`.
- Release/direct-pin SBOM parity, public-boundary, attribution,
  repository-secret, private-path, and diff-hygiene guards: pass.

## Remaining limits

Lifecycle evidence uses the pinned SDK and real localhost WebSocket transports,
not a live RPC provider. Quiescent shutdown intentionally has no abandonment
timeout: an SDK initializer or close that never returns continues to block
close and reopening instead of escaping ownership. Process death, `SIGKILL`,
kernel failure, and remote-provider behavior are outside this in-process proof.
