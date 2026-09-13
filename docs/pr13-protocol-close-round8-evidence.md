# PR13 protocol and chain-close round-8 repair evidence

## Immutable input and scope

Findings `PR13-ASTRA-017` and `PR13-ASTRA-019` were reproduced and repaired in
the authoritative public source. Before the first repository edit, the clean
writer branch, local `HEAD`, local `origin/main`, external `origin/main`, and
merge base were pinned to `8bb49b2d7dc194fcfdcb43fb91e84ba93267f43f`.
The review specification hash was
`1135e3d8fc8f4813ab096ee6af1d867e37d3513610c7542c47210d67068f2318`.

This is a local public-source repair. It does not read or modify a private
vendor snapshot, publish a branch or pull request, start CI, use a wallet or
live chain, access credentials, or alter production, cloud, or service state.

## Failing-before reproduction

The durable public reproducer was added before production source changed and
then run on the exact old SHA:

```sh
bash scripts/reproduce-pr13-round8-public.sh --tb=short
```

It produced six independent failures and nine passing controls:

- the committed v2 schema rejected canonical `ambiguous` plus `103-2`;
- the real Unix client/executor converted that response to an ambiguous CLI
  error without `extrinsic_ref`, and its audit receipt also lacked the
  reference;
- all four ordinary/repeated-cancellation and success/error close schedules
  let a second `BittensorChain.close()` finish while the first real
  Bittensor 11.1.0 `Client.close()` was deliberately held. The live WebSocket
  descriptor and `rpc-session` supervisor remained active until the first
  closer was released.

The test cleanup released every artificial delay, joined both closer tasks,
closed every SDK transport, and aborted any test peer necessary to make the
failing-old run resource-clean.

## Repair and invariants

Weight-signer protocol v2 keeps its exact version and envelope. Its status
rules are now aligned across the checked-in schema and parser:

- `confirmed`: reference required, error forbidden;
- `rejected`: error required, reference forbidden;
- `ambiguous`: error required, canonical reference optional.

The public client attaches an ambiguous reference only after canonical framing,
exact shape/version checks, peer-UID authentication, and request-ID binding.
The executor carries that reference through its ambiguous post-send exception,
captures it before fallible audit persistence, emits it in the CLI diagnostic,
and leaves the attempt non-retryable. Null-reference ambiguity is unchanged.
Confirmed and rejected controls remain strict.

`BittensorChain` now owns a lifecycle lock, a retirement flag, and one shared
close task. The first close atomically closes admission and detaches the client
for use only by the retained retirement task. Concurrent close callers join the
same task; repeated caller cancellation cannot detach it; every joiner sees the
original SDK close error. `open()` is refused until SDK cleanup completes and
the close gate is cleared. Captured descriptors and supervisors must therefore
reach the closed fixed point before any successful close or reopen.

## Validation

- Durable reproducer after repair: **18 passed**.
- Fresh, separately built and installed public wheel exchanging raw canonical
  v2 bytes with an independent stdlib Unix producer: **4 passed**, covering
  referenced/null ambiguity with successful/failed audit persistence.
- Focused executor/reconciliation suite: **212 passed**.
- Focused chain/real-SDK suite: **85 passed**.
- Deterministic protocol/close stress: **20 consecutive rounds passed**.
- Complete public Python suite: **1,017 passed** in 181.24 seconds.
- Ruff check and format: pass, 73 Python files; strict mypy: pass, 35 source
  files.
- Python 3.12.3, pinned Bittensor 11.1.0, all 12 exact direct runtime/dev pins,
  and `pip check`: pass.
- Go 1.23.12: `gofmt` clean, `go mod verify`, `go vet ./...`, and uncached
  `go test -race -count=1 ./...`: pass.
- Both fixture/schema generators ran twice; the tracked diff hash remained
  `1740425d76b39a8db3f016bf5d588c1a425f9b0ca2974b244e9394ce3b38cf5f`.
- Release/direct-pin SBOM parity, public-boundary, attribution,
  repository-secret, private-path, and diff-hygiene guards: pass.

## Remaining limits

The SDK lifecycle tests use the real pinned client and real localhost WebSocket
transports, not a live RPC provider. The protocol test uses real Unix sockets
and an installed wheel, with an independent canonical producer rather than a
private distribution. No vendor synchronization is part of this public-first
change. Quiescent close intentionally has no abandonment timeout: an SDK close
that never returns continues to delay close and reopen instead of escaping
cleanup. Process death, `SIGKILL`, and OS failure are outside this in-process
lifecycle proof.
