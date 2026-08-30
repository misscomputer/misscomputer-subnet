# Bittensor SDK compatibility record

Selection date: 2026-08-22; weight-intent surface re-inspected 2026-08-24.

The implementation was selected after checking the stable PyPI package, the official Bittensor v11 migration/signed-request guidance, the current SDK surface, and the official subnet-template notice.

## Selected versions

`pyproject.toml` pins the direct runtime and development dependencies exactly:

- `bittensor==11.1.0`
- `fastapi==0.141.1`
- `httpx==0.28.1`
- `cryptography==50.0.0` for public X.509 parsing, validity checks, and
  certificate/key matching without private `ssl` internals
- `pydantic==2.13.4`
- `uvicorn==0.52.4`
- `ruff==0.16.4`, `mypy==2.3.1`, `pytest==9.1.1`, and `pytest-asyncio==1.4.0`

Python is pinned to the production runtime, Python 3.12. Package metadata, CI,
tooling, and the neuron container all enforce that single version rather than
maintaining compatibility with runtimes that are not deployed.

## APIs used

- `bt.Wallet(name, hotkey, path=...)`, resolved at neuron startup into the
  private implementation of a purpose-limited hotkey-signing facade
- async `bt.Subtensor(network)` and block-pinned
  `client.subnets.metagraph(netuid=..., block=..., commitments=False)`, held
  behind a query adapter that exposes only `open`, `sync`, and `close`
- `bt.http_auth.sign` / `bt.http_auth.verify` with a durable `NonceStore`; neuron
  code requests typed HTTP signatures through the facade rather than receiving
  an SDK `Signer`
- `bt.resolve_signer(..., role="hotkey")` inside the facade for
  Wallet/Keypair-compatible btauth and service-binding signatures
- `bt.sp_core` keypairs for deterministic mock identities and signature verification
- only behind the external weight-signer protocol, `bt.SetWeights(netuid=..., uids=...,
  weights=..., version_key=2)` and async
  `client.execute(intent, wallet, retries=0, wait_for_inclusion=True,
  wait_for_finalization=True)`

`bt.SetWeights` and `Subtensor.execute` remain absent from both long-running
neurons and the shared chain query adapter. The live query adapter has no public
`client`, `wallet`, or `signer` member, and the facade does not implement
`bittensor.Signer` or expose a general `sign(payload)` method. This blocks the
former ordinary daemon call path
`adapter.client.execute(SetWeights(...), adapter.wallet)`. The wallet-free
executor can send only one canonical digest request over a peer-UID-pinned Unix
socket. The separately privileged one-shot signer independently reloads the
plan, derives the current vector, checks both digests, and constructs its wallet
and client only after its own durable in-progress receipt.

The inspected v11.1 `SetWeights` intent preflights registration and rate limit,
conforms the supplied relative vector to current subnet min-count/max-weight
parameters, and u16-quantizes it. Its ordinary implementation auto-selects
plaintext `set_mechanism_weights` or a delayed timelocked commit. Signer v1
rejects commit-reveal at both finalized admission reads and wraps the SDK intent
so a build that returns `reveal_round` fails before signing/submission. A mode
change after the last local query can therefore cause only rejection/ambiguity,
not a delayed commit recorded as applied. The audit
execution digest covers the exact hotkey/planned-UID/current-UID/float vector
passed to that intent. It does not claim that the post-clipping u16 encoding is
byte-identical to those floats. The confirmed receipt records the SDK's included
extrinsic reference; a success without a reference is treated as ambiguous.
SDK-level retries are explicitly zero so the wrapper can make no second
submission. Any timeout/exception after entering `execute` is also ambiguous,
even when an SDK preflight may have failed before signing, because the wrapper
cannot prove that boundary from an exception alone.

The neuron facade remains API/call-path isolation, but weight execution adds an
independently privileged signer boundary: the executor process and OS account
cannot read the wallet, cannot supply arbitrary weights, and can address only
the versioned digest protocol. The signer is still software on the same host,
not a hardware device or defense against root, its own OS user, or replacement
of its binary/unit/configuration.

The current metagraph exposes a served axon as `ip:port`; it does not carry a trustworthy scheme, hostname, or CA identity. The validator treats scheme as local policy and constructs HTTPS for a live numeric endpoint. It rejects private/local/hostname targets before connection, captures the exact self-signed non-CA leaf with a bounded stdlib TLS preflight, and authenticates its fingerprint through the miner hotkey signature. Publishing the numeric endpoint is a separate `ServeAxon`/`btcli axon set` chain transaction and is intentionally not automated.

### Finality behavior inspected in v11.1

The installed v11.1 `Client` exposes finalized block subscriptions publicly and
its connected substrate transport exposes the one-shot
`get_chain_finalised_head()` and `get_block_number(hash)` RPC helpers. The
validator capability-detects those exact helpers, resolves the finalized height,
and passes it to the public block-pinned metagraph read. It verifies that the
returned graph reports the requested block. This avoids treating a moving best
head as authoritative during scheduling admission.

The transport helper is isolated behind capability detection because it is not
a top-level `Client` method. If a compatible SDK omits it, the adapter reads the
head and marks the snapshot non-finalized. `MetagraphState` then provides the
documented conservative fallback: a block lower than the admitted floor, or a
different scheduling identity fingerprint at the same block, is rejected. The
Go bridge independently applies the same block floor and same-height chain-state
conflict check before committing its staged chain/miner snapshot.

The one-shot executor is stricter than the daemon fallback: every execution
preflight requires `snapshot.finalized is True`. An SDK/transport without the
finalized helpers therefore cannot execute a WeightPlan. It performs a second
finalized metagraph read immediately before the durable send boundary and
requires the same adjusted execution digest; a relevant UID/hotkey/permit race
fails before `client.execute`.

## Why there are no SDK Axon/Dendrite/Synapse objects

Bittensor v11 intentionally removed the legacy neuron networking stack and raises a migration error for `bittensor.axon`, `bittensor.dendrite`, and `bittensor.synapse`. The official guidance recommends framework-neutral HTTP with btauth/1 signed requests. This project follows that model:

- Pydantic models retain the subnet-level “Synapse” semantics and versioning;
- FastAPI/Uvicorn is the miner axon HTTPS role with validated operator-provided
  certificate/key material;
- stdlib `asyncio`/`ssl` performs leaf capture and httpx uses exact-leaf trust
  for the validator dendrite/fanout role; and
- btauth/1 supplies hotkey request authentication and replay/freshness checks.

This avoids pinning an obsolete SDK merely to preserve removed class names.

## Sources

- [Stable `bittensor` package on PyPI](https://pypi.org/project/bittensor/)
- [Official v11 migration content](https://www.bittensor.com/llms.mdx/docs/migration/content.md)
- [Official signed-request content](https://www.bittensor.com/llms.mdx/docs/guides/signed-requests/content.md)
- [Official subnet template repository](https://github.com/opentensor/bittensor-subnet-template)
- Installed v11 API docstrings/types, exercised by the no-chain Python unit tests

Network behavior is not inferred from a successful live call: live-chain tests
remain opt-in. Executor tests use offline chain/submitter doubles and this change
does not contact or mutate any subtensor.
