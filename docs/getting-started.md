# Getting started

This page gets a fresh machine from `git clone` to a verified local install.
Everything here runs locally; nothing on this page registers a key, spends
TAO, or sends a transaction. Role-specific steps continue in the
[miner quickstart](miner-quickstart.md) and the
[validator quickstart](validator-quickstart.md).

## What runs where

| Step | Where it runs | Touches a live network? |
| --- | --- | --- |
| Install, lint, unit tests | your machine | no |
| Mock-mode miner smoke test (below) | your machine, loopback only | no |
| Read-only chain check (below) | your machine | reads public chain state only |
| Wallet creation | your machine | no |
| Hotkey registration, `btcli axon set` | your machine | **yes: sends transactions** |
| Miner or validator services | your server | **yes** |

## Prerequisites

| Requirement | Version | Why |
| --- | --- | --- |
| Linux, x86_64 | any current distribution | Miner workloads run as `linux/amd64` containers; the miner TLS loader uses `memfd_create`, which is Linux-only |
| Python | **3.12 exactly** (`requires-python = "==3.12.*"`) | Python neurons and CLIs |
| Go | 1.23.x (`go.mod` toolchain `go1.23.12`) | Builds the miner's Go agent (miners only) |
| `git`, `openssl`, `curl`, `sha256sum` | any | Install, TLS certificates, health checks, digests |
| Docker Engine and `iptables` | current | Miners only: runs assigned workloads; see the miner guide |
| `btcli` (package `bittensor-cli`) | current | Wallet creation and registration; installed separately from this repository |

The Python package pins its runtime dependencies exactly, including
`bittensor==11.1.0`. Install it into its own virtual environment so those pins
do not collide with other Bittensor tooling on the same host. Install `btcli`
into a separate environment for the same reason.

## Install

```bash
git clone https://github.com/misscomputer/misscomputer-subnet.git
cd misscomputer-subnet

python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
python -m pip check
```

`python -m pip check` should print `No broken requirements found.`

The install adds these console scripts to `.venv/bin`:

| Command | Who uses it | Purpose |
| --- | --- | --- |
| `misscomputer-miner` | miners | Public HTTPS miner axon; talks to the local Go agent |
| `misscomputer-assignment-probe` | validators | One five-minute epoch of hidden organic probes |
| `misscomputer-organic-window` | validators | Seals a window decision and, when eligible, a WeightPlan |
| `misscomputer-score-checkpoint-relay` | validators | Offline verification of a signed central score checkpoint |
| `misscomputer-weight-executor` | validators | Read-only WeightPlan preflight; gated submission path |
| `misscomputer-weight-reconcile` | validators | Read-only reconciliation of an uncertain weight attempt |
| `misscomputer-validator` | subnet operator | Long-running validator bridge; needs an operator-owned Go control service (see the validator guide) |
| `misscomputer-release-verify` | release auditors | Offline production release verification |
| `misscomputer-python-boundary`, `misscomputer-checkpoint-boundary` | tooling | One-shot request/response process boundaries |

`misscomputer-miner`, `misscomputer-validator`, `misscomputer-weight-executor`,
`misscomputer-weight-reconcile`, and `misscomputer-release-verify` print normal
`--help` output. The hardened validator CLIs (`misscomputer-assignment-probe`,
`misscomputer-organic-window`, `misscomputer-score-checkpoint-relay`)
deliberately never echo arguments: `--help` prints only `REJECTED usage` and
exits `64`. Their flags are documented in the validator guide and runbooks.

Miners also build the Go agent:

```bash
go build -o build/miner-agent ./cmd/miner-agent
./build/miner-agent -h
```

`build/` is ignored by git.

## Run the repository checks (optional, local)

These are the same checks CI runs. They need the development extras:

```bash
python -m pip install -e '.[dev]'
ruff check src tests
ruff format --check src tests
mypy src
pytest -q
go vet ./...
go test ./...
./scripts/check-public-boundary.sh
./scripts/check-repository-secrets.sh
python scripts/check-release-metadata.py
```

No test contacts a live chain. Two Go integration tests are opt-in and skipped
by default: the real-engine Docker test needs `MISSCOMPUTER_DOCKER_OCI_TEST=1`
and root (see [`miner-oci-runtime.md`](miner-oci-runtime.md)), and the S3
store test runs only when `MINIO_ENDPOINT` and its companion variables point
at a disposable local test store.

## Local smoke test: mock-mode miner

This starts only the Python miner axon against an in-process mock chain, on
loopback, over plain HTTP. It needs no wallet, no Go agent, no Docker, and no
network access. It proves the install works and shows what healthy logs look
like.

```bash
mkdir -p /tmp/mc-smoke && cd /tmp/mc-smoke
(umask 077; openssl rand -hex 32 > bridge.secret)

cat > peers.json <<'EOF'
[
  {"uri": "//Alice", "uid": 0, "axon": "127.0.0.1:8091"},
  {"uri": "//Bob", "uid": 1, "validator_permit": true, "tao_stake": 5000}
]
EOF

misscomputer-miner \
  --netuid 1 --subtensor-network mock \
  --mock-uri //Alice --mock-peers ./peers.json \
  --allow-insecure-mock-http \
  --axon-host 127.0.0.1 --axon-port 18091 \
  --bridge-secret-file ./bridge.secret \
  --state-db ./miner-nonces.sqlite
```

`//Alice` and `//Bob` are the well-known public development keys; they are not
secrets and must never hold funds. In a second terminal:

```bash
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:18091/healthz
```

Expected: `204`. The miner logs one JSON object per line on stderr, including:

```text
{"timestamp":"...","level":"info","logger":"misscomputer_subnet.miner","message":"metagraph synchronized","hotkey":"5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY","block":...}
```

Stop it with Ctrl+C. If you change `--mock-uri` to a key that is not in
`peers.json` (for example `//Charlie`), `/healthz` returns `503` and the log
shows `miner hotkey is not registered`; that is the same signal a live miner
gives before its hotkey is registered.

Mock mode is a local development aid only. `--allow-insecure-mock-http`
refuses to start without `--mock-uri`, and a live miner refuses to start
without TLS files.

## Read-only chain check

Before and after registering, confirm what the chain reports for a hotkey. This
uses the same chain adapter as the neurons, reads the finalized head, and sends
no transaction:

```bash
python - <<'EOF'
import asyncio

from misscomputer_subnet.chain import BittensorChain

NETWORK = "finney"             # or "test"
NETUID = 0                     # replace with the subnet netuid
HOTKEY = "<hotkey-ss58>"       # public address only


async def main() -> None:
    chain = BittensorChain(network=NETWORK, netuid=NETUID)
    await chain.open()
    try:
        snapshot = await chain.sync()
        print(f"block={snapshot.block} finalized={snapshot.finalized} tempo={snapshot.tempo}")
        record = snapshot.by_hotkey(HOTKEY)
        if record is None:
            print("hotkey is not registered on this subnet")
        else:
            print(
                f"uid={record.uid} active={record.active} "
                f"validator_permit={record.validator_permit} "
                f"tao_stake={record.tao_stake} axon={record.axon}"
            )
    finally:
        await chain.close()


asyncio.run(main())
EOF
```

Expected output looks like `block=<n> finalized=True tempo=<n>` followed by
either your UID line or `hotkey is not registered on this subnet`. `active`
is the chain's own flag for the record; the miner, validator discovery, and
the window coordinator only accept records where it is `True`. The
`block` value is also a convenient source for the validator probe's
`--finalized-height` when `finalized=True`.

## Networks and netuids

- The Bittensor SDK network names are `finney` (mainnet) and `test`
  (testnet). The neuron and executor commands default `--subtensor-network`
  to `BT_NETWORK` when set, otherwise `finney`; `misscomputer-organic-window`
  defaults to `finney`.
- This repository does not publish a testnet deployment or netuid. Always pass
  `--netuid` explicitly and take the value from the subnet's official
  announcements. `misscomputer-organic-window` has a built-in default of
  `--netuid 24`; pass it explicitly anyway so every command agrees.

## Next steps

- Keys and secret files: [keys-and-secrets.md](keys-and-secrets.md)
- Run a miner: [miner-quickstart.md](miner-quickstart.md)
- Run a validator: [validator-quickstart.md](validator-quickstart.md)
- Something failed: [troubleshooting.md](troubleshooting.md)
