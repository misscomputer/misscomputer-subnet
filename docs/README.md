# Documentation

## Start here

| I want to... | Read |
| --- | --- |
| Install the software and check it works locally | [getting-started.md](getting-started.md) |
| Handle wallets, TLS keys, bridge secrets, and probe seeds safely | [keys-and-secrets.md](keys-and-secrets.md) |
| Run a miner | [miner-quickstart.md](miner-quickstart.md) |
| Run an independent validator | [validator-quickstart.md](validator-quickstart.md) |
| Fix an error message | [troubleshooting.md](troubleshooting.md) |

The quickstarts mark every step as **local** (safe to run anywhere, no
transactions) or **live** (reads or writes the chain, or serves the internet).
Commands use placeholders such as `<NETUID>` and `<hotkey-ss58>`; this
repository does not publish production hosts, credentials, or a testnet
deployment.

## Operator runbooks

| Topic | Document |
| --- | --- |
| Validator hidden probes and window close, full flag and state semantics | [public-validator-live-probe-runbook.md](public-validator-live-probe-runbook.md) |
| Offline verification of the signed central score checkpoint | [signed-score-checkpoint-relay-runbook.md](signed-score-checkpoint-relay-runbook.md) |
| Third-party verifier SDK path and restart/backup rules | [third-party-verifier-relay-runbook.md](third-party-verifier-relay-runbook.md) |
| WeightPlan read-only preflight and reconciliation of uncertain attempts | [weight-reconciliation.md](weight-reconciliation.md) |
| Submitting weights with the one-shot standalone signer | [weight-signer-runbook.md](weight-signer-runbook.md) |
| Offline production release verification | [production-release-verifier-runbook.md](production-release-verifier-runbook.md) |

## Design and contracts

| Topic | Document |
| --- | --- |
| Wire protocol, identity binding, TLS pinning, loopback bridge | [protocol.md](protocol.md) |
| How the miner agent runs an assignment (OCI, isolation, cleanup) | [miner-oci-runtime.md](miner-oci-runtime.md) |
| Static sites on the miner (verify-then-serve, shared handler; off by default) | [miner-static-sites.md](miner-static-sites.md) |
| Static temporary origin: verify-then-listen process contract (development) | [static-origin.md](static-origin.md) |
| Organic deployment contracts and sources of truth | [organic-contracts.md](organic-contracts.md) |
| What the score measures and how probes are attributed | [organic-availability-scoring.md](organic-availability-scoring.md) |
| Hidden-probe design | [public-validator-live-probe.md](public-validator-live-probe.md) |
| Static-site index ingestion, admission crawl, and hidden probes (development) | [static-site-validator-probe.md](static-site-validator-probe.md) |
| Static-site scoring, durable evidence, quarantine and alert records (development) | [static-site-scoring.md](static-site-scoring.md) |
| Signed score checkpoint design | [signed-score-checkpoint-relay.md](signed-score-checkpoint-relay.md) |
| Release integrity contracts | [production-release-integrity.md](production-release-integrity.md) |
| Bittensor SDK version and API choices | [sdk-compatibility.md](sdk-compatibility.md) |

JSON Schemas and golden fixtures for every contract live in
[`../contracts/schemas`](../contracts/schemas) and
[`../contracts/fixtures`](../contracts/fixtures).
