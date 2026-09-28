# Miss Computer Subnet

Public miner, validator, checkpoint-verification, and weight-relay software for
the Miss Computer Bittensor subnet. This repository is prepared as a clean
snapshot from the private provenance archive; it contains no source history or
operator infrastructure.

The software is licensed under `AGPL-3.0-only`. Operational secrets, central
scoring policy and implementation, the operator's own signer/executor
deployment, production host topology, cloud configuration, and private runbooks
are intentionally absent. The standalone weight signer for independent
validators is public (see [`docs/weight-signer-runbook.md`](docs/weight-signer-runbook.md)).

## Quickstart

| Goal | Guide |
| --- | --- |
| Install and verify locally (no wallet or network needed) | [`docs/getting-started.md`](docs/getting-started.md) |
| Handle wallets, TLS keys, and secrets safely | [`docs/keys-and-secrets.md`](docs/keys-and-secrets.md) |
| Run a miner | [`docs/miner-quickstart.md`](docs/miner-quickstart.md) |
| Run an independent validator | [`docs/validator-quickstart.md`](docs/validator-quickstart.md) |
| Diagnose an error | [`docs/troubleshooting.md`](docs/troubleshooting.md) |
| Browse all documentation | [`docs/README.md`](docs/README.md) |

```bash
git clone https://github.com/misscomputer/misscomputer-subnet.git
cd misscomputer-subnet
python3.12 -m venv .venv && . .venv/bin/activate
python -m pip install -e .
go build -o build/miner-agent ./cmd/miner-agent   # miners only; needs Go 1.23
```

## Repository overview

`cmd/miner-agent` is the miner's Go agent. The validator neuron verifies
assignments and communicates with miners over the public synapse and bridge
protocols. Scheduling, route assignment, edge serving, the customer CLI, and
their release pipelines are operator-owned and maintained outside this
repository.
The Python distribution provides the miner and validator neurons,
checkpoint verification, weight execution, the separately privileged one-shot
`misscomputer-weight-signer` (see `docs/weight-signer-runbook.md`), the online
`misscomputer-assignment-probe` public-validator hidden probes of organic app
assignments (see `docs/public-validator-live-probe.md` and
`docs/organic-availability-scoring.md`), and
the one-shot `misscomputer-python-boundary` /
`misscomputer-checkpoint-boundary` commands. The complete generic third-party
catch-up, live-head, sealed-decision, and dry-run WeightPlan route is documented
in [`docs/third-party-verifier-relay-runbook.md`](docs/third-party-verifier-relay-runbook.md).

Current miner and verifier wire contracts are documented in
[`docs/protocol.md`](docs/protocol.md),
[`docs/organic-contracts.md`](docs/organic-contracts.md), and
[`docs/organic-availability-scoring.md`](docs/organic-availability-scoring.md).
Historical operator migration and publication records remain in the private
provenance archive, not in this public-source snapshot.
