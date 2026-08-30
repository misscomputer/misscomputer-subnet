# Miss Computer Subnet

Public miner, validator, checkpoint-verification, and weight-relay software for
the Miss Computer Bittensor subnet. This repository is prepared as a clean
snapshot from the private provenance archive; it contains no source history or
operator infrastructure.

The software is licensed under `AGPL-3.0-only`. Operational secrets, central
scoring policy and implementation, signer/executor operations, production host
topology, cloud configuration, and private runbooks are intentionally absent.

`cmd/misscomputer-runtime` is the validator's Go runtime. It owns finalized
chain and miner-set admission, three-replica scheduling, the signed edge route
authority and provider-neutral edge origin, health actions, dry-run weight
preparation, restart recovery, and the optional synthetic campaign
(`pkg/controlplane`), and serves that control plane over a local Unix socket
(`misscomputer.runtime.v1`, `pkg/runtimeapi`) to whichever authenticated
front-end an operator runs in front of it. `cmd/miner-agent` is the miner's Go
agent. The Python distribution provides the miner and validator neurons,
checkpoint verification, weight execution, the online
`misscomputer-assignment-probe` public-validator liveness check of signed
active-assignment manifests (see `docs/public-validator-live-probe.md`), and
the one-shot `misscomputer-python-boundary` /
`misscomputer-checkpoint-boundary` commands.
