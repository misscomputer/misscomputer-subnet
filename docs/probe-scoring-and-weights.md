# From verified probe reports to a weight vector

## What this closes

[`public-validator-live-probe.md`](public-validator-live-probe.md) ends by
stating what a `validator-probe-report` is not: "not a score, not a weight, and
not an authorization to submit anything". That was accurate — the probe was a
standalone audit tool, and nothing in the validator neuron consumed it.

`probe_scoring` is the bridge. It accumulates verified reports across a scoring
window and derives one weight vector over the registered miner set, which is
handed to the existing `weight_plan.build_weight_plan`. No new path to the
chain is introduced; submission remains exactly the plan/executor flow that
already exists.

## Why a window, not a single report

The public probe issues one untargeted request per deployment, and the central
edge round-robins it across that deployment's healthy replicas. One request
therefore attributes exactly one replica — this is the second entry under
"Known limitations" in the probe design document, and it is deliberate:
targeted replica selection is offered only to the central, credentialed probe.

Scoring a three-replica deployment from a single report would score whichever
miner happened to answer and silently zero its two healthy peers. Only repeated
probing covers the replica set. So the scorer consumes many rounds and compares
what it actually observed against what fair round-robin predicts.

Operationally, a validator runs the existing `misscomputer-assignment-probe`
CLI on an interval across the window. Each run verifies the current manifest and
archives one report. At the window boundary the archived `(manifest, report)`
pairs become `ProbeRound` values and are scored in one pass.

## The scoring rule

For each observation, every replica the manifest published for that deployment
accrues one **opportunity** and its round-robin share, `1 / replica_count`, of
one **expected attribution**. When the observation is `serving`, the miner named
by its verified attestation accrues one **attribution**.

```
coverage       = min(1, attributions / expected_attributions)
latency_factor = 1 if mean_latency <= target else target / mean_latency
score          = attributions × latency_factor × coverage
```

Attributions are the primary term, because a miner cannot be attributed without
a valid Ed25519 attestation over the exact published challenge digest — the
volume of proven serving is the thing that cannot be faked. Coverage is the
reliability term: a miner that stays published but stops answering keeps
accruing expected attributions while its observed count stalls, so its score
falls. The final vector is each miner's share of the total.

Worked example, one three-replica deployment probed 19 times, where `MinerA`
goes dark after round 9:

| Miner | opportunities | attributions | expected | coverage | weight |
| --- | --- | --- | --- | --- | --- |
| MinerA | 19 | 3 | 19/3 | 9/19 | 0.082 |
| MinerB | 19 | 8 | 19/3 | 1 | 0.459 |
| MinerC | 19 | 8 | 19/3 | 1 | 0.459 |

Had all three served the whole window they would each hold `0.333`.

## Zero is the default

Every registered miner appears in the vector exactly once. A miner that never
appeared in a manifest, or never produced a verified attested serving
observation, is emitted at exactly `0.0`.

`build_weight_plan` drops zero rows when it normalizes, and refuses a plan with
no positive target at all. That refusal is the correct outcome: a validator
that observed no proven serving must not submit weights.

Two identities must never enter the registered set — the validator's own
hotkey, and any inactive neuron. `build_weight_plan` rejects a row naming
either, and it checks that *before* it looks at the weight, so a zero row is not
a safe way to mention them. `build_probe_weight_vector` rejects them up front.

## Independence and determinism

Every input is the validator's own probe output or the finalized metagraph. No
other validator's data participates, so each validator scores independently and
the chain reconciles under ordinary Yuma consensus.

Accumulation is exact rational arithmetic; floating point appears only where a
row is handed to the weight plan. Two validators that observed the same serving
behaviour therefore compute bit-identical scores, and reordering the reports
cannot change the result.

`probe_scoring.py` holds the same purity boundary as `assignment_probe.py`: no
clock, network, file, process, environment, wallet, chain, randomness, or
signing capability, enforced by a source scan in the test suite. A scorer that
could read a clock or reach the chain could make two validators disagree for
reasons unrelated to what either observed.

## Fail-closed inputs

A window is refused outright, rather than silently scored, when a report names
a different validator, falls outside the window bounds, is paired with a
manifest it did not probe, repeats an already-counted report digest (a replay —
genuine probes bind fresh nonces, so an exact repeat cannot occur naturally),
attributes a miner the manifest never published for that deployment, or binds
one UID to two hotkeys inside the window.

## Not wired to the neuron yet

This module is the computation, and it is complete and tested. Deciding *when*
a validator closes a window and submits — the epoch boundary policy in
`checkpoint_boundary.py`, and the operator's opt-in to weighting from probe
evidence at all — is a separate change against the neuron's run loop.

The question of *whether* a closed window's vector may become a plan at all —
abstain on an invalid or missing manifest, abstain on insufficient sampling,
zero only under safe preconditions, no transaction without positive evidence,
activation grace — is frozen separately in
[`contract-checkpoint-v1.md`](contract-checkpoint-v1.md) and implemented by
`validator_decision.decide_weight_submission`, whose sealed record is the only
input the neuron will hand to `build_weight_plan`.
