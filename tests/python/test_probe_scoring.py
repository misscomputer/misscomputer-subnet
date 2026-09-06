# SPDX-License-Identifier: AGPL-3.0-only

"""Scoring a window of verified probe reports into a weight vector."""

from __future__ import annotations

import ast
import hashlib
from collections.abc import Sequence
from pathlib import Path

import pytest
from assignment_probe_context import (
    BASE_EPOCH,
    MINERS,
    ROOT,
    build_deployment,
    build_manifest,
    build_policy,
    make_context,
    serving_response,
    sign_attestation,
    sign_manifest,
    signer_keys,
)

from misscomputer_subnet.assignment_probe import (
    ActiveAssignmentManifest,
    ActiveDeploymentAssignment,
    AssignmentManifestTrustPolicy,
    ProbeTransportFailure,
    ValidatorProbeReport,
    build_initial_manifest_chain_state,
    build_validator_probe_report,
    evaluate_probe_response,
    verify_active_assignment_manifest,
)
from misscomputer_subnet.probe_scoring import (
    ProbeRound,
    ProbeScoringError,
    ProbeScoringPolicy,
    RegisteredMiner,
    accumulate_scoring_window,
    build_probe_weight_vector,
    score_probe_rounds,
)
from misscomputer_subnet.weight_plan import WeightPlanError, build_weight_plan

VALIDATOR_UID = 7
VALIDATOR_HOTKEY = "ValidatorSelf"
WINDOW_START = BASE_EPOCH
WINDOW_END = BASE_EPOCH + 3_600


def nonce_for(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def build_round(
    policy: AssignmentManifestTrustPolicy,
    manifest: ActiveAssignmentManifest,
    *,
    responders: dict[str, str | None],
    label: str,
    evaluation_epoch: int,
    latency_millis: int = 42,
    keys: dict[str, object] | None = None,
) -> ProbeRound:
    """Probe every deployment once, letting ``responders`` pick who answered.

    A ``None`` responder models a deployment that did not serve at all, which
    is exactly what a validator sees when the route is down: the report names
    no miner, because an unanswered request attributes nobody.
    """

    signing_keys = keys if keys is not None else signer_keys()
    state = build_initial_manifest_chain_state(policy)
    verification = verify_active_assignment_manifest(
        manifest,
        sign_manifest(manifest, signing_keys),
        policy,
        state,
        evaluation_epoch=evaluation_epoch,
    )
    observations = []
    for deployment in manifest.deployments:
        probe_nonce = nonce_for(f"{label}-{deployment.deployment_id}")
        responder = responders.get(deployment.deployment_id)
        if responder is None:
            result: object = ProbeTransportFailure(code="timeout", latency_millis=latency_millis)
        else:
            replica = next(item for item in deployment.replicas if item.miner_hotkey == responder)
            attestation = sign_attestation(deployment, replica, probe_nonce=probe_nonce)
            result = serving_response(
                deployment, attestation=attestation, latency_millis=latency_millis
            )
        observations.append(
            evaluate_probe_response(deployment, policy, probe_nonce=probe_nonce, result=result)
        )
    report = build_validator_probe_report(
        verification,
        policy,
        state,
        observations,
        validator_uid=VALIDATOR_UID,
        validator_hotkey=VALIDATOR_HOTKEY,
        evaluation_epoch=evaluation_epoch,
        edge_origin_override=False,
    )
    return ProbeRound(manifest=manifest, report=report)


def single_deployment_context() -> tuple[AssignmentManifestTrustPolicy, ActiveAssignmentManifest]:
    """One three-replica deployment served by MinerA, MinerB and MinerC."""

    policy = build_policy(signer_keys())
    deployment = build_deployment("fixture-alpha", MINERS[:3], campaign_sequence=1)
    return policy, build_manifest(policy, [deployment])


def registered(*, include: Sequence[tuple[int, str]] = MINERS) -> list[RegisteredMiner]:
    return [RegisteredMiner(uid=uid, hotkey=hotkey) for uid, hotkey in include]


def rotate(
    policy: AssignmentManifestTrustPolicy,
    manifest: ActiveAssignmentManifest,
    hotkeys: Sequence[str],
    *,
    rounds: int,
    start: int = 0,
    latency_millis: int = 42,
) -> list[ProbeRound]:
    """Probe ``rounds`` times, round-robining the responder across ``hotkeys``."""

    deployment_id = manifest.deployments[0].deployment_id
    return [
        build_round(
            policy,
            manifest,
            responders={deployment_id: hotkeys[index % len(hotkeys)]},
            label=f"round-{start + index}",
            evaluation_epoch=WINDOW_START + start + index,
            latency_millis=latency_millis,
        )
        for index in range(rounds)
    ]


def score(
    rounds: Sequence[ProbeRound],
    *,
    include: Sequence[tuple[int, str]] = MINERS,
    policy: ProbeScoringPolicy | None = None,
) -> dict[str, float]:
    vector = score_probe_rounds(
        rounds,
        validator_uid=VALIDATOR_UID,
        validator_hotkey=VALIDATOR_HOTKEY,
        window_start_epoch=WINDOW_START,
        window_end_epoch=WINDOW_END,
        registered=registered(include=include),
        policy=policy,
    )
    return {row.hotkey: row.weight for row in vector.rows}


def test_every_registered_uid_defaults_to_zero() -> None:
    policy, manifest = single_deployment_context()
    # MinerD is registered but is not a replica of the only deployment, so it
    # never appears in any manifest and must never earn weight.
    weights = score(rotate(policy, manifest, ["MinerA", "MinerB", "MinerC"], rounds=9))
    assert set(weights) == {hotkey for _, hotkey in MINERS}
    assert weights["MinerD"] == 0.0
    assert all(weights[hotkey] > 0.0 for hotkey in ("MinerA", "MinerB", "MinerC"))


def test_miner_absent_from_every_manifest_stays_at_zero() -> None:
    policy, manifest = single_deployment_context()
    rounds = rotate(policy, manifest, ["MinerA", "MinerB", "MinerC"], rounds=6)
    window = accumulate_scoring_window(
        rounds,
        validator_uid=VALIDATOR_UID,
        validator_hotkey=VALIDATOR_HOTKEY,
        window_start_epoch=WINDOW_START,
        window_end_epoch=WINDOW_END,
    )
    assert window.tally_for("MinerD") is None
    vector = build_probe_weight_vector(window, registered=registered())
    row = next(item for item in vector.rows if item.hotkey == "MinerD")
    assert row.weight == 0.0
    assert row.attributions == 0
    assert row.opportunities == 0
    assert "MinerD" not in {item.hotkey for item in vector.scored_rows}


def test_equal_serving_replicas_receive_equal_weight() -> None:
    policy, manifest = single_deployment_context()
    weights = score(rotate(policy, manifest, ["MinerA", "MinerB", "MinerC"], rounds=9))
    served = [weights[hotkey] for hotkey in ("MinerA", "MinerB", "MinerC")]
    assert served[0] == served[1] == served[2]
    assert sum(weights.values()) == pytest.approx(1.0)


def test_miner_that_stops_serving_mid_window_scores_lower() -> None:
    policy, manifest = single_deployment_context()
    # First half: all three replicas answer their share.
    first_half = rotate(policy, manifest, ["MinerA", "MinerB", "MinerC"], rounds=9)
    # Second half: MinerA has gone dark. It stays published as a replica, so it
    # keeps accruing opportunity, but the edge only ever routes to its peers.
    second_half = rotate(policy, manifest, ["MinerB", "MinerC"], rounds=10, start=9)
    weights = score([*first_half, *second_half])

    assert weights["MinerA"] > 0.0, "a miner that served for half the window is not a zero"
    assert weights["MinerA"] < weights["MinerB"]
    assert weights["MinerA"] < weights["MinerC"]

    # The same miner scored strictly higher when it served the whole window.
    healthy = score(first_half)
    assert weights["MinerA"] < healthy["MinerA"]


def test_miner_dark_for_the_whole_window_scores_zero() -> None:
    policy, manifest = single_deployment_context()
    # MinerA is a published replica for every round but never answers one.
    weights = score(rotate(policy, manifest, ["MinerB", "MinerC"], rounds=10))
    assert weights["MinerA"] == 0.0
    assert weights["MinerB"] > 0.0 and weights["MinerC"] > 0.0

    window = accumulate_scoring_window(
        rotate(policy, manifest, ["MinerB", "MinerC"], rounds=10),
        validator_uid=VALIDATOR_UID,
        validator_hotkey=VALIDATOR_HOTKEY,
        window_start_epoch=WINDOW_START,
        window_end_epoch=WINDOW_END,
    )
    dark = window.tally_for("MinerA")
    assert dark is not None
    # It had every opportunity and took none of them.
    assert dark.opportunities == 10
    assert dark.attributions == 0
    assert dark.coverage() == 0


def test_deployment_that_stops_serving_zeroes_all_of_its_replicas() -> None:
    policy, manifest = single_deployment_context()
    deployment_id = manifest.deployments[0].deployment_id
    rounds = [
        build_round(
            policy,
            manifest,
            responders={deployment_id: None},
            label=f"down-{index}",
            evaluation_epoch=WINDOW_START + index,
        )
        for index in range(5)
    ]
    window = accumulate_scoring_window(
        rounds,
        validator_uid=VALIDATOR_UID,
        validator_hotkey=VALIDATOR_HOTKEY,
        window_start_epoch=WINDOW_START,
        window_end_epoch=WINDOW_END,
    )
    assert window.serving_observation_count == 0
    vector = build_probe_weight_vector(window, registered=registered())
    assert all(row.weight == 0.0 for row in vector.rows)
    # A validator with no proven serving must not be able to submit anything.
    assert vector.scored_rows == ()


def test_slower_miner_scores_below_an_equally_available_fast_one() -> None:
    policy, manifest = single_deployment_context()
    deployment_id = manifest.deployments[0].deployment_id
    rounds: list[ProbeRound] = []
    for index in range(8):
        responder = "MinerA" if index % 2 == 0 else "MinerB"
        rounds.append(
            build_round(
                policy,
                manifest,
                responders={deployment_id: responder},
                label=f"latency-{index}",
                evaluation_epoch=WINDOW_START + index,
                latency_millis=50 if responder == "MinerA" else 4_000,
            )
        )
    weights = score(rounds, policy=ProbeScoringPolicy(latency_target_millis=1_000))
    assert weights["MinerA"] > weights["MinerB"] > 0.0


def test_scoring_is_independent_of_report_order() -> None:
    policy, manifest = single_deployment_context()
    rounds = rotate(policy, manifest, ["MinerA", "MinerB", "MinerC"], rounds=7)
    forward = score(rounds)
    reverse = score(list(reversed(rounds)))
    # Exact equality, not approximate: accumulation is rational, not floating.
    assert forward == reverse


def test_weight_vector_feeds_the_existing_weight_plan() -> None:
    pytest.importorskip("misscomputer_subnet.chain")
    from misscomputer_subnet.chain import MetagraphSnapshot, NeuronRecord

    policy, manifest = single_deployment_context()
    rounds = rotate(policy, manifest, ["MinerA", "MinerB", "MinerC"], rounds=9)
    vector = score_probe_rounds(
        rounds,
        validator_uid=VALIDATOR_UID,
        validator_hotkey=VALIDATOR_HOTKEY,
        window_start_epoch=WINDOW_START,
        window_end_epoch=WINDOW_END,
        registered=registered(),
    )
    neurons = [
        NeuronRecord(
            uid=VALIDATOR_UID,
            hotkey=VALIDATOR_HOTKEY,
            validator_permit=True,
            tao_stake=1_000.0,
            axon=None,
            active=True,
        ),
        *[
            NeuronRecord(
                uid=uid,
                hotkey=hotkey,
                validator_permit=False,
                tao_stake=1.0,
                axon="127.0.0.1:8091",
                active=True,
            )
            for uid, hotkey in MINERS
        ],
    ]
    snapshot = MetagraphSnapshot(
        network="finney",
        netuid=24,
        block=1_000,
        tempo=100,
        neurons=tuple(neurons),
        finalized=True,
    )
    plan = build_weight_plan(
        snapshot=snapshot,
        validator_hotkey=VALIDATOR_HOTKEY,
        rows=vector.weight_plan_rows(),
        version_key=1,
    )
    # The zero rows are dropped by the plan; only proven servers survive.
    assert {entry.hotkey for entry in plan.weights} == {"MinerA", "MinerB", "MinerC"}
    assert sum(entry.weight for entry in plan.weights) == pytest.approx(1.0)

    empty = build_probe_weight_vector(
        accumulate_scoring_window(
            rotate(policy, manifest, ["MinerA"], rounds=1),
            validator_uid=VALIDATOR_UID,
            validator_hotkey=VALIDATOR_HOTKEY,
            window_start_epoch=WINDOW_START,
            window_end_epoch=WINDOW_END,
        ),
        registered=registered(include=[MINERS[3]]),
    )
    with pytest.raises(WeightPlanError):
        build_weight_plan(
            snapshot=snapshot,
            validator_hotkey=VALIDATOR_HOTKEY,
            rows=empty.weight_plan_rows(),
            version_key=1,
        )


def test_scoring_rejects_untrustworthy_windows() -> None:
    policy, manifest = single_deployment_context()
    rounds = rotate(policy, manifest, ["MinerA", "MinerB", "MinerC"], rounds=3)

    with pytest.raises(ProbeScoringError, match="scoring_rounds_empty"):
        accumulate_scoring_window(
            [],
            validator_uid=VALIDATOR_UID,
            validator_hotkey=VALIDATOR_HOTKEY,
            window_start_epoch=WINDOW_START,
            window_end_epoch=WINDOW_END,
        )
    with pytest.raises(ProbeScoringError, match="scoring_window_invalid"):
        accumulate_scoring_window(
            rounds,
            validator_uid=VALIDATOR_UID,
            validator_hotkey=VALIDATOR_HOTKEY,
            window_start_epoch=WINDOW_END,
            window_end_epoch=WINDOW_START,
        )
    # Replaying one report would let a single observation be spent twice.
    with pytest.raises(ProbeScoringError, match="scoring_report_duplicate"):
        accumulate_scoring_window(
            [*rounds, rounds[0]],
            validator_uid=VALIDATOR_UID,
            validator_hotkey=VALIDATOR_HOTKEY,
            window_start_epoch=WINDOW_START,
            window_end_epoch=WINDOW_END,
        )
    with pytest.raises(ProbeScoringError, match="scoring_report_outside_window"):
        accumulate_scoring_window(
            rounds,
            validator_uid=VALIDATOR_UID,
            validator_hotkey=VALIDATOR_HOTKEY,
            window_start_epoch=WINDOW_START + 10_000,
            window_end_epoch=WINDOW_START + 20_000,
        )
    with pytest.raises(ProbeScoringError, match="scoring_report_identity_mismatch"):
        accumulate_scoring_window(
            rounds,
            validator_uid=VALIDATOR_UID + 1,
            validator_hotkey=VALIDATOR_HOTKEY,
            window_start_epoch=WINDOW_START,
            window_end_epoch=WINDOW_END,
        )
    # A report paired with a manifest it did not probe cannot be scored.
    other = build_manifest(
        policy, [build_deployment("fixture-beta", MINERS[1:], campaign_sequence=2)]
    )
    with pytest.raises(ProbeScoringError, match="scoring_manifest_mismatch"):
        accumulate_scoring_window(
            [ProbeRound(manifest=other, report=rounds[0].report)],
            validator_uid=VALIDATOR_UID,
            validator_hotkey=VALIDATOR_HOTKEY,
            window_start_epoch=WINDOW_START,
            window_end_epoch=WINDOW_END,
        )


def test_weight_vector_rejects_unusable_registered_sets() -> None:
    policy, manifest = single_deployment_context()
    window = accumulate_scoring_window(
        rotate(policy, manifest, ["MinerA", "MinerB", "MinerC"], rounds=3),
        validator_uid=VALIDATOR_UID,
        validator_hotkey=VALIDATOR_HOTKEY,
        window_start_epoch=WINDOW_START,
        window_end_epoch=WINDOW_END,
    )
    with pytest.raises(ProbeScoringError, match="scoring_registered_duplicate"):
        build_probe_weight_vector(window, registered=[*registered(), registered()[0]])
    # build_weight_plan refuses any row naming the validator, zero or not, so
    # the validator must never enter the registered set.
    with pytest.raises(ProbeScoringError, match="scoring_registered_duplicate"):
        build_probe_weight_vector(
            window,
            registered=[
                *registered(),
                RegisteredMiner(uid=VALIDATOR_UID, hotkey=VALIDATOR_HOTKEY),
            ],
        )


def test_context_fixture_report_scores_its_attested_miner() -> None:
    """The committed probe fixtures score without any bespoke construction."""

    context = make_context()
    window = accumulate_scoring_window(
        [ProbeRound(manifest=context.manifest, report=context.report)],
        validator_uid=context.report.validator_uid,
        validator_hotkey=context.report.validator_hotkey,
        window_start_epoch=context.report.evaluation_epoch,
        window_end_epoch=context.report.evaluation_epoch + 1,
    )
    attested = context.attestation.miner_hotkey
    tally = window.tally_for(attested)
    assert tally is not None and tally.attributions >= 1


def test_source_is_a_pure_offline_scoring_core() -> None:
    """Scoring must not acquire a clock, a network, a wallet, or the chain.

    ``assignment_probe`` holds the same boundary. A scorer that could read a
    clock or reach the chain could make two validators disagree for reasons
    that have nothing to do with what either observed.
    """

    source = (ROOT / "src" / "misscomputer_subnet" / "probe_scoring.py").read_text()
    tree = ast.parse(source)
    imported_roots: set[str] = set()
    called_names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_roots.update(alias.name.split(".", maxsplit=1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            imported_roots.add(node.module.split(".", maxsplit=1)[0])
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                called_names.add(node.func.id)
            elif isinstance(node.func, ast.Attribute):
                called_names.add(node.func.attr)
    assert imported_roots <= {
        "__future__",
        "assignment_probe",
        "collections",
        "dataclasses",
        "fractions",
        "pydantic",
        "typing",
    }
    assert not called_names & {
        "Popen",
        "connect",
        "create_subprocess_exec",
        "getenv",
        "monotonic",
        "now",
        "open",
        "request",
        "run",
        "set_weights",
        "sign",
        "submit",
        "system",
        "time",
        "urlopen",
        "write_bytes",
        "write_text",
    }
    lowered = source.lower()
    for forbidden in (
        "import bittensor",
        "import datetime",
        "import httpx",
        "import os",
        "import random",
        "import requests",
        "import socket",
        "import subprocess",
        "import time",
        "os.environ",
        "wallet.",
    ):
        assert forbidden not in lowered, forbidden


def test_scoring_module_is_discoverable_from_the_repository_root() -> None:
    assert (Path(ROOT) / "src" / "misscomputer_subnet" / "probe_scoring.py").is_file()


def test_unpublished_attribution_is_refused() -> None:
    """Credit is only ever given to an identity the manifest published."""

    policy, manifest = single_deployment_context()
    round_one = rotate(policy, manifest, ["MinerA"], rounds=1)[0]
    # Re-point the round at a manifest whose replica set excludes MinerA while
    # keeping the same deployment identity, so the attestation names a miner
    # that this manifest never published.
    foreign_deployment: ActiveDeploymentAssignment = build_deployment(
        "fixture-alpha", MINERS[1:], campaign_sequence=1
    )
    foreign: ActiveAssignmentManifest = build_manifest(policy, [foreign_deployment])
    report: ValidatorProbeReport = round_one.report
    with pytest.raises(ProbeScoringError, match="scoring_manifest_mismatch"):
        accumulate_scoring_window(
            [ProbeRound(manifest=foreign, report=report)],
            validator_uid=VALIDATOR_UID,
            validator_hotkey=VALIDATOR_HOTKEY,
            window_start_epoch=WINDOW_START,
            window_end_epoch=WINDOW_END,
        )
