# SPDX-License-Identifier: AGPL-3.0-only
"""Producer/replay and fully resealed policy attacks from the next exact-SHA review."""

from __future__ import annotations

import socket
from typing import Any

import httpcore
import pytest
from assignment_probe_context import build_policy, canonical, label_digest, sign_manifest
from contract_checkpoint_context import (
    WINDOW_END,
    WINDOW_START,
    build_snapshot,
    forged_decision_with_report,
    make_window_context,
    reseal_observation,
    reseal_report_observations,
)
from pydantic import ValidationError

from misscomputer_subnet import assignment_probe as p
from misscomputer_subnet import assignment_snapshot as s
from misscomputer_subnet import probe_transport as t
from misscomputer_subnet.probe_scoring import (
    ProbeRound,
    ProbeScoringError,
    accumulate_scoring_window,
)
from misscomputer_subnet.validator_decision import (
    ValidatorWeightDecision,
    WeightDecisionError,
    decide_weight_submission,
    parse_validator_weight_decision,
    validator_weight_decision_bytes,
)


def capture(index: int) -> s.ActiveAssignmentSnapshot:
    template = build_snapshot().deployments[0].model_dump(mode="json", by_alias=True)
    original = template["replicas"][0]
    deployments = []
    for number in range(512):
        name = f"cap-{number:04}"
        replicas = []
        for miner in range(8):
            hotkey = f"Miner{miner}"
            rid = f"{name}-{hotkey}"
            nonce = label_digest(f"nonce-{index}-{number}-{miner}")[:32]
            replicas.append(
                {
                    **original,
                    "miner_uid": miner,
                    "miner_hotkey": hotkey,
                    "replica_id": rid,
                    "generation": index,
                    "assignment_nonce": nonce,
                    "endpoint_id": f"{rid}-g{index}-{nonce}",
                    "ticket_digest_sha256": label_digest(f"ticket-{index}-{number}-{miner}"),
                    "receipt_digest_sha256": label_digest(f"receipt-{index}-{number}-{miner}"),
                }
            )
        deployments.append(
            s.SnapshotDeployment.model_validate(
                {
                    **template,
                    "deployment_id": name,
                    "route_host": f"{name}.mock.local",
                    "replicas": replicas,
                }
            )
        )
    return build_snapshot(
        snapshot_sequence=index, state_revision=index + 7, snapshot_deployments=deployments
    )


def test_atomic_boundary() -> None:
    first = capture(1)
    head = s.build_initial_snapshot_lineage(
        central_authority_fingerprint_sha256=first.central_authority_fingerprint_sha256
    )
    for index in range(1, 22):
        head = s.advance_snapshot_lineage(head, first if index == 1 else capture(index))
    assert len(head.used_ticket_digests) == 86016
    candidate = capture(22)
    pending = s.begin_snapshot_lineage_era(head, retain_for=candidate)
    assert (
        s.replay_snapshot_lineage(
            head, [], era_boundaries=pending.era_boundaries, pending_candidate=candidate
        )
        == pending
    )
    with pytest.raises(s.AssignmentSnapshotError, match="snapshot_lineage_replay_work_exceeded"):
        s.replay_snapshot_lineage(
            head,
            [],
            era_boundaries=pending.era_boundaries,
            pending_candidate=candidate,
            max_work=1_000_000,
        )
    # Reach the actual fact ceiling through producer calls, not synthetic model state.
    for index in range(22, 33):
        head = s.advance_snapshot_lineage(head, capture(index))
    assert len(head.used_ticket_digests) == s.MAX_LINEAGE_FACTS
    candidate = capture(33)
    pending = s.begin_snapshot_lineage_era(head, retain_for=candidate)
    restored = s.replay_snapshot_lineage(
        head, [], era_boundaries=pending.era_boundaries, pending_candidate=candidate
    )
    assert restored == pending
    accepted = s.advance_snapshot_lineage(pending, candidate)
    assert s.replay_snapshot_lineage(pending, [candidate], boundary_mode="suffix") == accepted
    assert (
        s.replay_snapshot_lineage(
            pending, [], era_boundaries=pending.era_boundaries, pending_candidate=candidate
        )
        == pending
    )


def test_replay_ceiling_covers_every_atomic_charge() -> None:
    state = 1 + s.MAX_LINEAGE_REPLICAS + 3 * s.MAX_LINEAGE_FACTS + s.MAX_LINEAGE_ERAS - 1
    candidate = 1 + s.MAX_DEPLOYMENTS + s.MAX_LINEAGE_REPLICAS
    assert s.MAX_REPLAY_WORK == 4 * state + 3 * candidate == 1_814_787
    assert state + 3 * (state + candidate) <= s.MAX_REPLAY_WORK  # candidate boundary
    assert state + state + candidate <= s.MAX_REPLAY_WORK  # capture / pending validation
    assert state + state <= s.MAX_REPLAY_WORK  # plain boundary


def test_resealed_timeout_full_window() -> None:
    ctx = make_window_context()
    strict = build_policy(ctx.keys, max_age=3600, probe_timeout_millis=100)
    original = ctx.rounds[0]
    obs = p.evaluate_probe_response(
        original.manifest.deployments[0],
        strict,
        probe_nonce=original.report.observations[0].probe_nonce,
        result=p.ProbeTransportFailure("timeout", 101),
    )
    forged = p.ProbeObservation.model_validate(
        reseal_observation(
            {
                **obs.model_dump(mode="json", by_alias=True),
                "trust_policy_digest_sha256": ctx.policy.trust_policy_digest_sha256,
            }
        )
    )
    # Every self digest is valid. Rejection must come from the unchanged facts.
    with pytest.raises(p.AssignmentProbeError, match="observation_policy_violation"):
        p.verify_observation_policy_binding(forged, ctx.policy)
    doc = reseal_report_observations(
        original.report.model_dump(mode="json", by_alias=True),
        [
            forged.model_dump(mode="json", by_alias=True),
            original.report.observations[1].model_dump(mode="json", by_alias=True),
        ],
    )
    with pytest.raises(ValidationError, match="observation_policy_violation"):
        p.ValidatorProbeReport.model_validate(doc)
    with pytest.raises(ValueError, match="document_invalid"):
        p.parse_validator_probe_report(canonical(doc) + b"\n")
    verification = p.verify_active_assignment_manifest(
        original.manifest,
        sign_manifest(original.manifest, ctx.keys),
        ctx.policy,
        ctx.states[0],
        evaluation_epoch=original.report.evaluation_epoch,
        current_finalized_height=original.manifest.finalized_height,
    )
    with pytest.raises(p.AssignmentProbeError, match="observation_policy_violation"):
        p.build_validator_probe_report(
            verification,
            ctx.policy,
            ctx.states[0],
            [forged, original.report.observations[1]],
            validator_uid=original.report.validator_uid,
            validator_hotkey=original.report.validator_hotkey,
            evaluation_epoch=original.report.evaluation_epoch,
            edge_origin_override=False,
        )
    # Bypass Pydantic only to exercise consumer revalidation, never to produce evidence.
    report = original.report.model_copy(
        update={
            **{
                k: doc[k]
                for k in (
                    "status",
                    "serving_count",
                    "failed_count",
                    "observation_vector_digest_sha256",
                    "report_digest_sha256",
                )
            },
            "observations": [forged, original.report.observations[1]],
        }
    )
    rounds = [ProbeRound(original.manifest, report), *ctx.rounds[1:]]
    assert len(rounds) == 45
    with pytest.raises(WeightDecisionError, match="decision_round_invalid"):
        decide_weight_submission(
            rounds,
            terminal=ctx.terminal,
            registered=ctx.registered,
            trust_policies=[ctx.policy],
            window_start_epoch=WINDOW_START,
            window_end_epoch=WINDOW_END,
        )
    with pytest.raises(ProbeScoringError, match="scoring_round_invalid"):
        accumulate_scoring_window(
            rounds,
            validator_uid=report.validator_uid,
            validator_hotkey=report.validator_hotkey,
            window_start_epoch=WINDOW_START,
            window_end_epoch=WINDOW_END,
        )
    attack = forged_decision_with_report(
        validator_weight_decision_bytes(ctx.decision),
        report_digest_sha256=original.report.report_digest_sha256,
        **{k: v for k, v in doc.items() if k != "report_digest_sha256"},
    )
    with pytest.raises(ValidationError, match="observation_policy_violation"):
        ValidatorWeightDecision.model_validate(attack)
    with pytest.raises(ValueError, match="document_invalid"):
        parse_validator_weight_decision(canonical(attack) + b"\n")


@pytest.mark.parametrize("elapsed", [0.1005, 0.101])
def test_real_backend_cutoff(elapsed: float) -> None:
    now = [0.0]
    budget = t.RequestBudget(0.1, clock=lambda: now[0])
    now[0] = elapsed
    # Real TCP dial + socket stream; only DNS and the monotonic clock are injected.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(1)
        port = listener.getsockname()[1]
        backend = t.DeadlineNetworkBackend(
            budget.remaining_seconds,
            resolver=lambda h, p: [(socket.AF_INET, socket.SOCK_STREAM, 0, ("127.0.0.1", port))],
        )
        if elapsed == 0.101:
            assert budget.latency_millis() == 101 and budget.exhausted(101)
            assert budget.remaining_seconds() == 0
            with pytest.raises(httpcore.ConnectTimeout):
                backend.connect_tcp("invalid", port)
        else:
            assert budget.latency_millis() == 100 and not budget.exhausted(100)
            assert budget.remaining_seconds() == pytest.approx(0.0005)
            stream = backend.connect_tcp("invalid", port)
            try:
                peer, _ = listener.accept()
                with peer:
                    peer.sendall(b"ok")
                    assert stream.read(2) == b"ok"
                    stream.write(b"yes")
                    assert peer.recv(3) == b"yes"
                    now[0] = 0.101
                    with pytest.raises(httpcore.ReadTimeout):
                        stream.read(1)
                    with pytest.raises(httpcore.WriteTimeout):
                        stream.write(b"late")
            finally:
                stream.close()


@pytest.mark.parametrize("latency", [99, 100, 101, 4999, 5000, 5001])
@pytest.mark.parametrize("code", ["timeout", "connection_failed", "transport_error"])
def test_timeout_cause_is_rederived_with_producer_parser_scorer_parity(
    latency: int, code: Any
) -> None:
    from assignment_probe_context import make_context

    ctx = make_context()
    observations = [
        p.evaluate_probe_response(
            deployment,
            ctx.policy,
            probe_nonce=label_digest(deployment.deployment_id),
            result=p.ProbeTransportFailure(code, latency),
        )
        for deployment in ctx.manifest.deployments
    ]
    expected = (
        "timeout"
        if latency > ctx.policy.probe_timeout_millis
        else ("transport_error" if code == "timeout" else code)
    )
    assert {item.failure_code for item in observations} == {expected}
    for item in observations:
        p.verify_observation_policy_binding(item, ctx.policy)
    report = p.build_validator_probe_report(
        ctx.verification,
        ctx.policy,
        ctx.state,
        observations,
        validator_uid=ctx.report.validator_uid,
        validator_hotkey=ctx.report.validator_hotkey,
        evaluation_epoch=ctx.report.evaluation_epoch,
        edge_origin_override=False,
    )
    assert p.parse_validator_probe_report(p.validator_probe_report_bytes(report)) == report
    accumulate_scoring_window(
        [ProbeRound(ctx.manifest, report)],
        validator_uid=report.validator_uid,
        validator_hotkey=report.validator_hotkey,
        window_start_epoch=WINDOW_START,
        window_end_epoch=WINDOW_END,
    )
