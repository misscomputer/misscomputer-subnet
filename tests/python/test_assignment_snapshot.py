# SPDX-License-Identifier: AGPL-3.0-only

"""Transactional active-assignment snapshot: projection, succession, malleability."""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from assignment_probe_context import (
    BASE_EPOCH,
    FINALIZED_HEIGHT,
    MINERS,
    build_deployment,
    build_manifest,
    build_policy,
    fixture_deployments,
    label_digest,
    make_context,
    signer_keys,
)
from contract_checkpoint_context import (
    ROUTE_ACTIVATED_AT,
    build_signer_skew_snapshot,
    build_snapshot,
    snapshot_deployment_from,
)
from pydantic import ValidationError

from misscomputer_subnet.assignment_probe import (
    build_active_assignment_manifest,
    parse_active_assignment_manifest,
)
from misscomputer_subnet.assignment_snapshot import (
    MAX_LINEAGE_ERAS,
    MAX_LINEAGE_FACTS,
    MAX_LINEAGE_REPLICAS,
    TICKET_MAX_FUTURE_SKEW_SECONDS,
    ActiveAssignmentSnapshot,
    AssignmentSnapshotError,
    SnapshotDeployment,
    SnapshotLineage,
    SnapshotReplica,
    active_assignment_snapshot_bytes,
    advance_snapshot_lineage,
    begin_snapshot_lineage_era,
    build_initial_snapshot_lineage,
    build_snapshot_deployment,
    build_snapshot_replica,
    parse_active_assignment_snapshot,
    parse_snapshot_lineage,
    project_manifest_deployments,
    replay_snapshot_lineage,
    snapshot_history_gaps,
    snapshot_lineage_bytes,
    verify_manifest_derived_from_snapshot,
    verify_snapshot_lineage_anchor,
    verify_snapshot_succession,
)
from misscomputer_subnet.contract_codec import digest as canonical_digest

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "contracts" / "fixtures"


def test_snapshot_projects_to_exactly_the_committed_manifest_deployments() -> None:
    snapshot = parse_active_assignment_snapshot(
        (FIXTURES / "active-assignment-snapshot.v1.json").read_bytes()
    )
    manifest = parse_active_assignment_manifest(
        (FIXTURES / "active-assignment-manifest.v1.json").read_bytes()
    )
    projected = project_manifest_deployments(snapshot)
    assert [item.model_dump(mode="json") for item in projected] == [
        item.model_dump(mode="json") for item in manifest.deployments
    ]
    assert snapshot.projected_assignment_vector_digest_sha256 == (
        manifest.assignment_vector_digest_sha256
    )
    verify_manifest_derived_from_snapshot(manifest, snapshot)
    # The projection drops exactly the activation timing the manifest lacks.
    replica = snapshot.deployments[0].replicas[0]
    assert replica.route_activated_at_epoch == ROUTE_ACTIVATED_AT
    assert "route_activated_at_epoch" not in manifest.deployments[0].replicas[0].model_dump()


def test_publisher_derivation_check_rejects_every_content_drift() -> None:
    context = make_context()
    snapshot = build_snapshot()
    verify_manifest_derived_from_snapshot(context.manifest, snapshot)
    deployments = fixture_deployments()

    def manifest(**overrides: object) -> object:
        return build_manifest(context.policy, deployments, **overrides)  # type: ignore[arg-type]

    cases = {
        "snapshot_manifest_issued_at_mismatch": manifest(issued_at=BASE_EPOCH + 1),
        "snapshot_manifest_chain_mismatch": manifest(finalized_height=FINALIZED_HEIGHT + 1),
        "snapshot_manifest_route_mismatch": manifest(probe_port=8443),
        "snapshot_manifest_vector_mismatch": build_manifest(context.policy, deployments[:1]),
        "snapshot_authority_mismatch": build_manifest(
            build_policy(signer_keys(), central_authority=label_digest("other-authority")),
            deployments,
        ),
    }
    for code, candidate in cases.items():
        with pytest.raises(AssignmentSnapshotError) as failure:
            verify_manifest_derived_from_snapshot(candidate, snapshot)  # type: ignore[arg-type]
        assert failure.value.code == code


def test_empty_snapshot_is_a_valid_state_that_cannot_become_a_manifest() -> None:
    empty = build_snapshot([])
    assert empty.deployments == []
    assert project_manifest_deployments(empty) == []
    rendered = active_assignment_snapshot_bytes(empty)
    assert parse_active_assignment_snapshot(rendered) == empty
    with pytest.raises(ValidationError):
        build_active_assignment_manifest(
            build_policy(signer_keys()),
            finalized_height=FINALIZED_HEIGHT,
            finalized_block_hash=empty.finalized_block_hash,
            finalized_epoch=42,
            sequence=1,
            previous_manifest_digest_sha256=None,
            issued_at_epoch=BASE_EPOCH,
            expires_at_epoch=BASE_EPOCH + 3_600,
            route_host_suffix=empty.route_host_suffix,
            probe_port=empty.probe_port,
            deployments=project_manifest_deployments(empty),
        )


def test_succession_rules_are_transactional() -> None:
    first = build_snapshot()
    second = build_snapshot(
        snapshot_sequence=2,
        state_revision=8,
        captured_at_epoch=BASE_EPOCH + 30,
        finalized_height=FINALIZED_HEIGHT + 5,
        finalized_block_hash=label_digest("next-block"),
        deployments=fixture_deployments()[:1],
    )
    verify_snapshot_succession(first, second)
    # An unchanged revision must carry byte-identical deployments.
    verify_snapshot_succession(
        first, build_snapshot(snapshot_sequence=2, captured_at_epoch=BASE_EPOCH + 30)
    )
    cases = {
        "snapshot_sequence_not_increasing": build_snapshot(snapshot_sequence=1, state_revision=8),
        "snapshot_revision_rollback": build_snapshot(snapshot_sequence=2, state_revision=6),
        "snapshot_revision_content_divergence": build_snapshot(
            fixture_deployments()[:1], snapshot_sequence=2
        ),
        "snapshot_capture_rollback": build_snapshot(
            snapshot_sequence=2, state_revision=8, captured_at_epoch=BASE_EPOCH - 1
        ),
        "snapshot_finalized_rollback": build_snapshot(
            snapshot_sequence=2, state_revision=8, finalized_height=FINALIZED_HEIGHT - 1
        ),
        "snapshot_finalized_fork": build_snapshot(
            snapshot_sequence=2, state_revision=8, finalized_block_hash=label_digest("fork")
        ),
        "snapshot_finalized_epoch_rollback": build_snapshot(
            snapshot_sequence=2,
            state_revision=8,
            finalized_height=FINALIZED_HEIGHT + 5,
            finalized_block_hash=label_digest("next-block"),
            finalized_epoch=41,
        ),
        "snapshot_authority_mismatch": build_snapshot(
            snapshot_sequence=2, state_revision=8, central_authority=label_digest("other")
        ),
    }
    for code, candidate in cases.items():
        with pytest.raises(AssignmentSnapshotError) as failure:
            verify_snapshot_succession(first, candidate)
        assert failure.value.code == code


def test_model_invariants_reject_inconsistent_captures() -> None:
    document = json.loads((FIXTURES / "active-assignment-snapshot.v1.json").read_bytes())

    def rejects(code: str, mutate: object) -> None:
        candidate = json.loads(json.dumps(document))
        mutate(candidate)  # type: ignore[operator]
        with pytest.raises(ValidationError) as failure:
            ActiveAssignmentSnapshot.model_validate(candidate)
        assert code in str(failure.value)

    def duplicate_nonce(value: dict[str, object]) -> None:
        deployments = value["deployments"]
        assert isinstance(deployments, list)
        alpha, beta = deployments[0]["replicas"][0], deployments[1]["replicas"][0]
        beta["assignment_nonce"] = alpha["assignment_nonce"]
        beta["endpoint_id"] = (
            f"{beta['replica_id']}-g{beta['generation']}-{alpha['assignment_nonce']}"
        )

    def identity_conflict(value: dict[str, object]) -> None:
        deployments = value["deployments"]
        assert isinstance(deployments, list)
        replica = deployments[1]["replicas"][0]
        replica["miner_uid"] = deployments[0]["replicas"][0]["miner_uid"]

    def ticket_expired(value: dict[str, object]) -> None:
        deployments = value["deployments"]
        assert isinstance(deployments, list)
        deployments[0]["replicas"][0]["ticket_expires_at_epoch"] = document["captured_at_epoch"]

    def ticket_from_the_future(value: dict[str, object]) -> None:
        deployments = value["deployments"]
        assert isinstance(deployments, list)
        replica = deployments[0]["replicas"][0]
        replica["ticket_issued_at_epoch"] = (
            document["captured_at_epoch"] + TICKET_MAX_FUTURE_SKEW_SECONDS + 1
        )
        replica["route_activated_at_epoch"] = replica["ticket_issued_at_epoch"]

    def unsorted_deployments(value: dict[str, object]) -> None:
        deployments = value["deployments"]
        assert isinstance(deployments, list)
        deployments.reverse()

    rejects("snapshot_assignment_nonce_duplicate", duplicate_nonce)
    rejects("snapshot_miner_identity_conflict", identity_conflict)
    rejects("snapshot_replica_ticket_expired", ticket_expired)
    rejects("snapshot_replica_ticket_issued_after_capture", ticket_from_the_future)
    rejects("snapshot_deployments_not_canonical", unsorted_deployments)


def test_replica_model_rejects_impossible_timing_and_digest_bindings() -> None:
    def replica(**overrides: object) -> object:
        values: dict[str, object] = {
            "miner_uid": 10,
            "miner_hotkey": "MinerA",
            "miner_service_public_key": fixture_deployments()[0]
            .replicas[0]
            .miner_service_public_key,
            "generation": 1,
            "assignment_nonce": label_digest("nonce")[:32],
            "deployment_id": "fixture-alpha",
            "ticket_digest_sha256": label_digest("ticket"),
            "receipt_digest_sha256": label_digest("receipt"),
            "chain_block": FINALIZED_HEIGHT - 60,
            "expires_at_block": FINALIZED_HEIGHT + 60,
            "ticket_issued_at_epoch": BASE_EPOCH - 500,
            "ticket_expires_at_epoch": BASE_EPOCH + 3_500,
            "route_activated_at_epoch": BASE_EPOCH - 100,
        }
        values.update(overrides)
        return build_snapshot_replica(**values)  # type: ignore[arg-type]

    replica()
    # The signer's clock may lead the runtime's by the tolerance, never more:
    # activation on the runtime clock may trail ticket issuance by exactly
    # TICKET_MAX_FUTURE_SKEW_SECONDS.
    replica(route_activated_at_epoch=BASE_EPOCH - 500 - TICKET_MAX_FUTURE_SKEW_SECONDS)
    for code, overrides in {
        "replica_block_window_invalid": {"expires_at_block": FINALIZED_HEIGHT - 60},
        "replica_ticket_window_invalid": {"ticket_expires_at_epoch": BASE_EPOCH - 500},
        "replica_digest_binding_invalid": {"receipt_digest_sha256": label_digest("ticket")},
        "replica_activation_order_invalid": {
            "route_activated_at_epoch": BASE_EPOCH - 500 - TICKET_MAX_FUTURE_SKEW_SECONDS - 1
        },
        "ed25519_public_key_small_order": {"miner_service_public_key": "01" + "00" * 31},
    }.items():
        with pytest.raises(ValidationError) as failure:
            replica(**overrides)
        assert code in str(failure.value)


def _skewed_capture(
    *, ticket_issued_at_epoch: int, route_activated_at_epoch: int
) -> ActiveAssignmentSnapshot:
    """The golden capture at BASE_EPOCH with alpha's replicas re-stamped."""

    alpha, beta = fixture_deployments()
    return build_snapshot(
        snapshot_deployments=[
            snapshot_deployment_from(
                alpha,
                route_activated_at_epoch=route_activated_at_epoch,
                reissued_ticket_at_epoch=ticket_issued_at_epoch,
            ),
            snapshot_deployment_from(beta),
        ]
    )


@pytest.mark.parametrize("lead_seconds", [1, TICKET_MAX_FUTURE_SKEW_SECONDS])
def test_signer_clock_may_lead_capture_by_the_documented_tolerance(lead_seconds: int) -> None:
    """A ticket stamped after the capture instant, within tolerance, is a valid capture.

    The route is activated exactly at the capture (runtime clock) while the
    signer stamped issuance ``lead_seconds`` later; both cross-domain checks
    apply the same tolerance, so the advertised capture+30 branch is reachable.
    """

    snapshot = _skewed_capture(
        ticket_issued_at_epoch=BASE_EPOCH + lead_seconds, route_activated_at_epoch=BASE_EPOCH
    )
    replica = snapshot.deployments[0].replicas[0]
    assert replica.ticket_issued_at_epoch == snapshot.captured_at_epoch + lead_seconds
    assert replica.route_activated_at_epoch == snapshot.captured_at_epoch
    rendered = active_assignment_snapshot_bytes(snapshot)
    assert parse_active_assignment_snapshot(rendered) == snapshot
    assert ActiveAssignmentSnapshot.model_validate(json.loads(rendered)) == snapshot
    # The skewed capture still projects to a valid manifest issued at capture.
    manifest = build_active_assignment_manifest(
        build_policy(signer_keys()),
        finalized_height=FINALIZED_HEIGHT,
        finalized_block_hash=snapshot.finalized_block_hash,
        finalized_epoch=snapshot.finalized_epoch,
        sequence=1,
        previous_manifest_digest_sha256=None,
        issued_at_epoch=snapshot.captured_at_epoch,
        expires_at_epoch=snapshot.captured_at_epoch + 3_000,
        route_host_suffix=snapshot.route_host_suffix,
        probe_port=snapshot.probe_port,
        deployments=project_manifest_deployments(snapshot),
    )
    verify_manifest_derived_from_snapshot(manifest, snapshot)
    assert manifest.deployments[0].replicas[0].ticket_issued_at_epoch == (BASE_EPOCH + lead_seconds)


def test_signer_clock_skew_rejections_are_branch_complete() -> None:
    def rejects(code: str, *, ticket_issued_at_epoch: int, route_activated_at_epoch: int) -> None:
        with pytest.raises(ValidationError) as failure:
            _skewed_capture(
                ticket_issued_at_epoch=ticket_issued_at_epoch,
                route_activated_at_epoch=route_activated_at_epoch,
            )
        assert code in str(failure.value)

    beyond = BASE_EPOCH + TICKET_MAX_FUTURE_SKEW_SECONDS + 1
    # One second past the tolerance: the replica's own ordering rule refuses a
    # route activated at capture, and the capture rule refuses a route whose
    # activation was pushed past the capture to keep the ordering rule happy.
    rejects(
        "replica_activation_order_invalid",
        ticket_issued_at_epoch=beyond,
        route_activated_at_epoch=BASE_EPOCH,
    )
    rejects(
        "snapshot_replica_ticket_issued_after_capture",
        ticket_issued_at_epoch=beyond,
        route_activated_at_epoch=beyond,
    )
    # Activation and capture share one clock: no tolerance between them.
    rejects(
        "snapshot_replica_activated_after_capture",
        ticket_issued_at_epoch=BASE_EPOCH + 1,
        route_activated_at_epoch=BASE_EPOCH + 1,
    )
    rejects(
        "snapshot_replica_activated_after_capture",
        ticket_issued_at_epoch=BASE_EPOCH - 500,
        route_activated_at_epoch=BASE_EPOCH + 1,
    )
    # Activation trailing issuance by exactly the tolerance is the last valid
    # instant; one more second is an ordering violation.
    _skewed_capture(
        ticket_issued_at_epoch=BASE_EPOCH - 500,
        route_activated_at_epoch=BASE_EPOCH - 500 - TICKET_MAX_FUTURE_SKEW_SECONDS,
    )
    rejects(
        "replica_activation_order_invalid",
        ticket_issued_at_epoch=BASE_EPOCH - 500,
        route_activated_at_epoch=BASE_EPOCH - 500 - TICKET_MAX_FUTURE_SKEW_SECONDS - 1,
    )


def test_signer_skew_fixture_is_a_fresh_incarnation_successor_at_both_tolerances() -> None:
    """The shared Go/Python parity fixture pins the +30 and +1 branches together.

    Its replicas are fresh incarnations (generation 2 with fresh nonce, endpoint,
    ticket and receipt digests), never the golden incarnation with a rewritten
    ticket instant, so it is a legitimate successor of the golden capture.
    """

    rendered = (FIXTURES / "active-assignment-snapshot-signer-skew.v1.json").read_bytes()
    snapshot = parse_active_assignment_snapshot(rendered)
    assert snapshot == build_signer_skew_snapshot()
    assert active_assignment_snapshot_bytes(snapshot) == rendered
    leads = {
        item.deployment_id: {
            replica.ticket_issued_at_epoch - snapshot.captured_at_epoch for replica in item.replicas
        }
        for item in snapshot.deployments
    }
    assert leads == {
        "fixture-alpha": {TICKET_MAX_FUTURE_SKEW_SECONDS},
        "fixture-beta": {1},
    }
    assert all(
        replica.route_activated_at_epoch == snapshot.captured_at_epoch
        for item in snapshot.deployments
        for replica in item.replicas
    )
    golden = build_snapshot()
    golden_replicas = {
        replica.endpoint_id: replica for item in golden.deployments for replica in item.replicas
    }
    golden_facts = {
        (replica.assignment_nonce, replica.ticket_digest_sha256, replica.receipt_digest_sha256)
        for replica in golden_replicas.values()
    }
    for item in snapshot.deployments:
        for replica in item.replicas:
            assert replica.generation == 2
            assert replica.endpoint_id not in golden_replicas
            assert replica.assignment_nonce not in {
                r.assignment_nonce for r in golden_replicas.values()
            }
            assert (
                replica.assignment_nonce,
                replica.ticket_digest_sha256,
                replica.receipt_digest_sha256,
            ) not in golden_facts
    verify_snapshot_succession(golden, snapshot)
    document = json.loads(rendered)
    document["deployments"][0]["replicas"][0]["ticket_issued_at_epoch"] += 1
    with pytest.raises(ValidationError, match="replica_activation_order_invalid"):
        ActiveAssignmentSnapshot.model_validate(document)


def test_succession_refuses_rewritten_incarnation_facts() -> None:
    """One incarnation has one set of signed facts across every capture that exports it.

    A signed ticket binds its own issuance, so a successor capture that keeps an
    endpoint's ticket digest, nonce, and receipt digest while restamping
    ``ticket_issued_at_epoch`` (or any other fact of that incarnation) is an
    impossible rewrite, not a re-assignment, and is refused.
    """

    golden = build_snapshot()
    alpha, beta = fixture_deployments()

    def successor(**replica_changes: object) -> ActiveAssignmentSnapshot:
        lifted = snapshot_deployment_from(alpha)
        replicas = [
            SnapshotReplica.model_validate({**replica.model_dump(mode="json"), **replica_changes})
            if index == 0
            else replica
            for index, replica in enumerate(lifted.replicas)
        ]
        rewritten = SnapshotDeployment.model_validate(
            {
                **lifted.model_dump(mode="json"),
                "replicas": [item.model_dump(mode="json") for item in replicas],
            }
        )
        return build_snapshot(
            snapshot_sequence=2,
            state_revision=8,
            snapshot_deployments=[rewritten, snapshot_deployment_from(beta)],
        )

    # Unchanged incarnations succeed; every rewrite of a retained incarnation fails.
    verify_snapshot_succession(golden, successor())
    for changes in (
        {"ticket_issued_at_epoch": BASE_EPOCH - 499},
        {"ticket_issued_at_epoch": BASE_EPOCH + 1, "route_activated_at_epoch": BASE_EPOCH},
        {"ticket_digest_sha256": label_digest("rewritten-ticket")},
        {"receipt_digest_sha256": label_digest("rewritten-receipt")},
        {"ticket_expires_at_epoch": BASE_EPOCH + 3_501},
        {"route_activated_at_epoch": ROUTE_ACTIVATED_AT + 1},
        {"expires_at_block": FINALIZED_HEIGHT + 61},
        {"chain_block": FINALIZED_HEIGHT - 61},
    ):
        with pytest.raises(AssignmentSnapshotError) as failure:
            verify_snapshot_succession(golden, successor(**changes))
        assert failure.value.code == "snapshot_incarnation_rewritten", changes
    # A genuinely re-issued ticket is a new incarnation and succeeds.
    verify_snapshot_succession(
        golden,
        build_snapshot(
            snapshot_sequence=2,
            state_revision=8,
            snapshot_deployments=[
                snapshot_deployment_from(
                    alpha,
                    route_activated_at_epoch=BASE_EPOCH,
                    reissued_ticket_at_epoch=BASE_EPOCH + 1,
                ),
                snapshot_deployment_from(beta),
            ],
        ),
    )


def _alpha_with(
    replica_changes: dict[str, object], *, deployment_changes: dict[str, object] | None = None
) -> SnapshotDeployment:
    """The golden alpha deployment with its first replica (and optionally its facts) rewritten."""

    alpha, _ = fixture_deployments()
    lifted = snapshot_deployment_from(alpha)
    replica = SnapshotReplica.model_validate(
        {**lifted.replicas[0].model_dump(mode="json"), **replica_changes}
    )
    document = {**lifted.model_dump(mode="json"), **(deployment_changes or {})}
    document["replicas"] = [
        replica.model_dump(mode="json"),
        *[item.model_dump(mode="json") for item in lifted.replicas[1:]],
    ]
    return SnapshotDeployment.model_validate(document)


def _capture(sequence: int, alpha: SnapshotDeployment | None) -> ActiveAssignmentSnapshot:
    _, beta = fixture_deployments()
    return build_snapshot(
        snapshot_sequence=sequence,
        state_revision=6 + sequence,
        snapshot_deployments=[snapshot_deployment_from(beta)]
        if alpha is None
        else [alpha, snapshot_deployment_from(beta)],
    )


def test_incarnation_lineage_refuses_every_rewrite_and_reuse() -> None:
    """Replacement needs a higher generation and fresh signed facts; retention needs identity.

    ``replica_id`` (deployment and hotkey) is the stable lineage; a new
    ``endpoint_id`` for it is a replacement and must advance the generation and
    carry a fresh nonce, ticket digest, and receipt digest; the same
    ``endpoint_id`` must carry the identical replica document and identical
    ticket-bound deployment facts. The lineage remembers every incarnation it
    accepted, so a capture that drops an incarnation and a later one that
    re-exports it rewritten is still refused.
    """

    golden = build_snapshot()
    alpha, _ = fixture_deployments()
    first = snapshot_deployment_from(alpha).replicas[0]
    genesis = build_initial_snapshot_lineage(
        central_authority_fingerprint_sha256=golden.central_authority_fingerprint_sha256
    )
    after_golden = advance_snapshot_lineage(genesis, golden)
    assert after_golden.accepted_snapshot_count == 1 and len(after_golden.replicas) == 6
    fresh_nonce = label_digest("fresh-nonce")[:32]

    def rejects(code: str, alpha_variant: SnapshotDeployment) -> None:
        capture = _capture(2, alpha_variant)
        with pytest.raises(AssignmentSnapshotError) as durable:
            advance_snapshot_lineage(after_golden, capture)
        assert durable.value.code == code
        with pytest.raises(AssignmentSnapshotError) as adjacent:
            verify_snapshot_succession(golden, capture)
        assert adjacent.value.code == code

    # g1 -> g2 keeping nonce, ticket, and receipt: a replacement without fresh facts.
    rejects(
        "snapshot_incarnation_facts_reused",
        _alpha_with(
            {
                "generation": 2,
                "endpoint_id": f"{first.replica_id}-g2-{first.assignment_nonce}",
                "ticket_issued_at_epoch": BASE_EPOCH + 1,
                "route_activated_at_epoch": BASE_EPOCH,
            }
        ),
    )
    # Same generation with a fresh nonce and endpoint, retaining ticket and receipt.
    rejects(
        "snapshot_generation_not_increasing",
        _alpha_with(
            {
                "assignment_nonce": fresh_nonce,
                "endpoint_id": f"{first.replica_id}-g1-{fresh_nonce}",
                "ticket_issued_at_epoch": BASE_EPOCH + 1,
                "route_activated_at_epoch": BASE_EPOCH,
            }
        ),
    )
    # Higher generation and fresh nonce, but a retained ticket or receipt digest.
    for retained in (
        {"receipt_digest_sha256": label_digest("fresh-receipt")},
        {"ticket_digest_sha256": label_digest("fresh-ticket")},
    ):
        rejects(
            "snapshot_incarnation_facts_reused",
            _alpha_with(
                {
                    "generation": 2,
                    "assignment_nonce": fresh_nonce,
                    "endpoint_id": f"{first.replica_id}-g2-{fresh_nonce}",
                    **retained,
                }
            ),
        )
    # Same endpoint and ticket, parent deployment facts changed.
    for facts in (
        {"image_digest": "sha256:" + label_digest("other-image")},
        {"challenge_sha256": label_digest("other-challenge")},
        {"workload_spec_digest_sha256": label_digest("other-workload")},
        {"campaign_sequence": 9},
    ):
        rejects("snapshot_incarnation_rewritten", _alpha_with({}, deployment_changes=facts))
    # Same endpoint, replica facts rewritten (every fact, not only the ticket instant).
    for changes in (
        {"ticket_issued_at_epoch": BASE_EPOCH + 1, "route_activated_at_epoch": BASE_EPOCH},
        {"receipt_digest_sha256": label_digest("rewritten-receipt")},
        {"route_activated_at_epoch": ROUTE_ACTIVATED_AT + 1},
        {"expires_at_block": FINALIZED_HEIGHT + 61},
    ):
        rejects("snapshot_incarnation_rewritten", _alpha_with(changes))

    # Empty intermediate capture, then the old endpoint re-exported rewritten:
    # invisible to adjacent succession, refused by the durable lineage.
    empty = build_snapshot([], snapshot_sequence=2, state_revision=8)
    after_empty = advance_snapshot_lineage(after_golden, empty)
    assert after_empty.replicas == after_golden.replicas
    rewritten = _capture(
        3,
        _alpha_with(
            {"ticket_issued_at_epoch": BASE_EPOCH + 1, "route_activated_at_epoch": BASE_EPOCH}
        ),
    )
    verify_snapshot_succession(golden, empty)
    verify_snapshot_succession(empty, rewritten)
    with pytest.raises(AssignmentSnapshotError) as failure:
        advance_snapshot_lineage(after_empty, rewritten)
    assert failure.value.code == "snapshot_incarnation_rewritten"
    # ...while the identical incarnation re-exported after the gap is accepted.
    restored = advance_snapshot_lineage(after_empty, _capture(3, snapshot_deployment_from(alpha)))
    assert [
        item.model_dump(exclude={"last_seen_snapshot_sequence"}) for item in restored.replicas
    ] == [
        item.model_dump(exclude={"last_seen_snapshot_sequence"}) for item in after_golden.replicas
    ]
    assert {item.last_seen_snapshot_sequence for item in restored.replicas} == {3}

    # A genuine replacement: higher generation, fresh nonce, ticket, and receipt.
    genuine = _capture(
        2,
        snapshot_deployment_from(
            alpha, route_activated_at_epoch=BASE_EPOCH, reissued_ticket_at_epoch=BASE_EPOCH + 1
        ),
    )
    verify_snapshot_succession(golden, genuine)
    advanced = advance_snapshot_lineage(after_golden, genuine)
    replaced = {item.replica_id: item for item in advanced.replicas}
    for replica in genuine.deployments[0].replicas:
        entry = replaced[replica.replica_id]
        assert entry.generation == 2 and entry.endpoint_id == replica.endpoint_id
    # Replacing again must advance past generation 2, not merely differ from 1.
    stale_generation = _capture(
        3,
        snapshot_deployment_from(
            alpha, route_activated_at_epoch=BASE_EPOCH, reissued_ticket_at_epoch=BASE_EPOCH + 2
        ),
    )
    assert stale_generation.deployments[0].replicas[0].generation == 2
    with pytest.raises(AssignmentSnapshotError) as failure:
        advance_snapshot_lineage(advanced, stale_generation)
    assert failure.value.code == "snapshot_generation_not_increasing"

    # The lineage is a durable canonical document.
    rendered = snapshot_lineage_bytes(advanced)
    assert parse_snapshot_lineage(rendered) == advanced
    assert advanced.last_snapshot_sequence == 2 and advanced.accepted_snapshot_count == 2
    # Transactional rules hold against the lineage exactly as between captures.
    with pytest.raises(AssignmentSnapshotError) as failure:
        advance_snapshot_lineage(advanced, golden)
    assert failure.value.code == "snapshot_sequence_not_increasing"
    with pytest.raises(AssignmentSnapshotError) as failure:
        advance_snapshot_lineage(
            genesis, build_snapshot(central_authority=label_digest("other-authority"))
        )
    assert failure.value.code == "snapshot_authority_mismatch"


def _reincarnation(
    template: SnapshotDeployment, facts_from: SnapshotDeployment, *, generation: int
) -> SnapshotDeployment:
    """``template`` re-exported at ``generation`` with the signed facts of ``facts_from``."""

    replicas = []
    for current, old in zip(template.replicas, facts_from.replicas, strict=True):
        replicas.append(
            SnapshotReplica.model_validate(
                {
                    **current.model_dump(mode="json"),
                    "generation": generation,
                    "assignment_nonce": old.assignment_nonce,
                    "ticket_digest_sha256": old.ticket_digest_sha256,
                    "receipt_digest_sha256": old.receipt_digest_sha256,
                    "endpoint_id": f"{old.replica_id}-g{generation}-{old.assignment_nonce}",
                }
            ).model_dump(mode="json")
        )
    return SnapshotDeployment.model_validate(
        {**template.model_dump(mode="json"), "replicas": replicas}
    )


def test_retired_incarnation_facts_are_never_recycled() -> None:
    """A -> B -> A: facts retired by one replacement cannot return at a later generation.

    The lineage remembers every nonce, ticket digest, and receipt digest it has
    ever accepted, not only the latest incarnation per ``replica_id``, so a
    third-generation incarnation that recycles the first generation's facts
    is refused after any number of intervening captures, empty or not, while a
    third generation with fresh facts is accepted. Partial recycling (one fact
    only) and recycling another replica's facts are refused the same way.
    """

    golden = build_snapshot()
    alpha, beta = fixture_deployments()
    a1 = snapshot_deployment_from(alpha)
    b2 = snapshot_deployment_from(
        alpha, route_activated_at_epoch=BASE_EPOCH, reissued_ticket_at_epoch=BASE_EPOCH + 1
    )
    second = _capture(2, b2)
    genesis = build_initial_snapshot_lineage(
        central_authority_fingerprint_sha256=golden.central_authority_fingerprint_sha256
    )
    lineage = advance_snapshot_lineage(advance_snapshot_lineage(genesis, golden), second)
    assert len(lineage.used_assignment_nonces) == 9
    assert len(lineage.used_ticket_digests) == 9 and len(lineage.used_receipt_digests) == 9
    a1_facts = {
        (r.assignment_nonce, r.ticket_digest_sha256, r.receipt_digest_sha256) for r in a1.replicas
    }
    assert all(nonce in lineage.used_assignment_nonces for nonce, _, _ in a1_facts)
    assert {
        item.generation for item in lineage.replicas if item.deployment_id == "fixture-alpha"
    } == {2}

    recycled = _capture(3, _reincarnation(b2, a1, generation=3))
    assert {
        (r.assignment_nonce, r.ticket_digest_sha256, r.receipt_digest_sha256)
        for r in recycled.deployments[0].replicas
    } == a1_facts
    with pytest.raises(AssignmentSnapshotError) as failure:
        advance_snapshot_lineage(lineage, recycled)
    assert failure.value.code == "snapshot_incarnation_facts_reused"
    # An empty capture in between changes nothing: the facts stay retired.
    after_empty = advance_snapshot_lineage(
        lineage, build_snapshot([], snapshot_sequence=3, state_revision=9)
    )
    assert after_empty.used_assignment_nonces == lineage.used_assignment_nonces
    with pytest.raises(AssignmentSnapshotError) as failure:
        advance_snapshot_lineage(after_empty, _capture(4, _reincarnation(b2, a1, generation=3)))
    assert failure.value.code == "snapshot_incarnation_facts_reused"
    # The two-capture form cannot know what B replaced; only the durable lineage can.
    verify_snapshot_succession(second, recycled)

    # Partial recycling of a single retired fact is refused too.
    fresh = snapshot_deployment_from(
        alpha, route_activated_at_epoch=BASE_EPOCH, reissued_ticket_at_epoch=BASE_EPOCH + 2
    )
    for changes in (
        {"assignment_nonce": a1.replicas[0].assignment_nonce},
        {"ticket_digest_sha256": a1.replicas[0].ticket_digest_sha256},
        {"receipt_digest_sha256": a1.replicas[0].receipt_digest_sha256},
    ):
        first = fresh.replicas[0].model_dump(mode="json")
        first = {**first, **changes, "generation": 3}
        first["endpoint_id"] = f"{first['replica_id']}-g3-{first['assignment_nonce']}"
        partial = SnapshotDeployment.model_validate(
            {
                **fresh.model_dump(mode="json"),
                "replicas": [
                    SnapshotReplica.model_validate(first).model_dump(mode="json"),
                    *[
                        SnapshotReplica.model_validate(
                            {**r.model_dump(mode="json"), "generation": 3}
                            | {"endpoint_id": f"{r.replica_id}-g3-{r.assignment_nonce}"}
                        ).model_dump(mode="json")
                        for r in fresh.replicas[1:]
                    ],
                ],
            }
        )
        with pytest.raises(AssignmentSnapshotError) as failure:
            advance_snapshot_lineage(lineage, _capture(3, partial))
        assert failure.value.code == "snapshot_incarnation_facts_reused", changes
    # Recycling another replica's retired ticket under a brand-new replica_id is refused.
    beta_lifted = snapshot_deployment_from(beta)
    stolen = SnapshotDeployment.model_validate(
        {
            **beta_lifted.model_dump(mode="json"),
            "deployment_id": "fixture-gamma",
            "route_host": "fixture-gamma.mock.local",
            "replicas": [
                SnapshotReplica.model_validate(
                    {
                        **beta_lifted.replicas[0].model_dump(mode="json"),
                        "replica_id": f"fixture-gamma-{beta_lifted.replicas[0].miner_hotkey}",
                        "endpoint_id": (
                            f"fixture-gamma-{beta_lifted.replicas[0].miner_hotkey}-g1-"
                            f"{label_digest('gamma-nonce')[:32]}"
                        ),
                        "assignment_nonce": label_digest("gamma-nonce")[:32],
                        "receipt_digest_sha256": label_digest("gamma-receipt"),
                        "ticket_digest_sha256": a1.replicas[0].ticket_digest_sha256,
                    }
                ).model_dump(mode="json")
            ],
        }
    )
    with pytest.raises(AssignmentSnapshotError) as failure:
        advance_snapshot_lineage(
            lineage,
            build_snapshot(
                snapshot_sequence=3,
                state_revision=9,
                snapshot_deployments=[b2, beta_lifted, stolen],
            ),
        )
    assert failure.value.code == "snapshot_incarnation_facts_reused"

    # A genuine third generation with fresh facts is accepted and remembered.
    third = _capture(
        3,
        SnapshotDeployment.model_validate(
            {
                **fresh.model_dump(mode="json"),
                "replicas": [
                    SnapshotReplica.model_validate(
                        {**r.model_dump(mode="json"), "generation": 3}
                        | {"endpoint_id": f"{r.replica_id}-g3-{r.assignment_nonce}"}
                    ).model_dump(mode="json")
                    for r in fresh.replicas
                ],
            }
        ),
    )
    advanced = advance_snapshot_lineage(lineage, third)
    assert len(advanced.used_assignment_nonces) == 12
    assert {
        item.generation for item in advanced.replicas if item.deployment_id == "fixture-alpha"
    } == {3}
    assert parse_snapshot_lineage(snapshot_lineage_bytes(advanced)) == advanced
    # A lineage whose used-fact sets omit a current incarnation's facts is refused on parse.
    document = json.loads(snapshot_lineage_bytes(advanced))
    document["used_ticket_digests"].remove(document["replicas"][0]["ticket_digest_sha256"])
    unsigned = {k: v for k, v in document.items() if k != "lineage_digest_sha256"}
    document["lineage_digest_sha256"] = canonical_digest(unsigned)
    with pytest.raises(ValidationError, match="lineage_used_facts_not_derived"):
        SnapshotLineage.model_validate(document)


def test_lineage_recovery_never_silently_resets_retired_fact_memory() -> None:
    """Overflow refuses, gaps refuse, stale restores refuse, and eras are explicit and visible.

    The retired-fact guarantee survives every recovery path: a full lineage
    refuses the next capture instead of forgetting; a capture out of sequence
    is a gap that must be replayed; a restored lineage must match the anchored
    head digest; and the only way to shed retired facts is an explicit era
    boundary that the document records and that keeps every current
    incarnation's facts, so A -> B -> A recycling is refused in the era that
    saw A, and after an era boundary the document says exactly which era
    forgot what.
    """

    golden = build_snapshot()
    alpha, beta = fixture_deployments()
    a1 = snapshot_deployment_from(alpha)
    b2 = snapshot_deployment_from(
        alpha, route_activated_at_epoch=BASE_EPOCH, reissued_ticket_at_epoch=BASE_EPOCH + 1
    )
    second = _capture(2, b2)
    genesis = build_initial_snapshot_lineage(
        central_authority_fingerprint_sha256=golden.central_authority_fingerprint_sha256
    )
    assert (genesis.era, genesis.history_start_snapshot_sequence) == (1, 1)
    after_first = advance_snapshot_lineage(genesis, golden)
    lineage = advance_snapshot_lineage(after_first, second)
    # Hash chain: every advance names its predecessor.
    assert after_first.previous_lineage_digest_sha256 == genesis.lineage_digest_sha256
    assert lineage.previous_lineage_digest_sha256 == after_first.lineage_digest_sha256

    # Gap: the next capture must be exactly sequence 3; genesis must start at
    # its declared history start; replay supplies the missing captures.
    with pytest.raises(AssignmentSnapshotError) as failure:
        advance_snapshot_lineage(lineage, _capture(4, b2))
    assert failure.value.code == "snapshot_lineage_gap"
    with pytest.raises(AssignmentSnapshotError) as failure:
        advance_snapshot_lineage(genesis, second)
    assert failure.value.code == "snapshot_lineage_gap"
    later_start = build_initial_snapshot_lineage(
        central_authority_fingerprint_sha256=golden.central_authority_fingerprint_sha256,
        first_snapshot_sequence=2,
    )
    assert advance_snapshot_lineage(later_start, second).history_start_snapshot_sequence == 2
    with pytest.raises(AssignmentSnapshotError) as failure:
        advance_snapshot_lineage(later_start, golden)
    assert failure.value.code == "snapshot_lineage_gap"
    assert replay_snapshot_lineage(genesis, [golden, second]) == lineage
    with pytest.raises(AssignmentSnapshotError) as failure:
        replay_snapshot_lineage(genesis, [golden, _capture(3, b2)])
    assert failure.value.code == "snapshot_lineage_gap"
    for invalid in (0, -1, True):
        with pytest.raises(ValueError, match="lineage_history_start_invalid"):
            build_initial_snapshot_lineage(
                central_authority_fingerprint_sha256=golden.central_authority_fingerprint_sha256,
                first_snapshot_sequence=invalid,  # type: ignore[arg-type]
            )

    # Stale restore: only the anchored head is accepted; the predecessor, a
    # resealed copy with retired facts removed, and a foreign digest are not.
    assert (
        verify_snapshot_lineage_anchor(
            lineage, expected_lineage_digest_sha256=lineage.lineage_digest_sha256
        )
        == lineage
    )
    with pytest.raises(AssignmentSnapshotError) as failure:
        verify_snapshot_lineage_anchor(
            after_first, expected_lineage_digest_sha256=lineage.lineage_digest_sha256
        )
    assert failure.value.code == "snapshot_lineage_anchor_mismatch"
    document = json.loads(snapshot_lineage_bytes(lineage))
    retired_only = sorted(
        set(document["used_ticket_digests"])
        - {item["ticket_digest_sha256"] for item in document["replicas"]}
    )
    assert len(retired_only) == 3
    document["used_ticket_digests"] = [
        item for item in document["used_ticket_digests"] if item not in retired_only
    ]
    unsigned = {k: v for k, v in document.items() if k != "lineage_digest_sha256"}
    document["lineage_digest_sha256"] = canonical_digest(unsigned)
    resealed = SnapshotLineage.model_validate(document)  # digest-valid, history-false
    with pytest.raises(AssignmentSnapshotError) as failure:
        verify_snapshot_lineage_anchor(
            resealed, expected_lineage_digest_sha256=lineage.lineage_digest_sha256
        )
    assert failure.value.code == "snapshot_lineage_anchor_mismatch"

    # Overflow: a capture that would exceed the fact budget is refused and
    # nothing is forgotten; the same lineage still accepts a capture that fits.
    recycled = _capture(3, _reincarnation(b2, a1, generation=3))
    fresh_third = _capture(
        3,
        SnapshotDeployment.model_validate(
            {
                **b2.model_dump(mode="json"),
                "replicas": [
                    SnapshotReplica.model_validate(
                        {
                            **r.model_dump(mode="json"),
                            "generation": 3,
                            "assignment_nonce": label_digest(f"g3-nonce-{r.miner_hotkey}")[:32],
                            "ticket_digest_sha256": label_digest(f"g3-ticket-{r.miner_hotkey}"),
                            "receipt_digest_sha256": label_digest(f"g3-receipt-{r.miner_hotkey}"),
                            "endpoint_id": (
                                f"{r.replica_id}-g3-{label_digest(f'g3-nonce-{r.miner_hotkey}')[:32]}"
                            ),
                        }
                    ).model_dump(mode="json")
                    for r in b2.replicas
                ],
            }
        ),
    )
    with pytest.raises(AssignmentSnapshotError) as failure:
        advance_snapshot_lineage(lineage, fresh_third, max_facts=9)
    assert failure.value.code == "snapshot_lineage_overflow"
    grown = advance_snapshot_lineage(lineage, fresh_third, max_facts=12)
    assert len(grown.used_ticket_digests) == 12 and grown.era == 1
    with pytest.raises(AssignmentSnapshotError) as failure:
        advance_snapshot_lineage(lineage, recycled)
    assert failure.value.code == "snapshot_incarnation_facts_reused"

    # Era boundary: explicit, recorded, keeps the current incarnations' facts.
    with pytest.raises(AssignmentSnapshotError) as failure:
        begin_snapshot_lineage_era(genesis)
    assert failure.value.code == "snapshot_lineage_gap"
    era_two = begin_snapshot_lineage_era(lineage)
    assert era_two.era == 2 and era_two.accepted_snapshot_count == 2
    assert era_two.previous_lineage_digest_sha256 == lineage.lineage_digest_sha256
    assert era_two.replicas == lineage.replicas
    assert len(era_two.used_ticket_digests) == 6 and len(era_two.era_boundaries) == 1
    boundary = era_two.era_boundaries[0]
    assert (boundary.era, boundary.opened_after_snapshot_sequence) == (2, 2)
    assert (
        boundary.dropped_assignment_nonces,
        boundary.dropped_ticket_digests,
        boundary.dropped_receipt_digests,
    ) == (3, 3, 3)
    assert boundary.previous_lineage_digest_sha256 == lineage.lineage_digest_sha256
    assert parse_snapshot_lineage(snapshot_lineage_bytes(era_two)) == era_two
    # Within era 2 the guarantee is re-scoped: A's era-1 facts are no longer
    # remembered, and the document says so; current facts are still guarded.
    era_two_recycled = advance_snapshot_lineage(era_two, recycled)
    assert era_two_recycled.era == 2 and era_two_recycled.era_boundaries == [boundary]
    with pytest.raises(AssignmentSnapshotError) as failure:
        advance_snapshot_lineage(era_two, _capture(3, _reincarnation(b2, b2, generation=3)))
    assert failure.value.code == "snapshot_incarnation_facts_reused"
    with pytest.raises(AssignmentSnapshotError) as failure:
        advance_snapshot_lineage(
            era_two,
            _capture(
                3,
                SnapshotDeployment.model_validate(
                    {
                        **b2.model_dump(mode="json"),
                        "image_digest": "sha256:" + label_digest("other-image"),
                    }
                ),
            ),
        )
    assert failure.value.code == "snapshot_incarnation_rewritten"
    # Eras chain, one boundary per accepted capture, and are bounded.
    with pytest.raises(AssignmentSnapshotError) as failure:
        begin_snapshot_lineage_era(era_two)
    assert failure.value.code == "snapshot_lineage_boundary_pending"
    era_two_followed = advance_snapshot_lineage(
        era_two, build_snapshot([], snapshot_sequence=3, state_revision=9)
    )
    era_three = begin_snapshot_lineage_era(era_two_followed)
    assert [item.era for item in era_three.era_boundaries] == [2, 3]
    assert era_three.previous_lineage_digest_sha256 == era_two_followed.lineage_digest_sha256
    forged = json.loads(snapshot_lineage_bytes(era_three))
    forged["era_boundaries"] = forged["era_boundaries"][:1]
    unsigned = {k: v for k, v in forged.items() if k != "lineage_digest_sha256"}
    forged["lineage_digest_sha256"] = canonical_digest(unsigned)
    with pytest.raises(ValidationError, match="lineage_era_invalid"):
        SnapshotLineage.model_validate(forged)


def test_era_boundary_prunes_only_inactive_lineage_and_eras_are_capped() -> None:
    """Recovery from a replica-lineage overflow is pruning inactive entries at an era boundary.

    Every replica lineage records the last capture that exported it; an era
    boundary keeps exactly the entries of the last accepted capture and drops
    the rest, recording how many, so a lineage over ``MAX_LINEAGE_REPLICAS``
    (which necessarily holds inactive entries: one capture cannot exceed the
    bound) recovers there and nowhere else. ``era`` never exceeds
    ``MAX_LINEAGE_ERAS``.
    """

    golden = build_snapshot()
    alpha, beta = fixture_deployments()
    genesis = build_initial_snapshot_lineage(
        central_authority_fingerprint_sha256=golden.central_authority_fingerprint_sha256
    )
    after_golden = advance_snapshot_lineage(genesis, golden)
    assert {item.last_seen_snapshot_sequence for item in after_golden.replicas} == {1}
    only_beta = build_snapshot(
        snapshot_sequence=2, state_revision=8, snapshot_deployments=[snapshot_deployment_from(beta)]
    )
    after_beta = advance_snapshot_lineage(after_golden, only_beta)
    seen = {item.replica_id: item.last_seen_snapshot_sequence for item in after_beta.replicas}
    assert seen == {
        "fixture-alpha-MinerA": 1,
        "fixture-alpha-MinerB": 1,
        "fixture-alpha-MinerC": 1,
        "fixture-beta-MinerB": 2,
        "fixture-beta-MinerC": 2,
        "fixture-beta-MinerD": 2,
    }
    era_two = begin_snapshot_lineage_era(after_beta)
    assert [item.replica_id for item in era_two.replicas] == [
        "fixture-beta-MinerB",
        "fixture-beta-MinerC",
        "fixture-beta-MinerD",
    ]
    boundary = era_two.era_boundaries[0]
    assert (boundary.dropped_replica_lineages, boundary.dropped_ticket_digests) == (3, 3)
    assert len(era_two.used_ticket_digests) == 3
    assert parse_snapshot_lineage(snapshot_lineage_bytes(era_two)) == era_two
    # After an empty capture nothing is active, and a boundary keeps nothing.
    empty = build_snapshot([], snapshot_sequence=3, state_revision=9)
    era_after_empty = begin_snapshot_lineage_era(advance_snapshot_lineage(after_beta, empty))
    assert era_after_empty.replicas == [] and era_after_empty.used_assignment_nonces == []
    assert era_after_empty.era_boundaries[0].dropped_replica_lineages == 6
    # A pruned replica may return in the new era with a fresh incarnation; its
    # generation history is gone, which the boundary records.
    returned = advance_snapshot_lineage(
        era_two,
        build_snapshot(
            snapshot_sequence=3,
            state_revision=9,
            snapshot_deployments=[snapshot_deployment_from(alpha), snapshot_deployment_from(beta)],
        ),
    )
    assert len(returned.replicas) == 6 and returned.era == 2

    # Era cap: era never exceeds MAX_LINEAGE_ERAS, so at most MAX - 1 boundaries,
    # each separated from the next by at least one accepted capture.
    current = after_golden
    for step in range(MAX_LINEAGE_ERAS - 1):
        current = begin_snapshot_lineage_era(current)
        current = advance_snapshot_lineage(
            current, build_snapshot([], snapshot_sequence=2 + step, state_revision=8 + step)
        )
    assert current.era == MAX_LINEAGE_ERAS and len(current.era_boundaries) == MAX_LINEAGE_ERAS - 1
    with pytest.raises(AssignmentSnapshotError) as failure:
        begin_snapshot_lineage_era(current)
    assert failure.value.code == "snapshot_lineage_overflow"
    assert parse_snapshot_lineage(snapshot_lineage_bytes(current)) == current
    replayed = replay_snapshot_lineage(
        genesis,
        [
            golden,
            *[
                build_snapshot([], snapshot_sequence=2 + step, state_revision=8 + step)
                for step in range(MAX_LINEAGE_ERAS - 1)
            ],
        ],
        era_boundaries=current.era_boundaries,
    )
    assert replayed == current


def test_signed_fact_freshness_is_judged_across_every_fact_role() -> None:
    """A retired digest may not return in another role, and the lineage may not hold overlaps."""

    golden = build_snapshot()
    alpha, beta = fixture_deployments()
    a1 = snapshot_deployment_from(alpha)
    b2 = snapshot_deployment_from(
        alpha, route_activated_at_epoch=BASE_EPOCH, reissued_ticket_at_epoch=BASE_EPOCH + 1
    )
    lineage = advance_snapshot_lineage(
        build_initial_snapshot_lineage(
            central_authority_fingerprint_sha256=golden.central_authority_fingerprint_sha256
        ),
        golden,
    )

    def swapped(**changes: str) -> ActiveAssignmentSnapshot:
        first = SnapshotReplica.model_validate(
            {**b2.replicas[0].model_dump(mode="json"), **changes}
        )
        deployment = SnapshotDeployment.model_validate(
            {
                **b2.model_dump(mode="json"),
                "replicas": [
                    first.model_dump(mode="json"),
                    *[item.model_dump(mode="json") for item in b2.replicas[1:]],
                ],
            }
        )
        return build_snapshot(
            snapshot_sequence=2,
            state_revision=8,
            snapshot_deployments=[deployment, snapshot_deployment_from(beta)],
        )

    for changes in (
        {"receipt_digest_sha256": a1.replicas[0].ticket_digest_sha256},  # ticket -> receipt
        {"ticket_digest_sha256": a1.replicas[0].receipt_digest_sha256},  # receipt -> ticket
        {"ticket_digest_sha256": a1.replicas[1].receipt_digest_sha256},  # another replica's
    ):
        with pytest.raises(AssignmentSnapshotError) as failure:
            advance_snapshot_lineage(lineage, swapped(**changes))
        assert failure.value.code == "snapshot_incarnation_facts_reused", changes
    advance_snapshot_lineage(lineage, swapped())
    document = json.loads(snapshot_lineage_bytes(lineage))
    document["used_receipt_digests"] = sorted(
        {*document["used_receipt_digests"], document["used_ticket_digests"][0]}
    )
    unsigned = {k: v for k, v in document.items() if k != "lineage_digest_sha256"}
    document["lineage_digest_sha256"] = canonical_digest(unsigned)
    with pytest.raises(ValidationError, match="lineage_used_facts_overlap"):
        SnapshotLineage.model_validate(document)


def test_lineage_parser_requires_exact_history_and_in_range_era_claims() -> None:
    golden = build_snapshot()
    alpha, beta = fixture_deployments()
    genesis = build_initial_snapshot_lineage(
        central_authority_fingerprint_sha256=golden.central_authority_fingerprint_sha256
    )
    lineage = advance_snapshot_lineage(
        advance_snapshot_lineage(genesis, golden),
        build_snapshot(
            snapshot_sequence=2,
            state_revision=8,
            snapshot_deployments=[snapshot_deployment_from(beta)],
        ),
    )
    era_two = begin_snapshot_lineage_era(lineage)

    def reseal(base: SnapshotLineage, **changes: Any) -> dict[str, Any]:
        document = {**json.loads(snapshot_lineage_bytes(base)), **changes}
        unsigned = {k: v for k, v in document.items() if k != "lineage_digest_sha256"}
        return {**document, "lineage_digest_sha256": canonical_digest(unsigned)}

    for changes, code in (
        ({"last_snapshot_sequence": 3}, "lineage_history_not_contiguous"),
        ({"last_snapshot_sequence": 7}, "lineage_history_not_contiguous"),
        ({"accepted_snapshot_count": 1}, "lineage_history_not_contiguous"),
        ({"history_start_snapshot_sequence": 2}, "lineage_history_not_contiguous"),
    ):
        with pytest.raises(ValidationError, match=code):
            SnapshotLineage.model_validate(reseal(lineage, **changes))
    boundary = json.loads(snapshot_lineage_bytes(era_two))["era_boundaries"][0]
    with pytest.raises(ValidationError, match="greater_than_equal"):
        SnapshotLineage.model_validate(
            reseal(era_two, era_boundaries=[{**boundary, "opened_after_snapshot_sequence": 0}])
        )
    for opened in (3, 9):
        with pytest.raises(ValidationError, match="lineage_era_invalid"):
            SnapshotLineage.model_validate(
                reseal(
                    era_two,
                    era_boundaries=[{**boundary, "opened_after_snapshot_sequence": opened}],
                )
            )
    era_three = begin_snapshot_lineage_era(
        advance_snapshot_lineage(
            era_two,
            build_snapshot(
                snapshot_sequence=3,
                state_revision=9,
                snapshot_deployments=[snapshot_deployment_from(beta)],
            ),
        )
    )
    boundaries = json.loads(snapshot_lineage_bytes(era_three))["era_boundaries"]
    assert [item["opened_after_snapshot_sequence"] for item in boundaries] == [2, 3]
    with pytest.raises(ValidationError, match="lineage_era_invalid"):
        SnapshotLineage.model_validate(
            reseal(
                era_three,
                era_boundaries=[
                    {**boundaries[0], "opened_after_snapshot_sequence": 3},
                    {**boundaries[1], "opened_after_snapshot_sequence": 2},
                ],
            )
        )
    stale_seen = json.loads(snapshot_lineage_bytes(lineage))
    stale_seen["replicas"][0]["last_seen_snapshot_sequence"] = 9
    with pytest.raises(ValidationError, match="lineage_replica_seen_out_of_range"):
        SnapshotLineage.model_validate(reseal(lineage, replicas=stale_seen["replicas"]))
    del alpha


def test_history_gap_preflight_names_every_legacy_sequence_jump() -> None:
    """Base-contract histories may skip sequences; the lineage needs to know before it replays."""

    golden = build_snapshot()
    _, beta = fixture_deployments()
    second = build_snapshot(
        snapshot_sequence=2, state_revision=8, snapshot_deployments=[snapshot_deployment_from(beta)]
    )
    fifth = build_snapshot(
        snapshot_sequence=5, state_revision=9, snapshot_deployments=[snapshot_deployment_from(beta)]
    )
    sixth = build_snapshot(
        snapshot_sequence=6, state_revision=9, snapshot_deployments=[snapshot_deployment_from(beta)]
    )
    assert snapshot_history_gaps([golden, second]) == []
    assert snapshot_history_gaps([golden, second, fifth, sixth]) == [(2, 5)]
    genesis = build_initial_snapshot_lineage(
        central_authority_fingerprint_sha256=golden.central_authority_fingerprint_sha256
    )
    with pytest.raises(AssignmentSnapshotError) as failure:
        replay_snapshot_lineage(genesis, [golden, second, fifth, sixth])
    assert failure.value.code == "snapshot_lineage_gap"
    # The documented late start: a lineage whose memory begins after the jump.
    restarted = build_initial_snapshot_lineage(
        central_authority_fingerprint_sha256=golden.central_authority_fingerprint_sha256,
        first_snapshot_sequence=5,
    )
    seeded = replay_snapshot_lineage(restarted, [fifth, sixth])
    assert (seeded.history_start_snapshot_sequence, seeded.last_snapshot_sequence) == (5, 6)


def _fresh_capture(
    sequence: int, *, deployments: list[SnapshotDeployment]
) -> ActiveAssignmentSnapshot:
    return build_snapshot(
        snapshot_sequence=sequence, state_revision=6 + sequence, snapshot_deployments=deployments
    )


def test_exact_cap_turnover_recovers_only_through_a_boundary_taken_for_the_candidate() -> None:
    """At the replica-lineage cap, replacing every replica_id needs boundary-plus-candidate.

    A plain era boundary keeps every active lineage, so a capture that
    continues none of them still overflows; a boundary taken for that capture
    keeps only what it continues and the capture is then accepted. The bound is
    injected small so the lifecycle is exercised exactly at the cap.
    """

    golden = build_snapshot()
    alpha, beta = fixture_deployments()
    genesis = build_initial_snapshot_lineage(
        central_authority_fingerprint_sha256=golden.central_authority_fingerprint_sha256
    )
    only_alpha = _fresh_capture(1, deployments=[snapshot_deployment_from(alpha)])
    lineage = advance_snapshot_lineage(genesis, only_alpha, max_replicas=3)
    assert len(lineage.replicas) == 3
    turnover = _fresh_capture(2, deployments=[snapshot_deployment_from(beta)])
    with pytest.raises(AssignmentSnapshotError) as failure:
        advance_snapshot_lineage(lineage, turnover, max_replicas=3)
    assert failure.value.code == "snapshot_lineage_overflow"
    plain = begin_snapshot_lineage_era(lineage)
    assert len(plain.replicas) == 3
    with pytest.raises(AssignmentSnapshotError) as failure:
        advance_snapshot_lineage(plain, turnover, max_replicas=3)
    assert failure.value.code == "snapshot_lineage_overflow"
    taken = begin_snapshot_lineage_era(lineage, retain_for=turnover)
    assert taken.replicas == [] and taken.era == 2
    boundary = taken.era_boundaries[0]
    assert boundary.retained_for_snapshot_digest_sha256 == turnover.snapshot_digest_sha256
    assert boundary.dropped_replica_lineages == 3
    recovered = advance_snapshot_lineage(taken, turnover, max_replicas=3)
    assert [item.deployment_id for item in recovered.replicas] == ["fixture-beta"] * 3
    assert parse_snapshot_lineage(snapshot_lineage_bytes(recovered)) == recovered
    # The candidate must be the very next capture and share the authority.
    with pytest.raises(AssignmentSnapshotError) as failure:
        begin_snapshot_lineage_era(
            lineage, retain_for=_fresh_capture(3, deployments=[snapshot_deployment_from(beta)])
        )
    assert failure.value.code == "snapshot_lineage_gap"
    with pytest.raises(AssignmentSnapshotError) as failure:
        begin_snapshot_lineage_era(
            lineage,
            retain_for=build_snapshot(
                snapshot_sequence=2, state_revision=8, central_authority=label_digest("other")
            ),
        )
    assert failure.value.code == "snapshot_authority_mismatch"
    # A partially continued capture keeps exactly the continued lineages.
    partial = begin_snapshot_lineage_era(
        advance_snapshot_lineage(genesis, golden),
        retain_for=_fresh_capture(2, deployments=[snapshot_deployment_from(beta)]),
    )
    assert [item.deployment_id for item in partial.replicas] == ["fixture-beta"] * 3


def test_history_preflight_rejects_duplicates_and_rollbacks_as_never_compatible() -> None:
    """Only a forward skip is a compatibility gap; a repeated or lower sequence is refused."""

    golden = build_snapshot()
    _, beta = fixture_deployments()
    duplicate_empty = build_snapshot([], snapshot_sequence=1, state_revision=8)
    reuse = build_snapshot(snapshot_sequence=2, state_revision=9)
    with pytest.raises(AssignmentSnapshotError) as failure:
        snapshot_history_gaps([golden, duplicate_empty, reuse])
    assert failure.value.code == "snapshot_sequence_not_increasing"
    with pytest.raises(AssignmentSnapshotError) as failure:
        snapshot_history_gaps([reuse, golden])
    assert failure.value.code == "snapshot_sequence_not_increasing"
    # Every other base-contract invariant is enforced across the skip too.
    skipped = build_snapshot(
        snapshot_sequence=5, state_revision=6, snapshot_deployments=[snapshot_deployment_from(beta)]
    )
    with pytest.raises(AssignmentSnapshotError) as failure:
        snapshot_history_gaps([golden, skipped])
    assert failure.value.code == "snapshot_revision_rollback"
    forward = build_snapshot(
        snapshot_sequence=5, state_revision=9, snapshot_deployments=[snapshot_deployment_from(beta)]
    )
    assert snapshot_history_gaps([golden, forward]) == [(1, 5)]
    assert snapshot_history_gaps([golden]) == [] and snapshot_history_gaps([]) == []


def test_lineage_parser_refuses_duplicate_facts_among_current_replicas() -> None:
    golden = build_snapshot()
    lineage = advance_snapshot_lineage(
        build_initial_snapshot_lineage(
            central_authority_fingerprint_sha256=golden.central_authority_fingerprint_sha256
        ),
        golden,
    )
    base = json.loads(snapshot_lineage_bytes(lineage))
    for field, source in (
        ("assignment_nonce", "assignment_nonce"),
        ("ticket_digest_sha256", "ticket_digest_sha256"),
        ("receipt_digest_sha256", "receipt_digest_sha256"),
        ("receipt_digest_sha256", "ticket_digest_sha256"),  # cross-role copy
    ):
        document = json.loads(json.dumps(base))
        replica = document["replicas"][1]
        replica[field] = document["replicas"][0][source]
        if field == "assignment_nonce":
            replica["endpoint_id"] = (
                f"{replica['replica_id']}-g{replica['generation']}-{replica[field]}"
            )
        unsigned = {k: v for k, v in document.items() if k != "lineage_digest_sha256"}
        document["lineage_digest_sha256"] = canonical_digest(unsigned)
        with pytest.raises(ValidationError, match="lineage_replica_facts_duplicate"):
            SnapshotLineage.model_validate(document)


def test_era_boundary_claims_are_validated_exactly() -> None:
    golden = build_snapshot()
    _, beta = fixture_deployments()
    genesis = build_initial_snapshot_lineage(
        central_authority_fingerprint_sha256=golden.central_authority_fingerprint_sha256
    )
    lineage = advance_snapshot_lineage(genesis, golden)
    era_two = begin_snapshot_lineage_era(lineage)

    def reseal(base: SnapshotLineage, **changes: Any) -> dict[str, Any]:
        document = {**json.loads(snapshot_lineage_bytes(base)), **changes}
        unsigned = {k: v for k, v in document.items() if k != "lineage_digest_sha256"}
        return {**document, "lineage_digest_sha256": canonical_digest(unsigned)}

    boundary = json.loads(snapshot_lineage_bytes(era_two))["era_boundaries"][0]
    for field, ceiling in (
        ("dropped_assignment_nonces", MAX_LINEAGE_FACTS),
        ("dropped_ticket_digests", MAX_LINEAGE_FACTS),
        ("dropped_receipt_digests", MAX_LINEAGE_FACTS),
        ("dropped_replica_lineages", MAX_LINEAGE_REPLICAS),
    ):
        with pytest.raises(ValidationError, match="less_than_equal"):
            SnapshotLineage.model_validate(
                reseal(era_two, era_boundaries=[{**boundary, field: ceiling + 1}])
            )
    # An immediate boundary is this document's own transition: its predecessor
    # is the top-level predecessor.
    with pytest.raises(ValidationError, match="lineage_era_invalid"):
        SnapshotLineage.model_validate(
            reseal(
                era_two,
                era_boundaries=[{**boundary, "previous_lineage_digest_sha256": "0" * 64}],
            )
        )
    # Dropped lineages plus the retained ones cannot exceed the cap.
    with pytest.raises(ValidationError, match="lineage_era_invalid"):
        SnapshotLineage.model_validate(
            reseal(
                era_two,
                era_boundaries=[{**boundary, "dropped_replica_lineages": MAX_LINEAGE_REPLICAS}],
            )
        )
    # Once a capture follows the boundary, the top-level predecessor moves on
    # and the boundary keeps its own; that is the valid shape.
    followed = advance_snapshot_lineage(
        era_two,
        build_snapshot(
            snapshot_sequence=2,
            state_revision=8,
            snapshot_deployments=[snapshot_deployment_from(beta)],
        ),
    )
    assert followed.previous_lineage_digest_sha256 == era_two.lineage_digest_sha256
    assert (
        followed.era_boundaries[0].previous_lineage_digest_sha256 == lineage.lineage_digest_sha256
    )
    assert parse_snapshot_lineage(snapshot_lineage_bytes(followed)) == followed


def _many_fresh_replicas(count: int, *, sequence: int) -> ActiveAssignmentSnapshot:
    golden = build_snapshot()
    deployments = []
    for index in range(count):
        deployment_id = f"d{index:05d}"
        replica = build_snapshot_replica(
            miner_uid=10,
            miner_hotkey="MinerA",
            miner_service_public_key=fixture_deployments()[0].replicas[0].miner_service_public_key,
            generation=1,
            assignment_nonce=label_digest(f"nonce-{deployment_id}-{sequence}")[:32],
            deployment_id=deployment_id,
            ticket_digest_sha256=label_digest(f"ticket-{deployment_id}-{sequence}"),
            receipt_digest_sha256=label_digest(f"receipt-{deployment_id}-{sequence}"),
            chain_block=golden.finalized_height - 60,
            expires_at_block=golden.finalized_height + 60,
            ticket_issued_at_epoch=BASE_EPOCH - 500,
            ticket_expires_at_epoch=BASE_EPOCH + 3_500,
            route_activated_at_epoch=BASE_EPOCH - 100,
        )
        deployments.append(
            build_snapshot_deployment(
                deployment_id=deployment_id,
                campaign_sequence=1,
                route_host=f"{deployment_id}.mock.local",
                build_id="0" * 24,
                challenge_sha256=label_digest(f"challenge-{deployment_id}"),
                image_digest="sha256:" + label_digest("image"),
                workload_spec_digest_sha256=label_digest("workload"),
                attestation_requirement="miner_service_key_v1",
                replicas=[replica],
            )
        )
    return build_snapshot(
        snapshot_sequence=sequence, state_revision=6 + sequence, snapshot_deployments=deployments
    )


def test_freshness_checking_scales_linearly_with_the_capture() -> None:
    """Advancing over N fresh replicas must not rebuild the retained-fact union per replica.

    Quadratic behaviour makes 4x the replicas cost ~16x; linear costs ~4x. The
    ratio is measured rather than an absolute time so the guard holds on slow
    CI runners.
    """

    golden = build_snapshot()
    genesis = build_initial_snapshot_lineage(
        central_authority_fingerprint_sha256=golden.central_authority_fingerprint_sha256
    )
    small = _many_fresh_replicas(512, sequence=1)
    large = _many_fresh_replicas(2_048, sequence=1)
    advance_snapshot_lineage(genesis, small)  # warm caches
    best_small = min(_timed(lambda: advance_snapshot_lineage(genesis, small)) for _ in range(3))
    best_large = min(_timed(lambda: advance_snapshot_lineage(genesis, large)) for _ in range(2))
    assert best_large < 7 * best_small, (best_small, best_large)


def _timed(action: Callable[[], object]) -> float:
    started = time.perf_counter()
    action()
    return time.perf_counter() - started


def test_replay_reproduces_recorded_era_boundaries() -> None:
    """A history with a boundary replays to the same lineage, boundary and all."""

    golden = build_snapshot()
    alpha, beta = fixture_deployments()
    a1 = snapshot_deployment_from(alpha)
    b2 = snapshot_deployment_from(
        alpha, route_activated_at_epoch=BASE_EPOCH, reissued_ticket_at_epoch=BASE_EPOCH + 1
    )
    second = _capture(2, b2)
    third = _capture(3, _reincarnation(b2, a1, generation=3))  # A's era-1 facts back in era 2
    genesis = build_initial_snapshot_lineage(
        central_authority_fingerprint_sha256=golden.central_authority_fingerprint_sha256
    )
    live = advance_snapshot_lineage(
        begin_snapshot_lineage_era(
            advance_snapshot_lineage(advance_snapshot_lineage(genesis, golden), second)
        ),
        third,
    )
    assert live.era == 2
    with pytest.raises(AssignmentSnapshotError) as failure:
        replay_snapshot_lineage(genesis, [golden, second, third])
    assert failure.value.code == "snapshot_incarnation_facts_reused"
    replayed = replay_snapshot_lineage(
        genesis, [golden, second, third], era_boundaries=live.era_boundaries
    )
    assert replayed == live
    # A boundary taken for a candidate replays with that candidate and must match it.
    taken = begin_snapshot_lineage_era(
        advance_snapshot_lineage(advance_snapshot_lineage(genesis, golden), second),
        retain_for=third,
    )
    live_taken = advance_snapshot_lineage(taken, third)
    assert (
        replay_snapshot_lineage(
            genesis, [golden, second, third], era_boundaries=live_taken.era_boundaries
        )
        == live_taken
    )
    wrong_candidate = live_taken.era_boundaries[0].model_copy(
        update={"retained_for_snapshot_digest_sha256": golden.snapshot_digest_sha256}
    )
    with pytest.raises(AssignmentSnapshotError) as failure:
        replay_snapshot_lineage(genesis, [golden, second, third], era_boundaries=[wrong_candidate])
    assert failure.value.code == "snapshot_lineage_replay_mismatch"
    forged = live.era_boundaries[0].model_copy(update={"dropped_ticket_digests": 1})
    with pytest.raises(AssignmentSnapshotError) as failure:
        replay_snapshot_lineage(genesis, [golden, second, third], era_boundaries=[forged])
    assert failure.value.code == "snapshot_lineage_replay_mismatch"
    # A boundary no retained capture reaches cannot have happened.
    with pytest.raises(AssignmentSnapshotError) as failure:
        replay_snapshot_lineage(genesis, [golden], era_boundaries=live.era_boundaries)
    assert failure.value.code == "snapshot_lineage_replay_mismatch"
    # Resuming from a persisted mid-history lineage replays only the remainder.
    partial = advance_snapshot_lineage(genesis, golden)
    assert (
        replay_snapshot_lineage(partial, [second, third], era_boundaries=live.era_boundaries)
        == live
    )


def test_boundary_candidate_commitment_is_enforced_by_the_live_lineage() -> None:
    """A boundary taken for one capture admits exactly that capture, and nothing else.

    The boundary dropped history on the candidate's account, so the live
    lineage refuses any other next capture (``snapshot_lineage_candidate_mismatch``),
    refuses a second boundary while one is pending (``snapshot_lineage_boundary_pending``),
    validates the candidate as the next capture before dropping anything, and
    every accepted live history replays to itself.
    """

    golden = build_snapshot()
    _, beta = fixture_deployments()
    genesis = build_initial_snapshot_lineage(
        central_authority_fingerprint_sha256=golden.central_authority_fingerprint_sha256
    )
    lineage = advance_snapshot_lineage(genesis, golden)
    empty_two = build_snapshot([], snapshot_sequence=2, state_revision=8)
    other_two = build_snapshot(
        snapshot_sequence=2, state_revision=8, snapshot_deployments=[snapshot_deployment_from(beta)]
    )
    prepared = begin_snapshot_lineage_era(lineage, retain_for=empty_two)
    assert prepared.replicas == []
    with pytest.raises(AssignmentSnapshotError) as failure:
        advance_snapshot_lineage(prepared, other_two)
    assert failure.value.code == "snapshot_lineage_candidate_mismatch"
    with pytest.raises(AssignmentSnapshotError) as failure:
        begin_snapshot_lineage_era(prepared)
    assert failure.value.code == "snapshot_lineage_boundary_pending"
    with pytest.raises(AssignmentSnapshotError) as failure:
        begin_snapshot_lineage_era(prepared, retain_for=other_two)
    assert failure.value.code == "snapshot_lineage_boundary_pending"
    live = advance_snapshot_lineage(prepared, empty_two)
    assert live.era == 2 and live.replicas == []
    assert (
        replay_snapshot_lineage(genesis, [golden, empty_two], era_boundaries=live.era_boundaries)
        == live
    )
    # A plain boundary (no candidate) admits any valid next capture; once a
    # capture followed it, a new boundary may open.
    plain = begin_snapshot_lineage_era(lineage)
    followed = advance_snapshot_lineage(plain, other_two)
    assert followed.era == 2
    assert begin_snapshot_lineage_era(followed).era == 3
    # An invalid candidate is refused before any history is dropped, with the
    # transition's own code.
    for candidate, code in (
        (build_snapshot(snapshot_sequence=2, state_revision=6), "snapshot_revision_rollback"),
        (build_snapshot(snapshot_sequence=3, state_revision=8), "snapshot_lineage_gap"),
        (build_snapshot(snapshot_sequence=1, state_revision=8), "snapshot_sequence_not_increasing"),
        (
            build_snapshot(snapshot_sequence=2, state_revision=8, captured_at_epoch=BASE_EPOCH - 1),
            "snapshot_capture_rollback",
        ),
        (
            build_snapshot(
                snapshot_sequence=2, state_revision=8, finalized_block_hash=label_digest("fork")
            ),
            "snapshot_finalized_fork",
        ),
    ):
        with pytest.raises(AssignmentSnapshotError) as failure:
            begin_snapshot_lineage_era(lineage, retain_for=candidate)
        assert failure.value.code == code, code
    # The parser refuses two boundaries at one sequence.
    document = json.loads(snapshot_lineage_bytes(followed))
    boundary = document["era_boundaries"][0]
    second = {
        **boundary,
        "era": 3,
        "previous_lineage_digest_sha256": followed.lineage_digest_sha256,
    }
    document["era"] = 3
    document["era_boundaries"] = [boundary, second]
    unsigned = {k: v for k, v in document.items() if k != "lineage_digest_sha256"}
    document["lineage_digest_sha256"] = canonical_digest(unsigned)
    with pytest.raises(ValidationError, match="lineage_era_invalid"):
        SnapshotLineage.model_validate(document)


def test_replay_scales_linearly_with_the_retained_history() -> None:
    golden = build_snapshot()
    genesis = build_initial_snapshot_lineage(
        central_authority_fingerprint_sha256=golden.central_authority_fingerprint_sha256
    )

    def history(count: int) -> list[ActiveAssignmentSnapshot]:
        return [
            build_snapshot([], snapshot_sequence=index, state_revision=7 + index)
            for index in range(1, count + 1)
        ]

    short, long = history(300), history(1_200)
    replay_snapshot_lineage(genesis, short)  # warm
    best_short = min(_timed(lambda: replay_snapshot_lineage(genesis, short)) for _ in range(2))
    best_long = min(_timed(lambda: replay_snapshot_lineage(genesis, long)) for _ in range(2))
    assert best_long < 7 * best_short, (best_short, best_long)
    sequential = genesis
    for snapshot in long:
        sequential = advance_snapshot_lineage(sequential, snapshot)
    assert replay_snapshot_lineage(genesis, long) == sequential


def test_builder_never_trusts_a_supplied_projection_digest_or_order() -> None:
    reversed_snapshot = build_snapshot(list(reversed(fixture_deployments())))
    assert reversed_snapshot == build_snapshot()
    deployment = snapshot_deployment_from(
        build_deployment("fixture-alpha", list(reversed(MINERS[:3])), campaign_sequence=1)
    )
    assert [item.miner_uid for item in deployment.replicas] == [10, 11, 12]


def test_canonical_bytes_round_trip_and_reject_malleability() -> None:
    rendered = (FIXTURES / "active-assignment-snapshot.v1.json").read_bytes()
    snapshot = parse_active_assignment_snapshot(rendered)
    assert active_assignment_snapshot_bytes(snapshot) == rendered
    document = json.loads(rendered)
    pretty = json.dumps(document, indent=2).encode("ascii") + b"\n"
    with pytest.raises(ValueError, match="document_not_canonical"):
        parse_active_assignment_snapshot(pretty)
    with pytest.raises(ValueError, match="document_not_canonical"):
        parse_active_assignment_snapshot(rendered.rstrip(b"\n"))
    duplicated = rendered.replace(b'"netuid":24', b'"netuid":24,"netuid":24', 1)
    with pytest.raises(ValueError, match="document_invalid"):
        parse_active_assignment_snapshot(duplicated)
    with pytest.raises(ValueError, match="document_size_invalid"):
        parse_active_assignment_snapshot(b"")
    with pytest.raises(ValueError, match="document_invalid"):
        parse_active_assignment_snapshot(rendered.replace(b"fixture-alpha", b"fixture-\xc3\xa9"))
