# SPDX-License-Identifier: AGPL-3.0-only

"""Transactional active-assignment snapshot: projection, succession, malleability."""

from __future__ import annotations

import json
from pathlib import Path

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
    TICKET_MAX_FUTURE_SKEW_SECONDS,
    ActiveAssignmentSnapshot,
    AssignmentSnapshotError,
    active_assignment_snapshot_bytes,
    build_snapshot_replica,
    parse_active_assignment_snapshot,
    project_manifest_deployments,
    verify_manifest_derived_from_snapshot,
    verify_snapshot_succession,
)

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
                ticket_issued_at_epoch=ticket_issued_at_epoch,
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


def test_signer_skew_fixture_is_the_golden_capture_at_both_tolerances() -> None:
    """The shared Go/Python parity fixture pins the +30 and +1 branches together."""

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
    # Same content as the golden capture apart from the re-stamped timing, so
    # it is the successor capture of the golden snapshot at the next revision.
    verify_snapshot_succession(build_snapshot(), snapshot)
    document = json.loads(rendered)
    document["deployments"][0]["replicas"][0]["ticket_issued_at_epoch"] += 1
    with pytest.raises(ValidationError, match="replica_activation_order_invalid"):
        ActiveAssignmentSnapshot.model_validate(document)


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
