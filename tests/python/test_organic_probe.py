# SPDX-License-Identifier: AGPL-3.0-only
"""Manifest v2 publication/verification and hidden organic probe evaluation."""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

import pytest
from assignment_probe_context import BASE_EPOCH, FINALIZED_HEIGHT, ROOT, signer_keys
from jsonschema import Draft202012Validator
from organic_context import (
    BEHAVIORS,
    EPOCH,
    SCHEMA_MODELS,
    SHOP,
    VALIDATOR_HOTKEY,
    build_deployment,
    build_manifest,
    endpoint,
    fixture_deployments,
    fixture_documents,
    fixture_path,
    make_context,
    probe,
    sign_manifest,
)
from pydantic import ValidationError

from misscomputer_subnet.assignment_probe import (
    AssignmentProbeError,
    build_initial_manifest_chain_state,
)
from misscomputer_subnet.checkpoint_score_contracts import parse_canonical_score_report
from misscomputer_subnet.contract_codec import canonical_json, digest, model_document
from misscomputer_subnet.organic_contracts import (
    ActiveAssignmentManifestV2,
    OrganicDeploymentAssignment,
)
from misscomputer_subnet.organic_manifest import (
    organic_assignment_manifest_bytes,
    organic_manifest_signature_message,
    parse_organic_assignment_manifest,
    verify_organic_assignment_manifest,
)
from misscomputer_subnet.organic_probe import (
    attestation_v2_header,
    parse_attestation_v2_header,
    parse_organic_probe_observation,
    parse_probe_authorization_header,
    plan_hidden_probes,
    probe_authorization_header,
)
from misscomputer_subnet.organic_scoring import (
    parse_organic_availability_score,
    parse_organic_epoch_score,
)
from misscomputer_subnet.validator_decision import parse_validator_weight_decision

PARSERS: dict[str, Any] = {
    "organic-probe-observation": parse_organic_probe_observation,
    "organic-epoch-score": parse_organic_epoch_score,
    "organic-availability-score": parse_organic_availability_score,
    "organic-central-score-report": parse_canonical_score_report,
    "validator-weight-decision": parse_validator_weight_decision,
}


@pytest.fixture(scope="module")
def context():  # type: ignore[no-untyped-def]
    return make_context()


def verify(context, manifest, signatures, *, at=BASE_EPOCH, state=None, height=FINALIZED_HEIGHT):  # type: ignore[no-untyped-def]
    return verify_organic_assignment_manifest(
        manifest,
        signatures,
        context.policy,
        state or build_initial_manifest_chain_state(context.policy),
        evaluation_epoch=at,
        current_finalized_height=height,
    )


@pytest.mark.parametrize("stem", sorted(SCHEMA_MODELS))
def test_generated_schema_and_golden_fixture_are_pinned(stem: str, context) -> None:  # type: ignore[no-untyped-def]
    schema = json.loads(fixture_path(stem, schema=True).read_text())
    Draft202012Validator.check_schema(schema)
    fixture_bytes = fixture_path(stem).read_bytes()
    Draft202012Validator(schema).validate(json.loads(fixture_bytes))
    assert isinstance(PARSERS[stem](fixture_bytes), SCHEMA_MODELS[stem][1])
    rendered = json.dumps(
        SCHEMA_MODELS[stem][1].model_json_schema(), indent=2, sort_keys=True, ensure_ascii=True
    )
    assert fixture_path(stem, schema=True).read_bytes() == (rendered + "\n").encode("ascii")
    assert fixture_bytes == fixture_documents(context)[stem]


def test_manifest_v2_verifies_under_the_reused_trust_policy_and_chains(context) -> None:  # type: ignore[no-untyped-def]
    keys = signer_keys()
    first = verify(context, context.manifest, context.signatures)
    assert not first.reprobe
    second_manifest = build_manifest(
        context.policy,
        fixture_deployments()[:1],
        sequence=2,
        previous=context.manifest.manifest_digest_sha256,
        issued_at=BASE_EPOCH,
    )
    second = verify(
        context,
        second_manifest,
        sign_manifest(second_manifest, keys),
        at=BASE_EPOCH + 10,
        state=first.next_chain_state,
    )
    assert second.next_chain_state.last_manifest_digest_sha256 == (
        second_manifest.manifest_digest_sha256
    )
    rival = build_manifest(
        context.policy,
        fixture_deployments()[1:],
        sequence=2,
        previous=context.manifest.manifest_digest_sha256,
        issued_at=BASE_EPOCH,
    )
    with pytest.raises(AssignmentProbeError, match="same_sequence_divergence"):
        verify(
            context,
            rival,
            sign_manifest(rival, keys),
            at=BASE_EPOCH + 10,
            state=second.next_chain_state,
        )


#: ``pkg/organicmanifest`` pins the same digest for the canonical fixture, so
#: the Go exporter and the Python publisher sign identical v2 bytes.
CANONICAL_FIXTURE_SIGNING_MESSAGE_SHA256 = (
    "d701a12f377cc6878d1502b517fcf61061dd28794097b3c1c8c380710cb0dc9d"
)


def test_v2_signing_message_matches_the_go_exporter() -> None:
    manifest = parse_organic_assignment_manifest(
        (ROOT / "contracts" / "fixtures" / "active-assignment-manifest.v2.json").read_bytes()
    )
    message = organic_manifest_signature_message(manifest)
    assert message.startswith(
        b"miss.computer/misscomputer-subnet/active-assignment-manifest/v2/ed25519\x00"
    )
    assert hashlib.sha256(message).hexdigest() == CANONICAL_FIXTURE_SIGNING_MESSAGE_SHA256


#: The retired synthetic v1 manifest signing domain.
RETIRED_V1_SIGNATURE_DOMAIN = (
    b"miss.computer/misscomputer-subnet/active-assignment-manifest/v1/ed25519"
)


def test_v1_signing_domain_never_verifies_a_v2_manifest(context) -> None:  # type: ignore[no-untyped-def]
    v1_message = (
        RETIRED_V1_SIGNATURE_DOMAIN + b"\x00" + canonical_json(model_document(context.manifest))
    )
    with pytest.raises(AssignmentProbeError, match="signature_invalid"):
        verify(
            context,
            context.manifest,
            sign_manifest(context.manifest, signer_keys(), message=v1_message),
        )


def test_manifest_horizon_is_the_earliest_publication_lease(context) -> None:  # type: ignore[no-untyped-def]
    lease_end = BASE_EPOCH + 120
    manifest = build_manifest(
        context.policy,
        [build_deployment(SHOP, ["MinerA", "MinerB", "MinerC"], lease_expires_at=lease_end)],
    )
    signatures = sign_manifest(manifest, signer_keys())
    verify(context, manifest, signatures, at=lease_end - 1)
    with pytest.raises(AssignmentProbeError, match="manifest_expired"):
        verify(context, manifest, signatures, at=lease_end)
    with pytest.raises(AssignmentProbeError, match="manifest_replica_lease_expired"):
        verify(context, manifest, signatures, height=FINALIZED_HEIGHT + 600)


@pytest.mark.parametrize(
    ("mutate", "reason"),
    [
        pytest.param(
            lambda d: d["deployments"][0].update(challenge_path="/__challenge/" + "0" * 24),
            "extra_forbidden",
            id="synthetic-challenge",
        ),
        pytest.param(
            lambda d: d["deployments"][0].update(serving_backend="origin"),
            "extra_forbidden",
            id="origin-serving",
        ),
        pytest.param(
            lambda d: d["deployments"][0]["replicas"][0].update(route_state="pending"),
            "route_state",
            id="pending-route",
        ),
        pytest.param(
            lambda d: d["deployments"][0]["health"].update(path="/healthz?token=x"),
            "path",
            id="query-in-health-path",
        ),
    ],
)
def test_manifest_v2_has_no_representation_for_synthetic_origin_or_pending_entries(  # type: ignore[no-untyped-def]
    context, mutate, reason: str
) -> None:
    document = json.loads(organic_assignment_manifest_bytes(context.manifest))
    mutate(document)
    with pytest.raises(ValidationError, match=reason):
        ActiveAssignmentManifestV2.model_validate(document)


def test_verification_refuses_identity_reuse_across_endpoints(context) -> None:  # type: ignore[no-untyped-def]
    """Two replicas naming one hotkey under two UIDs would misattribute evidence."""

    shop = build_deployment(SHOP, ["MinerA", "MinerB", "MinerC"])
    document = model_document(shop, exclude={"assignment_digest_sha256"})
    replicas = document["replicas"]
    assert isinstance(replicas, list)
    replicas[1]["miner_service_public_key"] = replicas[0]["miner_service_public_key"]
    # Same hotkey and key under two UIDs, resealed so only the identity rule fails.
    replicas[1]["miner_hotkey"] = "MinerA"
    replicas[1]["replica_id"] = f"{SHOP}-MinerA"
    replicas[1]["endpoint_id"] = (
        f"{SHOP}-MinerA-g{replicas[1]['generation']}-{replicas[1]['assignment_nonce']}"
    )
    conflicted = OrganicDeploymentAssignment.model_validate(
        {**document, "assignment_digest_sha256": digest(document)}
    )
    manifest = build_manifest(context.policy, [conflicted])
    with pytest.raises(ValueError, match="manifest_miner_identity_conflict"):
        verify(context, manifest, sign_manifest(manifest, signer_keys()))
    early = build_manifest(context.policy, fixture_deployments(), issued_at=BASE_EPOCH - 1_000)
    with pytest.raises(ValueError, match="manifest_replica_not_yet_active"):
        verify(context, early, sign_manifest(early, signer_keys()), at=BASE_EPOCH - 900)


EXPECTED_ATTRIBUTION = {
    "success": ("success", None, "none", "verified"),
    "edge_down": ("failure", "edge_generated", "path", "not_presented"),
    "transport": ("failure", "connection_failed", "path", "not_presented"),
    "app_status": ("failure", "unexpected_status", "application", "verified"),
    "app_marker": ("failure", "marker_missing", "application", "verified"),
    "no_attestation": ("failure", "attestation_missing", "miner", "not_presented"),
    "replayed_attestation": ("failure", "attestation_fraud", "miner", "fraudulent"),
    "foreign_key": ("failure", "attestation_invalid", "miner", "rejected"),
    "altered_body": ("failure", "attestation_invalid", "miner", "rejected"),
}


@pytest.mark.parametrize("behavior", BEHAVIORS)
def test_probe_outcome_attribution_and_fraud_classification(context, behavior: str) -> None:  # type: ignore[no-untyped-def]
    """Only a verified miner signature over a mismatched identity is fraud (contract §11.3)."""

    observation = probe(
        context.policy,
        context.manifest,
        endpoint(context.manifest, SHOP, "MinerA"),
        offset_seconds=1,
        behavior=behavior,
    )
    assert (
        observation.outcome,
        observation.failure_code,
        observation.attribution,
        observation.attestation_status,
    ) == EXPECTED_ATTRIBUTION[behavior]


def test_probe_headers_carry_exact_canonical_documents(context) -> None:  # type: ignore[no-untyped-def]
    header = attestation_v2_header(context.attestation)
    assert parse_attestation_v2_header(header) == context.attestation
    assert parse_probe_authorization_header(probe_authorization_header(context.authorization)) == (
        context.authorization
    )
    spaced = json.dumps(model_document(context.attestation), sort_keys=True).encode("ascii")
    with pytest.raises(ValueError):
        parse_attestation_v2_header(base64.b64encode(spaced).decode("ascii"))


def test_hidden_schedule_is_seed_private_deterministic_and_stratified(context) -> None:  # type: ignore[no-untyped-def]
    seed = hashlib.sha256(b"validator-private-seed").digest()
    plan = plan_hidden_probes(
        seed=seed, validator_hotkey=VALIDATOR_HOTKEY, manifest=context.manifest, epoch_index=EPOCH
    )
    again = plan_hidden_probes(
        seed=seed, validator_hotkey=VALIDATOR_HOTKEY, manifest=context.manifest, epoch_index=EPOCH
    )
    other = plan_hidden_probes(
        seed=hashlib.sha256(b"another-seed").digest(),
        validator_hotkey=VALIDATOR_HOTKEY,
        manifest=context.manifest,
        epoch_index=EPOCH,
    )
    assert plan == again
    assert {(p.endpoint_id, p.fire_at_millis) for p in plan} != {
        (p.endpoint_id, p.fire_at_millis) for p in other
    }
    endpoints = {r.endpoint_id for d in context.manifest.deployments for r in d.replicas}
    epoch_start = EPOCH * 300_000
    for endpoint_id in endpoints:
        mine = sorted(
            (p for p in plan if p.endpoint_id == endpoint_id), key=lambda p: p.probe_index
        )
        assert [p.probe_index for p in mine] == [0, 1, 2]
        assert [(p.fire_at_millis - epoch_start) // 100_000 for p in mine] == [0, 1, 2]
    assert len({p.nonce for p in plan}) == len(plan)
    late = plan_hidden_probes(
        seed=seed,
        validator_hotkey=VALIDATOR_HOTKEY,
        manifest=context.manifest,
        epoch_index=(BASE_EPOCH + 3_000) // 300,
    )
    assert late == []
