# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import ast
import base64
import hashlib
import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest
from assignment_probe_context import (
    BASE_EPOCH,
    EVALUATION_EPOCH,
    FINALIZED_BLOCK_HASH,
    FINALIZED_HEIGHT,
    FIXTURE_PROBE_NONCE,
    MINERS,
    SCHEMA_MODELS,
    Context,
    attestation_header,
    build_deployment,
    build_manifest,
    build_policy,
    build_replica,
    challenge_value,
    digest,
    fixture_deployments,
    fixture_documents,
    label_digest,
    make_context,
    miner_key,
    schema_bytes,
    serving_response,
    sign_attestation,
    sign_manifest,
    signer_keys,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jsonschema import Draft202012Validator
from pydantic import ValidationError

import misscomputer_subnet.assignment_probe as assignment_probe_module
from misscomputer_subnet.assignment_probe import (
    MANIFEST_CHAIN_STATE_SCHEMA,
    MANIFEST_SCHEMA,
    MANIFEST_SIGNATURE_ENVELOPE_SCHEMA,
    MANIFEST_TRUST_POLICY_SCHEMA,
    PROBE_ATTESTATION_SCHEMA,
    PROBE_REPORT_SCHEMA,
    ActiveAssignmentManifest,
    ActiveDeploymentAssignment,
    AssignedReplica,
    AssignmentManifestChainState,
    AssignmentManifestSignatureEnvelope,
    AssignmentManifestTrustPolicy,
    AssignmentProbeError,
    MinerProbeAttestation,
    ProbeResponse,
    ProbeTransportFailure,
    ValidatorProbeReport,
    active_assignment_manifest_bytes,
    advance_manifest_chain_state,
    assignment_manifest_chain_state_bytes,
    assignment_manifest_signature_envelope_bytes,
    assignment_manifest_trust_policy_bytes,
    build_initial_manifest_chain_state,
    build_manifest_signature_envelope,
    build_validator_probe_report,
    evaluate_probe_response,
    manifest_signature_message,
    miner_probe_attestation_bytes,
    parse_active_assignment_manifest,
    parse_assignment_manifest_chain_state,
    parse_assignment_manifest_signature_envelope,
    parse_assignment_manifest_trust_policy,
    parse_miner_probe_attestation,
    parse_miner_probe_attestation_header,
    parse_validator_probe_report,
    validator_probe_report_bytes,
    verify_active_assignment_manifest,
    verify_miner_probe_attestation,
)

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "contracts" / "fixtures"
SCHEMAS = ROOT / "contracts" / "schemas"


def assert_rejected(code: str, function: Any, *args: object, **kwargs: object) -> None:
    with pytest.raises(AssignmentProbeError) as error:
        function(*args, **kwargs)
    assert error.value.code == code
    assert str(error.value) == code


def reseal_manifest(
    manifest: ActiveAssignmentManifest, **changes: object
) -> ActiveAssignmentManifest:
    document = manifest.model_dump(mode="json", by_alias=True)
    document.update(changes)
    document.pop("manifest_digest_sha256", None)
    if "deployments" in changes and "assignment_vector_digest_sha256" not in changes:
        document["assignment_vector_digest_sha256"] = digest(document["deployments"])
    document["manifest_digest_sha256"] = digest(document)
    return ActiveAssignmentManifest.model_validate(document)


def resigned(
    context: Context,
    manifest: ActiveAssignmentManifest,
    key_ids: Sequence[str] = ("auditor", "issuer"),
) -> list[AssignmentManifestSignatureEnvelope]:
    return sign_manifest(manifest, context.keys, key_ids)


def verify(
    context: Context,
    manifest: ActiveAssignmentManifest | None = None,
    signatures: Sequence[AssignmentManifestSignatureEnvelope] | None = None,
    policy: AssignmentManifestTrustPolicy | None = None,
    state: AssignmentManifestChainState | None = None,
    *,
    evaluation_epoch: int = EVALUATION_EPOCH,
) -> Any:
    return verify_active_assignment_manifest(
        manifest or context.manifest,
        signatures or context.signatures,
        policy or context.policy,
        state or context.state,
        evaluation_epoch=evaluation_epoch,
    )


def unverified_publication(
    *,
    signed_key_ids: Sequence[str] = ("auditor", "issuer"),
    **policy_changes: Any,
) -> tuple[
    ActiveAssignmentManifest,
    list[AssignmentManifestSignatureEnvelope],
    AssignmentManifestTrustPolicy,
    AssignmentManifestChainState,
]:
    keys = signer_keys()
    policy = build_policy(keys, **policy_changes)
    manifest = build_manifest(policy, fixture_deployments())
    signatures = sign_manifest(manifest, keys, signed_key_ids)
    return manifest, signatures, policy, build_initial_manifest_chain_state(policy)


def verify_publication(
    manifest: ActiveAssignmentManifest,
    signatures: Sequence[AssignmentManifestSignatureEnvelope],
    policy: AssignmentManifestTrustPolicy,
    state: AssignmentManifestChainState,
) -> Any:
    return verify_active_assignment_manifest(
        manifest, signatures, policy, state, evaluation_epoch=EVALUATION_EPOCH
    )


def test_happy_path_verifies_probes_and_seals_an_archivable_report() -> None:
    context = make_context()
    verification = context.verification
    assert verification.verified_signer_key_ids == ["auditor", "issuer"]
    assert verification.verified_roles == ["assignment_auditor", "assignment_issuer"]
    assert verification.reprobe is False
    assert verification.next_chain_state.accepted_manifest_count == 1
    assert verification.next_chain_state.last_sequence == 1
    assert verification.next_chain_state.last_manifest_digest_sha256 == (
        context.manifest.manifest_digest_sha256
    )
    report = context.report
    assert report.status == "serving"
    assert (report.deployment_count, report.serving_count, report.failed_count) == (2, 2, 0)
    assert report.manifest_digest_sha256 == context.manifest.manifest_digest_sha256
    assert report.prior_chain_state_digest_sha256 == context.state.state_digest_sha256
    assert report.next_chain_state_digest_sha256 == (
        verification.next_chain_state.state_digest_sha256
    )
    alpha, beta = report.observations
    assert alpha.deployment_id == "fixture-alpha"
    assert alpha.outcome == "serving"
    assert alpha.attestation_status == "verified"
    assert alpha.attestation is not None
    assert (alpha.attestation.miner_uid, alpha.attestation.miner_hotkey) == (10, "MinerA")
    assert alpha.attestation.probe_nonce == FIXTURE_PROBE_NONCE
    assert alpha.build_id_header_verified is True
    assert beta.attestation_status == "not_required"
    assert beta.attestation is None
    assert beta.outcome == "serving"
    assert beta.assignment_digest_sha256 == context.manifest.deployments[1].assignment_digest_sha256
    second = verify(context)
    assert second == verification


def test_reprobe_of_the_identical_manifest_leaves_state_unchanged() -> None:
    context = make_context()
    next_state = context.verification.next_chain_state
    again = verify(context, state=next_state, evaluation_epoch=EVALUATION_EPOCH + 60)
    assert again.reprobe is True
    assert again.next_chain_state == next_state
    report = build_validator_probe_report(
        again,
        context.policy,
        next_state,
        context.observations,
        validator_uid=7,
        validator_hotkey="ValidatorA",
        evaluation_epoch=EVALUATION_EPOCH + 60,
        edge_origin_override=True,
    )
    assert report.manifest_reprobe is True
    assert report.edge_origin_override is True
    assert report.prior_chain_state_digest_sha256 == report.next_chain_state_digest_sha256


@pytest.mark.parametrize(
    ("evaluation_epoch", "code"),
    [
        (BASE_EPOCH - 100, "manifest_future"),
        (BASE_EPOCH + 3_600, "manifest_expired"),
        (BASE_EPOCH + 1_000, "manifest_stale"),
        (BASE_EPOCH - 5_000, "trust_policy_not_yet_valid"),
        (BASE_EPOCH + 100_000, "trust_policy_expired"),
    ],
)
def test_stale_future_expired_and_policy_window_manifests_fail_closed(
    evaluation_epoch: int, code: str
) -> None:
    context = make_context()
    assert_rejected(code, verify, context, evaluation_epoch=evaluation_epoch)


def test_manifest_lifetime_and_trust_policy_binding_fail_closed() -> None:
    context = make_context()
    long_lived = build_manifest(context.policy, context.deployments, expires_at=BASE_EPOCH + 7_200)
    assert_rejected(
        "manifest_lifetime_invalid",
        verify,
        context,
        long_lived,
        resigned(context, long_lived),
    )
    other_policy = build_policy(context.keys, threshold=1)
    assert_rejected("trust_policy_mismatch", verify, context, policy=other_policy)
    foreign_manifest = reseal_manifest(
        context.manifest, central_authority_fingerprint_sha256=label_digest("other-authority")
    )
    assert_rejected(
        "authority_mismatch",
        verify,
        context,
        foreign_manifest,
        resigned(context, foreign_manifest),
    )


def test_wrong_signature_signer_swap_untrusted_threshold_roles_and_key_windows() -> None:
    context = make_context()
    message = manifest_signature_message(context.manifest)
    forged = bytearray(context.keys["auditor"].sign(message))
    forged[0] ^= 0x01
    wrong = build_manifest_signature_envelope(
        context.manifest,
        signer_key_id="auditor",
        signature_base64=base64.b64encode(bytes(forged)).decode("ascii"),
    )
    assert_rejected("signature_invalid", verify, context, signatures=[wrong, context.signatures[1]])

    swapped = build_manifest_signature_envelope(
        context.manifest,
        signer_key_id="issuer",
        signature_base64=context.signatures[0].signature_base64,
    )
    assert_rejected(
        "signature_invalid", verify, context, signatures=[context.signatures[0], swapped]
    )

    stranger = build_manifest_signature_envelope(
        context.manifest,
        signer_key_id="stranger",
        signature_base64=context.signatures[0].signature_base64,
    )
    assert_rejected(
        "signer_untrusted", verify, context, signatures=[context.signatures[0], stranger]
    )

    unbound = context.signatures[1].model_copy(
        update={"manifest_digest_sha256": label_digest("other-manifest")}
    )
    assert_rejected(
        "signature_binding_mismatch",
        verify,
        context,
        signatures=[context.signatures[0], unbound],
    )
    assert_rejected(
        "signature_binding_mismatch",
        verify,
        context,
        signatures=[context.signatures[0], context.signatures[0]],
    )
    assert_rejected("threshold_not_met", verify, context, signatures=[context.signatures[0]])

    assert_rejected(
        "required_role_missing",
        verify_publication,
        *unverified_publication(signed_key_ids=("auditor", "security")),
    )
    assert_rejected(
        "signer_revoked",
        verify_publication,
        *unverified_publication(revoked={"issuer": EVALUATION_EPOCH - 1}),
    )
    future_revocation = verify_publication(
        *unverified_publication(revoked={"issuer": EVALUATION_EPOCH + 1})
    )
    assert future_revocation.verified_signer_key_ids == ["auditor", "issuer"]
    assert_rejected(
        "signer_not_yet_valid",
        verify_publication,
        *unverified_publication(key_windows={"issuer": (BASE_EPOCH + 50, BASE_EPOCH + 100_000)}),
    )
    assert_rejected(
        "signer_expired",
        verify_publication,
        *unverified_publication(key_windows={"issuer": (BASE_EPOCH - 1_000, BASE_EPOCH + 100)}),
    )


def test_wrong_route_host_policy_and_scheme_fail_closed() -> None:
    context = make_context()
    other_suffix = build_policy(context.keys, allowed_route_host_suffixes=("other.local",))
    foreign = build_manifest(other_suffix, context.deployments)
    assert_rejected(
        "route_host_policy_violation",
        verify,
        context,
        foreign,
        sign_manifest(foreign, context.keys),
        other_suffix,
        context.state,
    )
    with pytest.raises(ValidationError, match="manifest_route_host_invalid"):
        build_manifest(context.policy, context.deployments, route_suffix="other.local")
    with pytest.raises(ValidationError):
        build_deployment("fixture-gamma", MINERS[:3], campaign_sequence=3, route_suffix="")
    with pytest.raises(ValidationError):
        reseal_manifest(context.manifest, probe_scheme="http")


def test_duplicate_conflicting_or_expired_assignments_are_rejected() -> None:
    context = make_context()
    alpha, beta = context.deployments
    duplicate_nonce = beta.model_dump(mode="json", by_alias=True)
    duplicate_nonce["replicas"][0]["assignment_nonce"] = alpha.replicas[1].assignment_nonce
    duplicate_nonce["replicas"][0]["endpoint_id"] = (
        f"{duplicate_nonce['replicas'][0]['replica_id']}-g1-{alpha.replicas[1].assignment_nonce}"
    )
    duplicate_nonce.pop("assignment_digest_sha256")
    duplicate_nonce["assignment_digest_sha256"] = digest(duplicate_nonce)
    with pytest.raises(ValidationError, match="manifest_assignment_nonce_duplicate"):
        build_manifest(context.policy, [alpha, beta.model_validate(duplicate_nonce)])

    conflicting = build_deployment("fixture-gamma", ((10, "MinerZ"),), campaign_sequence=3)
    with pytest.raises(ValidationError, match="manifest_miner_identity_conflict"):
        build_manifest(context.policy, [alpha, beta, conflicting])

    with pytest.raises(ValidationError, match="manifest_deployments_not_canonical"):
        reseal_manifest(
            context.manifest,
            deployments=[alpha.model_dump(mode="json", by_alias=True)] * 2,
        )
    with pytest.raises(ValidationError, match="assignment_replica_uid_duplicate"):
        build_deployment("fixture-gamma", ((10, "MinerA"), (10, "MinerB")), campaign_sequence=3)
    gamma = build_deployment("fixture-gamma", MINERS[:1], campaign_sequence=3)
    gamma_document = gamma.model_dump(mode="json", by_alias=True)
    gamma_document["replicas"][0]["endpoint_id"] = "fixture-gamma-MinerA-g2-" + "0" * 32
    gamma_document.pop("assignment_digest_sha256")
    gamma_document["assignment_digest_sha256"] = digest(gamma_document)
    with pytest.raises(ValidationError, match="assignment_replica_identity_invalid"):
        ActiveDeploymentAssignment.model_validate(gamma_document)
    with pytest.raises(ValidationError, match="assignment_challenge_path_invalid"):
        ActiveDeploymentAssignment.model_validate(
            {
                **gamma.model_dump(
                    mode="json", by_alias=True, exclude={"assignment_digest_sha256"}
                ),
                "challenge_path": "/__challenge/" + "0" * 24,
                "assignment_digest_sha256": digest(
                    {
                        **gamma.model_dump(
                            mode="json", by_alias=True, exclude={"assignment_digest_sha256"}
                        ),
                        "challenge_path": "/__challenge/" + "0" * 24,
                    }
                ),
            }
        )
    with pytest.raises(ValidationError, match="manifest_replica_block_expired"):
        build_manifest(context.policy, context.deployments, finalized_height=FINALIZED_HEIGHT + 60)
    with pytest.raises(ValidationError, match="manifest_replica_ticket_expired"):
        build_manifest(
            context.policy,
            context.deployments,
            issued_at=BASE_EPOCH + 3_500,
            expires_at=BASE_EPOCH + 3_600,
        )


def test_append_only_rollback_gap_link_fork_and_divergence() -> None:
    context = make_context()
    policy = context.policy
    first = context.manifest
    state_one, reprobe = advance_manifest_chain_state(context.state, first, policy)
    assert reprobe is False
    second = build_manifest(
        policy,
        context.deployments,
        sequence=2,
        previous=first.manifest_digest_sha256,
        issued_at=BASE_EPOCH + 300,
        expires_at=BASE_EPOCH + 3_900,
        finalized_height=FINALIZED_HEIGHT + 10,
        finalized_block_hash=label_digest("block-two"),
    )
    state_two, _ = advance_manifest_chain_state(state_one, second, policy)
    assert state_two.last_sequence == 2
    assert state_two.accepted_manifest_count == 2

    assert_rejected("sequence_rollback", advance_manifest_chain_state, state_two, first, policy)
    replayed, reprobe = advance_manifest_chain_state(state_two, second, policy)
    assert reprobe is True and replayed == state_two
    divergent = build_manifest(
        policy,
        context.deployments,
        sequence=2,
        previous=first.manifest_digest_sha256,
        issued_at=BASE_EPOCH + 301,
        expires_at=BASE_EPOCH + 3_900,
        finalized_height=FINALIZED_HEIGHT + 10,
        finalized_block_hash=label_digest("block-two"),
    )
    assert_rejected(
        "same_sequence_divergence", advance_manifest_chain_state, state_two, divergent, policy
    )

    def third(**changes: Any) -> ActiveAssignmentManifest:
        values: dict[str, Any] = {
            "sequence": 3,
            "previous": second.manifest_digest_sha256,
            "issued_at": BASE_EPOCH + 600,
            "expires_at": BASE_EPOCH + 4_200,
            "finalized_height": FINALIZED_HEIGHT + 20,
            "finalized_block_hash": label_digest("block-three"),
        }
        values.update(changes)
        return build_manifest(policy, context.deployments, **values)

    assert_rejected(
        "sequence_gap", advance_manifest_chain_state, state_two, third(sequence=7), policy
    )
    assert_rejected(
        "previous_link_mismatch",
        advance_manifest_chain_state,
        state_two,
        third(previous=first.manifest_digest_sha256),
        policy,
    )
    assert_rejected(
        "finalized_height_rollback",
        advance_manifest_chain_state,
        state_two,
        third(finalized_height=FINALIZED_HEIGHT + 9),
        policy,
    )
    gap_policy = build_policy(context.keys, max_finalized_height_gap=5)
    gap_first = build_manifest(gap_policy, context.deployments)
    gap_state, _ = advance_manifest_chain_state(
        build_initial_manifest_chain_state(gap_policy), gap_first, gap_policy
    )
    assert_rejected(
        "finalized_height_gap",
        advance_manifest_chain_state,
        gap_state,
        build_manifest(
            gap_policy,
            context.deployments,
            sequence=2,
            previous=gap_first.manifest_digest_sha256,
            issued_at=BASE_EPOCH + 300,
            expires_at=BASE_EPOCH + 3_900,
            finalized_height=FINALIZED_HEIGHT + 6,
            finalized_block_hash=label_digest("block-two"),
        ),
        gap_policy,
    )
    with pytest.raises(ValidationError, match="manifest_replica_block_expired"):
        third(finalized_height=FINALIZED_HEIGHT + 60)
    assert_rejected(
        "same_height_fork",
        advance_manifest_chain_state,
        state_two,
        third(finalized_height=FINALIZED_HEIGHT + 10, finalized_block_hash=FINALIZED_BLOCK_HASH),
        policy,
    )
    assert_rejected(
        "issued_at_rollback",
        advance_manifest_chain_state,
        state_two,
        third(issued_at=BASE_EPOCH + 299),
        policy,
    )
    assert_rejected("sequence_gap", advance_manifest_chain_state, context.state, second, policy)
    foreign_state = AssignmentManifestChainState.model_validate(
        {
            **context.state.model_dump(mode="json", by_alias=True),
            "central_authority_fingerprint_sha256": label_digest("elsewhere"),
            "state_digest_sha256": digest(
                {
                    **context.state.model_dump(
                        mode="json", by_alias=True, exclude={"state_digest_sha256"}
                    ),
                    "central_authority_fingerprint_sha256": label_digest("elsewhere"),
                }
            ),
        }
    )
    assert_rejected(
        "authority_mismatch", advance_manifest_chain_state, foreign_state, first, policy
    )


def failure_response(deployment: Any, **changes: Any) -> ProbeResponse:
    base = serving_response(deployment)
    values: dict[str, Any] = {
        "status": base.status,
        "headers": base.headers,
        "body": base.body,
        "latency_millis": base.latency_millis,
        "tls_leaf_certificate_sha256": base.tls_leaf_certificate_sha256,
    }
    values.update(changes)
    return ProbeResponse(**values)


def test_assignment_admission_rejects_every_small_order_miner_service_key(
    small_order_ed25519_public_key: bytes,
) -> None:
    valid = build_replica("fixture-alpha", 10, "MinerA")
    document = valid.model_dump(mode="json", by_alias=True)
    document["miner_service_public_key"] = small_order_ed25519_public_key.hex()
    with pytest.raises(ValidationError, match="ed25519_public_key_small_order"):
        AssignedReplica.model_validate(document)

    assert AssignedReplica.model_validate(valid.model_dump(mode="json", by_alias=True)) == valid


def test_identity_key_message_independent_attestation_forgery_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = make_context()
    deployment = context.manifest.deployments[0]
    valid_replica = deployment.replicas[0]
    identity_key = "01" + "00" * 31
    forged_signature = (
        "5866666666666666666666666666666666666666666666666666666666666666"
        "0100000000000000000000000000000000000000000000000000000000000000"
    )

    backend_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(identity_key))
    backend_key.verify(bytes.fromhex(forged_signature), b"first unrelated message")
    backend_key.verify(bytes.fromhex(forged_signature), b"second unrelated message")

    forged_replica = valid_replica.model_copy(update={"miner_service_public_key": identity_key})
    forged_deployment = deployment.model_copy(update={"replicas": [forged_replica]})
    forged_attestation = context.attestation.model_copy(
        update={
            "miner_service_public_key": identity_key,
            "signature_hex": forged_signature,
        }
    )

    with pytest.raises(ValueError, match="ed25519_public_key_small_order"):
        verify_miner_probe_attestation(
            forged_attestation,
            forged_deployment,
            probe_nonce=FIXTURE_PROBE_NONCE,
            response_body_sha256=deployment.challenge_sha256,
        )

    monkeypatch.setattr(
        assignment_probe_module,
        "_revalidate",
        lambda value, _model_type: value,
    )
    with pytest.raises(ValueError, match="attestation_signature_invalid"):
        verify_miner_probe_attestation(
            forged_attestation,
            forged_deployment,
            probe_nonce=FIXTURE_PROBE_NONCE,
            response_body_sha256=deployment.challenge_sha256,
        )
    observation = evaluate_probe_response(
        forged_deployment,
        context.policy,
        probe_nonce=FIXTURE_PROBE_NONCE,
        result=serving_response(forged_deployment, attestation=forged_attestation),
    )
    assert (observation.outcome, observation.failure_code, observation.attestation_status) == (
        "failed",
        "attestation_invalid",
        "rejected",
    )


def test_probe_evaluation_fail_closed_matrix() -> None:
    context = make_context()
    alpha, beta = context.manifest.deployments
    policy = context.policy
    nonce = label_digest("matrix-nonce")

    def outcome(deployment: Any, result: Any, *, policy_value: Any = policy) -> tuple[str, Any]:
        observation = evaluate_probe_response(
            deployment, policy_value, probe_nonce=nonce, result=result
        )
        return observation.outcome, observation.failure_code

    assert outcome(beta, serving_response(beta)) == ("serving", None)
    assert outcome(beta, failure_response(beta, status=500)) == ("failed", "unexpected_status")
    assert outcome(beta, failure_response(beta, status=302, body=b"")) == (
        "failed",
        "redirect_rejected",
    )
    assert outcome(beta, failure_response(beta, body=b"wrong")) == (
        "failed",
        "body_digest_mismatch",
    )
    build_only = tuple(item for item in serving_response(beta).headers if item[0] != "X-Build-ID")
    assert outcome(beta, failure_response(beta, headers=build_only)) == (
        "failed",
        "build_id_header_mismatch",
    )
    assert outcome(
        beta, failure_response(beta, headers=(*build_only, ("x-build-id", "0" * 24)))
    ) == ("failed", "build_id_header_mismatch")
    assert outcome(
        beta,
        failure_response(
            beta, headers=(*serving_response(beta).headers, ("X-Build-ID", beta.build_id))
        ),
    ) == ("failed", "build_id_header_mismatch")
    oversized = failure_response(beta, body=b"x" * (policy.max_response_bytes + 1))
    assert outcome(beta, oversized) == ("failed", "response_oversized")
    for code in ("timeout", "connection_failed", "tls_handshake_failed", "tls_certificate_invalid"):
        observation = evaluate_probe_response(
            beta,
            policy,
            probe_nonce=nonce,
            result=ProbeTransportFailure(code, 1_000),  # type: ignore[arg-type]
        )
        assert (observation.outcome, observation.failure_code) == ("failed", code)
        assert observation.response_status is None
        assert observation.response_bytes == 0

    pinned = build_policy(
        context.keys, pinned_edge_leaf_certificate_sha256=(label_digest("edge-leaf"),)
    )
    assert outcome(
        beta,
        failure_response(beta, tls_leaf_certificate_sha256=label_digest("edge-leaf")),
        policy_value=pinned,
    ) == ("serving", None)
    assert outcome(
        beta,
        failure_response(beta, tls_leaf_certificate_sha256=label_digest("other-leaf")),
        policy_value=pinned,
    ) == ("failed", "tls_pin_mismatch")
    assert outcome(beta, serving_response(beta), policy_value=pinned) == (
        "failed",
        "tls_pin_mismatch",
    )

    replica = alpha.replicas[0]
    assert outcome(alpha, serving_response(alpha)) == ("failed", "attestation_missing")
    good = sign_attestation(alpha, replica, probe_nonce=nonce)
    observation = evaluate_probe_response(
        alpha, policy, probe_nonce=nonce, result=serving_response(alpha, attestation=good)
    )
    assert (observation.outcome, observation.attestation_status) == ("serving", "verified")
    assert observation.attestation == good
    stale_nonce = sign_attestation(alpha, replica, probe_nonce=label_digest("old-nonce"))
    assert outcome(alpha, serving_response(alpha, attestation=stale_nonce)) == (
        "failed",
        "attestation_invalid",
    )
    wrong_key = sign_attestation(alpha, replica, probe_nonce=nonce, signing_key=miner_key("MinerB"))
    assert outcome(alpha, serving_response(alpha, attestation=wrong_key)) == (
        "failed",
        "attestation_invalid",
    )
    foreign_replica = build_replica("fixture-alpha", 13, "MinerD")
    outsider = sign_attestation(alpha, foreign_replica, probe_nonce=nonce)
    assert outcome(alpha, serving_response(alpha, attestation=outsider)) == (
        "failed",
        "attestation_invalid",
    )
    wrong_body = sign_attestation(
        alpha, replica, probe_nonce=nonce, response_body_sha256=label_digest("other-body")
    )
    assert outcome(alpha, serving_response(alpha, attestation=wrong_body)) == (
        "failed",
        "attestation_invalid",
    )
    garbage = failure_response(
        beta, headers=(*serving_response(beta).headers, ("X-Miss-Probe-Attestation", "!!!"))
    )
    assert outcome(beta, garbage) == ("failed", "attestation_invalid")
    beta_attested = sign_attestation(beta, beta.replicas[0], probe_nonce=nonce)
    volunteer = evaluate_probe_response(
        beta, policy, probe_nonce=nonce, result=serving_response(beta, attestation=beta_attested)
    )
    assert (volunteer.outcome, volunteer.attestation_status) == ("serving", "verified")
    duplicated = failure_response(
        alpha,
        headers=(
            *serving_response(alpha).headers,
            ("X-Miss-Probe-Attestation", attestation_header(good)),
            ("X-Miss-Probe-Attestation", attestation_header(good)),
        ),
    )
    assert outcome(alpha, duplicated) == ("failed", "attestation_invalid")
    with pytest.raises(ValueError, match="probe_nonce_invalid"):
        evaluate_probe_response(beta, policy, probe_nonce="short", result=serving_response(beta))


def test_attestation_header_round_trip_and_rejections() -> None:
    context = make_context()
    header = attestation_header(context.attestation)
    assert parse_miner_probe_attestation_header(header) == context.attestation
    for invalid in ("", "not base64!", header[:-4], base64.b64encode(b"{}").decode("ascii")):
        with pytest.raises(ValueError, match="attestation_header_invalid"):
            parse_miner_probe_attestation_header(invalid)
    padded = base64.b64encode(
        json.dumps(context.attestation.model_dump(mode="json", by_alias=True), indent=1).encode()
    ).decode("ascii")
    with pytest.raises(ValueError, match="attestation_header_invalid"):
        parse_miner_probe_attestation_header(padded)
    with pytest.raises(ValidationError, match="attestation_endpoint_invalid"):
        MinerProbeAttestation.model_validate(
            {
                **context.attestation.model_dump(mode="json", by_alias=True),
                "endpoint_id": "fixture-alpha-MinerA-g9-" + "0" * 32,
            }
        )


def test_report_requires_exact_deployment_coverage_and_counts_failures() -> None:
    context = make_context()
    verification = context.verification
    assert_rejected(
        "observation_coverage_mismatch",
        build_validator_probe_report,
        verification,
        context.policy,
        context.state,
        context.observations[:1],
        validator_uid=7,
        validator_hotkey="ValidatorA",
        evaluation_epoch=EVALUATION_EPOCH,
        edge_origin_override=False,
    )
    beta = context.manifest.deployments[1]
    failed = evaluate_probe_response(
        beta,
        context.policy,
        probe_nonce=label_digest("failed-nonce"),
        result=ProbeTransportFailure("timeout", 5_000),
    )
    degraded = build_validator_probe_report(
        verification,
        context.policy,
        context.state,
        [context.observations[0], failed],
        validator_uid=7,
        validator_hotkey="ValidatorA",
        evaluation_epoch=EVALUATION_EPOCH,
        edge_origin_override=False,
    )
    assert degraded.status == "degraded"
    assert (degraded.serving_count, degraded.failed_count) == (1, 1)
    assert degraded.observations[1].failure_code == "timeout"
    with pytest.raises(ValidationError, match="report_status_invalid"):
        ValidatorProbeReport.model_validate(
            {
                **degraded.model_dump(mode="json", by_alias=True, exclude={"report_digest_sha256"}),
                "status": "serving",
                "report_digest_sha256": digest(
                    {
                        **degraded.model_dump(
                            mode="json", by_alias=True, exclude={"report_digest_sha256"}
                        ),
                        "status": "serving",
                    }
                ),
            }
        )


def test_canonical_contract_bytes_round_trip_and_reject_malleability() -> None:
    context = make_context()
    contracts = [
        (
            context.manifest,
            active_assignment_manifest_bytes,
            parse_active_assignment_manifest,
            "manifest_digest_sha256",
        ),
        (
            context.policy,
            assignment_manifest_trust_policy_bytes,
            parse_assignment_manifest_trust_policy,
            "trust_policy_digest_sha256",
        ),
        (
            context.signatures[0],
            assignment_manifest_signature_envelope_bytes,
            parse_assignment_manifest_signature_envelope,
            None,
        ),
        (
            context.verification.next_chain_state,
            assignment_manifest_chain_state_bytes,
            parse_assignment_manifest_chain_state,
            "state_digest_sha256",
        ),
        (
            context.attestation,
            miner_probe_attestation_bytes,
            parse_miner_probe_attestation,
            None,
        ),
        (
            context.report,
            validator_probe_report_bytes,
            parse_validator_probe_report,
            "report_digest_sha256",
        ),
    ]
    for model, canonicalizer, parser, sealed_field in contracts:
        rendered = canonicalizer(model)
        assert rendered.endswith(b"\n") and rendered.isascii()
        assert parser(rendered) == model
        document = json.loads(rendered)
        with pytest.raises(ValueError, match="document_not_canonical"):
            parser(json.dumps(document, indent=1).encode("ascii") + b"\n")
        with pytest.raises(ValueError, match="document_not_canonical"):
            parser(rendered[:-1])
        duplicated = rendered[:-2] + b',"schema_version":1}\n'
        with pytest.raises(ValueError, match="document_invalid"):
            parser(duplicated)
        with pytest.raises(ValueError, match="document_invalid"):
            parser(rendered[:-2] + b',"unexpected":1}\n')
        with pytest.raises(ValueError, match="document_size_invalid"):
            parser(b"")
        if sealed_field is not None:
            tampered = {**document, sealed_field: "0" * 64}
            with pytest.raises(ValueError, match="document_invalid"):
                parser(json.dumps(tampered, sort_keys=True, separators=(",", ":")).encode() + b"\n")
    with pytest.raises(ValueError, match="document_size_invalid"):
        parse_assignment_manifest_signature_envelope(b"{" * (16 * 1_024 + 1))


def test_schema_and_fixture_names_are_stable() -> None:
    assert (
        MANIFEST_SCHEMA,
        MANIFEST_TRUST_POLICY_SCHEMA,
        MANIFEST_SIGNATURE_ENVELOPE_SCHEMA,
        MANIFEST_CHAIN_STATE_SCHEMA,
        PROBE_ATTESTATION_SCHEMA,
        PROBE_REPORT_SCHEMA,
    ) == (
        "miss.computer/misscomputer-subnet/active-assignment-manifest",
        "miss.computer/misscomputer-subnet/assignment-manifest-trust-policy",
        "miss.computer/misscomputer-subnet/assignment-manifest-signature-envelope",
        "miss.computer/misscomputer-subnet/assignment-manifest-chain-state",
        "miss.computer/misscomputer-subnet/miner-probe-attestation",
        "miss.computer/misscomputer-subnet/validator-probe-report",
    )


@pytest.mark.parametrize(
    ("stem", "parser"),
    [
        ("active-assignment-manifest", parse_active_assignment_manifest),
        ("assignment-manifest-trust-policy", parse_assignment_manifest_trust_policy),
        ("assignment-manifest-signature-envelope", parse_assignment_manifest_signature_envelope),
        ("assignment-manifest-chain-state", parse_assignment_manifest_chain_state),
        ("miner-probe-attestation", parse_miner_probe_attestation),
        ("validator-probe-report", parse_validator_probe_report),
    ],
)
def test_generated_schema_and_canonical_fixture(stem: str, parser: Any) -> None:
    schema = json.loads((SCHEMAS / f"{stem}.v1.schema.json").read_bytes())
    fixture_bytes = (FIXTURES / f"{stem}.v1.json").read_bytes()
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(json.loads(fixture_bytes))
    assert parser(fixture_bytes)
    assert (SCHEMAS / f"{stem}.v1.schema.json").read_bytes() == schema_bytes(SCHEMA_MODELS[stem])


def test_golden_fixtures_are_reproducible_and_verify_with_external_signatures() -> None:
    context = make_context()
    for stem, rendered in fixture_documents(context).items():
        assert (FIXTURES / f"{stem}.v1.json").read_bytes() == rendered
    policy = parse_assignment_manifest_trust_policy(
        (FIXTURES / "assignment-manifest-trust-policy.v1.json").read_bytes()
    )
    manifest = parse_active_assignment_manifest(
        (FIXTURES / "active-assignment-manifest.v1.json").read_bytes()
    )
    envelope = parse_assignment_manifest_signature_envelope(
        (FIXTURES / "assignment-manifest-signature-envelope.v1.json").read_bytes()
    )
    genesis = AssignmentManifestChainState.model_validate(
        context.state.model_dump(mode="json", by_alias=True)
    )
    result = verify_active_assignment_manifest(
        manifest,
        [envelope, context.signatures[1]],
        policy,
        genesis,
        evaluation_epoch=EVALUATION_EPOCH,
    )
    assert assignment_manifest_chain_state_bytes(result.next_chain_state) == (
        (FIXTURES / "assignment-manifest-chain-state.v1.json").read_bytes()
    )
    report = parse_validator_probe_report(
        (FIXTURES / "validator-probe-report.v1.json").read_bytes()
    )
    assert report.manifest_digest_sha256 == manifest.manifest_digest_sha256
    assert report.observations[0].attestation == parse_miner_probe_attestation(
        (FIXTURES / "miner-probe-attestation.v1.json").read_bytes()
    )
    assert challenge_value("fixture-alpha") != challenge_value("fixture-beta")
    assert fixture_deployments()[0].attestation_requirement == "miner_service_key_v1"


def test_source_has_only_public_offline_pure_capabilities() -> None:
    source = (ROOT / "src" / "misscomputer_subnet" / "assignment_probe.py").read_text()
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
        elif isinstance(node, ast.Constant) and isinstance(node.value, float):
            pytest.fail("assignment probe source contains a floating-point literal")
    assert imported_roots <= {
        "__future__",
        "base64",
        "binascii",
        "collections",
        "cryptography",
        "dataclasses",
        "ed25519_trust",
        "hashlib",
        "json",
        "pydantic",
        "typing",
    }
    assert not called_names & {
        "Popen",
        "connect",
        "create_subprocess_exec",
        "getenv",
        "open",
        "request",
        "run",
        "set_weights",
        "sign",
        "submit",
        "system",
        "urlopen",
        "write_text",
        "write_bytes",
    }
    lowered = source.lower()
    for forbidden in (
        "ed25519privatekey",
        "import bittensor",
        "import httpx",
        "import os",
        "import requests",
        "import socket",
        "import subprocess",
        "os.environ",
        ".sign(",
        "wallet.",
        "token_hex",
    ):
        assert forbidden not in lowered


@pytest.mark.parametrize(
    ("model", "expected_schema"),
    [
        (ActiveAssignmentManifest, MANIFEST_SCHEMA),
        (AssignmentManifestTrustPolicy, MANIFEST_TRUST_POLICY_SCHEMA),
        (AssignmentManifestSignatureEnvelope, MANIFEST_SIGNATURE_ENVELOPE_SCHEMA),
        (AssignmentManifestChainState, MANIFEST_CHAIN_STATE_SCHEMA),
        (MinerProbeAttestation, PROBE_ATTESTATION_SCHEMA),
        (ValidatorProbeReport, PROBE_REPORT_SCHEMA),
    ],
)
def test_all_top_level_contracts_are_extra_forbid(model: Any, expected_schema: str) -> None:
    schema = model.model_json_schema()
    assert schema["additionalProperties"] is False
    assert schema["properties"]["schema"]["const"] == expected_schema


def test_public_manifest_carries_only_public_safe_facts() -> None:
    rendered = (FIXTURES / "active-assignment-manifest.v1.json").read_bytes().decode("ascii")
    for forbidden in (
        "axon",
        "credential",
        "encrypted_image_key",
        "manifest_key",
        "private",
        "provider",
        "secret",
        "seed",
        "token",
        "tunnel",
        "wallet",
    ):
        assert forbidden not in rendered.lower()
    manifest = parse_active_assignment_manifest(rendered.encode("ascii"))
    assert hashlib.sha256(challenge_value("fixture-alpha").encode()).hexdigest() == (
        manifest.deployments[0].challenge_sha256
    )
    assert challenge_value("fixture-alpha") not in rendered
    assert set(signer_keys()) == {"auditor", "issuer", "security"}
