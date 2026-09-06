# SPDX-License-Identifier: AGPL-3.0-only

"""Publication layout, latest pointer, and trust-policy re-anchoring."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from assignment_probe_context import (
    BASE_EPOCH,
    EVALUATION_EPOCH,
    build_manifest,
    build_policy,
    fixture_deployments,
    label_digest,
    make_context,
    sign_manifest,
    signer_keys,
)
from contract_checkpoint_context import build_pointer

from misscomputer_subnet.assignment_probe import (
    AssignmentProbeError,
    build_initial_manifest_chain_state,
    verify_active_assignment_manifest,
)
from misscomputer_subnet.manifest_publication import (
    FETCH_REQUEST_CACHE_CONTROL,
    IMMUTABLE_OBJECT_CACHE_CONTROL,
    IMMUTABLE_OBJECT_MAX_AGE_SECONDS,
    LATEST_POINTER_CACHE_CONTROL,
    LATEST_POINTER_MAX_AGE_SECONDS,
    LATEST_POINTER_OBJECT_KEY,
    ManifestPublicationError,
    assignment_manifest_latest_pointer_bytes,
    bind_latest_pointer_to_manifest,
    build_manifest_latest_pointer,
    manifest_object_key,
    parse_assignment_manifest_latest_pointer,
    rebind_manifest_chain_state_trust_policy,
    signature_object_key,
    verify_manifest_latest_pointer,
)

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "contracts" / "fixtures"


def test_object_keys_are_content_addressed_and_layout_is_versioned() -> None:
    digest = "ab" * 32
    assert manifest_object_key(digest) == f"v1/manifests/{digest}.json"
    assert signature_object_key(digest, "issuer") == f"v1/manifests/{digest}.issuer.signature.json"
    assert LATEST_POINTER_OBJECT_KEY == "v1/latest.json"
    assert f"max-age={IMMUTABLE_OBJECT_MAX_AGE_SECONDS}" in IMMUTABLE_OBJECT_CACHE_CONTROL
    assert "immutable" in IMMUTABLE_OBJECT_CACHE_CONTROL
    assert f"max-age={LATEST_POINTER_MAX_AGE_SECONDS}" in LATEST_POINTER_CACHE_CONTROL
    assert "must-revalidate" in LATEST_POINTER_CACHE_CONTROL
    assert FETCH_REQUEST_CACHE_CONTROL == "no-cache"
    # A cached pointer can never outlive the tightest fixture freshness bound.
    assert LATEST_POINTER_MAX_AGE_SECONDS <= make_context().policy.max_manifest_age_seconds


def test_pointer_names_exactly_the_published_objects() -> None:
    context = make_context()
    pointer = build_pointer()
    assert pointer.manifest_digest_sha256 == context.manifest.manifest_digest_sha256
    assert pointer.manifest_object_key == manifest_object_key(pointer.manifest_digest_sha256)
    assert pointer.signer_key_ids == ["auditor", "issuer"]
    assert pointer.signature_object_keys == [
        signature_object_key(pointer.manifest_digest_sha256, "auditor"),
        signature_object_key(pointer.manifest_digest_sha256, "issuer"),
    ]
    bind_latest_pointer_to_manifest(pointer, context.manifest)
    other = build_manifest(context.policy, fixture_deployments()[:1])
    with pytest.raises(ManifestPublicationError) as failure:
        bind_latest_pointer_to_manifest(pointer, other)
    assert failure.value.code == "pointer_manifest_mismatch"
    with pytest.raises(ManifestPublicationError) as failure:
        build_manifest_latest_pointer(other, context.signatures)
    assert failure.value.code == "signature_binding_mismatch"
    with pytest.raises(ManifestPublicationError):
        build_manifest_latest_pointer(context.manifest, [])
    with pytest.raises(ManifestPublicationError):
        build_manifest_latest_pointer(context.manifest, context.signatures * 2)


def test_pointer_precheck_mirrors_manifest_acceptance() -> None:
    context = make_context()
    pointer = build_pointer()
    genesis = build_initial_manifest_chain_state(context.policy)
    verdict = verify_manifest_latest_pointer(
        pointer, context.policy, genesis, evaluation_epoch=EVALUATION_EPOCH
    )
    assert verdict.reprobe is False
    assert verdict.manifest_object_key == pointer.manifest_object_key
    assert verdict.signature_object_keys == pointer.signature_object_keys
    accepted = context.verification.next_chain_state
    assert (
        verify_manifest_latest_pointer(
            pointer, context.policy, accepted, evaluation_epoch=EVALUATION_EPOCH
        ).reprobe
        is True
    )

    second = build_manifest(
        context.policy,
        fixture_deployments(),
        sequence=2,
        previous=context.manifest.manifest_digest_sha256,
        issued_at=BASE_EPOCH + 100,
    )
    second_pointer = build_manifest_latest_pointer(second, sign_manifest(second, context.keys))
    state_two = verify_active_assignment_manifest(
        second,
        sign_manifest(second, context.keys),
        context.policy,
        accepted,
        evaluation_epoch=EVALUATION_EPOCH,
    ).next_chain_state
    equivocating = build_manifest(
        context.policy,
        fixture_deployments()[:1],
        sequence=2,
        previous=context.manifest.manifest_digest_sha256,
        issued_at=BASE_EPOCH + 100,
    )
    far = build_manifest(
        context.policy,
        fixture_deployments(),
        sequence=1 + context.policy.max_sequence_gap + 1,
        previous=context.manifest.manifest_digest_sha256,
        issued_at=BASE_EPOCH + 100,
    )
    cases = [
        ("pointer_rollback", pointer, context.policy, state_two, EVALUATION_EPOCH),
        (
            "pointer_equivocation",
            build_manifest_latest_pointer(equivocating, sign_manifest(equivocating, context.keys)),
            context.policy,
            state_two,
            EVALUATION_EPOCH,
        ),
        (
            "pointer_sequence_gap",
            build_manifest_latest_pointer(far, sign_manifest(far, context.keys)),
            context.policy,
            accepted,
            EVALUATION_EPOCH,
        ),
        ("pointer_sequence_gap", second_pointer, context.policy, genesis, EVALUATION_EPOCH),
        ("pointer_expired", pointer, context.policy, genesis, context.manifest.expires_at_epoch),
        (
            "pointer_stale",
            pointer,
            context.policy,
            genesis,
            BASE_EPOCH + context.policy.max_manifest_age_seconds + 1,
        ),
        (
            "pointer_future",
            pointer,
            context.policy,
            genesis,
            BASE_EPOCH - context.policy.max_future_skew_seconds - 1,
        ),
        (
            "pointer_threshold_not_met",
            build_manifest_latest_pointer(context.manifest, context.signatures[:1]),
            context.policy,
            genesis,
            EVALUATION_EPOCH,
        ),
    ]
    for code, candidate, policy, state, epoch in cases:
        with pytest.raises(ManifestPublicationError) as failure:
            verify_manifest_latest_pointer(candidate, policy, state, evaluation_epoch=epoch)
        assert failure.value.code == code, code

    other_policy = build_policy(signer_keys(), threshold=1)
    with pytest.raises(ManifestPublicationError) as failure:
        verify_manifest_latest_pointer(
            pointer, other_policy, genesis, evaluation_epoch=EVALUATION_EPOCH
        )
    assert failure.value.code == "pointer_trust_policy_mismatch"
    foreign_policy = build_policy(signer_keys(), central_authority=label_digest("foreign"))
    foreign_manifest = build_manifest(foreign_policy, fixture_deployments())
    foreign_pointer = build_manifest_latest_pointer(
        foreign_manifest, sign_manifest(foreign_manifest, context.keys)
    )
    with pytest.raises(ManifestPublicationError) as failure:
        verify_manifest_latest_pointer(
            foreign_pointer,
            context.policy,
            genesis,
            evaluation_epoch=EVALUATION_EPOCH,
        )
    assert failure.value.code == "pointer_authority_mismatch"
    stranger_pointer = pointer.model_copy(update={"signer_key_ids": ["auditor", "stranger"]})
    with pytest.raises(ManifestPublicationError) as failure:
        verify_manifest_latest_pointer(
            build_manifest_latest_pointer(
                context.manifest,
                [
                    context.signatures[0],
                    context.signatures[1].model_copy(update={"signer_key_id": "stranger"}),
                ],
            ),
            context.policy,
            genesis,
            evaluation_epoch=EVALUATION_EPOCH,
        )
    assert failure.value.code == "pointer_signer_untrusted"
    del stranger_pointer
    with pytest.raises(ValueError, match="evaluation_epoch_invalid"):
        verify_manifest_latest_pointer(pointer, context.policy, genesis, evaluation_epoch=-1)


def test_key_rotation_reanchors_state_without_resetting_history() -> None:
    context = make_context()
    keys = signer_keys()
    accepted = context.verification.next_chain_state
    successor = build_policy(keys, revoked={"security": BASE_EPOCH + 10}, max_age=1_200)
    assert successor.trust_policy_digest_sha256 != context.policy.trust_policy_digest_sha256
    rebound = rebind_manifest_chain_state_trust_policy(
        accepted, context.policy, successor, evaluation_epoch=EVALUATION_EPOCH
    )
    assert rebound.trust_policy_digest_sha256 == successor.trust_policy_digest_sha256
    assert rebound.last_sequence == accepted.last_sequence == 1
    assert rebound.last_manifest_digest_sha256 == accepted.last_manifest_digest_sha256
    assert rebound.accepted_manifest_count == accepted.accepted_manifest_count
    assert rebound.state_digest_sha256 != accepted.state_digest_sha256

    # The next publication under the successor policy must extend the same chain.
    second = build_manifest(
        successor,
        fixture_deployments(),
        sequence=2,
        previous=context.manifest.manifest_digest_sha256,
        issued_at=BASE_EPOCH + 100,
    )
    result = verify_active_assignment_manifest(
        second,
        sign_manifest(second, keys),
        successor,
        rebound,
        evaluation_epoch=EVALUATION_EPOCH,
    )
    assert result.next_chain_state.last_sequence == 2
    # Without the re-anchor the successor policy rejects even a valid chain.
    with pytest.raises(AssignmentProbeError) as failure:
        verify_active_assignment_manifest(
            second,
            sign_manifest(second, keys),
            successor,
            accepted,
            evaluation_epoch=EVALUATION_EPOCH,
        )
    assert failure.value.code == "trust_policy_mismatch"
    # A rebound state does not accept a sequence-1 replay or a rollback.
    with pytest.raises(AssignmentProbeError) as failure:
        verify_active_assignment_manifest(
            build_manifest(successor, fixture_deployments()),
            sign_manifest(build_manifest(successor, fixture_deployments()), keys),
            successor,
            rebound,
            evaluation_epoch=EVALUATION_EPOCH,
        )
    assert failure.value.code == "same_sequence_divergence"

    cases = {
        "rebind_state_policy_mismatch": (accepted, successor, successor, EVALUATION_EPOCH),
        "rebind_policy_unchanged": (accepted, context.policy, context.policy, EVALUATION_EPOCH),
        "rebind_authority_mismatch": (
            accepted,
            context.policy,
            build_policy(keys, central_authority=label_digest("elsewhere")),
            EVALUATION_EPOCH,
        ),
        "rebind_policy_not_yet_valid": (
            accepted,
            context.policy,
            successor,
            successor.valid_from_epoch - 1,
        ),
        "rebind_policy_expired": (accepted, context.policy, successor, successor.valid_until_epoch),
    }
    for code, (state, current, next_policy, epoch) in cases.items():
        with pytest.raises(ManifestPublicationError) as failure:
            rebind_manifest_chain_state_trust_policy(
                state, current, next_policy, evaluation_epoch=epoch
            )
        assert failure.value.code == code, code


def test_pointer_bytes_round_trip_and_reject_malleability() -> None:
    rendered = (FIXTURES / "assignment-manifest-latest-pointer.v1.json").read_bytes()
    pointer = parse_assignment_manifest_latest_pointer(rendered)
    assert assignment_manifest_latest_pointer_bytes(pointer) == rendered
    assert pointer == build_pointer()
    document = json.loads(rendered)
    with pytest.raises(ValueError, match="document_not_canonical"):
        parse_assignment_manifest_latest_pointer(json.dumps(document).encode("ascii") + b"\n")
    with pytest.raises(ValueError, match="document_size_invalid"):
        parse_assignment_manifest_latest_pointer(rendered + b" " * 16 * 1_024)
