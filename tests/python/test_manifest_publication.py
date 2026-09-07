# SPDX-License-Identifier: AGPL-3.0-only

"""Publication layout, latest pointer, and trust-policy re-anchoring."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from assignment_probe_context import (
    BASE_EPOCH,
    EVALUATION_EPOCH,
    FINALIZED_HEIGHT,
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
    ActiveAssignmentManifest,
    AssignmentManifestChainState,
    AssignmentProbeError,
    build_initial_manifest_chain_state,
    verify_active_assignment_manifest,
    verify_historical_active_assignment_manifest,
)
from misscomputer_subnet.manifest_publication import (
    FETCH_REQUEST_CACHE_CONTROL,
    IMMUTABLE_OBJECT_CACHE_CONTROL,
    IMMUTABLE_OBJECT_MAX_AGE_SECONDS,
    LATEST_POINTER_CACHE_CONTROL,
    LATEST_POINTER_MAX_AGE_SECONDS,
    LATEST_POINTER_OBJECT_KEY,
    ManifestHistoryEntry,
    ManifestPublicationError,
    anchor_manifest_chain_state,
    assignment_manifest_latest_pointer_bytes,
    bind_latest_pointer_to_manifest,
    build_manifest_latest_pointer,
    manifest_object_key,
    parse_assignment_manifest_latest_pointer,
    pointer_object_key,
    rebind_manifest_chain_state_trust_policy,
    replay_manifest_history,
    signature_object_key,
    verify_manifest_latest_pointer,
)

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "contracts" / "fixtures"


def test_object_keys_are_content_addressed_and_layout_is_versioned() -> None:
    digest = "ab" * 32
    assert manifest_object_key(digest) == f"v1/manifests/{digest}.json"
    assert signature_object_key(digest, "issuer") == f"v1/manifests/{digest}.issuer.signature.json"
    assert pointer_object_key(digest) == f"v1/manifests/{digest}.pointer.json"
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
    assert pointer.pointer_object_key == pointer_object_key(pointer.manifest_digest_sha256)
    assert pointer.finalized_epoch == context.manifest.finalized_epoch
    bind_latest_pointer_to_manifest(pointer, context.manifest, context.signatures)
    other = build_manifest(context.policy, fixture_deployments()[:1])
    with pytest.raises(ManifestPublicationError) as failure:
        bind_latest_pointer_to_manifest(pointer, other, context.signatures)
    assert failure.value.code == "pointer_manifest_mismatch"
    # The fetched envelopes must be exactly the signer set the pointer names:
    # a missing, extra, re-ordered, or differently-signed set is refused
    # before any signature is checked.
    all_three = sign_manifest(context.manifest, context.keys, ("auditor", "issuer", "security"))
    for envelopes in (
        context.signatures[:1],
        all_three,
        list(reversed(context.signatures)),
        [context.signatures[0], all_three[2]],
        [],
    ):
        with pytest.raises(ManifestPublicationError) as failure:
            bind_latest_pointer_to_manifest(pointer, context.manifest, envelopes)
        assert failure.value.code == "pointer_signature_mismatch"
    foreign = sign_manifest(other, context.keys)
    with pytest.raises(ManifestPublicationError) as failure:
        bind_latest_pointer_to_manifest(pointer, context.manifest, foreign)
    assert failure.value.code == "pointer_signature_mismatch"
    epoch_pointer = pointer.model_copy(update={"finalized_epoch": pointer.finalized_epoch + 1})
    with pytest.raises(ManifestPublicationError) as failure:
        bind_latest_pointer_to_manifest(
            build_manifest_latest_pointer(context.manifest, context.signatures).model_copy(
                update={
                    "finalized_epoch": epoch_pointer.finalized_epoch,
                    "pointer_digest_sha256": _resealed_pointer_digest(epoch_pointer),
                }
            ),
            context.manifest,
            context.signatures,
        )
    assert failure.value.code == "pointer_manifest_mismatch"
    with pytest.raises(ManifestPublicationError) as failure:
        build_manifest_latest_pointer(other, context.signatures)
    assert failure.value.code == "signature_binding_mismatch"
    with pytest.raises(ManifestPublicationError):
        build_manifest_latest_pointer(context.manifest, [])
    with pytest.raises(ManifestPublicationError):
        build_manifest_latest_pointer(context.manifest, context.signatures * 2)


def _resealed_pointer_digest(pointer: object) -> str:
    from misscomputer_subnet.contract_codec import digest as canonical_digest
    from misscomputer_subnet.contract_codec import model_document

    return canonical_digest(model_document(pointer, exclude={"pointer_digest_sha256"}))  # type: ignore[arg-type]


def test_pointer_precheck_mirrors_manifest_acceptance() -> None:
    context = make_context()
    pointer = build_pointer()
    genesis = build_initial_manifest_chain_state(context.policy)
    verdict = verify_manifest_latest_pointer(
        pointer, context.policy, genesis, evaluation_epoch=EVALUATION_EPOCH
    )
    assert verdict.reprobe is False
    assert verdict.history_depth == 0
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
        current_finalized_height=FINALIZED_HEIGHT,
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


def test_pointer_precheck_binds_signer_provenance_to_the_policy() -> None:
    """A pointer's claimed signer set is judged like the envelopes will be, minus cryptography."""

    context = make_context()
    keys = signer_keys()
    genesis = build_initial_manifest_chain_state(context.policy)
    # issuer + security satisfies the threshold of two but not the required
    # auditor role; under the old precheck it passed and the fetcher would
    # have downloaded objects that can only fail.
    wrong_roles = build_manifest_latest_pointer(
        context.manifest, sign_manifest(context.manifest, keys, ("issuer", "security"))
    )
    with pytest.raises(ManifestPublicationError) as failure:
        verify_manifest_latest_pointer(
            wrong_roles, context.policy, genesis, evaluation_epoch=EVALUATION_EPOCH
        )
    assert failure.value.code == "pointer_required_role_missing"
    # A revoked or not-yet-valid signer named by the pointer is refused.
    revoked_policy = build_policy(keys, revoked={"issuer": BASE_EPOCH + 10})
    revoked_manifest = build_manifest(revoked_policy, fixture_deployments())
    revoked_pointer = build_manifest_latest_pointer(
        revoked_manifest, sign_manifest(revoked_manifest, keys)
    )
    with pytest.raises(ManifestPublicationError) as failure:
        verify_manifest_latest_pointer(
            revoked_pointer,
            revoked_policy,
            build_initial_manifest_chain_state(revoked_policy),
            evaluation_epoch=EVALUATION_EPOCH,
        )
    assert failure.value.code == "pointer_signer_invalid"
    late_policy = build_policy(keys, key_windows={"issuer": (BASE_EPOCH + 1, BASE_EPOCH + 100_000)})
    late_manifest = build_manifest(late_policy, fixture_deployments())
    with pytest.raises(ManifestPublicationError) as failure:
        verify_manifest_latest_pointer(
            build_manifest_latest_pointer(late_manifest, sign_manifest(late_manifest, keys)),
            late_policy,
            build_initial_manifest_chain_state(late_policy),
            evaluation_epoch=EVALUATION_EPOCH,
        )
    assert failure.value.code == "pointer_signer_invalid"
    # Chain-view fields copied into the pointer are checked against the state
    # before any fetch: a rollback or fork at the pointer is refused as such.
    accepted = context.verification.next_chain_state
    second = build_manifest(
        context.policy,
        fixture_deployments(),
        sequence=2,
        previous=context.manifest.manifest_digest_sha256,
        issued_at=BASE_EPOCH + 100,
        finalized_height=context.manifest.finalized_height - 1,
    )
    with pytest.raises(ManifestPublicationError) as failure:
        verify_manifest_latest_pointer(
            build_manifest_latest_pointer(second, sign_manifest(second, keys)),
            context.policy,
            accepted,
            evaluation_epoch=EVALUATION_EPOCH,
        )
    assert failure.value.code == "pointer_rollback"
    forked = build_manifest(
        context.policy,
        fixture_deployments(),
        sequence=2,
        previous=context.manifest.manifest_digest_sha256,
        issued_at=BASE_EPOCH + 100,
        finalized_block_hash=label_digest("fork"),
    )
    with pytest.raises(ManifestPublicationError) as failure:
        verify_manifest_latest_pointer(
            build_manifest_latest_pointer(forked, sign_manifest(forked, keys)),
            context.policy,
            accepted,
            evaluation_epoch=EVALUATION_EPOCH,
        )
    assert failure.value.code == "pointer_equivocation"
    unlinked = build_manifest(
        context.policy,
        fixture_deployments(),
        sequence=2,
        previous=label_digest("someone-else"),
        issued_at=BASE_EPOCH + 100,
    )
    with pytest.raises(ManifestPublicationError) as failure:
        verify_manifest_latest_pointer(
            build_manifest_latest_pointer(unlinked, sign_manifest(unlinked, keys)),
            context.policy,
            accepted,
            evaluation_epoch=EVALUATION_EPOCH,
        )
    assert failure.value.code == "pointer_equivocation"


def _chain(context: object, count: int) -> list[ActiveAssignmentManifest]:
    """Sequences 1..count, one publication every 100 seconds from the fixture head."""

    keys = signer_keys()
    policy = context.policy  # type: ignore[attr-defined]
    manifests = [context.manifest]  # type: ignore[attr-defined]
    for sequence in range(2, count + 1):
        previous = manifests[-1]
        manifests.append(
            build_manifest(
                policy,
                fixture_deployments(),
                sequence=sequence,
                previous=previous.manifest_digest_sha256,
                issued_at=BASE_EPOCH + 100 * (sequence - 1),
                expires_at=BASE_EPOCH + 100 * (sequence - 1) + 3_600,
                finalized_height=previous.finalized_height + 5,
                finalized_block_hash=label_digest(f"block-{sequence}"),
            )
        )
    del keys
    return manifests


def _entry(manifest: ActiveAssignmentManifest, keys: dict) -> ManifestHistoryEntry:  # type: ignore[type-arg]
    signatures = sign_manifest(manifest, keys)
    return ManifestHistoryEntry(
        pointer=build_manifest_latest_pointer(manifest, signatures),
        manifest=manifest,
        signatures=signatures,
    )


def test_catch_up_replays_missed_publications_under_historical_semantics() -> None:
    """A validator at sequence 1 that finds the pointer at sequence 5 catches up 2..4."""

    context = make_context(max_age=600)
    keys = signer_keys()
    manifests = _chain(context, 5)
    accepted = context.verification.next_chain_state
    head = manifests[4]
    head_signatures = sign_manifest(head, keys)
    head_pointer = build_manifest_latest_pointer(head, head_signatures)
    now = head.issued_at_epoch + 500
    verdict = verify_manifest_latest_pointer(
        head_pointer, context.policy, accepted, evaluation_epoch=now
    )
    assert verdict.history_depth == 3
    # Under live semantics the head does not extend sequence 1 (the link is
    # broken) and the intermediates are expired or stale by now.
    with pytest.raises(AssignmentProbeError) as failure:
        verify_active_assignment_manifest(
            head,
            head_signatures,
            context.policy,
            accepted,
            evaluation_epoch=now,
            current_finalized_height=FINALIZED_HEIGHT,
        )
    assert failure.value.code == "previous_link_mismatch"
    with pytest.raises(AssignmentProbeError) as failure:
        verify_active_assignment_manifest(
            manifests[1],
            sign_manifest(manifests[1], keys),
            context.policy,
            accepted,
            evaluation_epoch=now,
            current_finalized_height=FINALIZED_HEIGHT,
        )
    assert failure.value.code == "manifest_stale"
    history = [_entry(item, keys) for item in manifests[1:4]]
    caught_up = replay_manifest_history(accepted, history, context.policy, evaluation_epoch=now)
    assert caught_up.last_sequence == 4
    assert caught_up.accepted_manifest_count == 4
    assert caught_up.last_manifest_digest_sha256 == manifests[3].manifest_digest_sha256
    assert caught_up.last_finalized_epoch == manifests[3].finalized_epoch
    live = verify_active_assignment_manifest(
        head,
        head_signatures,
        context.policy,
        caught_up,
        evaluation_epoch=now,
        current_finalized_height=FINALIZED_HEIGHT,
    )
    assert live.next_chain_state.last_sequence == 5
    assert live.reprobe is False
    # The replayed state is exactly the state a validator that never missed
    # anything would hold.
    state = accepted
    for item in manifests[1:4]:
        state = verify_active_assignment_manifest(
            item,
            sign_manifest(item, keys),
            context.policy,
            state,
            evaluation_epoch=item.issued_at_epoch + 1,
            current_finalized_height=FINALIZED_HEIGHT,
        ).next_chain_state
    assert state == caught_up

    # Historical acceptance is still real verification: a bad signature, a
    # wrong policy binding, or a foreign signer is refused.
    bad_signature = ManifestHistoryEntry(
        pointer=history[0].pointer,
        manifest=history[0].manifest,
        signatures=[
            history[0].signatures[0],
            history[0]
            .signatures[1]
            .model_copy(update={"signature_base64": history[0].signatures[0].signature_base64}),
        ],
    )
    with pytest.raises(AssignmentProbeError) as failure:
        replay_manifest_history(accepted, [bad_signature], context.policy, evaluation_epoch=now)
    assert failure.value.code == "signature_invalid"
    # Out of order, gapped, or duplicated history breaks the link.
    for broken in ([history[1]], [history[0], history[2]], [history[0], history[0]]):
        with pytest.raises(ManifestPublicationError) as failure:
            replay_manifest_history(accepted, broken, context.policy, evaluation_epoch=now)
        assert failure.value.code == "history_link_mismatch"
    # A pointer copy that does not name exactly the fetched objects is refused.
    mismatched = ManifestHistoryEntry(
        pointer=history[1].pointer, manifest=history[0].manifest, signatures=history[0].signatures
    )
    with pytest.raises(ManifestPublicationError) as failure:
        replay_manifest_history(accepted, [mismatched], context.policy, evaluation_epoch=now)
    assert failure.value.code == "history_pointer_mismatch"
    # The catch-up span is bounded by the policy gap; beyond it the pointer
    # precheck already refuses and the replay refuses too.
    long_chain = _chain(context, 2 + context.policy.max_sequence_gap + 1)
    with pytest.raises(ManifestPublicationError) as failure:
        verify_manifest_latest_pointer(
            build_manifest_latest_pointer(long_chain[-1], sign_manifest(long_chain[-1], keys)),
            context.policy,
            accepted,
            evaluation_epoch=long_chain[-1].issued_at_epoch,
        )
    assert failure.value.code == "pointer_sequence_gap"
    with pytest.raises(ManifestPublicationError) as failure:
        replay_manifest_history(
            accepted,
            [_entry(item, keys) for item in long_chain[1:-1]],
            context.policy,
            evaluation_epoch=long_chain[-1].issued_at_epoch,
        )
    assert failure.value.code == "history_depth_exceeded"
    # Historical verification judges signer validity at issuance, so a key
    # revoked after a publication still authenticates that publication, but
    # never one issued after the revocation.
    rotated = build_policy(keys, revoked={"issuer": manifests[2].issued_at_epoch})
    rotated_chain = [
        build_manifest(
            rotated,
            fixture_deployments(),
            sequence=item.sequence,
            previous=None if item.sequence == 1 else previous_digest,
            issued_at=item.issued_at_epoch,
            expires_at=item.expires_at_epoch,
            finalized_height=item.finalized_height,
            finalized_block_hash=item.finalized_block_hash,
        )
        for item, previous_digest in _linked(manifests[:3], rotated)
    ]
    rotated_genesis = build_initial_manifest_chain_state(rotated)
    early = verify_historical_active_assignment_manifest(
        rotated_chain[0],
        sign_manifest(rotated_chain[0], keys),
        rotated,
        rotated_genesis,
        evaluation_epoch=now,
    )
    assert early.verified_signer_key_ids == ["auditor", "issuer"]
    with pytest.raises(AssignmentProbeError) as failure:
        verify_historical_active_assignment_manifest(
            rotated_chain[2],
            sign_manifest(rotated_chain[2], keys),
            rotated,
            verify_historical_active_assignment_manifest(
                rotated_chain[1],
                sign_manifest(rotated_chain[1], keys),
                rotated,
                early.next_chain_state,
                evaluation_epoch=now,
            ).next_chain_state,
            evaluation_epoch=now,
        )
    assert failure.value.code == "signer_revoked"


def _linked(
    manifests: list[ActiveAssignmentManifest], policy: object
) -> list[tuple[ActiveAssignmentManifest, str | None]]:
    """Re-issue a chain under another policy, threading the previous digests."""

    out: list[tuple[ActiveAssignmentManifest, str | None]] = []
    previous: str | None = None
    for item in manifests:
        rebuilt = build_manifest(
            policy,  # type: ignore[arg-type]
            fixture_deployments(),
            sequence=item.sequence,
            previous=previous,
            issued_at=item.issued_at_epoch,
            expires_at=item.expires_at_epoch,
            finalized_height=item.finalized_height,
            finalized_block_hash=item.finalized_block_hash,
        )
        out.append((item, previous))
        previous = rebuilt.manifest_digest_sha256
    return out


def test_onboarding_anchors_on_the_live_head_only_from_genesis() -> None:
    context = make_context()
    keys = signer_keys()
    manifests = _chain(context, 4)
    head = manifests[3]
    head_signatures = sign_manifest(head, keys)
    genesis = build_initial_manifest_chain_state(context.policy)
    now = head.issued_at_epoch + 10
    # Genesis alone refuses a head beyond sequence 1, as it always did.
    with pytest.raises(AssignmentProbeError) as failure:
        verify_active_assignment_manifest(
            head,
            head_signatures,
            context.policy,
            genesis,
            evaluation_epoch=now,
            current_finalized_height=FINALIZED_HEIGHT,
        )
    assert failure.value.code == "sequence_gap"
    anchored = anchor_manifest_chain_state(
        head,
        head_signatures,
        context.policy,
        genesis,
        evaluation_epoch=now,
        current_finalized_height=FINALIZED_HEIGHT,
    )
    state = anchored.next_chain_state
    assert anchored.reprobe is False
    assert anchored.verified_signer_key_ids == ["auditor", "issuer"]
    assert state.accepted_manifest_count == 1
    assert state.last_sequence == 4
    assert state.last_manifest_digest_sha256 == head.manifest_digest_sha256
    assert state.last_finalized_height == head.finalized_height
    assert state.last_finalized_block_hash == head.finalized_block_hash
    assert state.last_finalized_epoch == head.finalized_epoch
    assert state.last_issued_at_epoch == head.issued_at_epoch
    assert state.last_expires_at_epoch == head.expires_at_epoch
    # From the anchor the ordinary rules apply: re-probe, then the next
    # sequence extends, and rollback is refused.
    assert (
        verify_active_assignment_manifest(
            head,
            head_signatures,
            context.policy,
            state,
            evaluation_epoch=now,
            current_finalized_height=FINALIZED_HEIGHT,
        ).reprobe
        is True
    )
    fifth = _chain(context, 5)[4]
    assert (
        verify_active_assignment_manifest(
            fifth,
            sign_manifest(fifth, keys),
            context.policy,
            state,
            evaluation_epoch=now + 100,
            current_finalized_height=FINALIZED_HEIGHT,
        ).next_chain_state.last_sequence
        == 5
    )
    with pytest.raises(AssignmentProbeError) as failure:
        verify_active_assignment_manifest(
            manifests[2],
            sign_manifest(manifests[2], keys),
            context.policy,
            state,
            evaluation_epoch=now,
            current_finalized_height=FINALIZED_HEIGHT,
        )
    assert failure.value.code == "sequence_rollback"
    # Anchoring is complete live verification: stale heads and bad signatures
    # are refused, and it is never available from a non-genesis state.
    with pytest.raises(AssignmentProbeError) as failure:
        anchor_manifest_chain_state(
            head,
            head_signatures,
            context.policy,
            genesis,
            evaluation_epoch=head.issued_at_epoch + context.policy.max_manifest_age_seconds + 1,
            current_finalized_height=FINALIZED_HEIGHT,
        )
    assert failure.value.code == "manifest_stale"
    with pytest.raises(AssignmentProbeError) as failure:
        anchor_manifest_chain_state(
            head,
            head_signatures[:1],
            context.policy,
            genesis,
            evaluation_epoch=now,
            current_finalized_height=FINALIZED_HEIGHT,
        )
    assert failure.value.code == "threshold_not_met"
    with pytest.raises(ManifestPublicationError) as failure:
        anchor_manifest_chain_state(
            head,
            head_signatures,
            context.policy,
            state,
            evaluation_epoch=now,
            current_finalized_height=FINALIZED_HEIGHT,
        )
    assert failure.value.code == "anchor_state_not_genesis"
    with pytest.raises(ManifestPublicationError) as failure:
        anchor_manifest_chain_state(
            head,
            head_signatures,
            context.policy,
            build_initial_manifest_chain_state(build_policy(keys, threshold=1)),
            evaluation_epoch=now,
            current_finalized_height=FINALIZED_HEIGHT,
        )
    assert failure.value.code == "rebind_state_policy_mismatch"
    # Anchoring on sequence 1 is exactly the ordinary genesis acceptance.
    assert (
        anchor_manifest_chain_state(
            context.manifest,
            context.signatures,
            context.policy,
            genesis,
            evaluation_epoch=EVALUATION_EPOCH,
            current_finalized_height=FINALIZED_HEIGHT,
        ).next_chain_state
        == context.verification.next_chain_state
    )
    assert isinstance(state, AssignmentManifestChainState)


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
    assert rebound.last_finalized_epoch == accepted.last_finalized_epoch == 42
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
        current_finalized_height=FINALIZED_HEIGHT,
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
            current_finalized_height=FINALIZED_HEIGHT,
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
            current_finalized_height=FINALIZED_HEIGHT,
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


def test_live_verification_always_enforces_block_leases() -> None:
    """No live consumer can skip the lease check: the finalized height is required input."""

    context = make_context()
    keys = signer_keys()
    genesis = build_initial_manifest_chain_state(context.policy)
    earliest = min(
        replica.expires_at_block
        for item in context.manifest.deployments
        for replica in item.replicas
    )
    assert earliest > context.manifest.finalized_height
    # There is no opt-out: omitting the height is a programming error, not a pass.
    with pytest.raises(TypeError):
        verify_active_assignment_manifest(  # type: ignore[call-arg]
            context.manifest,
            context.signatures,
            context.policy,
            genesis,
            evaluation_epoch=EVALUATION_EPOCH,
        )
    with pytest.raises(TypeError):
        anchor_manifest_chain_state(  # type: ignore[call-arg]
            context.manifest,
            context.signatures,
            context.policy,
            genesis,
            evaluation_epoch=EVALUATION_EPOCH,
        )
    # The last leased height verifies; the first expired height is refused,
    # and no next state is produced.
    live = verify_active_assignment_manifest(
        context.manifest,
        context.signatures,
        context.policy,
        genesis,
        evaluation_epoch=EVALUATION_EPOCH,
        current_finalized_height=earliest - 1,
    )
    assert live.next_chain_state.last_sequence == 1
    for height in (earliest, earliest + 1_000):
        with pytest.raises(AssignmentProbeError) as failure:
            verify_active_assignment_manifest(
                context.manifest,
                context.signatures,
                context.policy,
                genesis,
                evaluation_epoch=EVALUATION_EPOCH,
                current_finalized_height=height,
            )
        assert failure.value.code == "manifest_replica_lease_expired"
    for bad_height in (-1, True, "12", 1.5, None):
        with pytest.raises(ValueError, match="current_finalized_height_invalid"):
            verify_active_assignment_manifest(
                context.manifest,
                context.signatures,
                context.policy,
                genesis,
                evaluation_epoch=EVALUATION_EPOCH,
                current_finalized_height=bad_height,  # type: ignore[arg-type]
            )
    # Onboarding on a later head is the same live verification, leases included.
    head = _chain(context, 3)[2]
    head_signatures = sign_manifest(head, keys)
    now = head.issued_at_epoch + 10
    anchored = anchor_manifest_chain_state(
        head,
        head_signatures,
        context.policy,
        genesis,
        evaluation_epoch=now,
        current_finalized_height=earliest - 1,
    )
    assert anchored.next_chain_state.last_sequence == 3
    with pytest.raises(AssignmentProbeError) as failure:
        anchor_manifest_chain_state(
            head,
            head_signatures,
            context.policy,
            genesis,
            evaluation_epoch=now,
            current_finalized_height=earliest,
        )
    assert failure.value.code == "manifest_replica_lease_expired"
    # Historical replay is deliberately lease-free: the manifests are already
    # superseded and are never probed; only the live head is leased.
    history = [_entry(item, keys) for item in _chain(context, 3)[1:2]]
    replayed = replay_manifest_history(
        context.verification.next_chain_state,
        history,
        context.policy,
        evaluation_epoch=now,
    )
    assert replayed.last_sequence == 2
