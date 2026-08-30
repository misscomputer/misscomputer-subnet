# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import ast
import base64
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from misscomputer_subnet.checkpoint_score_contracts import (
    CanonicalScoreReport,
    parse_canonical_score_report,
)
from misscomputer_subnet.score_checkpoint_relay import (
    CHAIN_STATE_SCHEMA,
    CHECKPOINT_PURPOSE,
    CHECKPOINT_SCHEMA,
    NORMALIZATION_ALGORITHM,
    RELAY_METAGRAPH_SCHEMA,
    RELAY_PLAN_SCHEMA,
    SIGNATURE_ENVELOPE_SCHEMA,
    TRUST_POLICY_SCHEMA,
    VERIFICATION_INPUT_SCHEMA,
    VERIFICATION_REPORT_SCHEMA,
    WEIGHT_U16_TOTAL,
    CentralScoreCheckpoint,
    CheckpointChainState,
    CheckpointRelayError,
    CheckpointSignatureEnvelope,
    CheckpointTrustPolicy,
    ExternalValidatorIdentity,
    ExternalValidatorRelayPlan,
    ExternalValidatorVerificationInput,
    ExternalValidatorVerificationReport,
    MetagraphMinerMapping,
    RelayFinalizedMetagraphSnapshot,
    TrustedCheckpointKey,
    advance_checkpoint_chain_state,
    build_central_score_checkpoint,
    build_checkpoint_signature_envelope,
    build_checkpoint_trust_policy,
    build_external_validator_verification_input,
    build_initial_checkpoint_chain_state,
    build_relay_finalized_metagraph_snapshot,
    central_score_checkpoint_bytes,
    checkpoint_chain_state_bytes,
    checkpoint_signature_envelope_bytes,
    checkpoint_signature_message,
    checkpoint_trust_policy_bytes,
    external_validator_relay_plan_bytes,
    external_validator_verification_input_bytes,
    external_validator_verification_report_bytes,
    parse_central_score_checkpoint,
    parse_checkpoint_chain_state,
    parse_checkpoint_signature_envelope,
    parse_checkpoint_trust_policy,
    parse_external_validator_relay_plan,
    parse_external_validator_verification_input,
    parse_external_validator_verification_report,
    parse_relay_finalized_metagraph_snapshot,
    relay_finalized_metagraph_snapshot_bytes,
    verify_checkpoint_and_build_relay,
)

ROOT = Path(__file__).resolve().parents[2]
REPORT_FIXTURE = ROOT / "contracts" / "fixtures" / "canonical-synthetic-score-report.v1.json"
BASE_EPOCH = 2_000_000_000


def canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def digest(value: object) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def raw_public(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def deterministic_key(label: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(label.encode("ascii")).digest())


def trusted_key(
    key_id: str,
    key: Ed25519PrivateKey,
    role: str,
    *,
    valid_from: int = BASE_EPOCH - 1_000,
    valid_until: int = BASE_EPOCH + 100_000,
    revoked_at: int | None = None,
) -> TrustedCheckpointKey:
    public = raw_public(key)
    return TrustedCheckpointKey.model_validate(
        {
            "key_id": key_id,
            "algorithm": "ed25519",
            "public_key_base64": base64.b64encode(public).decode("ascii"),
            "public_key_sha256": hashlib.sha256(public).hexdigest(),
            "roles": [role],
            "purposes": [CHECKPOINT_PURPOSE],
            "valid_from_epoch": valid_from,
            "valid_until_epoch": valid_until,
            "revoked_at_epoch": revoked_at,
        }
    )


def load_report() -> CanonicalScoreReport:
    return parse_canonical_score_report(REPORT_FIXTURE.read_bytes())


@dataclass(frozen=True)
class Context:
    report: CanonicalScoreReport
    keys: dict[str, Ed25519PrivateKey]
    policy: CheckpointTrustPolicy
    checkpoint: CentralScoreCheckpoint
    signatures: list[CheckpointSignatureEnvelope]
    state: CheckpointChainState
    validator: ExternalValidatorIdentity
    metagraph: RelayFinalizedMetagraphSnapshot
    verification_input: ExternalValidatorVerificationInput


def make_context(
    *,
    report: CanonicalScoreReport | None = None,
    threshold: int = 2,
    required_roles: tuple[str, ...] = ("checkpoint_auditor", "checkpoint_issuer"),
    signed_key_ids: tuple[str, ...] = ("auditor", "issuer"),
    key_windows: dict[str, tuple[int, int]] | None = None,
    revoked: dict[str, int | None] | None = None,
    checkpoint_evaluation: int = BASE_EPOCH + 100,
    checkpoint_expiry: int = BASE_EPOCH + 3_600,
    verifier_evaluation: int = BASE_EPOCH + 200,
    max_age: int = 1_000,
) -> Context:
    score_report = report or load_report()
    keys = {
        "auditor": deterministic_key("checkpoint-auditor"),
        "issuer": deterministic_key("checkpoint-issuer"),
        "security": deterministic_key("checkpoint-security"),
    }
    roles = {
        "auditor": "checkpoint_auditor",
        "issuer": "checkpoint_issuer",
        "security": "checkpoint_security",
    }
    key_models = []
    for key_id in sorted(keys):
        start, end = (key_windows or {}).get(
            key_id,
            (BASE_EPOCH - 1_000, BASE_EPOCH + 100_000),
        )
        key_models.append(
            trusted_key(
                key_id,
                keys[key_id],
                roles[key_id],
                valid_from=start,
                valid_until=end,
                revoked_at=(revoked or {}).get(key_id),
            )
        )
    policy = build_checkpoint_trust_policy(
        central_authority_fingerprint_sha256=(score_report.central_authority_fingerprint_sha256),
        central_scoring_policy_digest_sha256=score_report.policy_digest_sha256,
        threshold=threshold,
        required_roles=required_roles,  # type: ignore[arg-type]
        trusted_keys=key_models,
        valid_from_epoch=BASE_EPOCH - 1_000,
        valid_until_epoch=BASE_EPOCH + 100_000,
        max_checkpoint_age_seconds=max_age,
        max_future_skew_seconds=5,
        max_checkpoint_lifetime_seconds=7_200,
        max_sequence_gap=4,
        max_finalized_height_gap=100,
    )
    checkpoint = build_central_score_checkpoint(
        score_report,
        policy,
        finalized_epoch=42,
        sequence=1,
        issued_at_epoch=BASE_EPOCH,
        evaluation_epoch=checkpoint_evaluation,
        expires_at_epoch=checkpoint_expiry,
        previous_checkpoint_digest_sha256=None,
    )
    signatures = []
    for key_id in sorted(signed_key_ids):
        signature = keys[key_id].sign(checkpoint_signature_message(checkpoint))
        signatures.append(
            build_checkpoint_signature_envelope(
                checkpoint,
                signer_key_id=key_id,
                signature_base64=base64.b64encode(signature).decode("ascii"),
            )
        )
    state = build_initial_checkpoint_chain_state(policy)
    validator = ExternalValidatorIdentity(
        uid=7,
        hotkey="ValidatorA",
        active=True,
        validator_permit=True,
    )
    metagraph = build_relay_finalized_metagraph_snapshot(
        finalized_height=checkpoint.finalized_height,
        finalized_block_hash=checkpoint.finalized_block_hash,
        finalized_epoch=checkpoint.finalized_epoch,
        validator=validator,
        miner_mappings=[
            MetagraphMinerMapping(uid=item.miner_uid, hotkey=item.miner_hotkey)
            for item in checkpoint.score_vector
        ],
    )
    verification_input = build_external_validator_verification_input(
        evaluation_epoch=verifier_evaluation,
        trust_policy=policy,
        checkpoint=checkpoint,
        signatures=signatures,
        canonical_score_report=score_report,
        prior_chain_state=state,
        validator=validator,
        finalized_metagraph=metagraph,
    )
    return Context(
        report=score_report,
        keys=keys,
        policy=policy,
        checkpoint=checkpoint,
        signatures=signatures,
        state=state,
        validator=validator,
        metagraph=metagraph,
        verification_input=verification_input,
    )


def rebuild_input(context: Context, **changes: object) -> ExternalValidatorVerificationInput:
    values: dict[str, object] = {
        "evaluation_epoch": context.verification_input.evaluation_epoch,
        "trust_policy": context.policy,
        "checkpoint": context.checkpoint,
        "signatures": context.signatures,
        "canonical_score_report": context.report,
        "prior_chain_state": context.state,
        "validator": context.validator,
        "finalized_metagraph": context.metagraph,
    }
    values.update(changes)
    return build_external_validator_verification_input(**values)  # type: ignore[arg-type]


def reseal_checkpoint(
    checkpoint: CentralScoreCheckpoint,
    **changes: object,
) -> CentralScoreCheckpoint:
    document = checkpoint.model_dump(mode="json", by_alias=True)
    document.update(changes)
    document.pop("checkpoint_digest_sha256", None)
    if "score_vector" in changes and "score_vector_digest_sha256" not in changes:
        document["score_vector_digest_sha256"] = digest(document["score_vector"])
    document["checkpoint_digest_sha256"] = digest(document)
    return CentralScoreCheckpoint.model_validate(document)


def sign_checkpoint(
    context: Context,
    checkpoint: CentralScoreCheckpoint,
    key_ids: tuple[str, ...] = ("auditor", "issuer"),
) -> list[CheckpointSignatureEnvelope]:
    return [
        build_checkpoint_signature_envelope(
            checkpoint,
            signer_key_id=key_id,
            signature_base64=base64.b64encode(
                context.keys[key_id].sign(checkpoint_signature_message(checkpoint))
            ).decode("ascii"),
        )
        for key_id in sorted(key_ids)
    ]


def ineligible_report(report: CanonicalScoreReport) -> CanonicalScoreReport:
    document = report.model_dump(mode="json", by_alias=True)
    scores = document["miner_scores"]
    assert isinstance(scores, list)
    record = dict(scores[-1])
    record["eligibility_status"] = "ineligible"
    record["reason_codes"] = ["insufficient_scored_observations"]
    record["canonical_score_ppm"] = 0
    record.pop("record_digest_sha256")
    record["record_digest_sha256"] = digest(record)
    scores[-1] = record
    document["eligible_miner_count"] = 3
    document["ineligible_miner_count"] = 1
    document["score_vector_digest_sha256"] = digest(scores)
    document.pop("report_digest_sha256")
    document["report_digest_sha256"] = digest(document)
    return CanonicalScoreReport.model_validate(document)


def assert_rejected(code: str, function: Any, *args: object) -> None:
    with pytest.raises(CheckpointRelayError) as error:
        function(*args)
    assert error.value.code == code
    assert str(error.value) == code


def test_happy_path_is_canonical_integer_only_and_dependency_bound() -> None:
    context = make_context()
    first = verify_checkpoint_and_build_relay(context.verification_input, context.policy)
    second = verify_checkpoint_and_build_relay(context.verification_input, context.policy)

    assert first == second
    assert first.next_chain_state.accepted_checkpoint_count == 1
    assert first.next_chain_state.last_checkpoint_digest_sha256 == (
        context.checkpoint.checkpoint_digest_sha256
    )
    assert first.verification_report.reason_codes == ["checkpoint_verified"]
    assert first.verification_report.verified_signer_key_ids == ["auditor", "issuer"]
    assert first.relay_plan.normalization_algorithm == NORMALIZATION_ALGORITHM
    assert sum(item.weight_u16 for item in first.relay_plan.weights) == WEIGHT_U16_TOTAL
    assert [item.weight_u16 for item in first.relay_plan.weights] == [
        16_384,
        16_384,
        16_384,
        16_383,
    ]
    assert first.relay_plan.verification_report_digest_sha256 == (
        first.verification_report.report_digest_sha256
    )
    assert first.relay_plan.validator_hotkey == context.validator.hotkey
    assert first.relay_plan.checkpoint_digest_sha256 == (
        context.checkpoint.checkpoint_digest_sha256
    )


def test_checkpoint_trust_rejects_every_small_order_ed25519_encoding(
    small_order_ed25519_public_key: bytes,
) -> None:
    context = make_context()
    valid_key = context.policy.trusted_keys[0]
    updates = {
        "public_key_base64": base64.b64encode(small_order_ed25519_public_key).decode("ascii"),
        "public_key_sha256": hashlib.sha256(small_order_ed25519_public_key).hexdigest(),
    }
    key_document = valid_key.model_dump(mode="json", by_alias=True)
    key_document.update(updates)
    with pytest.raises(ValidationError, match="ed25519_public_key_small_order"):
        TrustedCheckpointKey.model_validate(key_document)

    trusted_keys = list(context.policy.trusted_keys)
    trusted_keys[0] = valid_key.model_copy(update=updates)
    weak_policy = context.policy.model_copy(update={"trusted_keys": trusted_keys})
    assert_rejected(
        "signer_key_invalid",
        verify_checkpoint_and_build_relay,
        context.verification_input,
        weak_policy,
    )


def test_canonical_contract_bytes_round_trip_and_reject_malleability() -> None:
    context = make_context()
    result = verify_checkpoint_and_build_relay(context.verification_input, context.policy)
    contracts = [
        (
            context.checkpoint,
            central_score_checkpoint_bytes,
            parse_central_score_checkpoint,
        ),
        (context.policy, checkpoint_trust_policy_bytes, parse_checkpoint_trust_policy),
        (
            context.signatures[0],
            checkpoint_signature_envelope_bytes,
            parse_checkpoint_signature_envelope,
        ),
        (context.state, checkpoint_chain_state_bytes, parse_checkpoint_chain_state),
        (
            context.metagraph,
            relay_finalized_metagraph_snapshot_bytes,
            parse_relay_finalized_metagraph_snapshot,
        ),
        (
            context.verification_input,
            external_validator_verification_input_bytes,
            parse_external_validator_verification_input,
        ),
        (
            result.verification_report,
            external_validator_verification_report_bytes,
            parse_external_validator_verification_report,
        ),
        (
            result.relay_plan,
            external_validator_relay_plan_bytes,
            parse_external_validator_relay_plan,
        ),
    ]
    for value, renderer, parser in contracts:
        rendered = renderer(value)
        assert rendered.endswith(b"\n")
        assert parser(rendered) == value
        with pytest.raises(ValueError):
            parser(b" " + rendered)
        key = next(iter(json.loads(rendered)))
        duplicate = rendered[:-2] + f',"{key}":null}}\n'.encode()
        with pytest.raises(ValueError):
            parser(duplicate)


def test_strict_frozen_extra_forbid_and_fixed_identity_fields() -> None:
    context = make_context()
    with pytest.raises(ValidationError):
        CentralScoreCheckpoint.model_validate(
            {**context.checkpoint.model_dump(mode="json", by_alias=True), "extra": True}
        )
    with pytest.raises(ValidationError):
        context.checkpoint.sequence = 9  # type: ignore[misc]
    for field, value in (
        ("network", "test"),
        ("netuid", 25),
        ("purpose", "local_score_override"),
        ("schema", "competing/domain"),
    ):
        document = context.checkpoint.model_dump(mode="json", by_alias=True)
        document[field] = value
        document.pop("checkpoint_digest_sha256")
        document["checkpoint_digest_sha256"] = digest(document)
        with pytest.raises(ValidationError):
            CentralScoreCheckpoint.model_validate(document)


def test_invalid_malleated_signature_signer_swap_and_untrusted_signer() -> None:
    context = make_context()
    original = base64.b64decode(context.signatures[0].signature_base64)
    malformed = original[:-1] + bytes([original[-1] ^ 1])
    envelope = build_checkpoint_signature_envelope(
        context.checkpoint,
        signer_key_id="auditor",
        signature_base64=base64.b64encode(malformed).decode("ascii"),
    )
    value = rebuild_input(context, signatures=[envelope, context.signatures[1]])
    assert_rejected("signature_invalid", verify_checkpoint_and_build_relay, value, context.policy)

    issuer_signature = context.keys["issuer"].sign(checkpoint_signature_message(context.checkpoint))
    swapped = build_checkpoint_signature_envelope(
        context.checkpoint,
        signer_key_id="auditor",
        signature_base64=base64.b64encode(issuer_signature).decode("ascii"),
    )
    value = rebuild_input(context, signatures=[swapped, context.signatures[1]])
    assert_rejected("signature_invalid", verify_checkpoint_and_build_relay, value, context.policy)

    unknown = build_checkpoint_signature_envelope(
        context.checkpoint,
        signer_key_id="unknown",
        signature_base64=base64.b64encode(issuer_signature).decode("ascii"),
    )
    value = rebuild_input(context, signatures=[context.signatures[0], unknown])
    assert_rejected("signer_untrusted", verify_checkpoint_and_build_relay, value, context.policy)


def test_threshold_roles_revocation_expiry_and_future_key_fail_closed() -> None:
    threshold = make_context(threshold=3)
    assert_rejected(
        "threshold_not_met",
        verify_checkpoint_and_build_relay,
        threshold.verification_input,
        threshold.policy,
    )

    roles = make_context(
        required_roles=("checkpoint_auditor", "checkpoint_security"),
        signed_key_ids=("auditor", "issuer"),
    )
    assert_rejected(
        "required_role_missing",
        verify_checkpoint_and_build_relay,
        roles.verification_input,
        roles.policy,
    )

    revoked = make_context(revoked={"issuer": BASE_EPOCH + 150})
    assert_rejected(
        "signer_revoked",
        verify_checkpoint_and_build_relay,
        revoked.verification_input,
        revoked.policy,
    )

    expired = make_context(key_windows={"issuer": (BASE_EPOCH - 1_000, BASE_EPOCH + 3_599)})
    assert_rejected(
        "signer_expired",
        verify_checkpoint_and_build_relay,
        expired.verification_input,
        expired.policy,
    )

    future = make_context(key_windows={"issuer": (BASE_EPOCH + 1, BASE_EPOCH + 100_000)})
    assert_rejected(
        "signer_not_yet_valid",
        verify_checkpoint_and_build_relay,
        future.verification_input,
        future.policy,
    )


def test_checkpoint_stale_future_expired_and_lifetime_bounds() -> None:
    stale = make_context(verifier_evaluation=BASE_EPOCH + 1_101)
    assert_rejected(
        "checkpoint_stale",
        verify_checkpoint_and_build_relay,
        stale.verification_input,
        stale.policy,
    )

    future = make_context(verifier_evaluation=BASE_EPOCH + 94)
    assert_rejected(
        "checkpoint_future",
        verify_checkpoint_and_build_relay,
        future.verification_input,
        future.policy,
    )

    expired = make_context(verifier_evaluation=BASE_EPOCH + 3_600)
    assert_rejected(
        "checkpoint_expired",
        verify_checkpoint_and_build_relay,
        expired.verification_input,
        expired.policy,
    )

    context = make_context()
    long_lived = reseal_checkpoint(
        context.checkpoint,
        expires_at_epoch=BASE_EPOCH + 7_201,
    )
    value = rebuild_input(
        context,
        checkpoint=long_lived,
        signatures=sign_checkpoint(context, long_lived),
    )
    assert_rejected(
        "checkpoint_lifetime_invalid",
        verify_checkpoint_and_build_relay,
        value,
        context.policy,
    )


def test_report_vector_and_authority_substitution_are_rejected() -> None:
    context = make_context()
    substituted_report = ineligible_report(context.report)
    value = rebuild_input(context, canonical_score_report=substituted_report)
    assert_rejected(
        "report_binding_mismatch",
        verify_checkpoint_and_build_relay,
        value,
        context.policy,
    )

    vector = context.checkpoint.model_dump(mode="json", by_alias=True)["score_vector"]
    assert isinstance(vector, list)
    changed_vector = [dict(item) for item in vector]
    changed_vector[0]["canonical_score_ppm"] = 999_999
    changed = reseal_checkpoint(context.checkpoint, score_vector=changed_vector)
    value = rebuild_input(
        context,
        checkpoint=changed,
        signatures=sign_checkpoint(context, changed),
    )
    assert_rejected(
        "score_vector_mismatch",
        verify_checkpoint_and_build_relay,
        value,
        context.policy,
    )

    authority_changed = reseal_checkpoint(
        context.checkpoint,
        central_authority_fingerprint_sha256="f" * 64,
    )
    value = rebuild_input(
        context,
        checkpoint=authority_changed,
        signatures=sign_checkpoint(context, authority_changed),
    )
    assert_rejected(
        "authority_mismatch",
        verify_checkpoint_and_build_relay,
        value,
        context.policy,
    )


def test_metagraph_uid_hotkey_coverage_validator_and_finality_are_exact() -> None:
    context = make_context()
    mappings = list(context.metagraph.miner_mappings)
    churn = [
        MetagraphMinerMapping(uid=item.uid, hotkey=("MinerZ" if index == 0 else item.hotkey))
        for index, item in enumerate(mappings)
    ]
    churned = build_relay_finalized_metagraph_snapshot(
        finalized_height=context.checkpoint.finalized_height,
        finalized_block_hash=context.checkpoint.finalized_block_hash,
        finalized_epoch=context.checkpoint.finalized_epoch,
        validator=context.validator,
        miner_mappings=churn,
    )
    value = rebuild_input(context, finalized_metagraph=churned)
    assert_rejected(
        "metagraph_mapping_mismatch",
        verify_checkpoint_and_build_relay,
        value,
        context.policy,
    )

    for changed in (
        mappings[:-1],
        [*mappings, MetagraphMinerMapping(uid=99, hotkey="MinerExtra")],
    ):
        metagraph = build_relay_finalized_metagraph_snapshot(
            finalized_height=context.checkpoint.finalized_height,
            finalized_block_hash=context.checkpoint.finalized_block_hash,
            finalized_epoch=context.checkpoint.finalized_epoch,
            validator=context.validator,
            miner_mappings=changed,
        )
        value = rebuild_input(context, finalized_metagraph=metagraph)
        assert_rejected(
            "metagraph_coverage_mismatch",
            verify_checkpoint_and_build_relay,
            value,
            context.policy,
        )

    with pytest.raises(ValidationError):
        build_relay_finalized_metagraph_snapshot(
            finalized_height=context.checkpoint.finalized_height,
            finalized_block_hash=context.checkpoint.finalized_block_hash,
            finalized_epoch=context.checkpoint.finalized_epoch,
            validator=context.validator,
            miner_mappings=[*mappings, mappings[0]],
        )

    other_validator = ExternalValidatorIdentity(
        uid=8,
        hotkey="ValidatorB",
        active=True,
        validator_permit=True,
    )
    value = rebuild_input(context, validator=other_validator)
    assert_rejected(
        "validator_identity_mismatch",
        verify_checkpoint_and_build_relay,
        value,
        context.policy,
    )

    wrong_finality = build_relay_finalized_metagraph_snapshot(
        finalized_height=context.checkpoint.finalized_height,
        finalized_block_hash="f" * 64,
        finalized_epoch=context.checkpoint.finalized_epoch,
        validator=context.validator,
        miner_mappings=mappings,
    )
    value = rebuild_input(context, finalized_metagraph=wrong_finality)
    assert_rejected(
        "metagraph_binding_mismatch",
        verify_checkpoint_and_build_relay,
        value,
        context.policy,
    )


def test_ineligible_miners_are_zero_and_largest_remainder_ties_are_stable() -> None:
    context = make_context(report=ineligible_report(load_report()))
    result = verify_checkpoint_and_build_relay(context.verification_input, context.policy)
    last = result.relay_plan.weights[-1]
    assert last.source_eligibility_status == "ineligible"
    assert last.source_canonical_score_ppm == 0
    assert last.weight_u16 == 0
    assert [item.weight_u16 for item in result.relay_plan.weights[:3]] == [
        21_845,
        21_845,
        21_845,
    ]

    tie = make_context()
    plan = verify_checkpoint_and_build_relay(tie.verification_input, tie.policy).relay_plan
    assert [(item.miner_uid, item.weight_u16) for item in plan.weights] == [
        (10, 16_384),
        (11, 16_384),
        (12, 16_384),
        (13, 16_383),
    ]

    invalid = context.checkpoint.model_dump(mode="json", by_alias=True)
    invalid_vector = invalid["score_vector"]
    assert isinstance(invalid_vector, list)
    invalid_vector[0]["eligibility_status"] = "ineligible"
    with pytest.raises(ValidationError, match="ineligible_score_nonzero"):
        CentralScoreCheckpoint.model_validate(invalid)

    duplicate = context.checkpoint.model_dump(mode="json", by_alias=True)
    duplicate_vector = duplicate["score_vector"]
    assert isinstance(duplicate_vector, list)
    duplicate_vector[-1] = dict(duplicate_vector[0])
    duplicate["score_vector_digest_sha256"] = digest(duplicate_vector)
    duplicate.pop("checkpoint_digest_sha256")
    duplicate["checkpoint_digest_sha256"] = digest(duplicate)
    with pytest.raises(ValidationError, match="checkpoint_score_vector_not_canonical"):
        CentralScoreCheckpoint.model_validate(duplicate)


def sequence_checkpoint(
    context: Context,
    *,
    sequence: int,
    previous: str,
    **changes: object,
) -> CentralScoreCheckpoint:
    checkpoint = build_central_score_checkpoint(
        context.report,
        context.policy,
        finalized_epoch=context.checkpoint.finalized_epoch,
        sequence=sequence,
        issued_at_epoch=BASE_EPOCH + sequence,
        evaluation_epoch=BASE_EPOCH + 100 + sequence,
        expires_at_epoch=BASE_EPOCH + 3_600 + sequence,
        previous_checkpoint_digest_sha256=previous,
    )
    return reseal_checkpoint(checkpoint, **changes) if changes else checkpoint


def test_append_only_non_equivocation_and_bounded_gaps() -> None:
    context = make_context()
    state1 = advance_checkpoint_chain_state(context.state, context.checkpoint, context.policy)
    assert_rejected(
        "checkpoint_replay",
        advance_checkpoint_chain_state,
        state1,
        context.checkpoint,
        context.policy,
    )
    reused_sequence = reseal_checkpoint(
        context.checkpoint,
        canonical_score_report_digest_sha256="e" * 64,
    )
    assert_rejected(
        "same_height_divergence",
        advance_checkpoint_chain_state,
        state1,
        reused_sequence,
        context.policy,
    )

    second = sequence_checkpoint(
        context,
        sequence=2,
        previous=context.checkpoint.checkpoint_digest_sha256,
    )
    state2 = advance_checkpoint_chain_state(state1, second, context.policy)
    assert state2.accepted_checkpoint_count == 2
    assert state2.last_sequence == 2
    assert_rejected(
        "sequence_rollback",
        advance_checkpoint_chain_state,
        state2,
        context.checkpoint,
        context.policy,
    )

    wrong_link = sequence_checkpoint(context, sequence=2, previous="f" * 64)
    assert_rejected(
        "previous_link_mismatch",
        advance_checkpoint_chain_state,
        state1,
        wrong_link,
        context.policy,
    )
    gap = sequence_checkpoint(
        context,
        sequence=6,
        previous=context.checkpoint.checkpoint_digest_sha256,
    )
    assert_rejected(
        "sequence_gap",
        advance_checkpoint_chain_state,
        state1,
        gap,
        context.policy,
    )

    rollback = sequence_checkpoint(
        context,
        sequence=2,
        previous=context.checkpoint.checkpoint_digest_sha256,
        finalized_height=context.checkpoint.finalized_height - 1,
    )
    assert_rejected(
        "finalized_height_rollback",
        advance_checkpoint_chain_state,
        state1,
        rollback,
        context.policy,
    )
    fork = sequence_checkpoint(
        context,
        sequence=2,
        previous=context.checkpoint.checkpoint_digest_sha256,
        finalized_block_hash="f" * 64,
    )
    assert_rejected(
        "same_height_fork",
        advance_checkpoint_chain_state,
        state1,
        fork,
        context.policy,
    )
    divergence = sequence_checkpoint(
        context,
        sequence=2,
        previous=context.checkpoint.checkpoint_digest_sha256,
        canonical_score_report_digest_sha256="e" * 64,
    )
    assert_rejected(
        "same_height_divergence",
        advance_checkpoint_chain_state,
        state1,
        divergence,
        context.policy,
    )
    height_gap = sequence_checkpoint(
        context,
        sequence=2,
        previous=context.checkpoint.checkpoint_digest_sha256,
        finalized_height=context.checkpoint.finalized_height + 101,
        finalized_epoch=context.checkpoint.finalized_epoch + 1,
    )
    assert_rejected(
        "finalized_height_gap",
        advance_checkpoint_chain_state,
        state1,
        height_gap,
        context.policy,
    )
    epoch_rollback = sequence_checkpoint(
        context,
        sequence=2,
        previous=context.checkpoint.checkpoint_digest_sha256,
        finalized_height=context.checkpoint.finalized_height + 1,
        finalized_epoch=context.checkpoint.finalized_epoch - 1,
    )
    assert_rejected(
        "finalized_epoch_rollback",
        advance_checkpoint_chain_state,
        state1,
        epoch_rollback,
        context.policy,
    )


def test_immutable_chain_identity_policy_and_authority() -> None:
    context = make_context()
    state = advance_checkpoint_chain_state(context.state, context.checkpoint, context.policy)
    cases = (
        ("authority_mismatch", {"central_authority_fingerprint_sha256": "f" * 64}),
        ("policy_mismatch", {"central_scoring_policy_digest_sha256": "e" * 64}),
        ("trust_policy_mismatch", {"trust_policy_digest_sha256": "d" * 64}),
    )
    for code, changes in cases:
        checkpoint = sequence_checkpoint(
            context,
            sequence=2,
            previous=context.checkpoint.checkpoint_digest_sha256,
            **changes,
        )
        assert_rejected(
            code,
            advance_checkpoint_chain_state,
            state,
            checkpoint,
            context.policy,
        )


def test_external_scores_cannot_be_supplied_and_plan_has_no_activation_fields() -> None:
    input_fields = ExternalValidatorVerificationInput.model_fields
    assert (
        not {
            "local_scores",
            "score_override",
            "evidence_override",
            "challenge",
            "domain",
            "provisioning",
        }
        & input_fields.keys()
    )
    plan_fields = ExternalValidatorRelayPlan.model_fields
    assert (
        not {
            "wallet",
            "rpc",
            "submit",
            "apply",
            "private_key",
            "endpoint",
        }
        & plan_fields.keys()
    )


def test_schema_and_fixture_names_are_stable() -> None:
    assert (
        CHECKPOINT_SCHEMA,
        TRUST_POLICY_SCHEMA,
        SIGNATURE_ENVELOPE_SCHEMA,
        CHAIN_STATE_SCHEMA,
        RELAY_METAGRAPH_SCHEMA,
        VERIFICATION_INPUT_SCHEMA,
        VERIFICATION_REPORT_SCHEMA,
        RELAY_PLAN_SCHEMA,
    ) == (
        "miss.computer/misscomputer-subnet/central-score-checkpoint",
        "miss.computer/misscomputer-subnet/score-checkpoint-trust-policy",
        "miss.computer/misscomputer-subnet/score-checkpoint-signature-envelope",
        "miss.computer/misscomputer-subnet/score-checkpoint-chain-state",
        "miss.computer/misscomputer-subnet/relay-finalized-metagraph-snapshot",
        "miss.computer/misscomputer-subnet/external-validator-verification-input",
        "miss.computer/misscomputer-subnet/external-validator-verification-report",
        "miss.computer/misscomputer-subnet/external-validator-score-relay-plan",
    )


@pytest.mark.parametrize(
    ("stem", "parser"),
    [
        ("central-score-checkpoint", parse_central_score_checkpoint),
        ("score-checkpoint-trust-policy", parse_checkpoint_trust_policy),
        ("score-checkpoint-signature-envelope", parse_checkpoint_signature_envelope),
        ("score-checkpoint-chain-state", parse_checkpoint_chain_state),
        ("relay-finalized-metagraph-snapshot", parse_relay_finalized_metagraph_snapshot),
        (
            "external-validator-verification-input",
            parse_external_validator_verification_input,
        ),
        (
            "external-validator-verification-report",
            parse_external_validator_verification_report,
        ),
        ("external-validator-score-relay-plan", parse_external_validator_relay_plan),
    ],
)
def test_generated_schema_and_canonical_fixture(stem: str, parser: Any) -> None:
    schema = json.loads((ROOT / "contracts" / "schemas" / f"{stem}.v1.schema.json").read_bytes())
    fixture_bytes = (ROOT / "contracts" / "fixtures" / f"{stem}.v1.json").read_bytes()
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(json.loads(fixture_bytes))
    assert parser(fixture_bytes)


def test_golden_external_signatures_verify_and_outputs_match_fixtures() -> None:
    fixtures = ROOT / "contracts" / "fixtures"
    policy = parse_checkpoint_trust_policy(
        (fixtures / "score-checkpoint-trust-policy.v1.json").read_bytes()
    )
    verification_input = parse_external_validator_verification_input(
        (fixtures / "external-validator-verification-input.v1.json").read_bytes()
    )
    result = verify_checkpoint_and_build_relay(verification_input, policy)
    assert (
        external_validator_verification_report_bytes(result.verification_report)
        == (fixtures / "external-validator-verification-report.v1.json").read_bytes()
    )
    assert (
        external_validator_relay_plan_bytes(result.relay_plan)
        == (fixtures / "external-validator-score-relay-plan.v1.json").read_bytes()
    )


def test_source_has_only_public_offline_pure_capabilities() -> None:
    source_path = ROOT / "src" / "misscomputer_subnet" / "score_checkpoint_relay.py"
    source = source_path.read_text()
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
            pytest.fail("checkpoint relay source contains a floating-point literal")

    assert imported_roots <= {
        "__future__",
        "base64",
        "binascii",
        "collections",
        "checkpoint_score_contracts",
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
    ):
        assert forbidden not in lowered


@pytest.mark.parametrize(
    ("model", "expected_schema"),
    [
        (CentralScoreCheckpoint, CHECKPOINT_SCHEMA),
        (CheckpointTrustPolicy, TRUST_POLICY_SCHEMA),
        (CheckpointSignatureEnvelope, SIGNATURE_ENVELOPE_SCHEMA),
        (CheckpointChainState, CHAIN_STATE_SCHEMA),
        (RelayFinalizedMetagraphSnapshot, RELAY_METAGRAPH_SCHEMA),
        (ExternalValidatorVerificationInput, VERIFICATION_INPUT_SCHEMA),
        (ExternalValidatorVerificationReport, VERIFICATION_REPORT_SCHEMA),
        (ExternalValidatorRelayPlan, RELAY_PLAN_SCHEMA),
    ],
)
def test_all_top_level_contracts_are_extra_forbid(model: Any, expected_schema: str) -> None:
    schema = model.model_json_schema()
    assert schema["additionalProperties"] is False
    assert schema["properties"]["schema"]["const"] == expected_schema
