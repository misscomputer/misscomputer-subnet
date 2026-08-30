# SPDX-License-Identifier: AGPL-3.0-only
"""Pure signed central-score checkpoint verification and weight relay contracts.

The central ``miss.computer`` scorer is the only source of score and evidence
truth.  This module accepts an already-produced canonical score report and externally
produced Ed25519 signatures, verifies them without side effects, advances a
caller-supplied append-only state value, and derives one deterministic integer
relay plan.  It deliberately has no file, environment, clock, randomness,
network, process, chain-client, credential, signing, submission, or activation
capability.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Annotated, Final, Literal, NoReturn, Self, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from .checkpoint_score_contracts import CanonicalScoreReport
from .ed25519_trust import (
    Ed25519PublicKeyValidationError,
    decode_ed25519_public_key_base64,
)

CHECKPOINT_SCHEMA: Final = "miss.computer/misscomputer-subnet/central-score-checkpoint"
TRUST_POLICY_SCHEMA: Final = "miss.computer/misscomputer-subnet/score-checkpoint-trust-policy"
SIGNATURE_ENVELOPE_SCHEMA: Final = (
    "miss.computer/misscomputer-subnet/score-checkpoint-signature-envelope"
)
CHAIN_STATE_SCHEMA: Final = "miss.computer/misscomputer-subnet/score-checkpoint-chain-state"
RELAY_METAGRAPH_SCHEMA: Final = (
    "miss.computer/misscomputer-subnet/relay-finalized-metagraph-snapshot"
)
VERIFICATION_INPUT_SCHEMA: Final = (
    "miss.computer/misscomputer-subnet/external-validator-verification-input"
)
VERIFICATION_REPORT_SCHEMA: Final = (
    "miss.computer/misscomputer-subnet/external-validator-verification-report"
)
RELAY_PLAN_SCHEMA: Final = "miss.computer/misscomputer-subnet/external-validator-score-relay-plan"
CHECKPOINT_SCHEMA_VERSION: Final = 1
CHECKPOINT_PURPOSE: Final = "central_score_checkpoint_weight_relay_v1"
VERIFICATION_PURPOSE: Final = "external_validator_checkpoint_verification_v1"
RELAY_PURPOSE: Final = "external_validator_weight_relay_v1"
SIGNATURE_DOMAIN_SEPARATOR: Final = (
    b"miss.computer/misscomputer-subnet/central-score-checkpoint/v1/ed25519"
)
NORMALIZATION_ALGORITHM: Final = "largest_remainder_score_ppm_to_u16_v1"
WEIGHT_DOMAIN: Final = "weight-plan.v1/u16-normalized"
WEIGHT_U16_TOTAL: Final = (1 << 16) - 1
MAINNET_NETWORK: Final = "finney"
MAINNET_NETUID: Final = 24
MAX_MINERS: Final = 4_096
MAX_KEYS: Final = 16
MAX_DOCUMENT_BYTES: Final = 64 * 1_024 * 1_024
MAX_EPOCH: Final = (1 << 63) - 1

Digest = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
Hotkey = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9]{1,128}$")]
KeyID = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=64,
        pattern=r"^[a-z0-9](?:[a-z0-9_-]{0,62}[a-z0-9])?$",
    ),
]
UID = Annotated[int, Field(ge=0, le=WEIGHT_U16_TOTAL)]
Epoch = Annotated[int, Field(ge=0, le=MAX_EPOCH)]
PositiveEpoch = Annotated[int, Field(ge=1, le=MAX_EPOCH)]
Role = Literal["checkpoint_auditor", "checkpoint_issuer", "checkpoint_security"]
Eligibility = Literal["eligible", "ineligible"]

RelayRejectionCode = Literal[
    "authority_mismatch",
    "checkpoint_expired",
    "checkpoint_future",
    "checkpoint_lifetime_invalid",
    "checkpoint_replay",
    "checkpoint_stale",
    "finalized_epoch_rollback",
    "finalized_height_gap",
    "finalized_height_rollback",
    "input_snapshot_mismatch",
    "metagraph_binding_mismatch",
    "metagraph_coverage_mismatch",
    "metagraph_mapping_mismatch",
    "network_mismatch",
    "normalization_empty",
    "policy_mismatch",
    "previous_link_mismatch",
    "report_binding_mismatch",
    "required_role_missing",
    "same_height_divergence",
    "same_height_fork",
    "score_vector_mismatch",
    "sequence_gap",
    "sequence_rollback",
    "signature_binding_mismatch",
    "signature_invalid",
    "signer_expired",
    "signer_key_invalid",
    "signer_not_yet_valid",
    "signer_purpose_mismatch",
    "signer_revoked",
    "signer_untrusted",
    "threshold_not_met",
    "trust_policy_expired",
    "trust_policy_mismatch",
    "trust_policy_not_yet_valid",
    "validator_identity_mismatch",
]


class CheckpointRelayError(ValueError):
    """Stable, sanitized fail-closed verification rejection."""

    def __init__(self, code: RelayRejectionCode) -> None:
        super().__init__(code)
        self.code = code


def _reject(code: RelayRejectionCode) -> NoReturn:
    raise CheckpointRelayError(code)


class _StrictFrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


def _canonical_json(value: object) -> bytes:
    try:
        rendered = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError, RecursionError) as exc:
        raise ValueError("canonical_json_invalid") from exc
    return rendered.encode("ascii")


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _model_document(model: BaseModel, *, exclude: set[str] | None = None) -> dict[str, object]:
    return cast(
        dict[str, object],
        model.model_dump(mode="json", by_alias=True, exclude=exclude),
    )


def _verify_model_digest(model: BaseModel, field_name: str) -> None:
    document = _model_document(model, exclude={field_name})
    if cast(str, getattr(model, field_name)) != _digest(document):
        raise ValueError(f"{field_name}_mismatch")


def _revalidate[ModelT: BaseModel](value: ModelT, model_type: type[ModelT]) -> ModelT:
    return model_type.model_validate(value.model_dump(mode="json", by_alias=True))


def _decode_base64(value: str, *, expected_bytes: int) -> bytes:
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("base64_invalid") from exc
    if len(decoded) != expected_bytes or base64.b64encode(decoded).decode("ascii") != value:
        raise ValueError("base64_invalid")
    return decoded


class CheckpointScoreEntry(_StrictFrozenModel):
    miner_uid: UID
    miner_hotkey: Hotkey
    eligibility_status: Eligibility
    canonical_score_ppm: int = Field(ge=0, le=1_000_000)
    record_digest_sha256: Digest

    @model_validator(mode="after")
    def fail_closed_ineligible(self) -> Self:
        if self.eligibility_status == "ineligible" and self.canonical_score_ppm != 0:
            raise ValueError("ineligible_score_nonzero")
        return self


class CentralScoreCheckpoint(_StrictFrozenModel):
    contract_schema: Literal["miss.computer/misscomputer-subnet/central-score-checkpoint"] = Field(
        alias="schema"
    )
    schema_version: Literal[1]
    purpose: Literal["central_score_checkpoint_weight_relay_v1"]
    network: Literal["finney"]
    netuid: Literal[24]
    central_authority_fingerprint_sha256: Digest
    central_scoring_policy_digest_sha256: Digest
    trust_policy_digest_sha256: Digest
    finalized_height: Epoch
    finalized_block_hash: Digest
    finalized_epoch: Epoch
    input_snapshot_digest_sha256: Digest
    canonical_score_report_digest_sha256: Digest
    report_score_vector_digest_sha256: Digest
    score_vector: list[CheckpointScoreEntry] = Field(min_length=1, max_length=MAX_MINERS)
    score_vector_digest_sha256: Digest
    sequence: PositiveEpoch
    issued_at_epoch: Epoch
    evaluation_epoch: Epoch
    expires_at_epoch: Epoch
    previous_checkpoint_digest_sha256: Digest | None
    checkpoint_digest_sha256: Digest

    @model_validator(mode="after")
    def canonical_checkpoint(self) -> Self:
        if not self.issued_at_epoch <= self.evaluation_epoch < self.expires_at_epoch:
            raise ValueError("checkpoint_time_window_invalid")
        if (self.sequence == 1) != (self.previous_checkpoint_digest_sha256 is None):
            raise ValueError("checkpoint_previous_link_invalid")
        keys = [(item.miner_uid, item.miner_hotkey) for item in self.score_vector]
        if keys != sorted(set(keys)):
            raise ValueError("checkpoint_score_vector_not_canonical")
        if len({item.miner_uid for item in self.score_vector}) != len(self.score_vector):
            raise ValueError("checkpoint_score_vector_uid_duplicate")
        if len({item.miner_hotkey for item in self.score_vector}) != len(self.score_vector):
            raise ValueError("checkpoint_score_vector_hotkey_duplicate")
        vector = [_model_document(item) for item in self.score_vector]
        if self.score_vector_digest_sha256 != _digest(vector):
            raise ValueError("score_vector_digest_sha256_mismatch")
        _verify_model_digest(self, "checkpoint_digest_sha256")
        return self


class TrustedCheckpointKey(_StrictFrozenModel):
    key_id: KeyID
    algorithm: Literal["ed25519"]
    public_key_base64: Annotated[str, StringConstraints(min_length=44, max_length=44)]
    public_key_sha256: Digest
    roles: list[Role] = Field(min_length=1, max_length=3)
    purposes: list[Literal["central_score_checkpoint_weight_relay_v1"]] = Field(
        min_length=1, max_length=1
    )
    valid_from_epoch: Epoch
    valid_until_epoch: Epoch
    revoked_at_epoch: Epoch | None

    @model_validator(mode="after")
    def valid_key(self) -> Self:
        public_bytes = decode_ed25519_public_key_base64(self.public_key_base64)
        if hashlib.sha256(public_bytes).hexdigest() != self.public_key_sha256:
            raise ValueError("public_key_digest_mismatch")
        if self.roles != sorted(set(self.roles)):
            raise ValueError("key_roles_not_canonical")
        if self.purposes != [CHECKPOINT_PURPOSE]:
            raise ValueError("key_purpose_invalid")
        if self.valid_until_epoch <= self.valid_from_epoch:
            raise ValueError("key_validity_window_invalid")
        if self.revoked_at_epoch is not None and not (
            self.valid_from_epoch <= self.revoked_at_epoch <= self.valid_until_epoch
        ):
            raise ValueError("key_revocation_epoch_invalid")
        return self


class CheckpointTrustPolicy(_StrictFrozenModel):
    contract_schema: Literal["miss.computer/misscomputer-subnet/score-checkpoint-trust-policy"] = (
        Field(alias="schema")
    )
    schema_version: Literal[1]
    policy_id: Literal["miss-computer-central-score-checkpoint-trust-v1"]
    purpose: Literal["central_score_checkpoint_weight_relay_v1"]
    network: Literal["finney"]
    netuid: Literal[24]
    central_authority_fingerprint_sha256: Digest
    central_scoring_policy_digest_sha256: Digest
    threshold: int = Field(ge=1, le=MAX_KEYS)
    required_roles: list[Role] = Field(min_length=1, max_length=3)
    trusted_keys: list[TrustedCheckpointKey] = Field(min_length=1, max_length=MAX_KEYS)
    valid_from_epoch: Epoch
    valid_until_epoch: Epoch
    max_checkpoint_age_seconds: int = Field(ge=1, le=86_400)
    max_future_skew_seconds: int = Field(ge=0, le=300)
    max_checkpoint_lifetime_seconds: int = Field(ge=1, le=86_400)
    max_sequence_gap: int = Field(ge=1, le=64)
    max_finalized_height_gap: int = Field(ge=1, le=1_000_000)
    trust_policy_digest_sha256: Digest

    @model_validator(mode="after")
    def canonical_policy(self) -> Self:
        if self.valid_until_epoch <= self.valid_from_epoch:
            raise ValueError("trust_policy_validity_window_invalid")
        if self.required_roles != sorted(set(self.required_roles)):
            raise ValueError("required_roles_not_canonical")
        key_ids = [item.key_id for item in self.trusted_keys]
        if key_ids != sorted(set(key_ids)):
            raise ValueError("trusted_keys_not_canonical")
        public_keys = [item.public_key_sha256 for item in self.trusted_keys]
        if len(public_keys) != len(set(public_keys)):
            raise ValueError("trusted_public_key_duplicate")
        if self.threshold > len(self.trusted_keys):
            raise ValueError("threshold_exceeds_key_count")
        covered_roles = {role for key in self.trusted_keys for role in key.roles}
        if not set(self.required_roles) <= covered_roles:
            raise ValueError("required_role_uncovered")
        _verify_model_digest(self, "trust_policy_digest_sha256")
        return self


class CheckpointSignatureEnvelope(_StrictFrozenModel):
    contract_schema: Literal[
        "miss.computer/misscomputer-subnet/score-checkpoint-signature-envelope"
    ] = Field(alias="schema")
    schema_version: Literal[1]
    purpose: Literal["central_score_checkpoint_weight_relay_v1"]
    algorithm: Literal["ed25519"]
    signer_key_id: KeyID
    checkpoint_digest_sha256: Digest
    signed_message_digest_sha256: Digest
    signature_base64: Annotated[str, StringConstraints(min_length=88, max_length=88)]

    @model_validator(mode="after")
    def canonical_signature(self) -> Self:
        _decode_base64(self.signature_base64, expected_bytes=64)
        return self


class CheckpointChainState(_StrictFrozenModel):
    contract_schema: Literal["miss.computer/misscomputer-subnet/score-checkpoint-chain-state"] = (
        Field(alias="schema")
    )
    schema_version: Literal[1]
    purpose: Literal["central_score_checkpoint_weight_relay_v1"]
    network: Literal["finney"]
    netuid: Literal[24]
    central_authority_fingerprint_sha256: Digest
    central_scoring_policy_digest_sha256: Digest
    trust_policy_digest_sha256: Digest
    accepted_checkpoint_count: Epoch
    last_sequence: Epoch
    last_finalized_height: Epoch | None
    last_finalized_block_hash: Digest | None
    last_finalized_epoch: Epoch | None
    last_issued_at_epoch: Epoch | None
    last_evaluation_epoch: Epoch | None
    last_input_snapshot_digest_sha256: Digest | None
    last_canonical_score_report_digest_sha256: Digest | None
    last_report_score_vector_digest_sha256: Digest | None
    last_score_vector_digest_sha256: Digest | None
    last_checkpoint_digest_sha256: Digest | None
    state_digest_sha256: Digest

    @model_validator(mode="after")
    def canonical_state(self) -> Self:
        tail = (
            self.last_finalized_height,
            self.last_finalized_block_hash,
            self.last_finalized_epoch,
            self.last_issued_at_epoch,
            self.last_evaluation_epoch,
            self.last_input_snapshot_digest_sha256,
            self.last_canonical_score_report_digest_sha256,
            self.last_report_score_vector_digest_sha256,
            self.last_score_vector_digest_sha256,
            self.last_checkpoint_digest_sha256,
        )
        if self.accepted_checkpoint_count == 0:
            if self.last_sequence != 0 or any(value is not None for value in tail):
                raise ValueError("genesis_chain_state_invalid")
        elif (
            self.last_sequence == 0
            or self.accepted_checkpoint_count > self.last_sequence
            or any(value is None for value in tail)
        ):
            raise ValueError("nonempty_chain_state_invalid")
        _verify_model_digest(self, "state_digest_sha256")
        return self


class MetagraphMinerMapping(_StrictFrozenModel):
    uid: UID
    hotkey: Hotkey


class ExternalValidatorIdentity(_StrictFrozenModel):
    uid: UID
    hotkey: Hotkey
    active: Literal[True]
    validator_permit: Literal[True]


class RelayFinalizedMetagraphSnapshot(_StrictFrozenModel):
    contract_schema: Literal[
        "miss.computer/misscomputer-subnet/relay-finalized-metagraph-snapshot"
    ] = Field(alias="schema")
    schema_version: Literal[1]
    purpose: Literal["external_validator_checkpoint_verification_v1"]
    network: Literal["finney"]
    netuid: Literal[24]
    finalized: Literal[True]
    finalized_height: Epoch
    finalized_block_hash: Digest
    finalized_epoch: Epoch
    validator: ExternalValidatorIdentity
    miner_mappings: list[MetagraphMinerMapping] = Field(min_length=1, max_length=MAX_MINERS)
    miner_mapping_digest_sha256: Digest
    metagraph_snapshot_digest_sha256: Digest

    @model_validator(mode="after")
    def canonical_metagraph(self) -> Self:
        keys = [(item.uid, item.hotkey) for item in self.miner_mappings]
        if keys != sorted(set(keys)):
            raise ValueError("metagraph_mappings_not_canonical")
        if len({item.uid for item in self.miner_mappings}) != len(self.miner_mappings):
            raise ValueError("metagraph_uid_duplicate")
        if len({item.hotkey for item in self.miner_mappings}) != len(self.miner_mappings):
            raise ValueError("metagraph_hotkey_duplicate")
        if self.validator.uid in {item.uid for item in self.miner_mappings} or (
            self.validator.hotkey in {item.hotkey for item in self.miner_mappings}
        ):
            raise ValueError("validator_identity_overlaps_miner")
        mappings = [_model_document(item) for item in self.miner_mappings]
        if self.miner_mapping_digest_sha256 != _digest(mappings):
            raise ValueError("miner_mapping_digest_mismatch")
        _verify_model_digest(self, "metagraph_snapshot_digest_sha256")
        return self


class ExternalValidatorVerificationInput(_StrictFrozenModel):
    contract_schema: Literal[
        "miss.computer/misscomputer-subnet/external-validator-verification-input"
    ] = Field(alias="schema")
    schema_version: Literal[1]
    purpose: Literal["external_validator_checkpoint_verification_v1"]
    evaluation_epoch: Epoch
    trust_policy_digest_sha256: Digest
    checkpoint: CentralScoreCheckpoint
    signatures: list[CheckpointSignatureEnvelope] = Field(min_length=1, max_length=MAX_KEYS)
    canonical_score_report: CanonicalScoreReport
    prior_chain_state: CheckpointChainState
    validator: ExternalValidatorIdentity
    finalized_metagraph: RelayFinalizedMetagraphSnapshot
    input_digest_sha256: Digest

    @model_validator(mode="after")
    def canonical_input(self) -> Self:
        signer_ids = [item.signer_key_id for item in self.signatures]
        if signer_ids != sorted(set(signer_ids)):
            raise ValueError("signature_envelopes_not_canonical")
        _verify_model_digest(self, "input_digest_sha256")
        return self


class RelayWeightEntry(_StrictFrozenModel):
    miner_uid: UID
    miner_hotkey: Hotkey
    source_eligibility_status: Eligibility
    source_canonical_score_ppm: int = Field(ge=0, le=1_000_000)
    weight_u16: int = Field(ge=0, le=WEIGHT_U16_TOTAL)

    @model_validator(mode="after")
    def fail_closed_weight(self) -> Self:
        if (
            self.source_eligibility_status == "ineligible" or self.source_canonical_score_ppm == 0
        ) and self.weight_u16 != 0:
            raise ValueError("zero_source_weight_nonzero")
        return self


class ExternalValidatorVerificationReport(_StrictFrozenModel):
    contract_schema: Literal[
        "miss.computer/misscomputer-subnet/external-validator-verification-report"
    ] = Field(alias="schema")
    schema_version: Literal[1]
    purpose: Literal["external_validator_checkpoint_verification_v1"]
    status: Literal["verified"]
    reason_codes: list[Literal["checkpoint_verified"]] = Field(min_length=1, max_length=1)
    evaluation_epoch: Epoch
    validator_uid: UID
    validator_hotkey: Hotkey
    checkpoint_digest_sha256: Digest
    canonical_score_report_digest_sha256: Digest
    input_snapshot_digest_sha256: Digest
    score_vector_digest_sha256: Digest
    metagraph_snapshot_digest_sha256: Digest
    trust_policy_digest_sha256: Digest
    verification_input_digest_sha256: Digest
    prior_chain_state_digest_sha256: Digest
    next_chain_state_digest_sha256: Digest
    verified_signer_key_ids: list[KeyID] = Field(min_length=1, max_length=MAX_KEYS)
    verified_roles: list[Role] = Field(min_length=1, max_length=3)
    normalization_algorithm: Literal["largest_remainder_score_ppm_to_u16_v1"]
    normalized_weight_vector_digest_sha256: Digest
    report_digest_sha256: Digest

    @model_validator(mode="after")
    def canonical_report(self) -> Self:
        if self.reason_codes != ["checkpoint_verified"]:
            raise ValueError("verification_reason_invalid")
        if self.verified_signer_key_ids != sorted(set(self.verified_signer_key_ids)):
            raise ValueError("verified_signers_not_canonical")
        if self.verified_roles != sorted(set(self.verified_roles)):
            raise ValueError("verified_roles_not_canonical")
        _verify_model_digest(self, "report_digest_sha256")
        return self


class ExternalValidatorRelayPlan(_StrictFrozenModel):
    contract_schema: Literal[
        "miss.computer/misscomputer-subnet/external-validator-score-relay-plan"
    ] = Field(alias="schema")
    schema_version: Literal[1]
    purpose: Literal["external_validator_weight_relay_v1"]
    network: Literal["finney"]
    netuid: Literal[24]
    validator_uid: UID
    validator_hotkey: Hotkey
    finalized_height: Epoch
    finalized_block_hash: Digest
    finalized_epoch: Epoch
    expires_at_epoch: Epoch
    checkpoint_digest_sha256: Digest
    canonical_score_report_digest_sha256: Digest
    input_snapshot_digest_sha256: Digest
    score_vector_digest_sha256: Digest
    metagraph_snapshot_digest_sha256: Digest
    verification_input_digest_sha256: Digest
    verification_report_digest_sha256: Digest
    next_chain_state_digest_sha256: Digest
    weight_domain: Literal["weight-plan.v1/u16-normalized"]
    normalization_algorithm: Literal["largest_remainder_score_ppm_to_u16_v1"]
    weight_total_u16: Literal[65535]
    weights: list[RelayWeightEntry] = Field(min_length=1, max_length=MAX_MINERS)
    weight_vector_digest_sha256: Digest
    plan_digest_sha256: Digest

    @model_validator(mode="after")
    def canonical_plan(self) -> Self:
        keys = [(item.miner_uid, item.miner_hotkey) for item in self.weights]
        if keys != sorted(set(keys)):
            raise ValueError("relay_weights_not_canonical")
        if len({item.miner_uid for item in self.weights}) != len(self.weights):
            raise ValueError("relay_weight_uid_duplicate")
        if len({item.miner_hotkey for item in self.weights}) != len(self.weights):
            raise ValueError("relay_weight_hotkey_duplicate")
        if sum(item.weight_u16 for item in self.weights) != WEIGHT_U16_TOTAL:
            raise ValueError("relay_weight_total_invalid")
        weights = [_model_document(item) for item in self.weights]
        if self.weight_vector_digest_sha256 != _digest(weights):
            raise ValueError("relay_weight_vector_digest_mismatch")
        _verify_model_digest(self, "plan_digest_sha256")
        return self


@dataclass(frozen=True)
class RelayVerificationResult:
    verification_report: ExternalValidatorVerificationReport
    relay_plan: ExternalValidatorRelayPlan
    next_chain_state: CheckpointChainState


def build_checkpoint_trust_policy(
    *,
    central_authority_fingerprint_sha256: str,
    central_scoring_policy_digest_sha256: str,
    threshold: int,
    required_roles: Sequence[Role],
    trusted_keys: Sequence[TrustedCheckpointKey],
    valid_from_epoch: int,
    valid_until_epoch: int,
    max_checkpoint_age_seconds: int,
    max_future_skew_seconds: int,
    max_checkpoint_lifetime_seconds: int,
    max_sequence_gap: int,
    max_finalized_height_gap: int,
) -> CheckpointTrustPolicy:
    """Seal a local public-key trust policy; no secret key material is accepted."""

    keys = sorted(
        (_revalidate(item, TrustedCheckpointKey) for item in trusted_keys),
        key=lambda item: item.key_id,
    )
    unsigned: dict[str, object] = {
        "schema": TRUST_POLICY_SCHEMA,
        "schema_version": CHECKPOINT_SCHEMA_VERSION,
        "policy_id": "miss-computer-central-score-checkpoint-trust-v1",
        "purpose": CHECKPOINT_PURPOSE,
        "network": MAINNET_NETWORK,
        "netuid": MAINNET_NETUID,
        "central_authority_fingerprint_sha256": central_authority_fingerprint_sha256,
        "central_scoring_policy_digest_sha256": central_scoring_policy_digest_sha256,
        "threshold": threshold,
        "required_roles": sorted(required_roles),
        "trusted_keys": [_model_document(item) for item in keys],
        "valid_from_epoch": valid_from_epoch,
        "valid_until_epoch": valid_until_epoch,
        "max_checkpoint_age_seconds": max_checkpoint_age_seconds,
        "max_future_skew_seconds": max_future_skew_seconds,
        "max_checkpoint_lifetime_seconds": max_checkpoint_lifetime_seconds,
        "max_sequence_gap": max_sequence_gap,
        "max_finalized_height_gap": max_finalized_height_gap,
    }
    return CheckpointTrustPolicy.model_validate(
        {**unsigned, "trust_policy_digest_sha256": _digest(unsigned)}
    )


def build_central_score_checkpoint(
    report: CanonicalScoreReport,
    trust_policy: CheckpointTrustPolicy,
    *,
    finalized_epoch: int,
    sequence: int,
    issued_at_epoch: int,
    evaluation_epoch: int,
    expires_at_epoch: int,
    previous_checkpoint_digest_sha256: str | None,
) -> CentralScoreCheckpoint:
    """Bind one exact canonical score report into an unsigned checkpoint."""

    report = _revalidate(report, CanonicalScoreReport)
    policy = _revalidate(trust_policy, CheckpointTrustPolicy)
    if (
        report.network != policy.network
        or report.netuid != policy.netuid
        or report.central_authority_fingerprint_sha256
        != policy.central_authority_fingerprint_sha256
        or report.policy_digest_sha256 != policy.central_scoring_policy_digest_sha256
    ):
        raise ValueError("report_trust_policy_binding_invalid")
    vector = [
        CheckpointScoreEntry(
            miner_uid=item.miner_uid,
            miner_hotkey=item.miner_hotkey,
            eligibility_status=item.eligibility_status,
            canonical_score_ppm=item.canonical_score_ppm,
            record_digest_sha256=item.record_digest_sha256,
        )
        for item in report.miner_scores
    ]
    vector_documents = [_model_document(item) for item in vector]
    unsigned: dict[str, object] = {
        "schema": CHECKPOINT_SCHEMA,
        "schema_version": CHECKPOINT_SCHEMA_VERSION,
        "purpose": CHECKPOINT_PURPOSE,
        "network": report.network,
        "netuid": report.netuid,
        "central_authority_fingerprint_sha256": (report.central_authority_fingerprint_sha256),
        "central_scoring_policy_digest_sha256": report.policy_digest_sha256,
        "trust_policy_digest_sha256": policy.trust_policy_digest_sha256,
        "finalized_height": report.finalized_height,
        "finalized_block_hash": report.finalized_block_hash,
        "finalized_epoch": finalized_epoch,
        "input_snapshot_digest_sha256": report.input_snapshot_digest_sha256,
        "canonical_score_report_digest_sha256": report.report_digest_sha256,
        "report_score_vector_digest_sha256": report.score_vector_digest_sha256,
        "score_vector": vector_documents,
        "score_vector_digest_sha256": _digest(vector_documents),
        "sequence": sequence,
        "issued_at_epoch": issued_at_epoch,
        "evaluation_epoch": evaluation_epoch,
        "expires_at_epoch": expires_at_epoch,
        "previous_checkpoint_digest_sha256": previous_checkpoint_digest_sha256,
    }
    return CentralScoreCheckpoint.model_validate(
        {**unsigned, "checkpoint_digest_sha256": _digest(unsigned)}
    )


def checkpoint_signature_message(checkpoint: CentralScoreCheckpoint) -> bytes:
    """Return the only domain-separated bytes accepted by public-key verification."""

    checkpoint = _revalidate(checkpoint, CentralScoreCheckpoint)
    return SIGNATURE_DOMAIN_SEPARATOR + b"\x00" + _canonical_json(_model_document(checkpoint))


def build_checkpoint_signature_envelope(
    checkpoint: CentralScoreCheckpoint,
    *,
    signer_key_id: str,
    signature_base64: str,
) -> CheckpointSignatureEnvelope:
    """Wrap externally produced signature bytes; this function never creates them."""

    checkpoint = _revalidate(checkpoint, CentralScoreCheckpoint)
    message_digest = hashlib.sha256(checkpoint_signature_message(checkpoint)).hexdigest()
    return CheckpointSignatureEnvelope(
        schema=SIGNATURE_ENVELOPE_SCHEMA,
        schema_version=CHECKPOINT_SCHEMA_VERSION,
        purpose=CHECKPOINT_PURPOSE,
        algorithm="ed25519",
        signer_key_id=signer_key_id,
        checkpoint_digest_sha256=checkpoint.checkpoint_digest_sha256,
        signed_message_digest_sha256=message_digest,
        signature_base64=signature_base64,
    )


def build_initial_checkpoint_chain_state(
    trust_policy: CheckpointTrustPolicy,
) -> CheckpointChainState:
    policy = _revalidate(trust_policy, CheckpointTrustPolicy)
    unsigned: dict[str, object] = {
        "schema": CHAIN_STATE_SCHEMA,
        "schema_version": CHECKPOINT_SCHEMA_VERSION,
        "purpose": CHECKPOINT_PURPOSE,
        "network": policy.network,
        "netuid": policy.netuid,
        "central_authority_fingerprint_sha256": (policy.central_authority_fingerprint_sha256),
        "central_scoring_policy_digest_sha256": (policy.central_scoring_policy_digest_sha256),
        "trust_policy_digest_sha256": policy.trust_policy_digest_sha256,
        "accepted_checkpoint_count": 0,
        "last_sequence": 0,
        "last_finalized_height": None,
        "last_finalized_block_hash": None,
        "last_finalized_epoch": None,
        "last_issued_at_epoch": None,
        "last_evaluation_epoch": None,
        "last_input_snapshot_digest_sha256": None,
        "last_canonical_score_report_digest_sha256": None,
        "last_report_score_vector_digest_sha256": None,
        "last_score_vector_digest_sha256": None,
        "last_checkpoint_digest_sha256": None,
    }
    return CheckpointChainState.model_validate(
        {**unsigned, "state_digest_sha256": _digest(unsigned)}
    )


def build_relay_finalized_metagraph_snapshot(
    *,
    finalized_height: int,
    finalized_block_hash: str,
    finalized_epoch: int,
    validator: ExternalValidatorIdentity,
    miner_mappings: Sequence[MetagraphMinerMapping],
) -> RelayFinalizedMetagraphSnapshot:
    validator = _revalidate(validator, ExternalValidatorIdentity)
    mappings = sorted(
        (_revalidate(item, MetagraphMinerMapping) for item in miner_mappings),
        key=lambda item: (item.uid, item.hotkey),
    )
    mapping_documents = [_model_document(item) for item in mappings]
    unsigned: dict[str, object] = {
        "schema": RELAY_METAGRAPH_SCHEMA,
        "schema_version": CHECKPOINT_SCHEMA_VERSION,
        "purpose": VERIFICATION_PURPOSE,
        "network": MAINNET_NETWORK,
        "netuid": MAINNET_NETUID,
        "finalized": True,
        "finalized_height": finalized_height,
        "finalized_block_hash": finalized_block_hash,
        "finalized_epoch": finalized_epoch,
        "validator": _model_document(validator),
        "miner_mappings": mapping_documents,
        "miner_mapping_digest_sha256": _digest(mapping_documents),
    }
    return RelayFinalizedMetagraphSnapshot.model_validate(
        {**unsigned, "metagraph_snapshot_digest_sha256": _digest(unsigned)}
    )


def build_external_validator_verification_input(
    *,
    evaluation_epoch: int,
    trust_policy: CheckpointTrustPolicy,
    checkpoint: CentralScoreCheckpoint,
    signatures: Sequence[CheckpointSignatureEnvelope],
    canonical_score_report: CanonicalScoreReport,
    prior_chain_state: CheckpointChainState,
    validator: ExternalValidatorIdentity,
    finalized_metagraph: RelayFinalizedMetagraphSnapshot,
) -> ExternalValidatorVerificationInput:
    policy = _revalidate(trust_policy, CheckpointTrustPolicy)
    checkpoint = _revalidate(checkpoint, CentralScoreCheckpoint)
    signature_values = sorted(
        (_revalidate(item, CheckpointSignatureEnvelope) for item in signatures),
        key=lambda item: item.signer_key_id,
    )
    report = _revalidate(canonical_score_report, CanonicalScoreReport)
    state = _revalidate(prior_chain_state, CheckpointChainState)
    validator = _revalidate(validator, ExternalValidatorIdentity)
    metagraph = _revalidate(finalized_metagraph, RelayFinalizedMetagraphSnapshot)
    unsigned: dict[str, object] = {
        "schema": VERIFICATION_INPUT_SCHEMA,
        "schema_version": CHECKPOINT_SCHEMA_VERSION,
        "purpose": VERIFICATION_PURPOSE,
        "evaluation_epoch": evaluation_epoch,
        "trust_policy_digest_sha256": policy.trust_policy_digest_sha256,
        "checkpoint": _model_document(checkpoint),
        "signatures": [_model_document(item) for item in signature_values],
        "canonical_score_report": _model_document(report),
        "prior_chain_state": _model_document(state),
        "validator": _model_document(validator),
        "finalized_metagraph": _model_document(metagraph),
    }
    return ExternalValidatorVerificationInput.model_validate(
        {**unsigned, "input_digest_sha256": _digest(unsigned)}
    )


def _verify_trust_and_freshness(
    value: ExternalValidatorVerificationInput,
    policy: CheckpointTrustPolicy,
) -> None:
    checkpoint = value.checkpoint
    if value.trust_policy_digest_sha256 != policy.trust_policy_digest_sha256:
        _reject("trust_policy_mismatch")
    if checkpoint.trust_policy_digest_sha256 != policy.trust_policy_digest_sha256:
        _reject("trust_policy_mismatch")
    if checkpoint.network != policy.network or checkpoint.netuid != policy.netuid:
        _reject("network_mismatch")
    if (
        checkpoint.central_authority_fingerprint_sha256
        != policy.central_authority_fingerprint_sha256
    ):
        _reject("authority_mismatch")
    if (
        checkpoint.central_scoring_policy_digest_sha256
        != policy.central_scoring_policy_digest_sha256
    ):
        _reject("policy_mismatch")
    if value.evaluation_epoch < policy.valid_from_epoch:
        _reject("trust_policy_not_yet_valid")
    if value.evaluation_epoch >= policy.valid_until_epoch:
        _reject("trust_policy_expired")
    if (
        checkpoint.issued_at_epoch < policy.valid_from_epoch
        or checkpoint.expires_at_epoch > policy.valid_until_epoch
    ):
        _reject("trust_policy_mismatch")
    if (
        checkpoint.expires_at_epoch - checkpoint.issued_at_epoch
        > policy.max_checkpoint_lifetime_seconds
    ):
        _reject("checkpoint_lifetime_invalid")
    if checkpoint.evaluation_epoch > value.evaluation_epoch + policy.max_future_skew_seconds:
        _reject("checkpoint_future")
    if value.evaluation_epoch >= checkpoint.expires_at_epoch:
        _reject("checkpoint_expired")
    if (
        value.evaluation_epoch > checkpoint.evaluation_epoch
        and value.evaluation_epoch - checkpoint.evaluation_epoch > policy.max_checkpoint_age_seconds
    ):
        _reject("checkpoint_stale")


def _verify_report_binding(value: ExternalValidatorVerificationInput) -> None:
    checkpoint = value.checkpoint
    report = value.canonical_score_report
    if report.report_digest_sha256 != checkpoint.canonical_score_report_digest_sha256:
        _reject("report_binding_mismatch")
    if report.input_snapshot_digest_sha256 != checkpoint.input_snapshot_digest_sha256:
        _reject("input_snapshot_mismatch")
    if report.score_vector_digest_sha256 != checkpoint.report_score_vector_digest_sha256:
        _reject("score_vector_mismatch")
    if (
        report.network != checkpoint.network
        or report.netuid != checkpoint.netuid
        or report.finalized_height != checkpoint.finalized_height
        or report.finalized_block_hash != checkpoint.finalized_block_hash
        or report.central_authority_fingerprint_sha256
        != checkpoint.central_authority_fingerprint_sha256
        or report.policy_digest_sha256 != checkpoint.central_scoring_policy_digest_sha256
    ):
        _reject("report_binding_mismatch")
    expected_vector = [
        {
            "miner_uid": item.miner_uid,
            "miner_hotkey": item.miner_hotkey,
            "eligibility_status": item.eligibility_status,
            "canonical_score_ppm": item.canonical_score_ppm,
            "record_digest_sha256": item.record_digest_sha256,
        }
        for item in report.miner_scores
    ]
    if [_model_document(item) for item in checkpoint.score_vector] != expected_vector:
        _reject("score_vector_mismatch")
    if checkpoint.score_vector_digest_sha256 != _digest(expected_vector):
        _reject("score_vector_mismatch")


def _trusted_public_keys(policy: CheckpointTrustPolicy) -> dict[str, bytes]:
    try:
        return {
            item.key_id: decode_ed25519_public_key_base64(item.public_key_base64)
            for item in policy.trusted_keys
        }
    except Ed25519PublicKeyValidationError:
        _reject("signer_key_invalid")


def _verify_signatures(
    value: ExternalValidatorVerificationInput,
    policy: CheckpointTrustPolicy,
    public_keys: dict[str, bytes],
) -> tuple[list[str], list[Role]]:
    checkpoint = value.checkpoint
    message = checkpoint_signature_message(checkpoint)
    message_digest = hashlib.sha256(message).hexdigest()
    trusted = {item.key_id: item for item in policy.trusted_keys}
    verified_ids: list[str] = []
    verified_roles: set[Role] = set()
    for envelope in value.signatures:
        key = trusted.get(envelope.signer_key_id)
        if key is None:
            _reject("signer_untrusted")
        if CHECKPOINT_PURPOSE not in key.purposes:
            _reject("signer_purpose_mismatch")
        if (
            envelope.checkpoint_digest_sha256 != checkpoint.checkpoint_digest_sha256
            or envelope.signed_message_digest_sha256 != message_digest
        ):
            _reject("signature_binding_mismatch")
        if checkpoint.issued_at_epoch < key.valid_from_epoch:
            _reject("signer_not_yet_valid")
        if (
            checkpoint.expires_at_epoch > key.valid_until_epoch
            or value.evaluation_epoch >= key.valid_until_epoch
        ):
            _reject("signer_expired")
        if key.revoked_at_epoch is not None and key.revoked_at_epoch <= value.evaluation_epoch:
            _reject("signer_revoked")
        public_bytes = public_keys[key.key_id]
        signature_bytes = _decode_base64(envelope.signature_base64, expected_bytes=64)
        try:
            Ed25519PublicKey.from_public_bytes(public_bytes).verify(signature_bytes, message)
        except (InvalidSignature, ValueError):
            _reject("signature_invalid")
        verified_ids.append(key.key_id)
        verified_roles.update(key.roles)
    if len(verified_ids) < policy.threshold:
        _reject("threshold_not_met")
    if not set(policy.required_roles) <= verified_roles:
        _reject("required_role_missing")
    return sorted(verified_ids), sorted(verified_roles)


def advance_checkpoint_chain_state(
    state: CheckpointChainState,
    checkpoint: CentralScoreCheckpoint,
    policy: CheckpointTrustPolicy,
) -> CheckpointChainState:
    """Apply append-only non-equivocation rules and return the next sealed state."""

    state = _revalidate(state, CheckpointChainState)
    checkpoint = _revalidate(checkpoint, CentralScoreCheckpoint)
    policy = _revalidate(policy, CheckpointTrustPolicy)
    if (
        state.network != checkpoint.network
        or state.netuid != checkpoint.netuid
        or state.central_authority_fingerprint_sha256
        != checkpoint.central_authority_fingerprint_sha256
    ):
        _reject("authority_mismatch")
    if (
        state.central_scoring_policy_digest_sha256
        != checkpoint.central_scoring_policy_digest_sha256
    ):
        _reject("policy_mismatch")
    if state.trust_policy_digest_sha256 != checkpoint.trust_policy_digest_sha256:
        _reject("trust_policy_mismatch")
    if state.accepted_checkpoint_count == 0:
        if checkpoint.sequence != 1:
            _reject("sequence_gap")
        if checkpoint.previous_checkpoint_digest_sha256 is not None:
            _reject("previous_link_mismatch")
    else:
        if checkpoint.sequence == state.last_sequence:
            if checkpoint.checkpoint_digest_sha256 == state.last_checkpoint_digest_sha256:
                _reject("checkpoint_replay")
            if checkpoint.finalized_height == state.last_finalized_height:
                if checkpoint.finalized_block_hash != state.last_finalized_block_hash:
                    _reject("same_height_fork")
                if (
                    checkpoint.finalized_epoch != state.last_finalized_epoch
                    or checkpoint.input_snapshot_digest_sha256
                    != state.last_input_snapshot_digest_sha256
                    or checkpoint.canonical_score_report_digest_sha256
                    != state.last_canonical_score_report_digest_sha256
                    or checkpoint.report_score_vector_digest_sha256
                    != state.last_report_score_vector_digest_sha256
                    or checkpoint.score_vector_digest_sha256
                    != state.last_score_vector_digest_sha256
                ):
                    _reject("same_height_divergence")
            _reject("sequence_rollback")
        if checkpoint.sequence < state.last_sequence:
            _reject("sequence_rollback")
        if checkpoint.sequence - state.last_sequence > policy.max_sequence_gap:
            _reject("sequence_gap")
        if checkpoint.previous_checkpoint_digest_sha256 != state.last_checkpoint_digest_sha256:
            _reject("previous_link_mismatch")
        last_height = cast(int, state.last_finalized_height)
        last_epoch = cast(int, state.last_finalized_epoch)
        last_issued = cast(int, state.last_issued_at_epoch)
        last_evaluation = cast(int, state.last_evaluation_epoch)
        if checkpoint.finalized_height < last_height:
            _reject("finalized_height_rollback")
        if checkpoint.finalized_epoch < last_epoch:
            _reject("finalized_epoch_rollback")
        if checkpoint.finalized_height - last_height > policy.max_finalized_height_gap:
            _reject("finalized_height_gap")
        if (
            checkpoint.issued_at_epoch < last_issued
            or checkpoint.evaluation_epoch < last_evaluation
        ):
            _reject("sequence_rollback")
        if checkpoint.finalized_height == last_height:
            if checkpoint.finalized_block_hash != state.last_finalized_block_hash:
                _reject("same_height_fork")
            if (
                checkpoint.finalized_epoch != state.last_finalized_epoch
                or checkpoint.input_snapshot_digest_sha256
                != state.last_input_snapshot_digest_sha256
                or checkpoint.canonical_score_report_digest_sha256
                != state.last_canonical_score_report_digest_sha256
                or checkpoint.report_score_vector_digest_sha256
                != state.last_report_score_vector_digest_sha256
                or checkpoint.score_vector_digest_sha256 != state.last_score_vector_digest_sha256
            ):
                _reject("same_height_divergence")
    unsigned: dict[str, object] = {
        "schema": CHAIN_STATE_SCHEMA,
        "schema_version": CHECKPOINT_SCHEMA_VERSION,
        "purpose": CHECKPOINT_PURPOSE,
        "network": state.network,
        "netuid": state.netuid,
        "central_authority_fingerprint_sha256": (state.central_authority_fingerprint_sha256),
        "central_scoring_policy_digest_sha256": (state.central_scoring_policy_digest_sha256),
        "trust_policy_digest_sha256": state.trust_policy_digest_sha256,
        "accepted_checkpoint_count": state.accepted_checkpoint_count + 1,
        "last_sequence": checkpoint.sequence,
        "last_finalized_height": checkpoint.finalized_height,
        "last_finalized_block_hash": checkpoint.finalized_block_hash,
        "last_finalized_epoch": checkpoint.finalized_epoch,
        "last_issued_at_epoch": checkpoint.issued_at_epoch,
        "last_evaluation_epoch": checkpoint.evaluation_epoch,
        "last_input_snapshot_digest_sha256": checkpoint.input_snapshot_digest_sha256,
        "last_canonical_score_report_digest_sha256": (
            checkpoint.canonical_score_report_digest_sha256
        ),
        "last_report_score_vector_digest_sha256": (checkpoint.report_score_vector_digest_sha256),
        "last_score_vector_digest_sha256": checkpoint.score_vector_digest_sha256,
        "last_checkpoint_digest_sha256": checkpoint.checkpoint_digest_sha256,
    }
    return CheckpointChainState.model_validate(
        {**unsigned, "state_digest_sha256": _digest(unsigned)}
    )


def _verify_metagraph_binding(value: ExternalValidatorVerificationInput) -> None:
    checkpoint = value.checkpoint
    metagraph = value.finalized_metagraph
    if value.validator != metagraph.validator:
        _reject("validator_identity_mismatch")
    if (
        metagraph.network != checkpoint.network
        or metagraph.netuid != checkpoint.netuid
        or metagraph.finalized_height != checkpoint.finalized_height
        or metagraph.finalized_block_hash != checkpoint.finalized_block_hash
        or metagraph.finalized_epoch != checkpoint.finalized_epoch
    ):
        _reject("metagraph_binding_mismatch")
    score_keys = [(item.miner_uid, item.miner_hotkey) for item in checkpoint.score_vector]
    mapping_keys = [(item.uid, item.hotkey) for item in metagraph.miner_mappings]
    if len(score_keys) != len(mapping_keys) or {uid for uid, _ in score_keys} != {
        uid for uid, _ in mapping_keys
    }:
        _reject("metagraph_coverage_mismatch")
    if score_keys != mapping_keys:
        _reject("metagraph_mapping_mismatch")


def _normalize_score_vector(
    score_vector: Sequence[CheckpointScoreEntry],
) -> list[RelayWeightEntry]:
    positive = [item for item in score_vector if item.canonical_score_ppm > 0]
    total = sum(item.canonical_score_ppm for item in positive)
    if total <= 0:
        _reject("normalization_empty")
    floors: dict[tuple[int, str], int] = {}
    remainders: list[tuple[int, int, str]] = []
    allocated = 0
    for item in positive:
        numerator = item.canonical_score_ppm * WEIGHT_U16_TOTAL
        quotient, remainder = divmod(numerator, total)
        key = (item.miner_uid, item.miner_hotkey)
        floors[key] = quotient
        remainders.append((remainder, item.miner_uid, item.miner_hotkey))
        allocated += quotient
    remaining = WEIGHT_U16_TOTAL - allocated
    for _, uid, hotkey in sorted(remainders, key=lambda item: (-item[0], item[1], item[2]))[
        :remaining
    ]:
        floors[(uid, hotkey)] += 1
    return [
        RelayWeightEntry(
            miner_uid=item.miner_uid,
            miner_hotkey=item.miner_hotkey,
            source_eligibility_status=item.eligibility_status,
            source_canonical_score_ppm=item.canonical_score_ppm,
            weight_u16=floors.get((item.miner_uid, item.miner_hotkey), 0),
        )
        for item in score_vector
    ]


def verify_checkpoint_and_build_relay(
    verification_input: ExternalValidatorVerificationInput,
    approved_trust_policy: CheckpointTrustPolicy,
) -> RelayVerificationResult:
    """Verify one dependency-only checkpoint and derive an inert integer plan."""

    trusted_public_keys = _trusted_public_keys(approved_trust_policy)
    value = _revalidate(verification_input, ExternalValidatorVerificationInput)
    policy = _revalidate(approved_trust_policy, CheckpointTrustPolicy)
    _verify_trust_and_freshness(value, policy)
    _verify_report_binding(value)
    signer_ids, roles = _verify_signatures(value, policy, trusted_public_keys)
    next_state = advance_checkpoint_chain_state(value.prior_chain_state, value.checkpoint, policy)
    _verify_metagraph_binding(value)
    weights = _normalize_score_vector(value.checkpoint.score_vector)
    weight_documents = [_model_document(item) for item in weights]
    weight_digest = _digest(weight_documents)
    validator = value.validator
    report_unsigned: dict[str, object] = {
        "schema": VERIFICATION_REPORT_SCHEMA,
        "schema_version": CHECKPOINT_SCHEMA_VERSION,
        "purpose": VERIFICATION_PURPOSE,
        "status": "verified",
        "reason_codes": ["checkpoint_verified"],
        "evaluation_epoch": value.evaluation_epoch,
        "validator_uid": validator.uid,
        "validator_hotkey": validator.hotkey,
        "checkpoint_digest_sha256": value.checkpoint.checkpoint_digest_sha256,
        "canonical_score_report_digest_sha256": (
            value.checkpoint.canonical_score_report_digest_sha256
        ),
        "input_snapshot_digest_sha256": value.checkpoint.input_snapshot_digest_sha256,
        "score_vector_digest_sha256": value.checkpoint.score_vector_digest_sha256,
        "metagraph_snapshot_digest_sha256": (
            value.finalized_metagraph.metagraph_snapshot_digest_sha256
        ),
        "trust_policy_digest_sha256": policy.trust_policy_digest_sha256,
        "verification_input_digest_sha256": value.input_digest_sha256,
        "prior_chain_state_digest_sha256": value.prior_chain_state.state_digest_sha256,
        "next_chain_state_digest_sha256": next_state.state_digest_sha256,
        "verified_signer_key_ids": signer_ids,
        "verified_roles": roles,
        "normalization_algorithm": NORMALIZATION_ALGORITHM,
        "normalized_weight_vector_digest_sha256": weight_digest,
    }
    verification_report = ExternalValidatorVerificationReport.model_validate(
        {**report_unsigned, "report_digest_sha256": _digest(report_unsigned)}
    )
    plan_unsigned: dict[str, object] = {
        "schema": RELAY_PLAN_SCHEMA,
        "schema_version": CHECKPOINT_SCHEMA_VERSION,
        "purpose": RELAY_PURPOSE,
        "network": value.checkpoint.network,
        "netuid": value.checkpoint.netuid,
        "validator_uid": validator.uid,
        "validator_hotkey": validator.hotkey,
        "finalized_height": value.checkpoint.finalized_height,
        "finalized_block_hash": value.checkpoint.finalized_block_hash,
        "finalized_epoch": value.checkpoint.finalized_epoch,
        "expires_at_epoch": value.checkpoint.expires_at_epoch,
        "checkpoint_digest_sha256": value.checkpoint.checkpoint_digest_sha256,
        "canonical_score_report_digest_sha256": (
            value.checkpoint.canonical_score_report_digest_sha256
        ),
        "input_snapshot_digest_sha256": value.checkpoint.input_snapshot_digest_sha256,
        "score_vector_digest_sha256": value.checkpoint.score_vector_digest_sha256,
        "metagraph_snapshot_digest_sha256": (
            value.finalized_metagraph.metagraph_snapshot_digest_sha256
        ),
        "verification_input_digest_sha256": value.input_digest_sha256,
        "verification_report_digest_sha256": verification_report.report_digest_sha256,
        "next_chain_state_digest_sha256": next_state.state_digest_sha256,
        "weight_domain": WEIGHT_DOMAIN,
        "normalization_algorithm": NORMALIZATION_ALGORITHM,
        "weight_total_u16": WEIGHT_U16_TOTAL,
        "weights": weight_documents,
        "weight_vector_digest_sha256": weight_digest,
    }
    relay_plan = ExternalValidatorRelayPlan.model_validate(
        {**plan_unsigned, "plan_digest_sha256": _digest(plan_unsigned)}
    )
    return RelayVerificationResult(
        verification_report=verification_report,
        relay_plan=relay_plan,
        next_chain_state=next_state,
    )


def _model_bytes[ModelT: BaseModel](value: ModelT, model_type: type[ModelT]) -> bytes:
    value = _revalidate(value, model_type)
    return _canonical_json(_model_document(value)) + b"\n"


def central_score_checkpoint_bytes(value: CentralScoreCheckpoint) -> bytes:
    return _model_bytes(value, CentralScoreCheckpoint)


def checkpoint_trust_policy_bytes(value: CheckpointTrustPolicy) -> bytes:
    return _model_bytes(value, CheckpointTrustPolicy)


def checkpoint_signature_envelope_bytes(value: CheckpointSignatureEnvelope) -> bytes:
    return _model_bytes(value, CheckpointSignatureEnvelope)


def checkpoint_chain_state_bytes(value: CheckpointChainState) -> bytes:
    return _model_bytes(value, CheckpointChainState)


def relay_finalized_metagraph_snapshot_bytes(
    value: RelayFinalizedMetagraphSnapshot,
) -> bytes:
    return _model_bytes(value, RelayFinalizedMetagraphSnapshot)


def external_validator_verification_input_bytes(
    value: ExternalValidatorVerificationInput,
) -> bytes:
    return _model_bytes(value, ExternalValidatorVerificationInput)


def external_validator_verification_report_bytes(
    value: ExternalValidatorVerificationReport,
) -> bytes:
    return _model_bytes(value, ExternalValidatorVerificationReport)


def external_validator_relay_plan_bytes(value: ExternalValidatorRelayPlan) -> bytes:
    return _model_bytes(value, ExternalValidatorRelayPlan)


def _reject_nonstandard_constant(value: str) -> NoReturn:
    raise ValueError(f"nonstandard_json_constant:{value}")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate_json_key")
        value[key] = item
    return value


def _parse_model[ModelT: BaseModel](
    rendered: bytes,
    model_type: type[ModelT],
    canonicalizer: Callable[[ModelT], bytes],
    *,
    maximum_bytes: int = MAX_DOCUMENT_BYTES,
) -> ModelT:
    if not rendered or len(rendered) > maximum_bytes:
        raise ValueError("document_size_invalid")
    try:
        document = json.loads(
            rendered.decode("ascii"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_nonstandard_constant,
        )
        model = model_type.model_validate(document)
    except (UnicodeDecodeError, ValueError, TypeError, RecursionError) as exc:
        raise ValueError("document_invalid") from exc
    if rendered != canonicalizer(model):
        raise ValueError("document_not_canonical")
    return model


def parse_central_score_checkpoint(rendered: bytes) -> CentralScoreCheckpoint:
    return _parse_model(rendered, CentralScoreCheckpoint, central_score_checkpoint_bytes)


def parse_checkpoint_trust_policy(rendered: bytes) -> CheckpointTrustPolicy:
    return _parse_model(rendered, CheckpointTrustPolicy, checkpoint_trust_policy_bytes)


def parse_checkpoint_signature_envelope(rendered: bytes) -> CheckpointSignatureEnvelope:
    return _parse_model(
        rendered,
        CheckpointSignatureEnvelope,
        checkpoint_signature_envelope_bytes,
        maximum_bytes=16 * 1_024,
    )


def parse_checkpoint_chain_state(rendered: bytes) -> CheckpointChainState:
    return _parse_model(
        rendered,
        CheckpointChainState,
        checkpoint_chain_state_bytes,
        maximum_bytes=64 * 1_024,
    )


def parse_relay_finalized_metagraph_snapshot(
    rendered: bytes,
) -> RelayFinalizedMetagraphSnapshot:
    return _parse_model(
        rendered,
        RelayFinalizedMetagraphSnapshot,
        relay_finalized_metagraph_snapshot_bytes,
    )


def parse_external_validator_verification_input(
    rendered: bytes,
) -> ExternalValidatorVerificationInput:
    return _parse_model(
        rendered,
        ExternalValidatorVerificationInput,
        external_validator_verification_input_bytes,
    )


def parse_external_validator_verification_report(
    rendered: bytes,
) -> ExternalValidatorVerificationReport:
    return _parse_model(
        rendered,
        ExternalValidatorVerificationReport,
        external_validator_verification_report_bytes,
    )


def parse_external_validator_relay_plan(rendered: bytes) -> ExternalValidatorRelayPlan:
    return _parse_model(
        rendered,
        ExternalValidatorRelayPlan,
        external_validator_relay_plan_bytes,
    )
