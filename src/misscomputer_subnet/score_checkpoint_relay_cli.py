# SPDX-License-Identifier: AGPL-3.0-only
"""Offline signed-checkpoint loading, durable acceptance, and relay preparation.

This module is intentionally a local-filesystem boundary.  It accepts only
explicit canonical files and out-of-band digests, verifies them through the
pure :mod:`score_checkpoint_relay` core, advances one locked append-only local
ledger, and creates inert output files.  It has no clock, environment,
network, subprocess, credential, signing, wallet, chain-client, submission,
cloud, DNS, provisioning, service, or activation capability.
"""

from __future__ import annotations

import argparse
import ctypes
import errno
import fcntl
import hashlib
import json
import os
import stat
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Annotated, Final, Literal, NoReturn, Self, cast

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationError,
    model_validator,
)

from .checkpoint_score_contracts import CanonicalScoreReport, parse_canonical_score_report
from .production_release_verifier import (
    HardenedFileSet,
    ReleaseVerificationError,
)
from .score_checkpoint_relay import (
    MAX_DOCUMENT_BYTES,
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
    RelayFinalizedMetagraphSnapshot,
    RelayVerificationResult,
    advance_checkpoint_chain_state,
    build_external_validator_verification_input,
    build_initial_checkpoint_chain_state,
    external_validator_relay_plan_bytes,
    external_validator_verification_report_bytes,
    parse_central_score_checkpoint,
    parse_checkpoint_signature_envelope,
    parse_checkpoint_trust_policy,
    parse_relay_finalized_metagraph_snapshot,
    verify_checkpoint_and_build_relay,
)
from .weight_plan import (
    WEIGHT_PLAN_PROTOCOL_VERSION_KEY,
    WeightPlan,
    WeightPlanEntry,
    WeightPlanError,
    WeightPlanSnapshot,
)

LEDGER_RECORD_SCHEMA: Final = "miss.computer/misscomputer-subnet/score-checkpoint-ledger-record"
LEDGER_POINTER_SCHEMA: Final = "miss.computer/misscomputer-subnet/score-checkpoint-ledger-pointer"
PREPARATION_SCHEMA: Final = (
    "miss.computer/misscomputer-subnet/external-validator-weight-plan-preparation"
)
LEDGER_PURPOSE: Final = "verified_score_checkpoint_append_only_ledger_v1"
PREPARATION_PURPOSE: Final = "verified_score_checkpoint_weight_plan_preparation_v1"
LEDGER_SCHEMA_VERSION: Final = 1
STATE_ROOT_MODE: Final = 0o700
STATE_FILE_MODE: Final = 0o600
MAX_LEDGER_RECORD_BYTES: Final = MAX_DOCUMENT_BYTES
MAX_LEDGER_POINTER_BYTES: Final = 256 * 1024
MAX_LEDGER_RECORDS: Final = 1_000_000
MAX_FORWARD_RECOVERY_RECORDS: Final = 1
READ_CHUNK_BYTES: Final = 1024 * 1024
LOCK_NAME: Final = "ledger.lock"
HEAD_NAME: Final = "head.json"
ANCHOR_NAME: Final = "anchor.json"
HEAD_INSTALL_NAME: Final = ".head.install"
ANCHOR_INSTALL_NAME: Final = ".anchor.install"
_AT_FDCWD: Final = -100
_AT_SYMLINK_FOLLOW: Final = 0x400
_AT_EMPTY_PATH: Final = 0x1000

EXIT_OK: Final = 0
EXIT_REJECTED: Final = 2
EXIT_USAGE: Final = 64
EXIT_BUSY: Final = 75
EXIT_INTERNAL: Final = 70

Digest = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
PositiveInteger = Annotated[int, Field(ge=1, le=(1 << 63) - 1)]
NonNegativeInteger = Annotated[int, Field(ge=0, le=(1 << 63) - 1)]


class CheckpointRelayCLIError(ValueError):
    """Stable failure code whose text never contains an input value or path."""

    def __init__(self, code: str) -> None:
        safe = (
            code
            if code
            and len(code) <= 64
            and code.isascii()
            and all(
                character.islower() or character.isdigit() or character == "_" for character in code
            )
            else "internal_error"
        )
        super().__init__(safe)
        self.code = safe


class _LocalModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, RecursionError) as exc:
        raise CheckpointRelayCLIError("document_invalid") from exc


def _digest_document(value: object) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _model_document(value: BaseModel, *, exclude: set[str] | None = None) -> dict[str, object]:
    return cast(
        dict[str, object],
        value.model_dump(mode="json", by_alias=True, exclude=exclude),
    )


def _model_bytes(value: BaseModel) -> bytes:
    return _canonical_json(_model_document(value)) + b"\n"


class CheckpointLedgerRecord(_LocalModel):
    contract_schema: Literal["miss.computer/misscomputer-subnet/score-checkpoint-ledger-record"] = (
        Field(alias="schema")
    )
    schema_version: Literal[1]
    purpose: Literal["verified_score_checkpoint_append_only_ledger_v1"]
    record_index: PositiveInteger
    prior_record_digest_sha256: Digest | None
    verification_input: ExternalValidatorVerificationInput
    verification_report: ExternalValidatorVerificationReport
    relay_plan: ExternalValidatorRelayPlan
    weight_plan: dict[str, object]
    weight_plan_digest_sha256: Digest
    record_digest_sha256: Digest

    @model_validator(mode="after")
    def canonical_record(self) -> Self:
        prior = self.verification_input.prior_chain_state
        if self.record_index != prior.accepted_checkpoint_count + 1:
            raise ValueError("ledger_record_index_invalid")
        if (self.record_index == 1) != (self.prior_record_digest_sha256 is None):
            raise ValueError("ledger_record_link_invalid")
        if self.weight_plan.get("digest_sha256") != self.weight_plan_digest_sha256:
            raise ValueError("ledger_weight_plan_digest_invalid")
        unsigned = _model_document(self, exclude={"record_digest_sha256"})
        if self.record_digest_sha256 != _digest_document(unsigned):
            raise ValueError("ledger_record_digest_invalid")
        return self


class CheckpointLedgerPointer(_LocalModel):
    contract_schema: Literal[
        "miss.computer/misscomputer-subnet/score-checkpoint-ledger-pointer"
    ] = Field(alias="schema")
    schema_version: Literal[1]
    purpose: Literal["verified_score_checkpoint_append_only_ledger_v1"]
    pointer_kind: Literal["anchor", "head"]
    network: Literal["finney"]
    netuid: Literal[24]
    central_authority_fingerprint_sha256: Digest
    central_scoring_policy_digest_sha256: Digest
    trust_policy_digest_sha256: Digest
    record_count: NonNegativeInteger
    last_record_digest_sha256: Digest | None
    chain_state: CheckpointChainState
    pointer_digest_sha256: Digest

    @model_validator(mode="after")
    def canonical_pointer(self) -> Self:
        if self.record_count != self.chain_state.accepted_checkpoint_count:
            raise ValueError("ledger_pointer_count_invalid")
        if (self.record_count == 0) != (self.last_record_digest_sha256 is None):
            raise ValueError("ledger_pointer_link_invalid")
        if (
            self.network != self.chain_state.network
            or self.netuid != self.chain_state.netuid
            or self.central_authority_fingerprint_sha256
            != self.chain_state.central_authority_fingerprint_sha256
            or self.central_scoring_policy_digest_sha256
            != self.chain_state.central_scoring_policy_digest_sha256
            or self.trust_policy_digest_sha256 != self.chain_state.trust_policy_digest_sha256
        ):
            raise ValueError("ledger_pointer_binding_invalid")
        unsigned = _model_document(self, exclude={"pointer_digest_sha256"})
        if self.pointer_digest_sha256 != _digest_document(unsigned):
            raise ValueError("ledger_pointer_digest_invalid")
        return self


class ExternalValidatorWeightPlanPreparation(_LocalModel):
    contract_schema: Literal[
        "miss.computer/misscomputer-subnet/external-validator-weight-plan-preparation"
    ] = Field(alias="schema")
    schema_version: Literal[1]
    purpose: Literal["verified_score_checkpoint_weight_plan_preparation_v1"]
    status: Literal["prepared_not_submitted"]
    submission_authorized: Literal[False]
    network: Literal["finney"]
    netuid: Literal[24]
    validator_uid: Annotated[int, Field(ge=0, le=WEIGHT_U16_TOTAL)]
    validator_hotkey: Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9]{1,128}$")]
    finalized_height: NonNegativeInteger
    finalized_block_hash: Digest
    finalized_epoch: NonNegativeInteger
    checkpoint_digest_sha256: Digest
    canonical_score_report_digest_sha256: Digest
    input_snapshot_digest_sha256: Digest
    central_scoring_policy_digest_sha256: Digest
    trust_policy_digest_sha256: Digest
    metagraph_snapshot_digest_sha256: Digest
    verification_input_digest_sha256: Digest
    verification_report_digest_sha256: Digest
    relay_plan_digest_sha256: Digest
    next_chain_state_digest_sha256: Digest
    ledger_record_index: PositiveInteger
    ledger_record_digest_sha256: Digest
    ledger_head_digest_sha256: Digest
    ledger_anchor_digest_sha256: Digest
    normalization_algorithm: Literal["largest_remainder_score_ppm_to_u16_v1"]
    normalized_weight_vector_digest_sha256: Digest
    weight_plan: dict[str, object]
    weight_plan_digest_sha256: Digest
    preparation_digest_sha256: Digest

    @model_validator(mode="after")
    def canonical_preparation(self) -> Self:
        if self.weight_plan.get("digest_sha256") != self.weight_plan_digest_sha256:
            raise ValueError("preparation_weight_plan_digest_invalid")
        unsigned = _model_document(self, exclude={"preparation_digest_sha256"})
        if self.preparation_digest_sha256 != _digest_document(unsigned):
            raise ValueError("preparation_digest_invalid")
        return self


@dataclass(frozen=True, slots=True)
class InputFile:
    path: str
    sha256: str


@dataclass(frozen=True, slots=True)
class CheckpointRelayInputFiles:
    trust_policy: InputFile
    checkpoint: InputFile
    signatures: tuple[InputFile, ...]
    canonical_score_report: InputFile
    finalized_metagraph: InputFile


@dataclass(frozen=True, slots=True)
class LoadedCheckpointRelayInputs:
    trust_policy: CheckpointTrustPolicy
    checkpoint: CentralScoreCheckpoint
    signatures: tuple[CheckpointSignatureEnvelope, ...]
    canonical_score_report: CanonicalScoreReport
    finalized_metagraph: RelayFinalizedMetagraphSnapshot


_INPUT_ERROR_MAP: Final[dict[str, str]] = {
    "closed_input": "input_file_unsafe",
    "duplicate_file": "input_file_alias",
    "input_changed": "input_changed",
    "input_read": "input_read_failed",
    "platform_boundary": "platform_unsupported",
    "sensitive_path": "input_path_sensitive",
    "size_limit": "input_size_invalid",
    "unsafe_file": "input_file_unsafe",
    "unsafe_file_metadata": "input_metadata_unsafe",
    "unsafe_path": "input_path_unsafe",
}


def _valid_digest(value: str) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _load_input_bytes(
    file_set: HardenedFileSet,
    value: InputFile,
    *,
    label: str,
    max_bytes: int,
) -> bytes:
    if not _valid_digest(value.sha256):
        raise CheckpointRelayCLIError("trusted_digest_invalid")
    try:
        with file_set.open(value.path, label=label) as source:
            rendered, observation = source.read_bytes(max_bytes=max_bytes)
    except ReleaseVerificationError as exc:
        raise CheckpointRelayCLIError(
            _INPUT_ERROR_MAP.get(exc.code, "input_file_rejected")
        ) from exc
    if observation.sha256 != value.sha256:
        raise CheckpointRelayCLIError("trusted_digest_mismatch")
    return rendered


def load_checkpoint_relay_inputs(
    files: CheckpointRelayInputFiles,
) -> LoadedCheckpointRelayInputs:
    """Load one bounded, inode-distinct, canonical checkpoint publication set."""

    if not 1 <= len(files.signatures) <= 16:
        raise CheckpointRelayCLIError("signature_count_invalid")
    file_set = HardenedFileSet()
    try:
        trust_policy = parse_checkpoint_trust_policy(
            _load_input_bytes(
                file_set,
                files.trust_policy,
                label="checkpoint_trust_policy",
                max_bytes=MAX_DOCUMENT_BYTES,
            )
        )
        checkpoint = parse_central_score_checkpoint(
            _load_input_bytes(
                file_set,
                files.checkpoint,
                label="central_score_checkpoint",
                max_bytes=MAX_DOCUMENT_BYTES,
            )
        )
        signatures = tuple(
            parse_checkpoint_signature_envelope(
                _load_input_bytes(
                    file_set,
                    item,
                    label=f"checkpoint_signature_{index:02d}",
                    max_bytes=16 * 1024,
                )
            )
            for index, item in enumerate(files.signatures)
        )
        score_report = parse_canonical_score_report(
            _load_input_bytes(
                file_set,
                files.canonical_score_report,
                label="canonical_score_report",
                max_bytes=MAX_DOCUMENT_BYTES,
            )
        )
        metagraph = parse_relay_finalized_metagraph_snapshot(
            _load_input_bytes(
                file_set,
                files.finalized_metagraph,
                label="relay_finalized_metagraph",
                max_bytes=MAX_DOCUMENT_BYTES,
            )
        )
    except CheckpointRelayCLIError:
        raise
    except (TypeError, ValueError, ValidationError, RecursionError) as exc:
        raise CheckpointRelayCLIError("input_contract_invalid") from exc
    signer_ids = [item.signer_key_id for item in signatures]
    if len(signer_ids) != len(set(signer_ids)):
        raise CheckpointRelayCLIError("signature_set_noncanonical")
    signatures = tuple(sorted(signatures, key=lambda item: item.signer_key_id))
    return LoadedCheckpointRelayInputs(
        trust_policy=trust_policy,
        checkpoint=checkpoint,
        signatures=signatures,
        canonical_score_report=score_report,
        finalized_metagraph=metagraph,
    )


def _weight_plan_from_document(document: object) -> WeightPlan:
    if not isinstance(document, Mapping):
        raise CheckpointRelayCLIError("weight_plan_invalid")
    expected = {
        "created_block",
        "digest_sha256",
        "expires_at_block",
        "netuid",
        "network",
        "schema",
        "schema_version",
        "snapshot",
        "validator_hotkey",
        "version_key",
        "weights",
    }
    if set(document) != expected:
        raise CheckpointRelayCLIError("weight_plan_invalid")
    snapshot_value = document.get("snapshot")
    weights_value = document.get("weights")
    if not isinstance(snapshot_value, Mapping) or set(snapshot_value) != {
        "block",
        "epoch",
        "finalized",
        "identity_fingerprint",
        "tempo",
    }:
        raise CheckpointRelayCLIError("weight_plan_invalid")
    if not isinstance(weights_value, list):
        raise CheckpointRelayCLIError("weight_plan_invalid")
    entries: list[WeightPlanEntry] = []
    for item in weights_value:
        if not isinstance(item, Mapping) or set(item) != {"hotkey", "uid", "weight"}:
            raise CheckpointRelayCLIError("weight_plan_invalid")
        entries.append(
            WeightPlanEntry(
                uid=cast(int, item["uid"]),
                hotkey=cast(str, item["hotkey"]),
                weight=cast(float, item["weight"]),
            )
        )
    try:
        plan = WeightPlan(
            network=cast(str, document["network"]),
            netuid=cast(int, document["netuid"]),
            validator_hotkey=cast(str, document["validator_hotkey"]),
            snapshot=WeightPlanSnapshot(
                block=cast(int, snapshot_value["block"]),
                tempo=cast(int, snapshot_value["tempo"]),
                epoch=cast(int, snapshot_value["epoch"]),
                finalized=cast(bool, snapshot_value["finalized"]),
                identity_fingerprint=cast(str, snapshot_value["identity_fingerprint"]),
            ),
            weights=tuple(entries),
            version_key=cast(int, document["version_key"]),
            created_block=cast(int, document["created_block"]),
            expires_at_block=cast(int, document["expires_at_block"]),
        )
    except (KeyError, TypeError, ValueError, WeightPlanError) as exc:
        raise CheckpointRelayCLIError("weight_plan_invalid") from exc
    if plan.document() != dict(document):
        raise CheckpointRelayCLIError("weight_plan_noncanonical")
    return plan


def build_bound_weight_plan(
    relay_plan: ExternalValidatorRelayPlan,
    trust_policy: CheckpointTrustPolicy,
    *,
    record_index: int,
    prior_record_digest_sha256: str | None,
    tempo: int,
    snapshot_identity_fingerprint_sha256: str,
) -> WeightPlan:
    """Project relay u16 values into a protocol-v2 WeightPlan without renormalizing.

    ``version_key`` identifies the supported weight protocol. Per-instance
    checkpoint, relay, ledger, validator, and metagraph identity remains bound
    by their canonical digests and the non-submission preparation manifest.
    """

    relay_plan = ExternalValidatorRelayPlan.model_validate(
        relay_plan.model_dump(mode="json", by_alias=True)
    )
    trust_policy = CheckpointTrustPolicy.model_validate(
        trust_policy.model_dump(mode="json", by_alias=True)
    )
    if (
        isinstance(tempo, bool)
        or not isinstance(tempo, int)
        or not 1 <= tempo <= (1 << 63) - 1
        or not _valid_digest(snapshot_identity_fingerprint_sha256)
        or isinstance(record_index, bool)
        or not 1 <= record_index <= MAX_LEDGER_RECORDS
        or (record_index == 1) != (prior_record_digest_sha256 is None)
        or (
            prior_record_digest_sha256 is not None and not _valid_digest(prior_record_digest_sha256)
        )
        or relay_plan.network != trust_policy.network
        or relay_plan.netuid != trust_policy.netuid
    ):
        raise CheckpointRelayCLIError("weight_plan_context_invalid")
    positive = [item for item in relay_plan.weights if item.weight_u16 > 0]
    if not positive or sum(item.weight_u16 for item in positive) != WEIGHT_U16_TOTAL:
        raise CheckpointRelayCLIError("weight_plan_vector_invalid")
    if any(
        item.source_eligibility_status != "eligible" or item.source_canonical_score_ppm <= 0
        for item in positive
    ):
        raise CheckpointRelayCLIError("weight_plan_vector_invalid")
    entries = tuple(
        WeightPlanEntry(
            uid=item.miner_uid,
            hotkey=item.miner_hotkey,
            weight=item.weight_u16 / WEIGHT_U16_TOTAL,
        )
        for item in positive
    )
    # A round trip proves that binary-float serialization did not select or
    # alter an integer allocation.  The authoritative allocation remains u16.
    if any(
        round(entry.weight * WEIGHT_U16_TOTAL) != source.weight_u16
        for entry, source in zip(entries, positive, strict=True)
    ):
        raise CheckpointRelayCLIError("weight_plan_conversion_invalid")
    block = relay_plan.finalized_height
    epoch = block // tempo
    next_epoch = (epoch + 1) * tempo
    expires_at_block = min(block + max(1, tempo // 4), next_epoch, (1 << 63) - 1)
    if expires_at_block <= block:
        raise CheckpointRelayCLIError("weight_plan_context_invalid")
    try:
        return WeightPlan(
            network=relay_plan.network,
            netuid=relay_plan.netuid,
            validator_hotkey=relay_plan.validator_hotkey,
            snapshot=WeightPlanSnapshot(
                block=block,
                tempo=tempo,
                epoch=epoch,
                finalized=True,
                identity_fingerprint=snapshot_identity_fingerprint_sha256,
            ),
            weights=entries,
            version_key=WEIGHT_PLAN_PROTOCOL_VERSION_KEY,
            created_block=block,
            expires_at_block=expires_at_block,
        )
    except WeightPlanError as exc:
        raise CheckpointRelayCLIError("weight_plan_invalid") from exc


def _build_ledger_record(
    verification_input: ExternalValidatorVerificationInput,
    result: RelayVerificationResult,
    weight_plan: WeightPlan,
    *,
    record_index: int,
    prior_record_digest_sha256: str | None,
) -> CheckpointLedgerRecord:
    unsigned: dict[str, object] = {
        "schema": LEDGER_RECORD_SCHEMA,
        "schema_version": LEDGER_SCHEMA_VERSION,
        "purpose": LEDGER_PURPOSE,
        "record_index": record_index,
        "prior_record_digest_sha256": prior_record_digest_sha256,
        "verification_input": _model_document(verification_input),
        "verification_report": _model_document(result.verification_report),
        "relay_plan": _model_document(result.relay_plan),
        "weight_plan": weight_plan.document(),
        "weight_plan_digest_sha256": weight_plan.digest_sha256,
    }
    try:
        return CheckpointLedgerRecord.model_validate(
            {**unsigned, "record_digest_sha256": _digest_document(unsigned)}
        )
    except ValidationError as exc:
        raise CheckpointRelayCLIError("ledger_record_invalid") from exc


def _build_pointer(
    kind: Literal["anchor", "head"],
    policy: CheckpointTrustPolicy,
    chain_state: CheckpointChainState,
    *,
    record_count: int,
    last_record_digest_sha256: str | None,
) -> CheckpointLedgerPointer:
    unsigned: dict[str, object] = {
        "schema": LEDGER_POINTER_SCHEMA,
        "schema_version": LEDGER_SCHEMA_VERSION,
        "purpose": LEDGER_PURPOSE,
        "pointer_kind": kind,
        "network": policy.network,
        "netuid": policy.netuid,
        "central_authority_fingerprint_sha256": (policy.central_authority_fingerprint_sha256),
        "central_scoring_policy_digest_sha256": (policy.central_scoring_policy_digest_sha256),
        "trust_policy_digest_sha256": policy.trust_policy_digest_sha256,
        "record_count": record_count,
        "last_record_digest_sha256": last_record_digest_sha256,
        "chain_state": _model_document(chain_state),
    }
    try:
        return CheckpointLedgerPointer.model_validate(
            {**unsigned, "pointer_digest_sha256": _digest_document(unsigned)}
        )
    except ValidationError as exc:
        raise CheckpointRelayCLIError("ledger_pointer_invalid") from exc


def build_weight_plan_preparation(
    record: CheckpointLedgerRecord,
    head: CheckpointLedgerPointer,
    anchor: CheckpointLedgerPointer,
) -> ExternalValidatorWeightPlanPreparation:
    """Bind a prepared WeightPlan to every verified and durable dependency."""

    value = record.verification_input
    report = record.verification_report
    relay = record.relay_plan
    if (
        head.pointer_kind != "head"
        or anchor.pointer_kind != "anchor"
        or head.record_count != record.record_index
        or anchor.record_count != record.record_index
        or head.last_record_digest_sha256 != record.record_digest_sha256
        or anchor.last_record_digest_sha256 != record.record_digest_sha256
    ):
        raise CheckpointRelayCLIError("ledger_pointer_invalid")
    unsigned: dict[str, object] = {
        "schema": PREPARATION_SCHEMA,
        "schema_version": LEDGER_SCHEMA_VERSION,
        "purpose": PREPARATION_PURPOSE,
        "status": "prepared_not_submitted",
        "submission_authorized": False,
        "network": relay.network,
        "netuid": relay.netuid,
        "validator_uid": relay.validator_uid,
        "validator_hotkey": relay.validator_hotkey,
        "finalized_height": relay.finalized_height,
        "finalized_block_hash": relay.finalized_block_hash,
        "finalized_epoch": relay.finalized_epoch,
        "checkpoint_digest_sha256": relay.checkpoint_digest_sha256,
        "canonical_score_report_digest_sha256": (relay.canonical_score_report_digest_sha256),
        "input_snapshot_digest_sha256": relay.input_snapshot_digest_sha256,
        "central_scoring_policy_digest_sha256": (
            value.checkpoint.central_scoring_policy_digest_sha256
        ),
        "trust_policy_digest_sha256": value.trust_policy_digest_sha256,
        "metagraph_snapshot_digest_sha256": relay.metagraph_snapshot_digest_sha256,
        "verification_input_digest_sha256": relay.verification_input_digest_sha256,
        "verification_report_digest_sha256": report.report_digest_sha256,
        "relay_plan_digest_sha256": relay.plan_digest_sha256,
        "next_chain_state_digest_sha256": relay.next_chain_state_digest_sha256,
        "ledger_record_index": record.record_index,
        "ledger_record_digest_sha256": record.record_digest_sha256,
        "ledger_head_digest_sha256": head.pointer_digest_sha256,
        "ledger_anchor_digest_sha256": anchor.pointer_digest_sha256,
        "normalization_algorithm": relay.normalization_algorithm,
        "normalized_weight_vector_digest_sha256": relay.weight_vector_digest_sha256,
        "weight_plan": record.weight_plan,
        "weight_plan_digest_sha256": record.weight_plan_digest_sha256,
    }
    try:
        return ExternalValidatorWeightPlanPreparation.model_validate(
            {**unsigned, "preparation_digest_sha256": _digest_document(unsigned)}
        )
    except ValidationError as exc:
        raise CheckpointRelayCLIError("preparation_invalid") from exc


def checkpoint_ledger_record_bytes(value: CheckpointLedgerRecord) -> bytes:
    return _model_bytes(CheckpointLedgerRecord.model_validate(_model_document(value)))


def checkpoint_ledger_pointer_bytes(value: CheckpointLedgerPointer) -> bytes:
    return _model_bytes(CheckpointLedgerPointer.model_validate(_model_document(value)))


def weight_plan_preparation_bytes(value: ExternalValidatorWeightPlanPreparation) -> bytes:
    return _model_bytes(
        ExternalValidatorWeightPlanPreparation.model_validate(_model_document(value))
    )


def _reject_json_constant(value: str) -> NoReturn:
    del value
    raise ValueError("json_constant")


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("json_duplicate")
        value[key] = item
    return value


def _parse_local_model[ModelT: BaseModel](
    rendered: bytes,
    model: type[ModelT],
    *,
    maximum_bytes: int,
) -> ModelT:
    if not rendered or len(rendered) > maximum_bytes:
        raise CheckpointRelayCLIError("ledger_document_size_invalid")
    try:
        document = json.loads(
            rendered.decode("ascii"),
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
        value = model.model_validate(document)
    except (UnicodeDecodeError, ValueError, TypeError, RecursionError, ValidationError) as exc:
        raise CheckpointRelayCLIError("ledger_document_invalid") from exc
    if rendered != _model_bytes(value):
        raise CheckpointRelayCLIError("ledger_document_noncanonical")
    return value


def parse_checkpoint_ledger_record(rendered: bytes) -> CheckpointLedgerRecord:
    return _parse_local_model(
        rendered,
        CheckpointLedgerRecord,
        maximum_bytes=MAX_LEDGER_RECORD_BYTES,
    )


def parse_checkpoint_ledger_pointer(rendered: bytes) -> CheckpointLedgerPointer:
    return _parse_local_model(
        rendered,
        CheckpointLedgerPointer,
        maximum_bytes=MAX_LEDGER_POINTER_BYTES,
    )


@dataclass(slots=True)
class _PinnedDirectoryChain:
    absolute_path: str
    components: tuple[str, ...]
    descriptors: list[int]
    identities: tuple[tuple[int, int], ...]
    state_root: bool

    @property
    def directory_fd(self) -> int:
        return self.descriptors[-1]

    def close(self) -> None:
        while self.descriptors:
            descriptor = self.descriptors.pop()
            try:
                os.close(descriptor)
            except OSError:
                pass


def _normalized_absolute_path(path: str, *, code: str) -> str:
    sensitive = {
        ".env",
        ".ssh",
        "credential",
        "credentials",
        "private-key",
        "private_key",
        "secret",
        "secrets",
        "wallet",
        "wallets",
    }
    if (
        not isinstance(path, str)
        or not path
        or "\x00" in path
        or not path.startswith("/")
        or path.startswith("//")
        or path != os.path.normpath(path)
    ):
        raise CheckpointRelayCLIError(code)
    components = path.split("/")[1:]
    if not components or any(
        not component
        or component.casefold() in sensitive
        or component.casefold().endswith((".key", ".p12", ".pem", ".pfx"))
        for component in components
    ):
        raise CheckpointRelayCLIError(code)
    return path


def _directory_flags() -> int:
    required = ("O_CLOEXEC", "O_DIRECTORY", "O_NOFOLLOW", "O_TMPFILE")
    if any(not hasattr(os, item) for item in required) or os.open not in os.supports_dir_fd:
        raise CheckpointRelayCLIError("platform_unsupported")
    return os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW


def _effective_uid() -> int:
    return os.geteuid() if hasattr(os, "geteuid") else os.getuid()


def _validate_directory_metadata(
    value: os.stat_result,
    *,
    final: bool,
    state_root: bool,
) -> None:
    if not stat.S_ISDIR(value.st_mode):
        raise CheckpointRelayCLIError("directory_unsafe")
    if state_root and final:
        if value.st_uid != _effective_uid() or stat.S_IMODE(value.st_mode) != STATE_ROOT_MODE:
            raise CheckpointRelayCLIError("ledger_root_unsafe")
        return
    if value.st_uid not in {0, _effective_uid()}:
        raise CheckpointRelayCLIError("directory_unsafe")
    unsafe = stat.S_IMODE(value.st_mode) & 0o022
    sticky_ancestor = bool(value.st_mode & stat.S_ISVTX) and not final
    if unsafe and not sticky_ancestor:
        raise CheckpointRelayCLIError("directory_unsafe")


def _pin_directory(path: str, *, state_root: bool) -> _PinnedDirectoryChain:
    absolute = _normalized_absolute_path(path, code="directory_path_unsafe")
    components = tuple(item for item in absolute.split("/") if item)
    descriptors: list[int] = []
    identities: list[tuple[int, int]] = []
    flags = _directory_flags()
    try:
        descriptor = os.open("/", flags)
        descriptors.append(descriptor)
        metadata = os.fstat(descriptor)
        _validate_directory_metadata(
            metadata,
            final=not components,
            state_root=state_root,
        )
        identities.append((metadata.st_dev, metadata.st_ino))
        for index, component in enumerate(components):
            descriptor = os.open(component, flags, dir_fd=descriptors[-1])
            descriptors.append(descriptor)
            metadata = os.fstat(descriptor)
            final = index == len(components) - 1
            _validate_directory_metadata(
                metadata,
                final=final,
                state_root=state_root,
            )
            identities.append((metadata.st_dev, metadata.st_ino))
        return _PinnedDirectoryChain(
            absolute_path=absolute,
            components=components,
            descriptors=descriptors,
            identities=tuple(identities),
            state_root=state_root,
        )
    except CheckpointRelayCLIError:
        while descriptors:
            os.close(descriptors.pop())
        raise
    except OSError as exc:
        while descriptors:
            os.close(descriptors.pop())
        raise CheckpointRelayCLIError("directory_unsafe") from exc


def _revalidate_chain(chain: _PinnedDirectoryChain) -> None:
    try:
        for index, descriptor in enumerate(chain.descriptors):
            metadata = os.fstat(descriptor)
            _validate_directory_metadata(
                metadata,
                final=index == len(chain.descriptors) - 1,
                state_root=chain.state_root,
            )
            if (metadata.st_dev, metadata.st_ino) != chain.identities[index]:
                raise CheckpointRelayCLIError("directory_changed")
        reopened = _pin_directory(chain.absolute_path, state_root=chain.state_root)
        try:
            if reopened.identities != chain.identities:
                raise CheckpointRelayCLIError("directory_changed")
        finally:
            reopened.close()
    except OSError as exc:
        raise CheckpointRelayCLIError("directory_changed") from exc


def _open_or_create_state_root(path: str) -> _PinnedDirectoryChain:
    absolute = _normalized_absolute_path(path, code="ledger_root_path_unsafe")
    parent_path, name = absolute.rsplit("/", 1)
    parent_path = parent_path or "/"
    parent = _pin_directory(parent_path, state_root=False)
    try:
        _revalidate_chain(parent)
        try:
            os.mkdir(name, STATE_ROOT_MODE, dir_fd=parent.directory_fd)
            os.fsync(parent.directory_fd)
        except FileExistsError:
            pass
        chain = _pin_directory(absolute, state_root=True)
        mapped = os.stat(name, dir_fd=parent.directory_fd, follow_symlinks=False)
        opened = os.fstat(chain.directory_fd)
        if (mapped.st_dev, mapped.st_ino) != (opened.st_dev, opened.st_ino):
            chain.close()
            raise CheckpointRelayCLIError("ledger_root_changed")
        return chain
    except CheckpointRelayCLIError:
        raise
    except OSError as exc:
        raise CheckpointRelayCLIError("ledger_root_unsafe") from exc
    finally:
        parent.close()


def _metadata_fingerprint(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_uid,
        value.st_gid,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _validate_state_file(value: os.stat_result, *, maximum_bytes: int, empty: bool) -> None:
    if (
        not stat.S_ISREG(value.st_mode)
        or value.st_uid != _effective_uid()
        or stat.S_IMODE(value.st_mode) != STATE_FILE_MODE
        or value.st_nlink != 1
        or value.st_size > maximum_bytes
        or (not empty and value.st_size == 0)
        or (empty and value.st_size != 0)
    ):
        raise CheckpointRelayCLIError("ledger_file_unsafe")


def _read_descriptor_twice(descriptor: int, *, maximum_bytes: int) -> bytes:
    observations: list[tuple[bytes, str]] = []
    for _ in range(2):
        try:
            os.lseek(descriptor, 0, os.SEEK_SET)
            chunks: list[bytes] = []
            remaining = maximum_bytes
            digest = hashlib.sha256()
            while remaining:
                chunk = os.read(descriptor, min(remaining, READ_CHUNK_BYTES))
                if not chunk:
                    break
                chunks.append(chunk)
                digest.update(chunk)
                remaining -= len(chunk)
            if remaining == 0 and os.read(descriptor, 1):
                raise CheckpointRelayCLIError("ledger_document_size_invalid")
            observations.append((b"".join(chunks), digest.hexdigest()))
        except OSError as exc:
            raise CheckpointRelayCLIError("ledger_read_failed") from exc
    if observations[0] != observations[1]:
        raise CheckpointRelayCLIError("ledger_file_changed")
    return observations[0][0]


def _read_state_file(directory_fd: int, name: str, *, maximum_bytes: int) -> bytes:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        _validate_state_file(before, maximum_bytes=maximum_bytes, empty=False)
        descriptor = os.open(name, flags, dir_fd=directory_fd)
        try:
            opened = os.fstat(descriptor)
            _validate_state_file(opened, maximum_bytes=maximum_bytes, empty=False)
            if _metadata_fingerprint(opened) != _metadata_fingerprint(before):
                raise CheckpointRelayCLIError("ledger_file_changed")
            rendered = _read_descriptor_twice(descriptor, maximum_bytes=maximum_bytes)
            after = os.fstat(descriptor)
            mapped = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if (
                _metadata_fingerprint(after) != _metadata_fingerprint(before)
                or _metadata_fingerprint(mapped) != _metadata_fingerprint(before)
                or len(rendered) != before.st_size
            ):
                raise CheckpointRelayCLIError("ledger_file_changed")
            return rendered
        finally:
            os.close(descriptor)
    except CheckpointRelayCLIError:
        raise
    except OSError as exc:
        raise CheckpointRelayCLIError("ledger_file_unsafe") from exc


def _write_all(descriptor: int, rendered: bytes) -> None:
    offset = 0
    view = memoryview(rendered)
    while offset < len(view):
        written = os.write(descriptor, view[offset:])
        if written <= 0:
            raise OSError("short_write")
        offset += written


def _open_unnamed_file(directory_fd: int) -> int:
    try:
        return os.open(
            ".",
            os.O_RDWR | os.O_TMPFILE | os.O_CLOEXEC,
            STATE_FILE_MODE,
            dir_fd=directory_fd,
        )
    except OSError as exc:
        if exc.errno in {
            errno.EINVAL,
            errno.EISDIR,
            errno.ENOSYS,
            errno.EOPNOTSUPP,
            errno.EPERM,
        }:
            raise CheckpointRelayCLIError("platform_unsupported") from exc
        raise CheckpointRelayCLIError("file_create_failed") from exc


def _linkat(olddirfd: int, oldpath: bytes, newdirfd: int, newpath: bytes, flags: int) -> int:
    """Return ``0`` or the ``errno`` reported by ``linkat(2)`` through the libc seam."""

    library = ctypes.CDLL(None, use_errno=True)
    result = library.linkat(
        olddirfd,
        ctypes.c_char_p(oldpath),
        newdirfd,
        ctypes.c_char_p(newpath),
        flags,
    )
    if result == 0:
        return 0
    return ctypes.get_errno() or errno.EIO


def _link_unnamed_file(descriptor: int, directory_fd: int, name: str) -> None:
    """Give the pinned unnamed ``descriptor`` exactly one name inside ``directory_fd``.

    ``linkat(AT_EMPTY_PATH)`` requires ``CAP_DAC_READ_SEARCH`` on Linux kernels
    before 6.10, which the dedicated unprivileged operator accounts never hold
    and which those kernels report as ``ENOENT``.  Retry through the
    ``/proc/self/fd`` form documented for ``O_TMPFILE``: both name the same
    inode, and every caller re-identifies the installed name by device and
    inode afterwards.
    """

    encoded = os.fsencode(name)
    error = _linkat(descriptor, b"", directory_fd, encoded, _AT_EMPTY_PATH)
    if error == errno.ENOENT:
        error = _linkat(
            _AT_FDCWD,
            f"/proc/self/fd/{descriptor}".encode("ascii"),
            directory_fd,
            encoded,
            _AT_SYMLINK_FOLLOW,
        )
    if error != 0:
        raise OSError(error, os.strerror(error))


def _prepare_unnamed_file(directory_fd: int, rendered: bytes) -> tuple[int, tuple[int, int]]:
    descriptor = _open_unnamed_file(directory_fd)
    try:
        os.fchmod(descriptor, STATE_FILE_MODE)
        _write_all(descriptor, rendered)
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != _effective_uid()
            or stat.S_IMODE(metadata.st_mode) != STATE_FILE_MODE
            or metadata.st_nlink != 0
            or metadata.st_size != len(rendered)
            or _read_descriptor_twice(descriptor, maximum_bytes=len(rendered) + 1) != rendered
        ):
            raise CheckpointRelayCLIError("file_create_failed")
        return descriptor, (metadata.st_dev, metadata.st_ino)
    except Exception:
        os.close(descriptor)
        raise


def _install_new_file(directory_fd: int, name: str, rendered: bytes) -> None:
    descriptor, identity = _prepare_unnamed_file(directory_fd, rendered)
    try:
        _link_unnamed_file(descriptor, directory_fd, name)
        mapped = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (mapped.st_dev, mapped.st_ino) != identity:
            raise CheckpointRelayCLIError("file_create_failed")
        _validate_state_file(mapped, maximum_bytes=len(rendered), empty=False)
        os.fsync(directory_fd)
    except FileExistsError as exc:
        raise CheckpointRelayCLIError("file_exists") from exc
    except CheckpointRelayCLIError:
        raise
    except OSError as exc:
        code = "file_exists" if exc.errno == errno.EEXIST else "file_create_failed"
        raise CheckpointRelayCLIError(code) from exc
    finally:
        os.close(descriptor)


def _replace_state_file(
    directory_fd: int,
    name: Literal["anchor.json", "head.json"],
    install_name: Literal[".anchor.install", ".head.install"],
    rendered: bytes,
) -> None:
    descriptor, identity = _prepare_unnamed_file(directory_fd, rendered)
    try:
        _link_unnamed_file(descriptor, directory_fd, install_name)
        staged = os.stat(install_name, dir_fd=directory_fd, follow_symlinks=False)
        if (staged.st_dev, staged.st_ino) != identity:
            raise CheckpointRelayCLIError("ledger_temp_invalid")
        _validate_state_file(staged, maximum_bytes=len(rendered), empty=False)
        os.replace(
            install_name,
            name,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
        )
        installed = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (installed.st_dev, installed.st_ino) != identity:
            raise CheckpointRelayCLIError("ledger_pointer_changed")
        os.fsync(directory_fd)
    except CheckpointRelayCLIError:
        raise
    except OSError as exc:
        code = "ledger_temp_residue" if exc.errno == errno.EEXIST else "ledger_write_failed"
        raise CheckpointRelayCLIError(code) from exc
    finally:
        os.close(descriptor)


def _record_name(index: int) -> str:
    if not 1 <= index <= MAX_LEDGER_RECORDS:
        raise CheckpointRelayCLIError("ledger_record_count_invalid")
    return f"record-{index:020d}.json"


def _validate_record_against_history(
    record: CheckpointLedgerRecord,
    policy: CheckpointTrustPolicy,
    *,
    expected_index: int,
    expected_prior_record_digest_sha256: str | None,
    expected_prior_state: CheckpointChainState,
) -> RelayVerificationResult:
    if (
        record.record_index != expected_index
        or record.prior_record_digest_sha256 != expected_prior_record_digest_sha256
        or record.verification_input.prior_chain_state != expected_prior_state
        or record.verification_input.trust_policy_digest_sha256 != policy.trust_policy_digest_sha256
    ):
        raise CheckpointRelayCLIError("ledger_chain_invalid")
    try:
        result = verify_checkpoint_and_build_relay(record.verification_input, policy)
    except (CheckpointRelayError, TypeError, ValueError, ValidationError) as exc:
        raise CheckpointRelayCLIError("ledger_record_unverified") from exc
    if (
        result.verification_report != record.verification_report
        or result.relay_plan != record.relay_plan
        or result.next_chain_state.state_digest_sha256
        != record.relay_plan.next_chain_state_digest_sha256
    ):
        raise CheckpointRelayCLIError("ledger_record_binding_invalid")
    plan = _weight_plan_from_document(record.weight_plan)
    expected_plan = build_bound_weight_plan(
        record.relay_plan,
        policy,
        record_index=record.record_index,
        prior_record_digest_sha256=record.prior_record_digest_sha256,
        tempo=plan.snapshot.tempo,
        snapshot_identity_fingerprint_sha256=plan.snapshot.identity_fingerprint,
    )
    if (
        plan.document() != expected_plan.document()
        or plan.digest_sha256 != record.weight_plan_digest_sha256
        or plan.network != record.relay_plan.network
        or plan.netuid != record.relay_plan.netuid
        or plan.validator_hotkey != record.relay_plan.validator_hotkey
        or plan.snapshot.block != record.relay_plan.finalized_height
    ):
        raise CheckpointRelayCLIError("ledger_weight_plan_invalid")
    relay_positive = [item for item in record.relay_plan.weights if item.weight_u16 > 0]
    if [
        (item.uid, item.hotkey, round(item.weight * WEIGHT_U16_TOTAL)) for item in plan.weights
    ] != [(item.miner_uid, item.miner_hotkey, item.weight_u16) for item in relay_positive]:
        raise CheckpointRelayCLIError("ledger_weight_plan_invalid")
    return result


def _pointer_matches(
    observed: CheckpointLedgerPointer,
    expected: CheckpointLedgerPointer,
) -> bool:
    return checkpoint_ledger_pointer_bytes(observed) == checkpoint_ledger_pointer_bytes(expected)


class CheckpointLedger:
    """Exclusive, descriptor-relative, append-only verified checkpoint ledger."""

    def __init__(
        self,
        state_root: str,
        trust_policy: CheckpointTrustPolicy,
        *,
        trusted_anchor_digest_sha256: str,
    ) -> None:
        self._chain: _PinnedDirectoryChain | None = None
        self._lock_descriptor = -1
        self._policy = CheckpointTrustPolicy.model_validate(
            trust_policy.model_dump(mode="json", by_alias=True)
        )
        self._records: list[CheckpointLedgerRecord] = []
        self._states: list[CheckpointChainState] = []
        self._head: CheckpointLedgerPointer | None = None
        self._anchor: CheckpointLedgerPointer | None = None
        self._trusted_anchor_index = -1
        try:
            self._chain = _open_or_create_state_root(state_root)
            self._open_lock()
            self._load_and_recover(trusted_anchor_digest_sha256)
        except Exception:
            self.close()
            raise

    @property
    def state_root(self) -> str:
        chain = self._chain
        if chain is None:
            raise CheckpointRelayCLIError("ledger_closed")
        return chain.absolute_path

    @property
    def chain_state(self) -> CheckpointChainState:
        if not self._states:
            raise CheckpointRelayCLIError("ledger_closed")
        return self._states[-1]

    @property
    def record_count(self) -> int:
        return len(self._records)

    @property
    def last_record_digest_sha256(self) -> str | None:
        return self._records[-1].record_digest_sha256 if self._records else None

    @property
    def head(self) -> CheckpointLedgerPointer:
        if self._head is None:
            raise CheckpointRelayCLIError("ledger_closed")
        return self._head

    @property
    def anchor(self) -> CheckpointLedgerPointer:
        if self._anchor is None:
            raise CheckpointRelayCLIError("ledger_closed")
        return self._anchor

    @property
    def _directory_fd(self) -> int:
        chain = self._chain
        if chain is None:
            raise CheckpointRelayCLIError("ledger_closed")
        return chain.directory_fd

    def _open_lock(self) -> None:
        directory_fd = self._directory_fd
        flags = os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW
        try:
            try:
                before = os.stat(LOCK_NAME, dir_fd=directory_fd, follow_symlinks=False)
            except FileNotFoundError:
                if os.listdir(directory_fd):
                    raise CheckpointRelayCLIError("ledger_lock_missing") from None
                try:
                    descriptor = os.open(
                        LOCK_NAME,
                        flags | os.O_CREAT | os.O_EXCL,
                        STATE_FILE_MODE,
                        dir_fd=directory_fd,
                    )
                except FileExistsError:
                    descriptor = os.open(LOCK_NAME, flags, dir_fd=directory_fd)
                os.fchmod(descriptor, STATE_FILE_MODE)
                os.fsync(descriptor)
                os.fsync(directory_fd)
                before = os.fstat(descriptor)
            else:
                descriptor = os.open(LOCK_NAME, flags, dir_fd=directory_fd)
            self._lock_descriptor = descriptor
            _validate_state_file(before, maximum_bytes=0, empty=True)
            opened = os.fstat(descriptor)
            _validate_state_file(opened, maximum_bytes=0, empty=True)
            mapped = os.stat(LOCK_NAME, dir_fd=directory_fd, follow_symlinks=False)
            if _metadata_fingerprint(opened) != _metadata_fingerprint(
                before
            ) or _metadata_fingerprint(mapped) != _metadata_fingerprint(before):
                raise CheckpointRelayCLIError("ledger_lock_changed")
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except (BlockingIOError, OSError) as exc:
                raise CheckpointRelayCLIError("ledger_busy") from exc
            after = os.fstat(descriptor)
            if _metadata_fingerprint(after) != _metadata_fingerprint(before):
                raise CheckpointRelayCLIError("ledger_lock_changed")
        except CheckpointRelayCLIError:
            raise
        except OSError as exc:
            raise CheckpointRelayCLIError("ledger_lock_unsafe") from exc

    def _record_indices(self, entries: set[str]) -> list[int]:
        indices: list[int] = []
        for name in entries:
            if not (name.startswith("record-") and name.endswith(".json")):
                continue
            digits = name[7:-5]
            if len(digits) != 20 or not digits.isascii() or not digits.isdigit():
                raise CheckpointRelayCLIError("ledger_extra_entry")
            index = int(digits)
            if name != _record_name(index):
                raise CheckpointRelayCLIError("ledger_extra_entry")
            indices.append(index)
        indices.sort()
        if len(indices) > MAX_LEDGER_RECORDS or indices != list(range(1, len(indices) + 1)):
            raise CheckpointRelayCLIError("ledger_record_gap")
        return indices

    def _load_pointer(self, name: str) -> CheckpointLedgerPointer | None:
        try:
            rendered = _read_state_file(
                self._directory_fd,
                name,
                maximum_bytes=MAX_LEDGER_POINTER_BYTES,
            )
        except CheckpointRelayCLIError:
            raise
        except FileNotFoundError:
            return None
        value = parse_checkpoint_ledger_pointer(rendered)
        expected_kind = "head" if name in {HEAD_NAME, HEAD_INSTALL_NAME} else "anchor"
        if value.pointer_kind != expected_kind:
            raise CheckpointRelayCLIError("ledger_pointer_invalid")
        return value

    def _expected_pointer(
        self,
        kind: Literal["anchor", "head"],
        index: int,
    ) -> CheckpointLedgerPointer:
        if not 0 <= index <= len(self._records):
            raise CheckpointRelayCLIError("ledger_pointer_invalid")
        return _build_pointer(
            kind,
            self._policy,
            self._states[index],
            record_count=index,
            last_record_digest_sha256=(
                self._records[index - 1].record_digest_sha256 if index else None
            ),
        )

    def _validate_pointer_history(self, pointer: CheckpointLedgerPointer) -> None:
        if pointer.record_count > len(self._records):
            raise CheckpointRelayCLIError("ledger_future_state")
        expected = self._expected_pointer(pointer.pointer_kind, pointer.record_count)
        if not _pointer_matches(pointer, expected):
            raise CheckpointRelayCLIError("ledger_pointer_invalid")

    def _trusted_index(
        self,
        trusted: str,
        anchor: CheckpointLedgerPointer | None,
    ) -> int:
        if trusted == "genesis":
            trusted_index = 0
        elif _valid_digest(trusted):
            matches = [
                index
                for index in range(len(self._records) + 1)
                if self._expected_pointer("anchor", index).pointer_digest_sha256 == trusted
            ]
            if len(matches) != 1:
                raise CheckpointRelayCLIError("ledger_anchor_untrusted")
            trusted_index = matches[0]
        else:
            raise CheckpointRelayCLIError("ledger_anchor_digest_invalid")
        anchor_index = anchor.record_count if anchor is not None else 0
        if (
            trusted_index > anchor_index
            or anchor_index - trusted_index > 1
            or len(self._records) - trusted_index > MAX_FORWARD_RECOVERY_RECORDS
        ):
            raise CheckpointRelayCLIError("ledger_rollback_detected")
        return trusted_index

    def _complete_install(
        self,
        install_name: Literal[".anchor.install", ".head.install"],
        target_name: Literal["anchor.json", "head.json"],
        staged: CheckpointLedgerPointer,
        current: CheckpointLedgerPointer | None,
    ) -> CheckpointLedgerPointer:
        count = len(self._records)
        if (
            count == 0
            or current is None
            or current.record_count != count - 1
            or staged.record_count != count
            or not _pointer_matches(
                staged,
                self._expected_pointer(staged.pointer_kind, count),
            )
        ):
            raise CheckpointRelayCLIError("ledger_temp_residue")
        try:
            os.replace(
                install_name,
                target_name,
                src_dir_fd=self._directory_fd,
                dst_dir_fd=self._directory_fd,
            )
            os.fsync(self._directory_fd)
        except OSError as exc:
            raise CheckpointRelayCLIError("ledger_recovery_failed") from exc
        recovered = self._load_pointer(target_name)
        if recovered is None or not _pointer_matches(recovered, staged):
            raise CheckpointRelayCLIError("ledger_recovery_failed")
        return recovered

    def _load_and_recover(self, trusted_anchor_digest_sha256: str) -> None:
        chain = self._chain
        if chain is None:
            raise CheckpointRelayCLIError("ledger_closed")
        _revalidate_chain(chain)
        try:
            entries = set(os.listdir(self._directory_fd))
        except OSError as exc:
            raise CheckpointRelayCLIError("ledger_root_unsafe") from exc
        indices = self._record_indices(entries)
        recognized = {
            LOCK_NAME,
            HEAD_NAME,
            ANCHOR_NAME,
            HEAD_INSTALL_NAME,
            ANCHOR_INSTALL_NAME,
            *(_record_name(index) for index in indices),
        }
        if entries - recognized or LOCK_NAME not in entries:
            raise CheckpointRelayCLIError("ledger_extra_entry")
        if HEAD_INSTALL_NAME in entries and ANCHOR_INSTALL_NAME in entries:
            raise CheckpointRelayCLIError("ledger_temp_residue")

        state = build_initial_checkpoint_chain_state(self._policy)
        self._states = [state]
        prior_digest: str | None = None
        for index in indices:
            record = parse_checkpoint_ledger_record(
                _read_state_file(
                    self._directory_fd,
                    _record_name(index),
                    maximum_bytes=MAX_LEDGER_RECORD_BYTES,
                )
            )
            result = _validate_record_against_history(
                record,
                self._policy,
                expected_index=index,
                expected_prior_record_digest_sha256=prior_digest,
                expected_prior_state=state,
            )
            self._records.append(record)
            state = result.next_chain_state
            self._states.append(state)
            prior_digest = record.record_digest_sha256

        head = self._load_pointer(HEAD_NAME) if HEAD_NAME in entries else None
        anchor = self._load_pointer(ANCHOR_NAME) if ANCHOR_NAME in entries else None
        if head is not None:
            self._validate_pointer_history(head)
        if anchor is not None:
            self._validate_pointer_history(anchor)
        if len(self._records) > 0 and (head is None or anchor is None):
            raise CheckpointRelayCLIError("ledger_pointer_missing")
        self._trusted_anchor_index = self._trusted_index(
            trusted_anchor_digest_sha256,
            anchor,
        )

        if HEAD_INSTALL_NAME in entries:
            staged_head = self._load_pointer(HEAD_INSTALL_NAME)
            if staged_head is None:
                raise CheckpointRelayCLIError("ledger_temp_residue")
            head = self._complete_install(HEAD_INSTALL_NAME, HEAD_NAME, staged_head, head)
        if ANCHOR_INSTALL_NAME in entries:
            staged_anchor = self._load_pointer(ANCHOR_INSTALL_NAME)
            if staged_anchor is None:
                raise CheckpointRelayCLIError("ledger_temp_residue")
            anchor = self._complete_install(
                ANCHOR_INSTALL_NAME,
                ANCHOR_NAME,
                staged_anchor,
                anchor,
            )

        if not self._records:
            expected_head = self._expected_pointer("head", 0)
            expected_anchor = self._expected_pointer("anchor", 0)
            if head is None:
                _install_new_file(
                    self._directory_fd,
                    HEAD_NAME,
                    checkpoint_ledger_pointer_bytes(expected_head),
                )
                head = expected_head
            if anchor is None:
                _install_new_file(
                    self._directory_fd,
                    ANCHOR_NAME,
                    checkpoint_ledger_pointer_bytes(expected_anchor),
                )
                anchor = expected_anchor
        if head is None or anchor is None:
            raise CheckpointRelayCLIError("ledger_pointer_missing")

        count = len(self._records)
        for pointer in (head, anchor):
            if pointer.record_count not in {count, count - 1}:
                raise CheckpointRelayCLIError("ledger_future_state")
        if count - min(head.record_count, anchor.record_count) > MAX_FORWARD_RECOVERY_RECORDS:
            raise CheckpointRelayCLIError("ledger_forward_gap")
        if head.record_count < count:
            expected_head = self._expected_pointer("head", count)
            _replace_state_file(
                self._directory_fd,
                HEAD_NAME,
                HEAD_INSTALL_NAME,
                checkpoint_ledger_pointer_bytes(expected_head),
            )
            head = expected_head
        if anchor.record_count < count:
            expected_anchor = self._expected_pointer("anchor", count)
            _replace_state_file(
                self._directory_fd,
                ANCHOR_NAME,
                ANCHOR_INSTALL_NAME,
                checkpoint_ledger_pointer_bytes(expected_anchor),
            )
            anchor = expected_anchor
        if not _pointer_matches(
            head, self._expected_pointer("head", count)
        ) or not _pointer_matches(
            anchor,
            self._expected_pointer("anchor", count),
        ):
            raise CheckpointRelayCLIError("ledger_pointer_invalid")
        self._head = head
        self._anchor = anchor
        self._assert_layout_unchanged()

    def _expected_layout(self) -> set[str]:
        return {
            LOCK_NAME,
            HEAD_NAME,
            ANCHOR_NAME,
            *(_record_name(index) for index in range(1, len(self._records) + 1)),
        }

    def _assert_layout_unchanged(self) -> None:
        chain = self._chain
        if chain is None:
            raise CheckpointRelayCLIError("ledger_closed")
        _revalidate_chain(chain)
        try:
            if set(os.listdir(self._directory_fd)) != self._expected_layout():
                raise CheckpointRelayCLIError("ledger_layout_changed")
        except OSError as exc:
            raise CheckpointRelayCLIError("ledger_root_unsafe") from exc
        current_head = self._load_pointer(HEAD_NAME)
        current_anchor = self._load_pointer(ANCHOR_NAME)
        if (
            current_head is None
            or current_anchor is None
            or not _pointer_matches(current_head, self.head)
            or not _pointer_matches(current_anchor, self.anchor)
        ):
            raise CheckpointRelayCLIError("ledger_pointer_changed")

    def verification_state_for(
        self,
        checkpoint_digest_sha256: str,
    ) -> tuple[CheckpointChainState, CheckpointLedgerRecord | None]:
        """Return the current state or the exact prior state for an idempotent replay."""

        if not _valid_digest(checkpoint_digest_sha256):
            raise CheckpointRelayCLIError("checkpoint_digest_invalid")
        replay = (
            self._records[-1]
            if self._records
            and self._records[-1].verification_input.checkpoint.checkpoint_digest_sha256
            == checkpoint_digest_sha256
            else None
        )
        if len(self._records) == self._trusted_anchor_index + 1:
            if replay is None:
                raise CheckpointRelayCLIError("ledger_anchor_stale")
        elif len(self._records) != self._trusted_anchor_index:
            raise CheckpointRelayCLIError("ledger_anchor_stale")
        if replay is not None:
            return replay.verification_input.prior_chain_state, replay
        return self.chain_state, None

    def append_or_match(
        self,
        record: CheckpointLedgerRecord,
        *,
        replay: CheckpointLedgerRecord | None,
    ) -> tuple[CheckpointLedgerRecord, CheckpointLedgerPointer, CheckpointLedgerPointer]:
        """Durably append one record, or prove an exact last-record replay."""

        if replay is not None:
            if checkpoint_ledger_record_bytes(record) != checkpoint_ledger_record_bytes(replay):
                raise CheckpointRelayCLIError("ledger_replay_mismatch")
            self._assert_layout_unchanged()
            return replay, self.head, self.anchor
        expected_index = len(self._records) + 1
        if (
            record.record_index != expected_index
            or record.prior_record_digest_sha256 != self.last_record_digest_sha256
        ):
            raise CheckpointRelayCLIError("ledger_append_invalid")
        _validate_record_against_history(
            record,
            self._policy,
            expected_index=expected_index,
            expected_prior_record_digest_sha256=self.last_record_digest_sha256,
            expected_prior_state=self.chain_state,
        )
        self._assert_layout_unchanged()
        name = _record_name(expected_index)
        _install_new_file(
            self._directory_fd,
            name,
            checkpoint_ledger_record_bytes(record),
        )
        installed = parse_checkpoint_ledger_record(
            _read_state_file(
                self._directory_fd,
                name,
                maximum_bytes=MAX_LEDGER_RECORD_BYTES,
            )
        )
        if checkpoint_ledger_record_bytes(installed) != checkpoint_ledger_record_bytes(record):
            raise CheckpointRelayCLIError("ledger_record_changed")
        next_state = advance_checkpoint_chain_state(
            self.chain_state,
            record.verification_input.checkpoint,
            self._policy,
        )
        next_head = _build_pointer(
            "head",
            self._policy,
            next_state,
            record_count=expected_index,
            last_record_digest_sha256=record.record_digest_sha256,
        )
        next_anchor = _build_pointer(
            "anchor",
            self._policy,
            next_state,
            record_count=expected_index,
            last_record_digest_sha256=record.record_digest_sha256,
        )
        _replace_state_file(
            self._directory_fd,
            HEAD_NAME,
            HEAD_INSTALL_NAME,
            checkpoint_ledger_pointer_bytes(next_head),
        )
        _replace_state_file(
            self._directory_fd,
            ANCHOR_NAME,
            ANCHOR_INSTALL_NAME,
            checkpoint_ledger_pointer_bytes(next_anchor),
        )
        self._records.append(record)
        self._states.append(next_state)
        self._head = next_head
        self._anchor = next_anchor
        self._trusted_anchor_index = expected_index
        self._assert_layout_unchanged()
        return record, next_head, next_anchor

    def close(self) -> None:
        if self._lock_descriptor >= 0:
            try:
                fcntl.flock(self._lock_descriptor, fcntl.LOCK_UN)
            except OSError:
                pass
            try:
                os.close(self._lock_descriptor)
            except OSError:
                pass
            self._lock_descriptor = -1
        if self._chain is not None:
            self._chain.close()
            self._chain = None

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


@dataclass(frozen=True, slots=True)
class RelayOutputPaths:
    verification_report: str
    relay_plan: str
    weight_plan: str
    preparation: str


@dataclass(frozen=True, slots=True)
class CheckpointRelayCLIConfig:
    inputs: CheckpointRelayInputFiles
    evaluation_epoch: int
    validator_uid: int
    validator_hotkey: str
    state_root: str
    trusted_ledger_anchor_digest_sha256: str
    weight_plan_tempo: int
    weight_plan_snapshot_identity_sha256: str
    outputs: RelayOutputPaths


@dataclass(frozen=True, slots=True)
class CheckpointRelayCLIResult:
    verification_report: ExternalValidatorVerificationReport
    relay_plan: ExternalValidatorRelayPlan
    weight_plan: WeightPlan
    preparation: ExternalValidatorWeightPlanPreparation
    replayed: bool


def _output_parent(path: str, *, state_root: str) -> tuple[_PinnedDirectoryChain, str, str]:
    normalized = _normalized_absolute_path(path, code="output_path_unsafe")
    root = _normalized_absolute_path(state_root, code="ledger_root_path_unsafe")
    if normalized == root or normalized.startswith(root + "/"):
        raise CheckpointRelayCLIError("output_path_unsafe")
    parent_path, name = normalized.rsplit("/", 1)
    if not name or name in {".", ".."}:
        raise CheckpointRelayCLIError("output_path_unsafe")
    chain = _pin_directory(parent_path or "/", state_root=False)
    return chain, name, normalized


def _read_existing_output(
    chain: _PinnedDirectoryChain,
    name: str,
    *,
    maximum_bytes: int,
) -> bytes | None:
    try:
        os.stat(name, dir_fd=chain.directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise CheckpointRelayCLIError("output_unsafe") from exc
    try:
        return _read_state_file(
            chain.directory_fd,
            name,
            maximum_bytes=maximum_bytes,
        )
    except CheckpointRelayCLIError as exc:
        raise CheckpointRelayCLIError("output_unsafe") from exc


def _preflight_outputs(
    paths: RelayOutputPaths,
    rendered: tuple[bytes, bytes, bytes, bytes],
    *,
    state_root: str,
    allow_existing_exact: bool,
) -> None:
    path_values = (
        paths.verification_report,
        paths.relay_plan,
        paths.weight_plan,
        paths.preparation,
    )
    normalized = [
        _normalized_absolute_path(item, code="output_path_unsafe") for item in path_values
    ]
    if len(normalized) != len(set(normalized)):
        raise CheckpointRelayCLIError("output_path_alias")
    for path, expected in zip(path_values, rendered, strict=True):
        chain, name, _ = _output_parent(path, state_root=state_root)
        try:
            _revalidate_chain(chain)
            existing = _read_existing_output(
                chain,
                name,
                maximum_bytes=max(len(expected), 1) + 1,
            )
            if existing is not None and (not allow_existing_exact or existing != expected):
                raise CheckpointRelayCLIError("output_exists")
            _revalidate_chain(chain)
        finally:
            chain.close()


def _write_output(
    path: str,
    rendered: bytes,
    *,
    state_root: str,
    allow_existing_exact: bool,
) -> None:
    chain, name, _ = _output_parent(path, state_root=state_root)
    try:
        _revalidate_chain(chain)
        existing = _read_existing_output(
            chain,
            name,
            maximum_bytes=max(len(rendered), 1) + 1,
        )
        if existing is not None:
            if allow_existing_exact and existing == rendered:
                return
            raise CheckpointRelayCLIError("output_exists")
        try:
            _install_new_file(chain.directory_fd, name, rendered)
        except CheckpointRelayCLIError as exc:
            if exc.code != "file_exists":
                raise CheckpointRelayCLIError("output_write_failed") from exc
            existing = _read_existing_output(
                chain,
                name,
                maximum_bytes=max(len(rendered), 1) + 1,
            )
            if not allow_existing_exact or existing != rendered:
                raise CheckpointRelayCLIError("output_exists") from exc
        _revalidate_chain(chain)
        installed = _read_existing_output(
            chain,
            name,
            maximum_bytes=max(len(rendered), 1) + 1,
        )
        if installed != rendered:
            raise CheckpointRelayCLIError("output_write_failed")
    finally:
        chain.close()


def _output_bytes(
    result: RelayVerificationResult,
    weight_plan: WeightPlan,
    preparation: ExternalValidatorWeightPlanPreparation,
) -> tuple[bytes, bytes, bytes, bytes]:
    return (
        external_validator_verification_report_bytes(result.verification_report),
        external_validator_relay_plan_bytes(result.relay_plan),
        weight_plan.canonical_bytes(),
        weight_plan_preparation_bytes(preparation),
    )


def execute_checkpoint_relay(config: CheckpointRelayCLIConfig) -> CheckpointRelayCLIResult:
    """Verify, durably accept, and prepare one offline checkpoint publication."""

    if (
        isinstance(config.evaluation_epoch, bool)
        or not isinstance(config.evaluation_epoch, int)
        or not 0 <= config.evaluation_epoch <= (1 << 63) - 1
        or isinstance(config.validator_uid, bool)
        or not isinstance(config.validator_uid, int)
        or not 0 <= config.validator_uid <= WEIGHT_U16_TOTAL
    ):
        raise CheckpointRelayCLIError("operator_context_invalid")
    loaded = load_checkpoint_relay_inputs(config.inputs)
    try:
        validator = ExternalValidatorIdentity(
            uid=config.validator_uid,
            hotkey=config.validator_hotkey,
            active=True,
            validator_permit=True,
        )
    except ValidationError as exc:
        raise CheckpointRelayCLIError("validator_identity_invalid") from exc
    input_paths = {
        config.inputs.trust_policy.path,
        config.inputs.checkpoint.path,
        config.inputs.canonical_score_report.path,
        config.inputs.finalized_metagraph.path,
        *(item.path for item in config.inputs.signatures),
    }
    output_paths = {
        config.outputs.verification_report,
        config.outputs.relay_plan,
        config.outputs.weight_plan,
        config.outputs.preparation,
    }
    if input_paths & output_paths:
        raise CheckpointRelayCLIError("output_path_alias")

    with CheckpointLedger(
        config.state_root,
        loaded.trust_policy,
        trusted_anchor_digest_sha256=config.trusted_ledger_anchor_digest_sha256,
    ) as ledger:
        prior_state, replay = ledger.verification_state_for(
            loaded.checkpoint.checkpoint_digest_sha256
        )
        try:
            verification_input = build_external_validator_verification_input(
                evaluation_epoch=config.evaluation_epoch,
                trust_policy=loaded.trust_policy,
                checkpoint=loaded.checkpoint,
                signatures=loaded.signatures,
                canonical_score_report=loaded.canonical_score_report,
                prior_chain_state=prior_state,
                validator=validator,
                finalized_metagraph=loaded.finalized_metagraph,
            )
            result = verify_checkpoint_and_build_relay(
                verification_input,
                loaded.trust_policy,
            )
        except CheckpointRelayError:
            raise
        except (TypeError, ValueError, ValidationError) as exc:
            raise CheckpointRelayCLIError("verification_input_invalid") from exc

        record_index = replay.record_index if replay is not None else ledger.record_count + 1
        prior_record_digest = (
            replay.prior_record_digest_sha256
            if replay is not None
            else ledger.last_record_digest_sha256
        )
        weight_plan = build_bound_weight_plan(
            result.relay_plan,
            loaded.trust_policy,
            record_index=record_index,
            prior_record_digest_sha256=prior_record_digest,
            tempo=config.weight_plan_tempo,
            snapshot_identity_fingerprint_sha256=(config.weight_plan_snapshot_identity_sha256),
        )
        proposed_record = _build_ledger_record(
            verification_input,
            result,
            weight_plan,
            record_index=record_index,
            prior_record_digest_sha256=prior_record_digest,
        )
        next_head = _build_pointer(
            "head",
            loaded.trust_policy,
            result.next_chain_state,
            record_count=record_index,
            last_record_digest_sha256=proposed_record.record_digest_sha256,
        )
        next_anchor = _build_pointer(
            "anchor",
            loaded.trust_policy,
            result.next_chain_state,
            record_count=record_index,
            last_record_digest_sha256=proposed_record.record_digest_sha256,
        )
        preparation = build_weight_plan_preparation(
            proposed_record,
            next_head,
            next_anchor,
        )
        rendered_outputs = _output_bytes(result, weight_plan, preparation)
        _preflight_outputs(
            config.outputs,
            rendered_outputs,
            state_root=config.state_root,
            allow_existing_exact=replay is not None,
        )
        installed_record, installed_head, installed_anchor = ledger.append_or_match(
            proposed_record,
            replay=replay,
        )
        if (
            checkpoint_ledger_record_bytes(installed_record)
            != checkpoint_ledger_record_bytes(proposed_record)
            or not _pointer_matches(installed_head, next_head)
            or not _pointer_matches(installed_anchor, next_anchor)
        ):
            raise CheckpointRelayCLIError("ledger_commit_mismatch")
        for path, rendered in zip(
            (
                config.outputs.verification_report,
                config.outputs.relay_plan,
                config.outputs.weight_plan,
                config.outputs.preparation,
            ),
            rendered_outputs,
            strict=True,
        ):
            _write_output(
                path,
                rendered,
                state_root=config.state_root,
                allow_existing_exact=replay is not None,
            )
        return CheckpointRelayCLIResult(
            verification_report=result.verification_report,
            relay_plan=result.relay_plan,
            weight_plan=weight_plan,
            preparation=preparation,
            replayed=replay is not None,
        )


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        del message
        raise CheckpointRelayCLIError("usage")


def _unsigned_decimal(value: str) -> int:
    if (
        not value
        or not value.isascii()
        or not value.isdigit()
        or (len(value) > 1 and value.startswith("0"))
    ):
        raise argparse.ArgumentTypeError("invalid")
    parsed = int(value)
    if parsed > (1 << 63) - 1:
        raise argparse.ArgumentTypeError("invalid")
    return parsed


def _parser() -> argparse.ArgumentParser:
    parser = _ArgumentParser(
        prog="misscomputer-score-checkpoint-relay",
        description="Offline signed score-checkpoint verifier and inert relay preparer.",
        allow_abbrev=False,
        add_help=False,
    )
    parser.add_argument("--trust-policy", required=True)
    parser.add_argument("--trust-policy-sha256", required=True)
    parser.add_argument("--checkpoint", required=True)
    parser.add_argument("--checkpoint-sha256", required=True)
    parser.add_argument("--signature", action="append", required=True)
    parser.add_argument("--signature-sha256", action="append", required=True)
    parser.add_argument("--score-report", required=True)
    parser.add_argument("--score-report-sha256", required=True)
    parser.add_argument("--metagraph", required=True)
    parser.add_argument("--metagraph-sha256", required=True)
    parser.add_argument("--evaluation-epoch", required=True, type=_unsigned_decimal)
    parser.add_argument("--validator-uid", required=True, type=_unsigned_decimal)
    parser.add_argument("--validator-hotkey", required=True)
    parser.add_argument("--state-root", required=True)
    parser.add_argument("--trusted-ledger-anchor", required=True)
    parser.add_argument("--weight-plan-tempo", required=True, type=_unsigned_decimal)
    parser.add_argument("--weight-plan-snapshot-identity-sha256", required=True)
    parser.add_argument("--verification-report-output", required=True)
    parser.add_argument("--relay-plan-output", required=True)
    parser.add_argument("--weight-plan-output", required=True)
    parser.add_argument("--preparation-output", required=True)
    return parser


def _config_from_arguments(arguments: argparse.Namespace) -> CheckpointRelayCLIConfig:
    signature_paths = cast(list[str], arguments.signature)
    signature_digests = cast(list[str], arguments.signature_sha256)
    if len(signature_paths) != len(signature_digests):
        raise CheckpointRelayCLIError("signature_count_invalid")
    return CheckpointRelayCLIConfig(
        inputs=CheckpointRelayInputFiles(
            trust_policy=InputFile(
                cast(str, arguments.trust_policy),
                cast(str, arguments.trust_policy_sha256),
            ),
            checkpoint=InputFile(
                cast(str, arguments.checkpoint),
                cast(str, arguments.checkpoint_sha256),
            ),
            signatures=tuple(
                InputFile(path, digest)
                for path, digest in zip(signature_paths, signature_digests, strict=True)
            ),
            canonical_score_report=InputFile(
                cast(str, arguments.score_report),
                cast(str, arguments.score_report_sha256),
            ),
            finalized_metagraph=InputFile(
                cast(str, arguments.metagraph),
                cast(str, arguments.metagraph_sha256),
            ),
        ),
        evaluation_epoch=cast(int, arguments.evaluation_epoch),
        validator_uid=cast(int, arguments.validator_uid),
        validator_hotkey=cast(str, arguments.validator_hotkey),
        state_root=cast(str, arguments.state_root),
        trusted_ledger_anchor_digest_sha256=cast(
            str,
            arguments.trusted_ledger_anchor,
        ),
        weight_plan_tempo=cast(int, arguments.weight_plan_tempo),
        weight_plan_snapshot_identity_sha256=cast(
            str,
            arguments.weight_plan_snapshot_identity_sha256,
        ),
        outputs=RelayOutputPaths(
            verification_report=cast(str, arguments.verification_report_output),
            relay_plan=cast(str, arguments.relay_plan_output),
            weight_plan=cast(str, arguments.weight_plan_output),
            preparation=cast(str, arguments.preparation_output),
        ),
    )


def run_cli(argv: Sequence[str]) -> int:
    """Run with stable statuses and without echoing arguments, paths, or content."""

    try:
        arguments = _parser().parse_args(list(argv))
        execute_checkpoint_relay(_config_from_arguments(arguments))
        sys.stdout.write("VERIFIED\n")
        return EXIT_OK
    except CheckpointRelayError as exc:
        sys.stderr.write(f"REJECTED {exc.code}\n")
        return EXIT_REJECTED
    except CheckpointRelayCLIError as exc:
        sys.stderr.write(f"REJECTED {exc.code}\n")
        if exc.code == "usage":
            return EXIT_USAGE
        if exc.code == "ledger_busy":
            return EXIT_BUSY
        return EXIT_REJECTED
    except (ValidationError, WeightPlanError, TypeError, ValueError):
        sys.stderr.write("REJECTED input_contract_invalid\n")
        return EXIT_REJECTED
    except Exception:
        sys.stderr.write("ERROR internal_error\n")
        return EXIT_INTERNAL


def main() -> None:
    raise SystemExit(run_cli(sys.argv[1:]))


if __name__ == "__main__":
    main()
