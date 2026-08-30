# SPDX-License-Identifier: AGPL-3.0-only
"""Canonical-file command boundary for checkpoint contract operations."""

from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path
from typing import Any, Final

from pydantic import BaseModel

from .assignment_probe import (
    ActiveAssignmentManifest,
    ActiveDeploymentAssignment,
    AssignedReplica,
    AssignmentManifestChainState,
    AssignmentManifestSignatureEnvelope,
    AssignmentManifestTrustPolicy,
    TrustedManifestKey,
    advance_manifest_chain_state,
    build_active_assignment_manifest,
    build_active_deployment_assignment,
    build_assigned_replica,
    build_assignment_manifest_trust_policy,
    build_initial_manifest_chain_state,
    build_manifest_signature_envelope,
    manifest_signature_message,
    verify_active_assignment_manifest,
)
from .checkpoint_score_contracts import CanonicalScoreReport
from .score_checkpoint_relay import (
    CentralScoreCheckpoint,
    CheckpointChainState,
    CheckpointSignatureEnvelope,
    CheckpointTrustPolicy,
    ExternalValidatorIdentity,
    ExternalValidatorVerificationInput,
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
    checkpoint_signature_message,
    verify_checkpoint_and_build_relay,
)

PROTOCOL: Final = "misscomputer.checkpoint-boundary.v1"
# Match the checkpoint contract's bounded maximum so full-cardinality canonical
# requests can cross the process boundary without relaxing the model ceiling.
MAX_BYTES: Final = 64 << 20


def _canonical(value: object) -> bytes:
    return (
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
        ).encode("ascii")
        + b"\n"
    )


def _document(value: BaseModel) -> dict[str, object]:
    return value.model_dump(mode="json", by_alias=True)


def _read(path: Path) -> dict[str, object]:
    payload = path.read_bytes()
    if len(payload) > MAX_BYTES:
        raise ValueError("document_size_invalid")
    value = json.loads(payload)
    if not isinstance(value, dict) or _canonical(value) != payload:
        raise ValueError("canonical_document_invalid")
    return value


def _model[ModelT: BaseModel](model: type[ModelT], value: object) -> ModelT:
    return model.model_validate(value)


def execute(request: dict[str, object]) -> dict[str, object]:
    if set(request) != {"arguments", "operation", "protocol"}:
        raise ValueError("request_shape_invalid")
    if request["protocol"] != PROTOCOL or not isinstance(request["arguments"], dict):
        raise ValueError("request_protocol_invalid")
    operation = request["operation"]
    arguments: dict[str, Any] = request["arguments"]
    if operation == "build_trust_policy":
        arguments = dict(arguments)
        arguments["trusted_keys"] = [
            _model(TrustedCheckpointKey, item) for item in arguments["trusted_keys"]
        ]
        trust_policy = build_checkpoint_trust_policy(**arguments)
        return {"value": _document(trust_policy)}
    if operation == "build_initial_state":
        initial_state = build_initial_checkpoint_chain_state(
            _model(CheckpointTrustPolicy, arguments["trust_policy"])
        )
        return {"value": _document(initial_state)}
    if operation == "build_metagraph":
        arguments = dict(arguments)
        arguments["validator"] = _model(ExternalValidatorIdentity, arguments["validator"])
        arguments["miner_mappings"] = [
            _model(MetagraphMinerMapping, item) for item in arguments["miner_mappings"]
        ]
        metagraph = build_relay_finalized_metagraph_snapshot(**arguments)
        return {"value": _document(metagraph)}
    if operation == "build_checkpoint":
        checkpoint = build_central_score_checkpoint(
            _model(CanonicalScoreReport, arguments["report"]),
            _model(CheckpointTrustPolicy, arguments["trust_policy"]),
            **arguments["parameters"],
        )
        return {"value": _document(checkpoint)}
    if operation == "advance_state":
        next_state = advance_checkpoint_chain_state(
            _model(CheckpointChainState, arguments["state"]),
            _model(CentralScoreCheckpoint, arguments["checkpoint"]),
            _model(CheckpointTrustPolicy, arguments["trust_policy"]),
        )
        return {"value": _document(next_state)}
    if operation == "build_signature_envelope":
        envelope = build_checkpoint_signature_envelope(
            _model(CentralScoreCheckpoint, arguments["checkpoint"]),
            signer_key_id=arguments["signer_key_id"],
            signature_base64=arguments["signature_base64"],
        )
        return {"value": _document(envelope)}
    if operation == "signature_message":
        signature_bytes = checkpoint_signature_message(
            _model(CentralScoreCheckpoint, arguments["checkpoint"])
        )
        return {"value_base64": base64.b64encode(signature_bytes).decode("ascii")}
    if operation == "build_verification_input":
        verification_input = build_external_validator_verification_input(
            evaluation_epoch=arguments["evaluation_epoch"],
            trust_policy=_model(CheckpointTrustPolicy, arguments["trust_policy"]),
            checkpoint=_model(CentralScoreCheckpoint, arguments["checkpoint"]),
            signatures=[
                _model(CheckpointSignatureEnvelope, item) for item in arguments["signatures"]
            ],
            canonical_score_report=_model(
                CanonicalScoreReport, arguments["canonical_score_report"]
            ),
            prior_chain_state=_model(CheckpointChainState, arguments["prior_chain_state"]),
            validator=_model(ExternalValidatorIdentity, arguments["validator"]),
            finalized_metagraph=_model(
                RelayFinalizedMetagraphSnapshot, arguments["finalized_metagraph"]
            ),
        )
        return {"value": _document(verification_input)}
    if operation == "verify_relay":
        result = verify_checkpoint_and_build_relay(
            _model(ExternalValidatorVerificationInput, arguments["verification_input"]),
            _model(CheckpointTrustPolicy, arguments["trust_policy"]),
        )
        return {
            "next_chain_state": _document(result.next_chain_state),
            "relay_plan": _document(result.relay_plan),
            "verification_report": _document(result.verification_report),
        }
    if operation == "build_manifest_trust_policy":
        arguments = dict(arguments)
        arguments["trusted_keys"] = [
            _model(TrustedManifestKey, item) for item in arguments["trusted_keys"]
        ]
        manifest_policy = build_assignment_manifest_trust_policy(**arguments)
        return {"value": _document(manifest_policy)}
    if operation == "build_manifest_initial_state":
        manifest_state = build_initial_manifest_chain_state(
            _model(AssignmentManifestTrustPolicy, arguments["trust_policy"])
        )
        return {"value": _document(manifest_state)}
    if operation == "build_assigned_replica":
        return {"value": _document(build_assigned_replica(**arguments))}
    if operation == "build_deployment_assignment":
        arguments = dict(arguments)
        arguments["replicas"] = [_model(AssignedReplica, item) for item in arguments["replicas"]]
        return {"value": _document(build_active_deployment_assignment(**arguments))}
    if operation == "build_assignment_manifest":
        manifest = build_active_assignment_manifest(
            _model(AssignmentManifestTrustPolicy, arguments["trust_policy"]),
            deployments=[
                _model(ActiveDeploymentAssignment, item) for item in arguments["deployments"]
            ],
            **arguments["parameters"],
        )
        return {"value": _document(manifest)}
    if operation == "manifest_signature_message":
        manifest_message = manifest_signature_message(
            _model(ActiveAssignmentManifest, arguments["manifest"])
        )
        return {"value_base64": base64.b64encode(manifest_message).decode("ascii")}
    if operation == "build_manifest_signature_envelope":
        manifest_envelope = build_manifest_signature_envelope(
            _model(ActiveAssignmentManifest, arguments["manifest"]),
            signer_key_id=arguments["signer_key_id"],
            signature_base64=arguments["signature_base64"],
        )
        return {"value": _document(manifest_envelope)}
    if operation == "advance_manifest_state":
        next_manifest_state, reprobe = advance_manifest_chain_state(
            _model(AssignmentManifestChainState, arguments["state"]),
            _model(ActiveAssignmentManifest, arguments["manifest"]),
            _model(AssignmentManifestTrustPolicy, arguments["trust_policy"]),
        )
        return {"reprobe": reprobe, "value": _document(next_manifest_state)}
    if operation == "verify_manifest":
        verification = verify_active_assignment_manifest(
            _model(ActiveAssignmentManifest, arguments["manifest"]),
            [_model(AssignmentManifestSignatureEnvelope, item) for item in arguments["signatures"]],
            _model(AssignmentManifestTrustPolicy, arguments["trust_policy"]),
            _model(AssignmentManifestChainState, arguments["prior_chain_state"]),
            evaluation_epoch=arguments["evaluation_epoch"],
        )
        return {
            "next_chain_state": _document(verification.next_chain_state),
            "reprobe": verification.reprobe,
            "verified_roles": list(verification.verified_roles),
            "verified_signer_key_ids": list(verification.verified_signer_key_ids),
        }
    if operation == "validate":
        models: dict[str, type[BaseModel]] = {
            "active_assignment_manifest": ActiveAssignmentManifest,
            "assignment_manifest_chain_state": AssignmentManifestChainState,
            "assignment_manifest_signature_envelope": AssignmentManifestSignatureEnvelope,
            "assignment_manifest_trust_policy": AssignmentManifestTrustPolicy,
            "central_score_checkpoint": CentralScoreCheckpoint,
            "checkpoint_chain_state": CheckpointChainState,
            "checkpoint_signature_envelope": CheckpointSignatureEnvelope,
            "checkpoint_trust_policy": CheckpointTrustPolicy,
            "relay_finalized_metagraph": RelayFinalizedMetagraphSnapshot,
        }
        model = models.get(str(arguments.get("model")))
        if model is None:
            raise ValueError("model_invalid")
        return {"value": _document(_model(model, arguments["value"]))}
    raise ValueError("operation_invalid")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--response", type=Path, required=True)
    args = parser.parse_args()
    try:
        response: dict[str, object] = {
            "protocol": PROTOCOL,
            "status": "ok",
            **execute(_read(args.request)),
        }
    except Exception as error:
        response = {
            "code": str(getattr(error, "code", str(error)))[:96],
            "protocol": PROTOCOL,
            "status": "rejected",
        }
    target = args.response
    temporary = target.with_name(f".{target.name}.{os.getpid()}.tmp")
    descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(_canonical(response))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
    finally:
        temporary.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
