# SPDX-License-Identifier: AGPL-3.0-only
"""Declarative wire-document fixtures for verifier tests.

These helpers assemble plain field dictionaries and validate them through the
public contract models. They deliberately contain no producer logic: every
value they compute is one the public verifier itself enforces — canonical
replica/deployment ordering, replica and endpoint identity strings, digest
sealing (``verify_model_digest``), the manifest/checkpoint header linkage
rules, and the report fields the relay verifier requires equal on a
checkpoint. Documents whose production involves private-only algorithms
(deployment.v4 route projection) are static golden fixtures under
``tests/python/fixtures/``, authored by the private producer implementation.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from pathlib import Path

from misscomputer_subnet.assignment_probe import (
    MANIFEST_PURPOSE,
    MANIFEST_SIGNATURE_ENVELOPE_SCHEMA,
    AssignmentManifestSignatureEnvelope,
    AssignmentManifestTrustPolicy,
)
from misscomputer_subnet.checkpoint_score_contracts import CanonicalScoreReport
from misscomputer_subnet.contract_codec import digest, model_document
from misscomputer_subnet.organic_contracts import (
    ActiveAssignmentManifestV2,
    OrganicAssignedReplica,
    OrganicDeploymentAssignment,
    OrganicHealthProbe,
)
from misscomputer_subnet.organic_manifest import (
    ORGANIC_ATTESTATION_REQUIREMENT,
    ORGANIC_MANIFEST_PURPOSE,
    ORGANIC_MANIFEST_SCHEMA,
    organic_manifest_signature_message,
)
from misscomputer_subnet.production_release import (
    LaunchAuthorizationBundle,
    ProductionReleaseManifest,
    _build_digested_document,
)
from misscomputer_subnet.score_checkpoint_relay import (
    CHECKPOINT_PURPOSE,
    CHECKPOINT_SCHEMA,
    CHECKPOINT_SCHEMA_VERSION,
    SIGNATURE_ENVELOPE_SCHEMA,
    CentralScoreCheckpoint,
    CheckpointScoreEntry,
    CheckpointSignatureEnvelope,
    CheckpointTrustPolicy,
    _digest,
    _model_document,
    checkpoint_signature_message,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def golden_route_projection() -> dict[str, object]:
    """The golden deployment.v4 route projection authored by the private producer."""

    return json.loads((FIXTURES / "organic-route-projection.v2.golden.json").read_bytes())


def health_probe_document(
    *,
    method: str,
    path: str,
    expected_statuses: Sequence[int],
    response_marker: str | None,
) -> OrganicHealthProbe:
    return OrganicHealthProbe.model_validate(
        {
            "method": method,
            "path": path,
            "expected_statuses": sorted(set(expected_statuses)),
            "response_marker": response_marker,
        }
    )


def replica_document(
    *,
    deployment_id: str,
    miner_hotkey: str,
    generation: int,
    assignment_nonce: str,
    **fields: object,
) -> OrganicAssignedReplica:
    # replica_id and endpoint_id follow the identity rule the public model
    # enforces (``assignment_replica_identity_invalid``).
    replica_id = f"{deployment_id}-{miner_hotkey}"
    return OrganicAssignedReplica.model_validate(
        {
            "miner_hotkey": miner_hotkey,
            "generation": generation,
            "assignment_nonce": assignment_nonce,
            "replica_id": replica_id,
            "endpoint_id": f"{replica_id}-g{generation}-{assignment_nonce}",
            "route_state": "active",
            **fields,
        }
    )


def deployment_document(
    *,
    deployment_id: str,
    route_host: str,
    artifact_digest: str,
    health: OrganicHealthProbe,
    replicas: Sequence[OrganicAssignedReplica],
) -> OrganicDeploymentAssignment:
    ordered = sorted(replicas, key=lambda item: (item.miner_uid, item.miner_hotkey))
    unsigned: dict[str, object] = {
        "deployment_id": deployment_id,
        "route_host": route_host,
        "artifact_digest": artifact_digest,
        "health": model_document(health),
        "attestation_requirement": ORGANIC_ATTESTATION_REQUIREMENT,
        "replicas": [model_document(item) for item in ordered],
    }
    return OrganicDeploymentAssignment.model_validate(
        {**unsigned, "assignment_digest_sha256": digest(unsigned)}
    )


def manifest_document(
    policy: AssignmentManifestTrustPolicy,
    *,
    deployments: Sequence[OrganicDeploymentAssignment],
    **header: object,
) -> ActiveAssignmentManifestV2:
    ordered = sorted(deployments, key=lambda item: item.deployment_id)
    vector = [model_document(item) for item in ordered]
    unsigned: dict[str, object] = {
        "schema": ORGANIC_MANIFEST_SCHEMA,
        "schema_version": 2,
        "purpose": ORGANIC_MANIFEST_PURPOSE,
        "network": policy.network,
        "netuid": policy.netuid,
        "central_authority_fingerprint_sha256": policy.central_authority_fingerprint_sha256,
        "trust_policy_digest_sha256": policy.trust_policy_digest_sha256,
        "probe_scheme": policy.probe_scheme,
        "deployments": vector,
        "assignment_vector_digest_sha256": digest(vector),
        **header,
    }
    return ActiveAssignmentManifestV2.model_validate(
        {**unsigned, "manifest_digest_sha256": digest(unsigned)}
    )


def manifest_signature_envelope(
    manifest: ActiveAssignmentManifestV2,
    *,
    signer_key_id: str,
    signature_base64: str,
) -> AssignmentManifestSignatureEnvelope:
    message_digest = hashlib.sha256(organic_manifest_signature_message(manifest)).hexdigest()
    return AssignmentManifestSignatureEnvelope.model_validate(
        {
            "schema": MANIFEST_SIGNATURE_ENVELOPE_SCHEMA,
            "schema_version": 1,
            "purpose": MANIFEST_PURPOSE,
            "algorithm": "ed25519",
            "signer_key_id": signer_key_id,
            "manifest_digest_sha256": manifest.manifest_digest_sha256,
            "signed_message_digest_sha256": message_digest,
            "signature_base64": signature_base64,
        }
    )


def checkpoint_document(
    report: CanonicalScoreReport,
    policy: CheckpointTrustPolicy,
    *,
    finalized_epoch: int,
    sequence: int,
    issued_at_epoch: int,
    evaluation_epoch: int,
    expires_at_epoch: int,
    previous_checkpoint_digest_sha256: str | None,
) -> CentralScoreCheckpoint:
    # Every report-derived field below is one the relay verifier requires
    # equal between the checkpoint and the canonical score report; the score
    # vector entries carry exactly the report's per-miner values.
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
        "central_authority_fingerprint_sha256": report.central_authority_fingerprint_sha256,
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


def checkpoint_signature_envelope(
    checkpoint: CentralScoreCheckpoint,
    *,
    signer_key_id: str,
    signature_base64: str,
) -> CheckpointSignatureEnvelope:
    message_digest = hashlib.sha256(checkpoint_signature_message(checkpoint)).hexdigest()
    return CheckpointSignatureEnvelope.model_validate(
        {
            "schema": SIGNATURE_ENVELOPE_SCHEMA,
            "schema_version": CHECKPOINT_SCHEMA_VERSION,
            "purpose": CHECKPOINT_PURPOSE,
            "algorithm": "ed25519",
            "signer_key_id": signer_key_id,
            "checkpoint_digest_sha256": checkpoint.checkpoint_digest_sha256,
            "signed_message_digest_sha256": message_digest,
            "signature_base64": signature_base64,
        }
    )


def release_manifest_document(document: Mapping[str, object]) -> ProductionReleaseManifest:
    built = _build_digested_document(document, model=ProductionReleaseManifest)
    assert isinstance(built, ProductionReleaseManifest)
    return built


def launch_authorization_document(document: Mapping[str, object]) -> LaunchAuthorizationBundle:
    built = _build_digested_document(document, model=LaunchAuthorizationBundle)
    assert isinstance(built, LaunchAuthorizationBundle)
    return built
