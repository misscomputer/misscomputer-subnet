# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic live-probe fixture publication shared by the pure and CLI tests.

Running this module directly regenerates the committed ``contracts/fixtures``
and ``contracts/schemas`` entries for the assignment-probe contracts.  Every
key is derived from a fixed label, so the committed bytes are reproducible and
contain no real secret material.
"""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import BaseModel

from misscomputer_subnet.assignment_probe import (
    MANIFEST_PURPOSE,
    ActiveAssignmentManifest,
    ActiveDeploymentAssignment,
    AssignedReplica,
    AssignmentManifestChainState,
    AssignmentManifestSignatureEnvelope,
    AssignmentManifestTrustPolicy,
    AttestationRequirement,
    ManifestRole,
    ManifestVerificationResult,
    MinerProbeAttestation,
    ProbeObservation,
    ProbeResponse,
    TrustedManifestKey,
    ValidatorProbeReport,
    active_assignment_manifest_bytes,
    assignment_manifest_chain_state_bytes,
    assignment_manifest_signature_envelope_bytes,
    assignment_manifest_trust_policy_bytes,
    build_active_assignment_manifest,
    build_active_deployment_assignment,
    build_assigned_replica,
    build_assignment_manifest_trust_policy,
    build_initial_manifest_chain_state,
    build_manifest_signature_envelope,
    build_miner_probe_attestation,
    build_validator_probe_report,
    evaluate_probe_response,
    manifest_signature_message,
    miner_probe_attestation_bytes,
    miner_probe_attestation_message,
    validator_probe_report_bytes,
    verify_active_assignment_manifest,
)

ROOT = Path(__file__).resolve().parents[2]
BASE_EPOCH = 1_800_000_000
EVALUATION_EPOCH = BASE_EPOCH + 200
ROUTE_SUFFIX = "mock.local"
PROBE_PORT = 443
FINALIZED_HEIGHT = 12_345_678
CENTRAL_AUTHORITY = hashlib.sha256(b"assignment-probe-central-authority").hexdigest()
FINALIZED_BLOCK_HASH = hashlib.sha256(b"assignment-probe-finalized-block").hexdigest()
FINALIZED_EPOCH = 42
FIXTURE_PROBE_NONCE = hashlib.sha256(b"assignment-probe-fixture-nonce").hexdigest()
SIGNER_ROLES: dict[str, ManifestRole] = {
    "auditor": "assignment_auditor",
    "issuer": "assignment_issuer",
    "security": "assignment_security",
}
MINERS: tuple[tuple[int, str], ...] = (
    (10, "MinerA"),
    (11, "MinerB"),
    (12, "MinerC"),
    (13, "MinerD"),
)


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


def label_digest(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def deterministic_key(label: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(label.encode("ascii")).digest())


def raw_public(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def signer_keys() -> dict[str, Ed25519PrivateKey]:
    return {key_id: deterministic_key(f"assignment-manifest-{key_id}") for key_id in SIGNER_ROLES}


def miner_key(hotkey: str) -> Ed25519PrivateKey:
    return deterministic_key(f"miner-service-{hotkey}")


def miner_service_public_key(hotkey: str) -> str:
    return raw_public(miner_key(hotkey)).hex()


def trusted_key(
    key_id: str,
    key: Ed25519PrivateKey,
    role: ManifestRole,
    *,
    valid_from: int = BASE_EPOCH - 1_000,
    valid_until: int = BASE_EPOCH + 100_000,
    revoked_at: int | None = None,
) -> TrustedManifestKey:
    public = raw_public(key)
    return TrustedManifestKey.model_validate(
        {
            "key_id": key_id,
            "algorithm": "ed25519",
            "public_key_base64": base64.b64encode(public).decode("ascii"),
            "public_key_sha256": hashlib.sha256(public).hexdigest(),
            "roles": [role],
            "purposes": [MANIFEST_PURPOSE],
            "valid_from_epoch": valid_from,
            "valid_until_epoch": valid_until,
            "revoked_at_epoch": revoked_at,
        }
    )


def build_policy(
    keys: dict[str, Ed25519PrivateKey],
    *,
    threshold: int = 2,
    required_roles: Sequence[ManifestRole] = ("assignment_auditor", "assignment_issuer"),
    key_windows: dict[str, tuple[int, int]] | None = None,
    revoked: dict[str, int | None] | None = None,
    max_age: int = 600,
    max_finalized_height_gap: int = 100,
    allowed_route_host_suffixes: Sequence[str] = (ROUTE_SUFFIX,),
    probe_timeout_millis: int = 5_000,
    max_response_bytes: int = 4_096,
    pinned_edge_leaf_certificate_sha256: Sequence[str] = (),
    central_authority: str = CENTRAL_AUTHORITY,
) -> AssignmentManifestTrustPolicy:
    key_models = []
    for key_id in sorted(keys):
        start, end = (key_windows or {}).get(key_id, (BASE_EPOCH - 1_000, BASE_EPOCH + 100_000))
        key_models.append(
            trusted_key(
                key_id,
                keys[key_id],
                SIGNER_ROLES[key_id],
                valid_from=start,
                valid_until=end,
                revoked_at=(revoked or {}).get(key_id),
            )
        )
    return build_assignment_manifest_trust_policy(
        central_authority_fingerprint_sha256=central_authority,
        threshold=threshold,
        required_roles=required_roles,
        trusted_keys=key_models,
        valid_from_epoch=BASE_EPOCH - 1_000,
        valid_until_epoch=BASE_EPOCH + 100_000,
        max_manifest_age_seconds=max_age,
        max_future_skew_seconds=5,
        max_manifest_lifetime_seconds=3_600,
        max_sequence_gap=4,
        max_finalized_height_gap=max_finalized_height_gap,
        allowed_route_host_suffixes=allowed_route_host_suffixes,
        probe_timeout_millis=probe_timeout_millis,
        max_response_bytes=max_response_bytes,
        pinned_edge_leaf_certificate_sha256=pinned_edge_leaf_certificate_sha256,
    )


def challenge_value(deployment_id: str) -> str:
    return label_digest(f"challenge-value-{deployment_id}")


def build_id(deployment_id: str) -> str:
    return label_digest(f"build-{deployment_id}")[:24]


def build_replica(
    deployment_id: str,
    miner_uid: int,
    miner_hotkey: str,
    *,
    generation: int = 1,
) -> AssignedReplica:
    return build_assigned_replica(
        miner_uid=miner_uid,
        miner_hotkey=miner_hotkey,
        miner_service_public_key=miner_service_public_key(miner_hotkey),
        generation=generation,
        assignment_nonce=label_digest(f"nonce-{deployment_id}-{miner_hotkey}-{generation}")[:32],
        deployment_id=deployment_id,
        ticket_digest_sha256=label_digest(f"ticket-{deployment_id}-{miner_hotkey}"),
        receipt_digest_sha256=label_digest(f"receipt-{deployment_id}-{miner_hotkey}"),
        chain_block=FINALIZED_HEIGHT - 60,
        expires_at_block=FINALIZED_HEIGHT + 60,
        ticket_issued_at_epoch=BASE_EPOCH - 500,
        ticket_expires_at_epoch=BASE_EPOCH + 3_500,
    )


def build_deployment(
    deployment_id: str,
    miners: Sequence[tuple[int, str]],
    *,
    campaign_sequence: int,
    attestation_requirement: AttestationRequirement = "miner_service_key_v1",
    route_suffix: str = ROUTE_SUFFIX,
) -> ActiveDeploymentAssignment:
    return build_active_deployment_assignment(
        deployment_id=deployment_id,
        campaign_sequence=campaign_sequence,
        route_host=f"{deployment_id}.{route_suffix}",
        build_id=build_id(deployment_id),
        challenge_sha256=hashlib.sha256(challenge_value(deployment_id).encode("ascii")).hexdigest(),
        image_digest="sha256:" + label_digest(f"image-{deployment_id}"),
        workload_spec_digest_sha256=label_digest(f"workload-{deployment_id}"),
        attestation_requirement=attestation_requirement,
        replicas=[build_replica(deployment_id, uid, hotkey) for uid, hotkey in miners],
    )


def fixture_deployments() -> list[ActiveDeploymentAssignment]:
    return [
        build_deployment(
            "fixture-alpha",
            MINERS[:3],
            campaign_sequence=1,
            attestation_requirement="miner_service_key_v1",
        ),
        build_deployment("fixture-beta", MINERS[1:], campaign_sequence=2),
    ]


def build_manifest(
    policy: AssignmentManifestTrustPolicy,
    deployments: Sequence[ActiveDeploymentAssignment],
    *,
    sequence: int = 1,
    previous: str | None = None,
    issued_at: int = BASE_EPOCH,
    expires_at: int = BASE_EPOCH + 3_600,
    finalized_height: int = FINALIZED_HEIGHT,
    finalized_block_hash: str = FINALIZED_BLOCK_HASH,
    route_suffix: str = ROUTE_SUFFIX,
    probe_port: int = PROBE_PORT,
) -> ActiveAssignmentManifest:
    return build_active_assignment_manifest(
        policy,
        finalized_height=finalized_height,
        finalized_block_hash=finalized_block_hash,
        finalized_epoch=FINALIZED_EPOCH,
        sequence=sequence,
        previous_manifest_digest_sha256=previous,
        issued_at_epoch=issued_at,
        expires_at_epoch=expires_at,
        route_host_suffix=route_suffix,
        probe_port=probe_port,
        deployments=deployments,
    )


def sign_manifest(
    manifest: ActiveAssignmentManifest,
    keys: dict[str, Ed25519PrivateKey],
    key_ids: Sequence[str] = ("auditor", "issuer"),
) -> list[AssignmentManifestSignatureEnvelope]:
    message = manifest_signature_message(manifest)
    return [
        build_manifest_signature_envelope(
            manifest,
            signer_key_id=key_id,
            signature_base64=base64.b64encode(keys[key_id].sign(message)).decode("ascii"),
        )
        for key_id in sorted(key_ids)
    ]


def sign_attestation(
    deployment: ActiveDeploymentAssignment,
    replica: AssignedReplica,
    *,
    probe_nonce: str,
    response_body_sha256: str | None = None,
    signing_key: Ed25519PrivateKey | None = None,
) -> MinerProbeAttestation:
    body_digest = response_body_sha256 or deployment.challenge_sha256
    unsigned = build_miner_probe_attestation(
        probe_nonce=probe_nonce,
        route_host=deployment.route_host,
        deployment_id=deployment.deployment_id,
        generation=replica.generation,
        assignment_nonce=replica.assignment_nonce,
        miner_uid=replica.miner_uid,
        miner_hotkey=replica.miner_hotkey,
        miner_service_public_key=replica.miner_service_public_key,
        response_body_sha256=body_digest,
        signature_hex="0" * 128,
    )
    key = signing_key or miner_key(replica.miner_hotkey)
    signature = key.sign(miner_probe_attestation_message(unsigned))
    return unsigned.model_copy(update={"signature_hex": signature.hex()})


def attestation_header(attestation: MinerProbeAttestation) -> str:
    document = attestation.model_dump(mode="json", by_alias=True)
    return base64.b64encode(canonical(document)).decode("ascii")


def serving_response(
    deployment: ActiveDeploymentAssignment,
    *,
    attestation: MinerProbeAttestation | None = None,
    latency_millis: int = 42,
    tls_leaf_certificate_sha256: str | None = None,
) -> ProbeResponse:
    headers: list[tuple[str, str]] = [
        ("Content-Type", "text/plain"),
        ("X-Build-ID", deployment.build_id),
        ("Cache-Control", "private, no-store"),
    ]
    if attestation is not None:
        headers.append(("X-Miss-Probe-Attestation", attestation_header(attestation)))
    return ProbeResponse(
        status=200,
        headers=tuple(headers),
        body=challenge_value(deployment.deployment_id).encode("ascii"),
        latency_millis=latency_millis,
        tls_leaf_certificate_sha256=tls_leaf_certificate_sha256,
    )


@dataclass(frozen=True)
class Context:
    keys: dict[str, Ed25519PrivateKey]
    policy: AssignmentManifestTrustPolicy
    deployments: list[ActiveDeploymentAssignment]
    manifest: ActiveAssignmentManifest
    signatures: list[AssignmentManifestSignatureEnvelope]
    state: AssignmentManifestChainState
    verification: ManifestVerificationResult
    attestation: MinerProbeAttestation
    observations: list[ProbeObservation]
    report: ValidatorProbeReport


def make_context(
    *,
    threshold: int = 2,
    required_roles: Sequence[ManifestRole] = ("assignment_auditor", "assignment_issuer"),
    signed_key_ids: Sequence[str] = ("auditor", "issuer"),
    key_windows: dict[str, tuple[int, int]] | None = None,
    revoked: dict[str, int | None] | None = None,
    evaluation_epoch: int = EVALUATION_EPOCH,
    max_age: int = 600,
) -> Context:
    keys = signer_keys()
    policy = build_policy(
        keys,
        threshold=threshold,
        required_roles=required_roles,
        key_windows=key_windows,
        revoked=revoked,
        max_age=max_age,
    )
    deployments = fixture_deployments()
    manifest = build_manifest(policy, deployments)
    signatures = sign_manifest(manifest, keys, signed_key_ids)
    state = build_initial_manifest_chain_state(policy)
    verification = verify_active_assignment_manifest(
        manifest,
        signatures,
        policy,
        state,
        evaluation_epoch=evaluation_epoch,
    )
    alpha = manifest.deployments[0]
    attestation = sign_attestation(alpha, alpha.replicas[0], probe_nonce=FIXTURE_PROBE_NONCE)
    beta = manifest.deployments[1]
    beta_probe_nonce = label_digest("fixture-beta-probe-nonce")
    # A different replica answers the beta probe, so the committed fixtures
    # demonstrate per-replica attribution of the actual responder.
    beta_attestation = sign_attestation(beta, beta.replicas[1], probe_nonce=beta_probe_nonce)
    observations = [
        evaluate_probe_response(
            alpha,
            policy,
            probe_nonce=FIXTURE_PROBE_NONCE,
            result=serving_response(alpha, attestation=attestation),
        ),
        evaluate_probe_response(
            beta,
            policy,
            probe_nonce=beta_probe_nonce,
            result=serving_response(beta, attestation=beta_attestation, latency_millis=57),
        ),
    ]
    report = build_validator_probe_report(
        verification,
        policy,
        state,
        observations,
        validator_uid=7,
        validator_hotkey="ValidatorA",
        evaluation_epoch=evaluation_epoch,
        edge_origin_override=False,
    )
    return Context(
        keys=keys,
        policy=policy,
        deployments=deployments,
        manifest=manifest,
        signatures=signatures,
        state=state,
        verification=verification,
        attestation=attestation,
        observations=observations,
        report=report,
    )


def fixture_documents(context: Context) -> dict[str, bytes]:
    return {
        "active-assignment-manifest": active_assignment_manifest_bytes(context.manifest),
        "assignment-manifest-trust-policy": assignment_manifest_trust_policy_bytes(context.policy),
        "assignment-manifest-signature-envelope": assignment_manifest_signature_envelope_bytes(
            context.signatures[0]
        ),
        "assignment-manifest-chain-state": assignment_manifest_chain_state_bytes(
            context.verification.next_chain_state
        ),
        "miner-probe-attestation": miner_probe_attestation_bytes(context.attestation),
        "validator-probe-report": validator_probe_report_bytes(context.report),
    }


SCHEMA_MODELS: dict[str, type[BaseModel]] = {
    "active-assignment-manifest": ActiveAssignmentManifest,
    "assignment-manifest-trust-policy": AssignmentManifestTrustPolicy,
    "assignment-manifest-signature-envelope": AssignmentManifestSignatureEnvelope,
    "assignment-manifest-chain-state": AssignmentManifestChainState,
    "miner-probe-attestation": MinerProbeAttestation,
    "validator-probe-report": ValidatorProbeReport,
}


def schema_bytes(model: type[BaseModel]) -> bytes:
    rendered = json.dumps(model.model_json_schema(), indent=2, sort_keys=True, ensure_ascii=True)
    return (rendered + "\n").encode("ascii")


def write_fixtures(root: Path) -> None:
    context = make_context()
    for stem, rendered in fixture_documents(context).items():
        (root / "contracts" / "fixtures" / f"{stem}.v1.json").write_bytes(rendered)
    for stem, model in SCHEMA_MODELS.items():
        (root / "contracts" / "schemas" / f"{stem}.v1.schema.json").write_bytes(schema_bytes(model))


if __name__ == "__main__":
    write_fixtures(ROOT)
