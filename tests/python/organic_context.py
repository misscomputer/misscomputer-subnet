# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic organic manifest v2 / probe / scoring fixtures.

Running this module directly regenerates the committed scoring-track
``contracts/fixtures`` and ``contracts/schemas`` entries (observation, epoch
score, availability score). Manifest v2, probe authorization and attestation
v2 are canonical contract-track documents built here with their own types.
Every key and nonce derives from a fixed label, so the bytes are reproducible
and hold no secret.
"""

from __future__ import annotations

import base64
import hashlib
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from assignment_probe_context import (
    BASE_EPOCH,
    FINALIZED_BLOCK_HASH,
    FINALIZED_EPOCH,
    FINALIZED_HEIGHT,
    MINERS,
    PROBE_PORT,
    ROUTE_SUFFIX,
    build_policy,
    label_digest,
    miner_key,
    miner_service_public_key,
    schema_bytes,
    signer_keys,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from document_fixtures import (
    deployment_document,
    health_probe_document,
    manifest_document,
    manifest_signature_envelope,
    replica_document,
)
from pydantic import BaseModel

from misscomputer_subnet.assignment_probe import (
    AssignmentManifestSignatureEnvelope,
    AssignmentManifestTrustPolicy,
    ProbeResponse,
    ProbeTransportFailure,
)
from misscomputer_subnet.chain import MetagraphSnapshot, NeuronRecord
from misscomputer_subnet.checkpoint_score_contracts import (
    CanonicalScoreReport,
    build_canonical_score_report,
    build_scoring_policy,
)
from misscomputer_subnet.contract_codec import model_bytes
from misscomputer_subnet.organic_contracts import (
    ActiveAssignmentManifestV2,
    MinerProbeAttestationV2,
    OrganicDeploymentAssignment,
    OrganicProbeAuthorization,
    format_timestamp,
    miner_probe_attestation_v2_message,
    response_header_sha256,
)
from misscomputer_subnet.organic_manifest import organic_manifest_signature_message
from misscomputer_subnet.organic_probe import (
    ATTESTATION_HEADER,
    UPSTREAM_RESPONSE_HEADER,
    OrganicProbeObservation,
    attestation_v2_header,
    build_probe_authorization,
    evaluate_organic_probe,
    find_replica,
    timestamp_epoch_seconds,
)
from misscomputer_subnet.organic_scoring import (
    OrganicAvailabilityScore,
    OrganicEpochScore,
    aggregate_organic_window,
    score_organic_epoch,
)
from misscomputer_subnet.validator_decision import (
    RegisteredMiner,
    RegisteredMinerSet,
    TerminalManifestObservation,
    ValidatorWeightDecision,
    WeightDecisionPolicy,
    decide_weight_submission,
)
from misscomputer_subnet.weight_plan import snapshot_identity_fingerprint

ROOT = Path(__file__).resolve().parents[2]
VALIDATOR_HOTKEY = "ValidatorSelf"
EPOCH_SECONDS = 300
EPOCH = BASE_EPOCH // EPOCH_SECONDS
EPOCH_START = EPOCH * EPOCH_SECONDS
#: Central score authority pinned by the checkpoint relay fixtures.
CENTRAL_SCORE_AUTHORITY = "919052900096fe34cae41b9655c842c617fed377a0db615c798640f30a4c3c79"
SHOP = "shop-k3j9x0q2ab"
BLOG = "blog-7h2m4n6p8r"
RESPONSE_HEADERS: list[tuple[str, str]] = [
    ("Content-Type", "text/plain; charset=utf-8"),
    ("Set-Cookie", "a=1"),
]

MINER_BY_HOTKEY = {hotkey: uid for uid, hotkey in MINERS}


def fake_hotkey_signature(message: bytes) -> bytes:
    """Stand-in for the validator's sr25519 hotkey signature; the edge verifies the real one."""

    return hashlib.sha512(b"validator-hotkey-signature\x00" + message).digest()


def build_deployment(
    deployment_id: str,
    hotkeys: Sequence[str],
    *,
    method: str = "GET",
    path: str = "/healthz",
    expected_statuses: Sequence[int] = (200,),
    marker: str | None = "ok",
    lease_expires_at: int = BASE_EPOCH + 3_000,
    generation: int = 1,
) -> OrganicDeploymentAssignment:
    return deployment_document(
        deployment_id=deployment_id,
        route_host=f"{deployment_id}.{ROUTE_SUFFIX}",
        artifact_digest="sha256:" + label_digest(f"artifact-{deployment_id}"),
        health=health_probe_document(
            method=method,
            path=path,
            expected_statuses=expected_statuses,
            response_marker=marker,
        ),
        replicas=[
            replica_document(
                deployment_id=deployment_id,
                miner_uid=MINER_BY_HOTKEY[hotkey],
                miner_hotkey=hotkey,
                miner_service_public_key=miner_service_public_key(hotkey),
                miner_tls_certificate_sha256=label_digest(f"tls-{hotkey}"),
                generation=generation,
                assignment_nonce=label_digest(f"nonce-{deployment_id}-{hotkey}-{generation}")[:32],
                ticket_digest="sha256:" + label_digest(f"ticket-{deployment_id}-{hotkey}"),
                receipt_digest="sha256:" + label_digest(f"receipt-{deployment_id}-{hotkey}"),
                chain_block=FINALIZED_HEIGHT - 10,
                expires_at_block=FINALIZED_HEIGHT + 600,
                activated_at_epoch=BASE_EPOCH - 900,
                expires_at_epoch=lease_expires_at,
            )
            for hotkey in hotkeys
        ],
    )


def fixture_deployments() -> list[OrganicDeploymentAssignment]:
    return [
        build_deployment(SHOP, ["MinerA", "MinerB", "MinerC"]),
        build_deployment(
            BLOG,
            ["MinerB", "MinerC", "MinerD"],
            path="/",
            expected_statuses=(204, 200),
            marker=None,
        ),
    ]


def build_manifest(
    policy: AssignmentManifestTrustPolicy,
    deployments: Sequence[OrganicDeploymentAssignment],
    *,
    sequence: int = 1,
    previous: str | None = None,
    issued_at: int = BASE_EPOCH - 60,
    expires_at: int = BASE_EPOCH + 1_800,
) -> ActiveAssignmentManifestV2:
    return manifest_document(
        policy,
        finalized_height=FINALIZED_HEIGHT + sequence - 1,
        finalized_block_hash=FINALIZED_BLOCK_HASH
        if sequence == 1
        else label_digest(f"b{sequence}"),
        finalized_epoch=FINALIZED_EPOCH,
        sequence=sequence,
        previous_manifest_digest_sha256=previous,
        issued_at_epoch=issued_at,
        expires_at_epoch=expires_at,
        route_host_suffix=ROUTE_SUFFIX,
        probe_port=PROBE_PORT,
        deployments=deployments,
    )


def sign_manifest(
    manifest: ActiveAssignmentManifestV2,
    keys: dict[str, Ed25519PrivateKey],
    key_ids: Sequence[str] = ("auditor", "issuer"),
    *,
    message: bytes | None = None,
) -> list[AssignmentManifestSignatureEnvelope]:
    signed = organic_manifest_signature_message(manifest) if message is None else message
    return [
        manifest_signature_envelope(
            manifest,
            signer_key_id=key_id,
            signature_base64=base64.b64encode(keys[key_id].sign(signed)).decode("ascii"),
        )
        for key_id in sorted(key_ids)
    ]


def probe_nonce(label: str) -> str:
    return label_digest(f"probe-nonce-{label}")


def authorize(
    manifest: ActiveAssignmentManifestV2,
    endpoint_id: str,
    *,
    issued_at: int,
    nonce: str,
) -> OrganicProbeAuthorization:
    deployment, replica = find_replica(manifest, endpoint_id)
    return build_probe_authorization(
        validator_hotkey=VALIDATOR_HOTKEY,
        endpoint_id=endpoint_id,
        generation=replica.generation,
        method=deployment.health.method,
        path=deployment.health.path,
        nonce=nonce,
        issued_at_epoch=issued_at,
        sign=fake_hotkey_signature,
    )


def sign_attestation_v2(
    manifest: ActiveAssignmentManifestV2,
    authorization: OrganicProbeAuthorization,
    *,
    status: int,
    body: bytes,
    key: Ed25519PrivateKey | None = None,
    nonce: str | None = None,
    observed_offset_micros: int = 40_250,
) -> MinerProbeAttestationV2:
    deployment, replica = find_replica(manifest, authorization.endpoint_id)
    observed = timestamp_epoch_seconds(authorization.issued_at) * 1_000_000 + observed_offset_micros
    document: dict[str, object] = {
        "schema": "miss.computer/misscomputer-subnet/miner-probe-attestation",
        "schema_version": 2,
        "endpoint_id": replica.endpoint_id,
        "generation": replica.generation,
        "ticket_digest": replica.ticket_digest,
        "artifact_digest": deployment.artifact_digest,
        "validator_hotkey": authorization.validator_hotkey,
        "probe_nonce": authorization.nonce if nonce is None else nonce,
        "request_method": authorization.method,
        "request_path": authorization.path,
        "response_status": status,
        "response_body_sha256": hashlib.sha256(body).hexdigest(),
        "response_header_sha256": response_header_sha256(RESPONSE_HEADERS),
        "observed_at": format_timestamp(
            datetime.fromtimestamp(observed // 1_000_000, UTC).replace(
                microsecond=observed % 1_000_000
            )
        ),
        "signature_hex": "00" * 64,
    }
    unsigned = MinerProbeAttestationV2.model_validate(document)
    signer = miner_key(replica.miner_hotkey) if key is None else key
    signature = signer.sign(miner_probe_attestation_v2_message(unsigned)).hex()
    return MinerProbeAttestationV2.model_validate({**document, "signature_hex": signature})


BEHAVIORS = (
    "success",
    "edge_down",
    "transport",
    "app_status",
    "app_marker",
    "no_attestation",
    "replayed_attestation",
    "foreign_key",
    "altered_body",
)


def probe(
    policy: AssignmentManifestTrustPolicy,
    manifest: ActiveAssignmentManifestV2,
    endpoint_id: str,
    *,
    offset_seconds: int,
    behavior: str = "success",
    label: str | None = None,
    epoch_start: int = EPOCH_START,
) -> OrganicProbeObservation:
    """Run one probe through :func:`evaluate_organic_probe` with a scripted replica."""

    issued_at = epoch_start + offset_seconds
    authorization = authorize(
        manifest,
        endpoint_id,
        issued_at=issued_at,
        nonce=probe_nonce(label or f"{endpoint_id}-{issued_at}"),
    )
    if behavior == "transport":
        return evaluate_organic_probe(
            manifest,
            policy,
            authorization,
            ProbeTransportFailure(code="connection_failed", latency_millis=12),
        )
    deployment, _ = find_replica(manifest, endpoint_id)
    status = deployment.health.expected_statuses[0]
    body = b"ok\n"
    if behavior == "app_status":
        status = 503
    if behavior == "app_marker":
        body = b"booting\n"
    headers: list[tuple[str, str]] = [("content-type", "text/plain")]
    if behavior == "edge_down":
        return evaluate_organic_probe(
            manifest,
            policy,
            authorization,
            ProbeResponse(502, tuple(headers), b"bad gateway", 20, None),
        )
    headers.append((UPSTREAM_RESPONSE_HEADER, "replica"))
    if behavior != "no_attestation":
        attestation = sign_attestation_v2(
            manifest,
            authorization,
            status=status,
            body=body,
            key=Ed25519PrivateKey.from_private_bytes(b"\x07" * 32)
            if behavior == "foreign_key"
            else None,
            nonce=probe_nonce("stale") if behavior == "replayed_attestation" else None,
        )
        headers.append((ATTESTATION_HEADER, attestation_v2_header(attestation)))
    if behavior == "altered_body":
        body = b"ok\n<!-- injected -->"
    return evaluate_organic_probe(
        manifest,
        policy,
        authorization,
        ProbeResponse(status, tuple(headers), body, 35, None),
    )


def endpoint(manifest: ActiveAssignmentManifestV2, deployment_id: str, hotkey: str) -> str:
    for item in manifest.deployments:
        if item.deployment_id == deployment_id:
            for replica in item.replicas:
                if replica.miner_hotkey == hotkey:
                    return replica.endpoint_id
    raise KeyError((deployment_id, hotkey))


def epoch_probes(
    policy: AssignmentManifestTrustPolicy,
    manifest: ActiveAssignmentManifestV2,
    behaviors: dict[str, Sequence[str]],
    *,
    epoch_start: int = EPOCH_START,
) -> list[OrganicProbeObservation]:
    """One scripted epoch: ``behaviors[endpoint_id]`` lists one behavior per probe."""

    observations: list[OrganicProbeObservation] = []
    for endpoint_id, script in behaviors.items():
        for index, behavior in enumerate(script):
            observations.append(
                probe(
                    policy,
                    manifest,
                    endpoint_id,
                    offset_seconds=10 + index * 100,
                    behavior=behavior,
                    epoch_start=epoch_start,
                )
            )
    return observations


@dataclass(frozen=True)
class OrganicContext:
    policy: AssignmentManifestTrustPolicy
    manifest: ActiveAssignmentManifestV2
    signatures: list[AssignmentManifestSignatureEnvelope]
    authorization: OrganicProbeAuthorization
    attestation: MinerProbeAttestationV2
    observation: OrganicProbeObservation
    epoch: OrganicEpochScore
    score: OrganicAvailabilityScore
    central_report: CanonicalScoreReport


def make_context() -> OrganicContext:
    keys = signer_keys()
    policy = build_policy(keys)
    manifest = build_manifest(policy, fixture_deployments())
    shop_a = endpoint(manifest, SHOP, "MinerA")
    authorization = authorize(
        manifest,
        shop_a,
        issued_at=EPOCH_START + 10,
        nonce=probe_nonce(f"{shop_a}-{EPOCH_START + 10}"),
    )
    attestation = sign_attestation_v2(manifest, authorization, status=200, body=b"ok\n")
    script: dict[str, Sequence[str]] = {
        shop_a: ("success", "success", "success"),
        endpoint(manifest, SHOP, "MinerB"): ("success", "edge_down", "success"),
        endpoint(manifest, SHOP, "MinerC"): ("success", "no_attestation"),
        endpoint(manifest, BLOG, "MinerB"): ("success", "success", "success"),
        endpoint(manifest, BLOG, "MinerC"): ("success",),
        endpoint(manifest, BLOG, "MinerD"): ("replayed_attestation", "success", "success"),
    }
    observations = epoch_probes(policy, manifest, script)
    epoch = score_organic_epoch(
        [manifest], observations, validator_hotkey=VALIDATOR_HOTKEY, epoch_index=EPOCH
    )
    score = aggregate_organic_window([epoch])
    return OrganicContext(
        policy=policy,
        manifest=manifest,
        signatures=sign_manifest(manifest, keys),
        authorization=authorization,
        attestation=attestation,
        observation=observations[0],
        epoch=epoch,
        score=score,
        central_report=build_canonical_score_report(
            score,
            build_scoring_policy(
                epoch_seconds=EPOCH_SECONDS, probes_per_endpoint=3, min_attempts=2
            ),
            central_authority_fingerprint_sha256=CENTRAL_SCORE_AUTHORITY,
            finalized_height=FINALIZED_HEIGHT,
            finalized_block_hash=FINALIZED_BLOCK_HASH,
        ),
    )


VALIDATOR_UID = 7
#: Registered miners: MinerE is registered but never assigned (unscored).
REGISTERED = (*MINERS, (14, "MinerE"))
REGISTERED_HEIGHT = FINALIZED_HEIGHT + 50
REGISTERED_TEMPO = 100
REGISTERED_BLOCK_HASH = label_digest("organic-registered-block")
WINDOW_START = EPOCH_START
WINDOW_END = EPOCH_START + 2 * EPOCH_SECONDS
DECISION_POLICY = WeightDecisionPolicy(min_scored_epochs=2, max_registered_height_gap=600)


def metagraph_snapshot(
    *, miners: Sequence[tuple[int, str]] = REGISTERED, block: int = REGISTERED_HEIGHT
) -> MetagraphSnapshot:
    return MetagraphSnapshot(
        network="finney",
        netuid=24,
        block=block,
        tempo=REGISTERED_TEMPO,
        neurons=(
            NeuronRecord(
                uid=VALIDATOR_UID,
                hotkey=VALIDATOR_HOTKEY,
                validator_permit=True,
                tao_stake=1_000.0,
                axon=None,
            ),
            *(
                NeuronRecord(
                    uid=uid,
                    hotkey=hotkey,
                    validator_permit=False,
                    tao_stake=1.0,
                    axon="127.0.0.1:8091",
                )
                for uid, hotkey in miners
            ),
        ),
        finalized=True,
    )


def registered_set(*, block: int = REGISTERED_HEIGHT) -> RegisteredMinerSet:
    snapshot = metagraph_snapshot(block=block)
    return RegisteredMinerSet(
        network="finney",
        netuid=24,
        finalized=True,
        finalized_height=block,
        finalized_block_hash=REGISTERED_BLOCK_HASH,
        finalized_epoch=block // REGISTERED_TEMPO,
        validator_uid=VALIDATOR_UID,
        validator_hotkey=VALIDATOR_HOTKEY,
        miners=[RegisteredMiner(uid=uid, hotkey=hotkey) for uid, hotkey in REGISTERED],
        metagraph_identity_fingerprint_sha256=snapshot_identity_fingerprint(snapshot),
    )


@dataclass(frozen=True)
class WindowContext:
    policy: AssignmentManifestTrustPolicy
    manifest: ActiveAssignmentManifestV2
    epochs: list[OrganicEpochScore]
    registered: RegisteredMinerSet
    decision: ValidatorWeightDecision


def window_epochs(
    policy: AssignmentManifestTrustPolicy, manifest: ActiveAssignmentManifestV2
) -> list[OrganicEpochScore]:
    """Two scored epochs: MinerB drops one probe in epoch two, MinerD replays an attestation."""

    shop_b = endpoint(manifest, SHOP, "MinerB")
    blog_d = endpoint(manifest, BLOG, "MinerD")
    healthy = {
        replica.endpoint_id: ("success",) * 3
        for deployment in manifest.deployments
        for replica in deployment.replicas
    }
    first = epoch_probes(
        policy, manifest, {**healthy, blog_d: ("replayed_attestation",) + ("success",) * 2}
    )
    second = epoch_probes(
        policy,
        manifest,
        {**healthy, shop_b: ("success", "edge_down", "success")},
        epoch_start=EPOCH_START + EPOCH_SECONDS,
    )
    return [
        score_organic_epoch(
            [manifest], first, validator_hotkey=VALIDATOR_HOTKEY, epoch_index=EPOCH
        ),
        score_organic_epoch(
            [manifest], second, validator_hotkey=VALIDATOR_HOTKEY, epoch_index=EPOCH + 1
        ),
    ]


def decide(
    context_policy: AssignmentManifestTrustPolicy,
    manifest: ActiveAssignmentManifestV2,
    epochs: Sequence[OrganicEpochScore],
    *,
    terminal: TerminalManifestObservation | None = None,
    registered: RegisteredMinerSet | None = None,
    decision_policy: WeightDecisionPolicy = DECISION_POLICY,
) -> ValidatorWeightDecision:
    return decide_weight_submission(
        epochs,
        manifests=[manifest],
        terminal=terminal
        or TerminalManifestObservation(
            status="verified", evaluated_at_epoch=WINDOW_END, manifest=manifest
        ),
        registered=registered or registered_set(),
        trust_policies=[context_policy],
        window_start_epoch=WINDOW_START,
        window_end_epoch=WINDOW_END,
        decision_policy=decision_policy,
    )


def make_window_context() -> WindowContext:
    # A one-hour manifest age bound lets the window's manifest close it.
    policy = build_policy(signer_keys(), max_age=3_600)
    manifest = build_manifest(policy, fixture_deployments())
    epochs = window_epochs(policy, manifest)
    return WindowContext(
        policy=policy,
        manifest=manifest,
        epochs=epochs,
        registered=registered_set(),
        decision=decide(policy, manifest, epochs),
    )


#: Scoring-track contract stem -> (schema version, model).
SCHEMA_MODELS: dict[str, tuple[int, type[BaseModel]]] = {
    "organic-probe-observation": (1, OrganicProbeObservation),
    "organic-epoch-score": (1, OrganicEpochScore),
    "organic-availability-score": (1, OrganicAvailabilityScore),
    "organic-central-score-report": (1, CanonicalScoreReport),
    "validator-weight-decision": (2, ValidatorWeightDecision),
}


def fixture_documents(context: OrganicContext | None = None) -> dict[str, bytes]:
    context = context or make_context()
    documents: dict[str, BaseModel] = {
        "organic-probe-observation": context.observation,
        "organic-epoch-score": context.epoch,
        "organic-availability-score": context.score,
        "organic-central-score-report": context.central_report,
        "validator-weight-decision": make_window_context().decision,
    }
    return {stem: model_bytes(value, SCHEMA_MODELS[stem][1]) for stem, value in documents.items()}


def fixture_path(stem: str, *, schema: bool = False) -> Path:
    version = SCHEMA_MODELS[stem][0]
    group, suffix = ("schemas", ".schema.json") if schema else ("fixtures", ".json")
    return ROOT / "contracts" / group / f"{stem}.v{version}{suffix}"


def write_fixtures() -> None:
    for stem, rendered in fixture_documents().items():
        fixture_path(stem).write_bytes(rendered)
    for stem, (_, model) in SCHEMA_MODELS.items():
        fixture_path(stem, schema=True).write_bytes(schema_bytes(model))


if __name__ == "__main__":
    write_fixtures()
