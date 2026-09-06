# SPDX-License-Identifier: AGPL-3.0-only
"""Versioned transactional active-assignment snapshot contract (``v1``).

The snapshot is the credential-safe, single-revision view of "which
assignments are route-active right now" that the scheduler runtime exports and
the manifest publisher consumes. It freezes the *producer side* of the
active-assignment pipeline so that the runtime snapshot endpoint, the publisher,
and every validator can be built in parallel against one boundary.

What it binds
-------------
- deployment identity (``deployment_id``, ``campaign_sequence``, ``route_host``,
  ``build_id``, ``challenge_path``, image and workload-spec digests);
- the exact endpoint incarnation of every replica (``replica_id`` and
  ``endpoint_id`` derived from ``generation`` and ``assignment_nonce`` exactly
  as the Go ``protocol.EndpointID`` derives them);
- miner UID, hotkey, and service public key;
- activation timing (``chain_block``/``expires_at_block``, the signed ticket
  window, and ``route_activated_at_epoch``);
- the challenge **digest only**, the ticket and ready-receipt **digests only**;
- the finalized chain context the scheduler held at capture;
- transactional sequencing: ``snapshot_sequence`` (one per capture, strictly
  increasing) and ``state_revision`` (the scheduler's durable revision the
  capture was read at under one lock; two captures at one revision must carry
  identical deployments).

What it never carries
---------------------
The raw challenge value, retained ticket or receipt bytes, credentials, axon
addresses, TLS pins, artifact keys, encrypted image keys, provider or tunnel
identifiers, scheduler queue state, signer seeds, wallets, or weights. The test
suite scans the golden fixture for every one of those.

Relationship to the manifest
----------------------------
:func:`project_manifest_deployments` is the only projection from a snapshot to
``active-assignment-manifest`` v1 deployments, and the snapshot seals the digest
of that projection (``projected_assignment_vector_digest_sha256``). A manifest
is derived from a snapshot when :func:`verify_manifest_derived_from_snapshot`
accepts the pair; the publisher must refuse to publish otherwise.

This module is pure: no clock, network, file, process, environment, wallet,
chain, randomness, or signing capability.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Final, Literal, NoReturn, Self

from pydantic import Field, model_validator

from .assignment_probe import (
    MAX_DEPLOYMENTS,
    MAX_REPLICAS,
    UID,
    ActiveAssignmentManifest,
    ActiveDeploymentAssignment,
    AttestationRequirement,
    ChallengePath,
    DeploymentID,
    Digest,
    EndpointID,
    Epoch,
    Hex24,
    Hex32,
    Hex64,
    Hotkey,
    ImageDigest,
    Port,
    PositiveEpoch,
    ReplicaID,
    RouteHost,
    build_active_deployment_assignment,
    build_assigned_replica,
)
from .contract_codec import (
    StrictFrozenModel,
    digest,
    model_bytes,
    model_document,
    parse_model,
    revalidate,
    verify_model_digest,
)
from .ed25519_trust import decode_ed25519_public_key_hex

SNAPSHOT_SCHEMA: Final = "miss.computer/misscomputer-subnet/active-assignment-snapshot"
SNAPSHOT_SCHEMA_VERSION: Final = 1
SNAPSHOT_PURPOSE: Final = "active_assignment_snapshot_v1"
MAINNET_NETWORK: Final = "finney"
MAINNET_NETUID: Final = 24
#: A ticket issued after the capture instant is impossible for a consistent
#: read; this is the only clock skew tolerated between signer and capture.
TICKET_MAX_FUTURE_SKEW_SECONDS: Final = 30
MAX_SNAPSHOT_BYTES: Final = 64 * 1_024 * 1_024

SnapshotRejectionCode = Literal[
    "snapshot_authority_mismatch",
    "snapshot_capture_rollback",
    "snapshot_finalized_fork",
    "snapshot_finalized_rollback",
    "snapshot_manifest_chain_mismatch",
    "snapshot_manifest_issued_at_mismatch",
    "snapshot_manifest_route_mismatch",
    "snapshot_manifest_vector_mismatch",
    "snapshot_network_mismatch",
    "snapshot_revision_content_divergence",
    "snapshot_revision_rollback",
    "snapshot_sequence_not_increasing",
]


class AssignmentSnapshotError(ValueError):
    """Stable, sanitized fail-closed snapshot succession or derivation rejection."""

    def __init__(self, code: SnapshotRejectionCode) -> None:
        super().__init__(code)
        self.code = code


def _reject(code: SnapshotRejectionCode) -> NoReturn:
    raise AssignmentSnapshotError(code)


class SnapshotReplica(StrictFrozenModel):
    """One route-active replica: exact incarnation, identity, digests, and timing."""

    miner_uid: UID
    miner_hotkey: Hotkey
    miner_service_public_key: Hex64
    generation: PositiveEpoch
    assignment_nonce: Hex32
    replica_id: ReplicaID
    endpoint_id: EndpointID
    ticket_digest_sha256: Digest
    receipt_digest_sha256: Digest
    chain_block: Epoch
    expires_at_block: PositiveEpoch
    ticket_issued_at_epoch: Epoch
    ticket_expires_at_epoch: PositiveEpoch
    route_state: Literal["active"]
    #: Instant the edge activated this exact incarnation (at or after the
    #: ready receipt). Consumers anchor activation grace on it.
    route_activated_at_epoch: Epoch

    @model_validator(mode="after")
    def canonical_replica(self) -> Self:
        decode_ed25519_public_key_hex(self.miner_service_public_key)
        if self.expires_at_block <= self.chain_block:
            raise ValueError("replica_block_window_invalid")
        if self.ticket_expires_at_epoch <= self.ticket_issued_at_epoch:
            raise ValueError("replica_ticket_window_invalid")
        if self.ticket_digest_sha256 == self.receipt_digest_sha256:
            raise ValueError("replica_digest_binding_invalid")
        if self.route_activated_at_epoch < self.ticket_issued_at_epoch:
            raise ValueError("replica_activation_order_invalid")
        return self


class SnapshotDeployment(StrictFrozenModel):
    """One route-active deployment and its replicas, challenge digest only."""

    deployment_id: DeploymentID
    campaign_sequence: PositiveEpoch
    route_host: RouteHost
    challenge_path: ChallengePath
    build_id: Hex24
    challenge_sha256: Digest
    expected_status: Literal[200]
    image_digest: ImageDigest
    workload_spec_digest_sha256: Digest
    attestation_requirement: AttestationRequirement
    replicas: list[SnapshotReplica] = Field(min_length=1, max_length=MAX_REPLICAS)

    @model_validator(mode="after")
    def canonical_deployment(self) -> Self:
        if self.challenge_path != f"/__challenge/{self.build_id}":
            raise ValueError("deployment_challenge_path_invalid")
        keys = [(item.miner_uid, item.miner_hotkey) for item in self.replicas]
        if keys != sorted(set(keys)):
            raise ValueError("deployment_replicas_not_canonical")
        if len({item.miner_uid for item in self.replicas}) != len(self.replicas):
            raise ValueError("deployment_replica_uid_duplicate")
        if len({item.miner_hotkey for item in self.replicas}) != len(self.replicas):
            raise ValueError("deployment_replica_hotkey_duplicate")
        if len({item.assignment_nonce for item in self.replicas}) != len(self.replicas):
            raise ValueError("deployment_replica_nonce_duplicate")
        for item in self.replicas:
            expected_replica = f"{self.deployment_id}-{item.miner_hotkey}"
            expected_endpoint = f"{expected_replica}-g{item.generation}-{item.assignment_nonce}"
            if item.replica_id != expected_replica or item.endpoint_id != expected_endpoint:
                raise ValueError("deployment_replica_identity_invalid")
        return self


class ActiveAssignmentSnapshot(StrictFrozenModel):
    """One consistent, credential-safe capture of every route-active assignment."""

    contract_schema: Literal["miss.computer/misscomputer-subnet/active-assignment-snapshot"] = (
        Field(alias="schema")
    )
    schema_version: Literal[1]
    purpose: Literal["active_assignment_snapshot_v1"]
    network: Literal["finney"]
    netuid: Literal[24]
    central_authority_fingerprint_sha256: Digest
    snapshot_sequence: PositiveEpoch
    state_revision: Epoch
    captured_at_epoch: Epoch
    finalized_height: Epoch
    finalized_block_hash: Digest
    finalized_epoch: Epoch
    route_host_suffix: RouteHost
    probe_scheme: Literal["https"]
    probe_port: Port
    #: Empty means "nothing is route-active"; that is a valid transactional
    #: state, and a publisher must not derive a manifest from it.
    deployments: list[SnapshotDeployment] = Field(max_length=MAX_DEPLOYMENTS)
    projected_assignment_vector_digest_sha256: Digest
    snapshot_digest_sha256: Digest

    @model_validator(mode="after")
    def canonical_snapshot(self) -> Self:
        deployment_ids = [item.deployment_id for item in self.deployments]
        if deployment_ids != sorted(set(deployment_ids)):
            raise ValueError("snapshot_deployments_not_canonical")
        route_hosts = [item.route_host for item in self.deployments]
        if len(set(route_hosts)) != len(route_hosts):
            raise ValueError("snapshot_route_host_duplicate")
        uid_to_hotkey: dict[int, str] = {}
        hotkey_to_uid: dict[str, int] = {}
        for item in self.deployments:
            if item.route_host != f"{item.deployment_id}.{self.route_host_suffix}":
                raise ValueError("snapshot_route_host_invalid")
            for replica in item.replicas:
                if not replica.chain_block <= self.finalized_height < replica.expires_at_block:
                    raise ValueError("snapshot_replica_block_window_invalid")
                if replica.ticket_expires_at_epoch <= self.captured_at_epoch:
                    raise ValueError("snapshot_replica_ticket_expired")
                if replica.ticket_issued_at_epoch > (
                    self.captured_at_epoch + TICKET_MAX_FUTURE_SKEW_SECONDS
                ):
                    raise ValueError("snapshot_replica_ticket_issued_after_capture")
                if replica.route_activated_at_epoch > self.captured_at_epoch:
                    raise ValueError("snapshot_replica_activated_after_capture")
                if uid_to_hotkey.setdefault(replica.miner_uid, replica.miner_hotkey) != (
                    replica.miner_hotkey
                ) or hotkey_to_uid.setdefault(replica.miner_hotkey, replica.miner_uid) != (
                    replica.miner_uid
                ):
                    raise ValueError("snapshot_miner_identity_conflict")
        nonces = [
            replica.assignment_nonce for item in self.deployments for replica in item.replicas
        ]
        if len(set(nonces)) != len(nonces):
            raise ValueError("snapshot_assignment_nonce_duplicate")
        endpoints = [replica.endpoint_id for item in self.deployments for replica in item.replicas]
        if len(set(endpoints)) != len(endpoints):
            raise ValueError("snapshot_endpoint_duplicate")
        projected = [model_document(item) for item in _project(self.deployments)]
        if self.projected_assignment_vector_digest_sha256 != digest(projected):
            raise ValueError("projected_assignment_vector_digest_sha256_mismatch")
        verify_model_digest(self, "snapshot_digest_sha256")
        return self


def _project(deployments: Sequence[SnapshotDeployment]) -> list[ActiveDeploymentAssignment]:
    projected: list[ActiveDeploymentAssignment] = []
    for item in deployments:
        replicas = [
            build_assigned_replica(
                miner_uid=replica.miner_uid,
                miner_hotkey=replica.miner_hotkey,
                miner_service_public_key=replica.miner_service_public_key,
                generation=replica.generation,
                assignment_nonce=replica.assignment_nonce,
                deployment_id=item.deployment_id,
                ticket_digest_sha256=replica.ticket_digest_sha256,
                receipt_digest_sha256=replica.receipt_digest_sha256,
                chain_block=replica.chain_block,
                expires_at_block=replica.expires_at_block,
                ticket_issued_at_epoch=replica.ticket_issued_at_epoch,
                ticket_expires_at_epoch=replica.ticket_expires_at_epoch,
            )
            for replica in item.replicas
        ]
        projected.append(
            build_active_deployment_assignment(
                deployment_id=item.deployment_id,
                campaign_sequence=item.campaign_sequence,
                route_host=item.route_host,
                build_id=item.build_id,
                challenge_sha256=item.challenge_sha256,
                image_digest=item.image_digest,
                workload_spec_digest_sha256=item.workload_spec_digest_sha256,
                attestation_requirement=item.attestation_requirement,
                replicas=replicas,
            )
        )
    return sorted(projected, key=lambda item: item.deployment_id)


def project_manifest_deployments(
    snapshot: ActiveAssignmentSnapshot,
) -> list[ActiveDeploymentAssignment]:
    """The only projection from a snapshot to manifest v1 deployments.

    Activation timing that the manifest v1 contract does not carry
    (``route_activated_at_epoch``) is dropped here; everything else is copied
    field-for-field, so the manifest's ``assignment_digest_sha256`` values are
    a function of the snapshot alone.
    """

    return _project(revalidate(snapshot, ActiveAssignmentSnapshot).deployments)


def build_snapshot_replica(
    *,
    miner_uid: int,
    miner_hotkey: str,
    miner_service_public_key: str,
    generation: int,
    assignment_nonce: str,
    deployment_id: str,
    ticket_digest_sha256: str,
    receipt_digest_sha256: str,
    chain_block: int,
    expires_at_block: int,
    ticket_issued_at_epoch: int,
    ticket_expires_at_epoch: int,
    route_activated_at_epoch: int,
) -> SnapshotReplica:
    replica_id = f"{deployment_id}-{miner_hotkey}"
    return SnapshotReplica.model_validate(
        {
            "miner_uid": miner_uid,
            "miner_hotkey": miner_hotkey,
            "miner_service_public_key": miner_service_public_key,
            "generation": generation,
            "assignment_nonce": assignment_nonce,
            "replica_id": replica_id,
            "endpoint_id": f"{replica_id}-g{generation}-{assignment_nonce}",
            "ticket_digest_sha256": ticket_digest_sha256,
            "receipt_digest_sha256": receipt_digest_sha256,
            "chain_block": chain_block,
            "expires_at_block": expires_at_block,
            "ticket_issued_at_epoch": ticket_issued_at_epoch,
            "ticket_expires_at_epoch": ticket_expires_at_epoch,
            "route_state": "active",
            "route_activated_at_epoch": route_activated_at_epoch,
        }
    )


def build_snapshot_deployment(
    *,
    deployment_id: str,
    campaign_sequence: int,
    route_host: str,
    build_id: str,
    challenge_sha256: str,
    image_digest: str,
    workload_spec_digest_sha256: str,
    attestation_requirement: AttestationRequirement,
    replicas: Sequence[SnapshotReplica],
) -> SnapshotDeployment:
    ordered = sorted(
        (revalidate(item, SnapshotReplica) for item in replicas),
        key=lambda item: (item.miner_uid, item.miner_hotkey),
    )
    return SnapshotDeployment.model_validate(
        {
            "deployment_id": deployment_id,
            "campaign_sequence": campaign_sequence,
            "route_host": route_host,
            "challenge_path": f"/__challenge/{build_id}",
            "build_id": build_id,
            "challenge_sha256": challenge_sha256,
            "expected_status": 200,
            "image_digest": image_digest,
            "workload_spec_digest_sha256": workload_spec_digest_sha256,
            "attestation_requirement": attestation_requirement,
            "replicas": [model_document(item) for item in ordered],
        }
    )


def build_active_assignment_snapshot(
    *,
    central_authority_fingerprint_sha256: str,
    snapshot_sequence: int,
    state_revision: int,
    captured_at_epoch: int,
    finalized_height: int,
    finalized_block_hash: str,
    finalized_epoch: int,
    route_host_suffix: str,
    probe_port: int,
    deployments: Sequence[SnapshotDeployment],
) -> ActiveAssignmentSnapshot:
    """Seal one snapshot; the projected manifest vector digest is derived, never supplied."""

    ordered = sorted(
        (revalidate(item, SnapshotDeployment) for item in deployments),
        key=lambda item: item.deployment_id,
    )
    projected = [model_document(item) for item in _project(ordered)]
    unsigned: dict[str, object] = {
        "schema": SNAPSHOT_SCHEMA,
        "schema_version": SNAPSHOT_SCHEMA_VERSION,
        "purpose": SNAPSHOT_PURPOSE,
        "network": MAINNET_NETWORK,
        "netuid": MAINNET_NETUID,
        "central_authority_fingerprint_sha256": central_authority_fingerprint_sha256,
        "snapshot_sequence": snapshot_sequence,
        "state_revision": state_revision,
        "captured_at_epoch": captured_at_epoch,
        "finalized_height": finalized_height,
        "finalized_block_hash": finalized_block_hash,
        "finalized_epoch": finalized_epoch,
        "route_host_suffix": route_host_suffix,
        "probe_scheme": "https",
        "probe_port": probe_port,
        "deployments": [model_document(item) for item in ordered],
        "projected_assignment_vector_digest_sha256": digest(projected),
    }
    return ActiveAssignmentSnapshot.model_validate(
        {**unsigned, "snapshot_digest_sha256": digest(unsigned)}
    )


def verify_snapshot_succession(
    previous: ActiveAssignmentSnapshot,
    current: ActiveAssignmentSnapshot,
) -> None:
    """Enforce the transactional ordering between two captures from one runtime.

    ``snapshot_sequence`` strictly increases; ``state_revision``, the capture
    instant, and the finalized height never go backwards; an unchanged
    revision must carry byte-identical deployments; one finalized height has
    one block hash.
    """

    previous = revalidate(previous, ActiveAssignmentSnapshot)
    current = revalidate(current, ActiveAssignmentSnapshot)
    if (
        previous.central_authority_fingerprint_sha256
        != current.central_authority_fingerprint_sha256
    ):
        _reject("snapshot_authority_mismatch")
    if previous.network != current.network or previous.netuid != current.netuid:
        _reject("snapshot_network_mismatch")
    if current.snapshot_sequence <= previous.snapshot_sequence:
        _reject("snapshot_sequence_not_increasing")
    if current.state_revision < previous.state_revision:
        _reject("snapshot_revision_rollback")
    if current.state_revision == previous.state_revision and (
        [model_document(item) for item in current.deployments]
        != [model_document(item) for item in previous.deployments]
    ):
        _reject("snapshot_revision_content_divergence")
    if current.captured_at_epoch < previous.captured_at_epoch:
        _reject("snapshot_capture_rollback")
    if current.finalized_height < previous.finalized_height:
        _reject("snapshot_finalized_rollback")
    if (
        current.finalized_height == previous.finalized_height
        and current.finalized_block_hash != previous.finalized_block_hash
    ):
        _reject("snapshot_finalized_fork")


def verify_manifest_derived_from_snapshot(
    manifest: ActiveAssignmentManifest,
    snapshot: ActiveAssignmentSnapshot,
) -> None:
    """Accept a manifest only when it is the exact projection of the snapshot.

    The publisher calls this before signing; a validator archive can call it
    later to cross-reference a published manifest with the runtime capture it
    claims to reflect. Sequence, previous-digest linkage, expiry, and trust
    policy are manifest-chain facts checked elsewhere; this binds content.
    """

    manifest = revalidate(manifest, ActiveAssignmentManifest)
    snapshot = revalidate(snapshot, ActiveAssignmentSnapshot)
    if (
        manifest.central_authority_fingerprint_sha256
        != snapshot.central_authority_fingerprint_sha256
    ):
        _reject("snapshot_authority_mismatch")
    if manifest.network != snapshot.network or manifest.netuid != snapshot.netuid:
        _reject("snapshot_network_mismatch")
    if (
        manifest.finalized_height != snapshot.finalized_height
        or manifest.finalized_block_hash != snapshot.finalized_block_hash
        or manifest.finalized_epoch != snapshot.finalized_epoch
    ):
        _reject("snapshot_manifest_chain_mismatch")
    if manifest.issued_at_epoch != snapshot.captured_at_epoch:
        _reject("snapshot_manifest_issued_at_mismatch")
    if (
        manifest.route_host_suffix != snapshot.route_host_suffix
        or manifest.probe_scheme != snapshot.probe_scheme
        or manifest.probe_port != snapshot.probe_port
    ):
        _reject("snapshot_manifest_route_mismatch")
    if (
        manifest.assignment_vector_digest_sha256
        != snapshot.projected_assignment_vector_digest_sha256
    ):
        _reject("snapshot_manifest_vector_mismatch")


def active_assignment_snapshot_bytes(value: ActiveAssignmentSnapshot) -> bytes:
    return model_bytes(value, ActiveAssignmentSnapshot)


def parse_active_assignment_snapshot(rendered: bytes) -> ActiveAssignmentSnapshot:
    return parse_model(
        rendered,
        ActiveAssignmentSnapshot,
        active_assignment_snapshot_bytes,
        maximum_bytes=MAX_SNAPSHOT_BYTES,
    )
