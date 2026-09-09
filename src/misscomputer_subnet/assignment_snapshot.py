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

Clock domains
-------------
A snapshot mixes two clocks. ``ticket_issued_at_epoch`` and
``ticket_expires_at_epoch`` are stamped by the ticket signer; ``captured_at_epoch``
and every ``route_activated_at_epoch`` are stamped by the runtime that
activated the route and took the capture. Comparisons inside one domain are
exact: a route is activated at or before the capture that exports it.
Comparisons across the two domains tolerate the signer's clock leading the
runtime's by at most :data:`TICKET_MAX_FUTURE_SKEW_SECONDS`: a ticket may be
stamped as issued up to that many seconds after the activation it authorised
and up to that many seconds after the capture instant, and never more. The
same constant governs both cross-domain checks, so a ticket issued at
``captured_at_epoch + TICKET_MAX_FUTURE_SKEW_SECONDS`` for a route activated
at the capture instant is a valid capture; one second more is not.

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
from typing import Final, Literal, NoReturn, Self, cast

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
#: The only clock skew tolerated between the ticket signer's clock and the
#: runtime's: a ticket may be stamped as issued at most this many seconds after
#: the route activation it authorised and after the capture instant.
TICKET_MAX_FUTURE_SKEW_SECONDS: Final = 30
MAX_SNAPSHOT_BYTES: Final = 64 * 1_024 * 1_024
LINEAGE_SCHEMA: Final = "miss.computer/misscomputer-subnet/active-assignment-snapshot-lineage"
LINEAGE_SCHEMA_VERSION: Final = 1
LINEAGE_PURPOSE: Final = "active_assignment_snapshot_lineage_v1"
#: Every ``replica_id`` a runtime has ever exported; a lineage past this must be
#: re-anchored by its operator.
MAX_LINEAGE_REPLICAS: Final = MAX_DEPLOYMENTS * MAX_REPLICAS
MAX_LINEAGE_BYTES: Final = 64 * 1_024 * 1_024

SnapshotRejectionCode = Literal[
    "snapshot_authority_mismatch",
    "snapshot_capture_rollback",
    "snapshot_finalized_epoch_rollback",
    "snapshot_finalized_fork",
    "snapshot_finalized_rollback",
    "snapshot_generation_not_increasing",
    "snapshot_incarnation_rewritten",
    "snapshot_lineage_overflow",
    "snapshot_manifest_chain_mismatch",
    "snapshot_manifest_issued_at_mismatch",
    "snapshot_manifest_route_mismatch",
    "snapshot_manifest_vector_mismatch",
    "snapshot_network_mismatch",
    "snapshot_replacement_facts_reused",
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
    #: Instant the runtime activated this exact incarnation (at or after the
    #: ready receipt), on the runtime's clock. Consumers anchor activation
    #: grace on it. The signer-stamped ``ticket_issued_at_epoch`` may lead it
    #: by at most :data:`TICKET_MAX_FUTURE_SKEW_SECONDS`.
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
        if self.ticket_issued_at_epoch > (
            self.route_activated_at_epoch + TICKET_MAX_FUTURE_SKEW_SECONDS
        ):
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


class ReplicaLineage(StrictFrozenModel):
    """The latest incarnation a lineage has accepted for one stable ``replica_id``.

    ``replica_id`` (deployment and hotkey) is stable across re-assignments;
    ``generation`` and ``assignment_nonce`` name the incarnation, and the
    ticket and receipt digests are the signed facts issued for it.
    ``replica_digest_sha256`` seals the complete replica document and
    ``deployment_facts_digest_sha256`` the enclosing deployment's ticket-bound
    facts (everything but its replicas), so a later capture that re-exports
    this incarnation can be held to exactly what was accepted.
    """

    replica_id: ReplicaID
    deployment_id: DeploymentID
    miner_hotkey: Hotkey
    generation: PositiveEpoch
    assignment_nonce: Hex32
    endpoint_id: EndpointID
    ticket_digest_sha256: Digest
    receipt_digest_sha256: Digest
    replica_digest_sha256: Digest
    deployment_facts_digest_sha256: Digest

    @model_validator(mode="after")
    def canonical_lineage(self) -> Self:
        if self.replica_id != f"{self.deployment_id}-{self.miner_hotkey}":
            raise ValueError("lineage_replica_identity_invalid")
        if self.endpoint_id != f"{self.replica_id}-g{self.generation}-{self.assignment_nonce}":
            raise ValueError("lineage_replica_identity_invalid")
        if self.ticket_digest_sha256 == self.receipt_digest_sha256:
            raise ValueError("lineage_digest_binding_invalid")
        return self


class SnapshotLineage(StrictFrozenModel):
    """Durable, append-only memory of every capture a publisher has accepted.

    The lineage carries the transactional position of the last accepted
    capture (so the succession rules hold across every capture, not only
    between two adjacent ones) and, for every ``replica_id`` ever exported,
    the latest incarnation accepted for it, including incarnations that later
    captures dropped. A publisher advances it with every capture it accepts
    and persists the result; an incarnation that disappears from a capture and
    reappears later is still held to the facts first accepted for it.
    """

    contract_schema: Literal[
        "miss.computer/misscomputer-subnet/active-assignment-snapshot-lineage"
    ] = Field(alias="schema")
    schema_version: Literal[1]
    purpose: Literal["active_assignment_snapshot_lineage_v1"]
    network: Literal["finney"]
    netuid: Literal[24]
    central_authority_fingerprint_sha256: Digest
    accepted_snapshot_count: int = Field(ge=0)
    last_snapshot_sequence: PositiveEpoch | None
    last_state_revision: Epoch | None
    last_captured_at_epoch: Epoch | None
    last_finalized_height: Epoch | None
    last_finalized_block_hash: Digest | None
    last_finalized_epoch: Epoch | None
    last_snapshot_digest_sha256: Digest | None
    #: Digest of the last capture's canonical ``deployments`` list, so an
    #: unchanged ``state_revision`` can be held to identical content.
    last_deployments_digest_sha256: Digest | None
    replicas: list[ReplicaLineage] = Field(max_length=MAX_LINEAGE_REPLICAS)
    lineage_digest_sha256: Digest

    @model_validator(mode="after")
    def canonical_lineage(self) -> Self:
        last_fields = (
            self.last_snapshot_sequence,
            self.last_state_revision,
            self.last_captured_at_epoch,
            self.last_finalized_height,
            self.last_finalized_block_hash,
            self.last_finalized_epoch,
            self.last_snapshot_digest_sha256,
            self.last_deployments_digest_sha256,
        )
        genesis = self.accepted_snapshot_count == 0
        if genesis != all(value is None for value in last_fields) or (
            not genesis and any(value is None for value in last_fields)
        ):
            raise ValueError("lineage_genesis_invalid")
        if genesis and self.replicas:
            raise ValueError("lineage_genesis_invalid")
        replica_ids = [item.replica_id for item in self.replicas]
        if replica_ids != sorted(set(replica_ids)):
            raise ValueError("lineage_replicas_not_canonical")
        endpoints = [item.endpoint_id for item in self.replicas]
        if len(set(endpoints)) != len(endpoints):
            raise ValueError("lineage_endpoint_duplicate")
        verify_model_digest(self, "lineage_digest_sha256")
        return self


def _deployment_facts_digest(deployment: SnapshotDeployment) -> str:
    """Digest of a deployment's ticket-bound facts: everything but its replicas."""

    return digest(
        {key: value for key, value in model_document(deployment).items() if key != "replicas"}
    )


def _replica_lineage(deployment: SnapshotDeployment, replica: SnapshotReplica) -> ReplicaLineage:
    return ReplicaLineage(
        replica_id=replica.replica_id,
        deployment_id=deployment.deployment_id,
        miner_hotkey=replica.miner_hotkey,
        generation=replica.generation,
        assignment_nonce=replica.assignment_nonce,
        endpoint_id=replica.endpoint_id,
        ticket_digest_sha256=replica.ticket_digest_sha256,
        receipt_digest_sha256=replica.receipt_digest_sha256,
        replica_digest_sha256=digest(model_document(replica)),
        deployment_facts_digest_sha256=_deployment_facts_digest(deployment),
    )


def build_initial_snapshot_lineage(*, central_authority_fingerprint_sha256: str) -> SnapshotLineage:
    """The lineage a publisher holds before it has accepted any capture."""

    unsigned: dict[str, object] = {
        "schema": LINEAGE_SCHEMA,
        "schema_version": LINEAGE_SCHEMA_VERSION,
        "purpose": LINEAGE_PURPOSE,
        "network": MAINNET_NETWORK,
        "netuid": MAINNET_NETUID,
        "central_authority_fingerprint_sha256": central_authority_fingerprint_sha256,
        "accepted_snapshot_count": 0,
        "last_snapshot_sequence": None,
        "last_state_revision": None,
        "last_captured_at_epoch": None,
        "last_finalized_height": None,
        "last_finalized_block_hash": None,
        "last_finalized_epoch": None,
        "last_snapshot_digest_sha256": None,
        "last_deployments_digest_sha256": None,
        "replicas": [],
    }
    return SnapshotLineage.model_validate({**unsigned, "lineage_digest_sha256": digest(unsigned)})


def advance_snapshot_lineage(
    lineage: SnapshotLineage, snapshot: ActiveAssignmentSnapshot
) -> SnapshotLineage:
    """Accept one capture into a lineage, or refuse it with a stable code.

    Transactional rules against the last accepted capture: ``snapshot_sequence``
    strictly increases; ``state_revision``, the capture instant, the finalized
    height, and the finalized epoch never go backwards; an unchanged revision
    carries identical deployments; one finalized height has one block hash and
    one epoch; authority and network never change.

    Incarnation rules against every ``replica_id`` the lineage has ever
    accepted, whether or not the previous capture still exported it:

    - the same ``endpoint_id`` must carry the identical replica document and
      identical ticket-bound deployment facts (``snapshot_incarnation_rewritten``);
      a signed ticket binds its own issuance and its assignment, so a retained
      ticket with a restamped instant, a moved activation, or a changed image,
      challenge, or workload spec is an impossible rewrite;
    - a replacement (a different ``endpoint_id`` for the same ``replica_id``)
      must advance the generation (``snapshot_generation_not_increasing``) and
      carry a fresh nonce, ticket digest, and receipt digest
      (``snapshot_replacement_facts_reused``).
    """

    lineage = revalidate(lineage, SnapshotLineage)
    snapshot = revalidate(snapshot, ActiveAssignmentSnapshot)
    if lineage.central_authority_fingerprint_sha256 != (
        snapshot.central_authority_fingerprint_sha256
    ):
        _reject("snapshot_authority_mismatch")
    if lineage.network != snapshot.network or lineage.netuid != snapshot.netuid:
        _reject("snapshot_network_mismatch")
    deployments_digest = digest([model_document(item) for item in snapshot.deployments])
    if lineage.accepted_snapshot_count > 0:
        last_sequence = cast(int, lineage.last_snapshot_sequence)
        last_revision = cast(int, lineage.last_state_revision)
        last_captured = cast(int, lineage.last_captured_at_epoch)
        last_height = cast(int, lineage.last_finalized_height)
        last_epoch = cast(int, lineage.last_finalized_epoch)
        if snapshot.snapshot_sequence <= last_sequence:
            _reject("snapshot_sequence_not_increasing")
        if snapshot.state_revision < last_revision:
            _reject("snapshot_revision_rollback")
        if snapshot.state_revision == last_revision and (
            deployments_digest != lineage.last_deployments_digest_sha256
        ):
            _reject("snapshot_revision_content_divergence")
        if snapshot.captured_at_epoch < last_captured:
            _reject("snapshot_capture_rollback")
        if snapshot.finalized_height < last_height:
            _reject("snapshot_finalized_rollback")
        if snapshot.finalized_height == last_height and (
            snapshot.finalized_block_hash != lineage.last_finalized_block_hash
            or snapshot.finalized_epoch != last_epoch
        ):
            _reject("snapshot_finalized_fork")
        if snapshot.finalized_epoch < last_epoch:
            _reject("snapshot_finalized_epoch_rollback")
    retained = {item.replica_id: item for item in lineage.replicas}
    for deployment in snapshot.deployments:
        for replica in deployment.replicas:
            current = _replica_lineage(deployment, replica)
            known = retained.get(current.replica_id)
            if known is None:
                retained[current.replica_id] = current
                continue
            if known.endpoint_id == current.endpoint_id:
                if known != current:
                    _reject("snapshot_incarnation_rewritten")
                continue
            if current.generation <= known.generation:
                _reject("snapshot_generation_not_increasing")
            if (
                current.assignment_nonce == known.assignment_nonce
                or current.ticket_digest_sha256 == known.ticket_digest_sha256
                or current.receipt_digest_sha256 == known.receipt_digest_sha256
            ):
                _reject("snapshot_replacement_facts_reused")
            retained[current.replica_id] = current
    if len(retained) > MAX_LINEAGE_REPLICAS:
        _reject("snapshot_lineage_overflow")
    unsigned: dict[str, object] = {
        "schema": LINEAGE_SCHEMA,
        "schema_version": LINEAGE_SCHEMA_VERSION,
        "purpose": LINEAGE_PURPOSE,
        "network": lineage.network,
        "netuid": lineage.netuid,
        "central_authority_fingerprint_sha256": lineage.central_authority_fingerprint_sha256,
        "accepted_snapshot_count": lineage.accepted_snapshot_count + 1,
        "last_snapshot_sequence": snapshot.snapshot_sequence,
        "last_state_revision": snapshot.state_revision,
        "last_captured_at_epoch": snapshot.captured_at_epoch,
        "last_finalized_height": snapshot.finalized_height,
        "last_finalized_block_hash": snapshot.finalized_block_hash,
        "last_finalized_epoch": snapshot.finalized_epoch,
        "last_snapshot_digest_sha256": snapshot.snapshot_digest_sha256,
        "last_deployments_digest_sha256": deployments_digest,
        "replicas": [model_document(retained[key]) for key in sorted(retained)],
    }
    return SnapshotLineage.model_validate({**unsigned, "lineage_digest_sha256": digest(unsigned)})


def verify_snapshot_succession(
    previous: ActiveAssignmentSnapshot,
    current: ActiveAssignmentSnapshot,
) -> None:
    """Enforce the transactional and incarnation rules between two adjacent captures.

    Exactly :func:`advance_snapshot_lineage` applied to a fresh lineage over
    ``previous`` and then ``current``; a publisher that persists its lineage
    gets the same rules across every capture it ever accepted, which this
    two-capture form cannot see (an incarnation dropped by one capture and
    rewritten by a later one).
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
    lineage = build_initial_snapshot_lineage(
        central_authority_fingerprint_sha256=previous.central_authority_fingerprint_sha256
    )
    advance_snapshot_lineage(advance_snapshot_lineage(lineage, previous), current)


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


def snapshot_lineage_bytes(value: SnapshotLineage) -> bytes:
    return model_bytes(value, SnapshotLineage)


def parse_snapshot_lineage(rendered: bytes) -> SnapshotLineage:
    return parse_model(
        rendered, SnapshotLineage, snapshot_lineage_bytes, maximum_bytes=MAX_LINEAGE_BYTES
    )
