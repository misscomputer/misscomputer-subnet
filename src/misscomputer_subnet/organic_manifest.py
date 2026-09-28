# SPDX-License-Identifier: AGPL-3.0-only
"""Publication and verification of ``active-assignment-manifest`` v2.

The document itself is the canonical
:class:`~misscomputer_subnet.organic_contracts.ActiveAssignmentManifestV2`.
This module is the scoring track's verifier-side pipeline around it
(contract §17.2): the v2 signing domain, live verification under the
validator's pinned trust policy with the append-only chain rules, and the
validity horizon a validator may probe inside. Producer-side sealing (route
projection, deployment and manifest building, signature envelopes) lives
with the private operator producer boundary.

Trust
-----
The frozen ``assignment-manifest-trust-policy`` v1, signature envelope v1 and
chain state v1 are reused unchanged. They pin the central manifest authority
and the publication *channel* (``active_assignment_manifest_publication_v1``)
and read only header fields every manifest version shares. Version 2 signs
under :data:`ORGANIC_MANIFEST_SIGNATURE_DOMAIN_SEPARATOR`, so a signature over
the retired synthetic v1 domain never verifies as v2.

Leases
------
An organic route outlives its acceptance ticket (contract §6.6). A replica's
``expires_at_epoch`` and ``chain_block``/``expires_at_block`` are therefore
*publication leases* the exporter refreshes on every export, not ticket
values. A manifest is valid until its own expiry or the earliest replica
lease, whichever is first, and never once a block lease has ended at the
validator's finalized height.

Beyond the canonical model, verification refuses a manifest that binds one
miner UID, hotkey or service key to two identities, reuses an assignment
nonce, or publishes a replica activated after issuance: each would let one
endpoint's evidence be credited to another miner.

This module is pure: no clock, network, file, process, environment, wallet,
chain, randomness, or signing capability.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Final

from .assignment_probe import (
    MAX_EPOCH,
    MAX_KEYS,
    AssignmentManifestChainState,
    AssignmentManifestSignatureEnvelope,
    AssignmentManifestTrustPolicy,
    AssignmentProbeError,
    ManifestRole,
    advance_manifest_header_chain_state,
    verify_manifest_policy_admission,
    verify_manifest_signatures,
)
from .contract_codec import (
    StrictFrozenModel,
    canonical_json,
    digest,
    model_document,
    revalidate,
)
from .organic_contracts import (
    ActiveAssignmentManifestV2,
    Hex64,
    document_bytes,
    parse_canonical_document,
)

ORGANIC_MANIFEST_SCHEMA: Final = "miss.computer/misscomputer-subnet/active-assignment-manifest"
ORGANIC_MANIFEST_PURPOSE: Final = "active_assignment_manifest_publication_v2"
ORGANIC_MANIFEST_SIGNATURE_DOMAIN_SEPARATOR: Final = (
    b"miss.computer/misscomputer-subnet/active-assignment-manifest/v2/ed25519"
)
ORGANIC_ATTESTATION_REQUIREMENT: Final = "miner_service_key_v2"


class OrganicManifestVerification(StrictFrozenModel):
    """One live verification of one v2 manifest and the chain state it produced."""

    manifest: ActiveAssignmentManifestV2
    verified_signer_key_ids: list[str]
    verified_roles: list[ManifestRole]
    next_chain_state: AssignmentManifestChainState
    reprobe: bool
    evaluation_epoch: int
    trust_policy_digest_sha256: Hex64


def verify_organic_manifest_identities(manifest: ActiveAssignmentManifestV2) -> None:
    """Refuse identity reuse the canonical model does not itself forbid."""

    value = revalidate(manifest, ActiveAssignmentManifestV2)
    replicas = [replica for item in value.deployments for replica in item.replicas]
    nonces = [replica.assignment_nonce for replica in replicas]
    if len(set(nonces)) != len(nonces):
        raise ValueError("manifest_assignment_nonce_duplicate")
    by_uid: dict[int, tuple[str, str]] = {}
    by_hotkey: dict[str, tuple[int, str]] = {}
    for replica in replicas:
        if replica.activated_at_epoch > value.issued_at_epoch:
            raise ValueError("manifest_replica_not_yet_active")
        if by_uid.setdefault(
            replica.miner_uid, (replica.miner_hotkey, replica.miner_service_public_key)
        ) != (replica.miner_hotkey, replica.miner_service_public_key) or by_hotkey.setdefault(
            replica.miner_hotkey, (replica.miner_uid, replica.miner_service_public_key)
        ) != (replica.miner_uid, replica.miner_service_public_key):
            raise ValueError("manifest_miner_identity_conflict")


def organic_manifest_signature_message(manifest: ActiveAssignmentManifestV2) -> bytes:
    """The only domain-separated bytes a central manifest key signs for a v2 manifest."""

    manifest = revalidate(manifest, ActiveAssignmentManifestV2)
    return (
        ORGANIC_MANIFEST_SIGNATURE_DOMAIN_SEPARATOR
        + b"\x00"
        + canonical_json(model_document(manifest))
    )


def organic_manifest_effective_expires_at_epoch(manifest: ActiveAssignmentManifestV2) -> int:
    """The manifest's own expiry or the earliest published replica lease, whichever is first."""

    return min(
        [
            manifest.expires_at_epoch,
            *(
                replica.expires_at_epoch
                for item in manifest.deployments
                for replica in item.replicas
            ),
        ]
    )


def organic_manifest_valid_at(manifest: ActiveAssignmentManifestV2, instant_epoch: int) -> bool:
    """Whether a probe issued at ``instant_epoch`` falls inside the manifest's horizon."""

    return (
        manifest.issued_at_epoch <= instant_epoch
        and instant_epoch < organic_manifest_effective_expires_at_epoch(manifest)
    )


def _bounded(value: int, name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= MAX_EPOCH:
        raise ValueError(f"{name}_invalid")


def verify_organic_assignment_manifest(
    manifest: ActiveAssignmentManifestV2,
    signatures: Sequence[AssignmentManifestSignatureEnvelope],
    approved_trust_policy: AssignmentManifestTrustPolicy,
    prior_chain_state: AssignmentManifestChainState,
    *,
    evaluation_epoch: int,
    current_finalized_height: int,
) -> OrganicManifestVerification:
    """Verify one v2 publication live and derive the next append-only chain state.

    Applies the channel's trust-policy binding and freshness, the identity
    rules, the effective horizon and block leases at the validator's own
    finalized height, threshold signatures under the v2 domain, and the shared
    non-equivocation chain rules. A validator that cannot verify the current
    manifest abstains.
    """

    _bounded(evaluation_epoch, "evaluation_epoch")
    _bounded(current_finalized_height, "current_finalized_height")
    policy = revalidate(approved_trust_policy, AssignmentManifestTrustPolicy)
    value = revalidate(manifest, ActiveAssignmentManifestV2)
    envelopes = [revalidate(item, AssignmentManifestSignatureEnvelope) for item in signatures]
    if not 1 <= len(envelopes) <= MAX_KEYS:
        raise AssignmentProbeError("signature_binding_mismatch")
    verify_manifest_policy_admission(value, policy, evaluation_epoch=evaluation_epoch)
    verify_organic_manifest_identities(value)
    if evaluation_epoch >= organic_manifest_effective_expires_at_epoch(value):
        raise AssignmentProbeError("manifest_expired")
    if any(
        replica.expires_at_block <= current_finalized_height
        for item in value.deployments
        for replica in item.replicas
    ):
        raise AssignmentProbeError("manifest_replica_lease_expired")
    signer_ids, roles = verify_manifest_signatures(
        value,
        organic_manifest_signature_message(value),
        envelopes,
        policy,
        evaluation_epoch=evaluation_epoch,
    )
    next_state, reprobe = advance_manifest_header_chain_state(prior_chain_state, value, policy)
    return OrganicManifestVerification(
        manifest=value,
        verified_signer_key_ids=signer_ids,
        verified_roles=roles,
        next_chain_state=next_state,
        reprobe=reprobe,
        evaluation_epoch=evaluation_epoch,
        trust_policy_digest_sha256=policy.trust_policy_digest_sha256,
    )


def anchor_organic_manifest_chain_state(
    manifest: ActiveAssignmentManifestV2,
    signatures: Sequence[AssignmentManifestSignatureEnvelope],
    approved_trust_policy: AssignmentManifestTrustPolicy,
    genesis_chain_state: AssignmentManifestChainState,
    *,
    evaluation_epoch: int,
    current_finalized_height: int,
) -> OrganicManifestVerification:
    """Onboard a validator with no history on the current live v2 head, at any sequence.

    Available only from a genesis state, so it can never skip history a
    validator already holds. The head passes complete live verification
    against a synthetic predecessor one sequence below it, exactly as the v1
    onboarding anchor does; every later publication extends the resulting
    state through the ordinary append-only rules.
    """

    state = revalidate(genesis_chain_state, AssignmentManifestChainState)
    if state.accepted_manifest_count != 0:
        raise ValueError("anchor_state_not_genesis")
    value = revalidate(manifest, ActiveAssignmentManifestV2)
    if value.sequence == 1:
        return verify_organic_assignment_manifest(
            value,
            signatures,
            approved_trust_policy,
            state,
            evaluation_epoch=evaluation_epoch,
            current_finalized_height=current_finalized_height,
        )
    unsigned: dict[str, object] = {
        **model_document(state, exclude={"state_digest_sha256"}),
        "accepted_manifest_count": 1,
        "last_sequence": value.sequence - 1,
        "last_finalized_height": value.finalized_height,
        "last_finalized_block_hash": value.finalized_block_hash,
        "last_finalized_epoch": value.finalized_epoch,
        "last_issued_at_epoch": value.issued_at_epoch,
        "last_expires_at_epoch": value.expires_at_epoch,
        "last_manifest_digest_sha256": value.previous_manifest_digest_sha256,
    }
    predecessor = AssignmentManifestChainState.model_validate(
        {**unsigned, "state_digest_sha256": digest(unsigned)}
    )
    result = verify_organic_assignment_manifest(
        value,
        signatures,
        approved_trust_policy,
        predecessor,
        evaluation_epoch=evaluation_epoch,
        current_finalized_height=current_finalized_height,
    )
    anchored: dict[str, object] = {
        **unsigned,
        "last_sequence": value.sequence,
        "last_manifest_digest_sha256": value.manifest_digest_sha256,
    }
    return result.model_copy(
        update={
            "next_chain_state": AssignmentManifestChainState.model_validate(
                {**anchored, "state_digest_sha256": digest(anchored)}
            ),
            "reprobe": False,
        }
    )


def organic_assignment_manifest_bytes(value: ActiveAssignmentManifestV2) -> bytes:
    return document_bytes(revalidate(value, ActiveAssignmentManifestV2))


def parse_organic_assignment_manifest(rendered: bytes) -> ActiveAssignmentManifestV2:
    return parse_canonical_document(rendered, ActiveAssignmentManifestV2)
