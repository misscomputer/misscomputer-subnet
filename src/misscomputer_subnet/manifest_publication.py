# SPDX-License-Identifier: AGPL-3.0-only
"""Signed active-assignment manifest publication layout and latest-pointer contract.

``active-assignment-manifest`` v1, its signature envelopes, the validator trust
policy, and the append-only chain state are already frozen in
:mod:`misscomputer_subnet.assignment_probe`. This module freezes what sits
around them so a publisher and a fetcher can be built independently:

Object layout (relative to one publication root)
-------------------------------------------------
- ``v1/manifests/<manifest_digest_sha256>.json`` — the immutable canonical
  manifest bytes, content-addressed by its own digest;
- ``v1/manifests/<manifest_digest_sha256>.<signer_key_id>.signature.json`` —
  one immutable canonical signature envelope per signer;
- ``v1/latest.json`` — the only mutable object: an
  ``assignment-manifest-latest-pointer`` v1 naming the current publication.

Atomic publication order
------------------------
The manifest object and every signature object are written and readable
*before* the pointer is replaced; the pointer is replaced atomically (single
object PUT or rename). A reader that follows the pointer therefore always
finds complete, immutable objects. A pointer is never rewritten to a lower
sequence. Immutable objects are never modified or deleted while any
unexpired pointer or validator chain state could still name them.

Cache behaviour
---------------
Immutable objects are served with :data:`IMMUTABLE_OBJECT_CACHE_CONTROL`;
the pointer with :data:`LATEST_POINTER_CACHE_CONTROL`. Fetchers send
``Cache-Control: no-cache`` for the pointer. No caching layer can widen the
trust boundary: a stale or replayed pointer resolves to a signed manifest
whose freshness, sequence, and chain linkage are still checked by
:func:`misscomputer_subnet.assignment_probe.verify_active_assignment_manifest`.
The worst a cache can do is withhold a newer publication, and the manifest
freshness bounds then force the validator to abstain.

Why the pointer is not independently signed
-------------------------------------------
Every field the pointer carries is copied from, and re-checked against, the
signed manifest it names, and the object key is the manifest's own digest.
A forged pointer can only name a manifest that verifies under the pinned
trust policy, and the append-only chain state rejects any rollback or
equivocation it might point at. Signing the pointer would add a signing
ceremony per publication without changing what an attacker can achieve.

Key rotation
------------
A validator pins one trust policy, and every manifest and chain state names
that policy's digest. Rotation is therefore a re-anchoring event:
:func:`rebind_manifest_chain_state_trust_policy` carries the accepted chain
position (sequence, digests, chain view) to the successor policy without
resetting non-equivocation history. The procedure is documented in
``docs/contract-checkpoint-v1.md``.

This module is pure: no clock, network, file, process, environment, wallet,
chain, randomness, or signing capability.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Annotated, Final, Literal, NoReturn, Self

from pydantic import Field, StringConstraints, model_validator

from .assignment_probe import (
    MANIFEST_CHAIN_STATE_SCHEMA,
    MANIFEST_PURPOSE,
    MAX_EPOCH,
    MAX_KEYS,
    PROBE_SCHEMA_VERSION,
    ActiveAssignmentManifest,
    AssignmentManifestChainState,
    AssignmentManifestSignatureEnvelope,
    AssignmentManifestTrustPolicy,
    Digest,
    Epoch,
    KeyID,
    PositiveEpoch,
)
from .contract_codec import (
    StrictFrozenModel,
    digest,
    model_bytes,
    parse_model,
    revalidate,
    verify_model_digest,
)

LATEST_POINTER_SCHEMA: Final = (
    "miss.computer/misscomputer-subnet/assignment-manifest-latest-pointer"
)
LATEST_POINTER_SCHEMA_VERSION: Final = 1
PUBLICATION_LAYOUT_VERSION: Final = "v1"
LATEST_POINTER_OBJECT_KEY: Final = "v1/latest.json"
MANIFEST_OBJECT_PREFIX: Final = "v1/manifests/"
#: One year, the conventional immutable ceiling; the object key is the digest.
IMMUTABLE_OBJECT_MAX_AGE_SECONDS: Final = 31_536_000
IMMUTABLE_OBJECT_CACHE_CONTROL: Final = "public, max-age=31536000, immutable"
#: A pointer may be cached for at most one minute; every manifest freshness
#: bound in the trust policy is measured in multiples of this.
LATEST_POINTER_MAX_AGE_SECONDS: Final = 60
LATEST_POINTER_CACHE_CONTROL: Final = "public, max-age=60, must-revalidate"
FETCH_REQUEST_CACHE_CONTROL: Final = "no-cache"
MAX_POINTER_BYTES: Final = 16 * 1_024

ObjectKey = Annotated[
    str,
    StringConstraints(
        min_length=len(MANIFEST_OBJECT_PREFIX) + 64 + len(".json"),
        max_length=len(MANIFEST_OBJECT_PREFIX) + 64 + len(".json"),
        pattern=r"^v1/manifests/[0-9a-f]{64}\.json$",
    ),
]

PublicationRejectionCode = Literal[
    "pointer_authority_mismatch",
    "pointer_equivocation",
    "pointer_expired",
    "pointer_future",
    "pointer_manifest_mismatch",
    "pointer_network_mismatch",
    "pointer_rollback",
    "pointer_sequence_gap",
    "pointer_signer_untrusted",
    "pointer_stale",
    "pointer_threshold_not_met",
    "pointer_trust_policy_mismatch",
    "rebind_authority_mismatch",
    "rebind_policy_expired",
    "rebind_policy_not_yet_valid",
    "rebind_policy_unchanged",
    "rebind_state_policy_mismatch",
    "signature_binding_mismatch",
]


class ManifestPublicationError(ValueError):
    """Stable, sanitized fail-closed publication-layout rejection."""

    def __init__(self, code: PublicationRejectionCode) -> None:
        super().__init__(code)
        self.code = code


def _reject(code: PublicationRejectionCode) -> NoReturn:
    raise ManifestPublicationError(code)


def manifest_object_key(manifest_digest_sha256: str) -> str:
    """Content-addressed immutable key for one manifest's canonical bytes."""

    return f"{MANIFEST_OBJECT_PREFIX}{manifest_digest_sha256}.json"


def signature_object_key(manifest_digest_sha256: str, signer_key_id: str) -> str:
    """Immutable key for one signer's envelope over one manifest."""

    return f"{MANIFEST_OBJECT_PREFIX}{manifest_digest_sha256}.{signer_key_id}.signature.json"


class AssignmentManifestLatestPointer(StrictFrozenModel):
    """The only mutable publication object: which immutable manifest is current."""

    contract_schema: Literal[
        "miss.computer/misscomputer-subnet/assignment-manifest-latest-pointer"
    ] = Field(alias="schema")
    schema_version: Literal[1]
    purpose: Literal["active_assignment_manifest_publication_v1"]
    network: Literal["finney"]
    netuid: Literal[24]
    central_authority_fingerprint_sha256: Digest
    trust_policy_digest_sha256: Digest
    sequence: PositiveEpoch
    previous_manifest_digest_sha256: Digest | None
    manifest_digest_sha256: Digest
    finalized_height: Epoch
    finalized_block_hash: Digest
    issued_at_epoch: Epoch
    expires_at_epoch: PositiveEpoch
    manifest_object_key: ObjectKey
    signer_key_ids: list[KeyID] = Field(min_length=1, max_length=MAX_KEYS)
    pointer_digest_sha256: Digest

    @model_validator(mode="after")
    def canonical_pointer(self) -> Self:
        if self.expires_at_epoch <= self.issued_at_epoch:
            raise ValueError("pointer_validity_window_invalid")
        if (self.sequence == 1) != (self.previous_manifest_digest_sha256 is None):
            raise ValueError("pointer_previous_link_invalid")
        if self.manifest_object_key != manifest_object_key(self.manifest_digest_sha256):
            raise ValueError("pointer_object_key_invalid")
        if self.signer_key_ids != sorted(set(self.signer_key_ids)):
            raise ValueError("pointer_signers_not_canonical")
        verify_model_digest(self, "pointer_digest_sha256")
        return self

    @property
    def signature_object_keys(self) -> list[str]:
        return [
            signature_object_key(self.manifest_digest_sha256, key_id)
            for key_id in self.signer_key_ids
        ]


@dataclass(frozen=True)
class LatestPointerVerdict:
    """Pre-fetch outcome: which immutable objects to fetch and whether this is a re-probe."""

    manifest_object_key: str
    signature_object_keys: list[str]
    reprobe: bool


def build_manifest_latest_pointer(
    manifest: ActiveAssignmentManifest,
    signatures: Sequence[AssignmentManifestSignatureEnvelope],
) -> AssignmentManifestLatestPointer:
    """Seal the pointer for one manifest and the exact envelopes published beside it."""

    manifest = revalidate(manifest, ActiveAssignmentManifest)
    envelopes = [revalidate(item, AssignmentManifestSignatureEnvelope) for item in signatures]
    if not 1 <= len(envelopes) <= MAX_KEYS:
        _reject("signature_binding_mismatch")
    signer_ids = [item.signer_key_id for item in envelopes]
    if signer_ids != sorted(set(signer_ids)):
        _reject("signature_binding_mismatch")
    for envelope in envelopes:
        if (
            envelope.manifest_digest_sha256 != manifest.manifest_digest_sha256
            or envelope.purpose != manifest.purpose
        ):
            _reject("signature_binding_mismatch")
    unsigned: dict[str, object] = {
        "schema": LATEST_POINTER_SCHEMA,
        "schema_version": LATEST_POINTER_SCHEMA_VERSION,
        "purpose": MANIFEST_PURPOSE,
        "network": manifest.network,
        "netuid": manifest.netuid,
        "central_authority_fingerprint_sha256": manifest.central_authority_fingerprint_sha256,
        "trust_policy_digest_sha256": manifest.trust_policy_digest_sha256,
        "sequence": manifest.sequence,
        "previous_manifest_digest_sha256": manifest.previous_manifest_digest_sha256,
        "manifest_digest_sha256": manifest.manifest_digest_sha256,
        "finalized_height": manifest.finalized_height,
        "finalized_block_hash": manifest.finalized_block_hash,
        "issued_at_epoch": manifest.issued_at_epoch,
        "expires_at_epoch": manifest.expires_at_epoch,
        "manifest_object_key": manifest_object_key(manifest.manifest_digest_sha256),
        "signer_key_ids": signer_ids,
    }
    return AssignmentManifestLatestPointer.model_validate(
        {**unsigned, "pointer_digest_sha256": digest(unsigned)}
    )


def verify_manifest_latest_pointer(
    pointer: AssignmentManifestLatestPointer,
    approved_trust_policy: AssignmentManifestTrustPolicy,
    prior_chain_state: AssignmentManifestChainState,
    *,
    evaluation_epoch: int,
) -> LatestPointerVerdict:
    """Cheap fail-closed pre-check before any immutable object is fetched.

    Every rejection here would also be a rejection of the manifest the pointer
    names, so this never widens acceptance; it only avoids fetching objects
    that cannot verify and gives the pointer its own stable reason codes.
    """

    if (
        isinstance(evaluation_epoch, bool)
        or not isinstance(evaluation_epoch, int)
        or not 0 <= evaluation_epoch <= MAX_EPOCH
    ):
        raise ValueError("evaluation_epoch_invalid")
    pointer = revalidate(pointer, AssignmentManifestLatestPointer)
    policy = revalidate(approved_trust_policy, AssignmentManifestTrustPolicy)
    state = revalidate(prior_chain_state, AssignmentManifestChainState)
    if pointer.network != policy.network or pointer.netuid != policy.netuid:
        _reject("pointer_network_mismatch")
    if pointer.central_authority_fingerprint_sha256 != policy.central_authority_fingerprint_sha256:
        _reject("pointer_authority_mismatch")
    if (
        pointer.trust_policy_digest_sha256 != policy.trust_policy_digest_sha256
        or state.trust_policy_digest_sha256 != policy.trust_policy_digest_sha256
    ):
        _reject("pointer_trust_policy_mismatch")
    trusted = {item.key_id for item in policy.trusted_keys}
    if not set(pointer.signer_key_ids) <= trusted:
        _reject("pointer_signer_untrusted")
    if len(pointer.signer_key_ids) < policy.threshold:
        _reject("pointer_threshold_not_met")
    if pointer.issued_at_epoch > evaluation_epoch + policy.max_future_skew_seconds:
        _reject("pointer_future")
    if evaluation_epoch >= pointer.expires_at_epoch:
        _reject("pointer_expired")
    if (
        evaluation_epoch > pointer.issued_at_epoch
        and evaluation_epoch - pointer.issued_at_epoch > policy.max_manifest_age_seconds
    ):
        _reject("pointer_stale")
    reprobe = False
    if state.accepted_manifest_count == 0:
        if pointer.sequence != 1:
            _reject("pointer_sequence_gap")
    elif pointer.sequence == state.last_sequence:
        if pointer.manifest_digest_sha256 != state.last_manifest_digest_sha256:
            _reject("pointer_equivocation")
        reprobe = True
    elif pointer.sequence < state.last_sequence:
        _reject("pointer_rollback")
    elif pointer.sequence - state.last_sequence > policy.max_sequence_gap:
        _reject("pointer_sequence_gap")
    return LatestPointerVerdict(
        manifest_object_key=pointer.manifest_object_key,
        signature_object_keys=pointer.signature_object_keys,
        reprobe=reprobe,
    )


def bind_latest_pointer_to_manifest(
    pointer: AssignmentManifestLatestPointer,
    manifest: ActiveAssignmentManifest,
) -> None:
    """Reject a fetched manifest that is not exactly the one the pointer named."""

    pointer = revalidate(pointer, AssignmentManifestLatestPointer)
    manifest = revalidate(manifest, ActiveAssignmentManifest)
    if (
        pointer.manifest_digest_sha256 != manifest.manifest_digest_sha256
        or pointer.sequence != manifest.sequence
        or pointer.previous_manifest_digest_sha256 != manifest.previous_manifest_digest_sha256
        or pointer.finalized_height != manifest.finalized_height
        or pointer.finalized_block_hash != manifest.finalized_block_hash
        or pointer.issued_at_epoch != manifest.issued_at_epoch
        or pointer.expires_at_epoch != manifest.expires_at_epoch
        or pointer.trust_policy_digest_sha256 != manifest.trust_policy_digest_sha256
        or pointer.central_authority_fingerprint_sha256
        != manifest.central_authority_fingerprint_sha256
        or pointer.network != manifest.network
        or pointer.netuid != manifest.netuid
    ):
        _reject("pointer_manifest_mismatch")


def rebind_manifest_chain_state_trust_policy(
    state: AssignmentManifestChainState,
    current_trust_policy: AssignmentManifestTrustPolicy,
    next_trust_policy: AssignmentManifestTrustPolicy,
    *,
    evaluation_epoch: int,
) -> AssignmentManifestChainState:
    """Carry an accepted chain position to a successor trust policy (key rotation).

    The successor must name the same authority, network, and netuid, differ
    from the current policy, and be valid at ``evaluation_epoch``. Sequence,
    digests, and chain view are preserved exactly, so a manifest published
    under the successor policy still has to extend the same append-only chain.
    """

    if (
        isinstance(evaluation_epoch, bool)
        or not isinstance(evaluation_epoch, int)
        or not 0 <= evaluation_epoch <= MAX_EPOCH
    ):
        raise ValueError("evaluation_epoch_invalid")
    state = revalidate(state, AssignmentManifestChainState)
    current = revalidate(current_trust_policy, AssignmentManifestTrustPolicy)
    successor = revalidate(next_trust_policy, AssignmentManifestTrustPolicy)
    if state.trust_policy_digest_sha256 != current.trust_policy_digest_sha256:
        _reject("rebind_state_policy_mismatch")
    if successor.trust_policy_digest_sha256 == current.trust_policy_digest_sha256:
        _reject("rebind_policy_unchanged")
    if (
        successor.central_authority_fingerprint_sha256
        != current.central_authority_fingerprint_sha256
        or successor.network != current.network
        or successor.netuid != current.netuid
        or state.central_authority_fingerprint_sha256
        != successor.central_authority_fingerprint_sha256
    ):
        _reject("rebind_authority_mismatch")
    if evaluation_epoch < successor.valid_from_epoch:
        _reject("rebind_policy_not_yet_valid")
    if evaluation_epoch >= successor.valid_until_epoch:
        _reject("rebind_policy_expired")
    unsigned: dict[str, object] = {
        "schema": MANIFEST_CHAIN_STATE_SCHEMA,
        "schema_version": PROBE_SCHEMA_VERSION,
        "purpose": MANIFEST_PURPOSE,
        "network": state.network,
        "netuid": state.netuid,
        "central_authority_fingerprint_sha256": state.central_authority_fingerprint_sha256,
        "trust_policy_digest_sha256": successor.trust_policy_digest_sha256,
        "accepted_manifest_count": state.accepted_manifest_count,
        "last_sequence": state.last_sequence,
        "last_finalized_height": state.last_finalized_height,
        "last_finalized_block_hash": state.last_finalized_block_hash,
        "last_issued_at_epoch": state.last_issued_at_epoch,
        "last_expires_at_epoch": state.last_expires_at_epoch,
        "last_manifest_digest_sha256": state.last_manifest_digest_sha256,
    }
    return AssignmentManifestChainState.model_validate(
        {**unsigned, "state_digest_sha256": digest(unsigned)}
    )


def assignment_manifest_latest_pointer_bytes(value: AssignmentManifestLatestPointer) -> bytes:
    return model_bytes(value, AssignmentManifestLatestPointer)


def parse_assignment_manifest_latest_pointer(rendered: bytes) -> AssignmentManifestLatestPointer:
    return parse_model(
        rendered,
        AssignmentManifestLatestPointer,
        assignment_manifest_latest_pointer_bytes,
        maximum_bytes=MAX_POINTER_BYTES,
    )
