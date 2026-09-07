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
- ``v1/manifests/<manifest_digest_sha256>.pointer.json`` — the immutable copy
  of the latest pointer as it was published for that manifest; it is what
  makes the publication history discoverable by walking ``previous`` links;
- ``v1/latest.json`` — the only mutable object: an
  ``assignment-manifest-latest-pointer`` v1 naming the current publication.

Atomic publication order
------------------------
The manifest object, every signature object, and the immutable pointer copy
are written and readable *before* ``v1/latest.json`` is replaced; the latest
pointer is replaced atomically (single object PUT or rename). A reader that
follows the pointer therefore always finds complete, immutable objects. A
pointer is never rewritten to a lower sequence. Immutable objects are never
modified or deleted while any validator could still need them to catch up.

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
signed manifest and the exact signature envelopes it names, and the object
key is the manifest's own digest. A forged pointer can only name a manifest
that verifies under the pinned trust policy, with the signer set the pointer
itself claims, and the append-only chain state rejects any rollback or
equivocation it might point at. Signing the pointer would add a signing
ceremony per publication without changing what an attacker can achieve.

Onboarding and catch-up
-----------------------
A validator's chain state starts at genesis and otherwise only ever advances
through accepted digest-linked publications (whose sequence values may make
bounded positive jumps), so two situations need a defined, authenticated path:

- **Onboarding.** A validator with no history has nothing to compare against;
  :func:`anchor_manifest_chain_state` accepts the current head at any
  sequence, but only through the complete live verification (canonical form,
  policy, threshold, roles, real signatures, freshness, block leases) and only
  from a genesis state. Its non-equivocation history begins at that anchor.
  An operator may instead distribute an already-anchored chain state beside
  the trust policy; both travel over the same out-of-band trust channel.
- **Catch-up.** A validator that missed publications walks ``previous``
  links back from the head, fetching each historical manifest, its immutable
  pointer copy, and the signature objects the copy names, until it reaches
  its last accepted digest. :func:`replay_manifest_history` then verifies the
  actual span in ascending order under historical semantics and yields the
  state from which the head verifies live. The span is bounded by the pinned
  policy's ``max_sequence_gap`` actual history entries; a deeper history is
  an operator re-anchoring event, never a silent reset.

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
    AssignmentProbeError,
    Digest,
    Epoch,
    KeyID,
    ManifestVerificationResult,
    PositiveEpoch,
    verify_active_assignment_manifest,
    verify_historical_active_assignment_manifest,
    verify_pointer_signer_set,
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
    "anchor_state_not_genesis",
    "history_depth_exceeded",
    "history_link_mismatch",
    "history_pointer_mismatch",
    "pointer_authority_mismatch",
    "pointer_equivocation",
    "pointer_expired",
    "pointer_future",
    "pointer_manifest_mismatch",
    "pointer_network_mismatch",
    "pointer_required_role_missing",
    "pointer_rollback",
    "pointer_sequence_gap",
    "pointer_signature_mismatch",
    "pointer_signer_invalid",
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


def _validate_evaluation_epoch(evaluation_epoch: int) -> None:
    if (
        isinstance(evaluation_epoch, bool)
        or not isinstance(evaluation_epoch, int)
        or not 0 <= evaluation_epoch <= MAX_EPOCH
    ):
        raise ValueError("evaluation_epoch_invalid")


def manifest_object_key(manifest_digest_sha256: str) -> str:
    """Content-addressed immutable key for one manifest's canonical bytes."""

    return f"{MANIFEST_OBJECT_PREFIX}{manifest_digest_sha256}.json"


def signature_object_key(manifest_digest_sha256: str, signer_key_id: str) -> str:
    """Immutable key for one signer's envelope over one manifest."""

    return f"{MANIFEST_OBJECT_PREFIX}{manifest_digest_sha256}.{signer_key_id}.signature.json"


def pointer_object_key(manifest_digest_sha256: str) -> str:
    """Immutable key for the pointer copy published beside one manifest."""

    return f"{MANIFEST_OBJECT_PREFIX}{manifest_digest_sha256}.pointer.json"


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
    finalized_epoch: Epoch
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

    @property
    def pointer_object_key(self) -> str:
        return pointer_object_key(self.manifest_digest_sha256)


@dataclass(frozen=True)
class LatestPointerVerdict:
    """Pre-fetch outcome: which immutable objects to fetch and how the chain state relates.

    Sequence numbers may make bounded jumps, so a head pointer alone cannot
    reveal the exact number of publications between it and the last accepted
    digest. ``history_depth`` is therefore the maximum number of historical
    entries the fetcher may walk: zero when the head directly names the local
    digest, otherwise the tighter of the remaining sequence slots and the
    policy's history-entry bound. The walk stops when it reaches the local
    digest and :func:`replay_manifest_history` validates its actual length.
    """

    manifest_object_key: str
    signature_object_keys: list[str]
    reprobe: bool
    history_depth: int


@dataclass(frozen=True)
class ManifestHistoryEntry:
    """One historical publication as fetched during catch-up: pointer copy, manifest, envelopes."""

    pointer: AssignmentManifestLatestPointer
    manifest: ActiveAssignmentManifest
    signatures: Sequence[AssignmentManifestSignatureEnvelope]


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
        "finalized_epoch": manifest.finalized_epoch,
        "issued_at_epoch": manifest.issued_at_epoch,
        "expires_at_epoch": manifest.expires_at_epoch,
        "manifest_object_key": manifest_object_key(manifest.manifest_digest_sha256),
        "signer_key_ids": signer_ids,
    }
    return AssignmentManifestLatestPointer.model_validate(
        {**unsigned, "pointer_digest_sha256": digest(unsigned)}
    )


def _verify_pointer_signer_provenance(
    pointer: AssignmentManifestLatestPointer,
    policy: AssignmentManifestTrustPolicy,
    *,
    evaluation_epoch: int,
) -> None:
    """Refuse a pointer whose claimed signer set could not satisfy the pinned policy."""

    try:
        verify_pointer_signer_set(
            policy,
            pointer.signer_key_ids,
            issued_at_epoch=pointer.issued_at_epoch,
            expires_at_epoch=pointer.expires_at_epoch,
            evaluation_epoch=evaluation_epoch,
        )
    except AssignmentProbeError as failure:
        if failure.code == "signer_untrusted":
            _reject("pointer_signer_untrusted")
        if failure.code == "threshold_not_met":
            _reject("pointer_threshold_not_met")
        if failure.code == "required_role_missing":
            _reject("pointer_required_role_missing")
        _reject("pointer_signer_invalid")


def _verify_pointer_chain_position(
    pointer: AssignmentManifestLatestPointer,
    policy: AssignmentManifestTrustPolicy,
    state: AssignmentManifestChainState,
) -> tuple[bool, int]:
    """Mirror the append-only chain rules on the pointer's copied chain fields.

    Returns ``(reprobe, history_depth)``. A sequence delta is bounded only for
    a direct digest-linked transition. When history is required, its actual
    entries (and the final head transition) enforce that bound per hop; the
    pointer can expose only a safe traversal budget, not an exact depth.
    """

    if state.accepted_manifest_count == 0:
        if pointer.sequence != 1:
            _reject("pointer_sequence_gap")
        return False, 0
    if pointer.sequence == state.last_sequence:
        if pointer.manifest_digest_sha256 != state.last_manifest_digest_sha256:
            _reject("pointer_equivocation")
        return True, 0
    if pointer.sequence < state.last_sequence:
        _reject("pointer_rollback")
    sequence_delta = pointer.sequence - state.last_sequence
    direct_extension = pointer.previous_manifest_digest_sha256 == state.last_manifest_digest_sha256
    if direct_extension:
        if sequence_delta > policy.max_sequence_gap:
            _reject("pointer_sequence_gap")
        history_depth = 0
    else:
        # At least one intermediate publication is required. With strictly
        # increasing sequence numbers, a delta of one leaves no slot for it.
        if sequence_delta == 1:
            _reject("pointer_equivocation")
        # Each digest-linked hop may advance by at most max_sequence_gap and
        # at most that many actual historical entries may be replayed. Reject
        # only when even the shortest possible bounded-jump path cannot fit;
        # a large cumulative delta is otherwise not itself a per-hop failure.
        minimum_history_entries = (sequence_delta - 1) // policy.max_sequence_gap
        if minimum_history_entries > policy.max_sequence_gap:
            _reject("pointer_sequence_gap")
        history_depth = min(sequence_delta - 1, policy.max_sequence_gap)
    last_height = state.last_finalized_height
    last_epoch = state.last_finalized_epoch
    if last_height is None or last_epoch is None:
        _reject("pointer_rollback")
    if pointer.finalized_height < last_height or pointer.finalized_epoch < last_epoch:
        _reject("pointer_rollback")
    if direct_extension and (
        pointer.finalized_height - last_height > policy.max_finalized_height_gap
    ):
        _reject("pointer_sequence_gap")
    if pointer.finalized_height == last_height and (
        pointer.finalized_block_hash != state.last_finalized_block_hash
        or pointer.finalized_epoch != last_epoch
    ):
        _reject("pointer_equivocation")
    last_issued = state.last_issued_at_epoch
    if last_issued is None or pointer.issued_at_epoch < last_issued:
        _reject("pointer_rollback")
    return False, history_depth


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
    that cannot verify and gives the pointer its own stable reason codes. The
    signer set the pointer claims is checked against the pinned policy's key
    validity windows, revocations, threshold, and required roles exactly as
    the envelopes will be, minus the cryptography.
    """

    _validate_evaluation_epoch(evaluation_epoch)
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
    if (
        pointer.issued_at_epoch < policy.valid_from_epoch
        or pointer.expires_at_epoch > policy.valid_until_epoch
        or pointer.expires_at_epoch - pointer.issued_at_epoch > policy.max_manifest_lifetime_seconds
    ):
        _reject("pointer_trust_policy_mismatch")
    _verify_pointer_signer_provenance(pointer, policy, evaluation_epoch=evaluation_epoch)
    if pointer.issued_at_epoch > evaluation_epoch + policy.max_future_skew_seconds:
        _reject("pointer_future")
    if evaluation_epoch >= pointer.expires_at_epoch:
        _reject("pointer_expired")
    if (
        evaluation_epoch > pointer.issued_at_epoch
        and evaluation_epoch - pointer.issued_at_epoch > policy.max_manifest_age_seconds
    ):
        _reject("pointer_stale")
    reprobe, history_depth = _verify_pointer_chain_position(pointer, policy, state)
    return LatestPointerVerdict(
        manifest_object_key=pointer.manifest_object_key,
        signature_object_keys=pointer.signature_object_keys,
        reprobe=reprobe,
        history_depth=history_depth,
    )


def bind_latest_pointer_to_manifest(
    pointer: AssignmentManifestLatestPointer,
    manifest: ActiveAssignmentManifest,
    signatures: Sequence[AssignmentManifestSignatureEnvelope],
) -> None:
    """Reject fetched objects that are not exactly the manifest and envelopes the pointer named.

    The envelopes must be exactly the pointer's signer set, in the pointer's
    canonical order, each over the pointer's manifest digest; a fetcher that
    obtained a different or additional envelope has not fetched what was
    published and must not proceed to signature verification with it.
    """

    pointer = revalidate(pointer, AssignmentManifestLatestPointer)
    manifest = revalidate(manifest, ActiveAssignmentManifest)
    envelopes = [revalidate(item, AssignmentManifestSignatureEnvelope) for item in signatures]
    if (
        pointer.manifest_digest_sha256 != manifest.manifest_digest_sha256
        or pointer.sequence != manifest.sequence
        or pointer.previous_manifest_digest_sha256 != manifest.previous_manifest_digest_sha256
        or pointer.finalized_height != manifest.finalized_height
        or pointer.finalized_block_hash != manifest.finalized_block_hash
        or pointer.finalized_epoch != manifest.finalized_epoch
        or pointer.issued_at_epoch != manifest.issued_at_epoch
        or pointer.expires_at_epoch != manifest.expires_at_epoch
        or pointer.trust_policy_digest_sha256 != manifest.trust_policy_digest_sha256
        or pointer.central_authority_fingerprint_sha256
        != manifest.central_authority_fingerprint_sha256
        or pointer.network != manifest.network
        or pointer.netuid != manifest.netuid
        or pointer.purpose != manifest.purpose
    ):
        _reject("pointer_manifest_mismatch")
    if [item.signer_key_id for item in envelopes] != pointer.signer_key_ids:
        _reject("pointer_signature_mismatch")
    for envelope in envelopes:
        if (
            envelope.manifest_digest_sha256 != pointer.manifest_digest_sha256
            or envelope.purpose != pointer.purpose
        ):
            _reject("pointer_signature_mismatch")


def anchor_manifest_chain_state(
    manifest: ActiveAssignmentManifest,
    signatures: Sequence[AssignmentManifestSignatureEnvelope],
    approved_trust_policy: AssignmentManifestTrustPolicy,
    genesis_chain_state: AssignmentManifestChainState,
    *,
    evaluation_epoch: int,
    current_finalized_height: int,
) -> ManifestVerificationResult:
    """Onboard a validator with no history on the current live head, at any sequence.

    This is the one deliberate exception to "genesis accepts only sequence 1"
    and it is available only from a genesis state, so it can never be used to
    skip past history a validator already holds. The head must pass complete
    live verification, including its block leases against the validator's
    ``current_finalized_height``; the resulting state records one accepted
    manifest at the head's sequence, and every later publication must extend
    it through the ordinary append-only rules.
    """

    _validate_evaluation_epoch(evaluation_epoch)
    state = revalidate(genesis_chain_state, AssignmentManifestChainState)
    if state.accepted_manifest_count != 0:
        _reject("anchor_state_not_genesis")
    policy = revalidate(approved_trust_policy, AssignmentManifestTrustPolicy)
    value = revalidate(manifest, ActiveAssignmentManifest)
    if state.trust_policy_digest_sha256 != policy.trust_policy_digest_sha256:
        _reject("rebind_state_policy_mismatch")
    # Verify the head exactly as the live path would, against a synthetic
    # genesis that already sits one sequence below it, so the append-only
    # rules (link, height, epoch, issue time) are not bypassed for the anchor.
    if value.sequence == 1:
        return verify_active_assignment_manifest(
            value,
            signatures,
            policy,
            state,
            evaluation_epoch=evaluation_epoch,
            current_finalized_height=current_finalized_height,
        )
    unsigned: dict[str, object] = {
        "schema": MANIFEST_CHAIN_STATE_SCHEMA,
        "schema_version": PROBE_SCHEMA_VERSION,
        "purpose": MANIFEST_PURPOSE,
        "network": state.network,
        "netuid": state.netuid,
        "central_authority_fingerprint_sha256": state.central_authority_fingerprint_sha256,
        "trust_policy_digest_sha256": state.trust_policy_digest_sha256,
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
    result = verify_active_assignment_manifest(
        value,
        signatures,
        policy,
        predecessor,
        evaluation_epoch=evaluation_epoch,
        current_finalized_height=current_finalized_height,
    )
    anchored: dict[str, object] = {
        **unsigned,
        "accepted_manifest_count": 1,
        "last_sequence": value.sequence,
        "last_manifest_digest_sha256": value.manifest_digest_sha256,
    }
    return ManifestVerificationResult(
        manifest=result.manifest,
        verified_signer_key_ids=result.verified_signer_key_ids,
        verified_roles=result.verified_roles,
        next_chain_state=AssignmentManifestChainState.model_validate(
            {**anchored, "state_digest_sha256": digest(anchored)}
        ),
        reprobe=False,
    )


def replay_manifest_history(
    prior_chain_state: AssignmentManifestChainState,
    history: Sequence[ManifestHistoryEntry],
    approved_trust_policy: AssignmentManifestTrustPolicy,
    *,
    evaluation_epoch: int,
) -> AssignmentManifestChainState:
    """Advance a chain state across the digest-linked historical publications it missed.

    ``history`` is the span strictly between the validator's last accepted
    manifest and the live head, in ascending sequence order, each entry
    carrying the immutable pointer copy, the manifest, and exactly the
    envelopes that copy names. Every entry is bound pointer-to-objects, then
    verified under historical semantics, and must be exactly the next
    digest-linked transition; its positive sequence delta is independently
    bounded by ``max_sequence_gap``. The returned state is the one the live
    head must extend. The head itself is not part of the history and is
    verified live afterwards, which is what authenticates the replayed span
    end to end. The span may not exceed the policy's ``max_sequence_gap``; a
    validator further behind than that is re-anchored by its operator, never
    silently resynchronised.
    """

    _validate_evaluation_epoch(evaluation_epoch)
    state = revalidate(prior_chain_state, AssignmentManifestChainState)
    policy = revalidate(approved_trust_policy, AssignmentManifestTrustPolicy)
    # Snapshot the caller-owned sequence before measuring it so the actual
    # entries checked against the bound are exactly the entries replayed.
    entries = tuple(history)
    if len(entries) > policy.max_sequence_gap:
        _reject("history_depth_exceeded")
    for entry in entries:
        pointer = revalidate(entry.pointer, AssignmentManifestLatestPointer)
        manifest = revalidate(entry.manifest, ActiveAssignmentManifest)
        if (
            pointer.trust_policy_digest_sha256 != policy.trust_policy_digest_sha256
            or pointer.central_authority_fingerprint_sha256
            != policy.central_authority_fingerprint_sha256
            or pointer.network != policy.network
            or pointer.netuid != policy.netuid
        ):
            _reject("history_pointer_mismatch")
        try:
            _verify_pointer_signer_provenance(
                pointer, policy, evaluation_epoch=pointer.issued_at_epoch
            )
            bind_latest_pointer_to_manifest(pointer, manifest, entry.signatures)
        except ManifestPublicationError:
            _reject("history_pointer_mismatch")
        if state.accepted_manifest_count == 0:
            sequence_gap = manifest.sequence != 1
        else:
            sequence_delta = manifest.sequence - state.last_sequence
            sequence_gap = not 1 <= sequence_delta <= policy.max_sequence_gap
        if sequence_gap or (
            state.accepted_manifest_count > 0
            and manifest.previous_manifest_digest_sha256 != state.last_manifest_digest_sha256
        ):
            _reject("history_link_mismatch")
        state = verify_historical_active_assignment_manifest(
            manifest,
            entry.signatures,
            policy,
            state,
            evaluation_epoch=evaluation_epoch,
        ).next_chain_state
    return state


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

    _validate_evaluation_epoch(evaluation_epoch)
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
        "last_finalized_epoch": state.last_finalized_epoch,
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
