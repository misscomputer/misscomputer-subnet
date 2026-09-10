# SPDX-License-Identifier: AGPL-3.0-only
"""Pure third-party verification across the frozen public checkpoint contracts.

This module composes the assignment-publication, probe/decision, and WeightPlan
boundaries without adding a scoring rule or a submission capability.  Callers
supply an independently finalized metagraph view and explicit time/height.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, NoReturn, Protocol

from .assignment_probe import (
    ActiveAssignmentManifest,
    AssignmentManifestChainState,
    AssignmentManifestSignatureEnvelope,
    AssignmentManifestTrustPolicy,
    ManifestVerificationResult,
    assignment_manifest_chain_state_bytes,
    parse_assignment_manifest_chain_state,
    verify_active_assignment_manifest,
)
from .manifest_publication import (
    AssignmentManifestLatestPointer,
    ManifestHistoryEntry,
    bind_latest_pointer_to_manifest,
    replay_manifest_history,
    verify_manifest_latest_pointer,
)
from .validator_decision import (
    ValidatorWeightDecision,
    parse_validator_weight_decision,
    validator_weight_decision_bytes,
)
from .weight_plan import (
    WEIGHT_PLAN_PROTOCOL_VERSION_KEY,
    WeightPlan,
    build_weight_plan_from_decision,
)

MAX_PUBLIC_HISTORY_ENTRIES: Final = 64


class FinalizedMetagraphView(Protocol):
    """Structural subset consumed by the frozen decision-aware plan builder."""

    network: str
    netuid: int
    block: int
    tempo: int
    neurons: object
    finalized: bool


class PublicVerifierError(ValueError):
    """Stable integration rejection with no artifact or path content."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _reject(code: str) -> NoReturn:
    raise PublicVerifierError(code)


@dataclass(frozen=True, slots=True)
class PublicRelayVerificationResult:
    """Verified live head, durable next state, and inert deterministic plan."""

    manifest_verification: ManifestVerificationResult
    decision: ValidatorWeightDecision
    weight_plan: WeightPlan
    history_entries_replayed: int


def verify_public_relay_path(
    *,
    trust_policy: AssignmentManifestTrustPolicy,
    prior_chain_state: AssignmentManifestChainState,
    latest_pointer: AssignmentManifestLatestPointer,
    history: tuple[ManifestHistoryEntry, ...],
    head_manifest: ActiveAssignmentManifest,
    head_signatures: tuple[AssignmentManifestSignatureEnvelope, ...],
    evaluation_epoch: int,
    current_finalized_height: int,
    decision: ValidatorWeightDecision,
    finalized_metagraph: FinalizedMetagraphView,
    finalized_block_hash: str,
    version_key: int = WEIGHT_PLAN_PROTOCOL_VERSION_KEY,
) -> PublicRelayVerificationResult:
    """Verify one complete public third-party relay preparation.

    The latest-pointer precheck bounds catch-up before any historical replay.
    Historical entries are authenticated in ascending order, then the named
    head is verified live (including signatures, freshness and block leases).
    The sealed decision is reparsed to re-derive policy/evidence bindings and
    is accepted only when its terminal manifest is that live head.  Finally,
    the existing decision-aware builder binds the decision to the caller's
    complete finalized metagraph and emits a dry-run :class:`WeightPlan`.

    No clock, filesystem, network, wallet, signer, executor, or submitter is
    reachable from this function.
    """

    # Deep-reparse the caller-owned state before pointer and replay checks so a
    # mutable nested object cannot be observed differently across boundaries.
    state = parse_assignment_manifest_chain_state(
        assignment_manifest_chain_state_bytes(prior_chain_state)
    )
    entries = tuple(history)
    if len(entries) > MAX_PUBLIC_HISTORY_ENTRIES:
        _reject("history_resource_limit")

    verdict = verify_manifest_latest_pointer(
        latest_pointer,
        trust_policy,
        state,
        evaluation_epoch=evaluation_epoch,
    )
    if verdict.reprobe and entries:
        _reject("history_unexpected")
    if verdict.history_depth == 0 and entries:
        _reject("history_unexpected")
    if len(entries) > verdict.history_depth:
        _reject("history_depth_exceeded")
    if verdict.history_depth > 0 and not entries:
        _reject("history_required")

    if entries:
        state = replay_manifest_history(
            state,
            entries,
            trust_policy,
            evaluation_epoch=evaluation_epoch,
        )

    bind_latest_pointer_to_manifest(latest_pointer, head_manifest, head_signatures)
    manifest_result = verify_active_assignment_manifest(
        head_manifest,
        head_signatures,
        trust_policy,
        state,
        evaluation_epoch=evaluation_epoch,
        current_finalized_height=current_finalized_height,
    )

    # A lower separately supplied lease height could make expired assignments
    # appear live while the actual plan targets a newer finalized snapshot.
    if (
        isinstance(finalized_metagraph.block, bool)
        or current_finalized_height != finalized_metagraph.block
    ):
        _reject("finalized_height_mismatch")

    sealed_decision = parse_validator_weight_decision(validator_weight_decision_bytes(decision))
    manifest = manifest_result.manifest
    if (
        sealed_decision.terminal_manifest_status != "verified"
        or sealed_decision.terminal_manifest_digest_sha256 != manifest.manifest_digest_sha256
        or sealed_decision.terminal_manifest_sequence != manifest.sequence
        or sealed_decision.terminal_finalized_height != manifest.finalized_height
        or sealed_decision.terminal_finalized_block_hash != manifest.finalized_block_hash
        or sealed_decision.terminal_finalized_epoch != manifest.finalized_epoch
    ):
        _reject("decision_terminal_mismatch")
    if not any(
        item.manifest.manifest_digest_sha256 == manifest.manifest_digest_sha256
        for item in sealed_decision.assignment_manifest_evidence
    ):
        _reject("decision_terminal_evidence_missing")
    if not any(
        item.trust_policy_digest_sha256 == trust_policy.trust_policy_digest_sha256
        for item in sealed_decision.trust_policies
    ):
        _reject("decision_trust_policy_missing")

    plan = build_weight_plan_from_decision(
        sealed_decision,
        snapshot=finalized_metagraph,  # type: ignore[arg-type]
        finalized_block_hash=finalized_block_hash,
        version_key=version_key,
    )
    return PublicRelayVerificationResult(
        manifest_verification=manifest_result,
        decision=sealed_decision,
        weight_plan=plan,
        history_entries_replayed=len(entries),
    )
