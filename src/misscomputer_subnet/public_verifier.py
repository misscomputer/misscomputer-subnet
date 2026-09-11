# SPDX-License-Identifier: AGPL-3.0-only
"""Pure third-party verification across the frozen public checkpoint contracts.

This module composes the assignment-publication, probe/decision, and WeightPlan
boundaries without adding a scoring rule or a submission capability.  Callers
supply an independently finalized metagraph view and explicit time/height.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Final, NoReturn, Protocol, cast

from .assignment_probe import (
    ActiveAssignmentManifest,
    AssignmentManifestChainState,
    AssignmentManifestSignatureEnvelope,
    AssignmentManifestTrustPolicy,
    ManifestVerificationResult,
    ValidatorProbeReport,
    assignment_manifest_chain_state_bytes,
    parse_assignment_manifest_chain_state,
    parse_validator_probe_report,
    validator_probe_report_bytes,
    verify_active_assignment_manifest,
    verify_miner_probe_attestation,
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
#: A public relay is a close-time operation. The independently trusted caller
#: clock may differ from the decision producer's clock by at most this bound.
PUBLIC_EVALUATION_TOLERANCE_SECONDS: Final = 5


class FinalizedNeuronView(Protocol):
    """Structural neuron fields copied into the verifier's immutable view."""

    uid: int
    hotkey: str
    validator_permit: bool
    tao_stake: float
    axon: str | None
    active: bool


class FinalizedMetagraphView(Protocol):
    """Caller-owned fields normalized before the weight builder can read them."""

    network: str
    netuid: int
    block: int
    tempo: int
    neurons: Sequence[FinalizedNeuronView]
    finalized: bool


@dataclass(frozen=True, slots=True)
class _NormalizedNeuron:
    uid: int
    hotkey: str
    validator_permit: bool
    tao_stake: float
    axon: str | None
    active: bool


@dataclass(frozen=True, slots=True)
class _NormalizedMetagraph:
    network: str
    netuid: int
    block: int
    tempo: int
    neurons: tuple[_NormalizedNeuron, ...]
    finalized: bool

    @property
    def epoch(self) -> int:
        """Derive the epoch from the copied block/tempo; never trust a caller label."""

        return self.block // self.tempo


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


def _normalize_metagraph(value: FinalizedMetagraphView) -> _NormalizedMetagraph:
    """Copy every plan-consumed field once into an immutable structural snapshot."""

    try:
        neurons = tuple(
            _NormalizedNeuron(
                uid=item.uid,
                hotkey=item.hotkey,
                validator_permit=item.validator_permit,
                tao_stake=item.tao_stake,
                axon=item.axon,
                active=item.active,
            )
            for item in value.neurons
        )
        return _NormalizedMetagraph(
            network=value.network,
            netuid=value.netuid,
            block=value.block,
            tempo=value.tempo,
            neurons=neurons,
            finalized=value.finalized,
        )
    except (AttributeError, TypeError):
        _reject("finalized_metagraph_invalid")


def _verify_decision_probe_evidence(
    decision: ValidatorWeightDecision,
    *,
    trusted_evaluation_epoch: int,
    retained_probe_reports: tuple[ValidatorProbeReport, ...],
) -> None:
    """Bind retained reports, reauthenticate credits, and reject probe replay."""

    # Frozen Pydantic models still contain mutable observations. A caller's
    # cached digest alone is not evidence of the retained archive's contents.
    try:
        retained = tuple(
            parse_validator_probe_report(validator_probe_report_bytes(item))
            for item in retained_probe_reports
        )
    except (AttributeError, TypeError, ValueError, RecursionError):
        _reject("decision_probe_records_invalid")
    retained_digests = [item.report_digest_sha256 for item in retained]
    sealed_digests = [
        report.report_digest_sha256
        for evidence in decision.assignment_manifest_evidence
        for report in evidence.scoring_reports
    ]
    if len(retained_digests) != len(set(retained_digests)) or sorted(retained_digests) != sorted(
        sealed_digests
    ):
        _reject("decision_probe_records_mismatch")

    tolerance = PUBLIC_EVALUATION_TOLERANCE_SECONDS
    if (
        abs(decision.window_end_epoch - trusted_evaluation_epoch) > tolerance
        or abs(decision.terminal_evaluated_at_epoch - trusted_evaluation_epoch) > tolerance
    ):
        _reject("decision_time_mismatch")

    seen_probe_nonces: set[str] = set()
    seen_attestations: set[tuple[str, str]] = set()
    latest_admissible_report = trusted_evaluation_epoch + tolerance
    for evidence in decision.assignment_manifest_evidence:
        deployments = {item.deployment_id: item for item in evidence.manifest.deployments}
        for report in evidence.scoring_reports:
            if report.evaluation_epoch > latest_admissible_report:
                _reject("decision_report_future")
            for observation in report.observations:
                if observation.probe_nonce in seen_probe_nonces:
                    _reject("decision_probe_evidence_replayed")
                seen_probe_nonces.add(observation.probe_nonce)
                if observation.outcome != "serving":
                    continue
                attestation = observation.attestation
                deployment = deployments.get(observation.deployment_id)
                if (
                    attestation is None
                    or deployment is None
                    or observation.response_body_sha256 is None
                ):
                    _reject("decision_attestation_invalid")
                authenticated_identity = (
                    attestation.miner_service_public_key,
                    attestation.signature_hex,
                )
                if authenticated_identity in seen_attestations:
                    _reject("decision_probe_evidence_replayed")
                seen_attestations.add(authenticated_identity)
                try:
                    verify_miner_probe_attestation(
                        attestation,
                        deployment,
                        probe_nonce=observation.probe_nonce,
                        response_body_sha256=observation.response_body_sha256,
                    )
                except ValueError:
                    _reject("decision_attestation_invalid")


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
    retained_probe_reports: tuple[ValidatorProbeReport, ...],
    finalized_metagraph: FinalizedMetagraphView,
    finalized_block_hash: str,
    version_key: int = WEIGHT_PLAN_PROTOCOL_VERSION_KEY,
) -> PublicRelayVerificationResult:
    """Verify one complete public third-party relay preparation.

    The latest-pointer precheck bounds catch-up before any historical replay.
    Historical entries are authenticated in ascending order, then the named
    head is verified live (including signatures, freshness and block leases).
    The sealed decision is reparsed to re-derive policy/evidence bindings, its
    reports must exactly match the caller's independently retained archive,
    and it is accepted only when its terminal manifest is that live head. Finally,
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

    # Copy the caller's structural adapter once. This both removes a mutable
    # read-after-check surface and safely derives the epoch omitted by the
    # public Protocol instead of asking adapters to supply a trusted label.
    normalized_metagraph = _normalize_metagraph(finalized_metagraph)

    # A lower separately supplied lease height could make expired assignments
    # appear live while the actual plan targets a newer finalized snapshot.
    if (
        isinstance(normalized_metagraph.block, bool)
        or current_finalized_height != normalized_metagraph.block
    ):
        _reject("finalized_height_mismatch")

    sealed_decision = parse_validator_weight_decision(validator_weight_decision_bytes(decision))
    _verify_decision_probe_evidence(
        sealed_decision,
        trusted_evaluation_epoch=evaluation_epoch,
        retained_probe_reports=retained_probe_reports,
    )
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
        snapshot=cast(Any, normalized_metagraph),
        finalized_block_hash=finalized_block_hash,
        version_key=version_key,
    )
    return PublicRelayVerificationResult(
        manifest_verification=manifest_result,
        decision=sealed_decision,
        weight_plan=plan,
        history_entries_replayed=len(entries),
    )
