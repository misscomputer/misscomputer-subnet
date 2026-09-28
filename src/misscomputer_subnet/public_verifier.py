# SPDX-License-Identifier: AGPL-3.0-only
"""Pure third-party verification of one organic validator's weight preparation.

This module composes the organic manifest v2 verification, the sealed
``validator-weight-decision`` v2 (which embeds and replays the validator's own
hidden-probe epochs), and the decision-aware WeightPlan builder, without adding
a scoring rule or a submission capability. Callers supply an independently
finalized metagraph view and explicit time/height.

v2 manifest catch-up: the caller's prior chain state must already reach the
head's predecessor (or be genesis, for onboarding through
:func:`~misscomputer_subnet.organic_manifest.anchor_organic_manifest_chain_state`).
The v2 latest-pointer/history walk is a documented publication gap; see
``docs/organic-availability-scoring.md``.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Final, NoReturn, Protocol, cast

from .assignment_probe import (
    AssignmentManifestChainState,
    AssignmentManifestSignatureEnvelope,
    AssignmentManifestTrustPolicy,
    assignment_manifest_chain_state_bytes,
    parse_assignment_manifest_chain_state,
)
from .organic_contracts import ActiveAssignmentManifestV2
from .organic_manifest import OrganicManifestVerification, verify_organic_assignment_manifest
from .organic_scoring import OrganicEpochScore, organic_epoch_score_bytes, parse_organic_epoch_score
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

    manifest_verification: OrganicManifestVerification
    decision: ValidatorWeightDecision
    weight_plan: WeightPlan


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


def _verify_decision_epoch_evidence(
    decision: ValidatorWeightDecision,
    *,
    trusted_evaluation_epoch: int,
    retained_epoch_records: tuple[OrganicEpochScore, ...],
) -> None:
    """Bind the retained epoch archive, the close time, and reject cross-epoch replay."""

    # Frozen models still contain mutable lists: reparse the caller's archive.
    try:
        retained = tuple(
            parse_organic_epoch_score(organic_epoch_score_bytes(item))
            for item in retained_epoch_records
        )
    except (AttributeError, TypeError, ValueError, RecursionError):
        _reject("decision_epoch_records_invalid")
    retained_digests = sorted(item.epoch_score_digest_sha256 for item in retained)
    sealed_digests = sorted(item.epoch_score_digest_sha256 for item in decision.epochs)
    if len(set(retained_digests)) != len(retained_digests) or retained_digests != sealed_digests:
        _reject("decision_epoch_records_mismatch")
    tolerance = PUBLIC_EVALUATION_TOLERANCE_SECONDS
    if (
        abs(decision.window_end_epoch - trusted_evaluation_epoch) > tolerance
        or abs(decision.terminal_evaluated_at_epoch - trusted_evaluation_epoch) > tolerance
    ):
        _reject("decision_time_mismatch")
    seen_nonces: set[str] = set()
    seen_signatures: set[str] = set()
    for epoch in decision.epochs:
        if (epoch.epoch_index + 1) * epoch.epoch_seconds > trusted_evaluation_epoch + tolerance:
            _reject("decision_epoch_future")
        for observation in epoch.observations:
            if observation.probe_nonce in seen_nonces:
                _reject("decision_probe_evidence_replayed")
            seen_nonces.add(observation.probe_nonce)
            if observation.attestation is not None:
                if observation.attestation.signature_hex in seen_signatures:
                    _reject("decision_probe_evidence_replayed")
                seen_signatures.add(observation.attestation.signature_hex)


def verify_public_relay_path(
    *,
    trust_policy: AssignmentManifestTrustPolicy,
    prior_chain_state: AssignmentManifestChainState,
    head_manifest: ActiveAssignmentManifestV2,
    head_signatures: tuple[AssignmentManifestSignatureEnvelope, ...],
    evaluation_epoch: int,
    current_finalized_height: int,
    decision: ValidatorWeightDecision,
    retained_epoch_records: tuple[OrganicEpochScore, ...],
    finalized_metagraph: FinalizedMetagraphView,
    finalized_block_hash: str,
    version_key: int = WEIGHT_PLAN_PROTOCOL_VERSION_KEY,
) -> PublicRelayVerificationResult:
    """Verify one complete public third-party relay preparation.

    The named head manifest is verified live (signatures, freshness, identity
    rules, leases, append-only chain). The sealed decision is reparsed, which
    replays every embedded epoch against its embedded manifests and re-derives
    every row and abstain reason; its epochs must exactly match the caller's
    independently retained archive, and it is accepted only when its terminal
    manifest is that live head. The existing decision-aware builder then binds
    the decision to the caller's complete finalized metagraph and emits a
    dry-run :class:`WeightPlan`.

    No clock, filesystem, network, wallet, signer, executor, or submitter is
    reachable from this function.
    """

    state = parse_assignment_manifest_chain_state(
        assignment_manifest_chain_state_bytes(prior_chain_state)
    )
    manifest_result = verify_organic_assignment_manifest(
        head_manifest,
        head_signatures,
        trust_policy,
        state,
        evaluation_epoch=evaluation_epoch,
        current_finalized_height=current_finalized_height,
    )
    normalized_metagraph = _normalize_metagraph(finalized_metagraph)
    if (
        isinstance(normalized_metagraph.block, bool)
        or current_finalized_height != normalized_metagraph.block
    ):
        _reject("finalized_height_mismatch")
    sealed_decision = parse_validator_weight_decision(validator_weight_decision_bytes(decision))
    _verify_decision_epoch_evidence(
        sealed_decision,
        trusted_evaluation_epoch=evaluation_epoch,
        retained_epoch_records=retained_epoch_records,
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
    )
