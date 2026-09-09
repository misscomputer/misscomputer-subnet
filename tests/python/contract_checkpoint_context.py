# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic contract-checkpoint fixture publication shared by the tests.

Running this module directly regenerates the committed ``contracts/fixtures``,
``contracts/schemas``, and ``contracts/negative`` entries for the
active-assignment snapshot, manifest latest-pointer, and validator
weight-decision contracts. Every key and nonce is derived from a fixed label,
so the committed bytes are reproducible and contain no real secret material.
The snapshot fixture projects to exactly the committed
``active-assignment-manifest.v1.json`` deployments.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from assignment_probe_context import (
    BASE_EPOCH,
    FINALIZED_BLOCK_HASH,
    FINALIZED_HEIGHT,
    MINERS,
    PROBE_PORT,
    ROOT,
    ROUTE_SUFFIX,
    build_deployment,
    build_manifest,
    build_policy,
    fixture_deployments,
    label_digest,
    make_context,
    serving_response,
    sign_attestation,
    sign_manifest,
    signer_keys,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import BaseModel

from misscomputer_subnet.assignment_probe import (
    ActiveAssignmentManifest,
    ActiveDeploymentAssignment,
    AssignedReplica,
    AssignmentManifestChainState,
    AssignmentManifestTrustPolicy,
    ProbeTransportFailure,
    build_initial_manifest_chain_state,
    build_validator_probe_report,
    evaluate_probe_response,
    verify_active_assignment_manifest,
)
from misscomputer_subnet.assignment_snapshot import (
    TICKET_MAX_FUTURE_SKEW_SECONDS,
    ActiveAssignmentSnapshot,
    SnapshotDeployment,
    SnapshotLineage,
    active_assignment_snapshot_bytes,
    advance_snapshot_lineage,
    build_active_assignment_snapshot,
    build_initial_snapshot_lineage,
    build_snapshot_deployment,
    build_snapshot_replica,
    snapshot_lineage_bytes,
)
from misscomputer_subnet.contract_codec import canonical_json
from misscomputer_subnet.contract_codec import digest as canonical_digest
from misscomputer_subnet.manifest_publication import (
    AssignmentManifestLatestPointer,
    assignment_manifest_latest_pointer_bytes,
    build_manifest_latest_pointer,
)
from misscomputer_subnet.probe_scoring import ProbeRound, RegisteredMiner
from misscomputer_subnet.validator_decision import (
    AssignedBaseline,
    RegisteredMinerSet,
    TerminalManifestObservation,
    ValidatorWeightDecision,
    WeightDecisionPolicy,
    decide_weight_submission,
    validator_weight_decision_bytes,
)
from misscomputer_subnet.weight_plan import snapshot_identity_fingerprint

VALIDATOR_UID = 7
VALIDATOR_HOTKEY = "ValidatorA"
WINDOW_START = BASE_EPOCH
WINDOW_END = BASE_EPOCH + 3_600
ROUTE_ACTIVATED_AT = BASE_EPOCH - 100
SNAPSHOT_SEQUENCE = 1
STATE_REVISION = 7
EXTRA_MINERS: tuple[tuple[int, str], ...] = ((14, "MinerE"), (15, "MinerF"), (16, "MinerG"))
REGISTERED_MINERS: tuple[tuple[int, str], ...] = MINERS + EXTRA_MINERS
REGISTERED_HEIGHT = FINALIZED_HEIGHT + 50
REGISTERED_TEMPO = 100
#: The window's manifests carry tickets and block leases renewed past window
#: close, as a live scheduler would republish them; the committed manifest
#: fixture keeps its original, shorter windows.
WINDOW_TICKET_EXPIRES_AT = WINDOW_END + 3_600
WINDOW_LEASE_EXPIRES_AT_BLOCK = FINALIZED_HEIGHT + 2_000
REGISTERED_BLOCK_HASH = label_digest("contract-checkpoint-registered-block")


@dataclass(frozen=True, slots=True)
class MetagraphNeuron:
    """Duck-typed ``chain.NeuronRecord`` so fixtures never need the chain client."""

    uid: int
    hotkey: str
    validator_permit: bool
    tao_stake: float
    axon: str | None
    active: bool = True


@dataclass(frozen=True, slots=True)
class MetagraphView:
    """Duck-typed ``chain.MetagraphSnapshot``: exactly what ``weight_plan`` reads."""

    network: str
    netuid: int
    block: int
    tempo: int
    neurons: tuple[MetagraphNeuron, ...]
    finalized: bool = True

    @property
    def epoch(self) -> int:
        return self.block // self.tempo


def metagraph_view(
    *,
    miners: Sequence[tuple[int, str]] = REGISTERED_MINERS,
    finalized_height: int = REGISTERED_HEIGHT,
    tempo: int = REGISTERED_TEMPO,
) -> MetagraphView:
    """The finalized metagraph the golden registered set and weight plan are bound to."""

    neurons = [
        MetagraphNeuron(
            uid=VALIDATOR_UID,
            hotkey=VALIDATOR_HOTKEY,
            validator_permit=True,
            tao_stake=1_000.0,
            axon=None,
        ),
        *[
            MetagraphNeuron(
                uid=uid, hotkey=hotkey, validator_permit=False, tao_stake=1.0, axon="127.0.0.1:8091"
            )
            for uid, hotkey in miners
        ],
    ]
    return MetagraphView(
        network="finney",
        netuid=24,
        block=finalized_height,
        tempo=tempo,
        neurons=tuple(neurons),
        finalized=True,
    )


def nonce_for(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def snapshot_deployment_from(
    deployment: ActiveDeploymentAssignment,
    *,
    route_activated_at_epoch: int = ROUTE_ACTIVATED_AT,
    reissued_ticket_at_epoch: int | None = None,
) -> SnapshotDeployment:
    """Lift a manifest deployment back into its snapshot form with activation timing.

    ``reissued_ticket_at_epoch`` models the scheduler re-assigning every replica
    under a fresh signed ticket stamped at that instant on the signer's clock.
    A ticket binds its own issuance, so a different issuance is a different
    ticket and a different assignment: the incarnation advances one generation
    with a fresh nonce, endpoint, ticket digest, and ready-receipt digest, all
    derived deterministically from the new facts. The golden incarnation's
    facts are never rewritten in place.
    """

    def reissued(replica: AssignedReplica) -> dict[str, object]:
        if reissued_ticket_at_epoch is None:
            return {
                "generation": replica.generation,
                "assignment_nonce": replica.assignment_nonce,
                "ticket_digest_sha256": replica.ticket_digest_sha256,
                "receipt_digest_sha256": replica.receipt_digest_sha256,
                "ticket_issued_at_epoch": replica.ticket_issued_at_epoch,
            }
        generation = replica.generation + 1
        stamp = f"{deployment.deployment_id}-{replica.miner_hotkey}-g{generation}"
        stamp = f"{stamp}-issued-{reissued_ticket_at_epoch}"
        return {
            "generation": generation,
            "assignment_nonce": label_digest(f"nonce-{stamp}")[:32],
            "ticket_digest_sha256": label_digest(f"ticket-{stamp}"),
            "receipt_digest_sha256": label_digest(f"receipt-{stamp}"),
            "ticket_issued_at_epoch": reissued_ticket_at_epoch,
        }

    replicas = [
        build_snapshot_replica(
            miner_uid=replica.miner_uid,
            miner_hotkey=replica.miner_hotkey,
            miner_service_public_key=replica.miner_service_public_key,
            deployment_id=deployment.deployment_id,
            chain_block=replica.chain_block,
            expires_at_block=replica.expires_at_block,
            ticket_expires_at_epoch=replica.ticket_expires_at_epoch,
            route_activated_at_epoch=route_activated_at_epoch,
            **reissued(replica),  # type: ignore[arg-type]
        )
        for replica in deployment.replicas
    ]
    return build_snapshot_deployment(
        deployment_id=deployment.deployment_id,
        campaign_sequence=deployment.campaign_sequence,
        route_host=deployment.route_host,
        build_id=deployment.build_id,
        challenge_sha256=deployment.challenge_sha256,
        image_digest=deployment.image_digest,
        workload_spec_digest_sha256=deployment.workload_spec_digest_sha256,
        attestation_requirement=deployment.attestation_requirement,
        replicas=replicas,
    )


def build_snapshot(
    deployments: Sequence[ActiveDeploymentAssignment] | None = None,
    *,
    snapshot_sequence: int = SNAPSHOT_SEQUENCE,
    state_revision: int = STATE_REVISION,
    captured_at_epoch: int = BASE_EPOCH,
    finalized_height: int = FINALIZED_HEIGHT,
    finalized_block_hash: str = FINALIZED_BLOCK_HASH,
    finalized_epoch: int = 42,
    central_authority: str | None = None,
    snapshot_deployments: Sequence[SnapshotDeployment] | None = None,
) -> ActiveAssignmentSnapshot:
    """Seal a capture; ``snapshot_deployments`` supplies pre-lifted deployments verbatim."""

    policy = build_policy(signer_keys())
    if snapshot_deployments is None:
        snapshot_deployments = [
            snapshot_deployment_from(item)
            for item in (fixture_deployments() if deployments is None else deployments)
        ]
    return build_active_assignment_snapshot(
        central_authority_fingerprint_sha256=(
            central_authority or policy.central_authority_fingerprint_sha256
        ),
        snapshot_sequence=snapshot_sequence,
        state_revision=state_revision,
        captured_at_epoch=captured_at_epoch,
        finalized_height=finalized_height,
        finalized_block_hash=finalized_block_hash,
        finalized_epoch=finalized_epoch,
        route_host_suffix=ROUTE_SUFFIX,
        probe_port=PROBE_PORT,
        deployments=list(snapshot_deployments),
    )


def build_signer_skew_snapshot() -> ActiveAssignmentSnapshot:
    """The golden capture's successor with the signer's clock leading the runtime's.

    Every replica has been re-assigned under a fresh signed ticket (generation
    2, fresh nonce, endpoint, ticket and receipt digests) and every route was
    activated exactly at the capture instant (the runtime clock), while the
    signer stamped alpha's tickets ``TICKET_MAX_FUTURE_SKEW_SECONDS`` after it
    and beta's one second after it: the full and the minimal cross-domain
    tolerance, at both bounds of the activation-ordering rule. It is the shared
    Go/Python parity fixture for the clock-domain rule and a valid successor of
    the golden capture because no golden incarnation is rewritten; one more
    second on alpha is ``replica_activation_order_invalid``.
    """

    alpha, beta = fixture_deployments()
    return build_snapshot(
        snapshot_sequence=SNAPSHOT_SEQUENCE + 1,
        state_revision=STATE_REVISION + 1,
        snapshot_deployments=[
            snapshot_deployment_from(
                alpha,
                route_activated_at_epoch=BASE_EPOCH,
                reissued_ticket_at_epoch=BASE_EPOCH + TICKET_MAX_FUTURE_SKEW_SECONDS,
            ),
            snapshot_deployment_from(
                beta, route_activated_at_epoch=BASE_EPOCH, reissued_ticket_at_epoch=BASE_EPOCH + 1
            ),
        ],
    )


def build_snapshot_lineage() -> SnapshotLineage:
    """The publisher's lineage after accepting the golden capture and its signer-skew successor."""

    golden = build_snapshot()
    lineage = build_initial_snapshot_lineage(
        central_authority_fingerprint_sha256=golden.central_authority_fingerprint_sha256
    )
    return advance_snapshot_lineage(
        advance_snapshot_lineage(lineage, golden), build_signer_skew_snapshot()
    )


def window_deployment(
    deployment_id: str,
    miners: Sequence[tuple[int, str]],
    *,
    campaign_sequence: int,
) -> ActiveDeploymentAssignment:
    """A deployment whose assignment authority outlives the golden window."""

    return build_deployment(
        deployment_id,
        miners,
        campaign_sequence=campaign_sequence,
        expires_at_block=WINDOW_LEASE_EXPIRES_AT_BLOCK,
        ticket_expires_at_epoch=WINDOW_TICKET_EXPIRES_AT,
    )


@dataclass(frozen=True)
class WindowContext:
    """A three-manifest scoring window that exercises every decision class."""

    keys: dict[str, Ed25519PrivateKey]
    policy: AssignmentManifestTrustPolicy
    manifests: list[ActiveAssignmentManifest]
    states: list[AssignmentManifestChainState]
    rounds: list[ProbeRound]
    registered: RegisteredMinerSet
    terminal: TerminalManifestObservation
    decision: ValidatorWeightDecision


def build_round(
    policy: AssignmentManifestTrustPolicy,
    manifest: ActiveAssignmentManifest,
    verification_state: AssignmentManifestChainState,
    keys: dict[str, Ed25519PrivateKey],
    *,
    responders: dict[str, str | None],
    label: str,
    evaluation_epoch: int,
    latency_millis: int = 42,
) -> ProbeRound:
    """Probe every deployment once; ``None`` models a route that did not answer."""

    verification = verify_active_assignment_manifest(
        manifest,
        sign_manifest(manifest, keys),
        policy,
        verification_state,
        evaluation_epoch=evaluation_epoch,
        current_finalized_height=FINALIZED_HEIGHT,
    )
    observations = []
    for deployment in manifest.deployments:
        probe_nonce = nonce_for(f"{label}-{deployment.deployment_id}")
        responder = responders.get(deployment.deployment_id)
        if responder is None:
            result: object = ProbeTransportFailure(code="timeout", latency_millis=latency_millis)
        else:
            replica = next(item for item in deployment.replicas if item.miner_hotkey == responder)
            attestation = sign_attestation(deployment, replica, probe_nonce=probe_nonce)
            result = serving_response(
                deployment, attestation=attestation, latency_millis=latency_millis
            )
        observations.append(
            evaluate_probe_response(deployment, policy, probe_nonce=probe_nonce, result=result)
        )
    report = build_validator_probe_report(
        verification,
        policy,
        verification_state,
        observations,
        validator_uid=VALIDATOR_UID,
        validator_hotkey=VALIDATOR_HOTKEY,
        evaluation_epoch=evaluation_epoch,
        edge_origin_override=False,
    )
    return ProbeRound(manifest=manifest, report=report)


def registered_set(
    *,
    miners: Sequence[tuple[int, str]] = REGISTERED_MINERS,
    finalized_height: int = REGISTERED_HEIGHT,
    finalized_block_hash: str = REGISTERED_BLOCK_HASH,
    finalized_epoch: int | None = None,
    tempo: int = REGISTERED_TEMPO,
) -> RegisteredMinerSet:
    """The registered view is a real fingerprint of :func:`metagraph_view`, never a label."""

    view = metagraph_view(
        miners=[item for item in miners if item[1] != VALIDATOR_HOTKEY],
        finalized_height=finalized_height,
        tempo=tempo,
    )
    return RegisteredMinerSet(
        network="finney",
        netuid=24,
        finalized=True,
        finalized_height=finalized_height,
        finalized_block_hash=finalized_block_hash,
        finalized_epoch=view.epoch if finalized_epoch is None else finalized_epoch,
        validator_uid=VALIDATOR_UID,
        validator_hotkey=VALIDATOR_HOTKEY,
        miners=[RegisteredMiner(uid=uid, hotkey=hotkey) for uid, hotkey in miners],
        metagraph_identity_fingerprint_sha256=snapshot_identity_fingerprint(view),
    )


def assigned_baseline(
    manifest: ActiveAssignmentManifest,
    *,
    established_at_epoch: int,
) -> AssignedBaseline:
    """The baseline a previous decision would have sealed for ``manifest`` at its close."""

    identities = sorted(
        {
            (replica.miner_uid, replica.miner_hotkey)
            for item in manifest.deployments
            for replica in item.replicas
        }
    )
    return AssignedBaseline(
        established_at_epoch=established_at_epoch,
        manifest_sequence=manifest.sequence,
        manifest_digest_sha256=manifest.manifest_digest_sha256,
        assigned_miner_count=len(identities),
        assigned_identity_digest_sha256=canonical_digest(
            [[uid, hotkey] for uid, hotkey in identities]
        ),
        assigned_identities=[RegisteredMiner(uid=uid, hotkey=hotkey) for uid, hotkey in identities],
    )


def make_window_context(
    *,
    decision_policy: WeightDecisionPolicy | None = None,
    prior_assigned_baseline: AssignedBaseline | None = None,
) -> WindowContext:
    """Build the golden window.

    - manifest 1 (sequence 1, issued at window start): alpha(A,B,C), beta(B,C,D);
      probed 24 times, every replica answers in turn;
    - manifest 2 (sequence 2, issued +1500s): adds gamma(E); probed 12 times,
      E answers, so E is a newly activated miner that earned weight; its first
      probe is evaluated ``max_future_skew_seconds`` *before* the manifest's
      issuance, exactly as a validator whose clock trails the publisher's by
      the trust policy's tolerance would record it;
    - manifest 3 (sequence 3, issued +3000s): adds delta(F); probed 9 times,
      delta never answers, so F is unverified but inside activation grace;
    - G is registered and never assigned; the terminal fetch at window close
      re-verifies manifest 3.

    The golden record is a first window: it carries no prior baseline and
    seals manifest 3's assigned set as the baseline for its successor. It
    seals the one trust policy every manifest and report of the window was
    verified under, which bounds the skewed round.
    """

    keys = signer_keys()
    policy = build_policy(keys, max_age=3_600)
    alpha = window_deployment("fixture-alpha", MINERS[:3], campaign_sequence=1)
    beta = window_deployment("fixture-beta", MINERS[1:], campaign_sequence=2)
    gamma = window_deployment("fixture-gamma", EXTRA_MINERS[:1], campaign_sequence=3)
    delta = window_deployment("fixture-delta", EXTRA_MINERS[1:2], campaign_sequence=4)
    manifest_one = build_manifest(policy, [alpha, beta])
    manifest_two = build_manifest(
        policy,
        [alpha, beta, gamma],
        sequence=2,
        previous=manifest_one.manifest_digest_sha256,
        issued_at=BASE_EPOCH + 1_500,
        expires_at=BASE_EPOCH + 1_500 + 3_600,
        finalized_height=FINALIZED_HEIGHT + 20,
        finalized_block_hash=label_digest("contract-checkpoint-block-two"),
    )
    manifest_three = build_manifest(
        policy,
        [alpha, beta, gamma, delta],
        sequence=3,
        previous=manifest_two.manifest_digest_sha256,
        issued_at=BASE_EPOCH + 3_000,
        expires_at=BASE_EPOCH + 3_000 + 3_600,
        finalized_height=FINALIZED_HEIGHT + 40,
        finalized_block_hash=label_digest("contract-checkpoint-block-three"),
    )
    genesis = build_initial_manifest_chain_state(policy)
    state_one = verify_active_assignment_manifest(
        manifest_one,
        sign_manifest(manifest_one, keys),
        policy,
        genesis,
        evaluation_epoch=BASE_EPOCH,
        current_finalized_height=FINALIZED_HEIGHT,
    ).next_chain_state
    state_two = verify_active_assignment_manifest(
        manifest_two,
        sign_manifest(manifest_two, keys),
        policy,
        state_one,
        evaluation_epoch=BASE_EPOCH + 1_500,
        current_finalized_height=FINALIZED_HEIGHT,
    ).next_chain_state
    rounds: list[ProbeRound] = []
    alpha_hotkeys = [hotkey for _, hotkey in MINERS[:3]]
    beta_hotkeys = [hotkey for _, hotkey in MINERS[1:]]
    for index in range(24):
        rounds.append(
            build_round(
                policy,
                manifest_one,
                genesis,
                keys,
                responders={
                    "fixture-alpha": alpha_hotkeys[index % 3],
                    "fixture-beta": beta_hotkeys[index % 3],
                },
                label=f"window-one-{index}",
                evaluation_epoch=BASE_EPOCH + 60 + 60 * index,
            )
        )
    for index in range(12):
        rounds.append(
            build_round(
                policy,
                manifest_two,
                state_one,
                keys,
                responders={
                    "fixture-alpha": alpha_hotkeys[index % 3],
                    "fixture-beta": beta_hotkeys[index % 3],
                    "fixture-gamma": "MinerE",
                },
                label=f"window-two-{index}",
                evaluation_epoch=(
                    BASE_EPOCH + 1_500 - policy.max_future_skew_seconds
                    if index == 0
                    else BASE_EPOCH + 1_560 + 60 * index
                ),
                latency_millis=57,
            )
        )
    for index in range(9):
        rounds.append(
            build_round(
                policy,
                manifest_three,
                state_two,
                keys,
                responders={
                    "fixture-alpha": alpha_hotkeys[index % 3],
                    "fixture-beta": beta_hotkeys[index % 3],
                    "fixture-gamma": "MinerE",
                    "fixture-delta": None,
                },
                label=f"window-three-{index}",
                evaluation_epoch=BASE_EPOCH + 3_060 + 60 * index,
            )
        )
    registered = registered_set()
    terminal = TerminalManifestObservation(
        status="verified", evaluated_at_epoch=WINDOW_END, manifest=manifest_three
    )
    decision = decide_weight_submission(
        rounds,
        terminal=terminal,
        registered=registered,
        trust_policies=[policy],
        window_start_epoch=WINDOW_START,
        window_end_epoch=WINDOW_END,
        decision_policy=decision_policy,
        prior_assigned_baseline=prior_assigned_baseline,
    )
    return WindowContext(
        keys=keys,
        policy=policy,
        manifests=[manifest_one, manifest_two, manifest_three],
        states=[genesis, state_one, state_two],
        rounds=rounds,
        registered=registered,
        terminal=terminal,
        decision=decision,
    )


def build_future_terminal(
    context: WindowContext,
    *,
    lead_seconds: int,
    policy: AssignmentManifestTrustPolicy | None = None,
) -> tuple[ActiveAssignmentManifest, AssignmentManifestChainState]:
    """Manifest 4: manifest 3's assignments republished ``lead_seconds`` after window close.

    It keeps manifest 3's finalized chain view, so the golden registered set
    stays bound to it and the only thing that changes is the issue instant.
    Returned with the chain state a validator holds after accepting manifest 3,
    so a test can verify manifest 4 live at any evaluation epoch.
    """

    manifest_three = context.manifests[2]
    state_three = verify_active_assignment_manifest(
        manifest_three,
        sign_manifest(manifest_three, context.keys),
        context.policy,
        context.states[2],
        evaluation_epoch=manifest_three.issued_at_epoch,
        current_finalized_height=FINALIZED_HEIGHT,
    ).next_chain_state
    manifest_four = build_manifest(
        context.policy if policy is None else policy,
        [
            ActiveDeploymentAssignment.model_validate(item.model_dump(mode="json", by_alias=True))
            for item in manifest_three.deployments
        ],
        sequence=4,
        previous=manifest_three.manifest_digest_sha256,
        issued_at=WINDOW_END + lead_seconds,
        expires_at=WINDOW_END + lead_seconds + 3_600,
        finalized_height=manifest_three.finalized_height,
        finalized_block_hash=manifest_three.finalized_block_hash,
    )
    return manifest_four, state_three


def future_terminal_decision(
    lead_seconds: int,
    *,
    evaluated_at_epoch: int,
    successor_policy: AssignmentManifestTrustPolicy | None = None,
) -> ValidatorWeightDecision:
    """The golden window closed by a terminal manifest issued after the close instant.

    With ``successor_policy`` the terminal is published under that policy (a
    rotation at the close) and both policies are supplied to the decision.
    """

    context = make_window_context()
    manifest_four, _ = build_future_terminal(
        context, lead_seconds=lead_seconds, policy=successor_policy
    )
    return decide_weight_submission(
        context.rounds,
        terminal=TerminalManifestObservation(
            status="verified", evaluated_at_epoch=evaluated_at_epoch, manifest=manifest_four
        ),
        registered=context.registered,
        trust_policies=[context.policy] + ([] if successor_policy is None else [successor_policy]),
        window_start_epoch=WINDOW_START,
        window_end_epoch=WINDOW_END,
    )


def successor_policy_valid_from(valid_from_epoch: int) -> AssignmentManifestTrustPolicy:
    """The golden trust policy re-issued with a later validity start (a rotation)."""

    return build_policy(signer_keys(), max_age=3_600, valid_from=valid_from_epoch)


def build_pointer() -> AssignmentManifestLatestPointer:
    context = make_context()
    return build_manifest_latest_pointer(context.manifest, context.signatures)


SCHEMA_MODELS: dict[str, type[BaseModel]] = {
    "active-assignment-snapshot": ActiveAssignmentSnapshot,
    "active-assignment-snapshot-lineage": SnapshotLineage,
    "assignment-manifest-latest-pointer": AssignmentManifestLatestPointer,
    "validator-weight-decision": ValidatorWeightDecision,
}


def fixture_documents() -> dict[str, bytes]:
    return {
        "active-assignment-snapshot": active_assignment_snapshot_bytes(build_snapshot()),
        "active-assignment-snapshot-signer-skew": active_assignment_snapshot_bytes(
            build_signer_skew_snapshot()
        ),
        "active-assignment-snapshot-lineage": snapshot_lineage_bytes(build_snapshot_lineage()),
        "assignment-manifest-latest-pointer": assignment_manifest_latest_pointer_bytes(
            build_pointer()
        ),
        "validator-weight-decision": validator_weight_decision_bytes(
            make_window_context().decision
        ),
    }


def schema_bytes(model: type[BaseModel]) -> bytes:
    rendered = json.dumps(model.model_json_schema(), indent=2, sort_keys=True, ensure_ascii=True)
    return (rendered + "\n").encode("ascii")


def negative_document(
    contract: str,
    case: str,
    expect: str,
    code: str,
    document: dict[str, Any],
) -> bytes:
    """Seal one golden invalid fixture; ``expect`` is ``schema`` or ``model``."""

    return (
        canonical_json(
            {
                "case": case,
                "code": code,
                "contract": contract,
                "document": document,
                "expect": expect,
                "schema_version": 1,
            }
        )
        + b"\n"
    )


def _mutate(rendered: bytes, **changes: Any) -> dict[str, Any]:
    document: dict[str, Any] = json.loads(rendered)
    for key, value in changes.items():
        if value is _DELETE:
            del document[key]
        else:
            document[key] = value
    return document


_DELETE = object()


def reseal_decision(document: dict[str, Any]) -> dict[str, Any]:
    """Recompute a mutated decision's row and self digests so only semantics can reject it."""

    resealed = dict(document)
    if resealed["decision"] == "submit":
        resealed["weight_plan_rows_digest_sha256"] = canonical_digest(
            [{"miner_hotkey": row["hotkey"], "weight": row["weight"]} for row in resealed["rows"]]
        )
    else:
        resealed["weight_plan_rows_digest_sha256"] = None
    unsigned = {key: value for key, value in resealed.items() if key != "decision_digest_sha256"}
    resealed["decision_digest_sha256"] = canonical_digest(unsigned)
    return resealed


def forged_decision(rendered: bytes, **changes: Any) -> dict[str, Any]:
    """A self-consistent (digest-valid) record that claims something its fields do not support."""

    return reseal_decision(_mutate(rendered, **changes))


def reseal_report(document: dict[str, Any]) -> dict[str, Any]:
    """Recompute a mutated report's self digest; reports are unsigned, so this is cheap."""

    resealed = dict(document)
    unsigned = {key: value for key, value in resealed.items() if key != "report_digest_sha256"}
    resealed["report_digest_sha256"] = canonical_digest(unsigned)
    return resealed


def reseal_observation(document: dict[str, Any]) -> dict[str, Any]:
    """Recompute a mutated observation's self digest."""

    resealed = dict(document)
    unsigned = {k: v for k, v in resealed.items() if k != "observation_digest_sha256"}
    resealed["observation_digest_sha256"] = canonical_digest(unsigned)
    return resealed


def reseal_report_observations(
    report: dict[str, Any], observations: list[dict[str, Any]]
) -> dict[str, Any]:
    """Replace a report's observations (resealing each) and re-derive its digests."""

    resealed = [reseal_observation(item) for item in observations]
    return reseal_report(
        {
            **report,
            "observations": resealed,
            "observation_vector_digest_sha256": canonical_digest(resealed),
        }
    )


def forged_decision_with_report(
    rendered: bytes,
    *,
    report_digest_sha256: str,
    observation_changes: dict[str, Any] | None = None,
    **report_changes: Any,
) -> dict[str, Any]:
    """Rewrite one sealed report in place and re-derive every digest that depends on it.

    The report is resealed, its manifest's evidence list is re-sorted, the
    scoring window's sorted report digests and digest are recomputed, and the
    record is resealed, so only the derived semantics can reject the result.
    """

    document: dict[str, Any] = json.loads(rendered)
    replaced = False
    for evidence in document["assignment_manifest_evidence"]:
        reports = evidence["scoring_reports"]
        for index, report in enumerate(reports):
            if report["report_digest_sha256"] == report_digest_sha256:
                rewritten = {**report, **report_changes}
                if observation_changes:
                    rewritten = reseal_report_observations(
                        rewritten,
                        [{**item, **observation_changes} for item in report["observations"]],
                    )
                reports[index] = reseal_report(rewritten)
                replaced = True
        reports.sort(key=lambda item: item["report_digest_sha256"])
    if not replaced:
        raise AssertionError("report not sealed in the record")
    window = document["scoring_window"]
    window["report_digests"] = sorted(
        report["report_digest_sha256"]
        for evidence in document["assignment_manifest_evidence"]
        for report in evidence["scoring_reports"]
    )
    document["scoring_window_digest_sha256"] = canonical_digest(window)
    return reseal_decision(document)


def negative_documents() -> dict[str, bytes]:
    documents = fixture_documents()
    snapshot = documents["active-assignment-snapshot"]
    pointer = documents["assignment-manifest-latest-pointer"]
    decision = documents["validator-weight-decision"]
    cases: dict[str, bytes] = {}

    def add(contract: str, case: str, expect: str, code: str, document: dict[str, Any]) -> None:
        cases[f"{contract}.v1/{case}"] = negative_document(contract, case, expect, code, document)

    snapshot_doc = json.loads(snapshot)
    add(
        "active-assignment-snapshot",
        "unknown-field",
        "schema",
        "extra_forbidden",
        _mutate(snapshot, challenge_value="not-allowed"),
    )
    add(
        "active-assignment-snapshot",
        "wrong-network",
        "schema",
        "literal_error",
        _mutate(snapshot, network="test"),
    )
    add(
        "active-assignment-snapshot",
        "self-digest-mismatch",
        "model",
        "snapshot_digest_sha256_mismatch",
        _mutate(snapshot, snapshot_digest_sha256="0" * 64),
    )
    add(
        "active-assignment-snapshot",
        "projected-vector-digest-mismatch",
        "model",
        "projected_assignment_vector_digest_sha256_mismatch",
        _mutate(snapshot, projected_assignment_vector_digest_sha256="0" * 64),
    )
    mutated = json.loads(snapshot)
    mutated["deployments"][0]["replicas"][0]["route_activated_at_epoch"] = BASE_EPOCH + 1
    add(
        "active-assignment-snapshot",
        "replica-activated-after-capture",
        "model",
        "snapshot_replica_activated_after_capture",
        mutated,
    )
    mutated = json.loads(snapshot)
    mutated["deployments"][0]["replicas"][0]["ticket_issued_at_epoch"] = (
        BASE_EPOCH + TICKET_MAX_FUTURE_SKEW_SECONDS + 1
    )
    mutated["deployments"][0]["replicas"][0]["route_activated_at_epoch"] = (
        BASE_EPOCH + TICKET_MAX_FUTURE_SKEW_SECONDS + 1
    )
    add(
        "active-assignment-snapshot",
        "replica-ticket-issued-beyond-capture-skew",
        "model",
        "snapshot_replica_ticket_issued_after_capture",
        mutated,
    )
    mutated = json.loads(snapshot)
    mutated["deployments"][0]["replicas"][0]["route_activated_at_epoch"] = (
        mutated["deployments"][0]["replicas"][0]["ticket_issued_at_epoch"]
        - TICKET_MAX_FUTURE_SKEW_SECONDS
        - 1
    )
    add(
        "active-assignment-snapshot",
        "replica-activated-before-ticket-skew",
        "model",
        "replica_activation_order_invalid",
        mutated,
    )
    mutated = json.loads(snapshot)
    mutated["deployments"][0]["replicas"][0]["endpoint_id"] = (
        "fixture-alpha-MinerA-g2-" + (mutated["deployments"][0]["replicas"][0]["assignment_nonce"])
    )
    add(
        "active-assignment-snapshot",
        "endpoint-incarnation-mismatch",
        "model",
        "deployment_replica_identity_invalid",
        mutated,
    )
    mutated = json.loads(snapshot)
    mutated["deployments"][0]["replicas"][0]["expires_at_block"] = snapshot_doc["finalized_height"]
    add(
        "active-assignment-snapshot",
        "replica-block-window-excludes-finalized-height",
        "model",
        "snapshot_replica_block_window_invalid",
        mutated,
    )
    mutated = json.loads(snapshot)
    mutated["deployments"][0]["route_host"] = "fixture-alpha.other.local"
    add(
        "active-assignment-snapshot",
        "route-host-not-derived-from-suffix",
        "model",
        "snapshot_route_host_invalid",
        mutated,
    )
    add(
        "assignment-manifest-latest-pointer",
        "object-key-not-content-addressed",
        "model",
        "pointer_object_key_invalid",
        _mutate(pointer, manifest_object_key="v1/manifests/" + "0" * 64 + ".json"),
    )
    add(
        "assignment-manifest-latest-pointer",
        "self-digest-mismatch",
        "model",
        "pointer_digest_sha256_mismatch",
        _mutate(pointer, pointer_digest_sha256="0" * 64),
    )
    add(
        "assignment-manifest-latest-pointer",
        "genesis-with-previous-link",
        "model",
        "pointer_previous_link_invalid",
        _mutate(pointer, previous_manifest_digest_sha256="1" * 64),
    )
    add(
        "assignment-manifest-latest-pointer",
        "unsorted-signers",
        "model",
        "pointer_signers_not_canonical",
        _mutate(pointer, signer_key_ids=["issuer", "auditor"]),
    )
    add(
        "assignment-manifest-latest-pointer",
        "unknown-field",
        "schema",
        "extra_forbidden",
        _mutate(pointer, signature_base64="AAAA"),
    )
    add(
        "assignment-manifest-latest-pointer",
        "missing-signers",
        "schema",
        "too_short",
        _mutate(pointer, signer_key_ids=[]),
    )
    add(
        "validator-weight-decision",
        "submit-without-positive-evidence",
        "model",
        "abstain_reasons_not_derived",
        forged_decision(
            decision,
            rows=[
                {**row, "weight": 0.0, "classification": "assigned_unverified"}
                if row["classification"] == "verified_serving"
                else row
                for row in json.loads(decision)["rows"]
            ],
        ),
    )
    decision_doc = json.loads(decision)
    outage_fields: dict[str, Any] = {
        "terminal_manifest_digest_sha256": None,
        "terminal_manifest_sequence": None,
        "terminal_manifest_expires_at_epoch": None,
        "terminal_manifest_effective_expires_at_epoch": None,
        "terminal_earliest_lease_expires_at_block": None,
        "terminal_finalized_height": None,
        "terminal_finalized_block_hash": None,
        "terminal_finalized_epoch": None,
        "assigned_baseline": None,
    }
    add(
        "validator-weight-decision",
        "submit-with-unavailable-terminal",
        "model",
        "abstain_reasons_not_derived",
        forged_decision(
            decision,
            terminal_manifest_status="unavailable",
            terminal_manifest_rejection_code="timeout",
            **outage_fields,
        ),
    )
    add(
        "validator-weight-decision",
        "submit-with-rejected-terminal",
        "model",
        "abstain_reasons_not_derived",
        forged_decision(
            decision,
            terminal_manifest_status="rejected",
            terminal_manifest_rejection_code="manifest_stale",
            **outage_fields,
        ),
    )
    add(
        "validator-weight-decision",
        "submit-with-expired-terminal",
        "model",
        "abstain_reasons_not_derived",
        forged_decision(
            decision,
            terminal_manifest_effective_expires_at_epoch=decision_doc[
                "terminal_evaluated_at_epoch"
            ],
        ),
    )
    add(
        "validator-weight-decision",
        "submit-with-expired-block-lease",
        "model",
        "abstain_reasons_not_derived",
        forged_decision(
            decision,
            terminal_earliest_lease_expires_at_block=decision_doc["registered_finalized_height"],
        ),
    )
    add(
        "validator-weight-decision",
        "submit-with-insufficient-rounds",
        "model",
        "abstain_reasons_not_derived",
        forged_decision(
            decision, round_count=decision_doc["decision_policy"]["min_verified_rounds"] - 1
        ),
    )
    add(
        "validator-weight-decision",
        "submit-with-undersampled-silent-row",
        "model",
        "abstain_reasons_not_derived",
        forged_decision(
            decision,
            rows=[
                {
                    **row,
                    "classification": "assigned_undersampled",
                    "first_seen_epoch": WINDOW_START,
                    "opportunities": 2,
                    "expected_attributions_numerator": 2,
                    "expected_attributions_denominator": 1,
                    "replica_share_counts": [{"opportunity_count": 2, "replica_count": 1}],
                }
                if row["hotkey"] == "MinerF"
                else row
                for row in decision_doc["rows"]
            ],
        ),
    )
    # The sealed record admits its skewed round only within the bound of the
    # sealed trust policy that verified it; a digest-valid rewrite that pushes
    # that report one more second before its manifest's issuance is refused.
    skewed_report = next(
        report
        for evidence in decision_doc["assignment_manifest_evidence"]
        for report in evidence["scoring_reports"]
        if report["evaluation_epoch"] < report["manifest_issued_at_epoch"]
    )
    add(
        "validator-weight-decision",
        "submit-with-report-preceding-manifest-beyond-skew",
        "model",
        "scoring_window_evidence_inconsistent",
        forged_decision_with_report(
            decision,
            report_digest_sha256=skewed_report["report_digest_sha256"],
            evaluation_epoch=skewed_report["evaluation_epoch"] - 1,
        ),
    )
    # A terminal manifest issued further ahead of the close evaluation instant
    # than its own trust policy's skew could never have verified live; the
    # record was legitimately produced at close+1 and its evaluation instant
    # rewritten back to the close.
    future_terminal = validator_weight_decision_bytes(
        future_terminal_decision(6, evaluated_at_epoch=WINDOW_END + 1)
    )
    add(
        "validator-weight-decision",
        "submit-with-terminal-issued-beyond-skew",
        "model",
        "terminal_manifest_future",
        forged_decision(future_terminal, terminal_evaluated_at_epoch=WINDOW_END),
    )
    # Every sealed report and manifest must be bound by a sealed trust policy.
    add(
        "validator-weight-decision",
        "submit-without-verifying-trust-policy",
        "model",
        "trust_policies_not_derived",
        forged_decision(decision, trust_policies=[]),
    )
    # A terminal published under a successor policy that only becomes valid at
    # the close+5 instant it was issued: legitimately produced at close+5, its
    # evaluation instant rewritten to the close, where that policy could not
    # yet have admitted anything.
    successor = successor_policy_valid_from(WINDOW_END + 5)
    rotated_terminal = validator_weight_decision_bytes(
        future_terminal_decision(5, evaluated_at_epoch=WINDOW_END + 5, successor_policy=successor)
    )
    add(
        "validator-weight-decision",
        "submit-with-terminal-before-policy-validity",
        "model",
        "terminal_policy_rejected",
        forged_decision(rotated_terminal, terminal_evaluated_at_epoch=WINDOW_END),
    )
    # A report's probe bounds are its policy's own scalars.
    first_report = decision_doc["assignment_manifest_evidence"][0]["scoring_reports"][0]
    add(
        "validator-weight-decision",
        "submit-with-report-probe-bounds-not-policy",
        "model",
        "scoring_window_evidence_inconsistent",
        forged_decision_with_report(
            decision,
            report_digest_sha256=first_report["report_digest_sha256"],
            max_response_bytes=first_report["max_response_bytes"] + 1,
        ),
    )
    # A serving observation larger than the policy's response ceiling could
    # only have been judged under a looser policy.
    add(
        "validator-weight-decision",
        "submit-with-observation-oversized-for-policy",
        "model",
        "report_policy_rejected",
        forged_decision_with_report(
            decision,
            report_digest_sha256=first_report["report_digest_sha256"],
            observation_changes={"response_bytes": first_report["max_response_bytes"] + 1},
        ),
    )
    lineage = documents["active-assignment-snapshot-lineage"]
    lineage_doc = json.loads(lineage)
    add(
        "active-assignment-snapshot-lineage",
        "unknown-field",
        "schema",
        "extra_forbidden",
        _mutate(lineage, ticket_json="not-allowed"),
    )
    add(
        "active-assignment-snapshot-lineage",
        "self-digest-mismatch",
        "model",
        "lineage_digest_sha256_mismatch",
        _mutate(lineage, lineage_digest_sha256="0" * 64),
    )
    add(
        "active-assignment-snapshot-lineage",
        "replicas-not-canonical",
        "model",
        "lineage_replicas_not_canonical",
        _mutate(lineage, replicas=list(reversed(lineage_doc["replicas"]))),
    )
    add(
        "active-assignment-snapshot-lineage",
        "genesis-with-history",
        "model",
        "lineage_genesis_invalid",
        _mutate(lineage, accepted_snapshot_count=0),
    )
    add(
        "validator-weight-decision",
        "submit-with-undersampled-positive-row",
        "model",
        "abstain_reasons_not_derived",
        forged_decision(
            decision,
            decision_policy={
                **decision_doc["decision_policy"],
                "min_expected_attributions": 16,
            },
        ),
    )
    add(
        "validator-weight-decision",
        "submit-with-late-first-seen",
        "model",
        "row_first_seen_not_derived",
        forged_decision(
            decision,
            decision_policy={
                **decision_doc["decision_policy"],
                "min_expected_attributions": 16,
            },
            rows=[
                {
                    **row,
                    "first_seen_epoch": WINDOW_END
                    - decision_doc["decision_policy"]["activation_grace_seconds"]
                    + 1,
                }
                if row["hotkey"] in {"MinerA", "MinerD"}
                else row
                for row in decision_doc["rows"]
            ],
        ),
    )
    # An earning identity whose first sighting was erased, as a producer that
    # tracked sightings per endpoint rather than per identity once could.
    add(
        "validator-weight-decision",
        "submit-with-erased-first-seen",
        "model",
        "row_assigned_first_seen_missing",
        forged_decision(
            decision,
            rows=[
                {**row, "first_seen_epoch": None} if row["hotkey"] == "MinerA" else row
                for row in decision_doc["rows"]
            ],
        ),
    )
    add(
        "validator-weight-decision",
        "submit-with-mass-drop",
        "model",
        "assigned_counts_invalid",
        forged_decision(
            decision,
            max_assigned_miner_count=decision_doc["terminal_assigned_miner_count"] * 3,
        ),
    )
    add(
        "validator-weight-decision",
        "submit-with-registered-view-behind-terminal",
        "model",
        "abstain_reasons_not_derived",
        forged_decision(
            decision,
            registered_finalized_height=decision_doc["terminal_finalized_height"] - 1,
        ),
    )
    add(
        "validator-weight-decision",
        "submit-with-same-height-fork",
        "model",
        "abstain_reasons_not_derived",
        forged_decision(
            decision,
            registered_finalized_height=decision_doc["terminal_finalized_height"],
            registered_finalized_epoch=decision_doc["terminal_finalized_epoch"],
        ),
    )
    add(
        "validator-weight-decision",
        "submit-with-epoch-behind-terminal",
        "model",
        "abstain_reasons_not_derived",
        forged_decision(
            decision,
            registered_finalized_epoch=decision_doc["terminal_finalized_epoch"] - 1,
        ),
    )
    add(
        "validator-weight-decision",
        "row-classification-not-derived",
        "model",
        "row_classification_not_derived",
        forged_decision(
            decision,
            rows=[
                {**row, "classification": "assigned_unverified"}
                if row["hotkey"] == "MinerF"
                else row
                for row in decision_doc["rows"]
            ],
        ),
    )
    add(
        "validator-weight-decision",
        "successor-baseline-not-derived",
        "model",
        "assigned_baseline_not_derived",
        forged_decision(
            decision,
            assigned_baseline={
                **decision_doc["assigned_baseline"],
                "manifest_sequence": 2,
                "manifest_digest_sha256": decision_doc["assignment_manifest_evidence"][1][
                    "manifest"
                ]["manifest_digest_sha256"],
            },
        ),
    )
    add(
        "validator-weight-decision",
        "prior-baseline-status-not-derived",
        "model",
        "baseline_status_not_derived",
        forged_decision(
            decision,
            prior_assigned_baseline={
                **decision_doc["assigned_baseline"],
                "established_at_epoch": WINDOW_START
                - decision_doc["decision_policy"]["assigned_baseline_max_age_seconds"]
                - 1,
                "manifest_sequence": 1,
            },
            prior_assigned_baseline_status="applied",
        ),
    )
    # Positive weight without sealed serving evidence, in every forgeable form.
    add(
        "validator-weight-decision",
        "submit-with-positive-weight-without-attributions",
        "model",
        "row_positive_weight_without_evidence",
        forged_decision(
            decision, rows=[{**row, "attributions": 0} for row in decision_doc["rows"]]
        ),
    )
    add(
        "validator-weight-decision",
        "submit-with-positive-weight-without-serving-observations",
        "model",
        "observation_counts_invalid",
        forged_decision(decision, serving_observation_count=0),
    )
    add(
        "validator-weight-decision",
        "submit-with-rounds-exceeding-observations",
        "model",
        "observation_counts_invalid",
        forged_decision(decision, round_count=decision_doc["observation_count"] + 1),
    )
    add(
        "validator-weight-decision",
        "submit-with-expected-attributions-exceeding-opportunities",
        "model",
        "row_expected_attributions_inconsistent",
        forged_decision(
            decision,
            rows=[
                {
                    **row,
                    "expected_attributions_numerator": row["opportunities"] + 1,
                    "expected_attributions_denominator": 1,
                }
                if row["hotkey"] == "MinerA"
                else row
                for row in decision_doc["rows"]
            ],
        ),
    )
    add(
        "validator-weight-decision",
        "submit-with-replica-share-aggregation-mismatch",
        "model",
        "row_expected_attributions_inconsistent",
        forged_decision(
            decision,
            rows=[
                {
                    **row,
                    "replica_share_counts": [
                        {"opportunity_count": row["opportunities"], "replica_count": 2}
                    ],
                }
                if row["hotkey"] == "MinerA"
                else row
                for row in decision_doc["rows"]
            ],
        ),
    )
    add(
        "validator-weight-decision",
        "submit-with-noncanonical-expected-attribution",
        "model",
        "row_expected_attributions_inconsistent",
        forged_decision(
            decision,
            rows=[
                {
                    **row,
                    "expected_attributions_numerator": row["expected_attributions_numerator"] * 2,
                    "expected_attributions_denominator": row["expected_attributions_denominator"]
                    * 2,
                }
                if row["hotkey"] == "MinerA"
                else row
                for row in decision_doc["rows"]
            ],
        ),
    )
    add(
        "validator-weight-decision",
        "submit-with-positive-weight-below-min-attributions",
        "model",
        "row_weight_below_min_attributions",
        forged_decision(
            decision,
            scoring_policy={**decision_doc["scoring_policy"], "min_attributions": 22},
        ),
    )
    add(
        "validator-weight-decision",
        "submit-with-unnormalized-weights",
        "model",
        "weights_not_normalized",
        forged_decision(
            decision,
            rows=[
                {**row, "weight": row["weight"] / 2} if row["hotkey"] == "MinerA" else row
                for row in decision_doc["rows"]
            ],
        ),
    )
    # A terminal set padded beyond the rows assigned at close.
    add(
        "validator-weight-decision",
        "submit-with-padded-terminal-count",
        "model",
        "assigned_counts_invalid",
        forged_decision(
            decision,
            terminal_assigned_miner_count=decision_doc["terminal_assigned_miner_count"] + 1,
            max_assigned_miner_count=decision_doc["max_assigned_miner_count"] + 1,
        ),
    )
    # A guarded drop whose successor baseline is the reduced terminal set.
    dropped_rows = [
        {
            **row,
            "assigned_at_close": row["hotkey"] == "MinerA",
            "first_seen_epoch": row["first_seen_epoch"] if row["hotkey"] == "MinerA" else None,
            "classification": ("verified_serving" if row["weight"] > 0.0 else "unassigned"),
        }
        for row in decision_doc["rows"]
    ]
    add(
        "validator-weight-decision",
        "guarded-drop-refreshes-baseline",
        "model",
        "abstain_reasons_not_derived",
        forged_decision(
            decision,
            decision="abstain",
            abstain_reasons=["mass_unassignment_guard"],
            rows=dropped_rows,
            terminal_assigned_miner_count=1,
            assigned_baseline={
                **decision_doc["assigned_baseline"],
                "assigned_miner_count": 1,
                "assigned_identity_digest_sha256": canonical_digest([[10, "MinerA"]]),
                "assigned_identities": [{"uid": 10, "hotkey": "MinerA"}],
            },
        ),
    )
    add(
        "validator-weight-decision",
        "abstain-with-plan-rows-digest",
        "model",
        "decision_reasons_inconsistent",
        _mutate(decision, decision="abstain"),
    )
    add(
        "validator-weight-decision",
        "self-digest-mismatch",
        "model",
        "decision_digest_sha256_mismatch",
        _mutate(decision, decision_digest_sha256="0" * 64),
    )
    add(
        "validator-weight-decision",
        "terminal-before-close",
        "model",
        "decision_terminal_before_close",
        _mutate(decision, terminal_evaluated_at_epoch=WINDOW_END - 1),
    )
    add(
        "validator-weight-decision",
        "unknown-abstain-reason",
        "schema",
        "literal_error",
        _mutate(decision, abstain_reasons=["validator_tired"], decision="abstain"),
    )
    add(
        "validator-weight-decision",
        "plan-rows-digest-mismatch",
        "model",
        "weight_plan_rows_digest_mismatch",
        _mutate(decision, weight_plan_rows_digest_sha256="0" * 64),
    )
    return cases


def write_fixtures(root: Path) -> None:
    for stem, rendered in fixture_documents().items():
        (root / "contracts" / "fixtures" / f"{stem}.v1.json").write_bytes(rendered)
    for stem, model in SCHEMA_MODELS.items():
        (root / "contracts" / "schemas" / f"{stem}.v1.schema.json").write_bytes(schema_bytes(model))
    negative_root = root / "contracts" / "negative"
    for name, rendered in negative_documents().items():
        target = negative_root / f"{name}.json"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(rendered)


if __name__ == "__main__":
    write_fixtures(ROOT)
