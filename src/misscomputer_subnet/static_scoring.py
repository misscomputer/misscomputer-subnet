# SPDX-License-Identifier: AGPL-3.0-only
"""Static-site availability scoring (separate, versioned path; organic v1 unchanged).

``static-epoch-score`` v1 and ``static-availability-score`` v1 score only
``static-site-v1`` endpoint incarnations, from the validator's sealed hidden
``static-probe-observation`` v1 records
(:mod:`misscomputer_subnet.static_probe`). Dynamic (``oci-image-v1``)
endpoints stay on ``organic-epoch-score`` v1, whose bytes and rules this
module neither reads nor changes.

Inputs
------
``targets``
    Every static deployment of the validator's verified manifest v3
    (:class:`~misscomputer_subnet.static_index.StaticDeploymentTarget`).
``indexes`` / ``abstentions``
    For every target exactly one of: a
    :class:`~misscomputer_subnet.static_index.VerifiedStaticIndex` (the
    release-authority-signed site the validator authenticated) or a
    :class:`~misscomputer_subnet.static_index.StaticIndexAbstention`. A target
    with neither refuses the epoch: an unknown index state is never scored.

Epoch rules
-----------
1. Endpoints of an abstained deployment **abstain** (``abstain_index``, alert
   ``static_index_unavailable`` / ``static_index_invalid``): never zero, never
   judged by a dynamic predicate; observations of them refuse the epoch.
2. Every observation must be a hidden probe by this validator of a published
   incarnation, carry exactly the target's release digest and the index's
   release trust-policy digest, the ``expected_static_response`` (status,
   length, body and normative header digests) of its method and path, stay
   inside the probe body ceiling, and embed an attestation whose status
   re-derives (signature under the manifest service key, nonce, incarnation
   and request binding, time window, attested = observed).
3. If more than half of the sampled endpoints saw only ``path`` failures the
   epoch is ``common_mode_unavailable``: every endpoint abstains and no
   content fault is charged (only proved fraud still acts).
4. A request is index-suspect only when **every** incarnation of its
   deployment answered it this epoch and all of them, from at least two
   distinct miners, returned the same wrong status, body and header digests.
   Observations of a suspect request are neither charged nor counted toward
   availability; every other request is judged normally, so replicas that
   agree with each other but not with a replica serving the indexed bytes
   are charged (colluding hotkeys cannot suppress their own faults).
5. An endpoint with fewer than ``min_attempts`` attempts abstains; otherwise
   availability is ``successes / attempts``.

Content faults, fraud, alerts
-----------------------------
A verified content fault (``quarantine_candidate``: attested = observed, but
status, body or normative headers differ from ``expected``) fails the probe,
is listed as evidence, and recommends removal, replacement and **quarantine** of that
incarnation, never trust-zero. Only ``attestation_fraud`` recommends
trust-zero. Cache replays and in-transit alteration are path faults that raise
alerts. Every record reports per-deployment coverage: indexed responses,
which the ceiling can byte-check, which only HEAD can reach, and what this
epoch probed.

Window rule: a miner's availability is the mean of its eligible
endpoint-epochs; a miner with none is unscored (absent, never zero).

Arithmetic is exact. Records re-derive every evidence-derived field on parse;
:func:`replay_static_epoch_score` additionally re-derives expectations and
coverage from the authenticated indexes. This module is pure: no clock,
network, file, environment, wallet, chain, randomness, or signing capability.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping, Sequence
from fractions import Fraction
from typing import Annotated, Final, Literal, NoReturn, Self

from pydantic import Field, model_serializer, model_validator

from .contract_codec import (
    StrictFrozenModel,
    digest,
    model_bytes,
    model_document,
    parse_model,
    revalidate,
    verify_model_digest,
)
from .organic_contracts import (
    UID,
    Digest,
    DNSLabel,
    EndpointID,
    Hex64,
    Hotkey,
    verify_miner_probe_attestation_v2,
)
from .organic_probe import (
    ATTESTATION_CLOCK_SKEW_NANOS,
    DEFAULT_EPOCH_SECONDS,
    PROBE_AUTHORIZATION_VALIDITY_NANOS,
    epoch_index_of,
    timestamp_epoch_seconds,
)
from .protocol import _rfc3339nano_instant
from .static_index import (
    AbstentionCode,
    AbstentionRecordCode,
    StaticDeploymentTarget,
    StaticEndpointTarget,
    StaticIndexAbstention,
    StaticPathError,
    VerifiedStaticIndex,
    expected_static_response,
)
from .static_probe import (
    HIDDEN_PROBE_CEILING_BYTES,
    PUBLIC_FRAMING_PROFILE,
    StaticProbeObservation,
    StaticPublicTransportPolicy,
    _public_framing_valid,
    static_probe_coverage,
)

STATIC_EPOCH_SCORE_SCHEMA: Final = "miss.computer/misscomputer-subnet/static-epoch-score"
STATIC_WINDOW_SCORE_SCHEMA: Final = "miss.computer/misscomputer-subnet/static-availability-score"
STATIC_SCORING_PURPOSE: Final = "static_availability_scoring_v1"
STATIC_PUBLIC_FRAMING_PURPOSE: Final = "static_availability_scoring_public_framing_v2"
DEFAULT_MIN_ATTEMPTS: Final = 2
MAX_ATTEMPTS_PER_ENDPOINT: Final = 16
MAX_DEPLOYMENTS: Final = 4_096
MAX_ENDPOINTS: Final = MAX_DEPLOYMENTS * 8
MAX_OBSERVATIONS: Final = MAX_ENDPOINTS * MAX_ATTEMPTS_PER_ENDPOINT
MAX_EPOCHS: Final = 2_016

Count = Annotated[int, Field(ge=0, le=MAX_OBSERVATIONS)]
ByteCount = Annotated[int, Field(ge=0, le=1 << 40)]
EpochIndex = Annotated[int, Field(ge=0, le=(1 << 62))]
EpochStatus = Literal["common_mode_unavailable", "no_eligible_endpoints", "scored"]
Disposition = Literal[
    "abstain_index",
    "abstain_insufficient_attempts",
    "eligible",
    "excluded_common_mode",
]
AlertCode = Literal[
    "static_attestation_fraud",
    "static_common_mode",
    "static_content_fault",
    "static_index_invalid",
    "static_index_suspect",
    "static_index_unavailable",
    "static_path_tampering",
    "static_replay_observed",
]
ActionReason = Literal["attestation_fraud", "content_fault"]

StaticScoringRejectionCode = Literal[
    "static_scoring_attempts_overflow",
    "static_scoring_attestation_unverified",
    "static_scoring_body_over_ceiling",
    "static_scoring_epoch_mismatch",
    "static_scoring_epochs_invalid",
    "static_scoring_expectation_mismatch",
    "static_scoring_identity_conflict",
    "static_scoring_index_abstained",
    "static_scoring_index_state_invalid",
    "static_scoring_network_mismatch",
    "static_scoring_observation_duplicate",
    "static_scoring_observation_unpublished",
    "static_scoring_outcome_inconsistent",
    "static_scoring_policy_invalid",
    "static_scoring_probe_kind_invalid",
    "static_scoring_validator_mismatch",
]


class StaticScoringError(ValueError):
    """Static score inputs that cannot be trusted to produce an availability result."""

    def __init__(self, code: StaticScoringRejectionCode) -> None:
        super().__init__(code)
        self.code = code


def _reject(code: StaticScoringRejectionCode) -> NoReturn:
    raise StaticScoringError(code)


class StaticEndpointTally(StrictFrozenModel):
    deployment_id: DNSLabel
    endpoint_id: EndpointID
    site_digest: Digest
    miner_uid: UID
    miner_hotkey: Hotkey
    attempts: Count
    successes: Count
    path_failures: Count
    miner_failures: Count
    cache_replays: Count
    altered_in_transit: Count
    content_faults: Count
    fraudulent_attestations: Count
    disposition: Disposition
    availability_numerator: Count | None
    availability_denominator: Count | None


class StaticDeploymentCoverage(StrictFrozenModel):
    """§11.3 coverage of one authenticated site: totals, GET-eligible bytes, what was probed."""

    deployment_id: DNSLabel
    site_digest: Digest
    release_digest: Digest
    release_trust_policy_digest_sha256: Hex64
    ceiling_bytes: int = Field(ge=1, le=HIDDEN_PROBE_CEILING_BYTES)
    routes_total: int = Field(ge=1, le=8_192)
    bytes_total: ByteCount
    bytes_get_eligible: ByteCount
    routes_probed: int = Field(ge=0, le=8_192)
    routes_body_verified: int = Field(ge=0, le=8_192)
    unlisted_path_probes: Count


class StaticIndexAbstentionRow(StrictFrozenModel):
    deployment_id: DNSLabel
    site_digest: Digest
    code: AbstentionCode
    record_code: AbstentionRecordCode

    @model_validator(mode="after")
    def record_code_follows(self) -> Self:
        abstention = StaticIndexAbstention(self.deployment_id, self.site_digest, self.code)
        if abstention.record_code != self.record_code:
            raise ValueError("static_abstention_record_code_mismatch")
        return self


class StaticEvidenceRef(StrictFrozenModel):
    miner_uid: UID
    miner_hotkey: Hotkey
    deployment_id: DNSLabel
    endpoint_id: EndpointID
    observation_digest_sha256: Hex64


class StaticEndpointAction(StrictFrozenModel):
    """Recommended runtime action for one incarnation (mirrors runtime policy actions)."""

    deployment_id: DNSLabel
    endpoint_id: EndpointID
    miner_uid: UID
    miner_hotkey: Hotkey
    reason: ActionReason
    remove_from_routing: Literal[True]
    assign_replacement: Literal[True]
    quarantine: Literal[True]
    trust_zero: bool
    evidence_digests: list[Hex64] = Field(min_length=1, max_length=MAX_ATTEMPTS_PER_ENDPOINT)


class StaticAlert(StrictFrozenModel):
    code: AlertCode
    deployment_id: DNSLabel | None
    endpoint_id: EndpointID | None


class StaticSuspectRequest(StrictFrozenModel):
    """A request every replica answered with the same wrong response (index suspect)."""

    deployment_id: DNSLabel
    request_method: Literal["GET", "HEAD"]
    request_path: str = Field(min_length=1, max_length=1_024)


class _Tally:
    __slots__ = ("attempts", "counts", "deployment", "endpoint", "faults", "frauds", "seen")

    def __init__(self, deployment: StaticDeploymentTarget, endpoint: StaticEndpointTarget) -> None:
        self.deployment = deployment
        self.endpoint = endpoint
        self.attempts = 0
        self.counts: dict[str, int] = defaultdict(int)
        self.faults: list[str] = []
        self.frauds: list[str] = []
        self.seen: list[StaticProbeObservation] = []


_PASS: Final = ("pass",)


def _answer(obs: StaticProbeObservation) -> tuple[object, ...]:
    if obs.outcome == "success":
        return _PASS
    if obs.quarantine_candidate:
        # V2's public framing digest may differ for the same signed response
        # (Content-Length versus chunked). Corroboration compares the miner's
        # authenticated representation, never CDN-specific wire framing.
        header = (
            obs.attestation.response_header_sha256
            if obs.schema_version == 2 and obs.attestation is not None
            else obs.response_header_sha256
        )
        return (obs.response_status, obs.response_body_sha256, header)
    return ("other", obs.failure_code)


def _suspect_requests(tallies: Mapping[str, _Tally]) -> set[tuple[str, str, str]]:
    """Requests every incarnation of a deployment answered with one wrong response."""

    answers: dict[tuple[str, str, str], dict[str, set[tuple[object, ...]]]] = defaultdict(
        lambda: defaultdict(set)
    )
    population: dict[str, set[str]] = defaultdict(set)
    miners: dict[str, set[str]] = defaultdict(set)
    for endpoint_id, tally in tallies.items():
        deployment_id = tally.deployment.deployment_id
        population[deployment_id].add(endpoint_id)
        miners[deployment_id].add(tally.endpoint.miner_hotkey)
        for obs in tally.seen:
            key: tuple[str, str, str] = (deployment_id, obs.request_method, obs.request_path)
            answers[key][endpoint_id].add(_answer(obs))
    suspect: set[tuple[str, str, str]] = set()
    for request, per_endpoint in answers.items():
        values = {value for seen in per_endpoint.values() for value in seen}
        (value,) = values if len(values) == 1 else (None,)
        if (
            set(per_endpoint) == population[request[0]]
            and len(miners[request[0]]) >= 2
            and value is not None
            and value != _PASS
            and value[0] != "other"
        ):
            suspect.add(request)
    return suspect


def _derive_static_epoch(
    targets: Sequence[StaticDeploymentTarget],
    indexed: Mapping[str, tuple[str, str]],
    abstained: Mapping[str, str],
    observations: Sequence[StaticProbeObservation],
    *,
    epoch_seconds: int,
    epoch_index: int,
    min_attempts: int,
) -> dict[str, object]:
    """Every evidence-derived field of a static epoch record.

    ``indexed`` maps each authenticated deployment id to its (release, release
    trust policy) digests; ``abstained`` maps every other target to its §11.2
    abstention record code.
    """

    tallies: dict[str, _Tally] = {}
    identities: dict[int, str] = {}
    hotkeys: dict[str, int] = {}
    for deployment in targets:
        for endpoint in deployment.endpoints:
            if (
                endpoint.endpoint_id in tallies
                or identities.setdefault(endpoint.miner_uid, endpoint.miner_hotkey)
                != endpoint.miner_hotkey
                or hotkeys.setdefault(endpoint.miner_hotkey, endpoint.miner_uid)
                != endpoint.miner_uid
            ):
                _reject("static_scoring_identity_conflict")
            tallies[endpoint.endpoint_id] = _Tally(deployment, endpoint)
    for obs in observations:
        if epoch_index_of(timestamp_epoch_seconds(obs.issued_at), epoch_seconds) != epoch_index:
            _reject("static_scoring_epoch_mismatch")
        tally = tallies.get(obs.endpoint_id)
        if tally is None:
            _reject("static_scoring_observation_unpublished")
        if indexed.get(obs.deployment_id) != (
            obs.release_digest,
            obs.release_trust_policy_digest_sha256,
        ):
            _reject("static_scoring_index_abstained")
        tally.seen.append(obs)
        if len(tally.seen) > MAX_ATTEMPTS_PER_ENDPOINT:
            _reject("static_scoring_attempts_overflow")
    suspect_requests = _suspect_requests(tallies)
    for tally in tallies.values():
        for obs in tally.seen:
            if obs.attestation_status == "fraudulent":
                tally.frauds.append(obs.observation_digest_sha256)
            if (obs.deployment_id, obs.request_method, obs.request_path) in suspect_requests:
                continue  # the index, not the miner, is in question
            tally.attempts += 1
            tally.counts[obs.attribution] += 1
            if obs.failure_code in {"cache_replay", "content_altered_in_transit"}:
                tally.counts[obs.failure_code] += 1
            if obs.quarantine_candidate:
                tally.faults.append(obs.observation_digest_sha256)
    sampled = [tally for tally in tallies.values() if tally.attempts]
    path_down = sum(1 for tally in sampled if tally.counts["path"] == tally.attempts)
    common_mode = bool(sampled) and path_down * 2 > len(sampled)
    suspect = sorted({request[0] for request in suspect_requests})
    endpoints: list[dict[str, object]] = []
    faults: list[dict[str, object]] = []
    frauds: list[dict[str, object]] = []
    actions: list[dict[str, object]] = []
    alerts: set[tuple[str, str | None, str | None]] = set()
    eligible = 0
    for endpoint_id in sorted(tallies):
        tally = tallies[endpoint_id]
        deployment_id = tally.deployment.deployment_id
        disposition: Disposition
        if deployment_id not in indexed:
            disposition = "abstain_index"
            alerts.add((abstained[deployment_id], deployment_id, None))
        elif common_mode:
            disposition = "excluded_common_mode"
        elif tally.attempts < min_attempts:
            disposition = "abstain_insufficient_attempts"
        else:
            disposition = "eligible"
        numerator: int | None = None
        denominator: int | None = None
        if disposition == "eligible":
            eligible += 1
            ratio = Fraction(tally.counts["none"], tally.attempts)
            numerator, denominator = ratio.numerator, ratio.denominator
        # A shared path outage charges no content fault; proved fraud still acts.
        charged = [] if common_mode else sorted(tally.faults)
        identity: dict[str, object] = {
            "miner_uid": tally.endpoint.miner_uid,
            "miner_hotkey": tally.endpoint.miner_hotkey,
            "deployment_id": deployment_id,
            "endpoint_id": endpoint_id,
        }
        faults.extend({**identity, "observation_digest_sha256": item} for item in charged)
        frauds.extend({**identity, "observation_digest_sha256": item} for item in tally.frauds)
        if tally.frauds or charged:
            actions.append(
                {
                    **identity,
                    "reason": "attestation_fraud" if tally.frauds else "content_fault",
                    "remove_from_routing": True,
                    "assign_replacement": True,
                    "quarantine": True,
                    "trust_zero": bool(tally.frauds),
                    "evidence_digests": sorted(tally.frauds or charged),
                }
            )
        for code, present in (
            ("static_content_fault", len(charged)),
            ("static_attestation_fraud", len(tally.frauds)),
            ("static_replay_observed", tally.counts["cache_replay"]),
            ("static_path_tampering", tally.counts["content_altered_in_transit"]),
        ):
            if present:
                alerts.add((code, deployment_id, endpoint_id))
        endpoints.append(
            {
                "deployment_id": deployment_id,
                "endpoint_id": endpoint_id,
                "site_digest": tally.deployment.site_digest,
                "miner_uid": tally.endpoint.miner_uid,
                "miner_hotkey": tally.endpoint.miner_hotkey,
                "attempts": tally.attempts,
                "successes": tally.counts["none"],
                "path_failures": tally.counts["path"],
                "miner_failures": tally.counts["miner"],
                "cache_replays": tally.counts["cache_replay"],
                "altered_in_transit": tally.counts["content_altered_in_transit"],
                "content_faults": len(tally.faults),
                "fraudulent_attestations": len(tally.frauds),
                "disposition": disposition,
                "availability_numerator": numerator,
                "availability_denominator": denominator,
            }
        )
    if common_mode:
        alerts.add(("static_common_mode", None, None))
    for deployment_id in suspect:
        alerts.add(("static_index_suspect", deployment_id, None))
    status: EpochStatus
    if common_mode:
        status = "common_mode_unavailable"
    elif eligible == 0:
        status = "no_eligible_endpoints"
    else:
        status = "scored"

    def ordered(rows: list[dict[str, object]]) -> list[dict[str, object]]:
        return sorted(rows, key=lambda row: str(row["observation_digest_sha256"]))

    return {
        "epoch_status": status,
        "sampled_endpoint_count": len(sampled),
        "path_unavailable_endpoint_count": path_down,
        "index_suspect_requests": [
            {"deployment_id": d, "request_method": m, "request_path": p}
            for d, m, p in sorted(suspect_requests)
        ],
        "endpoints": endpoints,
        "content_fault_evidence": ordered(faults),
        "fraud_evidence": ordered(frauds),
        "endpoint_actions": actions,
        "alerts": [
            {"code": code, "deployment_id": deployment, "endpoint_id": endpoint}
            for code, deployment, endpoint in sorted(
                alerts, key=lambda row: (row[0], row[1] or "", row[2] or "")
            )
        ],
    }


_INDEXED_KINDS: Final = frozenset({"directory_index", "file"})


def _probed(observations: Sequence[StaticProbeObservation]) -> dict[str, tuple[int, int, int]]:
    """Per deployment: distinct indexed paths probed, of them GET-verified, unlisted probes."""

    probed: dict[str, set[str]] = defaultdict(set)
    bodies: dict[str, set[str]] = defaultdict(set)
    unlisted: dict[str, int] = defaultdict(int)
    for obs in observations:
        if obs.expected_kind in _INDEXED_KINDS:
            probed[obs.deployment_id].add(obs.request_path)
            if obs.request_method == "GET":
                bodies[obs.deployment_id].add(obs.request_path)
        else:
            unlisted[obs.deployment_id] += 1
    return {
        key: (len(probed[key]), len(bodies[key]), unlisted[key])
        for key in set(probed) | set(unlisted)
    }


def _observation_order(item: StaticProbeObservation) -> tuple[str, str, str]:
    return (item.endpoint_id, item.issued_at, item.probe_nonce)


class StaticEpochScore(StrictFrozenModel):
    """``static-epoch-score`` v1: one validator's sealed static epoch, inputs bound."""

    contract_schema: Literal["miss.computer/misscomputer-subnet/static-epoch-score"] = Field(
        alias="schema"
    )
    schema_version: Literal[1, 2]
    purpose: Literal[
        "static_availability_scoring_v1", "static_availability_scoring_public_framing_v2"
    ]
    network: Literal["finney", "test"]
    netuid: Literal[24, 581]
    validator_hotkey: Hotkey
    epoch_seconds: int = Field(ge=60, le=3_600)
    epoch_index: EpochIndex
    min_attempts: int = Field(ge=1, le=MAX_ATTEMPTS_PER_ENDPOINT)
    probe_body_ceiling: int = Field(ge=1, le=HIDDEN_PROBE_CEILING_BYTES)
    targets: list[StaticDeploymentTarget] = Field(max_length=MAX_DEPLOYMENTS)
    coverage: list[StaticDeploymentCoverage] = Field(max_length=MAX_DEPLOYMENTS)
    index_abstentions: list[StaticIndexAbstentionRow] = Field(max_length=MAX_DEPLOYMENTS)
    epoch_status: EpochStatus
    sampled_endpoint_count: Count
    path_unavailable_endpoint_count: Count
    index_suspect_requests: list[StaticSuspectRequest] = Field(max_length=MAX_OBSERVATIONS)
    endpoints: list[StaticEndpointTally] = Field(max_length=MAX_ENDPOINTS)
    content_fault_evidence: list[StaticEvidenceRef] = Field(max_length=MAX_OBSERVATIONS)
    fraud_evidence: list[StaticEvidenceRef] = Field(max_length=MAX_OBSERVATIONS)
    endpoint_actions: list[StaticEndpointAction] = Field(max_length=MAX_ENDPOINTS)
    alerts: list[StaticAlert] = Field(max_length=MAX_ENDPOINTS * 4)
    observations: list[StaticProbeObservation] = Field(max_length=MAX_OBSERVATIONS)
    transport_profile: Literal["public-framing-v1"] | None = None
    transport_policy_digest_sha256: Hex64 | None = None
    observation_vector_digest_sha256: Hex64
    epoch_score_digest_sha256: Hex64

    @model_serializer(mode="wrap")
    def serialize_versioned(self, handler: object) -> dict[str, object]:
        document: dict[str, object] = handler(self)  # type: ignore[operator]
        if self.schema_version == 1:
            document.pop("transport_profile", None)
            document.pop("transport_policy_digest_sha256", None)
        return document

    @model_validator(mode="after")
    def canonical_epoch(self) -> Self:
        if self.purpose != (
            STATIC_SCORING_PURPOSE if self.schema_version == 1 else STATIC_PUBLIC_FRAMING_PURPOSE
        ):
            raise ValueError("static_epoch_purpose_invalid")
        if self.schema_version == 1:
            if (
                self.transport_profile is not None
                or self.transport_policy_digest_sha256 is not None
            ):
                raise ValueError("static_epoch_profile_invalid")
        elif (
            self.transport_profile != PUBLIC_FRAMING_PROFILE
            or self.transport_policy_digest_sha256 is None
            or (self.network, self.netuid) != ("test", 581)
        ):
            raise ValueError("static_epoch_profile_invalid")
        if any(
            item.schema_version != self.schema_version
            or item.transport_profile != self.transport_profile
            or item.transport_policy_digest_sha256 != self.transport_policy_digest_sha256
            for item in self.observations
        ):
            raise ValueError("static_epoch_profile_mixed")
        if (self.network, self.netuid) not in {("finney", 24), ("test", 581)}:
            raise ValueError("static_subnet_invalid")
        ids = [item.deployment_id for item in self.targets]
        covered = [item.deployment_id for item in self.coverage]
        abstained = [item.deployment_id for item in self.index_abstentions]
        if (
            ids != sorted(set(ids))
            or covered != sorted(set(covered))
            or abstained != sorted(set(abstained))
            or set(covered) & set(abstained)
            or set(covered) | set(abstained) != set(ids)
        ):
            raise ValueError("static_epoch_targets_not_canonical")
        sites = {item.deployment_id: item.site_digest for item in self.targets}
        if any(row.site_digest != sites[row.deployment_id] for row in self.coverage) or any(
            row.site_digest != sites[row.deployment_id] for row in self.index_abstentions
        ):
            raise ValueError("static_epoch_site_binding_mismatch")
        if self.observations != sorted(self.observations, key=_observation_order):
            raise ValueError("static_epoch_observations_not_canonical")
        nonces = [item.probe_nonce for item in self.observations]
        if len(set(nonces)) != len(nonces):
            raise ValueError("static_epoch_observation_nonce_duplicate")
        if any(
            item.validator_hotkey != self.validator_hotkey or item.probe_kind != "hidden"
            for item in self.observations
        ):
            raise ValueError("static_epoch_observation_foreign")
        probed = _probed(self.observations)
        for row in self.coverage:
            if (
                row.routes_probed,
                row.routes_body_verified,
                row.unlisted_path_probes,
            ) != probed.get(row.deployment_id, (0, 0, 0)) or (
                row.ceiling_bytes != self.probe_body_ceiling
                or row.bytes_get_eligible > row.bytes_total
                or row.routes_probed > row.routes_total
                or row.routes_body_verified > row.routes_probed
            ):
                raise ValueError("static_epoch_coverage_mismatch")
        derived = _derive_static_epoch(
            self.targets,
            {
                row.deployment_id: (row.release_digest, row.release_trust_policy_digest_sha256)
                for row in self.coverage
            },
            {row.deployment_id: row.record_code for row in self.index_abstentions},
            self.observations,
            epoch_seconds=self.epoch_seconds,
            epoch_index=self.epoch_index,
            min_attempts=self.min_attempts,
        )
        for key, value in derived.items():
            current = getattr(self, key)
            if isinstance(current, list):
                current = [
                    model_document(item) if isinstance(item, StrictFrozenModel) else item
                    for item in current
                ]
            if current != value:
                raise ValueError(f"static_epoch_{key}_mismatch")
        vector = [model_document(item) for item in self.observations]
        if self.observation_vector_digest_sha256 != digest(vector):
            raise ValueError("static_observation_vector_digest_mismatch")
        verify_model_digest(self, "epoch_score_digest_sha256")
        return self


def _attestation_status(
    obs: StaticProbeObservation, target: StaticDeploymentTarget, endpoint: StaticEndpointTarget
) -> str:
    """Re-derive the recorded attestation status from the embedded attestation (§11.4).

    Only ``verified``, ``replayed`` and ``fraudulent`` observations embed their
    attestation; the order mirrors the validator evaluator exactly.
    """

    attestation = obs.attestation
    if attestation is None:
        return obs.attestation_status
    try:
        verify_miner_probe_attestation_v2(attestation, endpoint.miner_service_public_key)
    except ValueError:
        return "rejected"
    if attestation.probe_nonce != obs.probe_nonce:
        return "replayed"
    if (
        attestation.endpoint_id != endpoint.endpoint_id
        or attestation.generation != endpoint.generation
        or attestation.ticket_digest != endpoint.ticket_digest
        or attestation.artifact_digest != target.site_digest
        or attestation.validator_hotkey != obs.validator_hotkey
        or attestation.request_method != obs.request_method
        or attestation.request_path != obs.request_path
    ):
        return "fraudulent"
    issued = _rfc3339nano_instant(obs.issued_at)
    observed = _rfc3339nano_instant(attestation.observed_at)
    if not (
        issued - ATTESTATION_CLOCK_SKEW_NANOS
        <= observed
        <= issued + PROBE_AUTHORIZATION_VALIDITY_NANOS + ATTESTATION_CLOCK_SKEW_NANOS
    ):
        return "rejected"
    if (
        attestation.response_status,
        attestation.response_body_sha256,
    ) != (
        obs.response_status,
        obs.response_body_sha256,
    ) or (
        obs.schema_version == 1 and attestation.response_header_sha256 != obs.response_header_sha256
    ):
        return "rejected"
    return "verified"


def _verify_observation(
    obs: StaticProbeObservation,
    index: VerifiedStaticIndex,
    probe_body_ceiling: int,
) -> None:
    """Bind one hidden observation to its published incarnation and authenticated index."""

    endpoint = next(
        (item for item in index.target.endpoints if item.endpoint_id == obs.endpoint_id), None
    )
    if endpoint is None or (
        obs.site_digest,
        obs.generation,
        obs.miner_uid,
        obs.miner_hotkey,
    ) != (index.target.site_digest, endpoint.generation, endpoint.miner_uid, endpoint.miner_hotkey):
        _reject("static_scoring_observation_unpublished")
    if (obs.release_digest, obs.release_trust_policy_digest_sha256) != (
        index.target.release_digest,
        index.trust_policy_digest_sha256,
    ):
        _reject("static_scoring_expectation_mismatch")
    try:
        expected = expected_static_response(index, obs.request_method, obs.request_path)
    except StaticPathError:
        _reject("static_scoring_expectation_mismatch")
    if (
        obs.expected_kind,
        obs.expected_status,
        obs.expected_content_length,
        obs.expected_body_sha256,
        obs.expected_header_sha256,
    ) != (
        expected.kind,
        expected.status,
        expected.content_length,
        expected.body_sha256,
        expected.header_sha256,
    ):
        _reject("static_scoring_expectation_mismatch")
    body_length = expected.content_length if obs.request_method == "GET" else 0
    if body_length > probe_body_ceiling or obs.response_bytes > probe_body_ceiling + 1:
        _reject("static_scoring_body_over_ceiling")
    if _attestation_status(obs, index.target, endpoint) != obs.attestation_status:
        _reject("static_scoring_attestation_unverified")
    if obs.schema_version == 2:
        if obs.outcome == "success" and (
            obs.delivered_headers is None
            or obs.delivered_http_version is None
            or not _public_framing_valid(
                obs.delivered_headers,
                http_version=obs.delivered_http_version,
                request_method=obs.request_method,
                expected_content_type=expected.content_type,
                expected_content_length=expected.content_length,
            )
        ):
            _reject("static_scoring_attestation_unverified")
        if obs.quarantine_candidate and (
            obs.attestation is None
            or obs.attestation.response_header_sha256 != expected.header_sha256
            or obs.failure_code == "header_mismatch"
            or (obs.failure_code == "status_mismatch" and obs.response_status == expected.status)
            or (
                obs.failure_code == "body_mismatch"
                and (
                    obs.response_status != expected.status
                    or obs.response_body_sha256 == expected.body_sha256
                )
            )
        ):
            _reject("static_scoring_attestation_unverified")


def score_static_epoch(
    targets: Sequence[StaticDeploymentTarget],
    indexes: Sequence[VerifiedStaticIndex],
    abstentions: Sequence[StaticIndexAbstention],
    observations: Sequence[StaticProbeObservation],
    *,
    validator_hotkey: str,
    epoch_index: int,
    epoch_seconds: int = DEFAULT_EPOCH_SECONDS,
    min_attempts: int = DEFAULT_MIN_ATTEMPTS,
    probe_body_ceiling: int = HIDDEN_PROBE_CEILING_BYTES,
    network: Literal["finney", "test"] = "finney",
    netuid: Literal[24, 581] = 24,
    public_transport_policy: StaticPublicTransportPolicy | None = None,
) -> StaticEpochScore:
    """Seal one static epoch from verified targets, index states and hidden evidence.

    Every target needs exactly one index state (verified or abstained) bound
    to its own site digest; any unbound, inconsistent, duplicated, admission,
    or foreign observation refuses the epoch rather than scoring it.
    """

    if (
        not 60 <= epoch_seconds <= 3_600
        or not 1 <= min_attempts <= MAX_ATTEMPTS_PER_ENDPOINT
        or not 1 <= probe_body_ceiling <= HIDDEN_PROBE_CEILING_BYTES
    ):
        _reject("static_scoring_policy_invalid")
    if len(targets) > MAX_DEPLOYMENTS or len(observations) > MAX_OBSERVATIONS:
        _reject("static_scoring_attempts_overflow")
    by_id: dict[str, StaticDeploymentTarget] = {}
    for raw in targets:
        item = revalidate(raw, StaticDeploymentTarget)
        if by_id.setdefault(item.deployment_id, item) != item:
            _reject("static_scoring_identity_conflict")
    verified: dict[str, VerifiedStaticIndex] = {}
    for index in indexes:
        key = index.target.deployment_id
        if key not in by_id or index.target != by_id[key] or key in verified:
            _reject("static_scoring_index_state_invalid")
        verified[key] = index
    abstained: dict[str, StaticIndexAbstention] = {}
    for row in abstentions:
        key = row.deployment_id
        if (
            key not in by_id
            or row.site_digest != by_id[key].site_digest
            or key in verified
            or key in abstained
        ):
            _reject("static_scoring_index_state_invalid")
        abstained[key] = row
    if set(verified) | set(abstained) != set(by_id):
        _reject("static_scoring_index_state_invalid")
    values = [revalidate(item, StaticProbeObservation) for item in observations]
    if public_transport_policy is not None and (network, netuid) != ("test", 581):
        _reject("static_scoring_policy_invalid")
    if any(
        item.schema_version != (2 if public_transport_policy is not None else 1)
        or item.transport_policy_digest_sha256
        != (public_transport_policy.policy_digest_sha256 if public_transport_policy else None)
        for item in values
    ):
        _reject("static_scoring_policy_invalid")
    seen_digests: set[str] = set()
    seen_nonces: set[str] = set()
    for obs in values:
        if obs.validator_hotkey != validator_hotkey:
            _reject("static_scoring_validator_mismatch")
        if obs.probe_kind != "hidden":
            _reject("static_scoring_probe_kind_invalid")
        if obs.observation_digest_sha256 in seen_digests or obs.probe_nonce in seen_nonces:
            _reject("static_scoring_observation_duplicate")
        seen_digests.add(obs.observation_digest_sha256)
        seen_nonces.add(obs.probe_nonce)
        if epoch_index_of(timestamp_epoch_seconds(obs.issued_at), epoch_seconds) != epoch_index:
            _reject("static_scoring_epoch_mismatch")
        if obs.deployment_id in abstained:
            _reject("static_scoring_index_abstained")
        if obs.deployment_id not in verified:
            _reject("static_scoring_observation_unpublished")
        _verify_observation(obs, verified[obs.deployment_id], probe_body_ceiling)
    values.sort(key=_observation_order)
    ordered_targets = [by_id[key] for key in sorted(by_id)]
    probed = _probed(values)
    coverage: list[dict[str, object]] = []
    for key in sorted(verified):
        index = verified[key]
        base = static_probe_coverage(index, (), probe_body_ceiling)
        routes_probed, routes_verified, unlisted = probed.get(key, (0, 0, 0))
        coverage.append(
            {
                "deployment_id": key,
                "site_digest": index.target.site_digest,
                "release_digest": index.target.release_digest,
                "release_trust_policy_digest_sha256": index.trust_policy_digest_sha256,
                "ceiling_bytes": base.ceiling_bytes,
                "routes_total": base.routes_total,
                "bytes_total": base.bytes_total,
                "bytes_get_eligible": base.bytes_get_eligible,
                "routes_probed": routes_probed,
                "routes_body_verified": routes_verified,
                "unlisted_path_probes": unlisted,
            }
        )
    derived = _derive_static_epoch(
        ordered_targets,
        {
            key: (index.target.release_digest, index.trust_policy_digest_sha256)
            for key, index in verified.items()
        },
        {key: row.record_code for key, row in abstained.items()},
        values,
        epoch_seconds=epoch_seconds,
        epoch_index=epoch_index,
        min_attempts=min_attempts,
    )
    vector = [model_document(item) for item in values]
    unsigned: dict[str, object] = {
        "schema": STATIC_EPOCH_SCORE_SCHEMA,
        "schema_version": 2 if public_transport_policy is not None else 1,
        "purpose": (
            STATIC_SCORING_PURPOSE
            if public_transport_policy is None
            else STATIC_PUBLIC_FRAMING_PURPOSE
        ),
        "network": network,
        "netuid": netuid,
        "validator_hotkey": validator_hotkey,
        "epoch_seconds": epoch_seconds,
        "epoch_index": epoch_index,
        "min_attempts": min_attempts,
        "probe_body_ceiling": probe_body_ceiling,
        "targets": [model_document(item) for item in ordered_targets],
        "coverage": coverage,
        "index_abstentions": [
            {
                "deployment_id": key,
                "site_digest": abstained[key].site_digest,
                "code": abstained[key].code,
                "record_code": abstained[key].record_code,
            }
            for key in sorted(abstained)
        ],
        **derived,
        "observations": vector,
        "observation_vector_digest_sha256": digest(vector),
    }
    if public_transport_policy is not None:
        unsigned["transport_profile"] = public_transport_policy.profile
        unsigned["transport_policy_digest_sha256"] = public_transport_policy.policy_digest_sha256
    return StaticEpochScore.model_validate(
        {**unsigned, "epoch_score_digest_sha256": digest(unsigned)}
    )


def replay_static_epoch_score(
    record: StaticEpochScore,
    indexes: Sequence[VerifiedStaticIndex],
    *,
    public_transport_policy: StaticPublicTransportPolicy | None = None,
) -> StaticEpochScore:
    """Third-party audit: rebuild a record from its evidence and re-authenticated indexes.

    ``indexes`` must authenticate exactly the deployments the record covered;
    every expectation, coverage row, attestation status and derived field is
    re-derived and must reproduce the record byte-for-byte.
    """

    value = revalidate(record, StaticEpochScore)
    if value.transport_policy_digest_sha256 != (
        public_transport_policy.policy_digest_sha256 if public_transport_policy else None
    ):
        _reject("static_scoring_policy_invalid")
    rebuilt = score_static_epoch(
        value.targets,
        indexes,
        [
            StaticIndexAbstention(row.deployment_id, row.site_digest, row.code)
            for row in value.index_abstentions
        ],
        value.observations,
        validator_hotkey=value.validator_hotkey,
        epoch_index=value.epoch_index,
        epoch_seconds=value.epoch_seconds,
        min_attempts=value.min_attempts,
        probe_body_ceiling=value.probe_body_ceiling,
        network=value.network,
        netuid=value.netuid,
        public_transport_policy=public_transport_policy,
    )
    if static_epoch_score_bytes(rebuilt) != static_epoch_score_bytes(value):
        _reject("static_scoring_outcome_inconsistent")
    return value


class StaticMinerAvailability(StrictFrozenModel):
    miner_uid: UID
    miner_hotkey: Hotkey
    eligible_endpoint_epochs: Annotated[int, Field(ge=1, le=MAX_ENDPOINTS * MAX_EPOCHS)]
    availability_numerator: Annotated[int, Field(ge=0)]
    availability_denominator: Annotated[int, Field(ge=1)]
    content_faults: Annotated[int, Field(ge=0)]
    fraudulent_attestations: Annotated[int, Field(ge=0)]

    @model_validator(mode="after")
    def reduced(self) -> Self:
        ratio = Fraction(self.availability_numerator, self.availability_denominator)
        if (ratio.numerator, ratio.denominator) != (
            self.availability_numerator,
            self.availability_denominator,
        ) or ratio > 1:
            raise ValueError("availability_not_reduced")
        return self


class StaticAvailabilityScore(StrictFrozenModel):
    """``static-availability-score`` v1: per-miner static availability over a window."""

    contract_schema: Literal["miss.computer/misscomputer-subnet/static-availability-score"] = Field(
        alias="schema"
    )
    schema_version: Literal[1]
    purpose: Literal["static_availability_scoring_v1"]
    network: Literal["finney", "test"]
    netuid: Literal[24, 581]
    validator_hotkey: Hotkey
    epoch_seconds: int = Field(ge=60, le=3_600)
    epoch_indexes: list[EpochIndex] = Field(min_length=1, max_length=MAX_EPOCHS)
    epoch_score_digests: list[Hex64] = Field(min_length=1, max_length=MAX_EPOCHS)
    abstained_epochs: list[EpochIndex] = Field(max_length=MAX_EPOCHS)
    miners: list[StaticMinerAvailability] = Field(max_length=MAX_ENDPOINTS)
    content_fault_evidence: list[StaticEvidenceRef] = Field(max_length=MAX_OBSERVATIONS)
    fraud_evidence: list[StaticEvidenceRef] = Field(max_length=MAX_OBSERVATIONS)
    score_digest_sha256: Hex64

    @model_validator(mode="after")
    def canonical_score(self) -> Self:
        if (self.network, self.netuid) not in {("finney", 24), ("test", 581)}:
            raise ValueError("static_subnet_invalid")
        if self.epoch_indexes != sorted(set(self.epoch_indexes)) or len(
            self.epoch_score_digests
        ) != len(self.epoch_indexes):
            raise ValueError("static_score_epochs_not_canonical")
        if not set(self.abstained_epochs) <= set(self.epoch_indexes) or (
            self.abstained_epochs != sorted(set(self.abstained_epochs))
        ):
            raise ValueError("static_score_abstained_invalid")
        keys = [(item.miner_uid, item.miner_hotkey) for item in self.miners]
        if keys != sorted(set(keys)) or len({key[1] for key in keys}) != len(keys):
            raise ValueError("static_score_miners_not_canonical")
        verify_model_digest(self, "score_digest_sha256")
        return self


def aggregate_static_window(epochs: Sequence[StaticEpochScore]) -> StaticAvailabilityScore:
    """Mean static availability per miner across its eligible endpoint-epochs."""

    values = sorted(
        (revalidate(item, StaticEpochScore) for item in epochs), key=lambda item: item.epoch_index
    )
    if not values or len(values) > MAX_EPOCHS:
        _reject("static_scoring_epochs_invalid")
    validator = values[0].validator_hotkey
    epoch_seconds = values[0].epoch_seconds
    indexes = [item.epoch_index for item in values]
    if len(set(indexes)) != len(indexes) or any(
        item.epoch_seconds != epoch_seconds for item in values
    ):
        _reject("static_scoring_epochs_invalid")
    if any(item.validator_hotkey != validator for item in values):
        _reject("static_scoring_validator_mismatch")
    network, netuid = values[0].network, values[0].netuid
    if any((item.network, item.netuid) != (network, netuid) for item in values):
        _reject("static_scoring_network_mismatch")
    sums: dict[tuple[int, str], Fraction] = defaultdict(Fraction)
    counts: dict[tuple[int, str], int] = defaultdict(int)
    faults: dict[str, int] = defaultdict(int)
    frauds: dict[str, int] = defaultdict(int)
    identities: dict[int, str] = {}
    hotkeys: dict[str, int] = {}
    fault_rows: list[StaticEvidenceRef] = []
    fraud_rows: list[StaticEvidenceRef] = []
    for epoch in values:
        for endpoint in epoch.endpoints:
            if (
                identities.setdefault(endpoint.miner_uid, endpoint.miner_hotkey)
                != endpoint.miner_hotkey
                or hotkeys.setdefault(endpoint.miner_hotkey, endpoint.miner_uid)
                != endpoint.miner_uid
            ):
                _reject("static_scoring_identity_conflict")
            if endpoint.disposition != "eligible":
                continue
            if endpoint.availability_numerator is None or not endpoint.availability_denominator:
                _reject("static_scoring_outcome_inconsistent")
            key = (endpoint.miner_uid, endpoint.miner_hotkey)
            sums[key] += Fraction(
                endpoint.availability_numerator, endpoint.availability_denominator
            )
            counts[key] += 1
        for row in epoch.content_fault_evidence:
            faults[row.miner_hotkey] += 1
        for row in epoch.fraud_evidence:
            frauds[row.miner_hotkey] += 1
        fault_rows.extend(epoch.content_fault_evidence)
        fraud_rows.extend(epoch.fraud_evidence)
    miners: list[dict[str, object]] = []
    for key in sorted(sums):
        mean = sums[key] / counts[key]
        miners.append(
            {
                "miner_uid": key[0],
                "miner_hotkey": key[1],
                "eligible_endpoint_epochs": counts[key],
                "availability_numerator": mean.numerator,
                "availability_denominator": mean.denominator,
                "content_faults": faults[key[1]],
                "fraudulent_attestations": frauds[key[1]],
            }
        )
    unsigned: dict[str, object] = {
        "schema": STATIC_WINDOW_SCORE_SCHEMA,
        "schema_version": 1,
        "purpose": STATIC_SCORING_PURPOSE,
        "network": network,
        "netuid": netuid,
        "validator_hotkey": validator,
        "epoch_seconds": epoch_seconds,
        "epoch_indexes": indexes,
        "epoch_score_digests": [item.epoch_score_digest_sha256 for item in values],
        "abstained_epochs": [item.epoch_index for item in values if item.epoch_status != "scored"],
        "miners": miners,
        "content_fault_evidence": [
            model_document(item)
            for item in sorted(fault_rows, key=lambda row: row.observation_digest_sha256)
        ],
        "fraud_evidence": [
            model_document(item)
            for item in sorted(fraud_rows, key=lambda row: row.observation_digest_sha256)
        ],
    }
    return StaticAvailabilityScore.model_validate(
        {**unsigned, "score_digest_sha256": digest(unsigned)}
    )


def static_epoch_score_bytes(value: StaticEpochScore) -> bytes:
    return model_bytes(value, StaticEpochScore)


def parse_static_epoch_score(rendered: bytes) -> StaticEpochScore:
    """Parse canonical bytes; every evidence-derived field is re-derived on validation."""

    return parse_model(rendered, StaticEpochScore, static_epoch_score_bytes)


def static_availability_score_bytes(value: StaticAvailabilityScore) -> bytes:
    return model_bytes(value, StaticAvailabilityScore)


def parse_static_availability_score(rendered: bytes) -> StaticAvailabilityScore:
    return parse_model(rendered, StaticAvailabilityScore, static_availability_score_bytes)
