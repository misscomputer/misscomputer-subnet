# SPDX-License-Identifier: AGPL-3.0-only
"""Organic availability scoring from hidden validator probes (contract §17.2).

The synthetic campaign scorer is gone. A validator's score for a miner is the
**availability of the real organic app endpoints it was assigned**, measured
by the validator's own hidden probes. It is never request volume, response
bytes, customer identity, popularity, or app-content correctness.

Epoch rules (five-minute epochs by default)
-------------------------------------------
1. An *attempt* is one sealed
   :class:`~misscomputer_subnet.organic_probe.OrganicProbeObservation` of a
   published endpoint incarnation; a *success* needs the edge upstream marker,
   a verified miner attestation v2, and the customer's health predicate.
2. An endpoint with fewer than ``min_attempts`` attempts in the epoch
   **abstains** (``abstain_insufficient_attempts``).
3. If more than half of the endpoints sampled in the epoch saw only
   ``path``-attributed failures, the edge/tunnel is presumed down: the epoch is
   ``common_mode_unavailable`` and every endpoint abstains.
4. If at least two replicas of the same app saw an ``application``-attributed
   failure (a miner-signed response that fails the customer's own predicate),
   the app is inconclusive for the epoch and all of its replicas are excluded.
5. Otherwise endpoint availability is ``successes / attempts``.

Window rule
-----------
A miner's availability is the arithmetic mean over all of its eligible
endpoint-epochs in the window. A miner with no eligible endpoint-epoch is
*unscored*: it is absent from the result, never forced to zero and never
trust-zeroed. Fraud evidence (a verified miner signature over a mismatched
identity, nonce or request) is surfaced separately; it fails the probe and is
for the trust policy to act on, not a scoring multiplier.

Corroboration only
------------------
``organic-serving-window`` counters may be attached per endpoint for audit.
They are summarized into the sealed record and **never** read by the score:
changing request counts cannot change any availability.

Determinism and self-enforcement
--------------------------------
Arithmetic is exact (:class:`fractions.Fraction`); availabilities are sealed
as reduced numerator/denominator pairs. The sealed ``organic-epoch-score``
record embeds every observation it was derived from, and re-derives every
tally, disposition and fraud entry on parse, so a record whose numbers do not
follow from its evidence is rejected. :func:`replay_organic_epoch_score`
additionally re-verifies every embedded miner attestation against the
published manifests, which lets any third party audit a validator's inputs.
Order of inputs never changes the output bytes.

This module is pure: no clock, network, file, process, environment, wallet,
chain, randomness, or signing capability.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping, Sequence
from fractions import Fraction
from typing import Annotated, Final, Literal, NoReturn, Self

from pydantic import Field, model_validator

from .assignment_probe import (
    UID,
    DeploymentID,
    Digest,
    EndpointID,
    Hotkey,
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
from .organic_contracts import ActiveAssignmentManifestV2
from .organic_manifest import organic_manifest_valid_at
from .organic_probe import (
    DEFAULT_EPOCH_SECONDS,
    OrganicProbeObservation,
    epoch_index_of,
    find_replica,
    timestamp_epoch_seconds,
    verify_attestation_v2,
)

EPOCH_SCORE_SCHEMA: Final = "miss.computer/misscomputer-subnet/organic-epoch-score"
WINDOW_SCORE_SCHEMA: Final = "miss.computer/misscomputer-subnet/organic-availability-score"
SCORING_PURPOSE: Final = "organic_availability_scoring_v1"
DEFAULT_MIN_ATTEMPTS: Final = 2
MAX_ATTEMPTS_PER_ENDPOINT: Final = 16
MAX_ENDPOINTS: Final = 4_096 * 8
MAX_OBSERVATIONS: Final = MAX_ENDPOINTS * MAX_ATTEMPTS_PER_ENDPOINT
MAX_EPOCHS: Final = 2_016  # one week of five-minute epochs
MAX_CORROBORATION_WINDOWS: Final = 64

Count = Annotated[int, Field(ge=0, le=MAX_OBSERVATIONS)]
EpochIndex = Annotated[int, Field(ge=0, le=(1 << 62))]
EpochStatus = Literal["common_mode_unavailable", "no_eligible_endpoints", "scored"]
Disposition = Literal[
    "abstain_insufficient_attempts",
    "eligible",
    "excluded_app_inconclusive",
    "excluded_common_mode",
]

ScoringRejectionCode = Literal[
    "scoring_attempts_overflow",
    "scoring_attestation_unverified",
    "scoring_epoch_mismatch",
    "scoring_epochs_invalid",
    "scoring_identity_conflict",
    "scoring_manifest_unknown",
    "scoring_observation_duplicate",
    "scoring_observation_unpublished",
    "scoring_outcome_inconsistent",
    "scoring_outside_manifest_horizon",
    "scoring_policy_invalid",
    "scoring_validator_mismatch",
]


class OrganicScoringError(ValueError):
    """Score inputs that cannot be trusted to produce an availability result."""

    def __init__(self, code: ScoringRejectionCode) -> None:
        super().__init__(code)
        self.code = code


def _reject(code: ScoringRejectionCode) -> NoReturn:
    raise OrganicScoringError(code)


class ServingCorroboration(StrictFrozenModel):
    """Caller projection of one ``organic-serving-window`` for audit; never scored."""

    endpoint_id: EndpointID
    window_start_epoch: Annotated[int, Field(ge=0, le=(1 << 63) - 1)]
    window_digest_sha256: Digest
    requests: Annotated[int, Field(ge=0, le=(1 << 63) - 1)]
    origin: bool


class EndpointEpochTally(StrictFrozenModel):
    deployment_id: DeploymentID
    endpoint_id: EndpointID
    miner_uid: UID
    miner_hotkey: Hotkey
    attempts: Count
    successes: Count
    application_failures: Count
    miner_failures: Count
    path_failures: Count
    fraudulent_attestations: Count
    disposition: Disposition
    availability_numerator: Count | None
    availability_denominator: Count | None
    corroborating_windows: Annotated[int, Field(ge=0, le=MAX_CORROBORATION_WINDOWS)]
    corroborating_requests: Annotated[int, Field(ge=0, le=(1 << 63) - 1)]


class FraudEvidence(StrictFrozenModel):
    miner_uid: UID
    miner_hotkey: Hotkey
    endpoint_id: EndpointID
    observation_digest_sha256: Digest


class _Tally:
    __slots__ = ("attempts", "counts", "deployment_id", "miner_hotkey", "miner_uid")

    def __init__(self, observation: OrganicProbeObservation) -> None:
        self.deployment_id = observation.deployment_id
        self.miner_uid = observation.miner_uid
        self.miner_hotkey = observation.miner_hotkey
        self.attempts = 0
        self.counts: dict[str, int] = defaultdict(int)


def _derive_epoch(
    observations: Sequence[OrganicProbeObservation],
    corroboration: Sequence[ServingCorroboration],
    *,
    epoch_seconds: int,
    epoch_index: int,
    min_attempts: int,
) -> dict[str, object]:
    """Every derived field of an epoch record, from observations alone."""

    tallies: dict[str, _Tally] = {}
    fraud: list[dict[str, object]] = []
    identities: dict[int, str] = {}
    hotkeys: dict[str, int] = {}
    for item in observations:
        if epoch_index_of(timestamp_epoch_seconds(item.issued_at), epoch_seconds) != epoch_index:
            _reject("scoring_epoch_mismatch")
        if (
            identities.setdefault(item.miner_uid, item.miner_hotkey) != item.miner_hotkey
            or hotkeys.setdefault(item.miner_hotkey, item.miner_uid) != item.miner_uid
        ):
            _reject("scoring_identity_conflict")
        tally = tallies.get(item.endpoint_id)
        if tally is None:
            tally = tallies[item.endpoint_id] = _Tally(item)
        elif (tally.deployment_id, tally.miner_uid, tally.miner_hotkey) != (
            item.deployment_id,
            item.miner_uid,
            item.miner_hotkey,
        ):
            _reject("scoring_identity_conflict")
        tally.attempts += 1
        if tally.attempts > MAX_ATTEMPTS_PER_ENDPOINT:
            _reject("scoring_attempts_overflow")
        tally.counts[item.attribution] += 1
        if item.attestation_status == "fraudulent":
            tally.counts["fraud"] += 1
            fraud.append(
                {
                    "miner_uid": item.miner_uid,
                    "miner_hotkey": item.miner_hotkey,
                    "endpoint_id": item.endpoint_id,
                    "observation_digest_sha256": item.observation_digest_sha256,
                }
            )
    windows: dict[str, list[ServingCorroboration]] = defaultdict(list)
    epoch_start = epoch_index * epoch_seconds
    for window in corroboration:
        if (
            not window.origin
            and window.endpoint_id in tallies
            and epoch_start <= window.window_start_epoch < epoch_start + epoch_seconds
        ):
            windows[window.endpoint_id].append(window)
    sampled = len(tallies)
    path_down = sum(1 for tally in tallies.values() if tally.counts["path"] == tally.attempts)
    common_mode = sampled > 0 and path_down * 2 > sampled
    app_failing: dict[str, int] = defaultdict(int)
    for tally in tallies.values():
        if tally.counts["application"] > 0:
            app_failing[tally.deployment_id] += 1
    inconclusive = sorted(key for key, count in app_failing.items() if count >= 2)
    endpoints: list[dict[str, object]] = []
    eligible = 0
    for endpoint_id in sorted(tallies):
        tally = tallies[endpoint_id]
        disposition: Disposition
        if common_mode:
            disposition = "excluded_common_mode"
        elif tally.deployment_id in inconclusive:
            disposition = "excluded_app_inconclusive"
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
        endpoint_windows = sorted(
            {item.window_digest_sha256: item for item in windows.get(endpoint_id, [])}.values(),
            key=lambda item: item.window_digest_sha256,
        )[:MAX_CORROBORATION_WINDOWS]
        endpoints.append(
            {
                "deployment_id": tally.deployment_id,
                "endpoint_id": endpoint_id,
                "miner_uid": tally.miner_uid,
                "miner_hotkey": tally.miner_hotkey,
                "attempts": tally.attempts,
                "successes": tally.counts["none"],
                "application_failures": tally.counts["application"],
                "miner_failures": tally.counts["miner"],
                "path_failures": tally.counts["path"],
                "fraudulent_attestations": tally.counts["fraud"],
                "disposition": disposition,
                "availability_numerator": numerator,
                "availability_denominator": denominator,
                "corroborating_windows": len(endpoint_windows),
                "corroborating_requests": sum(item.requests for item in endpoint_windows),
            }
        )
    status: EpochStatus
    if common_mode:
        status = "common_mode_unavailable"
    elif eligible == 0:
        status = "no_eligible_endpoints"
    else:
        status = "scored"
    return {
        "epoch_status": status,
        "sampled_endpoint_count": sampled,
        "path_unavailable_endpoint_count": path_down,
        "inconclusive_deployments": inconclusive,
        "endpoints": endpoints,
        "fraud_evidence": sorted(fraud, key=lambda item: str(item["observation_digest_sha256"])),
    }


def _observation_order(item: OrganicProbeObservation) -> tuple[str, str, str]:
    return (item.endpoint_id, item.issued_at, item.probe_nonce)


class OrganicEpochScore(StrictFrozenModel):
    """``organic-epoch-score`` v1: one validator's sealed, deterministic epoch score inputs."""

    contract_schema: Literal["miss.computer/misscomputer-subnet/organic-epoch-score"] = Field(
        alias="schema"
    )
    schema_version: Literal[1]
    purpose: Literal["organic_availability_scoring_v1"]
    network: Literal["finney"]
    netuid: Literal[24]
    validator_hotkey: Hotkey
    epoch_seconds: int = Field(ge=60, le=3_600)
    epoch_index: EpochIndex
    min_attempts: int = Field(ge=1, le=MAX_ATTEMPTS_PER_ENDPOINT)
    manifest_digests: list[Digest] = Field(max_length=1_024)
    epoch_status: EpochStatus
    sampled_endpoint_count: Count
    path_unavailable_endpoint_count: Count
    inconclusive_deployments: list[DeploymentID] = Field(max_length=4_096)
    endpoints: list[EndpointEpochTally] = Field(max_length=MAX_ENDPOINTS)
    fraud_evidence: list[FraudEvidence] = Field(max_length=MAX_OBSERVATIONS)
    corroboration: list[ServingCorroboration] = Field(max_length=MAX_ENDPOINTS)
    observations: list[OrganicProbeObservation] = Field(max_length=MAX_OBSERVATIONS)
    observation_vector_digest_sha256: Digest
    epoch_score_digest_sha256: Digest

    @model_validator(mode="after")
    def canonical_epoch(self) -> Self:
        if self.manifest_digests != sorted(set(self.manifest_digests)):
            raise ValueError("epoch_manifests_not_canonical")
        if {item.manifest_digest_sha256 for item in self.observations} - set(self.manifest_digests):
            raise ValueError("epoch_manifest_unlisted")
        if self.observations != sorted(self.observations, key=_observation_order):
            raise ValueError("epoch_observations_not_canonical")
        nonces = [item.probe_nonce for item in self.observations]
        if len(set(nonces)) != len(nonces):
            raise ValueError("epoch_observation_nonce_duplicate")
        if any(item.validator_hotkey != self.validator_hotkey for item in self.observations):
            raise ValueError("epoch_validator_mismatch")
        keys = [(item.endpoint_id, item.window_digest_sha256) for item in self.corroboration]
        if keys != sorted(set(keys)):
            raise ValueError("epoch_corroboration_not_canonical")
        derived = _derive_epoch(
            self.observations,
            self.corroboration,
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
                raise ValueError(f"epoch_{key}_mismatch")
        vector = [model_document(item) for item in self.observations]
        if self.observation_vector_digest_sha256 != digest(vector):
            raise ValueError("observation_vector_digest_mismatch")
        verify_model_digest(self, "epoch_score_digest_sha256")
        return self


def _manifest_index(
    manifests: Sequence[ActiveAssignmentManifestV2],
) -> dict[str, ActiveAssignmentManifestV2]:
    index: dict[str, ActiveAssignmentManifestV2] = {}
    for manifest in manifests:
        value = revalidate(manifest, ActiveAssignmentManifestV2)
        index[value.manifest_digest_sha256] = value
    return index


def _verify_against_manifest(
    item: OrganicProbeObservation, manifest: ActiveAssignmentManifestV2 | None
) -> None:
    """Bind one observation to the manifest entry it claims and re-verify its evidence."""

    if manifest is None:
        _reject("scoring_manifest_unknown")
    try:
        deployment, replica = find_replica(manifest, item.endpoint_id)
    except ValueError:
        _reject("scoring_observation_unpublished")
    if (
        item.trust_policy_digest_sha256 != manifest.trust_policy_digest_sha256
        or item.deployment_id != deployment.deployment_id
        or item.assignment_digest_sha256 != deployment.assignment_digest_sha256
        or item.generation != replica.generation
        or item.miner_uid != replica.miner_uid
        or item.miner_hotkey != replica.miner_hotkey
        or item.request_method != deployment.health.method
        or item.request_path != deployment.health.path
    ):
        _reject("scoring_observation_unpublished")
    if not organic_manifest_valid_at(manifest, timestamp_epoch_seconds(item.issued_at)):
        _reject("scoring_outside_manifest_horizon")
    if item.attestation is not None:
        verdict = verify_attestation_v2(
            item.attestation,
            deployment,
            replica,
            validator_hotkey=item.validator_hotkey,
            probe_nonce=item.probe_nonce,
            request_method=item.request_method,
            request_path=item.request_path,
            issued_at=item.issued_at,
            response_status=item.response_status or 0,
            response_body_sha256=item.response_body_sha256 or "",
        )
        expected = "fraudulent" if item.attestation_status == "fraudulent" else "verified"
        if verdict != expected:
            _reject("scoring_attestation_unverified")
    status = item.response_status
    in_expected = status is not None and status in deployment.health.expected_statuses
    if (
        (item.outcome == "success" and not in_expected)
        or (item.failure_code == "unexpected_status" and in_expected)
        or (item.failure_code == "marker_missing" and not in_expected)
        or (item.failure_code == "marker_missing" and deployment.health.response_marker is None)
    ):
        _reject("scoring_outcome_inconsistent")


def score_organic_epoch(
    manifests: Sequence[ActiveAssignmentManifestV2],
    observations: Sequence[OrganicProbeObservation],
    *,
    validator_hotkey: str,
    epoch_index: int,
    epoch_seconds: int = DEFAULT_EPOCH_SECONDS,
    min_attempts: int = DEFAULT_MIN_ATTEMPTS,
    corroboration: Sequence[ServingCorroboration] = (),
) -> OrganicEpochScore:
    """Seal one epoch's deterministic score inputs from verified manifests and observations.

    Every observation must name this validator, a supplied manifest, an
    endpoint that manifest published with the same identity and predicate,
    an issue time inside both the epoch and the manifest horizon, and carry an
    attestation that re-verifies exactly as recorded. Any violation refuses
    the epoch rather than scoring it.
    """

    if not 60 <= epoch_seconds <= 3_600 or not 1 <= min_attempts <= MAX_ATTEMPTS_PER_ENDPOINT:
        _reject("scoring_policy_invalid")
    index = _manifest_index(manifests)
    values = [revalidate(item, OrganicProbeObservation) for item in observations]
    if len(values) > MAX_OBSERVATIONS:
        _reject("scoring_attempts_overflow")
    seen_digests: set[str] = set()
    seen_nonces: set[str] = set()
    for item in values:
        if item.validator_hotkey != validator_hotkey:
            _reject("scoring_validator_mismatch")
        if item.observation_digest_sha256 in seen_digests or item.probe_nonce in seen_nonces:
            _reject("scoring_observation_duplicate")
        seen_digests.add(item.observation_digest_sha256)
        seen_nonces.add(item.probe_nonce)
        if epoch_index_of(timestamp_epoch_seconds(item.issued_at), epoch_seconds) != epoch_index:
            _reject("scoring_epoch_mismatch")
        _verify_against_manifest(item, index.get(item.manifest_digest_sha256))
    values.sort(key=_observation_order)
    windows = sorted(
        {
            (item.endpoint_id, item.window_digest_sha256): revalidate(item, ServingCorroboration)
            for item in corroboration
        }.values(),
        key=lambda item: (item.endpoint_id, item.window_digest_sha256),
    )
    derived = _derive_epoch(
        values,
        windows,
        epoch_seconds=epoch_seconds,
        epoch_index=epoch_index,
        min_attempts=min_attempts,
    )
    vector = [model_document(item) for item in values]
    unsigned: dict[str, object] = {
        "schema": EPOCH_SCORE_SCHEMA,
        "schema_version": 1,
        "purpose": SCORING_PURPOSE,
        "network": "finney",
        "netuid": 24,
        "validator_hotkey": validator_hotkey,
        "epoch_seconds": epoch_seconds,
        "epoch_index": epoch_index,
        "min_attempts": min_attempts,
        "manifest_digests": sorted({item.manifest_digest_sha256 for item in values}),
        **derived,
        "corroboration": [model_document(item) for item in windows],
        "observations": vector,
        "observation_vector_digest_sha256": digest(vector),
    }
    return OrganicEpochScore.model_validate(
        {**unsigned, "epoch_score_digest_sha256": digest(unsigned)}
    )


def replay_organic_epoch_score(
    record: OrganicEpochScore, manifests: Sequence[ActiveAssignmentManifestV2]
) -> OrganicEpochScore:
    """Third-party audit: rebuild the record from its own evidence and the public manifests.

    Returns the record when rebuilding its embedded observations against the
    supplied manifests (which re-verifies every miner attestation) reproduces
    it byte-for-byte; raises :class:`OrganicScoringError` otherwise.
    """

    value = revalidate(record, OrganicEpochScore)
    rebuilt = score_organic_epoch(
        manifests,
        value.observations,
        validator_hotkey=value.validator_hotkey,
        epoch_index=value.epoch_index,
        epoch_seconds=value.epoch_seconds,
        min_attempts=value.min_attempts,
        corroboration=value.corroboration,
    )
    if organic_epoch_score_bytes(rebuilt) != organic_epoch_score_bytes(value):
        _reject("scoring_outcome_inconsistent")
    return value


class MinerAvailability(StrictFrozenModel):
    miner_uid: UID
    miner_hotkey: Hotkey
    eligible_endpoint_epochs: Annotated[int, Field(ge=1, le=MAX_ENDPOINTS * MAX_EPOCHS)]
    availability_numerator: Annotated[int, Field(ge=0)]
    availability_denominator: Annotated[int, Field(ge=1)]
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


class OrganicAvailabilityScore(StrictFrozenModel):
    """``organic-availability-score`` v1: per-miner availability over a window of epochs."""

    contract_schema: Literal["miss.computer/misscomputer-subnet/organic-availability-score"] = (
        Field(alias="schema")
    )
    schema_version: Literal[1]
    purpose: Literal["organic_availability_scoring_v1"]
    network: Literal["finney"]
    netuid: Literal[24]
    validator_hotkey: Hotkey
    epoch_seconds: int = Field(ge=60, le=3_600)
    epoch_indexes: list[EpochIndex] = Field(min_length=1, max_length=MAX_EPOCHS)
    epoch_score_digests: list[Digest] = Field(min_length=1, max_length=MAX_EPOCHS)
    abstained_epochs: list[EpochIndex] = Field(max_length=MAX_EPOCHS)
    miners: list[MinerAvailability] = Field(max_length=MAX_ENDPOINTS)
    fraud_evidence: list[FraudEvidence] = Field(max_length=MAX_OBSERVATIONS)
    score_digest_sha256: Digest

    @model_validator(mode="after")
    def canonical_score(self) -> Self:
        if self.epoch_indexes != sorted(set(self.epoch_indexes)) or len(
            self.epoch_score_digests
        ) != len(self.epoch_indexes):
            raise ValueError("score_epochs_not_canonical")
        if not set(self.abstained_epochs) <= set(self.epoch_indexes) or (
            self.abstained_epochs != sorted(set(self.abstained_epochs))
        ):
            raise ValueError("score_abstained_invalid")
        keys = [(item.miner_uid, item.miner_hotkey) for item in self.miners]
        if keys != sorted(set(keys)) or len({key[1] for key in keys}) != len(keys):
            raise ValueError("score_miners_not_canonical")
        verify_model_digest(self, "score_digest_sha256")
        return self


def aggregate_organic_window(epochs: Sequence[OrganicEpochScore]) -> OrganicAvailabilityScore:
    """Mean availability per miner across all of its eligible endpoint-epochs."""

    values = sorted(
        (revalidate(item, OrganicEpochScore) for item in epochs),
        key=lambda item: item.epoch_index,
    )
    if not values or len(values) > MAX_EPOCHS:
        _reject("scoring_epochs_invalid")
    validator = values[0].validator_hotkey
    epoch_seconds = values[0].epoch_seconds
    indexes = [item.epoch_index for item in values]
    if len(set(indexes)) != len(indexes) or any(
        item.epoch_seconds != epoch_seconds for item in values
    ):
        _reject("scoring_epochs_invalid")
    if any(item.validator_hotkey != validator for item in values):
        _reject("scoring_validator_mismatch")
    sums: dict[tuple[int, str], Fraction] = defaultdict(Fraction)
    counts: dict[tuple[int, str], int] = defaultdict(int)
    fraud_counts: dict[str, int] = defaultdict(int)
    identities: dict[int, str] = {}
    hotkeys: dict[str, int] = {}
    fraud: list[FraudEvidence] = []
    for epoch in values:
        for endpoint in epoch.endpoints:
            if (
                identities.setdefault(endpoint.miner_uid, endpoint.miner_hotkey)
                != endpoint.miner_hotkey
                or hotkeys.setdefault(endpoint.miner_hotkey, endpoint.miner_uid)
                != endpoint.miner_uid
            ):
                _reject("scoring_identity_conflict")
            fraud_counts[endpoint.miner_hotkey] += endpoint.fraudulent_attestations
            if endpoint.disposition != "eligible":
                continue
            if endpoint.availability_numerator is None or not endpoint.availability_denominator:
                _reject("scoring_outcome_inconsistent")
            key = (endpoint.miner_uid, endpoint.miner_hotkey)
            sums[key] += Fraction(
                endpoint.availability_numerator, endpoint.availability_denominator
            )
            counts[key] += 1
        fraud.extend(epoch.fraud_evidence)
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
                "fraudulent_attestations": fraud_counts[key[1]],
            }
        )
    unsigned: dict[str, object] = {
        "schema": WINDOW_SCORE_SCHEMA,
        "schema_version": 1,
        "purpose": SCORING_PURPOSE,
        "network": "finney",
        "netuid": 24,
        "validator_hotkey": validator,
        "epoch_seconds": epoch_seconds,
        "epoch_indexes": indexes,
        "epoch_score_digests": [item.epoch_score_digest_sha256 for item in values],
        "abstained_epochs": [item.epoch_index for item in values if item.epoch_status != "scored"],
        "miners": miners,
        "fraud_evidence": [
            model_document(item)
            for item in sorted(fraud, key=lambda item: item.observation_digest_sha256)
        ],
    }
    return OrganicAvailabilityScore.model_validate(
        {**unsigned, "score_digest_sha256": digest(unsigned)}
    )


def organic_weight_rows(score: OrganicAvailabilityScore) -> list[Mapping[str, object]]:
    """Rows for :func:`misscomputer_subnet.weight_plan.build_weight_plan`.

    Only scored miners appear; unscored miners are absent rather than zero.
    The plan builder normalizes and drops zero-availability rows.
    """

    value = revalidate(score, OrganicAvailabilityScore)
    return [
        {
            "miner_hotkey": item.miner_hotkey,
            "weight": float(Fraction(item.availability_numerator, item.availability_denominator)),
        }
        for item in value.miners
    ]


def organic_epoch_score_bytes(value: OrganicEpochScore) -> bytes:
    return model_bytes(value, OrganicEpochScore)


def parse_organic_epoch_score(rendered: bytes) -> OrganicEpochScore:
    return parse_model(rendered, OrganicEpochScore, organic_epoch_score_bytes)


def organic_availability_score_bytes(value: OrganicAvailabilityScore) -> bytes:
    return model_bytes(value, OrganicAvailabilityScore)


def parse_organic_availability_score(rendered: bytes) -> OrganicAvailabilityScore:
    return parse_model(rendered, OrganicAvailabilityScore, organic_availability_score_bytes)
