# SPDX-License-Identifier: AGPL-3.0-only
"""Hidden validator probes of organic app assignments (contract §17.2).

Three contracts meet here. The first two are the canonical documents of
:mod:`misscomputer_subnet.organic_contracts`; this module is the validator's
transport and judgement around them.

``organic-probe-authorization`` v1 (validator → edge)
    An active validator signs ``{endpoint_id, generation, method, path, nonce,
    issued_at}`` (whole-second UTC) with its registered hotkey. The edge
    verifies validator membership, signature, 30 s freshness and one-time
    nonce, routes exactly one probe to the named active endpoint, and strips
    the authorization before the app is contacted. The caller's signer
    produces the sr25519 signature; headers carry base64 canonical documents.

``miner-probe-attestation`` v2 (miner → validator, through the edge)
    The miner agent signs the observed probe with its ticket-bound service key.
    A validator classifies it against the manifest v2 replica, its own
    authorization and the bytes it received.

``organic-probe-observation`` v1 (validator-local evidence)
    One sealed, canonical record per attempted probe: what was asked, what
    came back, which party the outcome is attributable to, and the attestation
    when its signature verified. :mod:`misscomputer_subnet.organic_scoring`
    consumes only these records.

Hidden schedule
---------------
:func:`plan_hidden_probes` derives each epoch's probe times and nonces from a
validator-private 32-byte CSPRNG seed with HMAC-SHA256. The schedule is
deterministic for the holder of the seed (so a validator can replay and audit
its own epoch) and unpredictable to anyone who only sees the public manifest.

Attribution
-----------
``success`` requires the edge upstream marker, a verified attestation v2, a
status in ``expected_statuses`` and, when configured, the response marker in
the first 64 KiB of the body. Failures are attributed as:

* ``path`` — transport failure, certificate pin mismatch, or an edge-generated
  response without the upstream marker (the miner may be unreachable, or the
  edge/tunnel may be down: common-mode detection happens at scoring);
* ``miner`` — the replica answered but the attestation is missing, invalid, or
  fraudulent;
* ``application`` — a verified attestation binds a response that fails the
  customer's own health predicate, or an upstream response exceeds the
  verifiable size bound.

Only a miner-signed attestation whose signature verifies but whose identity,
nonce, request, validator, ticket or artifact binding does not match is
``fraudulent``: that is cryptographically attributable evidence. A wrong
status, a missing marker, unreachability, or content altered in transit is
never fraud (contract §11.3).

This module is pure: no clock, network, file, process, environment, wallet,
chain, or randomness. Signing is delegated to a caller-supplied callable.
``datetime`` is used only to render a caller-supplied instant.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from typing import Annotated, Final, Literal, Self

from pydantic import AfterValidator, Field, StringConstraints, model_validator

from .assignment_probe import (
    MAX_LATENCY_MILLIS,
    MAX_RESPONSE_BYTES_CEILING,
    AssignmentManifestTrustPolicy,
    ProbeResponse,
    ProbeTransportFailure,
    TransportFailureCode,
)
from .contract_codec import (
    StrictFrozenModel,
    canonical_json,
    digest,
    model_bytes,
    model_document,
    parse_model,
    revalidate,
    verify_model_digest,
)
from .organic_contracts import (
    PROBE_ATTESTATION_HEADER,
    UID,
    ActiveAssignmentManifestV2,
    EndpointID,
    HealthPath,
    Hex64,
    Hotkey,
    MinerProbeAttestationV2,
    OrganicAssignedReplica,
    OrganicDeploymentAssignment,
    OrganicHealthProbe,
    OrganicProbeAuthorization,
    PositiveCount,
    RouteLabel,
    format_timestamp,
    organic_probe_message,
    verify_miner_probe_attestation_v2,
)
from .organic_manifest import organic_manifest_effective_expires_at_epoch
from .protocol import _rfc3339nano_instant

PROBE_AUTHORIZATION_SCHEMA: Final = "miss.computer/misscomputer-subnet/organic-probe-authorization"
PROBE_AUTHORIZATION_VALIDITY_NANOS: Final = 30_000_000_000
ATTESTATION_HEADER: Final = PROBE_ATTESTATION_HEADER.lower()
UPSTREAM_RESPONSE_HEADER: Final = "x-miss-edge-upstream"
UPSTREAM_RESPONSE_MARKER: Final = "replica"
OBSERVATION_SCHEMA: Final = "miss.computer/misscomputer-subnet/organic-probe-observation"
#: Clock skew tolerated between the validator's and the miner's clocks when
#: binding an attestation's ``observed_at`` to the authorization window.
ATTESTATION_CLOCK_SKEW_NANOS: Final = 2_000_000_000
MARKER_SEARCH_BYTES: Final = 64 * 1_024
MAX_ATTESTATION_BYTES: Final = 8 * 1_024
MAX_AUTHORIZATION_BYTES: Final = 4 * 1_024
PROBE_SEED_BYTES: Final = 32
DEFAULT_EPOCH_SECONDS: Final = 300
DEFAULT_PROBES_PER_ENDPOINT: Final = 3
_SCHEDULE_DOMAIN: Final = b"miss.computer/misscomputer-subnet/organic-probe-schedule/v1"
_NONCE_DOMAIN: Final = b"miss.computer/misscomputer-subnet/organic-probe-nonce/v1"
_MAX_EPOCH_MILLIS: Final = 253_402_300_799_999


def _seconds_timestamp(value: str) -> str:
    _rfc3339nano_instant(value)
    return value


#: Whole-second UTC timestamp, the canonical probe authorization ``issued_at``.
SecondsTimestamp = Annotated[
    str,
    StringConstraints(pattern=r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"),
    AfterValidator(_seconds_timestamp),
]

AttestationStatus = Literal["fraudulent", "not_presented", "rejected", "verified"]
Attribution = Literal["application", "miner", "none", "path"]
ProbeOutcome = Literal["failure", "success"]
ProbeFailureCode = Literal[
    "attestation_fraud",
    "attestation_invalid",
    "attestation_missing",
    "connection_failed",
    "edge_generated",
    "marker_missing",
    "response_oversized",
    "timeout",
    "tls_certificate_invalid",
    "tls_handshake_failed",
    "tls_pin_mismatch",
    "transport_error",
    "unexpected_status",
]
_ATTRIBUTION: Final[dict[str, Attribution]] = {
    "attestation_fraud": "miner",
    "attestation_invalid": "miner",
    "attestation_missing": "miner",
    "connection_failed": "path",
    "edge_generated": "path",
    "marker_missing": "application",
    "response_oversized": "application",
    "timeout": "path",
    "tls_certificate_invalid": "path",
    "tls_handshake_failed": "path",
    "tls_pin_mismatch": "path",
    "transport_error": "path",
    "unexpected_status": "application",
}


def failure_attribution(code: str | None) -> Attribution:
    """The party a failure code is attributable to; ``none`` for success."""

    return "none" if code is None else _ATTRIBUTION[code]


def build_probe_authorization(
    *,
    validator_hotkey: str,
    endpoint_id: str,
    generation: int,
    method: str,
    path: str,
    nonce: str,
    issued_at_epoch: int,
    sign: Callable[[bytes], bytes],
) -> OrganicProbeAuthorization:
    """Sign one probe request with the caller's sr25519 hotkey signer (64-byte signature).

    ``issued_at`` is whole-second UTC (canonical contract default 14).
    """

    document: dict[str, object] = {
        "schema": PROBE_AUTHORIZATION_SCHEMA,
        "schema_version": 1,
        "validator_hotkey": validator_hotkey,
        "endpoint_id": endpoint_id,
        "generation": generation,
        "method": method,
        "path": path,
        "nonce": nonce,
        "issued_at": format_timestamp(datetime.fromtimestamp(issued_at_epoch, UTC)),
        "signature": "00" * 64,
    }
    unsigned = OrganicProbeAuthorization.model_validate(document)
    signature = sign(organic_probe_message(unsigned))
    if not isinstance(signature, bytes) or len(signature) != 64:
        raise ValueError("probe_authorization_signature_invalid")
    return OrganicProbeAuthorization.model_validate({**document, "signature": signature.hex()})


def probe_authorization_header(authorization: OrganicProbeAuthorization) -> str:
    """Header value: base64 of the canonical authorization document."""

    value = revalidate(authorization, OrganicProbeAuthorization)
    return base64.b64encode(canonical_json(model_document(value))).decode("ascii")


def attestation_v2_header(attestation: MinerProbeAttestationV2) -> str:
    value = revalidate(attestation, MinerProbeAttestationV2)
    return base64.b64encode(canonical_json(model_document(value))).decode("ascii")


def _parse_canonical_header[ModelT: StrictFrozenModel](
    value: str, model_type: type[ModelT], maximum_bytes: int
) -> ModelT:
    if not isinstance(value, str) or not value or len(value) > maximum_bytes * 2:
        raise ValueError("header_invalid")
    try:
        rendered = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("header_invalid") from exc
    if (
        not rendered
        or len(rendered) > maximum_bytes
        or base64.b64encode(rendered).decode("ascii") != value
    ):
        raise ValueError("header_invalid")
    try:
        document = json.loads(rendered.decode("ascii"))
        model = model_type.model_validate(document)
    except (UnicodeDecodeError, ValueError, TypeError, RecursionError) as exc:
        raise ValueError("header_invalid") from exc
    if rendered != canonical_json(model_document(model)):
        raise ValueError("header_invalid")
    return model


def parse_attestation_v2_header(value: str) -> MinerProbeAttestationV2:
    return _parse_canonical_header(value, MinerProbeAttestationV2, MAX_ATTESTATION_BYTES)


def parse_probe_authorization_header(value: str) -> OrganicProbeAuthorization:
    return _parse_canonical_header(value, OrganicProbeAuthorization, MAX_AUTHORIZATION_BYTES)


AttestationVerdict = Literal["content_mismatch", "fraudulent", "signature_invalid", "verified"]


def verify_attestation_v2(
    attestation: MinerProbeAttestationV2,
    deployment: OrganicDeploymentAssignment,
    replica: OrganicAssignedReplica,
    *,
    validator_hotkey: str,
    probe_nonce: str,
    request_method: str,
    request_path: str,
    issued_at: str,
    response_status: int,
    response_body_sha256: str,
) -> AttestationVerdict:
    """Classify one attestation against the manifest replica, the request, and the bytes seen.

    The signature is checked first against the manifest's service key: an
    unverifiable statement is ``signature_invalid`` and attributable to no one.
    A verified statement for another endpoint incarnation, ticket, artifact,
    validator, nonce, or request, or observed outside the authorization window,
    is ``fraudulent``. A verified statement whose status or body digest differs
    from what arrived is ``content_mismatch``: a failed probe, never fraud,
    because an intermediary could have altered the bytes.
    """

    value = revalidate(attestation, MinerProbeAttestationV2)
    try:
        verify_miner_probe_attestation_v2(value, replica.miner_service_public_key)
    except ValueError:
        return "signature_invalid"
    issued_at_nanos = _rfc3339nano_instant(issued_at)
    observed_at = _rfc3339nano_instant(value.observed_at)
    if (
        value.endpoint_id != replica.endpoint_id
        or value.generation != replica.generation
        or value.ticket_digest != replica.ticket_digest
        or value.artifact_digest != deployment.artifact_digest
        or value.validator_hotkey != validator_hotkey
        or value.probe_nonce != probe_nonce
        or value.request_method != request_method
        or value.request_path != request_path
        or observed_at < issued_at_nanos - ATTESTATION_CLOCK_SKEW_NANOS
        or observed_at
        > issued_at_nanos + PROBE_AUTHORIZATION_VALIDITY_NANOS + ATTESTATION_CLOCK_SKEW_NANOS
    ):
        return "fraudulent"
    if (
        value.response_status != response_status
        or value.response_body_sha256 != response_body_sha256
    ):
        return "content_mismatch"
    return "verified"


class OrganicProbeObservation(StrictFrozenModel):
    """One sealed attempted probe of one published organic endpoint incarnation."""

    contract_schema: Literal["miss.computer/misscomputer-subnet/organic-probe-observation"] = Field(
        alias="schema"
    )
    schema_version: Literal[1]
    validator_hotkey: Hotkey
    manifest_digest_sha256: Hex64
    trust_policy_digest_sha256: Hex64
    deployment_id: RouteLabel
    assignment_digest_sha256: Hex64
    endpoint_id: EndpointID
    generation: PositiveCount
    miner_uid: UID
    miner_hotkey: Hotkey
    probe_nonce: Hex64
    issued_at: SecondsTimestamp
    request_method: Literal["GET", "HEAD"]
    request_path: HealthPath
    latency_millis: int = Field(ge=0, le=MAX_LATENCY_MILLIS)
    outcome: ProbeOutcome
    failure_code: ProbeFailureCode | None
    attribution: Attribution
    upstream_marker: bool
    response_status: int | None = Field(ge=100, le=599)
    response_bytes: int = Field(ge=0, le=MAX_RESPONSE_BYTES_CEILING + 1)
    response_body_sha256: Hex64 | None
    tls_leaf_certificate_sha256: Hex64 | None
    attestation_status: AttestationStatus
    attestation: MinerProbeAttestationV2 | None
    observation_digest_sha256: Hex64

    @model_validator(mode="after")
    def canonical_observation(self) -> Self:
        if (self.outcome == "success") != (self.failure_code is None):
            raise ValueError("observation_outcome_invalid")
        if self.attribution != failure_attribution(self.failure_code):
            raise ValueError("observation_attribution_invalid")
        if self.outcome == "success" and (
            not self.upstream_marker
            or self.response_status is None
            or self.response_body_sha256 is None
            or self.attestation_status != "verified"
        ):
            raise ValueError("observation_success_invalid")
        if (self.attestation_status in {"fraudulent", "verified"}) != (
            self.attestation is not None
        ):
            raise ValueError("observation_attestation_invalid")
        if (self.attestation_status == "fraudulent") != (self.failure_code == "attestation_fraud"):
            raise ValueError("observation_fraud_invalid")
        if (
            self.attestation_status == "verified"
            and self.attestation is not None
            and (
                self.attestation.endpoint_id != self.endpoint_id
                or self.attestation.probe_nonce != self.probe_nonce
                or self.attestation.validator_hotkey != self.validator_hotkey
                or self.attestation.response_status != self.response_status
                or self.attestation.response_body_sha256 != self.response_body_sha256
            )
        ):
            raise ValueError("observation_attestation_binding_invalid")
        if self.attribution == "application" and not self.upstream_marker:
            raise ValueError("observation_attribution_invalid")
        verify_model_digest(self, "observation_digest_sha256")
        return self


def _header_values(headers: Sequence[tuple[str, str]], name: str) -> list[str]:
    return [value for key, value in headers if key.lower() == name]


def find_replica(
    manifest: ActiveAssignmentManifestV2, endpoint_id: str
) -> tuple[OrganicDeploymentAssignment, OrganicAssignedReplica]:
    """The unique deployment and replica publishing ``endpoint_id``."""

    for deployment in manifest.deployments:
        for replica in deployment.replicas:
            if replica.endpoint_id == endpoint_id:
                return deployment, replica
    raise ValueError("endpoint_unpublished")


def predicate_satisfied(health: OrganicHealthProbe, status: int, body: bytes) -> str | None:
    """``None`` when the response meets the predicate, otherwise the failure code."""

    if status not in health.expected_statuses:
        return "unexpected_status"
    if health.response_marker is not None and (
        health.response_marker.encode("ascii") not in body[:MARKER_SEARCH_BYTES]
    ):
        return "marker_missing"
    return None


def seal_observation(document: dict[str, object]) -> OrganicProbeObservation:
    return OrganicProbeObservation.model_validate(
        {**document, "observation_digest_sha256": digest(document)}
    )


def evaluate_organic_probe(
    manifest: ActiveAssignmentManifestV2,
    trust_policy: AssignmentManifestTrustPolicy,
    authorization: OrganicProbeAuthorization,
    result: ProbeResponse | ProbeTransportFailure,
) -> OrganicProbeObservation:
    """Judge one observed probe against the manifest v2 entry it targeted."""

    value = revalidate(manifest, ActiveAssignmentManifestV2)
    policy = revalidate(trust_policy, AssignmentManifestTrustPolicy)
    request = revalidate(authorization, OrganicProbeAuthorization)
    if value.trust_policy_digest_sha256 != policy.trust_policy_digest_sha256:
        raise ValueError("trust_policy_mismatch")
    deployment, replica = find_replica(value, request.endpoint_id)
    if (
        request.generation != replica.generation
        or request.method != deployment.health.method
        or request.path != deployment.health.path
    ):
        raise ValueError("authorization_request_mismatch")
    document: dict[str, object] = {
        "schema": OBSERVATION_SCHEMA,
        "schema_version": 1,
        "validator_hotkey": request.validator_hotkey,
        "manifest_digest_sha256": value.manifest_digest_sha256,
        "trust_policy_digest_sha256": policy.trust_policy_digest_sha256,
        "deployment_id": deployment.deployment_id,
        "assignment_digest_sha256": deployment.assignment_digest_sha256,
        "endpoint_id": replica.endpoint_id,
        "generation": replica.generation,
        "miner_uid": replica.miner_uid,
        "miner_hotkey": replica.miner_hotkey,
        "probe_nonce": request.nonce,
        "issued_at": request.issued_at,
        "request_method": request.method,
        "request_path": request.path,
        "latency_millis": min(max(result.latency_millis, 0), MAX_LATENCY_MILLIS),
        "outcome": "failure",
        "failure_code": None,
        "attribution": "none",
        "upstream_marker": False,
        "response_status": None,
        "response_bytes": 0,
        "response_body_sha256": None,
        "tls_leaf_certificate_sha256": result.tls_leaf_certificate_sha256,
        "attestation_status": "not_presented",
        "attestation": None,
    }

    def fail(code: ProbeFailureCode) -> OrganicProbeObservation:
        document["failure_code"] = code
        document["attribution"] = failure_attribution(code)
        return seal_observation(document)

    if result.latency_millis > policy.probe_timeout_millis:
        return fail("timeout")
    if isinstance(result, ProbeTransportFailure):
        transport_code: TransportFailureCode = result.code
        document["response_status"] = result.response_status
        if transport_code == "response_oversized":
            # Without headers the transport cannot prove an upstream response.
            return fail("transport_error")
        return fail("transport_error" if transport_code == "timeout" else transport_code)
    if not 100 <= result.status <= 599:
        return fail("transport_error")
    document["response_status"] = result.status
    document["response_bytes"] = min(len(result.body), MAX_RESPONSE_BYTES_CEILING + 1)
    body_digest = hashlib.sha256(result.body).hexdigest()
    document["response_body_sha256"] = body_digest
    pins = policy.pinned_edge_leaf_certificate_sha256
    if pins and result.tls_leaf_certificate_sha256 not in pins:
        return fail("tls_pin_mismatch")
    if _header_values(result.headers, UPSTREAM_RESPONSE_HEADER) != [UPSTREAM_RESPONSE_MARKER]:
        return fail("edge_generated")
    document["upstream_marker"] = True
    if len(result.body) > policy.max_response_bytes:
        return fail("response_oversized")
    presented = _header_values(result.headers, ATTESTATION_HEADER)
    if not presented:
        return fail("attestation_missing")
    try:
        if len(presented) != 1:
            raise ValueError("attestation_header_repeated")
        attestation = parse_attestation_v2_header(presented[0])
    except ValueError:
        document["attestation_status"] = "rejected"
        return fail("attestation_invalid")
    verdict = verify_attestation_v2(
        attestation,
        deployment,
        replica,
        validator_hotkey=request.validator_hotkey,
        probe_nonce=request.nonce,
        request_method=request.method,
        request_path=request.path,
        issued_at=request.issued_at,
        response_status=result.status,
        response_body_sha256=body_digest,
    )
    if verdict == "fraudulent":
        document["attestation_status"] = "fraudulent"
        document["attestation"] = model_document(attestation)
        return fail("attestation_fraud")
    if verdict != "verified":
        document["attestation_status"] = "rejected"
        return fail("attestation_invalid")
    document["attestation_status"] = "verified"
    document["attestation"] = model_document(attestation)
    predicate_failure = predicate_satisfied(deployment.health, result.status, result.body)
    if predicate_failure == "unexpected_status":
        return fail("unexpected_status")
    if predicate_failure == "marker_missing":
        return fail("marker_missing")
    document["outcome"] = "success"
    return seal_observation(document)


class PlannedProbe(StrictFrozenModel):
    """One privately scheduled probe: when to fire, what to ask, and its one-time nonce."""

    deployment_id: RouteLabel
    endpoint_id: EndpointID
    generation: PositiveCount
    method: Literal["GET", "HEAD"]
    path: HealthPath
    probe_index: int = Field(ge=0, le=63)
    fire_at_millis: int = Field(ge=0, le=_MAX_EPOCH_MILLIS)
    nonce: Hex64


#: ``_rfc3339nano_instant`` counts from its own civil origin, not 1970.
_UNIX_EPOCH_NANOS: Final = _rfc3339nano_instant("1970-01-01T00:00:00Z")


def timestamp_epoch_seconds(value: str) -> int:
    """Unix seconds of one canonical UTC timestamp (fraction truncated)."""

    return (_rfc3339nano_instant(value) - _UNIX_EPOCH_NANOS) // 1_000_000_000


def epoch_index_of(unix_seconds: int, epoch_seconds: int = DEFAULT_EPOCH_SECONDS) -> int:
    return unix_seconds // epoch_seconds


def plan_hidden_probes(
    *,
    seed: bytes,
    validator_hotkey: str,
    manifest: ActiveAssignmentManifestV2,
    epoch_index: int,
    epoch_seconds: int = DEFAULT_EPOCH_SECONDS,
    probes_per_endpoint: int = DEFAULT_PROBES_PER_ENDPOINT,
) -> list[PlannedProbe]:
    """Derive one epoch's hidden probe schedule for every published endpoint.

    Each endpoint gets ``probes_per_endpoint`` probes, one uniformly placed in
    each equal slice of the epoch so two lost probes cannot leave an endpoint
    under-sampled by chance. Times and nonces are HMAC-SHA256 outputs keyed by
    the validator-private ``seed`` over the manifest digest, epoch, endpoint
    incarnation and probe index, so they are reproducible by the seed holder
    and unpredictable from the public manifest. Probes that would fire outside
    the manifest's validity horizon are omitted. The result is sorted by fire
    time, then endpoint, then index.
    """

    if not isinstance(seed, bytes) or len(seed) != PROBE_SEED_BYTES:
        raise ValueError("probe_seed_invalid")
    if not 60 <= epoch_seconds <= 3_600 or not 1 <= probes_per_endpoint <= 16:
        raise ValueError("probe_schedule_invalid")
    if isinstance(epoch_index, bool) or not isinstance(epoch_index, int) or epoch_index < 0:
        raise ValueError("epoch_index_invalid")
    value = revalidate(manifest, ActiveAssignmentManifestV2)
    epoch_millis = epoch_seconds * 1_000
    epoch_start = epoch_index * epoch_millis
    slot = epoch_millis // probes_per_endpoint
    horizon_start = value.issued_at_epoch * 1_000
    horizon_end = organic_manifest_effective_expires_at_epoch(value) * 1_000
    planned: list[PlannedProbe] = []
    for deployment in value.deployments:
        for replica in deployment.replicas:
            for index in range(probes_per_endpoint):
                context = canonical_json(
                    {
                        "epoch_index": epoch_index,
                        "epoch_seconds": epoch_seconds,
                        "endpoint_id": replica.endpoint_id,
                        "generation": replica.generation,
                        "manifest_digest_sha256": value.manifest_digest_sha256,
                        "probe_index": index,
                        "validator_hotkey": validator_hotkey,
                    }
                )
                timing = hmac.new(seed, _SCHEDULE_DOMAIN + b"\x00" + context, "sha256").digest()
                nonce = hmac.new(seed, _NONCE_DOMAIN + b"\x00" + context, "sha256").hexdigest()
                fire_at = epoch_start + index * slot + int.from_bytes(timing[:8], "big") % slot
                if not horizon_start <= fire_at < horizon_end:
                    continue
                planned.append(
                    PlannedProbe(
                        deployment_id=deployment.deployment_id,
                        endpoint_id=replica.endpoint_id,
                        generation=replica.generation,
                        method=deployment.health.method,
                        path=deployment.health.path,
                        probe_index=index,
                        fire_at_millis=fire_at,
                        nonce=nonce,
                    )
                )
    planned.sort(key=lambda item: (item.fire_at_millis, item.endpoint_id, item.probe_index))
    return planned


def organic_probe_observation_bytes(value: OrganicProbeObservation) -> bytes:
    return model_bytes(value, OrganicProbeObservation)


def parse_organic_probe_observation(rendered: bytes) -> OrganicProbeObservation:
    return parse_model(
        rendered,
        OrganicProbeObservation,
        organic_probe_observation_bytes,
        maximum_bytes=64 * 1_024,
    )
