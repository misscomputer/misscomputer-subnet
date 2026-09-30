# SPDX-License-Identifier: AGPL-3.0-only
"""Targeted, cache-bypassing validator probes of static endpoint incarnations.

Every request here is addressed to one endpoint incarnation through the public
route host with a fresh ``organic-probe-authorization`` v1 (validator hotkey,
one-time nonce, no query), and is judged against a
:class:`~misscomputer_subnet.static_index.VerifiedStaticIndex`: the validator
checks the bytes against the release-signed expected digest, never against the
miner's attestation alone. The miner's ``miner-probe-attestation`` v2 still
binds the response to the miner; for a static incarnation its
``artifact_digest`` is ``sha256:<site_digest>`` and its ``ticket_digest`` is the
static ticket digest the manifest v3 publishes.

Two plans share one evaluator:

* :func:`plan_static_admission_crawl` requests **every** indexed response of
  one incarnation (plus the navigation-fallback and missing-asset 404 vectors)
  in an unpredictable order, under an explicit request/byte budget. A plan
  that does not fit the budget is refused as a whole: bounded failure means no
  admission, never partial admission.
* :func:`plan_static_hidden_probes` samples each epoch within the 1 MiB
  per-probe ceiling at seed-derived times, choosing seed-derived paths,
  including synthetic never-published paths, so neither time nor target is
  predictable from the public manifest. :func:`static_probe_coverage` states
  which responses the ceiling leaves to admission and edge verification.

Attribution
-----------
``path`` (never the miner): transport failures, certificate-pin mismatch, an
edge-generated response, an oversized transfer without headers, a correctly
signed attestation for a *different* probe of the same incarnation (a replay
or cache hit), or bytes that differ from both the expected and the attested
ones while the attestation names the expected bytes (altered in transit).

``miner``: a missing or unverifiable attestation; a verified attestation for
this very probe whose status or body differs from the release-signed
expectation (a *verified content fault*, flagged ``quarantine_candidate``);
wrong normative headers under a verified attestation; and, as the only
``attestation_fraud``, a verified attestation for this probe's nonce that
names another incarnation, ticket, site, or request. Wrong bytes alone are
never fraud; trust-zero decisions stay with scoring.

This module is pure: no clock, network, file, process, environment, wallet,
chain, or randomness. Signing is delegated to the caller.
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Sequence
from typing import Final, Literal, Self

from pydantic import Field, model_validator

from .assignment_probe import (
    MAX_LATENCY_MILLIS,
    MAX_RESPONSE_BYTES_CEILING,
    ProbeResponse,
    ProbeTransportFailure,
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
    UID,
    DNSLabel,
    EndpointID,
    HealthPath,
    Hex64,
    Hotkey,
    MinerProbeAttestationV2,
    OrganicProbeAuthorization,
    PositiveCount,
    verify_miner_probe_attestation_v2,
)
from .organic_probe import (
    ATTESTATION_CLOCK_SKEW_NANOS,
    ATTESTATION_HEADER,
    PROBE_AUTHORIZATION_VALIDITY_NANOS,
    PROBE_SEED_BYTES,
    UPSTREAM_RESPONSE_HEADER,
    UPSTREAM_RESPONSE_MARKER,
    SecondsTimestamp,
    parse_attestation_v2_header,
)
from .protocol import _rfc3339nano_instant
from .static_index import (
    MAX_FILE_BYTES,
    MAX_FILES,
    MAX_TOTAL_BYTES,
    REQUIRED_CACHE_CONTROL,
    REQUIRED_NOSNIFF,
    ExpectedStaticResponse,
    StaticEndpointTarget,
    VerifiedStaticIndex,
    expected_static_response,
)

STATIC_OBSERVATION_SCHEMA: Final = "miss.computer/misscomputer-subnet/static-probe-observation"
#: Hidden probes stay within the public validator per-probe body ceiling.
HIDDEN_PROBE_CEILING_BYTES: Final = MAX_RESPONSE_BYTES_CEILING
#: Admission may carry any v1-legal response.
ADMISSION_RESPONSE_CEILING_BYTES: Final = MAX_FILE_BYTES
#: Synthetic vectors added to every admission crawl (fallback/404, HEAD of ``/``).
ADMISSION_SYNTHETIC_REQUESTS: Final = 3
MAX_ADMISSION_REQUESTS: Final = 2 * MAX_FILES + ADMISSION_SYNTHETIC_REQUESTS
_ADMISSION_DOMAIN: Final = b"miss.computer/misscomputer-subnet/static-admission-crawl/v1"
_HIDDEN_DOMAIN: Final = b"miss.computer/misscomputer-subnet/static-hidden-probe/v1"
_MAX_EPOCH_MILLIS: Final = 253_402_300_799_999

ProbeKind = Literal["admission", "hidden"]
Attribution = Literal["miner", "none", "path"]
AttestationStatus = Literal["fraudulent", "not_presented", "rejected", "replayed", "verified"]
StaticFailureCode = Literal[
    "attestation_fraud",
    "attestation_invalid",
    "attestation_missing",
    "body_mismatch",
    "cache_replay",
    "connection_failed",
    "content_altered_in_transit",
    "edge_generated",
    "header_mismatch",
    "response_oversized",
    "status_mismatch",
    "timeout",
    "tls_certificate_invalid",
    "tls_handshake_failed",
    "tls_pin_mismatch",
    "transport_error",
]
_ATTRIBUTION: Final[dict[str, Attribution]] = {
    "attestation_fraud": "miner",
    "attestation_invalid": "miner",
    "attestation_missing": "miner",
    "body_mismatch": "miner",
    "cache_replay": "path",
    "connection_failed": "path",
    "content_altered_in_transit": "path",
    "edge_generated": "path",
    "header_mismatch": "miner",
    "response_oversized": "path",
    "status_mismatch": "miner",
    "timeout": "path",
    "tls_certificate_invalid": "path",
    "tls_handshake_failed": "path",
    "tls_pin_mismatch": "path",
    "transport_error": "path",
}
#: Faults a verified attestation for this very probe proves the miner served.
_VERIFIED_CONTENT_FAULTS: Final = frozenset({"body_mismatch", "status_mismatch"})


def static_failure_attribution(code: str | None) -> Attribution:
    return "none" if code is None else _ATTRIBUTION[code]


def static_attestation_artifact_digest(site_digest: str) -> str:
    """The ``artifact_digest`` a static incarnation's attestation v2 must bind."""

    return f"sha256:{site_digest}"


class StaticProbeObservation(StrictFrozenModel):
    """One sealed attempted request to one static endpoint incarnation."""

    contract_schema: Literal["miss.computer/misscomputer-subnet/static-probe-observation"] = Field(
        alias="schema"
    )
    schema_version: Literal[1]
    probe_kind: Literal["admission", "hidden"]
    validator_hotkey: Hotkey
    deployment_id: DNSLabel
    site_digest: Hex64
    release_digest_sha256: Hex64
    static_trust_policy_digest_sha256: Hex64
    endpoint_id: EndpointID
    generation: PositiveCount
    miner_uid: UID
    miner_hotkey: Hotkey
    probe_nonce: Hex64
    issued_at: SecondsTimestamp
    request_method: Literal["GET", "HEAD"]
    request_path: HealthPath
    expected_kind: Literal["directory_index", "file", "navigation_fallback", "not_found"]
    expected_status: int = Field(ge=100, le=599)
    expected_content_length: int = Field(ge=0, le=MAX_FILE_BYTES)
    expected_body_sha256: Hex64
    latency_millis: int = Field(ge=0, le=MAX_LATENCY_MILLIS)
    outcome: Literal["failure", "success"]
    failure_code: StaticFailureCode | None
    attribution: Attribution
    quarantine_candidate: bool
    upstream_marker: bool
    response_status: int | None = Field(ge=100, le=599)
    response_bytes: int = Field(ge=0, le=MAX_FILE_BYTES + 1)
    response_body_sha256: Hex64 | None
    tls_leaf_certificate_sha256: Hex64 | None
    attestation_status: AttestationStatus
    attestation: MinerProbeAttestationV2 | None
    observation_digest_sha256: Hex64

    @model_validator(mode="after")
    def canonical_observation(self) -> Self:
        if (self.outcome == "success") != (self.failure_code is None):
            raise ValueError("observation_outcome_invalid")
        if self.attribution != static_failure_attribution(self.failure_code):
            raise ValueError("observation_attribution_invalid")
        if self.quarantine_candidate != (self.failure_code in _VERIFIED_CONTENT_FAULTS):
            raise ValueError("observation_quarantine_invalid")
        if self.outcome == "success" and (
            not self.upstream_marker
            or self.response_status != self.expected_status
            or self.response_body_sha256 != self.expected_body_sha256
            or self.attestation_status != "verified"
        ):
            raise ValueError("observation_success_invalid")
        if (self.attestation_status in {"fraudulent", "replayed", "verified"}) != (
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
                or self.attestation.response_status != self.response_status
                or self.attestation.response_body_sha256 != self.response_body_sha256
            )
        ):
            raise ValueError("observation_attestation_binding_invalid")
        if self.attribution == "miner" and not self.upstream_marker:
            raise ValueError("observation_attribution_invalid")
        verify_model_digest(self, "observation_digest_sha256")
        return self


def _header_values(headers: Sequence[tuple[str, str]], name: str) -> list[str]:
    return [value for key, value in headers if key.lower() == name]


def _headers_conform(headers: Sequence[tuple[str, str]], expected: ExpectedStaticResponse) -> bool:
    """The normative v1 header set: exact type/length, nosniff, no-store, identity only."""

    if (
        _header_values(headers, "content-type") != [expected.content_type]
        or _header_values(headers, "content-length") != [str(expected.content_length)]
        or _header_values(headers, "x-content-type-options") != [REQUIRED_NOSNIFF]
        or _header_values(headers, "cache-control") != [REQUIRED_CACHE_CONTROL]
    ):
        return False
    forbidden = ("content-encoding", "content-range", "location", "set-cookie", "transfer-encoding")
    return not any(_header_values(headers, name) for name in forbidden)


def find_static_endpoint(index: VerifiedStaticIndex, endpoint_id: str) -> StaticEndpointTarget:
    for endpoint in index.target.endpoints:
        if endpoint.endpoint_id == endpoint_id:
            return endpoint
    raise ValueError("endpoint_unpublished")


def _seal(document: dict[str, object]) -> StaticProbeObservation:
    return StaticProbeObservation.model_validate(
        {**document, "observation_digest_sha256": digest(document)}
    )


def evaluate_static_probe(
    index: VerifiedStaticIndex,
    authorization: OrganicProbeAuthorization,
    result: ProbeResponse | ProbeTransportFailure,
    *,
    probe_kind: ProbeKind,
    timeout_millis: int,
    pinned_edge_leaf_certificate_sha256: Sequence[str] = (),
) -> StaticProbeObservation:
    """Judge one observed static response against the release-signed expectation."""

    request = revalidate(authorization, OrganicProbeAuthorization)
    endpoint = find_static_endpoint(index, request.endpoint_id)
    if request.generation != endpoint.generation:
        raise ValueError("authorization_request_mismatch")
    expected = expected_static_response(index, request.method, request.path)
    site = index.target.site_digest
    document: dict[str, object] = {
        "schema": STATIC_OBSERVATION_SCHEMA,
        "schema_version": 1,
        "probe_kind": probe_kind,
        "validator_hotkey": request.validator_hotkey,
        "deployment_id": index.target.deployment_id,
        "site_digest": site,
        "release_digest_sha256": index.release_digest_sha256,
        "static_trust_policy_digest_sha256": index.trust_policy_digest_sha256,
        "endpoint_id": endpoint.endpoint_id,
        "generation": endpoint.generation,
        "miner_uid": endpoint.miner_uid,
        "miner_hotkey": endpoint.miner_hotkey,
        "probe_nonce": request.nonce,
        "issued_at": request.issued_at,
        "request_method": request.method,
        "request_path": request.path,
        "expected_kind": expected.kind,
        "expected_status": expected.status,
        "expected_content_length": expected.content_length,
        "expected_body_sha256": expected.body_sha256,
        "latency_millis": min(max(result.latency_millis, 0), MAX_LATENCY_MILLIS),
        "outcome": "failure",
        "failure_code": None,
        "attribution": "none",
        "quarantine_candidate": False,
        "upstream_marker": False,
        "response_status": None,
        "response_bytes": 0,
        "response_body_sha256": None,
        "tls_leaf_certificate_sha256": result.tls_leaf_certificate_sha256,
        "attestation_status": "not_presented",
        "attestation": None,
    }

    def fail(code: StaticFailureCode) -> StaticProbeObservation:
        document["failure_code"] = code
        document["attribution"] = static_failure_attribution(code)
        document["quarantine_candidate"] = code in _VERIFIED_CONTENT_FAULTS
        return _seal(document)

    if result.latency_millis > timeout_millis:
        return fail("timeout")
    if isinstance(result, ProbeTransportFailure):
        document["response_status"] = result.response_status
        return fail("transport_error" if result.code == "timeout" else result.code)
    if not 100 <= result.status <= 599:
        return fail("transport_error")
    body_digest = hashlib.sha256(result.body).hexdigest()
    document["response_status"] = result.status
    document["response_bytes"] = min(len(result.body), MAX_FILE_BYTES + 1)
    document["response_body_sha256"] = body_digest
    pins = tuple(pinned_edge_leaf_certificate_sha256)
    if pins and result.tls_leaf_certificate_sha256 not in pins:
        return fail("tls_pin_mismatch")
    if _header_values(result.headers, UPSTREAM_RESPONSE_HEADER) != [UPSTREAM_RESPONSE_MARKER]:
        return fail("edge_generated")
    document["upstream_marker"] = True
    presented = _header_values(result.headers, ATTESTATION_HEADER)
    if not presented:
        return fail("attestation_missing")
    try:
        if len(presented) != 1:
            raise ValueError("attestation_header_repeated")
        attestation = parse_attestation_v2_header(presented[0])
        verify_miner_probe_attestation_v2(attestation, endpoint.miner_service_public_key)
    except ValueError:
        document["attestation_status"] = "rejected"
        return fail("attestation_invalid")
    incarnation_bound = (
        attestation.endpoint_id == endpoint.endpoint_id
        and attestation.generation == endpoint.generation
        and attestation.ticket_digest == endpoint.ticket_digest
        and attestation.artifact_digest == static_attestation_artifact_digest(site)
    )
    if attestation.probe_nonce != request.nonce:
        if incarnation_bound:
            # The miner signed this for some other probe; something on the
            # path replayed or cached it. Never the miner's fault.
            document["attestation_status"] = "replayed"
            document["attestation"] = model_document(attestation)
            return fail("cache_replay")
        document["attestation_status"] = "rejected"
        return fail("attestation_invalid")
    if (
        not incarnation_bound
        or attestation.validator_hotkey != request.validator_hotkey
        or attestation.request_method != request.method
        or attestation.request_path != request.path
    ):
        document["attestation_status"] = "fraudulent"
        document["attestation"] = model_document(attestation)
        return fail("attestation_fraud")
    issued = _rfc3339nano_instant(request.issued_at)
    observed = _rfc3339nano_instant(attestation.observed_at)
    if not (
        issued - ATTESTATION_CLOCK_SKEW_NANOS
        <= observed
        <= issued + PROBE_AUTHORIZATION_VALIDITY_NANOS + ATTESTATION_CLOCK_SKEW_NANOS
    ):
        document["attestation_status"] = "rejected"
        return fail("attestation_invalid")
    received_expected = result.status == expected.status and body_digest == expected.body_sha256
    if (
        attestation.response_status != result.status
        or attestation.response_body_sha256 != body_digest
    ):
        document["attestation_status"] = "rejected"
        if not received_expected and (
            attestation.response_status == expected.status
            and attestation.response_body_sha256 == expected.body_sha256
        ):
            return fail("content_altered_in_transit")
        return fail("attestation_invalid")
    document["attestation_status"] = "verified"
    document["attestation"] = model_document(attestation)
    if result.status != expected.status:
        return fail("status_mismatch")
    if body_digest != expected.body_sha256:
        return fail("body_mismatch")
    if not _headers_conform(result.headers, expected):
        return fail("header_mismatch")
    document["outcome"] = "success"
    return _seal(document)


# --------------------------------------------------------------------------
# Planning
# --------------------------------------------------------------------------


class PlannedStaticProbe(StrictFrozenModel):
    """One planned targeted request: incarnation, method, path, one-time nonce."""

    probe_kind: Literal["admission", "hidden"]
    deployment_id: DNSLabel
    site_digest: Hex64
    endpoint_id: EndpointID
    generation: PositiveCount
    method: Literal["GET", "HEAD"]
    path: HealthPath
    expected_kind: Literal["directory_index", "file", "navigation_fallback", "not_found"]
    expected_content_length: int = Field(ge=0, le=MAX_FILE_BYTES)
    #: Position within the crawl, or the probe's slice within the epoch.
    probe_index: int = Field(ge=0, le=MAX_ADMISSION_REQUESTS)
    #: Unix milliseconds for hidden probes; ``None`` for admission requests.
    fire_at_millis: int | None = Field(ge=0, le=_MAX_EPOCH_MILLIS)
    nonce: Hex64


class StaticCrawlBudget(StrictFrozenModel):
    """Explicit bounds on one admission crawl of one incarnation."""

    max_requests: int = Field(ge=1, le=MAX_ADMISSION_REQUESTS)
    max_total_bytes: int = Field(ge=1, le=2 * MAX_TOTAL_BYTES)
    max_response_bytes: int = Field(ge=1, le=ADMISSION_RESPONSE_CEILING_BYTES)
    request_timeout_millis: int = Field(ge=100, le=60_000)
    max_duration_millis: int = Field(ge=1_000, le=3_600_000)
    #: Incarnations crawled at once; the integration contract allows at most 3.
    max_concurrent_endpoints: int = Field(ge=1, le=3)


class StaticCrawlRefusal(StrictFrozenModel):
    """An admission crawl that cannot run within its budget: no admission."""

    deployment_id: DNSLabel
    endpoint_id: EndpointID
    code: Literal["admission_budget_exceeded"]
    required_requests: int = Field(ge=0)
    required_bytes: int = Field(ge=0)


def _hmac(seed: bytes, domain: bytes, context: dict[str, object]) -> bytes:
    return hmac.new(seed, domain + b"\x00" + canonical_json(context), "sha256").digest()


def _validate_seed(seed: bytes) -> None:
    if not isinstance(seed, bytes) or len(seed) != PROBE_SEED_BYTES:
        raise ValueError("probe_seed_invalid")


def _synthetic_path(index: VerifiedStaticIndex, token: bytes, suffix: str) -> str | None:
    """A never-published path; ``None`` on the (negligible) chance it is published."""

    path = f"/{token[:12].hex()}{suffix}"
    return None if path in index.routes else path


def _planned(
    index: VerifiedStaticIndex,
    endpoint: StaticEndpointTarget,
    *,
    probe_kind: ProbeKind,
    method: Literal["GET", "HEAD"],
    path: str,
    probe_index: int,
    fire_at_millis: int | None,
    nonce: str,
) -> PlannedStaticProbe:
    expected = expected_static_response(index, method, path)
    return PlannedStaticProbe(
        probe_kind=probe_kind,
        deployment_id=index.target.deployment_id,
        site_digest=index.target.site_digest,
        endpoint_id=endpoint.endpoint_id,
        generation=endpoint.generation,
        method=method,
        path=path,
        expected_kind=expected.kind,
        expected_content_length=expected.content_length,
        probe_index=probe_index,
        fire_at_millis=fire_at_millis,
        nonce=nonce,
    )


def plan_static_admission_crawl(
    index: VerifiedStaticIndex,
    endpoint_id: str,
    budget: StaticCrawlBudget,
    *,
    seed: bytes,
    validator_hotkey: str,
    crawl_id: int,
) -> list[PlannedStaticProbe] | StaticCrawlRefusal:
    """Every indexed response of one incarnation, or a refusal; never a subset.

    The crawl requests each manifest-listed GET response, a HEAD of ``/``, a
    never-published navigation path (fallback or 404) and a never-published
    asset path (always 404), in a seed-derived order with seed-derived nonces.
    ``crawl_id`` distinguishes repeated admissions of the same incarnation.
    """

    _validate_seed(seed)
    budget = revalidate(budget, StaticCrawlBudget)
    endpoint = find_static_endpoint(index, endpoint_id)
    base: dict[str, object] = {
        "crawl_id": crawl_id,
        "endpoint_id": endpoint.endpoint_id,
        "generation": endpoint.generation,
        "site_digest": index.target.site_digest,
        "validator_hotkey": validator_hotkey,
    }
    token = _hmac(seed, _ADMISSION_DOMAIN, {**base, "purpose": "synthetic"})
    requests: list[tuple[Literal["GET", "HEAD"], str]] = [
        ("GET", item.path) for item in index.responses
    ]
    requests.append(("HEAD", "/"))
    for suffix, offset in (("", 0), (".js", 12)):
        synthetic = _synthetic_path(index, token[offset:], suffix)
        if synthetic is not None:
            requests.append(("GET", synthetic))
    sizes = [
        expected_static_response(index, method, path).content_length if method == "GET" else 0
        for method, path in requests
    ]
    if (
        len(requests) > budget.max_requests
        or sum(sizes) > budget.max_total_bytes
        or max(sizes) > budget.max_response_bytes
    ):
        return StaticCrawlRefusal(
            deployment_id=index.target.deployment_id,
            endpoint_id=endpoint.endpoint_id,
            code="admission_budget_exceeded",
            required_requests=len(requests),
            required_bytes=sum(sizes),
        )
    keyed = sorted(
        (
            _hmac(seed, _ADMISSION_DOMAIN, {**base, "method": method, "path": path}),
            method,
            path,
        )
        for method, path in requests
    )
    return [
        _planned(
            index,
            endpoint,
            probe_kind="admission",
            method=method,
            path=path,
            probe_index=position,
            fire_at_millis=None,
            nonce=key.hex(),
        )
        for position, (key, method, path) in enumerate(keyed)
    ]


def _hidden_choice(
    index: VerifiedStaticIndex, selector: bytes, ceiling_bytes: int
) -> tuple[Literal["GET", "HEAD"], str]:
    """Seed-derived request: mostly a GET within the ceiling, sometimes HEAD or synthetic."""

    eligible = [item.path for item in index.responses if item.content_length <= ceiling_bytes]
    every = [item.path for item in index.responses]
    lane = selector[0] % 16
    pick = int.from_bytes(selector[1:9], "big")
    if lane == 0:
        synthetic = _synthetic_path(index, selector[9:21], "")
        if synthetic is not None:
            return "GET", synthetic
    if lane == 1:
        synthetic = _synthetic_path(index, selector[9:21], ".js")
        if synthetic is not None:
            return "GET", synthetic
    if lane == 2 or not eligible:
        return "HEAD", every[pick % len(every)]
    return "GET", eligible[pick % len(eligible)]


def plan_static_hidden_probes(
    *,
    seed: bytes,
    validator_hotkey: str,
    indexes: Sequence[VerifiedStaticIndex],
    epoch_index: int,
    horizon_start_epoch: int,
    horizon_end_epoch: int,
    epoch_seconds: int = 300,
    probes_per_endpoint: int = 3,
    ceiling_bytes: int = HIDDEN_PROBE_CEILING_BYTES,
) -> list[PlannedStaticProbe]:
    """One epoch's hidden static probes for every incarnation of every verified index.

    As for organic probes, each endpoint gets one probe per equal slice of the
    epoch at an HMAC-derived instant; here the request itself (method and
    path, including synthetic never-published paths) is HMAC-derived too.
    Every GET stays within ``ceiling_bytes``. Probes outside the manifest's
    validity horizon ``[horizon_start_epoch, horizon_end_epoch)`` are omitted.
    Only verified indexes can be planned: an abstained deployment has none.
    """

    _validate_seed(seed)
    if not 60 <= epoch_seconds <= 3_600 or not 1 <= probes_per_endpoint <= 16:
        raise ValueError("probe_schedule_invalid")
    if isinstance(epoch_index, bool) or not isinstance(epoch_index, int) or epoch_index < 0:
        raise ValueError("epoch_index_invalid")
    if not 1 <= ceiling_bytes <= HIDDEN_PROBE_CEILING_BYTES:
        raise ValueError("probe_ceiling_invalid")
    epoch_millis = epoch_seconds * 1_000
    slot = epoch_millis // probes_per_endpoint
    planned: list[PlannedStaticProbe] = []
    for index in indexes:
        for endpoint in index.target.endpoints:
            for position in range(probes_per_endpoint):
                context: dict[str, object] = {
                    "endpoint_id": endpoint.endpoint_id,
                    "epoch_index": epoch_index,
                    "epoch_seconds": epoch_seconds,
                    "generation": endpoint.generation,
                    "probe_index": position,
                    "site_digest": index.target.site_digest,
                    "validator_hotkey": validator_hotkey,
                }
                timing = _hmac(seed, _HIDDEN_DOMAIN, {**context, "purpose": "time"})
                selector = _hmac(seed, _HIDDEN_DOMAIN, {**context, "purpose": "request"})
                nonce = _hmac(seed, _HIDDEN_DOMAIN, {**context, "purpose": "nonce"}).hex()
                fire_at = (
                    epoch_index * epoch_millis
                    + position * slot
                    + int.from_bytes(timing[:8], "big") % slot
                )
                if not horizon_start_epoch * 1_000 <= fire_at < horizon_end_epoch * 1_000:
                    continue
                method, path = _hidden_choice(index, selector, ceiling_bytes)
                planned.append(
                    _planned(
                        index,
                        endpoint,
                        probe_kind="hidden",
                        method=method,
                        path=path,
                        probe_index=position,
                        fire_at_millis=fire_at,
                        nonce=nonce,
                    )
                )
    planned.sort(key=lambda item: (item.fire_at_millis or 0, item.endpoint_id, item.probe_index))
    return planned


class StaticProbeCoverage(StrictFrozenModel):
    """What hidden probes can and cannot byte-check for one verified site."""

    deployment_id: DNSLabel
    site_digest: Hex64
    ceiling_bytes: int = Field(ge=1, le=HIDDEN_PROBE_CEILING_BYTES)
    indexed_responses: int = Field(ge=1)
    hidden_byte_checked_responses: int = Field(ge=0)
    #: Responses above the ceiling: only HEAD-checked by hidden probes; their
    #: bytes rest on admission, complete miner verification, and edge checks.
    hidden_head_only_responses: int = Field(ge=0)
    hidden_head_only_bytes: int = Field(ge=0)


def static_probe_coverage(
    index: VerifiedStaticIndex, ceiling_bytes: int = HIDDEN_PROBE_CEILING_BYTES
) -> StaticProbeCoverage:
    over = [item for item in index.responses if item.content_length > ceiling_bytes]
    return StaticProbeCoverage(
        deployment_id=index.target.deployment_id,
        site_digest=index.target.site_digest,
        ceiling_bytes=ceiling_bytes,
        indexed_responses=len(index.responses),
        hidden_byte_checked_responses=len(index.responses) - len(over),
        hidden_head_only_responses=len(over),
        hidden_head_only_bytes=sum(item.content_length for item in over),
    )


def static_probe_observation_bytes(value: StaticProbeObservation) -> bytes:
    return model_bytes(value, StaticProbeObservation)


def parse_static_probe_observation(rendered: bytes) -> StaticProbeObservation:
    return parse_model(
        rendered,
        StaticProbeObservation,
        static_probe_observation_bytes,
        maximum_bytes=64 * 1_024,
    )
