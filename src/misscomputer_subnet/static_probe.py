# SPDX-License-Identifier: AGPL-3.0-only
"""Targeted, cache-bypassing validator probes of static endpoint incarnations.

Every request here is addressed to one endpoint incarnation through the public
route host with a fresh ``organic-probe-authorization`` v1 (validator hotkey,
one-time nonce, no query) and is judged against a
:class:`~misscomputer_subnet.static_index.VerifiedStaticIndex`: status,
normative header digest, length and body SHA-256 must equal the contract's
``expected(...)`` (§5.5), never merely the miner's attestation. The miner's
``miner-probe-attestation`` v2 still binds the response to the miner (§11.4):
for a static incarnation its ``artifact_digest`` is the ``site_digest``, its
``ticket_digest`` the static ticket digest, and its ``response_header_sha256``
covers exactly the normative header set, so the validator recomputes it.

Two plans share one evaluator:

* :func:`plan_static_admission_crawl` requests every §4.4 route with GET, plus
  ``HEAD /``, ``GET /<32 hex>.absent`` and ``GET /<32 hex>`` (§10.2 crawl set),
  in an unpredictable order under explicit budgets. A plan that does not fit
  its budget is refused as a whole: no partial admission.
* :func:`plan_static_hidden_probes` samples each epoch at seed-derived times
  and seed-derived targets (routes and synthetic paths), GET only when the
  route's ``content_length`` is within the 1 MiB ceiling, otherwise HEAD
  (§11.3). :func:`static_probe_coverage` reports routes and bytes covered.

Attribution (§11.4)
-------------------
``path``: no response, timeout, TLS failure or pin mismatch, no
``X-Miss-Edge-Upstream: replica``, an attestation for another nonce (replay or
cache), an attestation whose status/body/header digests differ from what was
observed (tampering between miner and validator), and a forbidden header,
which the attestation does not cover.

``miner``: a missing attestation or an invalid signature on a replica-marked
response; an attestation whose digests equal the observation while the
observation differs from ``expected`` (a content fault, flagged
``quarantine_candidate``); and, as the only ``attestation_fraud``, a validly
signed attestation for this nonce naming another ticket, endpoint,
generation, site or request. Wrong bytes alone are never fraud; trust
decisions stay with scoring.

This module is pure: no clock, network, file, process, environment, wallet,
chain, or randomness. Signing is delegated to the caller.
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Sequence
from typing import Final, Literal, Self

from pydantic import Field, model_serializer, model_validator

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
    Digest,
    DNSLabel,
    EndpointID,
    HealthPath,
    Hex64,
    Hotkey,
    MinerProbeAttestationV2,
    OrganicProbeAuthorization,
    PositiveCount,
    response_header_sha256,
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
    StaticEndpointTarget,
    VerifiedStaticIndex,
    expected_static_response,
    normative_headers,
)

STATIC_OBSERVATION_SCHEMA: Final = "miss.computer/misscomputer-subnet/static-probe-observation"
#: §1/§11.3 validator probe body ceiling per GET.
HIDDEN_PROBE_CEILING_BYTES: Final = MAX_RESPONSE_BYTES_CEILING
#: §10.2 crawl set beyond the routes: ``HEAD /`` and two synthetic GETs.
ADMISSION_SYNTHETIC_REQUESTS: Final = 3
MAX_ADMISSION_REQUESTS: Final = 2 * MAX_FILES + ADMISSION_SYNTHETIC_REQUESTS
#: §10.2 per-incarnation byte budget: routes plus 64 KiB, never above 512 MiB.
ADMISSION_BYTE_SLACK: Final = 64 * 1_024
MAX_ADMISSION_BYTES: Final = 512 * 1_024 * 1_024
DEFAULT_REQUEST_TIMEOUT_MILLIS: Final = 30_000
DEFAULT_CRAWL_DURATION_MILLIS: Final = 15 * 60 * 1_000
#: §5.2: names covered by ``response_header_sha256``.
NORMATIVE_HEADER_NAMES: Final = frozenset(
    {"allow", "cache-control", "content-length", "content-type", "x-content-type-options"}
)
#: §5.2: a static response carries none of these; ``Date`` is permitted.
FORBIDDEN_HEADER_NAMES: Final = frozenset(
    {
        "accept-ranges",
        "content-disposition",
        "content-encoding",
        "content-range",
        "etag",
        "last-modified",
        "location",
        "refresh",
        "set-cookie",
        "transfer-encoding",
        "vary",
    }
)
_HOP_HEADERS: Final = frozenset({ATTESTATION_HEADER, UPSTREAM_RESPONSE_HEADER})
_ADMISSION_DOMAIN: Final = b"miss.computer/misscomputer-subnet/static-admission-crawl/v1"
_HIDDEN_DOMAIN: Final = b"miss.computer/misscomputer-subnet/static-hidden-probe/v1"
_MAX_EPOCH_MILLIS: Final = 253_402_300_799_999
PUBLIC_FRAMING_PROFILE: Final = "cloudflare-framing-v1"
PUBLIC_TRANSPORT_POLICY_SCHEMA: Final = (
    "miss.computer/misscomputer-subnet/static-public-transport-policy"
)


class StaticPublicTransportPolicy(StrictFrozenModel):
    """Explicit testnet-only pin for comparing signed representation to public framing."""

    contract_schema: Literal["miss.computer/misscomputer-subnet/static-public-transport-policy"] = (
        Field(alias="schema")
    )
    schema_version: Literal[1]
    profile: Literal["cloudflare-framing-v1"]
    network: Literal["test"]
    netuid: Literal[581]
    route_host_suffix: Literal["on.miss.computer"]
    manifest_trust_policy_digest_sha256: Hex64
    policy_digest_sha256: Hex64

    @model_validator(mode="after")
    def canonical_policy(self) -> Self:
        verify_model_digest(self, "policy_digest_sha256")
        return self


def parse_static_public_transport_policy(rendered: bytes) -> StaticPublicTransportPolicy:
    return parse_model(
        rendered,
        StaticPublicTransportPolicy,
        lambda value: model_bytes(value, StaticPublicTransportPolicy),
        maximum_bytes=4_096,
    )


def _public_framing_valid(
    headers: Sequence[Sequence[str]],
    *,
    http_version: str,
    request_method: str,
    expected_content_type: str,
    expected_content_length: int,
) -> bool:
    """Match end-to-end headers and permit only well-formed public wire framing."""

    if http_version not in {"HTTP/1.1", "HTTP/2", "HTTP/3"}:
        return False
    if (
        len(headers) > 128
        or sum(len(name) + len(value) for name, value in headers) > 16_384
        or any(
            not name.isascii() or not value.isascii() or len(name) > 128 or len(value) > 8_192
            for name, value in headers
        )
    ):
        return False
    stable = {
        name: value
        for name, value in normative_headers(expected_content_type, expected_content_length)
        if name != "content-length"
    }
    for name, value in stable.items():
        if _header_values(headers, name) != [value]:
            return False
    if _header_values(headers, "allow") or _has_forbidden_header(
        [(name, value) for name, value in headers if name.lower() != "transfer-encoding"]
    ):
        return False
    lengths = _header_values(headers, "content-length")
    codings = _header_values(headers, "transfer-encoding")
    if len(lengths) > 1 or len(codings) > 1:
        return False
    if lengths and (lengths[0] != str(expected_content_length) or codings):
        return False
    if codings and (http_version != "HTTP/1.1" or codings != ["chunked"]):
        return False
    if http_version == "HTTP/1.1" and request_method == "GET" and not lengths and not codings:
        return False
    # A complete HTTP/2 or HTTP/3 response may omit the representation length;
    # its signed expected digest and raw body length remain mandatory.
    return True


ProbeKind = Literal["admission", "hidden"]
Attribution = Literal["miner", "none", "path"]
AttestationStatus = Literal["fraudulent", "not_presented", "rejected", "replayed", "verified"]
ExpectedKind = Literal["directory_index", "file", "navigation_fallback", "not_found"]
StaticFailureCode = Literal[
    "attestation_fraud",
    "attestation_invalid",
    "attestation_missing",
    "body_mismatch",
    "cache_replay",
    "connection_failed",
    "content_altered_in_transit",
    "edge_generated",
    "forbidden_header",
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
    "forbidden_header": "path",
    "header_mismatch": "miner",
    "response_oversized": "path",
    "status_mismatch": "miner",
    "timeout": "path",
    "tls_certificate_invalid": "path",
    "tls_handshake_failed": "path",
    "tls_pin_mismatch": "path",
    "transport_error": "path",
}
#: §11.4 miner content faults: attested = observed ≠ expected.
_CONTENT_FAULTS: Final = frozenset({"body_mismatch", "header_mismatch", "status_mismatch"})


def static_failure_attribution(code: str | None) -> Attribution:
    return "none" if code is None else _ATTRIBUTION[code]


def observed_header_sha256(headers: Sequence[Sequence[str]]) -> str:
    """``response_header_sha256`` over the observed headers of the normative set."""

    return response_header_sha256(
        [(name.lower(), value) for name, value in headers if name.lower() in NORMATIVE_HEADER_NAMES]
    )


def _has_forbidden_header(headers: Sequence[Sequence[str]]) -> bool:
    for name, _value in headers:
        lowered = name.lower()
        if lowered in FORBIDDEN_HEADER_NAMES or (
            lowered.startswith("x-miss-") and lowered not in _HOP_HEADERS
        ):
            return True
    return False


class StaticProbeObservation(StrictFrozenModel):
    """One sealed attempted request to one static endpoint incarnation."""

    contract_schema: Literal["miss.computer/misscomputer-subnet/static-probe-observation"] = Field(
        alias="schema"
    )
    schema_version: Literal[1, 2]
    probe_kind: Literal["admission", "hidden"]
    validator_hotkey: Hotkey
    deployment_id: DNSLabel
    site_digest: Digest
    release_digest: Digest
    release_trust_policy_digest_sha256: Hex64
    endpoint_id: EndpointID
    generation: PositiveCount
    miner_uid: UID
    miner_hotkey: Hotkey
    probe_nonce: Hex64
    issued_at: SecondsTimestamp
    request_method: Literal["GET", "HEAD"]
    request_path: HealthPath
    expected_kind: ExpectedKind
    expected_status: int = Field(ge=100, le=599)
    expected_content_length: int = Field(ge=0, le=MAX_FILE_BYTES)
    expected_body_sha256: Hex64
    expected_header_sha256: Hex64
    latency_millis: int = Field(ge=0, le=MAX_LATENCY_MILLIS)
    outcome: Literal["failure", "success"]
    failure_code: StaticFailureCode | None
    attribution: Attribution
    quarantine_candidate: bool
    upstream_marker: bool
    response_status: int | None = Field(ge=100, le=599)
    response_bytes: int = Field(ge=0, le=MAX_FILE_BYTES + 1)
    response_body_sha256: Hex64 | None
    response_header_sha256: Hex64 | None
    tls_leaf_certificate_sha256: Hex64 | None
    attestation_status: AttestationStatus
    attestation: MinerProbeAttestationV2 | None
    transport_profile: Literal["cloudflare-framing-v1"] | None = None
    transport_policy_digest_sha256: Hex64 | None = None
    delivered_http_version: Literal["HTTP/1.1", "HTTP/2", "HTTP/3"] | None = None
    delivered_headers: list[list[str]] | None = None
    observation_digest_sha256: Hex64

    @model_serializer(mode="wrap")
    def serialize_versioned(self, handler: object) -> dict[str, object]:
        document: dict[str, object] = handler(self)  # type: ignore[operator]
        if self.schema_version == 1:
            for name in (
                "transport_profile",
                "transport_policy_digest_sha256",
                "delivered_http_version",
                "delivered_headers",
            ):
                document.pop(name, None)
        return document

    @model_validator(mode="after")
    def canonical_observation(self) -> Self:
        if self.schema_version == 1:
            if any(
                value is not None
                for value in (
                    self.transport_profile,
                    self.transport_policy_digest_sha256,
                    self.delivered_http_version,
                    self.delivered_headers,
                )
            ):
                raise ValueError("observation_profile_invalid")
        elif (
            self.transport_profile != PUBLIC_FRAMING_PROFILE
            or self.transport_policy_digest_sha256 is None
        ):
            raise ValueError("observation_profile_invalid")
        if self.schema_version == 2 and self.delivered_headers is not None:
            if self.delivered_http_version is None or (
                self.response_header_sha256 != observed_header_sha256(self.delivered_headers)
            ):
                raise ValueError("observation_delivered_headers_invalid")
        if (self.outcome == "success") != (self.failure_code is None):
            raise ValueError("observation_outcome_invalid")
        if self.attribution != static_failure_attribution(self.failure_code):
            raise ValueError("observation_attribution_invalid")
        if self.quarantine_candidate != (self.failure_code in _CONTENT_FAULTS):
            raise ValueError("observation_quarantine_invalid")
        if self.outcome == "success" and (
            not self.upstream_marker
            or self.response_status != self.expected_status
            or self.response_body_sha256 != self.expected_body_sha256
            or (
                self.schema_version == 1
                and self.response_header_sha256 != self.expected_header_sha256
            )
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
                or (
                    self.schema_version == 1
                    and self.attestation.response_header_sha256 != self.response_header_sha256
                )
            )
        ):
            raise ValueError("observation_attestation_binding_invalid")
        if self.schema_version == 2 and self.outcome == "success":
            content_types = (
                _header_values(self.delivered_headers, "content-type")
                if self.delivered_headers is not None
                else []
            )
            if (
                self.attestation is None
                or self.attestation.response_header_sha256 != self.expected_header_sha256
                or self.response_bytes
                != (self.expected_content_length if self.request_method == "GET" else 0)
                or self.delivered_headers is None
                or self.delivered_http_version is None
                or len(content_types) != 1
                or not _public_framing_valid(
                    self.delivered_headers,
                    http_version=self.delivered_http_version,
                    request_method=self.request_method,
                    expected_content_type=content_types[0],
                    expected_content_length=self.expected_content_length,
                )
            ):
                raise ValueError("observation_public_framing_invalid")
        if self.schema_version == 2 and self.quarantine_candidate:
            if (
                self.attestation_status != "verified"
                or self.attestation is None
                or self.attestation.response_header_sha256 != self.expected_header_sha256
                or self.failure_code == "header_mismatch"
                or (
                    self.failure_code == "status_mismatch"
                    and self.response_status == self.expected_status
                )
                or (
                    self.failure_code == "body_mismatch"
                    and (
                        self.response_status != self.expected_status
                        or self.response_body_sha256 == self.expected_body_sha256
                    )
                )
            ):
                raise ValueError("observation_content_fault_unproved")
        if self.attribution == "miner" and not self.upstream_marker:
            raise ValueError("observation_attribution_invalid")
        verify_model_digest(self, "observation_digest_sha256")
        return self


def _header_values(headers: Sequence[Sequence[str]], name: str) -> list[str]:
    return [value for key, value in headers if key.lower() == name]


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
    public_transport_policy: StaticPublicTransportPolicy | None = None,
) -> StaticProbeObservation:
    """Judge one observed static response against ``expected(...)`` (§11.4)."""

    request = revalidate(authorization, OrganicProbeAuthorization)
    endpoint = find_static_endpoint(index, request.endpoint_id)
    if request.generation != endpoint.generation:
        raise ValueError("authorization_request_mismatch")
    expected = expected_static_response(index, request.method, request.path)
    target = index.target
    if public_transport_policy is not None and not target.route_host.endswith(
        "." + public_transport_policy.route_host_suffix
    ):
        raise ValueError("public_transport_route_out_of_scope")
    document: dict[str, object] = {
        "schema": STATIC_OBSERVATION_SCHEMA,
        "schema_version": 2 if public_transport_policy is not None else 1,
        "probe_kind": probe_kind,
        "validator_hotkey": request.validator_hotkey,
        "deployment_id": target.deployment_id,
        "site_digest": target.site_digest,
        "release_digest": target.release_digest,
        "release_trust_policy_digest_sha256": index.trust_policy_digest_sha256,
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
        "expected_header_sha256": expected.header_sha256,
        "latency_millis": min(max(result.latency_millis, 0), MAX_LATENCY_MILLIS),
        "outcome": "failure",
        "failure_code": None,
        "attribution": "none",
        "quarantine_candidate": False,
        "upstream_marker": False,
        "response_status": None,
        "response_bytes": 0,
        "response_body_sha256": None,
        "response_header_sha256": None,
        "tls_leaf_certificate_sha256": result.tls_leaf_certificate_sha256,
        "attestation_status": "not_presented",
        "attestation": None,
    }
    if public_transport_policy is not None:
        document.update(
            transport_profile=public_transport_policy.profile,
            transport_policy_digest_sha256=public_transport_policy.policy_digest_sha256,
            delivered_http_version=None,
            delivered_headers=None,
        )

    def fail(code: StaticFailureCode) -> StaticProbeObservation:
        document["failure_code"] = code
        document["attribution"] = static_failure_attribution(code)
        document["quarantine_candidate"] = code in _CONTENT_FAULTS
        return _seal(document)

    if result.latency_millis > timeout_millis:
        return fail("timeout")
    if isinstance(result, ProbeTransportFailure):
        document["response_status"] = result.response_status
        return fail("transport_error" if result.code == "timeout" else result.code)
    if not 100 <= result.status <= 599:
        return fail("transport_error")
    body_digest = hashlib.sha256(result.body).hexdigest()
    header_digest = observed_header_sha256(result.headers)
    document["response_status"] = result.status
    document["response_bytes"] = min(len(result.body), MAX_FILE_BYTES + 1)
    document["response_body_sha256"] = body_digest
    document["response_header_sha256"] = header_digest
    if public_transport_policy is not None:
        document["delivered_http_version"] = (
            result.http_version if result.http_version in {"HTTP/1.1", "HTTP/2", "HTTP/3"} else None
        )
        if (
            len(result.headers) <= 128
            and sum(len(name) + len(value) for name, value in result.headers) <= 16_384
            and all(
                name.isascii() and value.isascii() and len(name) <= 128 and len(value) <= 8_192
                for name, value in result.headers
            )
        ):
            document["delivered_headers"] = [list(item) for item in result.headers]
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
    if attestation.probe_nonce != request.nonce:
        # A validly signed statement about some other probe: replayed or
        # cached somewhere on the path. Never the miner's fault.
        document["attestation_status"] = "replayed"
        document["attestation"] = model_document(attestation)
        return fail("cache_replay")
    if (
        attestation.endpoint_id != endpoint.endpoint_id
        or attestation.generation != endpoint.generation
        or attestation.ticket_digest != endpoint.ticket_digest
        or attestation.artifact_digest != target.site_digest
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
    if (
        attestation.response_status != result.status
        or attestation.response_body_sha256 != body_digest
        or (public_transport_policy is None and attestation.response_header_sha256 != header_digest)
    ):
        document["attestation_status"] = "rejected"
        return fail("content_altered_in_transit")
    document["attestation_status"] = "verified"
    document["attestation"] = model_document(attestation)
    if public_transport_policy is not None:
        # The signature commits to the complete representation header set,
        # including Content-Length. Its opaque mismatch cannot identify a
        # miner fault, so preserve path attribution and abstain.
        if attestation.response_header_sha256 != expected.header_sha256:
            return fail("content_altered_in_transit")
        if result.status != expected.status:
            return fail("status_mismatch")
        if body_digest != expected.body_sha256:
            return fail("body_mismatch")
        if len(result.body) != (expected.content_length if request.method == "GET" else 0):
            return fail("content_altered_in_transit")
        if not _public_framing_valid(
            result.headers,
            http_version=result.http_version or "",
            request_method=request.method,
            expected_content_type=expected.content_type,
            expected_content_length=expected.content_length,
        ):
            return fail("content_altered_in_transit")
        document["outcome"] = "success"
        return _seal(document)
    if result.status != expected.status:
        return fail("status_mismatch")
    if body_digest != expected.body_sha256:
        return fail("body_mismatch")
    if header_digest != expected.header_sha256:
        return fail("header_mismatch")
    if _has_forbidden_header(result.headers):
        return fail("forbidden_header")
    document["outcome"] = "success"
    return _seal(document)


# --------------------------------------------------------------------------
# Planning
# --------------------------------------------------------------------------


class PlannedStaticProbe(StrictFrozenModel):
    """One planned targeted request: incarnation, method, path, one-time nonce."""

    probe_kind: Literal["admission", "hidden"]
    deployment_id: DNSLabel
    site_digest: Digest
    endpoint_id: EndpointID
    generation: PositiveCount
    method: Literal["GET", "HEAD"]
    path: HealthPath
    expected_kind: ExpectedKind
    expected_content_length: int = Field(ge=0, le=MAX_FILE_BYTES)
    #: Position within the crawl, or the probe's slice within the epoch.
    probe_index: int = Field(ge=0, le=MAX_ADMISSION_REQUESTS)
    #: Unix milliseconds for hidden probes; ``None`` for admission requests.
    fire_at_millis: int | None = Field(ge=0, le=_MAX_EPOCH_MILLIS)
    nonce: Hex64


class StaticCrawlBudget(StrictFrozenModel):
    """Explicit bounds on one admission crawl of one incarnation (§10.2)."""

    max_requests: int = Field(ge=1, le=MAX_ADMISSION_REQUESTS)
    max_total_bytes: int = Field(ge=1, le=MAX_ADMISSION_BYTES)
    max_response_bytes: int = Field(ge=1, le=MAX_FILE_BYTES)
    request_timeout_millis: int = Field(ge=100, le=DEFAULT_REQUEST_TIMEOUT_MILLIS)
    max_duration_millis: int = Field(ge=1_000, le=DEFAULT_CRAWL_DURATION_MILLIS)
    #: Incarnations crawled at once; §10.2 allows at most 3.
    max_concurrent_endpoints: int = Field(ge=1, le=3)


def default_static_crawl_budget(index: VerifiedStaticIndex) -> StaticCrawlBudget:
    """The §10.2 default budget for one site."""

    return StaticCrawlBudget(
        max_requests=len(index.routes) + ADMISSION_SYNTHETIC_REQUESTS,
        max_total_bytes=min(
            sum(item.content_length for item in index.routes.values()) + ADMISSION_BYTE_SLACK,
            MAX_ADMISSION_BYTES,
        ),
        max_response_bytes=MAX_FILE_BYTES,
        request_timeout_millis=DEFAULT_REQUEST_TIMEOUT_MILLIS,
        max_duration_millis=DEFAULT_CRAWL_DURATION_MILLIS,
        max_concurrent_endpoints=3,
    )


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
    """§10.2 ``/<32 hex>`` or ``/<32 hex>.absent``; ``None`` if it is a route."""

    path = f"/{token[:16].hex()}{suffix}"
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
    """The §10.2 crawl set of one incarnation, or a refusal; never a subset.

    GET of every route, ``HEAD /``, ``GET /<32 hex>.absent`` and
    ``GET /<32 hex>``, in a seed-derived order with seed-derived nonces.
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
    requests: list[tuple[Literal["GET", "HEAD"], str]] = [
        ("GET", path) for path in sorted(index.routes)
    ]
    requests.append(("HEAD", "/"))
    for suffix in (".absent", ""):
        attempt = 0
        synthetic: str | None = None
        while synthetic is None:
            token = _hmac(
                seed, _ADMISSION_DOMAIN, {**base, "attempt": attempt, "synthetic": suffix}
            )
            synthetic = _synthetic_path(index, token, suffix)
            attempt += 1
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
    """Seed-derived target: usually a route, sometimes a synthetic path (§11.3)."""

    lane = selector[0] % 8
    if lane in {0, 1}:
        synthetic = _synthetic_path(index, selector[16:], ".absent" if lane == 0 else "")
        if synthetic is not None:
            expected = expected_static_response(index, "GET", synthetic)
            return ("GET" if expected.content_length <= ceiling_bytes else "HEAD"), synthetic
    routes = sorted(index.routes)
    path = routes[int.from_bytes(selector[1:9], "big") % len(routes)]
    return ("GET" if index.routes[path].content_length <= ceiling_bytes else "HEAD"), path


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

    Each endpoint gets one probe per equal slice of the epoch at an
    HMAC-derived instant; the target (a route or a synthetic path) is
    HMAC-derived too, so neither is predictable from public data. A route is
    probed with GET only when its ``content_length`` is within
    ``ceiling_bytes``, otherwise with HEAD. Probes outside the manifest's
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
    """§11.3 coverage of one site: routes total/probed, bytes total/GET-eligible."""

    deployment_id: DNSLabel
    site_digest: Digest
    ceiling_bytes: int = Field(ge=1, le=HIDDEN_PROBE_CEILING_BYTES)
    routes_total: int = Field(ge=1)
    routes_probed: int = Field(ge=0)
    bytes_total: int = Field(ge=0)
    bytes_get_eligible: int = Field(ge=0)


def static_probe_coverage(
    index: VerifiedStaticIndex,
    planned: Sequence[PlannedStaticProbe] = (),
    ceiling_bytes: int = HIDDEN_PROBE_CEILING_BYTES,
) -> StaticProbeCoverage:
    """Coverage of ``index`` by ``planned`` (probes of other sites are ignored).

    Routes above the ceiling are only HEAD-checked by hidden probes; their
    bytes rest on admission, complete miner verification and edge checks.
    """

    sizes = [item.content_length for item in index.routes.values()]
    probed = {
        probe.path
        for probe in planned
        if probe.site_digest == index.target.site_digest and probe.path in index.routes
    }
    return StaticProbeCoverage(
        deployment_id=index.target.deployment_id,
        site_digest=index.target.site_digest,
        ceiling_bytes=ceiling_bytes,
        routes_total=len(sizes),
        routes_probed=len(probed),
        bytes_total=sum(sizes),
        bytes_get_eligible=sum(size for size in sizes if size <= ceiling_bytes),
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
