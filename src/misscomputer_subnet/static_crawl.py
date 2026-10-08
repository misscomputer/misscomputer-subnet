# SPDX-License-Identifier: AGPL-3.0-only
"""Network boundary for static index ingestion, admission crawls, and hidden probes.

This module fetches the two static index documents, sends planned requests
from :mod:`misscomputer_subnet.static_probe` through the bounded HTTPS
:class:`~misscomputer_subnet.assignment_probe_cli.ProbeTransport`, and judges
each response with :func:`~misscomputer_subnet.static_probe.evaluate_static_probe`.

Every request targets one endpoint incarnation through its public route host
with a freshly signed one-time authorization, no query string, identity
encoding, and ``Cache-Control: no-cache``. Its only signing capability is the
caller's purpose-limited probe-authorization signer.

An admission crawl is all-or-nothing per incarnation. It runs at most
``max_concurrent_endpoints`` (never more than three) incarnations at once,
stops an incarnation at its first failed response, and treats an exhausted
time or byte budget as ``incomplete``. Only ``admitted`` admits; every other
verdict leaves the incarnation unadmitted, with its evidence retained.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from typing import Final, Literal, Self

from pydantic import Field, model_validator

from .assignment_probe import ProbeResponse
from .assignment_probe_cli import ProbeTransport
from .contract_codec import (
    StrictFrozenModel,
    digest,
    model_bytes,
    parse_model,
    revalidate,
    verify_model_digest,
)
from .organic_contracts import (
    ORGANIC_PROBE_AUTHORIZATION_HEADER,
    UID,
    Digest,
    DNSLabel,
    EndpointID,
    Hex64,
    Hotkey,
    PositiveCount,
)
from .organic_probe import build_probe_authorization, probe_authorization_header
from .static_index import (
    MAX_MANIFEST_BYTES,
    MAX_RELEASE_BYTES,
    StaticDeploymentTarget,
    VerifiedStaticIndex,
    static_index_manifest_key,
    static_index_release_key,
)
from .static_probe import (
    HIDDEN_PROBE_CEILING_BYTES,
    MAX_ADMISSION_REQUESTS,
    PlannedStaticProbe,
    StaticCrawlBudget,
    StaticCrawlRefusal,
    StaticFailureCode,
    StaticProbeObservation,
    StaticPublicTransportPolicy,
    evaluate_static_probe,
    find_static_endpoint,
    plan_static_admission_crawl,
)

STATIC_ADMISSION_SCHEMA: Final = "miss.computer/misscomputer-subnet/static-admission-record"
USER_AGENT: Final = "misscomputer-static-probe/1"
#: A hidden probe fired later than this after its planned instant is skipped.
MAX_FIRE_DELAY_MILLIS: Final = 10_000
INDEX_FETCH_TIMEOUT_SECONDS: Final = 10.0

AdmissionVerdict = Literal["admitted", "incomplete", "refused", "rejected"]
Signer = Callable[[bytes], bytes]


def fetch_static_index_documents(
    transport: ProbeTransport,
    target: StaticDeploymentTarget,
    *,
    index_origin: str,
    server_name: str,
    deadline: float | None = None,
) -> tuple[bytes | None, bytes | None]:
    """Fetch one deployment's manifest and release from the public static index.

    ``index_origin`` is the operator-configured HTTPS origin of the §1 public
    index (``static-sites/v1/...``). Any failure is ``None``; authenticity
    comes only from :func:`~misscomputer_subnet.static_index.ingest_static_index`,
    which abstains on ``None``. A caller may provide a shared monotonic deadline
    so many slow deployments cannot extend one validator epoch indefinitely.
    """

    def fetch(key: str, max_bytes: int) -> bytes | None:
        timeout = INDEX_FETCH_TIMEOUT_SECONDS
        if deadline is not None:
            timeout = min(timeout, deadline - time.monotonic())
            if timeout <= 0:
                return None
        result = transport.fetch(
            url=f"{index_origin.rstrip('/')}/{key}",
            server_name=server_name,
            headers={"accept": "application/json", "accept-encoding": "identity"},
            timeout_seconds=timeout,
            max_bytes=max_bytes,
        )
        if not isinstance(result, ProbeResponse) or result.status != 200:
            return None
        return result.body

    return (
        fetch(static_index_manifest_key(target.site_digest), MAX_MANIFEST_BYTES),
        fetch(static_index_release_key(target.release_digest), MAX_RELEASE_BYTES),
    )


def static_probe_url(
    route_host: str, path: str, *, probe_port: int, edge_origin: str | None
) -> str:
    if edge_origin is not None:
        return f"{edge_origin}{path}"
    return f"https://{route_host}:{probe_port}{path}"


def send_static_probe(
    index: VerifiedStaticIndex,
    planned: PlannedStaticProbe,
    transport: ProbeTransport,
    *,
    validator_hotkey: str,
    sign: Signer,
    issued_at_epoch: int,
    timeout_millis: int,
    max_bytes: int,
    probe_port: int,
    edge_origin: str | None,
    pinned_edge_leaf_certificate_sha256: Sequence[str] = (),
    public_transport_policy: StaticPublicTransportPolicy | None = None,
) -> StaticProbeObservation:
    """Sign, send, and judge one targeted request to one incarnation."""

    if planned.site_digest != index.target.site_digest:
        raise ValueError("planned_probe_site_mismatch")
    authorization = build_probe_authorization(
        validator_hotkey=validator_hotkey,
        endpoint_id=planned.endpoint_id,
        generation=planned.generation,
        method=planned.method,
        path=planned.path,
        nonce=planned.nonce,
        issued_at_epoch=issued_at_epoch,
        sign=sign,
    )
    route_host = index.target.route_host
    result = transport.fetch(
        url=static_probe_url(
            route_host, planned.path, probe_port=probe_port, edge_origin=edge_origin
        ),
        server_name=route_host,
        headers={
            "host": route_host,
            "accept": "*/*",
            "accept-encoding": "identity",
            "cache-control": "no-cache",
            "pragma": "no-cache",
            "user-agent": USER_AGENT,
            ORGANIC_PROBE_AUTHORIZATION_HEADER: probe_authorization_header(authorization),
        },
        timeout_seconds=timeout_millis / 1_000,
        max_bytes=max_bytes,
        method=planned.method,
    )
    return evaluate_static_probe(
        index,
        authorization,
        result,
        probe_kind=planned.probe_kind,
        timeout_millis=timeout_millis,
        pinned_edge_leaf_certificate_sha256=pinned_edge_leaf_certificate_sha256,
        public_transport_policy=public_transport_policy,
    )


class StaticAdmissionRecord(StrictFrozenModel):
    """Sealed outcome of one admission crawl of one endpoint incarnation."""

    contract_schema: Literal["miss.computer/misscomputer-subnet/static-admission-record"] = Field(
        alias="schema"
    )
    schema_version: Literal[1]
    validator_hotkey: Hotkey
    deployment_id: DNSLabel
    site_digest: Digest
    release_digest: Digest
    endpoint_id: EndpointID
    generation: PositiveCount
    miner_uid: UID
    miner_hotkey: Hotkey
    crawl_id: int = Field(ge=0)
    verdict: AdmissionVerdict
    planned_requests: int = Field(ge=0, le=MAX_ADMISSION_REQUESTS)
    completed_requests: int = Field(ge=0, le=MAX_ADMISSION_REQUESTS)
    response_bytes: int = Field(ge=0)
    failure_code: StaticFailureCode | None
    observation_digests_sha256: list[Hex64]
    record_digest_sha256: Hex64

    @model_validator(mode="after")
    def canonical_record(self) -> Self:
        if self.completed_requests != len(self.observation_digests_sha256):
            raise ValueError("admission_observation_count_invalid")
        if self.completed_requests > self.planned_requests:
            raise ValueError("admission_request_count_invalid")
        if (self.verdict == "rejected") != (self.failure_code is not None):
            raise ValueError("admission_failure_invalid")
        if self.verdict == "admitted" and self.completed_requests != self.planned_requests:
            raise ValueError("admission_incomplete")
        if self.verdict == "refused" and self.completed_requests != 0:
            raise ValueError("admission_refusal_invalid")
        verify_model_digest(self, "record_digest_sha256")
        return self


def _admission_record(
    index: VerifiedStaticIndex,
    endpoint_id: str,
    *,
    validator_hotkey: str,
    crawl_id: int,
    verdict: AdmissionVerdict,
    planned_requests: int,
    observations: Sequence[StaticProbeObservation],
) -> StaticAdmissionRecord:
    endpoint = find_static_endpoint(index, endpoint_id)
    failed = next((item for item in observations if item.failure_code is not None), None)
    document: dict[str, object] = {
        "schema": STATIC_ADMISSION_SCHEMA,
        "schema_version": 1,
        "validator_hotkey": validator_hotkey,
        "deployment_id": index.target.deployment_id,
        "site_digest": index.target.site_digest,
        "release_digest": index.target.release_digest,
        "endpoint_id": endpoint.endpoint_id,
        "generation": endpoint.generation,
        "miner_uid": endpoint.miner_uid,
        "miner_hotkey": endpoint.miner_hotkey,
        "crawl_id": crawl_id,
        "verdict": verdict,
        "planned_requests": planned_requests,
        "completed_requests": len(observations),
        "response_bytes": sum(item.response_bytes for item in observations),
        "failure_code": None if failed is None else failed.failure_code,
        "observation_digests_sha256": [item.observation_digest_sha256 for item in observations],
    }
    return StaticAdmissionRecord.model_validate(
        {**document, "record_digest_sha256": digest(document)}
    )


def _crawl_endpoint(
    index: VerifiedStaticIndex,
    endpoint_id: str,
    transport: ProbeTransport,
    budget: StaticCrawlBudget,
    *,
    seed: bytes,
    validator_hotkey: str,
    sign: Signer,
    crawl_id: int,
    probe_port: int,
    edge_origin: str | None,
    pinned_edge_leaf_certificate_sha256: Sequence[str],
    clock: Callable[[], float],
    wall_clock: Callable[[], float],
) -> tuple[StaticAdmissionRecord, list[StaticProbeObservation]]:
    plan = plan_static_admission_crawl(
        index, endpoint_id, budget, seed=seed, validator_hotkey=validator_hotkey, crawl_id=crawl_id
    )

    def record(
        verdict: AdmissionVerdict, planned: int, observations: list[StaticProbeObservation]
    ) -> tuple[StaticAdmissionRecord, list[StaticProbeObservation]]:
        return (
            _admission_record(
                index,
                endpoint_id,
                validator_hotkey=validator_hotkey,
                crawl_id=crawl_id,
                verdict=verdict,
                planned_requests=planned,
                observations=observations,
            ),
            observations,
        )

    if isinstance(plan, StaticCrawlRefusal):
        return record("refused", 0, [])
    deadline = clock() + budget.max_duration_millis / 1_000
    observations: list[StaticProbeObservation] = []
    received = 0
    for planned in plan:
        remaining_millis = int((deadline - clock()) * 1_000)
        if remaining_millis < 100 or received > budget.max_total_bytes:
            return record("incomplete", len(plan), observations)
        observation = send_static_probe(
            index,
            planned,
            transport,
            validator_hotkey=validator_hotkey,
            sign=sign,
            issued_at_epoch=int(wall_clock()),
            timeout_millis=min(budget.request_timeout_millis, remaining_millis),
            max_bytes=budget.max_response_bytes,
            probe_port=probe_port,
            edge_origin=edge_origin,
            pinned_edge_leaf_certificate_sha256=pinned_edge_leaf_certificate_sha256,
        )
        observations.append(observation)
        received += observation.response_bytes
        if observation.outcome != "success":
            return record("rejected", len(plan), observations)
    if received > budget.max_total_bytes:
        return record("incomplete", len(plan), observations)
    return record("admitted", len(plan), observations)


def run_static_admission_crawl(
    index: VerifiedStaticIndex,
    endpoint_ids: Sequence[str],
    transport: ProbeTransport,
    budget: StaticCrawlBudget,
    *,
    seed: bytes,
    validator_hotkey: str,
    sign: Signer,
    crawl_id: int,
    probe_port: int,
    edge_origin: str | None = None,
    pinned_edge_leaf_certificate_sha256: Sequence[str] = (),
    clock: Callable[[], float] = time.monotonic,
    wall_clock: Callable[[], float] = time.time,
) -> list[tuple[StaticAdmissionRecord, list[StaticProbeObservation]]]:
    """Crawl every indexed response on each named incarnation; results in input order."""

    budget = revalidate(budget, StaticCrawlBudget)
    if len(set(endpoint_ids)) != len(endpoint_ids):
        raise ValueError("admission_endpoint_duplicate")
    for endpoint_id in endpoint_ids:
        find_static_endpoint(index, endpoint_id)
    with ThreadPoolExecutor(
        max_workers=budget.max_concurrent_endpoints, thread_name_prefix="static-admission"
    ) as pool:
        futures = [
            pool.submit(
                _crawl_endpoint,
                index,
                endpoint_id,
                transport,
                budget,
                seed=seed,
                validator_hotkey=validator_hotkey,
                sign=sign,
                crawl_id=crawl_id,
                probe_port=probe_port,
                edge_origin=edge_origin,
                pinned_edge_leaf_certificate_sha256=pinned_edge_leaf_certificate_sha256,
                clock=clock,
                wall_clock=wall_clock,
            )
            for endpoint_id in endpoint_ids
        ]
        return [future.result() for future in futures]


def run_static_hidden_probes(
    plan: Sequence[PlannedStaticProbe],
    indexes: Mapping[str, VerifiedStaticIndex],
    transport: ProbeTransport,
    *,
    validator_hotkey: str,
    sign: Signer,
    epoch_end_millis: int,
    timeout_millis: int,
    probe_port: int,
    edge_origin: str | None = None,
    pinned_edge_leaf_certificate_sha256: Sequence[str] = (),
    clock: Callable[[], float] = time.time,
    sleep: Callable[[float], None] = time.sleep,
) -> tuple[list[StaticProbeObservation], int]:
    """Fire a hidden plan at its private instants; return observations and skipped count.

    ``indexes`` maps deployment id to its verified index. A probe whose
    instant already lies more than :data:`MAX_FIRE_DELAY_MILLIS` in the past,
    or whose send time has left the epoch, is skipped, never sent late.
    """

    observations: list[StaticProbeObservation] = []
    skipped = 0
    for planned in plan:
        if planned.probe_kind != "hidden" or planned.fire_at_millis is None:
            raise ValueError("hidden_plan_invalid")
        now_millis = int(clock() * 1_000)
        if planned.fire_at_millis > now_millis:
            sleep((planned.fire_at_millis - now_millis) / 1_000)
            now_millis = int(clock() * 1_000)
        if (
            now_millis - planned.fire_at_millis > MAX_FIRE_DELAY_MILLIS
            or now_millis >= epoch_end_millis
        ):
            skipped += 1
            continue
        observations.append(
            send_static_probe(
                indexes[planned.deployment_id],
                planned,
                transport,
                validator_hotkey=validator_hotkey,
                sign=sign,
                issued_at_epoch=now_millis // 1_000,
                timeout_millis=timeout_millis,
                max_bytes=HIDDEN_PROBE_CEILING_BYTES,
                probe_port=probe_port,
                edge_origin=edge_origin,
                pinned_edge_leaf_certificate_sha256=pinned_edge_leaf_certificate_sha256,
            )
        )
    return observations, skipped


def static_admission_record_bytes(value: StaticAdmissionRecord) -> bytes:
    return model_bytes(value, StaticAdmissionRecord)


def parse_static_admission_record(rendered: bytes) -> StaticAdmissionRecord:
    return parse_model(
        rendered,
        StaticAdmissionRecord,
        static_admission_record_bytes,
        maximum_bytes=1_024 * 1_024,
    )
