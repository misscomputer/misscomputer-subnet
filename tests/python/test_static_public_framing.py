# SPDX-License-Identifier: AGPL-3.0-only
"""Public CDN framing must not erase signed static representation proof."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

import pytest
from static_context import (
    ISSUED_EPOCH,
    SERVER,
    VALIDATOR,
    FakeStaticEdge,
    key,
    manifest_document,
    release_bytes,
    sha,
    site_digest,
    stored,
    target,
    trust_policy,
)

from misscomputer_subnet.assignment_probe import ProbeResponse
from misscomputer_subnet.contract_codec import canonical_json, digest, model_document
from misscomputer_subnet.static_crawl import send_static_probe
from misscomputer_subnet.static_evidence import (
    append_static_evidence,
    parse_static_evidence_record,
    static_evidence_record_bytes,
)
from misscomputer_subnet.static_index import (
    VerifiedStaticIndex,
    expected_static_response,
    ingest_static_index,
)
from misscomputer_subnet.static_probe import (
    PlannedStaticProbe,
    StaticProbeObservation,
    StaticPublicTransportPolicy,
    parse_static_probe_observation,
    static_probe_observation_bytes,
)
from misscomputer_subnet.static_scoring import (
    StaticScoringError,
    replay_static_epoch_score,
    score_static_epoch,
)


def policy() -> StaticPublicTransportPolicy:
    unsigned = {
        "schema": "miss.computer/misscomputer-subnet/static-public-transport-policy",
        "schema_version": 1,
        "profile": "cloudflare-framing-v1",
        "network": "test",
        "netuid": 581,
        "route_host_suffix": "on.miss.computer",
        "manifest_trust_policy_digest_sha256": "a" * 64,
    }
    return StaticPublicTransportPolicy.model_validate(
        {**unsigned, "policy_digest_sha256": digest(unsigned)}
    )


def site() -> tuple[VerifiedStaticIndex, FakeStaticEdge]:
    manifest = stored(manifest_document())
    site_id = site_digest(manifest)
    release = release_bytes(site_id)
    index = ingest_static_index(
        target(site_id, release),
        manifest,
        release,
        trust_policy(),
        pinned_server_implementation_digest=SERVER,
    )
    assert isinstance(index, VerifiedStaticIndex)
    return index, FakeStaticEdge(site_id, endpoints=tuple(index.target.endpoints))


class PublicFraming:
    def __init__(self, edge: FakeStaticEdge, *, change: str = "chunked") -> None:
        self.edge = edge
        self.change = change

    def fetch(self, **kwargs: Any) -> ProbeResponse:
        response = self.edge.fetch(**kwargs)
        assert isinstance(response, ProbeResponse)
        headers = (
            list(response.headers)
            if self.change == "length"
            else [(k, v) for k, v in response.headers if k.lower() != "content-length"]
        )
        if self.change in {"chunked", "gzip", "stable", "truncated"}:
            headers.append(("Transfer-Encoding", "chunked"))
        if self.change == "duplicate_length":
            headers.extend([("Content-Length", "22"), ("Content-Length", "22")])
        elif self.change == "gzip":
            headers.append(("Content-Encoding", "gzip"))
        elif self.change == "stable":
            headers = [(k, "public" if k.lower() == "cache-control" else v) for k, v in headers]
        elif self.change == "truncated":
            response = replace(response, body=response.body[:-1])
        return replace(response, headers=tuple(headers), http_version="HTTP/1.1")


def probe(
    index: VerifiedStaticIndex,
    edge: FakeStaticEdge,
    *,
    method: str = "GET",
    path: str = "/",
    change: str = "chunked",
    framed: bool = True,
    endpoint_position: int = 0,
):
    endpoint = index.target.endpoints[endpoint_position]
    expected = expected_static_response(index, method, path)
    planned = PlannedStaticProbe(
        probe_kind="hidden",
        deployment_id=index.target.deployment_id,
        site_digest=index.target.site_digest,
        endpoint_id=endpoint.endpoint_id,
        generation=endpoint.generation,
        method=method,
        path=path,
        expected_kind=expected.kind,
        expected_content_length=expected.content_length,
        probe_index=0,
        fire_at_millis=ISSUED_EPOCH * 1000,
        nonce=sha((method + path + change + str(endpoint_position)).encode()),
    )
    return send_static_probe(
        index,
        planned,
        PublicFraming(edge, change=change),
        validator_hotkey=VALIDATOR,
        sign=lambda _message: b"\x01" * 64,
        issued_at_epoch=ISSUED_EPOCH,
        timeout_millis=5_000,
        max_bytes=1_024 * 1_024,
        probe_port=443,
        edge_origin=None,
        public_transport_policy=policy() if framed else None,
    )


@pytest.mark.parametrize("method,path", [("GET", "/"), ("HEAD", "/"), ("GET", "/missing.absent")])
def test_signed_full_headers_and_public_chunked_body_score(method: str, path: str) -> None:
    index, edge = site()
    strict = probe(index, edge, method=method, path=path, framed=False)
    framed = probe(index, edge, method=method, path=path)
    assert strict.failure_code == "content_altered_in_transit"
    assert framed.outcome == "success" and framed.schema_version == 2
    assert framed.response_header_sha256 != framed.expected_header_sha256
    assert parse_static_probe_observation(static_probe_observation_bytes(framed)) == framed
    record = append_static_evidence(None, framed)
    assert parse_static_evidence_record(static_evidence_record_bytes(record)) == record
    epoch = score_static_epoch(
        [index.target],
        [index],
        [],
        [framed],
        validator_hotkey=VALIDATOR,
        epoch_index=ISSUED_EPOCH // 300,
        network="test",
        netuid=581,
        public_transport_policy=policy(),
    )
    assert epoch.schema_version == 2
    assert replay_static_epoch_score(epoch, [index], public_transport_policy=policy()) == epoch


@pytest.mark.parametrize("change", ["duplicate_length", "gzip", "stable", "truncated"])
def test_public_framing_rejects_unsafe_changes_without_miner_penalty(change: str) -> None:
    index, edge = site()
    observation = probe(index, edge, change=change)
    assert observation.outcome == "failure"
    assert observation.attribution == "path"
    assert not observation.quarantine_candidate


@pytest.mark.parametrize(
    "fault,code,attribution",
    [
        (
            lambda state: state.update(
                attested_headers=[
                    item
                    for item in state["attested_headers"]
                    if item[0].lower() != "x-content-type-options"
                ]
            ),
            "content_altered_in_transit",
            "path",
        ),
        (lambda state: state.update(nonce="ff" * 32), "cache_replay", "path"),
        (lambda state: state.update(signing_key=key("imposter")), "attestation_invalid", "miner"),
    ],
)
def test_signed_header_ambiguity_and_identity_checks_remain_fail_closed(
    fault: Any,
    code: str,
    attribution: str,
) -> None:
    index, edge = site()
    edge.faults[index.target.endpoints[0].endpoint_id] = fault
    observation = probe(index, edge)
    assert (observation.failure_code, observation.attribution) == (code, attribution)
    assert not observation.quarantine_candidate


def test_profile_cannot_be_removed_or_mixed_after_sealing() -> None:
    index, edge = site()
    observation = probe(index, edge)
    with pytest.raises(StaticScoringError, match="static_scoring_policy_invalid"):
        score_static_epoch(
            [index.target],
            [index],
            [],
            [observation],
            validator_hotkey=VALIDATOR,
            epoch_index=ISSUED_EPOCH // 300,
            network="test",
            netuid=581,
        )
    document = model_document(observation, exclude={"observation_digest_sha256"})
    document["schema_version"] = 1
    document["observation_digest_sha256"] = digest(document)
    with pytest.raises(ValueError):
        parse_static_probe_observation(canonical_json(document) + b"\n")


def test_resealed_v2_success_cannot_become_miner_content_fault() -> None:
    index, edge = site()
    observation = probe(index, edge)
    document = model_document(observation, exclude={"observation_digest_sha256"})
    document.update(
        outcome="failure",
        failure_code="body_mismatch",
        attribution="miner",
        quarantine_candidate=True,
    )
    document["observation_digest_sha256"] = digest(document)
    with pytest.raises(ValueError, match="observation_content_fault_unproved"):
        StaticProbeObservation.model_validate(document)


def test_same_signed_wrong_answer_is_index_suspect_across_public_framing() -> None:
    index, edge = site()
    for endpoint in index.target.endpoints:
        edge.faults[endpoint.endpoint_id] = lambda state: state.update(
            body=b"X" * len(state["body"]),
            attested_body=b"X" * len(state["attested_body"]),
        )
    observations = [
        probe(
            index, edge, change="length" if position == 0 else "chunked", endpoint_position=position
        )
        for position in range(len(index.target.endpoints))
    ]
    assert {item.failure_code for item in observations} == {"body_mismatch"}
    assert len({item.response_header_sha256 for item in observations}) == 2
    epoch = score_static_epoch(
        [index.target],
        [index],
        [],
        observations,
        validator_hotkey=VALIDATOR,
        epoch_index=ISSUED_EPOCH // 300,
        min_attempts=1,
        network="test",
        netuid=581,
        public_transport_policy=policy(),
    )
    assert len(epoch.index_suspect_requests) == 1
    assert epoch.content_fault_evidence == []
    assert epoch.endpoint_actions == []
