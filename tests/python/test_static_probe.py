# SPDX-License-Identifier: AGPL-3.0-only
"""Targeted static probes: admission crawl, hidden sampling, and fault attribution."""

from __future__ import annotations

import itertools
from collections.abc import Callable
from typing import Any

import pytest
from static_context import (
    FILES,
    NOW,
    SEED,
    VALIDATOR,
    FakeStaticEdge,
    canonical_bytes,
    key,
    manifest_document,
    release_bytes,
    sha,
    target,
    trust_policy,
)

from misscomputer_subnet.assignment_probe import ProbeResponse, ProbeTransportFailure
from misscomputer_subnet.contract_codec import canonical_json
from misscomputer_subnet.static_crawl import (
    fetch_static_index_documents,
    parse_static_admission_record,
    run_static_admission_crawl,
    run_static_hidden_probes,
    send_static_probe,
    static_admission_record_bytes,
)
from misscomputer_subnet.static_index import (
    StaticIndexAbstention,
    VerifiedStaticIndex,
    ingest_static_index,
)
from misscomputer_subnet.static_probe import (
    PlannedStaticProbe,
    StaticCrawlBudget,
    StaticCrawlRefusal,
    parse_static_probe_observation,
    plan_static_admission_crawl,
    plan_static_hidden_probes,
    static_probe_coverage,
    static_probe_observation_bytes,
)

BUDGET = StaticCrawlBudget(
    max_requests=64,
    max_total_bytes=1_024 * 1_024,
    max_response_bytes=1_024 * 1_024,
    request_timeout_millis=5_000,
    max_duration_millis=60_000,
    max_concurrent_endpoints=3,
)


def site(
    files: dict[str, tuple[bytes, str]] = FILES,
) -> tuple[VerifiedStaticIndex, FakeStaticEdge]:
    manifest = canonical_bytes(manifest_document(files))
    digest = sha(manifest)
    index = ingest_static_index(
        target(digest), manifest, release_bytes(digest), trust_policy(), evaluation_epoch=NOW
    )
    assert isinstance(index, VerifiedStaticIndex)
    return index, FakeStaticEdge(digest, files=files)


def crawl(
    index: VerifiedStaticIndex, edge: FakeStaticEdge, budget: StaticCrawlBudget = BUDGET, **kw: Any
) -> list[Any]:
    return run_static_admission_crawl(
        index,
        [item.endpoint_id for item in index.target.endpoints],
        edge,
        budget,
        seed=SEED,
        validator_hotkey=VALIDATOR,
        sign=lambda _message: b"\x01" * 64,
        crawl_id=1,
        probe_port=443,
        wall_clock=lambda: float(NOW),
        **kw,
    )


def test_admission_crawls_every_indexed_response_on_every_incarnation() -> None:
    index, edge = site()

    results = crawl(index, edge)

    assert [record.verdict for record, _ in results] == ["admitted"] * 3
    for endpoint in index.target.endpoints:
        requested = {
            (method, path) for eid, method, path in edge.calls if eid == endpoint.endpoint_id
        }
        indexed = {
            ("GET", path)
            for path in ("/", "/app.js", "/docs/", "/docs/index.html", "/index.html", "/logo.png")
        }
        assert indexed | {("HEAD", "/")} <= requested
        synthetic = requested - indexed - {("HEAD", "/")}
        assert len(synthetic) == 2
        assert {path.endswith(".js") for _, path in synthetic} == {True, False}
    record, observations = results[0]
    assert record.completed_requests == record.planned_requests == 9
    assert record.observation_digests_sha256 == [
        item.observation_digest_sha256 for item in observations
    ]
    assert parse_static_admission_record(static_admission_record_bytes(record)) == record


def _wrong_body(state: dict[str, Any]) -> None:
    if state["body"]:
        state["body"] = state["attested_body"] = b"defaced"


def _wrong_status(state: dict[str, Any]) -> None:
    state["status"] = state["attested_status"] = 500


def _no_nosniff(state: dict[str, Any]) -> None:
    state["headers"] = [item for item in state["headers"] if item[0] != "x-content-type-options"]


def _replayed(state: dict[str, Any]) -> None:
    state["nonce"] = "ff" * 32


def _altered(state: dict[str, Any]) -> None:
    state["body"] = b"altered-in-transit"


def _unattested(state: dict[str, Any]) -> None:
    state["attest"] = False


def _edge_generated(state: dict[str, Any]) -> None:
    state["upstream"] = False
    state["status"] = 502


def _other_ticket(state: dict[str, Any]) -> None:
    state["ticket_digest"] = "sha256:" + sha(b"another ticket")


def _imposter(state: dict[str, Any]) -> None:
    state["signing_key"] = key("imposter")


def _timeout(_state: dict[str, Any]) -> ProbeTransportFailure:
    return ProbeTransportFailure("timeout", 5_001)


FAULTS: dict[str, tuple[Callable[[dict[str, Any]], Any], str, str, bool]] = {
    "attested wrong body": (_wrong_body, "body_mismatch", "miner", True),
    "attested wrong status": (_wrong_status, "status_mismatch", "miner", True),
    "missing nosniff": (_no_nosniff, "header_mismatch", "miner", False),
    "replayed or cached attestation": (_replayed, "cache_replay", "path", False),
    "altered after miner signed": (_altered, "content_altered_in_transit", "path", False),
    "no attestation": (_unattested, "attestation_missing", "miner", False),
    "edge-generated error": (_edge_generated, "edge_generated", "path", False),
    "fresh attestation naming another ticket": (_other_ticket, "attestation_fraud", "miner", False),
    "attestation not signed by service key": (_imposter, "attestation_invalid", "miner", False),
    "whole-request timeout": (_timeout, "timeout", "path", False),
}


@pytest.mark.parametrize("case", sorted(FAULTS))
def test_faults_are_attributed_to_miner_or_path(case: str) -> None:
    fault, code, attribution, quarantine = FAULTS[case]
    index, edge = site()
    faulty = index.target.endpoints[1].endpoint_id
    edge.faults[faulty] = fault

    results = crawl(index, edge)

    assert [record.verdict for record, _ in results] == ["admitted", "rejected", "admitted"]
    record, observations = results[1]
    failed = observations[-1]
    assert (record.failure_code, failed.failure_code) == (code, code)
    assert (failed.attribution, failed.quarantine_candidate) == (attribution, quarantine)
    assert all(item.outcome == "success" for item in observations[:-1])
    assert parse_static_probe_observation(static_probe_observation_bytes(failed)) == failed


def test_admission_stops_an_incarnation_at_its_first_failure() -> None:
    index, edge = site()
    faulty = index.target.endpoints[0].endpoint_id
    edge.faults[faulty] = _unattested

    record, observations = crawl(index, edge)[0]

    assert record.completed_requests == len(observations) == 1
    assert record.planned_requests == 9
    assert len([call for call in edge.calls if call[0] == faulty]) == 1


def test_crawl_over_budget_is_refused_without_any_request() -> None:
    index, edge = site()
    tight = BUDGET.model_copy(update={"max_total_bytes": 100})

    results = crawl(index, edge, tight)

    assert [(record.verdict, record.completed_requests) for record, _ in results] == [
        ("refused", 0)
    ] * 3
    assert edge.calls == []
    refusal = plan_static_admission_crawl(
        index,
        index.target.endpoints[0].endpoint_id,
        tight,
        seed=SEED,
        validator_hotkey=VALIDATOR,
        crawl_id=1,
    )
    assert isinstance(refusal, StaticCrawlRefusal)
    assert refusal.required_requests == 9


def test_crawl_past_its_deadline_is_incomplete_not_admitted() -> None:
    index, edge = site()
    ticks = itertools.count(0.0, 20.0)

    results = crawl(index, edge, clock=lambda: next(ticks))

    assert {record.verdict for record, _ in results} == {"incomplete"}
    assert all(0 < record.completed_requests < record.planned_requests for record, _ in results)


def test_crawl_runs_at_most_the_configured_incarnations_at_once() -> None:
    index, edge = site()
    edge.hold_seconds = 0.02

    crawl(index, edge, BUDGET.model_copy(update={"max_concurrent_endpoints": 2}))

    assert edge.max_active == 2


def test_missing_index_fetch_abstains_instead_of_probing() -> None:
    manifest = canonical_bytes(manifest_document())
    digest = sha(manifest)

    class Store:
        def fetch(self, *, url: str, **_: Any) -> ProbeResponse:
            if url.endswith("manifest.json"):
                return ProbeResponse(404, (), b"not found", 3, None)
            return ProbeResponse(200, (), release_bytes(digest), 3, None)

    manifest_bytes, release = fetch_static_index_documents(
        Store(),  # type: ignore[arg-type]
        manifest_url="https://index.example/manifest.json",
        release_url="https://index.example/release.json",
        server_name="index.example",
    )
    result = ingest_static_index(
        target(digest), manifest_bytes, release, trust_policy(), evaluation_epoch=NOW
    )

    assert result == StaticIndexAbstention("site-a", digest, "index_unavailable")


def _hidden(
    index: VerifiedStaticIndex, seed: bytes, epochs: range, **kw: Any
) -> list[PlannedStaticProbe]:
    return [
        probe
        for epoch in epochs
        for probe in plan_static_hidden_probes(
            seed=seed,
            validator_hotkey=VALIDATOR,
            indexes=[index],
            epoch_index=epoch,
            horizon_start_epoch=0,
            horizon_end_epoch=NOW * 2,
            **kw,
        )
    ]


def test_hidden_probes_are_seed_derived_and_never_exceed_the_ceiling() -> None:
    large = b"x" * 2_048
    index, _ = site({**FILES, "/video.bin": (large, "application/octet-stream")})
    epochs = range(6_000_000, 6_000_060)

    plan = _hidden(index, SEED, epochs, ceiling_bytes=1_024)

    assert plan == _hidden(index, SEED, epochs, ceiling_bytes=1_024)
    other = _hidden(index, bytes(32), epochs, ceiling_bytes=1_024)
    assert [(p.fire_at_millis, p.path) for p in plan] != [(p.fire_at_millis, p.path) for p in other]
    assert len({p.nonce for p in plan}) == len(plan) == 60 * 3 * 3
    assert all(p.expected_content_length <= 1_024 for p in plan if p.method == "GET")
    kinds = {p.expected_kind for p in plan}
    assert {"file", "directory_index", "navigation_fallback", "not_found"} <= kinds
    assert ("HEAD", "/video.bin") in {(p.method, p.path) for p in plan}
    assert all(p.path not in index.routes for p in plan if p.expected_kind == "not_found")


def test_hidden_probes_stay_inside_the_manifest_horizon() -> None:
    index, _ = site()
    epoch = 6_000_000
    start = epoch * 300

    plan = plan_static_hidden_probes(
        seed=SEED,
        validator_hotkey=VALIDATOR,
        indexes=[index],
        epoch_index=epoch,
        horizon_start_epoch=start + 100,
        horizon_end_epoch=start + 200,
    )

    assert plan
    assert all((start + 100) * 1_000 <= p.fire_at_millis < (start + 200) * 1_000 for p in plan)  # type: ignore[operator]


def test_coverage_reports_responses_only_head_checked_by_hidden_probes() -> None:
    index, _ = site({**FILES, "/video.bin": (b"x" * 2_048, "application/octet-stream")})

    coverage = static_probe_coverage(index, ceiling_bytes=1_024)

    assert (
        coverage.indexed_responses,
        coverage.hidden_byte_checked_responses,
        coverage.hidden_head_only_responses,
        coverage.hidden_head_only_bytes,
    ) == (7, 6, 1, 2_048)


def test_hidden_runner_skips_probes_it_can_no_longer_send_on_time() -> None:
    index, edge = site()
    plan = _hidden(index, SEED, range(6_000_000, 6_000_001))
    late = plan[0].fire_at_millis + 10_001  # type: ignore[operator]

    observations, skipped = run_static_hidden_probes(
        plan,
        {"site-a": index},
        edge,
        validator_hotkey=VALIDATOR,
        sign=lambda _message: b"\x01" * 64,
        epoch_end_millis=(6_000_001) * 300_000,
        timeout_millis=5_000,
        probe_port=443,
        clock=lambda: late / 1_000,
        sleep=lambda _seconds: None,
    )

    fired = [p for p in plan if late - p.fire_at_millis <= 10_000]  # type: ignore[operator]
    assert skipped == len(plan) - len(fired)
    assert [o.probe_nonce for o in observations] == [p.nonce for p in fired]
    assert all(o.outcome == "success" and o.probe_kind == "hidden" for o in observations)


def test_sealed_observation_refuses_a_rewritten_outcome() -> None:
    index, edge = site()
    edge.faults[index.target.endpoints[0].endpoint_id] = _wrong_body
    plan = plan_static_admission_crawl(
        index,
        index.target.endpoints[0].endpoint_id,
        BUDGET,
        seed=SEED,
        validator_hotkey=VALIDATOR,
        crawl_id=1,
    )
    assert isinstance(plan, list)
    probe = next(p for p in plan if p.path == "/app.js")
    failed = send_static_probe(
        index,
        probe,
        edge,
        validator_hotkey=VALIDATOR,
        sign=lambda _message: b"\x01" * 64,
        issued_at_epoch=NOW,
        timeout_millis=5_000,
        max_bytes=1_024,
        probe_port=443,
        edge_origin=None,
    )
    document = failed.model_dump(mode="json", by_alias=True)
    document.update(
        outcome="success", failure_code=None, attribution="none", quarantine_candidate=False
    )

    with pytest.raises(ValueError, match="document_invalid"):
        parse_static_probe_observation(canonical_json(document) + b"\n")
