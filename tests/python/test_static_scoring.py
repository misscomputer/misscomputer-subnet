# SPDX-License-Identifier: AGPL-3.0-only
"""Static-site scoring, evidence journal, and edge evidence contracts."""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from fractions import Fraction
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError
from static_context import FILES, VALIDATOR, sha
from static_scoring_context import (
    EPOCH,
    SCHEMA_MODELS,
    edge_evidence,
    fixture_documents,
    fixture_path,
    hidden_epoch,
    score,
    targeted,
    verified_site,
    wrong_body,
)

from misscomputer_subnet.assignment_probe import ProbeTransportFailure
from misscomputer_subnet.contract_codec import digest, model_document
from misscomputer_subnet.static_evidence import (
    StaticEvidenceJournal,
    parse_static_edge_evidence,
    parse_static_evidence_record,
)
from misscomputer_subnet.static_index import StaticDeploymentTarget, StaticIndexAbstention
from misscomputer_subnet.static_probe import StaticProbeObservation
from misscomputer_subnet.static_scoring import (
    StaticEpochScore,
    StaticScoringError,
    aggregate_static_window,
    parse_static_availability_score,
    parse_static_epoch_score,
    replay_static_epoch_score,
    score_static_epoch,
    static_epoch_score_bytes,
)

PARSERS: dict[str, Callable[[bytes], Any]] = {
    "static-epoch-score": parse_static_epoch_score,
    "static-availability-score": parse_static_availability_score,
    "static-evidence-record": parse_static_evidence_record,
    "static-edge-evidence": parse_static_edge_evidence,
}


def _wrong_status(state: dict[str, Any]) -> None:
    state["status"] = state["attested_status"] = 500


def _replayed(state: dict[str, Any]) -> None:
    state["nonce"] = "ff" * 32


def _altered(state: dict[str, Any]) -> None:
    if state["body"]:
        state["body"] = b"y" * len(state["body"])


def _other_ticket(state: dict[str, Any]) -> None:
    state["ticket_digest"] = "sha256:" + sha(b"another ticket")


def _no_nosniff(state: dict[str, Any]) -> None:
    headers = [item for item in state["headers"] if item[0].lower() != "x-content-type-options"]
    state["headers"] = state["attested_headers"] = headers


def _timeout(_state: dict[str, Any]) -> ProbeTransportFailure:
    return ProbeTransportFailure("timeout", 5_001)


def _reseal(value: StaticProbeObservation, **changes: Any) -> StaticProbeObservation:
    document = {**model_document(value, exclude={"observation_digest_sha256"}), **changes}
    return StaticProbeObservation.model_validate(
        {**document, "observation_digest_sha256": digest(document)}
    )


@pytest.mark.parametrize("stem", sorted(SCHEMA_MODELS))
def test_generated_schema_and_golden_fixture_are_pinned(stem: str) -> None:
    schema = json.loads(fixture_path(stem, schema=True).read_text())
    Draft202012Validator.check_schema(schema)
    fixture_bytes = fixture_path(stem).read_bytes()
    Draft202012Validator(schema).validate(json.loads(fixture_bytes))
    assert isinstance(PARSERS[stem](fixture_bytes), SCHEMA_MODELS[stem][1])
    rendered = json.dumps(
        SCHEMA_MODELS[stem][1].model_json_schema(), indent=2, sort_keys=True, ensure_ascii=True
    )
    current_schema = fixture_path(stem, schema=True)
    if stem == "static-evidence-record":
        # Historical v1 schemas stay frozen; the current parser also accepts
        # profile-bound v2 records, whose schema is archived separately.
        current_schema = current_schema.with_name(f"{stem}.v2.schema.json")
    if stem == "static-epoch-score":
        # v1 and v2 stay frozen; the current parser also accepts
        # revocation-bound v3 records, whose schema is archived separately.
        current_schema = current_schema.with_name(f"{stem}.v3.schema.json")
    assert current_schema.read_bytes() == (rendered + "\n").encode("ascii")
    assert fixture_bytes == fixture_documents()[stem]


def test_honest_epoch_is_scored_bound_and_replayable() -> None:
    index, edge = verified_site()
    observations = hidden_epoch(index, edge)

    record = score(index, observations)

    assert record.epoch_status == "scored"
    assert [(item.disposition, item.successes, item.attempts) for item in record.endpoints] == [
        ("eligible", 3, 3)
    ] * 3
    assert record.endpoint_actions == record.alerts == record.content_fault_evidence == []
    rendered = static_epoch_score_bytes(record)
    assert parse_static_epoch_score(rendered) == record
    reordered = score(index, list(reversed(observations)))
    assert static_epoch_score_bytes(reordered) == rendered
    assert replay_static_epoch_score(record, [index]) == record


def test_testnet_static_epoch_and_window_keep_the_testnet_pair() -> None:
    index, edge = verified_site()
    observations = hidden_epoch(index, edge)

    epoch = score(index, observations, network="test", netuid=581)
    window = aggregate_static_window([epoch])

    assert (epoch.network, epoch.netuid) == ("test", 581)
    assert (window.network, window.netuid) == ("test", 581)
    assert replay_static_epoch_score(epoch, [index]) == epoch
    assert parse_static_epoch_score(static_epoch_score_bytes(epoch)) == epoch
    with pytest.raises(ValueError, match="static_subnet_invalid"):
        score(index, observations, network="test", netuid=24)
    mainnet_next = score(index, hidden_epoch(index, edge, epoch=EPOCH + 1), epoch=EPOCH + 1)
    with pytest.raises(StaticScoringError, match="static_scoring_network_mismatch"):
        aggregate_static_window([epoch, mainnet_next])


# fault -> (failure code, attribution, content fault charged, fraud, alert)
FAULTS: dict[str, tuple[Callable[[dict[str, Any]], Any], str, str, bool, bool, str | None]] = {
    "attested wrong body": (
        wrong_body,
        "body_mismatch",
        "miner",
        True,
        False,
        "static_content_fault",
    ),
    "attested wrong status": (
        _wrong_status,
        "status_mismatch",
        "miner",
        True,
        False,
        "static_content_fault",
    ),
    "cached or replayed attestation": (
        _replayed,
        "cache_replay",
        "path",
        False,
        False,
        "static_replay_observed",
    ),
    "altered after the miner signed": (
        _altered,
        "content_altered_in_transit",
        "path",
        False,
        False,
        "static_path_tampering",
    ),
    "fresh attestation naming another ticket": (
        _other_ticket,
        "attestation_fraud",
        "miner",
        False,
        True,
        "static_attestation_fraud",
    ),
    "attested wrong normative header": (
        _no_nosniff,
        "header_mismatch",
        "miner",
        True,
        False,
        "static_content_fault",
    ),
}


@pytest.mark.parametrize("case", sorted(FAULTS))
def test_faults_become_distinct_evidence_actions_and_alerts(case: str) -> None:
    fault, code, attribution, content_fault, fraud, alert = FAULTS[case]
    index, edge = verified_site()
    observations = hidden_epoch(index, edge, faults={1: fault})
    failing = [item for item in observations if item.outcome == "failure"]
    assert failing and {(item.failure_code, item.attribution) for item in failing} == {
        (code, attribution)
    }

    record = score(index, observations)

    faulty = record.endpoints[1]
    assert faulty.disposition == "eligible"
    assert faulty.successes == faulty.attempts - len(failing)
    assert faulty.content_faults == (len(failing) if content_fault else 0)
    assert faulty.fraudulent_attestations == (len(failing) if fraud else 0)
    assert [row.endpoint_id for row in record.content_fault_evidence] == (
        [faulty.endpoint_id] * len(failing) if content_fault else []
    )
    actions = [
        (row.endpoint_id, row.reason, row.quarantine, row.trust_zero)
        for row in record.endpoint_actions
    ]
    if content_fault:
        assert actions == [(faulty.endpoint_id, "content_fault", True, False)]
    elif fraud:
        assert actions == [(faulty.endpoint_id, "attestation_fraud", True, True)]
    else:
        assert actions == []
    assert [(row.code, row.endpoint_id) for row in record.alerts] == (
        [(alert, faulty.endpoint_id)] if alert else []
    )
    assert replay_static_epoch_score(record, [index]) == record


def _other_bytes(state: dict[str, Any]) -> None:
    if state["body"]:
        state["body"] = state["attested_body"] = b"y" * len(state["body"])


_WRONG, _PASS = wrong_body, None
# name -> (requests as (endpoint position, path, fault), charged positions, suspect paths)
INDEX_CASES: dict[str, tuple[list[tuple[int, str, Any]], list[int], list[str]]] = {
    "two colluding replicas while the third serves the index": (
        [(0, "/index.html", _WRONG), (1, "/index.html", _WRONG), (2, "/index.html", _PASS)],
        [0, 1],
        [],
    ),
    "every replica returns the same wrong response": (
        [(0, "/index.html", _WRONG), (1, "/index.html", _WRONG), (2, "/index.html", _WRONG)],
        [],
        ["/index.html"],
    ),
    "suspicion covers only the agreeing request": (
        [
            (0, "/index.html", _WRONG),
            (1, "/index.html", _WRONG),
            (2, "/index.html", _WRONG),
            (0, "/assets/app.js", _other_bytes),
        ],
        [0],
        ["/index.html"],
    ),
}


@pytest.mark.parametrize("case", sorted(INDEX_CASES))
def test_faults_are_charged_unless_every_replica_agrees_on_the_request(case: str) -> None:
    requests, charged, suspect = INDEX_CASES[case]
    index, edge = verified_site()
    passes = [(position, "/docs/index.html", None) for position in range(3)]

    record = score(index, targeted(index, edge, [*requests, *passes, *passes]))

    endpoints = index.target.endpoints
    assert [row.endpoint_id for row in record.endpoint_actions] == [
        endpoints[position].endpoint_id for position in charged
    ]
    assert [
        (row.deployment_id, row.request_method, row.request_path)
        for row in record.index_suspect_requests
    ] == [("site-a", "GET", path) for path in suspect]
    assert replay_static_epoch_score(record, [index]) == record


def test_a_shared_path_outage_charges_no_content_fault() -> None:
    index, edge = verified_site()
    requests = [
        (0, "/index.html", _timeout),
        (0, "/docs/index.html", _timeout),
        (1, "/index.html", _timeout),
        (1, "/docs/index.html", _timeout),
        (2, "/index.html", wrong_body),
        (2, "/docs/index.html", None),
    ]

    record = score(index, targeted(index, edge, requests))

    assert record.epoch_status == "common_mode_unavailable"
    assert record.endpoint_actions == [] and record.content_fault_evidence == []


def test_shared_path_outage_abstains_instead_of_scoring_miners_down() -> None:
    index, edge = verified_site()
    observations = hidden_epoch(index, edge, faults={0: _timeout, 1: _timeout})

    record = score(index, observations)

    assert record.epoch_status == "common_mode_unavailable"
    assert {item.disposition for item in record.endpoints} == {"excluded_common_mode"}
    assert [row.code for row in record.alerts] == ["static_common_mode"]
    window = aggregate_static_window([record])
    assert window.miners == [] and window.abstained_epochs == [EPOCH]


def _other_target(site_digest: str) -> StaticDeploymentTarget:
    index, _ = verified_site()
    document = model_document(index.target)
    document["deployment_id"] = "site-b"
    document["route_host"] = "site-b.on.miss.computer"
    document["site_digest"] = site_digest
    document["release_digest"] = "sha256:" + sha(b"unpublished release")
    for endpoint in document["endpoints"]:  # type: ignore[attr-defined]
        endpoint["endpoint_id"] = endpoint["endpoint_id"].replace("site-a-", "site-b-", 1)
    return StaticDeploymentTarget.model_validate(document)


def test_unavailable_index_abstains_and_is_never_scored_zero() -> None:
    index, edge = verified_site()
    observations = hidden_epoch(index, edge)
    other = _other_target("sha256:" + sha(b"unpublished site"))
    abstention = StaticIndexAbstention("site-b", other.site_digest, "index_unavailable")

    record = score_static_epoch(
        [index.target, other],
        [index],
        [abstention],
        observations,
        validator_hotkey=VALIDATOR,
        epoch_index=EPOCH,
    )

    abstained = [item for item in record.endpoints if item.deployment_id == "site-b"]
    assert [item.disposition for item in abstained] == ["abstain_index"] * 3
    assert [(row.code, row.record_code) for row in record.index_abstentions] == [
        ("index_unavailable", "static_index_unavailable")
    ]
    assert ("static_index_unavailable", "site-b") in {
        (row.code, row.deployment_id) for row in record.alerts
    }
    availability = {
        item.miner_hotkey: (item.eligible_endpoint_epochs, item.availability_numerator)
        for item in aggregate_static_window([record]).miners
    }
    # Each miner is scored only from site-a; the abstained site adds no zero epoch.
    assert set(availability.values()) == {(1, 1)}
    with pytest.raises(StaticScoringError, match="static_scoring_index_state_invalid"):
        score_static_epoch(
            [index.target, other],
            [index],
            [],
            observations,
            validator_hotkey=VALIDATOR,
            epoch_index=EPOCH,
        )


def test_forged_expectations_and_laundered_fraud_refuse_the_epoch() -> None:
    index, edge = verified_site()
    faulted = hidden_epoch(index, edge, faults={1: wrong_body})
    fault = next(item for item in faulted if item.failure_code == "body_mismatch")
    # A validator claiming the wrong bytes were expected cannot turn a fault into a pass.
    forged = _reseal(
        fault,
        expected_body_sha256=fault.response_body_sha256,
        outcome="success",
        failure_code=None,
        attribution="none",
        quarantine_candidate=False,
    )
    with pytest.raises(StaticScoringError, match="static_scoring_expectation_mismatch"):
        score(index, [forged if item is fault else item for item in faulted])

    frauds = hidden_epoch(index, edge, faults={1: _other_ticket})
    fraud = next(item for item in frauds if item.failure_code == "attestation_fraud")
    laundered = _reseal(
        fraud, attestation_status="replayed", failure_code="cache_replay", attribution="path"
    )
    with pytest.raises(StaticScoringError, match="static_scoring_attestation_unverified"):
        score(index, [laundered if item is fraud else item for item in frauds])

    honest = hidden_epoch(index, edge)
    admission = _reseal(honest[0], probe_kind="admission")
    with pytest.raises(StaticScoringError, match="static_scoring_probe_kind_invalid"):
        score(index, [admission, *honest[1:]])


def test_hidden_probes_above_the_ceiling_are_refused() -> None:
    index, edge = verified_site()
    observations = hidden_epoch(index, edge)
    smallest = min(item.content_length for item in index.responses)

    with pytest.raises(StaticScoringError, match="static_scoring_body_over_ceiling"):
        score(index, observations, probe_body_ceiling=max(smallest - 1, 1))


def test_coverage_reports_what_the_ceiling_leaves_to_head_and_edge_checks() -> None:
    index, edge = verified_site({**FILES, "/video.mp4": (b"v" * 2_048, "video/mp4")})
    observations = hidden_epoch(index, edge, ceiling_bytes=1_024)

    (row,) = score(index, observations, probe_body_ceiling=1_024).coverage

    sizes = [item.content_length for item in index.routes.values()]
    assert (row.routes_total, row.bytes_total) == (len(sizes), sum(sizes))
    assert row.bytes_get_eligible == row.bytes_total - 2_048
    indexed = {"file", "directory_index"}
    probed = {item.request_path for item in observations if item.expected_kind in indexed}
    get_paths = {
        item.request_path
        for item in observations
        if item.request_method == "GET" and item.expected_kind in indexed
    }
    assert (row.routes_probed, row.routes_body_verified) == (len(probed), len(get_paths))
    assert "/video.mp4" not in get_paths


def test_record_whose_numbers_do_not_follow_from_evidence_is_rejected() -> None:
    index, edge = verified_site()
    record = score(index, hidden_epoch(index, edge, faults={1: wrong_body}))
    document = model_document(record, exclude={"epoch_score_digest_sha256"})
    document["endpoint_actions"] = []
    document["epoch_score_digest_sha256"] = digest(document)

    with pytest.raises(ValidationError, match="static_epoch_endpoint_actions_mismatch"):
        StaticEpochScore.model_validate(document)


def test_window_is_the_mean_of_eligible_endpoint_epochs() -> None:
    index, edge = verified_site()
    first = score(index, hidden_epoch(index, edge, faults={1: wrong_body}))
    second_epoch = EPOCH + 1
    second = score(
        index,
        hidden_epoch(index, edge, epoch=second_epoch, faults={1: _timeout}),
        epoch=second_epoch,
    )

    window = aggregate_static_window([second, first])

    miner_b = next(item for item in window.miners if item.miner_hotkey == "5MinerB")
    expected = (
        sum(
            (
                Fraction(item.successes, item.attempts)
                for epoch in (first, second)
                for item in epoch.endpoints
                if item.miner_hotkey == "5MinerB"
            ),
            Fraction(0),
        )
        / 2
    )
    assert Fraction(miner_b.availability_numerator, miner_b.availability_denominator) == expected
    faults = sum(item.content_faults for item in first.endpoints if item.miner_hotkey == "5MinerB")
    assert faults > 0
    assert (miner_b.eligible_endpoint_epochs, miner_b.content_faults) == (2, faults)
    assert window.epoch_indexes == [EPOCH, second_epoch]


def test_journal_is_durable_append_only_and_refuses_tampering(tmp_path: Any) -> None:
    index, edge = verified_site()
    observations = hidden_epoch(index, edge)
    path = str(tmp_path / "evidence.jsonl")
    with StaticEvidenceJournal(path) as journal:
        journal.append(observations[0])
        journal.append(observations[1])
        with pytest.raises(ValueError, match="static_evidence_nonce_reused"):
            journal.append(observations[1])
    with StaticEvidenceJournal(path) as reopened:
        assert reopened.observations == tuple(observations[:2])
        record = reopened.append(observations[2])
        assert record.record_index == 3
        assert record.prior_record_digest_sha256 == reopened.records[1].record_digest_sha256
    assert os.stat(path).st_mode & 0o777 == 0o600

    rendered = open(path, "rb").read()  # noqa: SIM115
    lines = rendered.split(b"\n")
    for tampered in (
        rendered[:-5],  # torn tail
        b"\n".join([lines[0], lines[2], lines[1], b""]),  # reordered
        rendered.replace(b'"latency_millis":5', b'"latency_millis":6', 1),  # edited
    ):
        with open(path, "wb") as handle:
            handle.write(tampered)
        with pytest.raises(ValueError, match="static_evidence_journal_invalid"):
            StaticEvidenceJournal(path)

    os.chmod(path, 0o644)
    with pytest.raises(ValueError, match="static_evidence_journal_unsafe"):
        StaticEvidenceJournal(path)


@pytest.mark.parametrize(
    ("changes", "verdict"),
    [
        ({}, "pass"),
        ({"observed_body_sha256": sha(b"defaced"), "verdict": "content_fault"}, "content_fault"),
        ({"upstream_marker": False, "verdict": "path_fault"}, "path_fault"),
        ({"observed_status": None, "verdict": "path_fault"}, "path_fault"),
    ],
)
def test_edge_evidence_verdict_must_follow_from_its_facts(
    changes: dict[str, Any], verdict: str
) -> None:
    assert edge_evidence(**changes).verdict == verdict
    lying = "pass" if verdict != "pass" else "content_fault"
    with pytest.raises(ValidationError, match="static_edge_evidence_verdict_invalid"):
        edge_evidence(**{**changes, "verdict": lying})


def test_edge_evidence_attestation_must_name_the_checked_request() -> None:
    index, edge = verified_site()
    attestation = next(
        item.attestation for item in hidden_epoch(index, edge) if item.attestation is not None
    )
    assert attestation is not None
    with pytest.raises(ValidationError, match="static_edge_evidence_attestation_unbound"):
        edge_evidence(attestation=model_document(attestation), request_path="/unrelated")
