# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic static scoring fixtures built from real validator probes.

Observations come from the validator's own hidden plan and evaluator against
the independent :class:`static_context.FakeStaticEdge` replica, so scoring
tests never hand-build the evidence they judge. Running this module directly
regenerates the committed static scoring ``contracts/fixtures`` and
``contracts/schemas`` entries.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from pydantic import BaseModel
from static_context import (
    FILES,
    ISSUED_EPOCH,
    SEED,
    SERVER,
    VALIDATOR,
    FakeStaticEdge,
    manifest_document,
    release_bytes,
    sha,
    site_digest,
    stored,
    target,
    trust_policy,
)

from misscomputer_subnet.contract_codec import model_bytes
from misscomputer_subnet.static_crawl import send_static_probe
from misscomputer_subnet.static_evidence import (
    StaticEdgeEvidence,
    StaticEvidenceRecord,
    append_static_evidence,
    seal_static_edge_evidence,
)
from misscomputer_subnet.static_index import VerifiedStaticIndex, ingest_static_index
from misscomputer_subnet.static_probe import StaticProbeObservation, plan_static_hidden_probes
from misscomputer_subnet.static_scoring import (
    StaticAvailabilityScore,
    StaticEpochScore,
    aggregate_static_window,
    score_static_epoch,
)

ROOT = Path(__file__).resolve().parents[2]
EPOCH_SECONDS = 300
EPOCH = ISSUED_EPOCH // EPOCH_SECONDS
TIMEOUT_MILLIS = 5_000

Fault = Callable[[dict[str, Any]], Any]


def verified_site(
    files: Mapping[str, tuple[bytes, str]] = FILES,
) -> tuple[VerifiedStaticIndex, FakeStaticEdge]:
    manifest = stored(manifest_document(files))
    site = site_digest(manifest)
    release = release_bytes(site)
    index = ingest_static_index(
        target(site, release),
        manifest,
        release,
        trust_policy(),
        pinned_server_implementation_digest=SERVER,
    )
    assert isinstance(index, VerifiedStaticIndex)
    return index, FakeStaticEdge(site, files=dict(files), endpoints=tuple(index.target.endpoints))


def hidden_epoch(
    index: VerifiedStaticIndex,
    edge: FakeStaticEdge,
    *,
    epoch: int = EPOCH,
    faults: Mapping[int, Fault] | None = None,
    ceiling_bytes: int | None = None,
) -> list[StaticProbeObservation]:
    """Fire one epoch's real hidden plan; ``faults`` keys are endpoint positions."""

    edge.faults = {
        index.target.endpoints[position].endpoint_id: fault
        for position, fault in (faults or {}).items()
    }
    extra = {} if ceiling_bytes is None else {"ceiling_bytes": ceiling_bytes}
    plan = plan_static_hidden_probes(
        seed=SEED,
        validator_hotkey=VALIDATOR,
        indexes=[index],
        epoch_index=epoch,
        horizon_start_epoch=0,
        horizon_end_epoch=ISSUED_EPOCH * 2,
        epoch_seconds=EPOCH_SECONDS,
        **extra,
    )
    return [
        send_static_probe(
            index,
            planned,
            edge,
            validator_hotkey=VALIDATOR,
            sign=lambda _message: b"\x01" * 64,
            issued_at_epoch=(planned.fire_at_millis or 0) // 1_000,
            timeout_millis=TIMEOUT_MILLIS,
            max_bytes=ceiling_bytes or 1_024 * 1_024,
            probe_port=443,
            edge_origin=None,
        )
        for planned in plan
    ]


def score(
    index: VerifiedStaticIndex,
    observations: list[StaticProbeObservation],
    *,
    epoch: int = EPOCH,
    **kw: Any,
) -> StaticEpochScore:
    return score_static_epoch(
        [index.target],
        [index],
        [],
        observations,
        validator_hotkey=VALIDATOR,
        epoch_index=epoch,
        epoch_seconds=EPOCH_SECONDS,
        **kw,
    )


def wrong_body(state: dict[str, Any]) -> None:
    if state["body"]:
        state["body"] = state["attested_body"] = b"x" * len(state["body"])


def edge_evidence(**overrides: Any) -> StaticEdgeEvidence:
    body = FILES["/assets/app.js"][0]
    document: dict[str, Any] = {
        "schema": "miss.computer/misscomputer-subnet/static-edge-evidence",
        "schema_version": 1,
        "stage": "ordinary_traffic",
        "edge_instance": "edge-1",
        "route_label": "site-a",
        "site_digest": "sha256:" + sha(b"site"),
        "release_digest": "sha256:" + sha(b"release"),
        "endpoint_id": f"site-a-5MinerA-g1-{sha(b'5MinerA')[:32]}",
        "generation": 1,
        "ticket_digest": "sha256:" + sha(b"ticket"),
        "receipt_digest": "sha256:" + sha(b"receipt"),
        "request_method": "GET",
        "request_path": "/assets/app.js",
        "expected_status": 200,
        "expected_header_sha256": sha(b"headers"),
        "expected_body_length": len(body),
        "expected_body_sha256": sha(body),
        "observed_status": 200,
        "observed_header_sha256": sha(b"headers"),
        "observed_body_length": len(body),
        "observed_body_sha256": sha(body),
        "upstream_marker": True,
        "attestation": None,
        "observed_at": "2027-01-15T08:00:00.25Z",
        "verdict": "pass",
    }
    document.update(overrides)
    return seal_static_edge_evidence(document)


SCHEMA_MODELS: dict[str, tuple[int, type[BaseModel]]] = {
    "static-epoch-score": (1, StaticEpochScore),
    "static-availability-score": (1, StaticAvailabilityScore),
    "static-evidence-record": (1, StaticEvidenceRecord),
    "static-edge-evidence": (1, StaticEdgeEvidence),
}


def fixture_documents() -> dict[str, bytes]:
    index, edge = verified_site()
    observations = hidden_epoch(index, edge, faults={1: wrong_body})
    epoch = score(index, observations)
    documents: dict[str, BaseModel] = {
        "static-epoch-score": epoch,
        "static-availability-score": aggregate_static_window([epoch]),
        "static-evidence-record": append_static_evidence(None, observations[0]),
        "static-edge-evidence": edge_evidence(),
    }
    return {stem: model_bytes(value, SCHEMA_MODELS[stem][1]) for stem, value in documents.items()}


def fixture_path(stem: str, *, schema: bool = False) -> Path:
    version = SCHEMA_MODELS[stem][0]
    group, suffix = ("schemas", ".schema.json") if schema else ("fixtures", ".json")
    return ROOT / "contracts" / group / f"{stem}.v{version}{suffix}"


def write_fixtures() -> None:
    from assignment_probe_context import schema_bytes

    for stem, rendered in fixture_documents().items():
        fixture_path(stem).write_bytes(rendered)
    for stem, (_, model) in SCHEMA_MODELS.items():
        fixture_path(stem, schema=True).write_bytes(schema_bytes(model))


if __name__ == "__main__":
    write_fixtures()
