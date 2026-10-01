# SPDX-License-Identifier: AGPL-3.0-only
"""Durable static-site evidence: the validator journal and the edge evidence record.

Two records are defined here; neither judges a response itself.

``static-evidence-record`` v1 (validator-local, durable)
    One append-only, hash-chained journal entry wrapping one sealed
    ``static-probe-observation`` v1 produced by
    :func:`misscomputer_subnet.static_probe.evaluate_static_probe`. The chain
    (``record_index`` and ``prior_record_digest_sha256``) makes a gap, fork,
    reorder or edit detectable, and :class:`StaticEvidenceJournal` fsyncs each
    entry before reporting it durable, so the evidence behind a score, a
    quarantine recommendation or an alert survives a crash and can be replayed
    by :func:`misscomputer_subnet.static_scoring.score_static_epoch`.

``static-edge-evidence`` v1 (edge → operators/auditors, durable)
    The record schema the static-site contract (§10.4) assigns to scoring for
    every edge admission-crawl or ordinary-traffic check of a static response:
    edge instance, route label, site and release, endpoint incarnation,
    ticket and receipt, request, expected and observed status, normative
    header digest, length and body SHA-256, upstream marker, attestation (if
    any), time, and a verdict that must follow from the recorded facts. The
    private edge produces it; this public schema is the byte contract.

This module is pure apart from :class:`StaticEvidenceJournal`, which owns one
append-only local file. It has no clock, network, environment, wallet, chain,
randomness, or signing capability.
"""

from __future__ import annotations

import os
import stat
from collections.abc import Sequence
from typing import Annotated, Final, Literal, Self

from pydantic import Field, StringConstraints, model_validator

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
    Digest,
    EndpointID,
    HealthPath,
    Hex64,
    MinerProbeAttestationV2,
    PositiveCount,
    RouteLabel,
    Timestamp,
)
from .static_index import MAX_FILE_BYTES
from .static_probe import StaticProbeObservation, static_probe_observation_bytes

STATIC_EVIDENCE_RECORD_SCHEMA: Final = "miss.computer/misscomputer-subnet/static-evidence-record"
STATIC_EDGE_EVIDENCE_SCHEMA: Final = "miss.computer/misscomputer-subnet/static-edge-evidence"
MAX_EVIDENCE_JOURNAL_BYTES: Final = 256 * 1_024 * 1_024
MAX_EVIDENCE_RECORD_BYTES: Final = 64 * 1_024
MAX_EVIDENCE_RECORDS: Final = 1 << 20

FileLength = Annotated[int, Field(ge=0, le=MAX_FILE_BYTES)]


# --------------------------------------------------------------------------
# Edge evidence (static-site contract §10.4)
# --------------------------------------------------------------------------


class StaticEdgeEvidence(StrictFrozenModel):
    """``static-edge-evidence`` v1: one durable edge check of one static response.

    ``verdict`` must follow from the facts: ``pass`` needs a complete
    replica-marked response equal to the expectation; ``content_fault`` a
    complete replica-marked response that differs from it; ``path_fault``
    anything incomplete or not replica-marked. Digests use the contract's
    ``sha256:``-prefixed ``site_digest``/``release_digest`` form.
    """

    contract_schema: Literal["miss.computer/misscomputer-subnet/static-edge-evidence"] = Field(
        alias="schema"
    )
    schema_version: Literal[1]
    stage: Literal["admission_crawl", "ordinary_traffic"]
    edge_instance: Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9._-]{1,128}$")]
    route_label: RouteLabel
    site_digest: Digest
    release_digest: Digest
    endpoint_id: EndpointID
    generation: PositiveCount
    ticket_digest: Digest
    receipt_digest: Digest
    request_method: Literal["GET", "HEAD"]
    request_path: HealthPath
    expected_status: int = Field(ge=100, le=599)
    expected_header_sha256: Hex64
    expected_body_length: FileLength
    expected_body_sha256: Hex64
    observed_status: int | None = Field(ge=100, le=599)
    observed_header_sha256: Hex64 | None
    observed_body_length: FileLength | None
    observed_body_sha256: Hex64 | None
    upstream_marker: bool
    attestation: MinerProbeAttestationV2 | None
    observed_at: Timestamp
    verdict: Literal["content_fault", "pass", "path_fault"]
    evidence_digest_sha256: Hex64

    @model_validator(mode="after")
    def verdict_follows_from_facts(self) -> Self:
        observed = (
            self.observed_status,
            self.observed_header_sha256,
            self.observed_body_length,
            self.observed_body_sha256,
        )
        expected = (
            self.expected_status,
            self.expected_header_sha256,
            self.expected_body_length,
            self.expected_body_sha256,
        )
        complete = self.upstream_marker and None not in observed
        derived = "pass" if observed == expected else "content_fault"
        if not complete:
            derived = "path_fault"
        if self.verdict != derived:
            raise ValueError("static_edge_evidence_verdict_invalid")
        if self.attestation is not None and (
            self.attestation.endpoint_id != self.endpoint_id
            or self.attestation.request_path != self.request_path
            or self.attestation.request_method != self.request_method
        ):
            raise ValueError("static_edge_evidence_attestation_unbound")
        verify_model_digest(self, "evidence_digest_sha256")
        return self


def seal_static_edge_evidence(document: dict[str, object]) -> StaticEdgeEvidence:
    return StaticEdgeEvidence.model_validate(
        {**document, "evidence_digest_sha256": digest(document)}
    )


def static_edge_evidence_bytes(value: StaticEdgeEvidence) -> bytes:
    return model_bytes(value, StaticEdgeEvidence)


def parse_static_edge_evidence(rendered: bytes) -> StaticEdgeEvidence:
    return parse_model(
        rendered,
        StaticEdgeEvidence,
        static_edge_evidence_bytes,
        maximum_bytes=MAX_EVIDENCE_RECORD_BYTES,
    )


# --------------------------------------------------------------------------
# Durable, hash-chained validator evidence journal
# --------------------------------------------------------------------------


class StaticEvidenceRecord(StrictFrozenModel):
    """``static-evidence-record`` v1: one journal entry chained to its predecessor."""

    contract_schema: Literal["miss.computer/misscomputer-subnet/static-evidence-record"] = Field(
        alias="schema"
    )
    schema_version: Literal[1]
    record_index: int = Field(ge=1, le=MAX_EVIDENCE_RECORDS)
    prior_record_digest_sha256: Hex64 | None
    observation: StaticProbeObservation
    record_digest_sha256: Hex64

    @model_validator(mode="after")
    def canonical_record(self) -> Self:
        if (self.record_index == 1) != (self.prior_record_digest_sha256 is None):
            raise ValueError("static_evidence_link_invalid")
        verify_model_digest(self, "record_digest_sha256")
        return self


def append_static_evidence(
    prior: StaticEvidenceRecord | None, observation: StaticProbeObservation
) -> StaticEvidenceRecord:
    """The record that appends ``observation`` after ``prior`` (``None`` starts a journal)."""

    value = revalidate(observation, StaticProbeObservation)
    previous = None if prior is None else revalidate(prior, StaticEvidenceRecord)
    if previous is not None and (
        previous.observation.validator_hotkey != value.validator_hotkey
        or previous.record_index >= MAX_EVIDENCE_RECORDS
    ):
        raise ValueError("static_evidence_append_invalid")
    document: dict[str, object] = {
        "schema": STATIC_EVIDENCE_RECORD_SCHEMA,
        "schema_version": 1,
        "record_index": 1 if previous is None else previous.record_index + 1,
        "prior_record_digest_sha256": None if previous is None else previous.record_digest_sha256,
        "observation": model_document(value),
    }
    return StaticEvidenceRecord.model_validate(
        {**document, "record_digest_sha256": digest(document)}
    )


def verify_static_evidence_chain(records: Sequence[StaticEvidenceRecord]) -> None:
    """Refuse a journal with a gap, fork, reorder, foreign validator, or reused nonce."""

    previous: StaticEvidenceRecord | None = None
    nonces: set[str] = set()
    for item in records:
        value = revalidate(item, StaticEvidenceRecord)
        expected_index = 1 if previous is None else previous.record_index + 1
        expected_prior = None if previous is None else previous.record_digest_sha256
        if (
            value.record_index != expected_index
            or value.prior_record_digest_sha256 != expected_prior
            or (
                previous is not None
                and value.observation.validator_hotkey != previous.observation.validator_hotkey
            )
            or value.observation.probe_nonce in nonces
        ):
            raise ValueError("static_evidence_chain_invalid")
        nonces.add(value.observation.probe_nonce)
        previous = value


def static_evidence_record_bytes(value: StaticEvidenceRecord) -> bytes:
    return model_bytes(value, StaticEvidenceRecord)


def parse_static_evidence_record(rendered: bytes) -> StaticEvidenceRecord:
    return parse_model(
        rendered,
        StaticEvidenceRecord,
        static_evidence_record_bytes,
        maximum_bytes=MAX_EVIDENCE_RECORD_BYTES,
    )


class StaticEvidenceJournal:
    """One owner-only, append-only, fsynced file of canonical evidence records.

    Opening verifies the complete chain; a torn, edited, reordered, or
    oversized journal is refused rather than repaired, so a validator never
    extends evidence it cannot itself replay. Each append is one ``O_APPEND``
    write followed by ``fsync`` before it is reported durable; a short write
    closes the journal, and the torn tail then refuses the next open. Callers
    serialize access (the probe CLI holds its state-root lock).
    """

    def __init__(self, path: str) -> None:
        flags = os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC
        descriptor = os.open(path, flags, 0o600)
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or metadata.st_mode & 0o077
                or metadata.st_nlink != 1
                or metadata.st_size > MAX_EVIDENCE_JOURNAL_BYTES
            ):
                raise ValueError("static_evidence_journal_unsafe")
            records = self._load(descriptor, metadata.st_size)
            if metadata.st_size == 0:
                parent = os.open(os.path.dirname(os.path.abspath(path)), os.O_RDONLY)
                try:
                    os.fsync(parent)
                finally:
                    os.close(parent)
        except BaseException:
            os.close(descriptor)
            raise
        self._descriptor = descriptor
        self._records = records
        self._nonces = {item.observation.probe_nonce for item in records}
        self._size = metadata.st_size

    @staticmethod
    def _load(descriptor: int, size: int) -> list[StaticEvidenceRecord]:
        chunks: list[bytes] = []
        offset = 0
        while offset < size:
            chunk = os.pread(descriptor, min(size - offset, 1 << 20), offset)
            if not chunk:
                raise ValueError("static_evidence_journal_invalid")
            chunks.append(chunk)
            offset += len(chunk)
        rendered = b"".join(chunks)
        if rendered and not rendered.endswith(b"\n"):
            raise ValueError("static_evidence_journal_invalid")
        try:
            records = [
                parse_static_evidence_record(line + b"\n") for line in rendered.split(b"\n")[:-1]
            ]
            verify_static_evidence_chain(records)
        except ValueError as exc:
            raise ValueError("static_evidence_journal_invalid") from exc
        return records

    @property
    def records(self) -> tuple[StaticEvidenceRecord, ...]:
        return tuple(self._records)

    @property
    def observations(self) -> tuple[StaticProbeObservation, ...]:
        return tuple(item.observation for item in self._records)

    def append(self, observation: StaticProbeObservation) -> StaticEvidenceRecord:
        if self._descriptor < 0:
            raise ValueError("static_evidence_journal_closed")
        # Refuse a non-canonical observation before anything reaches the file.
        static_probe_observation_bytes(observation)
        record = append_static_evidence(self._records[-1] if self._records else None, observation)
        if record.observation.probe_nonce in self._nonces:
            raise ValueError("static_evidence_nonce_reused")
        rendered = static_evidence_record_bytes(record)
        if self._size + len(rendered) > MAX_EVIDENCE_JOURNAL_BYTES:
            raise ValueError("static_evidence_journal_full")
        written = os.write(self._descriptor, rendered)
        if written != len(rendered):
            self.close()
            raise OSError("static_evidence_journal_short_write")
        os.fsync(self._descriptor)
        self._size += written
        self._records.append(record)
        self._nonces.add(record.observation.probe_nonce)
        return record

    def close(self) -> None:
        if self._descriptor >= 0:
            os.close(self._descriptor)
            self._descriptor = -1

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
