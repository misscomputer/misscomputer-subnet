# SPDX-License-Identifier: AGPL-3.0-only
"""Public static-site-v1 wire contracts (static-site contract §1-§4, §8, §9).

This module owns the static-site manifest, the static-deployment ticket and
receipt v1 and the ``subnet-static-synapse.v1`` envelopes. They are separate
documents from ``deployment.v4`` and ``subnet-synapse.v3``: no v4 member is
reinterpreted as a site identity and a v3/v4 decoder rejects every static
document. The Go mirror lives in ``pkg/static``, ``pkg/protocol/static_v1.go``
and ``pkg/neuron/static_v1.go``; shared fixtures in ``contracts/`` pin both.

Unlike ``deployment.v4``, every static signature is domain separated: Ed25519
over ``domain || 0x00 || canonical(document without "signature")``, and no
static document omits a nullable member.

This module has no clock, network, file, process, environment, wallet or
randomness capability. Ed25519 helpers only verify caller-supplied bytes.
"""

from __future__ import annotations

import hashlib
from typing import Annotated, Final, Literal, Self

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import ConfigDict, Field, StringConstraints, model_validator

from misscomputer_subnet.contract_codec import (
    StrictFrozenModel,
    canonical_json,
    model_document,
    parse_model,
)
from misscomputer_subnet.organic_contracts import (
    Count,
    Digest,
    EndpointID,
    Hex32,
    Hex64,
    HexSignature,
    Hotkey,
    PositiveCount,
    RouteLabel,
    Timestamp,
    document_bytes,
    route_host,
)
from misscomputer_subnet.organic_contracts import ServiceKeyBinding as ServiceKeyBinding
from misscomputer_subnet.protocol import SubnetBinding, _rfc3339nano_instant

WORKLOAD_KIND: Final = "static-site-v1"
CAPABILITY_FEATURE: Final = "organic-static-v1"
HANDLER_VERSION: Final = "static-handler.v1"
SYNAPSE_VERSION: Final = "subnet-static-synapse.v1"
FALLBACK_KIND: Final = "spa-html-v1"

TICKET_SIGNING_DOMAIN: Final = (
    b"miss.computer/misscomputer-subnet/static-deployment-ticket/v1/ed25519"
)
RECEIPT_SIGNING_DOMAIN: Final = (
    b"miss.computer/misscomputer-subnet/static-deployment-receipt/v1/ed25519"
)

MAX_MANIFEST_BYTES: Final = 1 << 20
MAX_FILES: Final = 4_096
MAX_TOTAL_BYTES: Final = 256 << 20
MAX_FILE_BYTES: Final = 16 << 20
MAX_PATH_BYTES: Final = 1_024
MAX_SEGMENT_BYTES: Final = 255
MAX_DEPTH: Final = 32
INDEX_PATH: Final = "/index.html"
HTML_TYPE: Final = "text/html; charset=utf-8"

#: ``static-producer-policy.v3`` content types (§3.4), keyed by extension.
CONTENT_TYPES: Final[dict[str, str]] = {
    "html": HTML_TYPE,
    "htm": HTML_TYPE,
    "css": "text/css; charset=utf-8",
    "js": "text/javascript; charset=utf-8",
    "mjs": "text/javascript; charset=utf-8",
    "json": "application/json",
    "map": "application/json",
    "webmanifest": "application/manifest+json",
    "txt": "text/plain; charset=utf-8",
    "csv": "text/csv; charset=utf-8",
    "md": "text/markdown; charset=utf-8",
    "xml": "application/xml",
    "svg": "image/svg+xml",
    "png": "image/png",
    "jpg": "image/jpeg",
    "jpeg": "image/jpeg",
    "gif": "image/gif",
    "webp": "image/webp",
    "avif": "image/avif",
    "ico": "image/x-icon",
    "woff": "font/woff",
    "woff2": "font/woff2",
    "ttf": "font/ttf",
    "otf": "font/otf",
    "wasm": "application/wasm",
    "pdf": "application/pdf",
    "mp4": "video/mp4",
    "webm": "video/webm",
    "mp3": "audio/mpeg",
}

#: Static receipt error codes and their frozen attribution (§8.3).
ReceiptErrorCode = Literal[
    "static_fetch_failed",
    "static_verify_failed",
    "static_storage_exhausted",
    "static_server_implementation_mismatch",
    "static_manifest_invalid",
    "static_limits_exceeded",
    "deactivated",
    "internal",
]
RECEIPT_ERROR_ATTRIBUTION: Final[dict[str, str]] = {
    "static_fetch_failed": "miner",
    "static_verify_failed": "miner",
    "static_storage_exhausted": "miner",
    "static_server_implementation_mismatch": "miner",
    "static_manifest_invalid": "unknown",
    "static_limits_exceeded": "unknown",
    "deactivated": "none",
    "internal": "miner",
}

_LITERAL: Final = frozenset(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~!$&'()*+,;=:@"
)
_UPPER_HEX: Final = frozenset(b"0123456789ABCDEF")
SiteManifestKey = Annotated[str, StringConstraints(pattern=r"^v1/static-sites/[0-9a-f]{64}\.json$")]
RequestID = Annotated[str, StringConstraints(min_length=1, max_length=2_048)]


def site_manifest_key(site_digest: str) -> str:
    return f"v1/static-sites/{site_digest.removeprefix('sha256:')}.json"


def site_digest(stored: bytes) -> str:
    """The only site identity: SHA-256 of the stored manifest bytes (§3.2)."""

    return "sha256:" + hashlib.sha256(stored).hexdigest()


def content_type_for(path: str) -> str:
    last = path.rsplit("/", 1)[-1]
    if "." in last:
        return CONTENT_TYPES.get(last.rsplit(".", 1)[-1].lower(), "application/octet-stream")
    return "application/octet-stream"


def _valid_request_segment(segment: str) -> bool:
    """§4.3 rules 3-6 for one non-empty segment."""

    if not segment or len(segment) > MAX_SEGMENT_BYTES or segment in {".", ".."}:
        return False
    if not segment.isascii():
        return False
    raw = segment.encode("ascii")
    index = 0
    while index < len(raw):
        if raw[index] != 0x25:  # "%"
            if raw[index] not in _LITERAL:
                return False
            index += 1
            continue
        if (
            index + 2 >= len(raw)
            or raw[index + 1] not in _UPPER_HEX
            or raw[index + 2] not in _UPPER_HEX
        ):
            return False
        decoded = int(raw[index + 1 : index + 3], 16)
        if decoded in _LITERAL or decoded in {0x2F, 0x5C, 0x7F} or decoded < 0x20:
            return False
        index += 3
    return True


def _split_path(raw: str) -> list[str] | None:
    if not raw.startswith("/") or len(raw) > MAX_PATH_BYTES or raw.count("/") > MAX_DEPTH:
        return None
    return raw[1:].split("/")


def valid_file_path(path: str) -> bool:
    """§4.2: a request-valid path whose only escape is ``%20``, no empty segment."""

    segments = _split_path(path)
    if segments is None:
        return False
    for segment in segments:
        if not _valid_request_segment(segment):
            return False
        if "%" in segment.replace("%20", ""):
            return False
    return True


def valid_request_path(raw: str) -> bool:
    """§4.3: the raw request path (before ``?``); only the last segment may be empty."""

    segments = _split_path(raw)
    if segments is None:
        return False
    return all(
        (segment == "" and index == len(segments) - 1) or _valid_request_segment(segment)
        for index, segment in enumerate(segments)
    )


class _SerializedByAlias(StrictFrozenModel):
    # ``schema`` is an alias; every dump (including bridge and dendrite
    # bodies, which call ``model_dump(mode="json")``) must emit it.
    model_config = ConfigDict(serialize_by_alias=True)


# --------------------------------------------------------------------------
# §3 site manifest
# --------------------------------------------------------------------------


class StaticFile(StrictFrozenModel):
    body_sha256: Hex64
    content_length: int = Field(ge=0, le=MAX_FILE_BYTES)
    content_type: Annotated[str, StringConstraints(max_length=128)]
    path: Annotated[str, StringConstraints(min_length=2, max_length=MAX_PATH_BYTES)]


class StaticFallback(StrictFrozenModel):
    kind: Literal["spa-html-v1"]
    target: Annotated[str, StringConstraints(min_length=2, max_length=MAX_PATH_BYTES)]


class StaticSiteManifest(_SerializedByAlias):
    """``static-site-manifest`` v1; its identity is ``site_digest`` of the stored bytes."""

    fallback: StaticFallback | None
    files: list[StaticFile] = Field(min_length=1, max_length=MAX_FILES)
    handler: Literal["static-handler.v1"]
    contract_schema: Literal["miss.computer/misscomputer-subnet/static-site-manifest"] = Field(
        alias="schema"
    )
    schema_version: Literal[1]

    @model_validator(mode="after")
    def site_rules(self) -> Self:
        paths = [item.path for item in self.files]
        if paths != sorted(set(paths)):
            raise ValueError("static_paths_not_ascending")
        folded: set[str] = set()
        directories: set[str] = set()
        for item in self.files:
            if not valid_file_path(item.path):
                raise ValueError("static_path_invalid")
            if item.content_type != content_type_for(item.path):
                raise ValueError("static_content_type_invalid")
            key = item.path.lower()
            if key in folded:
                raise ValueError("static_case_fold_collision")
            folded.add(key)
            parts = key.split("/")
            directories.update("/".join(parts[:end]) for end in range(2, len(parts)))
        if folded & directories:
            raise ValueError("static_file_directory_collision")
        if sum(item.content_length for item in self.files) > MAX_TOTAL_BYTES:
            raise ValueError("static_total_bytes_exceeded")
        by_path = {item.path: item for item in self.files}
        index = by_path.get(INDEX_PATH)
        if index is None or index.content_type != HTML_TYPE:
            raise ValueError("static_index_missing")
        if self.fallback is not None:
            target = by_path.get(self.fallback.target)
            if target is None or target.content_type != HTML_TYPE:
                raise ValueError("static_fallback_invalid")
        return self


def static_site_manifest_bytes(manifest: StaticSiteManifest) -> bytes:
    rendered = document_bytes(manifest)
    if len(rendered) > MAX_MANIFEST_BYTES:
        raise ValueError("static_manifest_too_large")
    return rendered


def parse_static_site_manifest(rendered: bytes, expected_site_digest: str) -> StaticSiteManifest:
    """Parse stored manifest bytes bound to ``site_digest``; any other bytes fail."""

    if len(rendered) > MAX_MANIFEST_BYTES or site_digest(rendered) != expected_site_digest:
        raise ValueError("static_verify_failed")
    return parse_model(rendered, StaticSiteManifest, document_bytes)


# --------------------------------------------------------------------------
# §8 static ticket and receipt
# --------------------------------------------------------------------------


class StaticSubnetBinding(SubnetBinding):
    """The deployment.v4 subnet binding with ``miner_uid`` always present."""

    miner_uid: int | None = Field(ge=0, le=65_535)


class StaticDeploymentTicketV1(_SerializedByAlias):
    assignment_nonce: Hex32
    deployment_id: RouteLabel
    expires_at: Timestamp
    generation: PositiveCount
    issued_at: Timestamp
    miner_id: Hotkey
    release_digest: Digest
    route_host: Annotated[str, StringConstraints(max_length=253)]
    contract_schema: Literal["miss.computer/misscomputer-subnet/static-deployment-ticket"] = Field(
        alias="schema"
    )
    schema_version: Literal[1]
    server_implementation_digest: Digest
    signature: HexSignature
    site_digest: Digest
    site_manifest_key: SiteManifestKey
    subnet: StaticSubnetBinding
    workload_kind: Literal["static-site-v1"]

    @model_validator(mode="after")
    def exact_identity(self) -> Self:
        if self.route_host != route_host(self.deployment_id):
            raise ValueError("route_host_mismatch")
        if self.site_manifest_key != site_manifest_key(self.site_digest):
            raise ValueError("site_manifest_key_mismatch")
        if self.miner_id != self.subnet.miner_hotkey:
            raise ValueError("miner_id_mismatch")
        if _rfc3339nano_instant(self.expires_at) <= _rfc3339nano_instant(self.issued_at):
            raise ValueError("ticket_window_invalid")
        return self


OptionalTimestamp = Timestamp | None


class StaticDeploymentReceiptV1(_SerializedByAlias):
    assignment_nonce: Hex32
    assignment_seen: OptionalTimestamp
    deployment_id: RouteLabel
    endpoint_id: EndpointID
    error: Annotated[str, StringConstraints(max_length=512, pattern=r"^[\x20-\x7e]*$")]
    error_code: ReceiptErrorCode | None
    fetch_completed: OptionalTimestamp
    fetch_started: OptionalTimestamp
    generation: PositiveCount
    miner_id: Hotkey
    release_digest: Digest
    replica_id: Annotated[str, StringConstraints(min_length=3, max_length=256)]
    route_host: Annotated[str, StringConstraints(max_length=253)]
    contract_schema: Literal["miss.computer/misscomputer-subnet/static-deployment-receipt"] = Field(
        alias="schema"
    )
    schema_version: Literal[1]
    server_implementation_digest: Digest
    serving_started: OptionalTimestamp
    signature: HexSignature
    site_digest: Digest
    stage: Literal["accepted", "ready", "failed"]
    subnet: StaticSubnetBinding
    ticket_digest: Digest
    verified_file_count: Annotated[int, Field(ge=1, le=MAX_FILES)] | None
    verified_total_bytes: Annotated[int, Field(ge=0, le=MAX_TOTAL_BYTES)] | None

    @model_validator(mode="after")
    def consistent_receipt(self) -> Self:
        replica = f"{self.deployment_id}-{self.miner_id}"
        if (
            self.replica_id != replica
            or self.endpoint_id != f"{replica}-g{self.generation}-{self.assignment_nonce}"
            or self.route_host != route_host(self.deployment_id)
        ):
            raise ValueError("receipt_identity_invalid")
        if self.miner_id != self.subnet.miner_hotkey:
            raise ValueError("miner_id_mismatch")
        if (self.stage == "failed") != (self.error_code is not None):
            raise ValueError("receipt_error_code_invalid")
        ready = self.stage == "ready"
        if ready != (self.verified_file_count is not None) or ready != (
            self.verified_total_bytes is not None
        ):
            raise ValueError("verified_counts_invalid")
        if ready and self.error:
            raise ValueError("ready_receipt_incomplete")
        return self


def _signed_message(domain: bytes, model: StrictFrozenModel) -> bytes:
    return domain + b"\x00" + canonical_json(model_document(model, exclude={"signature"}))


def static_ticket_signed_message(ticket: StaticDeploymentTicketV1) -> bytes:
    """The exact bytes the validator Go service key signs for one static ticket."""

    return _signed_message(TICKET_SIGNING_DOMAIN, ticket)


def static_receipt_signed_message(receipt: StaticDeploymentReceiptV1) -> bytes:
    """The exact bytes the miner Go service key signs for one static receipt."""

    return _signed_message(RECEIPT_SIGNING_DOMAIN, receipt)


def _verify(public_key_hex: str, signature_hex: str, message: bytes, code: str) -> None:
    try:
        key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
        key.verify(bytes.fromhex(signature_hex), message)
    except (ValueError, InvalidSignature) as exc:
        raise ValueError(code) from exc


def verify_static_ticket_signature(ticket: StaticDeploymentTicketV1) -> None:
    _verify(
        ticket.subnet.validator_service_public_key,
        ticket.signature,
        static_ticket_signed_message(ticket),
        "static_ticket_signature_invalid",
    )


def verify_static_receipt_signature(receipt: StaticDeploymentReceiptV1) -> None:
    _verify(
        receipt.subnet.miner_service_public_key,
        receipt.signature,
        static_receipt_signed_message(receipt),
        "static_receipt_signature_invalid",
    )


def static_ticket_digest(ticket: StaticDeploymentTicketV1) -> str:
    """``sha256:`` of the canonical signed ticket, without a trailing newline."""

    return "sha256:" + hashlib.sha256(canonical_json(model_document(ticket))).hexdigest()


def static_receipt_digest(receipt: StaticDeploymentReceiptV1) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(model_document(receipt))).hexdigest()


def static_endpoint_id(ticket: StaticDeploymentTicketV1) -> str:
    return (
        f"{ticket.deployment_id}-{ticket.miner_id}-g{ticket.generation}-{ticket.assignment_nonce}"
    )


def static_receipt_answers_ticket(
    ticket: StaticDeploymentTicketV1, receipt: StaticDeploymentReceiptV1
) -> None:
    """The scheduler acceptance rule: every bound member equals the ticket."""

    if (
        receipt.deployment_id != ticket.deployment_id
        or receipt.generation != ticket.generation
        or receipt.assignment_nonce != ticket.assignment_nonce
        or receipt.miner_id != ticket.miner_id
        or receipt.route_host != ticket.route_host
        or receipt.site_digest != ticket.site_digest
        or receipt.release_digest != ticket.release_digest
        or receipt.server_implementation_digest != ticket.server_implementation_digest
        or receipt.endpoint_id != static_endpoint_id(ticket)
        or receipt.ticket_digest != static_ticket_digest(ticket)
        or receipt.subnet != ticket.subnet
    ):
        raise ValueError("static_receipt_does_not_answer_ticket")


# --------------------------------------------------------------------------
# §9 subnet-static-synapse.v1 envelopes
# --------------------------------------------------------------------------


class StaticDeploySynapseV1(StrictFrozenModel):
    """Validator -> miner static assignment (the DeploySynapseV3 shape)."""

    protocol: Literal["subnet-static-synapse.v1"]
    request_id: RequestID
    current_block: Count
    caller_hotkey: Hotkey
    validator_binding: ServiceKeyBinding
    ticket: StaticDeploymentTicketV1


class LocalStaticAssignRequestV1(StrictFrozenModel):
    """Miner Python -> Go loopback form of one btauth-verified static assignment."""

    protocol: Literal["subnet-static-synapse.v1"]
    request_id: RequestID
    current_block: Count
    caller_hotkey: Hotkey
    binding_verified: Literal[True]
    validator_binding: ServiceKeyBinding
    ticket: StaticDeploymentTicketV1


class BridgeStaticAssignRequestV1(StrictFrozenModel):
    """Scheduler -> validator loopback request to place one static ticket."""

    protocol: Literal["subnet-static-synapse.v1"]
    request_id: RequestID
    ticket: StaticDeploymentTicketV1


class StaticDeployResponseV1(StrictFrozenModel):
    protocol: Literal["subnet-static-synapse.v1"]
    request_id: RequestID
    endpoint_id: EndpointID
    receipt: StaticDeploymentReceiptV1
    idempotent: bool

    @model_validator(mode="after")
    def endpoint_matches(self) -> Self:
        if self.endpoint_id != self.receipt.endpoint_id:
            raise ValueError("result_endpoint_mismatch")
        return self


class StaticStatusSynapseV1(StrictFrozenModel):
    protocol: Literal["subnet-static-synapse.v1"]
    request_id: RequestID
    current_block: Count
    caller_hotkey: Hotkey
    endpoint_id: Annotated[str, StringConstraints(min_length=1, max_length=256)]


class StaticStatusResponseV1(StrictFrozenModel):
    protocol: Literal["subnet-static-synapse.v1"]
    request_id: RequestID
    status: Literal["absent", "processing", "accepted", "ready", "failed", "deactivated"]
    receipt: StaticDeploymentReceiptV1 | None

    @model_validator(mode="after")
    def receipt_matches_status(self) -> Self:
        if self.status in {"accepted", "ready", "failed"} and (
            self.receipt is None or self.receipt.stage != self.status
        ):
            raise ValueError("status_receipt_mismatch")
        if self.status in {"absent", "processing"} and self.receipt is not None:
            raise ValueError("status_receipt_mismatch")
        return self


#: Every static contract, keyed by its ``contracts/schemas`` file stem.
STATIC_CONTRACT_MODELS: Final[dict[str, type[StrictFrozenModel]]] = {
    "static-site-manifest.v1": StaticSiteManifest,
    "static-deployment-ticket.v1": StaticDeploymentTicketV1,
    "static-deployment-receipt.v1": StaticDeploymentReceiptV1,
    "static-deploy.v1": StaticDeploySynapseV1,
    "static-local-assign.v1": LocalStaticAssignRequestV1,
    "static-bridge-assign.v1": BridgeStaticAssignRequestV1,
    "static-deploy-response.v1": StaticDeployResponseV1,
    "static-status.v1": StaticStatusSynapseV1,
    "static-status-response.v1": StaticStatusResponseV1,
}
