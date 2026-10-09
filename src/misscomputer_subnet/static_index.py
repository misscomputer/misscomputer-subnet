# SPDX-License-Identifier: AGPL-3.0-only
"""Validator ingestion of the signed static-site index (``static-site-v1``).

Implements the validator side of the normative static-site contract: §3 site
manifest, §4 URL paths, §5 serving semantics, §7 release authority and §11.2
static index.

* ``static-site-manifest`` v1 is the promoter's file index. Its identity is
  ``site_digest = "sha256:" + hex(SHA-256(canonical_json(manifest) + "\\n"))``.
  The manifest carries no producer, source or server member.
* ``static-site-release`` v1 is one release-authority Ed25519 signature,
  domain separated, over the release without its ``signature`` member. It
  binds ``site_digest``, ``producer_policy_version`` and
  ``server_implementation_digest``;
  ``release_digest = "sha256:" + hex(SHA-256(stored signed release))``.
* ``static-site-release-trust-policy`` v1 pins the dedicated release keys
  (threshold 1) and is itself pinned by its ``digest_sha256``.

A validator accepts a static deployment of the public assignment manifest v3
only if the fetched manifest hashes to the bound ``site_digest``, the fetched
release hashes to the bound ``release_digest`` and verifies under the pinned
policy, the release names the same site and server implementation, the
producer policy is one this validator implements, and the server
implementation is the one it pins for ``static-handler.v1``. Anything else,
including an unavailable object, is a :class:`StaticIndexAbstention`: the
deployment is neither probed nor scored as zero, and never falls back to the
dynamic health probe. Nothing here raises for untrusted input.

:func:`expected_static_response` is the §5.5 ``expected(...)`` function for
the GET and HEAD requests a validator sends.

This module is pure: no clock, network, file, process, environment, wallet,
chain, randomness, or signing capability.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Annotated, Final, Literal, Self

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import AfterValidator, Field, StringConstraints, ValidationError, model_validator

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
from .ed25519_trust import decode_ed25519_public_key_hex
from .organic_contracts import (
    UID,
    DNSLabel,
    EndpointID,
    Hex64,
    HexSignature,
    Hostname,
    Hotkey,
    PositiveCount,
    StaticDeploymentAssignmentV3,
    Timestamp,
    parse_canonical_document,
    response_header_sha256,
)
from .organic_contracts import Digest as PrefixedDigest
from .organic_manifest import AssignmentManifestV3Verification
from .organic_probe import timestamp_epoch_seconds

STATIC_SITE_MANIFEST_SCHEMA: Final = "miss.computer/misscomputer-subnet/static-site-manifest"
STATIC_SITE_RELEASE_SCHEMA: Final = "miss.computer/misscomputer-subnet/static-site-release"
STATIC_SITE_RELEASE_TRUST_POLICY_SCHEMA: Final = (
    "miss.computer/misscomputer-subnet/static-site-release-trust-policy"
)
STATIC_SITE_RELEASE_DOMAIN_SEPARATOR: Final = (
    b"miss.computer/misscomputer-subnet/static-site-release/v1/ed25519"
)
WORKLOAD_KIND: Final = "static-site-v1"
HANDLER: Final = "static-handler.v1"
FALLBACK_KIND: Final = "spa-html-v1"
#: Producer policy versions this validator implements (§3.4, §3.6).
IMPLEMENTED_PRODUCER_POLICY_VERSIONS: Final = frozenset({"static-producer-policy.v3"})

#: §1 hard limits.
MAX_FILES: Final = 4_096
MAX_TOTAL_BYTES: Final = 268_435_456
MAX_FILE_BYTES: Final = 16_777_216
MAX_MANIFEST_BYTES: Final = 1_048_576
MAX_RELEASE_BYTES: Final = 16 * 1_024
MAX_PATH_BYTES: Final = 1_024
MAX_SEGMENT_BYTES: Final = 255
MAX_PATH_DEPTH: Final = 32
MAX_RELEASE_KEYS: Final = 16

INDEX_DOCUMENT: Final = "index.html"
HTML_CONTENT_TYPE: Final = "text/html; charset=utf-8"
PLATFORM_CONTENT_TYPE: Final = "text/plain; charset=utf-8"
#: §5.3 fixed 404 body.
NOT_FOUND_BODY: Final = b"Not Found\n"
EMPTY_SHA256: Final = hashlib.sha256(b"").hexdigest()
#: §5.2 normative header values.
REQUIRED_CACHE_CONTROL: Final = "private, no-store"
REQUIRED_NOSNIFF: Final = "nosniff"

#: §3.4 ``static-producer-policy.v3`` content types by lowercased extension.
CONTENT_TYPES: Final[Mapping[str, str]] = MappingProxyType(
    {
        "html": HTML_CONTENT_TYPE,
        "htm": HTML_CONTENT_TYPE,
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
)
DEFAULT_CONTENT_TYPE: Final = "application/octet-stream"

#: §4.1 **L**: RFC 3986 unreserved, sub-delims, ``:`` and ``@``.
_L: Final = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~!$&'()*+,;=:@"
)
_UPPER_HEX: Final = frozenset("0123456789ABCDEF")

AbstentionCode = Literal[
    "handler_unsupported",
    "index_invalid",
    "index_limits_exceeded",
    "index_not_canonical",
    "index_oversized",
    "index_unavailable",
    "producer_policy_unsupported",
    "release_binding_mismatch",
    "release_digest_mismatch",
    "release_invalid",
    "release_revoked",
    "release_unavailable",
    "server_implementation_mismatch",
    "signature_invalid",
    "signer_outside_validity",
    "signer_untrusted",
    "site_digest_mismatch",
]
AbstentionRecordCode = Literal[
    "static_index_invalid", "static_index_unavailable", "static_release_revoked"
]
ResponseKind = Literal["directory_index", "file", "navigation_fallback", "not_found"]


class StaticPathError(ValueError):
    """A path outside the §4.2 file-path or §4.3 request-path grammar."""


def _segments(path: str) -> list[str]:
    if not isinstance(path, str) or not path.startswith("/") or not path.isascii():
        raise StaticPathError("static_path_invalid")
    if len(path) > MAX_PATH_BYTES or path.count("/") > MAX_PATH_DEPTH:
        raise StaticPathError("static_path_limits_exceeded")
    segments = path[1:].split("/")
    for segment in segments:
        if len(segment) > MAX_SEGMENT_BYTES:
            raise StaticPathError("static_path_limits_exceeded")
        if segment in {".", ".."}:
            raise StaticPathError("static_path_dot_segment")
    return segments


def validate_file_path(path: str) -> str:
    """§4.2: a canonical manifest file path; ``%20`` is its only percent-encoding."""

    for segment in _segments(path):
        if not segment or not set(segment.replace("%20", " ")) <= _L | {" "}:
            raise StaticPathError("static_file_path_invalid")
    return path


def validate_request_path(path: str) -> str:
    """§4.3: a query-free request path the handler does not answer with 400."""

    segments = _segments(path)
    for position, segment in enumerate(segments):
        if not segment and position != len(segments) - 1:
            raise StaticPathError("static_path_empty_segment")
        index = 0
        while index < len(segment):
            char = segment[index]
            if char == "%":
                encoded = segment[index + 1 : index + 3]
                if len(encoded) != 2 or not set(encoded) <= _UPPER_HEX:
                    raise StaticPathError("static_path_encoding_invalid")
                byte = int(encoded, 16)
                if chr(byte) in _L | {"/", "\\"} or byte <= 0x1F or byte == 0x7F:
                    raise StaticPathError("static_path_encoding_invalid")
                index += 3
                continue
            if char not in _L:
                raise StaticPathError("static_path_invalid")
            index += 1
    return path


def content_type_for_path(path: str) -> str:
    """§3.4: the only valid ``content_type`` of a file at ``path``."""

    last = path.rsplit("/", 1)[-1]
    if "." not in last:
        return DEFAULT_CONTENT_TYPE
    return CONTENT_TYPES.get(last.rsplit(".", 1)[-1].lower(), DEFAULT_CONTENT_TYPE)


FilePath = Annotated[str, AfterValidator(validate_file_path)]
KeyID = Annotated[str, StringConstraints(pattern=r"^[a-z0-9](?:[a-z0-9_-]{0,62}[a-z0-9])?$")]
PolicyVersion = Annotated[
    str, StringConstraints(pattern=r"^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$")
]
Epoch = Annotated[int, Field(ge=0, le=(1 << 63) - 1)]


class StaticSiteFallback(StrictFrozenModel):
    kind: Literal["spa-html-v1"]
    target: FilePath


class StaticSiteFile(StrictFrozenModel):
    body_sha256: Hex64
    content_length: int = Field(ge=0, le=MAX_FILE_BYTES)
    content_type: Annotated[str, StringConstraints(max_length=128)]
    path: FilePath

    @model_validator(mode="after")
    def policy_content_type(self) -> Self:
        if self.content_type != content_type_for_path(self.path):
            raise ValueError("static_content_type_invalid")
        return self


def _directories(path: str) -> list[str]:
    """Every proper directory prefix of ``path``, each ending in ``/``."""

    return [path[: index + 1] for index, char in enumerate(path) if char == "/" and index > 0]


class StaticSiteManifest(StrictFrozenModel):
    """``static-site-manifest`` v1 (§3.1)."""

    fallback: StaticSiteFallback | None
    files: list[StaticSiteFile] = Field(min_length=1, max_length=MAX_FILES)
    handler: Literal["static-handler.v1"]
    contract_schema: Literal["miss.computer/misscomputer-subnet/static-site-manifest"] = Field(
        alias="schema"
    )
    schema_version: Literal[1]

    @model_validator(mode="after")
    def whole_manifest(self) -> Self:
        paths = [item.path for item in self.files]
        if any(left >= right for left, right in zip(paths, paths[1:], strict=False)):
            raise ValueError("static_files_not_ascending")
        if len({path.lower() for path in paths}) != len(paths):
            raise ValueError("static_path_case_collision")
        directories = {prefix for path in paths for prefix in _directories(path)}
        if any(path + "/" in directories for path in paths):
            raise ValueError("static_path_file_directory_collision")
        if sum(item.content_length for item in self.files) > MAX_TOTAL_BYTES:
            raise ValueError("static_total_bytes_exceeded")
        if "/" + INDEX_DOCUMENT not in paths:
            raise ValueError("static_root_response_missing")
        if self.fallback is not None:
            target = next((item for item in self.files if item.path == self.fallback.target), None)
            if target is None or target.content_type != HTML_CONTENT_TYPE:
                raise ValueError("static_fallback_invalid")
        return self


class StaticSiteRelease(StrictFrozenModel):
    """``static-site-release`` v1 (§7.1)."""

    issued_at: Timestamp
    producer_policy_version: PolicyVersion
    contract_schema: Literal["miss.computer/misscomputer-subnet/static-site-release"] = Field(
        alias="schema"
    )
    schema_version: Literal[1]
    server_implementation_digest: PrefixedDigest
    signature: HexSignature
    signer_key_id: KeyID
    site_digest: PrefixedDigest


class StaticReleaseKey(StrictFrozenModel):
    key_id: KeyID
    algorithm: Literal["ed25519"]
    public_key_hex: Hex64
    valid_from_epoch: Epoch
    valid_until_epoch: Epoch

    @model_validator(mode="after")
    def valid_key(self) -> Self:
        decode_ed25519_public_key_hex(self.public_key_hex)
        if self.valid_until_epoch <= self.valid_from_epoch:
            raise ValueError("key_validity_window_invalid")
        return self


class StaticSiteReleaseTrustPolicy(StrictFrozenModel):
    """``static-site-release-trust-policy`` v1 (§7.2); threshold is 1."""

    contract_schema: Literal[
        "miss.computer/misscomputer-subnet/static-site-release-trust-policy"
    ] = Field(alias="schema")
    schema_version: Literal[1]
    policy_id: KeyID
    trusted_keys: list[StaticReleaseKey] = Field(min_length=1, max_length=MAX_RELEASE_KEYS)
    digest_sha256: Hex64

    @model_validator(mode="after")
    def distinct_keys(self) -> Self:
        if len({item.key_id for item in self.trusted_keys}) != len(self.trusted_keys):
            raise ValueError("trusted_key_id_duplicate")
        if len({item.public_key_hex for item in self.trusted_keys}) != len(self.trusted_keys):
            raise ValueError("trusted_public_key_duplicate")
        verify_model_digest(self, "digest_sha256")
        return self


def build_static_site_release_trust_policy(
    *, policy_id: str, trusted_keys: Sequence[StaticReleaseKey]
) -> StaticSiteReleaseTrustPolicy:
    """Seal a local public-key policy; no secret key material is accepted."""

    unsigned: dict[str, object] = {
        "schema": STATIC_SITE_RELEASE_TRUST_POLICY_SCHEMA,
        "schema_version": 1,
        "policy_id": policy_id,
        "trusted_keys": [
            model_document(revalidate(item, StaticReleaseKey)) for item in trusted_keys
        ],
    }
    return StaticSiteReleaseTrustPolicy.model_validate(
        {**unsigned, "digest_sha256": digest(unsigned)}
    )


def stored_digest(rendered: bytes) -> str:
    """``sha256:<hex>`` of stored bytes: ``site_digest`` and ``release_digest``."""

    return "sha256:" + hashlib.sha256(rendered).hexdigest()


def static_site_release_message(release: StaticSiteRelease) -> bytes:
    """The only bytes a release key signs: domain, NUL, canonical unsigned release."""

    unsigned = model_document(revalidate(release, StaticSiteRelease), exclude={"signature"})
    return STATIC_SITE_RELEASE_DOMAIN_SEPARATOR + b"\x00" + canonical_json(unsigned)


def static_index_manifest_key(site_digest: str) -> str:
    """§1 public static index path of a site manifest."""

    return f"static-sites/v1/manifests/{site_digest.removeprefix('sha256:')}.json"


def static_index_release_key(release_digest: str) -> str:
    """§1 public static index path of a signed release."""

    return f"static-sites/v1/releases/{release_digest.removeprefix('sha256:')}.json"


# --------------------------------------------------------------------------
# Assignment interface (public active-assignment manifest v3, §11.1)
# --------------------------------------------------------------------------


class StaticEndpointTarget(StrictFrozenModel):
    """One published static endpoint incarnation of a verified manifest v3."""

    endpoint_id: EndpointID
    generation: PositiveCount
    miner_uid: UID
    miner_hotkey: Hotkey
    miner_service_public_key: Hex64
    ticket_digest: PrefixedDigest


class StaticDeploymentTarget(StrictFrozenModel):
    """The static bindings of one manifest v3 deployment and its incarnations.

    The manifest v3 verifier owns the authenticity of these fields.
    """

    deployment_id: DNSLabel
    route_host: Hostname
    site_digest: PrefixedDigest
    release_digest: PrefixedDigest
    server_implementation_digest: PrefixedDigest
    endpoints: list[StaticEndpointTarget] = Field(min_length=1, max_length=8)

    @model_validator(mode="after")
    def unique_endpoints(self) -> Self:
        ids = [item.endpoint_id for item in self.endpoints]
        if len(set(ids)) != len(ids):
            raise ValueError("static_target_endpoint_duplicate")
        return self


def static_deployment_targets(
    verification: AssignmentManifestV3Verification,
) -> list[StaticDeploymentTarget]:
    """The ``static-site-v1`` deployments of one live-verified manifest v3, in order.

    Only a manifest that passed :func:`~misscomputer_subnet.organic_manifest.
    verify_assignment_manifest_v3` yields targets; ``oci-image-v1`` deployments
    are left to the existing OCI probe path. Each replica becomes one endpoint
    incarnation bound to its static ``ticket_digest``.
    """

    manifest = revalidate(verification, AssignmentManifestV3Verification).manifest
    return [
        StaticDeploymentTarget(
            deployment_id=item.deployment_id,
            route_host=item.route_host,
            site_digest=item.site_digest,
            release_digest=item.release_digest,
            server_implementation_digest=item.server_implementation_digest,
            endpoints=[
                StaticEndpointTarget(
                    endpoint_id=replica.endpoint_id,
                    generation=replica.generation,
                    miner_uid=replica.miner_uid,
                    miner_hotkey=replica.miner_hotkey,
                    miner_service_public_key=replica.miner_service_public_key,
                    ticket_digest=replica.ticket_digest,
                )
                for replica in item.replicas
            ],
        )
        for item in manifest.deployments
        if isinstance(item, StaticDeploymentAssignmentV3)
    ]


# --------------------------------------------------------------------------
# Verified index, abstention, and expected responses
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ExpectedStaticResponse:
    """§5.5 ``expected(...)`` for one GET or HEAD of a valid request path."""

    path: str
    method: Literal["GET", "HEAD"]
    kind: ResponseKind
    status: int
    content_type: str
    #: ``Content-Length`` of the representation (the GET length also for HEAD).
    content_length: int
    #: SHA-256 of the body on the wire; the empty-body digest for HEAD.
    body_sha256: str
    #: ``organic.ResponseHeaderSHA256`` over exactly the normative header set.
    header_sha256: str


@dataclass(frozen=True, slots=True)
class StaticIndexAbstention:
    """A static deployment the validator cannot judge: no probes, no score, no downgrade."""

    deployment_id: str
    site_digest: str
    code: AbstentionCode

    @property
    def record_code(self) -> AbstentionRecordCode:
        """The §11.2 abstention record code."""

        if self.code in {"index_unavailable", "release_unavailable"}:
            return "static_index_unavailable"
        if self.code == "release_revoked":
            return "static_release_revoked"
        return "static_index_invalid"


@dataclass(frozen=True, slots=True)
class VerifiedStaticIndex:
    """A static site index authenticated under the validator's pinned policy."""

    target: StaticDeploymentTarget
    manifest: StaticSiteManifest
    release: StaticSiteRelease
    trust_policy_digest_sha256: str
    #: §4.4 response table: request path -> file.
    routes: Mapping[str, StaticSiteFile]

    @property
    def responses(self) -> tuple[ExpectedStaticResponse, ...]:
        """Every §4.4 route's GET response, in path order."""

        return tuple(expected_static_response(self, "GET", path) for path in sorted(self.routes))


def _routes(manifest: StaticSiteManifest) -> dict[str, StaticSiteFile]:
    table = {item.path: item for item in manifest.files}
    for item in manifest.files:
        if item.path.rsplit("/", 1)[-1] == INDEX_DOCUMENT:
            table[item.path[: -len(INDEX_DOCUMENT)]] = item
    return table


def normative_headers(content_type: str, content_length: int) -> list[tuple[str, str]]:
    """§5.2 normative header set of a 200 or 404 response (lowercased names)."""

    return [
        ("cache-control", REQUIRED_CACHE_CONTROL),
        ("content-length", str(content_length)),
        ("content-type", content_type),
        ("x-content-type-options", REQUIRED_NOSNIFF),
    ]


def _expected(
    path: str,
    method: Literal["GET", "HEAD"],
    kind: ResponseKind,
    status: int,
    content_type: str,
    content_length: int,
    body_sha256: str,
) -> ExpectedStaticResponse:
    return ExpectedStaticResponse(
        path=path,
        method=method,
        kind=kind,
        status=status,
        content_type=content_type,
        content_length=content_length,
        body_sha256=body_sha256 if method == "GET" else EMPTY_SHA256,
        header_sha256=response_header_sha256(normative_headers(content_type, content_length)),
    )


def expected_static_response(
    index: VerifiedStaticIndex, method: Literal["GET", "HEAD"], path: str
) -> ExpectedStaticResponse:
    """§5.1 steps 5–7 for a §4.3-valid path: route, fallback, else 404.

    A path is fallback-eligible when the manifest declares a fallback and the
    text after its final ``/`` (possibly empty) contains no ``.`` (§4.4).
    """

    validate_request_path(path)
    item = index.routes.get(path)
    kind: ResponseKind
    if item is not None:
        kind = "file" if item.path == path else "directory_index"
    elif index.manifest.fallback is not None and "." not in path.rsplit("/", 1)[-1]:
        item = index.routes[index.manifest.fallback.target]
        kind = "navigation_fallback"
    else:
        return _expected(
            path,
            method,
            "not_found",
            404,
            PLATFORM_CONTENT_TYPE,
            len(NOT_FOUND_BODY),
            hashlib.sha256(NOT_FOUND_BODY).hexdigest(),
        )
    return _expected(
        path, method, kind, 200, item.content_type, item.content_length, item.body_sha256
    )


#: Model errors meaning "over a §1 limit", reported apart from malformed input.
_LIMIT_ERROR_TYPES: Final = frozenset({"too_long", "less_than_equal", "string_too_long"})
_LIMIT_VALUE_ERRORS: Final = ("static_total_bytes_exceeded", "static_path_limits_exceeded")


def _manifest_abstention(exc: ValueError) -> AbstentionCode:
    if str(exc) == "document_not_canonical":
        return "index_not_canonical"
    cause = exc.__cause__
    if isinstance(cause, ValidationError):
        for error in cause.errors():
            message = str(error.get("msg", ""))
            if error["type"] in _LIMIT_ERROR_TYPES or any(
                code in message for code in _LIMIT_VALUE_ERRORS
            ):
                return "index_limits_exceeded"
            if error["loc"] == ("handler",):
                return "handler_unsupported"
    return "index_invalid"


def _verify_release(
    release: StaticSiteRelease, policy: StaticSiteReleaseTrustPolicy
) -> AbstentionCode | None:
    key = next((item for item in policy.trusted_keys if item.key_id == release.signer_key_id), None)
    if key is None:
        return "signer_untrusted"
    issued = timestamp_epoch_seconds(release.issued_at)
    if not key.valid_from_epoch <= issued < key.valid_until_epoch:
        return "signer_outside_validity"
    try:
        Ed25519PublicKey.from_public_bytes(
            decode_ed25519_public_key_hex(key.public_key_hex)
        ).verify(bytes.fromhex(release.signature), static_site_release_message(release))
    except (InvalidSignature, ValueError):
        return "signature_invalid"
    return None


def ingest_static_index(
    target: StaticDeploymentTarget,
    manifest_bytes: bytes | None,
    release_bytes: bytes | None,
    policy: StaticSiteReleaseTrustPolicy,
    *,
    pinned_server_implementation_digest: str,
) -> VerifiedStaticIndex | StaticIndexAbstention:
    """Authenticate the fetched static index objects against one manifest v3 binding.

    ``None`` bytes mean the object could not be fetched. Every failure is an
    abstention with a stable code.
    """

    target = revalidate(target, StaticDeploymentTarget)
    policy = revalidate(policy, StaticSiteReleaseTrustPolicy)

    def abstain(code: AbstentionCode) -> StaticIndexAbstention:
        return StaticIndexAbstention(target.deployment_id, target.site_digest, code)

    if manifest_bytes is None:
        return abstain("index_unavailable")
    if release_bytes is None:
        return abstain("release_unavailable")
    if len(manifest_bytes) > MAX_MANIFEST_BYTES:
        return abstain("index_oversized")
    if stored_digest(manifest_bytes) != target.site_digest:
        return abstain("site_digest_mismatch")
    if stored_digest(release_bytes) != target.release_digest:
        return abstain("release_digest_mismatch")
    try:
        manifest = parse_canonical_document(manifest_bytes, StaticSiteManifest)
    except ValueError as exc:
        return abstain(_manifest_abstention(exc))
    try:
        release = parse_model(
            release_bytes,
            StaticSiteRelease,
            static_site_release_bytes,
            maximum_bytes=MAX_RELEASE_BYTES,
        )
    except ValueError:
        return abstain("release_invalid")
    if release.site_digest != target.site_digest:
        return abstain("release_binding_mismatch")
    failure = _verify_release(release, policy)
    if failure is not None:
        return abstain(failure)
    if release.producer_policy_version not in IMPLEMENTED_PRODUCER_POLICY_VERSIONS:
        return abstain("producer_policy_unsupported")
    if not (
        release.server_implementation_digest
        == target.server_implementation_digest
        == pinned_server_implementation_digest
    ):
        return abstain("server_implementation_mismatch")
    return VerifiedStaticIndex(
        target=target,
        manifest=manifest,
        release=release,
        trust_policy_digest_sha256=policy.digest_sha256,
        routes=MappingProxyType(_routes(manifest)),
    )


def static_site_manifest_bytes(value: StaticSiteManifest) -> bytes:
    return model_bytes(value, StaticSiteManifest)


def static_site_release_bytes(value: StaticSiteRelease) -> bytes:
    return model_bytes(value, StaticSiteRelease)


def static_site_release_trust_policy_bytes(value: StaticSiteReleaseTrustPolicy) -> bytes:
    return model_bytes(value, StaticSiteReleaseTrustPolicy)


def parse_static_site_release_trust_policy(rendered: bytes) -> StaticSiteReleaseTrustPolicy:
    return parse_model(
        rendered,
        StaticSiteReleaseTrustPolicy,
        static_site_release_trust_policy_bytes,
        maximum_bytes=256 * 1_024,
    )
