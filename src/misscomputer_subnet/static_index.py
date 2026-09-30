# SPDX-License-Identifier: AGPL-3.0-only
"""Validator ingestion of the signed static-site index (``static-site-v1`` workload).

A static deployment is a content-addressed file bundle served by a pinned
platform handler. The public assignment manifest binds each static deployment
to one ``site_digest`` and its endpoint incarnations; this module turns that
binding into the exact responses a validator may demand, and nothing else:

* ``static-site-manifest`` v1 is the promoter-produced file index. Its
  ``site_digest`` is the SHA-256 of its canonical bytes (canonical JSON plus
  one newline), so the bytes a validator fetched are the bytes the digest
  names.
* ``static-site-release`` v1 is the release authority's threshold signature
  over ``{site_digest, producer_policy_version, server_implementation_digest}``
  under a domain separator. A content digest alone does not say what a site
  *should* be; only a release signature under the validator's pinned
  :class:`StaticSiteTrustPolicy` does. No miner or client key can define
  expected bytes.

Ingestion never raises for bad input. A missing, oversized, non-canonical,
unsigned, mis-bound, over-cap, or otherwise unverifiable index yields a
:class:`StaticIndexAbstention`. There is deliberately no path from an
abstention to the organic health probe: a static deployment whose index
cannot be verified is not probed at all, and is never scored as dynamic or as
zero.

Serving semantics (exact lookup, directory index, the manifest-declared SPA
navigation fallback, the pinned platform 404) are derived in one place,
:func:`expected_static_response`, so reconciling them with the normative
contract vectors touches one function.

This module is pure: no clock, network, file, process, environment, wallet,
chain, randomness, or signing capability.
"""

from __future__ import annotations

import base64
import binascii
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
from .ed25519_trust import decode_ed25519_public_key_base64
from .organic_contracts import (
    UID,
    DNSLabel,
    EndpointID,
    Hex64,
    Hostname,
    Hotkey,
    PositiveCount,
    parse_canonical_document,
)
from .organic_contracts import (
    Digest as PrefixedDigest,
)

STATIC_SITE_MANIFEST_SCHEMA: Final = "miss.computer/misscomputer-subnet/static-site-manifest"
STATIC_SITE_RELEASE_SCHEMA: Final = "miss.computer/misscomputer-subnet/static-site-release"
STATIC_SITE_TRUST_POLICY_SCHEMA: Final = (
    "miss.computer/misscomputer-subnet/static-site-trust-policy"
)
STATIC_SITE_RELEASE_PURPOSE: Final = "static_site_release_v1"
STATIC_SITE_RELEASE_DOMAIN_SEPARATOR: Final = (
    b"miss.computer/misscomputer-subnet/static-site-release/v1/ed25519"
)
WORKLOAD_KIND: Final = "static-site-v1"

#: Provisional v1 caps (integration contract). Hard admission limits: a site
#: over any of them is refused, never silently served or probed as dynamic.
MAX_FILES: Final = 4_096
MAX_TOTAL_BYTES: Final = 256 * 1_024 * 1_024
MAX_FILE_BYTES: Final = 16 * 1_024 * 1_024
MAX_MANIFEST_BYTES: Final = 1_024 * 1_024
MAX_RELEASE_BYTES: Final = 64 * 1_024
MAX_PATH_BYTES: Final = 1_024
MAX_SEGMENT_BYTES: Final = 255
MAX_PATH_DEPTH: Final = 32
MAX_RELEASE_KEYS: Final = 16
INDEX_DOCUMENT: Final = "index.html"
#: Response headers the pinned handler must emit for every static response.
REQUIRED_CACHE_CONTROL: Final = "private, no-store"
REQUIRED_NOSNIFF: Final = "nosniff"

_UNRESERVED: Final = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
_SEGMENT_LITERALS: Final = _UNRESERVED | frozenset("!$&'()*+,;=:@")
_UPPER_HEX: Final = frozenset("0123456789ABCDEF")

AbstentionCode = Literal[
    "index_caps_exceeded",
    "index_invalid",
    "index_not_canonical",
    "index_oversized",
    "index_unavailable",
    "producer_policy_unapproved",
    "release_binding_mismatch",
    "release_invalid",
    "release_unavailable",
    "root_response_missing",
    "server_implementation_unpinned",
    "signature_invalid",
    "signer_expired",
    "signer_not_yet_valid",
    "signer_revoked",
    "signer_untrusted",
    "site_digest_mismatch",
    "threshold_not_met",
    "trust_policy_expired",
    "trust_policy_not_yet_valid",
]
ResponseKind = Literal["file", "directory_index", "navigation_fallback", "not_found"]


class StaticPathError(ValueError):
    """A URL path outside the canonical static path grammar."""


def validate_static_path(path: str, *, allow_directory: bool = True) -> str:
    """Return ``path`` if it is a canonical static URL path, else raise.

    The grammar admits ``/`` and ``/``-separated non-empty segments of RFC 3986
    ``pchar`` literals, with percent-encoding only in uppercase hex and only
    for a byte that has no literal form here (never an unreserved byte, ``/``,
    ``\\``, or a control). Dot segments, empty segments, queries, fragments,
    backslashes, and controls are refused, as are the length and depth caps.
    ``allow_directory`` admits one trailing ``/`` (a directory-index request).
    """

    if not isinstance(path, str) or not path.startswith("/") or not path.isascii():
        raise StaticPathError("static_path_invalid")
    if len(path) > MAX_PATH_BYTES:
        raise StaticPathError("static_path_too_long")
    if path == "/":
        return path
    body = path[1:]
    if body.endswith("/"):
        if not allow_directory:
            raise StaticPathError("static_path_invalid")
        body = body[:-1]
    segments = body.split("/")
    if len(segments) > MAX_PATH_DEPTH:
        raise StaticPathError("static_path_too_deep")
    for segment in segments:
        if not segment or segment in {".", ".."} or len(segment) > MAX_SEGMENT_BYTES:
            raise StaticPathError("static_path_invalid")
        index = 0
        while index < len(segment):
            char = segment[index]
            if char == "%":
                encoded = segment[index + 1 : index + 3]
                if len(encoded) != 2 or not set(encoded) <= _UPPER_HEX:
                    raise StaticPathError("static_path_encoding_invalid")
                byte = int(encoded, 16)
                if byte < 0x20 or byte == 0x7F or chr(byte) in _UNRESERVED | {"/", "\\"}:
                    raise StaticPathError("static_path_encoding_invalid")
                index += 3
                continue
            if char not in _SEGMENT_LITERALS:
                raise StaticPathError("static_path_invalid")
            index += 1
    return path


def _file_path(value: str) -> str:
    return validate_static_path(value, allow_directory=False)


StaticFilePath = Annotated[str, AfterValidator(_file_path)]
ContentType = Annotated[str, StringConstraints(pattern=r"^[\x21-\x7e][\x20-\x7e]{0,126}$")]
PolicyVersion = Annotated[
    str, StringConstraints(pattern=r"^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$")
]
KeyID = Annotated[str, StringConstraints(pattern=r"^[a-z0-9](?:[a-z0-9_-]{0,62}[a-z0-9])?$")]
Epoch = Annotated[int, Field(ge=0, le=(1 << 63) - 1)]


def _is_navigation(path: str) -> bool:
    """A navigation request: its last segment names no file extension."""

    return "." not in path.rstrip("/").rsplit("/", 1)[-1]


class StaticSiteFile(StrictFrozenModel):
    path: StaticFilePath
    size_bytes: int = Field(ge=0, le=MAX_FILE_BYTES)
    sha256: Hex64
    content_type: ContentType


class StaticSiteManifest(StrictFrozenModel):
    """``static-site-manifest`` v1: the promoter's verified, canonical file index."""

    contract_schema: Literal["miss.computer/misscomputer-subnet/static-site-manifest"] = Field(
        alias="schema"
    )
    schema_version: Literal[1]
    workload_kind: Literal["static-site-v1"]
    producer_policy_version: PolicyVersion
    files: list[StaticSiteFile] = Field(min_length=1, max_length=MAX_FILES)
    #: Path of the HTML file served for unmatched navigation requests, or none.
    navigation_fallback_path: StaticFilePath | None

    @model_validator(mode="after")
    def canonical_index(self) -> Self:
        paths = [item.path for item in self.files]
        if paths != sorted(set(paths)):
            raise ValueError("static_files_not_canonical")
        if len({path.casefold() for path in paths}) != len(paths):
            raise ValueError("static_path_case_collision")
        if sum(item.size_bytes for item in self.files) > MAX_TOTAL_BYTES:
            raise ValueError("static_total_bytes_exceeded")
        if "/" + INDEX_DOCUMENT not in paths:
            raise ValueError("static_root_response_missing")
        fallback = self.navigation_fallback_path
        if fallback is not None and (fallback not in paths or not fallback.endswith(".html")):
            raise ValueError("static_navigation_fallback_invalid")
        return self


class StaticReleaseSignature(StrictFrozenModel):
    signer_key_id: KeyID
    signature_base64: Annotated[str, StringConstraints(min_length=88, max_length=88)]


class StaticSiteRelease(StrictFrozenModel):
    """``static-site-release`` v1: the release authority's binding of one site digest."""

    contract_schema: Literal["miss.computer/misscomputer-subnet/static-site-release"] = Field(
        alias="schema"
    )
    schema_version: Literal[1]
    purpose: Literal["static_site_release_v1"]
    site_digest: Hex64
    producer_policy_version: PolicyVersion
    server_implementation_digest: PrefixedDigest
    signatures: list[StaticReleaseSignature] = Field(min_length=1, max_length=MAX_RELEASE_KEYS)

    @model_validator(mode="after")
    def canonical_signatures(self) -> Self:
        ids = [item.signer_key_id for item in self.signatures]
        if ids != sorted(set(ids)):
            raise ValueError("release_signatures_not_canonical")
        return self


class StaticReleaseKey(StrictFrozenModel):
    key_id: KeyID
    algorithm: Literal["ed25519"]
    public_key_base64: Annotated[str, StringConstraints(min_length=44, max_length=44)]
    public_key_sha256: Hex64
    valid_from_epoch: Epoch
    valid_until_epoch: Epoch
    revoked_at_epoch: Epoch | None

    @model_validator(mode="after")
    def valid_key(self) -> Self:
        public = decode_ed25519_public_key_base64(self.public_key_base64)
        if hashlib.sha256(public).hexdigest() != self.public_key_sha256:
            raise ValueError("public_key_digest_mismatch")
        if self.valid_until_epoch <= self.valid_from_epoch:
            raise ValueError("key_validity_window_invalid")
        return self


class StaticServerProfile(StrictFrozenModel):
    """One pinned platform handler and the fixed 404 response it serves."""

    server_implementation_digest: PrefixedDigest
    not_found_content_type: ContentType
    not_found_size_bytes: int = Field(ge=0, le=64 * 1_024)
    not_found_sha256: Hex64


class StaticSiteTrustPolicy(StrictFrozenModel):
    """Validator-local pin of the static release authority and pinned handlers."""

    contract_schema: Literal["miss.computer/misscomputer-subnet/static-site-trust-policy"] = Field(
        alias="schema"
    )
    schema_version: Literal[1]
    purpose: Literal["static_site_release_v1"]
    threshold: int = Field(ge=1, le=MAX_RELEASE_KEYS)
    release_keys: list[StaticReleaseKey] = Field(min_length=1, max_length=MAX_RELEASE_KEYS)
    approved_producer_policy_versions: list[PolicyVersion] = Field(min_length=1, max_length=16)
    server_profiles: list[StaticServerProfile] = Field(min_length=1, max_length=16)
    valid_from_epoch: Epoch
    valid_until_epoch: Epoch
    trust_policy_digest_sha256: Hex64

    @model_validator(mode="after")
    def canonical_policy(self) -> Self:
        ids = [item.key_id for item in self.release_keys]
        if ids != sorted(set(ids)):
            raise ValueError("release_keys_not_canonical")
        if len({item.public_key_sha256 for item in self.release_keys}) != len(ids):
            raise ValueError("release_public_key_duplicate")
        if self.threshold > len(ids):
            raise ValueError("threshold_exceeds_key_count")
        versions = self.approved_producer_policy_versions
        if versions != sorted(set(versions)):
            raise ValueError("producer_policy_versions_not_canonical")
        servers = [item.server_implementation_digest for item in self.server_profiles]
        if servers != sorted(set(servers)):
            raise ValueError("server_profiles_not_canonical")
        if self.valid_until_epoch <= self.valid_from_epoch:
            raise ValueError("trust_policy_validity_window_invalid")
        verify_model_digest(self, "trust_policy_digest_sha256")
        return self


def build_static_site_trust_policy(
    *,
    threshold: int,
    release_keys: Sequence[StaticReleaseKey],
    approved_producer_policy_versions: Sequence[str],
    server_profiles: Sequence[StaticServerProfile],
    valid_from_epoch: int,
    valid_until_epoch: int,
) -> StaticSiteTrustPolicy:
    """Seal a local public-key policy; no secret key material is accepted."""

    unsigned: dict[str, object] = {
        "schema": STATIC_SITE_TRUST_POLICY_SCHEMA,
        "schema_version": 1,
        "purpose": STATIC_SITE_RELEASE_PURPOSE,
        "threshold": threshold,
        "release_keys": [
            model_document(revalidate(item, StaticReleaseKey))
            for item in sorted(release_keys, key=lambda item: item.key_id)
        ],
        "approved_producer_policy_versions": sorted(set(approved_producer_policy_versions)),
        "server_profiles": [
            model_document(revalidate(item, StaticServerProfile))
            for item in sorted(server_profiles, key=lambda item: item.server_implementation_digest)
        ],
        "valid_from_epoch": valid_from_epoch,
        "valid_until_epoch": valid_until_epoch,
    }
    return StaticSiteTrustPolicy.model_validate(
        {**unsigned, "trust_policy_digest_sha256": digest(unsigned)}
    )


def static_site_release_message(release: StaticSiteRelease) -> bytes:
    """The only domain-separated bytes a release authority key signs."""

    signed = model_document(revalidate(release, StaticSiteRelease), exclude={"signatures"})
    return STATIC_SITE_RELEASE_DOMAIN_SEPARATOR + b"\x00" + canonical_json(signed)


# --------------------------------------------------------------------------
# Assignment interface (public active-assignment manifest v3)
# --------------------------------------------------------------------------


class StaticEndpointTarget(StrictFrozenModel):
    """One published static endpoint incarnation, as bound by a verified manifest v3."""

    endpoint_id: EndpointID
    generation: PositiveCount
    miner_uid: UID
    miner_hotkey: Hotkey
    miner_service_public_key: Hex64
    ticket_digest: PrefixedDigest


class StaticDeploymentTarget(StrictFrozenModel):
    """One static deployment of a verified manifest v3: site binding and incarnations.

    The manifest v3 verifier owns the authenticity of these fields; this
    module only refuses shapes it could not probe safely.
    """

    deployment_id: DNSLabel
    route_host: Hostname
    site_digest: Hex64
    endpoints: list[StaticEndpointTarget] = Field(min_length=1, max_length=8)

    @model_validator(mode="after")
    def unique_endpoints(self) -> Self:
        ids = [item.endpoint_id for item in self.endpoints]
        if len(set(ids)) != len(ids):
            raise ValueError("static_target_endpoint_duplicate")
        return self


# --------------------------------------------------------------------------
# Verified index and abstention
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ExpectedStaticResponse:
    """The exact response a correct replica returns to one GET or HEAD of ``path``."""

    path: str
    method: Literal["GET", "HEAD"]
    kind: ResponseKind
    status: int
    content_type: str
    #: The ``Content-Length`` of the full representation (also for HEAD).
    content_length: int
    #: SHA-256 of the body on the wire; the empty-body digest for HEAD.
    body_sha256: str


_EMPTY_SHA256: Final = hashlib.sha256(b"").hexdigest()


@dataclass(frozen=True, slots=True)
class StaticIndexAbstention:
    """A static deployment the validator cannot judge: no probes, no score, no downgrade."""

    deployment_id: str
    site_digest: str
    code: AbstentionCode


@dataclass(frozen=True, slots=True)
class VerifiedStaticIndex:
    """A static site index authenticated under the validator's pinned policy."""

    target: StaticDeploymentTarget
    manifest: StaticSiteManifest
    release: StaticSiteRelease
    release_digest_sha256: str
    trust_policy_digest_sha256: str
    server: StaticServerProfile
    verified_signer_key_ids: tuple[str, ...]
    #: Request path -> file, for every exact and directory-index path.
    routes: Mapping[str, StaticSiteFile]

    @property
    def responses(self) -> tuple[ExpectedStaticResponse, ...]:
        """Every manifest-listed GET response, in path order."""

        return tuple(expected_static_response(self, "GET", path) for path in sorted(self.routes))


def _routes(manifest: StaticSiteManifest) -> dict[str, StaticSiteFile]:
    table: dict[str, StaticSiteFile] = {}
    for item in manifest.files:
        table[item.path] = item
        if item.path.rsplit("/", 1)[-1] == INDEX_DOCUMENT:
            table[item.path[: -len(INDEX_DOCUMENT)]] = item
    return table


def _file_response(
    path: str, method: Literal["GET", "HEAD"], kind: ResponseKind, item: StaticSiteFile
) -> ExpectedStaticResponse:
    return ExpectedStaticResponse(
        path=path,
        method=method,
        kind=kind,
        status=200,
        content_type=item.content_type,
        content_length=item.size_bytes,
        body_sha256=item.sha256 if method == "GET" else _EMPTY_SHA256,
    )


def expected_static_response(
    index: VerifiedStaticIndex, method: Literal["GET", "HEAD"], path: str
) -> ExpectedStaticResponse:
    """The single normative lookup: exact path, directory index, fallback, else 404.

    Query strings never reach lookup (signed probes carry none). A navigation
    request (last segment without an extension) that matches nothing receives
    the manifest-declared fallback file, if any; every other miss, including a
    missing asset, is the pinned handler's fixed 404.
    """

    validate_static_path(path)
    item = index.routes.get(path)
    if item is not None:
        kind: ResponseKind = "file" if item.path == path else "directory_index"
        return _file_response(path, method, kind, item)
    fallback = index.manifest.navigation_fallback_path
    if fallback is not None and _is_navigation(path):
        return _file_response(path, method, "navigation_fallback", index.routes[fallback])
    server = index.server
    return ExpectedStaticResponse(
        path=path,
        method=method,
        kind="not_found",
        status=404,
        content_type=server.not_found_content_type,
        content_length=server.not_found_size_bytes,
        body_sha256=server.not_found_sha256 if method == "GET" else _EMPTY_SHA256,
    )


def _decode_signature(value: str) -> bytes | None:
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return None
    if len(decoded) != 64 or base64.b64encode(decoded).decode("ascii") != value:
        return None
    return decoded


def _verify_release(
    release: StaticSiteRelease, policy: StaticSiteTrustPolicy, evaluation_epoch: int
) -> tuple[str, ...] | AbstentionCode:
    keys = {item.key_id: item for item in policy.release_keys}
    message = static_site_release_message(release)
    verified: list[str] = []
    for envelope in release.signatures:
        key = keys.get(envelope.signer_key_id)
        if key is None:
            return "signer_untrusted"
        if evaluation_epoch < key.valid_from_epoch:
            return "signer_not_yet_valid"
        if evaluation_epoch >= key.valid_until_epoch:
            return "signer_expired"
        if key.revoked_at_epoch is not None and key.revoked_at_epoch <= evaluation_epoch:
            return "signer_revoked"
        signature = _decode_signature(envelope.signature_base64)
        if signature is None:
            return "signature_invalid"
        try:
            Ed25519PublicKey.from_public_bytes(
                decode_ed25519_public_key_base64(key.public_key_base64)
            ).verify(signature, message)
        except (InvalidSignature, ValueError):
            return "signature_invalid"
        verified.append(key.key_id)
    if len(verified) < policy.threshold:
        return "threshold_not_met"
    return tuple(verified)


#: Model errors that mean "over a v1 cap", reported apart from malformed input.
_CAP_ERROR_TYPES: Final = frozenset({"too_long", "less_than_equal"})
_CAP_VALUE_ERRORS: Final = (
    "static_total_bytes_exceeded",
    "static_path_too_long",
    "static_path_too_deep",
)


def _manifest_abstention(exc: ValueError) -> AbstentionCode:
    if str(exc) == "document_not_canonical":
        return "index_not_canonical"
    cause = exc.__cause__
    if isinstance(cause, ValidationError):
        for error in cause.errors():
            message = str(error.get("msg", ""))
            if error["type"] in _CAP_ERROR_TYPES or any(
                code in message for code in _CAP_VALUE_ERRORS
            ):
                return "index_caps_exceeded"
            if "static_root_response_missing" in message:
                return "root_response_missing"
    return "index_invalid"


def ingest_static_index(
    target: StaticDeploymentTarget,
    manifest_bytes: bytes | None,
    release_bytes: bytes | None,
    policy: StaticSiteTrustPolicy,
    *,
    evaluation_epoch: int,
) -> VerifiedStaticIndex | StaticIndexAbstention:
    """Authenticate one fetched static index against its manifest v3 binding.

    ``None`` bytes mean the fetch failed. Every failure is an abstention with a
    stable code; nothing here raises for untrusted input.
    """

    target = revalidate(target, StaticDeploymentTarget)
    policy = revalidate(policy, StaticSiteTrustPolicy)

    def abstain(code: AbstentionCode) -> StaticIndexAbstention:
        return StaticIndexAbstention(target.deployment_id, target.site_digest, code)

    if evaluation_epoch < policy.valid_from_epoch:
        return abstain("trust_policy_not_yet_valid")
    if evaluation_epoch >= policy.valid_until_epoch:
        return abstain("trust_policy_expired")
    if manifest_bytes is None:
        return abstain("index_unavailable")
    if release_bytes is None:
        return abstain("release_unavailable")
    if len(manifest_bytes) > MAX_MANIFEST_BYTES:
        return abstain("index_oversized")
    if hashlib.sha256(manifest_bytes).hexdigest() != target.site_digest:
        return abstain("site_digest_mismatch")
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
    if (
        release.site_digest != target.site_digest
        or release.producer_policy_version != manifest.producer_policy_version
    ):
        return abstain("release_binding_mismatch")
    signers = _verify_release(release, policy, evaluation_epoch)
    if isinstance(signers, str):
        return abstain(signers)
    if release.producer_policy_version not in policy.approved_producer_policy_versions:
        return abstain("producer_policy_unapproved")
    server = next(
        (
            item
            for item in policy.server_profiles
            if item.server_implementation_digest == release.server_implementation_digest
        ),
        None,
    )
    if server is None:
        return abstain("server_implementation_unpinned")
    return VerifiedStaticIndex(
        target=target,
        manifest=manifest,
        release=release,
        release_digest_sha256=hashlib.sha256(release_bytes).hexdigest(),
        trust_policy_digest_sha256=policy.trust_policy_digest_sha256,
        server=server,
        verified_signer_key_ids=signers,
        routes=MappingProxyType(_routes(manifest)),
    )


def static_site_manifest_bytes(value: StaticSiteManifest) -> bytes:
    return model_bytes(value, StaticSiteManifest)


def static_site_release_bytes(value: StaticSiteRelease) -> bytes:
    return model_bytes(value, StaticSiteRelease)


def static_site_trust_policy_bytes(value: StaticSiteTrustPolicy) -> bytes:
    return model_bytes(value, StaticSiteTrustPolicy)


def parse_static_site_trust_policy(rendered: bytes) -> StaticSiteTrustPolicy:
    return parse_model(
        rendered,
        StaticSiteTrustPolicy,
        static_site_trust_policy_bytes,
        maximum_bytes=256 * 1_024,
    )
