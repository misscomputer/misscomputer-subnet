# SPDX-License-Identifier: AGPL-3.0-only
"""Bounded online public-validator probe of centrally published active assignments.

This module is the only network-capable boundary of the live-probe flow.  It
loads a locally pinned trust policy, obtains one signed active-assignment
manifest from an explicit operator-supplied file or URL, verifies it through
the pure :mod:`assignment_probe` core against a locked local acceptance state,
performs exactly one bounded HTTPS GET per published deployment route, and
seals one canonical probe report.  It never contacts a Miss Computer endpoint
unless the operator supplies the manifest source and runs the command, and it
has no wallet, RPC, signing, scheduling, scoring, submission, or activation
capability.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import os
import re
import secrets
import ssl
import stat
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Final, Literal, NoReturn, Protocol, cast
from urllib.parse import urlsplit

import httpx
from pydantic import ValidationError

from .assignment_probe import (
    MAX_DOCUMENT_BYTES,
    MAX_EPOCH,
    MAX_KEYS,
    PROBE_NONCE_HEADER,
    ActiveAssignmentManifest,
    AssignmentManifestChainState,
    AssignmentManifestSignatureEnvelope,
    AssignmentManifestTrustPolicy,
    AssignmentProbeError,
    ProbeObservation,
    ProbeResponse,
    ProbeTransportFailure,
    ValidatorProbeReport,
    assignment_manifest_chain_state_bytes,
    build_initial_manifest_chain_state,
    build_validator_probe_report,
    evaluate_probe_response,
    parse_active_assignment_manifest,
    parse_assignment_manifest_chain_state,
    parse_assignment_manifest_signature_envelope,
    parse_assignment_manifest_trust_policy,
    validator_probe_report_bytes,
    verify_active_assignment_manifest,
)
from .score_checkpoint_relay_cli import (
    CheckpointRelayCLIError,
    InputFile,
    _load_input_bytes,
    _normalized_absolute_path,
)

EXIT_OK: Final = 0
EXIT_REJECTED: Final = 2
EXIT_DEGRADED: Final = 3
EXIT_USAGE: Final = 64
EXIT_INTERNAL: Final = 70
EXIT_BUSY: Final = 75

STATE_ROOT_MODE: Final = 0o700
STATE_FILE_MODE: Final = 0o600
STATE_NAME: Final = "state.json"
STATE_INSTALL_NAME: Final = ".state.install"
LOCK_NAME: Final = "probe.lock"
MAX_TRUST_POLICY_BYTES: Final = 256 * 1_024
MAX_SIGNATURE_BYTES: Final = 16 * 1_024
MAX_STATE_BYTES: Final = 64 * 1_024
MAX_FETCH_BYTES: Final = 16 * 1_024 * 1_024
MAX_CA_BUNDLE_BYTES: Final = 1_024 * 1_024
USER_AGENT: Final = "misscomputer-assignment-probe/1"
_HOTKEY = re.compile(r"^[A-Za-z0-9]{1,128}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_HOSTNAME = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$"
)

TrustedStateAnchor = Literal["current", "genesis"] | str


class AssignmentProbeCLIError(ValueError):
    """Stable failure code whose text never contains an input value or path."""

    def __init__(self, code: str) -> None:
        safe = (
            code
            if code
            and len(code) <= 64
            and code.isascii()
            and all(
                character.islower() or character.isdigit() or character == "_" for character in code
            )
            else "internal_error"
        )
        super().__init__(safe)
        self.code = safe


def _fail(code: str) -> NoReturn:
    raise AssignmentProbeCLIError(code)


@dataclass(frozen=True, slots=True)
class ManifestSource:
    """Exactly one explicit manifest origin: a local canonical file or an HTTPS URL."""

    file: InputFile | None = None
    url: str | None = None

    def __post_init__(self) -> None:
        if (self.file is None) == (self.url is None):
            raise AssignmentProbeCLIError("manifest_source_invalid")


@dataclass(frozen=True, slots=True)
class SignatureSource:
    file: InputFile | None = None
    url: str | None = None

    def __post_init__(self) -> None:
        if (self.file is None) == (self.url is None):
            raise AssignmentProbeCLIError("signature_source_invalid")


@dataclass(frozen=True, slots=True)
class AssignmentProbeCLIConfig:
    trust_policy: InputFile
    manifest: ManifestSource
    signatures: tuple[SignatureSource, ...]
    evaluation_epoch: int
    validator_uid: int
    validator_hotkey: str
    state_root: str
    trusted_state_anchor: str
    report_output: str
    edge_origin: str | None = None
    tls_ca_file: str | None = None


@dataclass(frozen=True, slots=True)
class AssignmentProbeCLIResult:
    report: ValidatorProbeReport
    next_chain_state: AssignmentManifestChainState
    state_advanced: bool


class ProbeTransport(Protocol):
    """One bounded HTTPS GET; every outcome is classified, never raised."""

    def fetch(
        self,
        *,
        url: str,
        server_name: str,
        headers: Mapping[str, str],
        timeout_seconds: float,
        max_bytes: int,
    ) -> ProbeResponse | ProbeTransportFailure: ...


TransportFactory = Callable[[ssl.SSLContext], ProbeTransport]


def _exception_chain(exc: BaseException) -> list[BaseException]:
    seen: list[BaseException] = []
    current: BaseException | None = exc
    while current is not None and current not in seen and len(seen) < 16:
        seen.append(current)
        current = current.__cause__ or current.__context__
    return seen


def _classify_transport_error(exc: Exception) -> str:
    chain = _exception_chain(exc)
    if any(isinstance(item, httpx.TimeoutException | TimeoutError) for item in chain):
        return "timeout"
    if any(isinstance(item, ssl.SSLCertVerificationError) for item in chain):
        return "tls_certificate_invalid"
    if any(isinstance(item, ssl.SSLError) for item in chain):
        return "tls_handshake_failed"
    if isinstance(exc, httpx.ConnectError | ConnectionError | OSError):
        return "connection_failed"
    return "transport_error"


def _peer_leaf_sha256(response: httpx.Response) -> str | None:
    stream = response.extensions.get("network_stream")
    if stream is None:
        return None
    ssl_object = stream.get_extra_info("ssl_object")
    getter = getattr(ssl_object, "getpeercert", None)
    if getter is None:
        return None
    try:
        der = getter(True)
    except (ValueError, OSError):
        return None
    if not isinstance(der, bytes) or not der:
        return None
    return hashlib.sha256(der).hexdigest()


class HttpsProbeTransport:
    """httpx-based transport: no redirects, no environment proxies, exact byte bounds."""

    def __init__(self, ssl_context: ssl.SSLContext) -> None:
        self._context = ssl_context

    def fetch(
        self,
        *,
        url: str,
        server_name: str,
        headers: Mapping[str, str],
        timeout_seconds: float,
        max_bytes: int,
    ) -> ProbeResponse | ProbeTransportFailure:
        started = time.monotonic()
        deadline = started + timeout_seconds

        def elapsed_millis() -> int:
            return int((time.monotonic() - started) * 1000)

        leaf: str | None = None
        try:
            transport = httpx.HTTPTransport(verify=self._context, retries=0, http2=False)
            with httpx.Client(
                transport=transport,
                timeout=httpx.Timeout(timeout_seconds),
                follow_redirects=False,
                max_redirects=0,
                trust_env=False,
            ) as client:
                with client.stream(
                    "GET",
                    url,
                    headers=dict(headers),
                    extensions={"sni_hostname": server_name},
                ) as response:
                    leaf = _peer_leaf_sha256(response)
                    declared = response.headers.get("content-length")
                    if declared is not None and (
                        not declared.isascii()
                        or not declared.isdigit()
                        or int(declared) > max_bytes
                    ):
                        return ProbeTransportFailure(
                            "response_oversized",
                            elapsed_millis(),
                            response_status=response.status_code,
                            tls_leaf_certificate_sha256=leaf,
                        )
                    chunks: list[bytes] = []
                    total = 0
                    for chunk in response.iter_raw(chunk_size=16_384):
                        if time.monotonic() > deadline:
                            return ProbeTransportFailure(
                                "timeout",
                                elapsed_millis(),
                                response_status=response.status_code,
                                tls_leaf_certificate_sha256=leaf,
                            )
                        total += len(chunk)
                        if total > max_bytes:
                            return ProbeTransportFailure(
                                "response_oversized",
                                elapsed_millis(),
                                response_status=response.status_code,
                                tls_leaf_certificate_sha256=leaf,
                            )
                        chunks.append(chunk)
                    observed_headers = tuple(
                        (str(key), str(value)) for key, value in response.headers.multi_items()
                    )
                    return ProbeResponse(
                        status=response.status_code,
                        headers=observed_headers,
                        body=b"".join(chunks),
                        latency_millis=elapsed_millis(),
                        tls_leaf_certificate_sha256=leaf,
                    )
        except Exception as exc:  # noqa: BLE001 - every transport fault is classified
            code = _classify_transport_error(exc)
            return ProbeTransportFailure(
                cast(
                    Literal[
                        "connection_failed",
                        "response_oversized",
                        "timeout",
                        "tls_certificate_invalid",
                        "tls_handshake_failed",
                        "transport_error",
                    ],
                    code,
                ),
                elapsed_millis(),
                tls_leaf_certificate_sha256=leaf,
            )


def _default_transport_factory(context: ssl.SSLContext) -> ProbeTransport:
    return HttpsProbeTransport(context)


_SENSITIVE_COMPONENTS: Final = frozenset(
    {
        ".env",
        ".ssh",
        "credential",
        "credentials",
        "private-key",
        "private_key",
        "secret",
        "secrets",
        "wallet",
        "wallets",
    }
)


def _normalized_bundle_path(path: str) -> str:
    """Public certificate bundles may be ``.pem``/``.crt`` but never live beside secrets."""

    if (
        not isinstance(path, str)
        or not path
        or "\x00" in path
        or not path.startswith("/")
        or path.startswith("//")
        or path != os.path.normpath(path)
    ):
        _fail("ca_bundle_path_unsafe")
    components = path.split("/")[1:]
    if not components or any(
        not component
        or component.casefold() in _SENSITIVE_COMPONENTS
        or component.casefold().endswith((".key", ".p12", ".pfx"))
        for component in components
    ):
        _fail("ca_bundle_path_unsafe")
    return path


def _read_ca_bundle(path: str) -> str:
    normalized = _normalized_bundle_path(path)
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        descriptor = os.open(normalized, flags)
    except OSError as exc:
        raise AssignmentProbeCLIError("ca_bundle_unreadable") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_CA_BUNDLE_BYTES:
            _fail("ca_bundle_unsafe")
        rendered = os.read(descriptor, MAX_CA_BUNDLE_BYTES + 1)
        if not rendered or len(rendered) > MAX_CA_BUNDLE_BYTES or os.read(descriptor, 1):
            _fail("ca_bundle_unsafe")
    except OSError as exc:
        raise AssignmentProbeCLIError("ca_bundle_unreadable") from exc
    finally:
        os.close(descriptor)
    if b"PRIVATE KEY" in rendered or b"-----BEGIN CERTIFICATE-----" not in rendered:
        _fail("ca_bundle_unsafe")
    try:
        return rendered.decode("ascii")
    except UnicodeDecodeError as exc:
        raise AssignmentProbeCLIError("ca_bundle_unsafe") from exc


def build_probe_ssl_context(tls_ca_file: str | None) -> ssl.SSLContext:
    """Strict TLS 1.2+ client context trusting the system store or one explicit bundle."""

    try:
        if tls_ca_file is None:
            context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        else:
            context = ssl.create_default_context(
                ssl.Purpose.SERVER_AUTH, cadata=_read_ca_bundle(tls_ca_file)
            )
    except ssl.SSLError as exc:
        raise AssignmentProbeCLIError("ca_bundle_invalid") from exc
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    return context


def _validated_https_url(value: str, *, code: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 2_048 or not value.isascii():
        _fail(code)
    parts = urlsplit(value)
    if (
        parts.scheme != "https"
        or parts.username is not None
        or parts.password is not None
        or parts.fragment
        or parts.query
        or not parts.hostname
        or not _HOSTNAME.fullmatch(parts.hostname)
    ):
        _fail(code)
    try:
        port = parts.port
    except ValueError as exc:
        raise AssignmentProbeCLIError(code) from exc
    if port is not None and not 1 <= port <= 65_535:
        _fail(code)
    return value


def _validated_edge_origin(value: str) -> str:
    validated = _validated_https_url(value, code="edge_origin_invalid")
    parts = urlsplit(validated)
    if parts.path not in {"", "/"}:
        _fail("edge_origin_invalid")
    return validated.rstrip("/")


def _fetch_document(
    transport: ProbeTransport,
    url: str,
    *,
    max_bytes: int,
    timeout_seconds: float,
    code: str,
) -> bytes:
    validated = _validated_https_url(url, code=f"{code}_url_invalid")
    host = urlsplit(validated).hostname or ""
    result = transport.fetch(
        url=validated,
        server_name=host,
        headers={
            "accept": "application/json",
            "accept-encoding": "identity",
            "cache-control": "no-cache",
            "user-agent": USER_AGENT,
        },
        timeout_seconds=timeout_seconds,
        max_bytes=max_bytes,
    )
    if isinstance(result, ProbeTransportFailure):
        _fail(f"{code}_fetch_{result.code}")
    if result.status != 200:
        _fail(f"{code}_fetch_status_invalid")
    if not result.body:
        _fail(f"{code}_fetch_empty")
    return result.body


def _load_trust_policy(value: InputFile) -> AssignmentManifestTrustPolicy:
    from .production_release_verifier import HardenedFileSet

    try:
        rendered = _load_input_bytes(
            HardenedFileSet(),
            value,
            label="assignment_manifest_trust_policy",
            max_bytes=MAX_TRUST_POLICY_BYTES,
        )
    except CheckpointRelayCLIError as exc:
        raise AssignmentProbeCLIError(exc.code) from exc
    try:
        return parse_assignment_manifest_trust_policy(rendered)
    except (TypeError, ValueError, ValidationError, RecursionError) as exc:
        raise AssignmentProbeCLIError("trust_policy_invalid") from exc


def _load_file_bytes(value: InputFile, *, label: str, max_bytes: int) -> bytes:
    from .production_release_verifier import HardenedFileSet

    try:
        return _load_input_bytes(HardenedFileSet(), value, label=label, max_bytes=max_bytes)
    except CheckpointRelayCLIError as exc:
        raise AssignmentProbeCLIError(exc.code) from exc


def _load_publication(
    config: AssignmentProbeCLIConfig,
    transport: ProbeTransport,
    policy: AssignmentManifestTrustPolicy,
) -> tuple[ActiveAssignmentManifest, tuple[AssignmentManifestSignatureEnvelope, ...]]:
    timeout_seconds = policy.probe_timeout_millis / 1000
    if config.manifest.file is not None:
        manifest_bytes = _load_file_bytes(
            config.manifest.file,
            label="active_assignment_manifest",
            max_bytes=MAX_DOCUMENT_BYTES,
        )
    else:
        manifest_bytes = _fetch_document(
            transport,
            cast(str, config.manifest.url),
            max_bytes=MAX_FETCH_BYTES,
            timeout_seconds=timeout_seconds,
            code="manifest",
        )
    try:
        manifest = parse_active_assignment_manifest(manifest_bytes)
    except (TypeError, ValueError, ValidationError, RecursionError) as exc:
        raise AssignmentProbeCLIError("manifest_invalid") from exc
    if not 1 <= len(config.signatures) <= MAX_KEYS:
        _fail("signature_count_invalid")
    envelopes: list[AssignmentManifestSignatureEnvelope] = []
    for index, source in enumerate(config.signatures):
        if source.file is not None:
            rendered = _load_file_bytes(
                source.file,
                label=f"manifest_signature_{index:02d}",
                max_bytes=MAX_SIGNATURE_BYTES,
            )
        else:
            rendered = _fetch_document(
                transport,
                cast(str, source.url),
                max_bytes=MAX_SIGNATURE_BYTES,
                timeout_seconds=timeout_seconds,
                code="signature",
            )
        try:
            envelopes.append(parse_assignment_manifest_signature_envelope(rendered))
        except (TypeError, ValueError, ValidationError, RecursionError) as exc:
            raise AssignmentProbeCLIError("signature_invalid") from exc
    signer_ids = [item.signer_key_id for item in envelopes]
    if len(signer_ids) != len(set(signer_ids)):
        _fail("signature_set_noncanonical")
    return manifest, tuple(sorted(envelopes, key=lambda item: item.signer_key_id))


def _effective_uid() -> int:
    return os.geteuid() if hasattr(os, "geteuid") else os.getuid()


def _safe_parent(value: os.stat_result) -> bool:
    if not stat.S_ISDIR(value.st_mode) or value.st_uid not in {0, _effective_uid()}:
        return False
    unsafe = stat.S_IMODE(value.st_mode) & 0o022
    return not unsafe or bool(value.st_mode & stat.S_ISVTX)


class _StateRoot:
    """Exclusive owner-only directory holding one canonical acceptance state file."""

    def __init__(self, path: str) -> None:
        self.path = _normalized_absolute_path(path, code="state_root_path_unsafe")
        self._directory_fd = -1
        self._lock_fd = -1
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        parent_path, name = self.path.rsplit("/", 1)
        parent_path = parent_path or "/"
        try:
            parent_fd = os.open(parent_path, flags)
        except OSError as exc:
            raise AssignmentProbeCLIError("state_root_unsafe") from exc
        try:
            if not _safe_parent(os.fstat(parent_fd)):
                _fail("state_root_unsafe")
            try:
                os.mkdir(name, STATE_ROOT_MODE, dir_fd=parent_fd)
                os.fsync(parent_fd)
            except FileExistsError:
                pass
            except OSError as exc:
                raise AssignmentProbeCLIError("state_root_unsafe") from exc
            self._directory_fd = os.open(name, flags, dir_fd=parent_fd)
            metadata = os.fstat(self._directory_fd)
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != _effective_uid()
                or stat.S_IMODE(metadata.st_mode) != STATE_ROOT_MODE
            ):
                _fail("state_root_unsafe")
            self._lock()
        except OSError as exc:
            self.close()
            raise AssignmentProbeCLIError("state_root_unsafe") from exc
        except AssignmentProbeCLIError:
            self.close()
            raise
        finally:
            os.close(parent_fd)

    def _lock(self) -> None:
        flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC
        self._lock_fd = os.open(LOCK_NAME, flags, STATE_FILE_MODE, dir_fd=self._directory_fd)
        metadata = os.fstat(self._lock_fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != _effective_uid():
            _fail("state_root_unsafe")
        try:
            fcntl.flock(self._lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise AssignmentProbeCLIError("probe_busy") from exc

    def entries(self) -> set[str]:
        try:
            return set(os.listdir(self._directory_fd))
        except OSError as exc:
            raise AssignmentProbeCLIError("state_root_unsafe") from exc

    def read_state(self) -> AssignmentManifestChainState | None:
        entries = self.entries()
        if STATE_NAME not in entries:
            return None
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
        try:
            descriptor = os.open(STATE_NAME, flags, dir_fd=self._directory_fd)
        except OSError as exc:
            raise AssignmentProbeCLIError("state_file_unsafe") from exc
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != _effective_uid()
                or stat.S_IMODE(metadata.st_mode) != STATE_FILE_MODE
                or metadata.st_nlink != 1
                or not 0 < metadata.st_size <= MAX_STATE_BYTES
            ):
                _fail("state_file_unsafe")
            rendered = os.read(descriptor, MAX_STATE_BYTES + 1)
            if len(rendered) != metadata.st_size or os.read(descriptor, 1):
                _fail("state_file_unsafe")
        except OSError as exc:
            raise AssignmentProbeCLIError("state_file_unsafe") from exc
        finally:
            os.close(descriptor)
        try:
            return parse_assignment_manifest_chain_state(rendered)
        except (TypeError, ValueError, ValidationError, RecursionError) as exc:
            raise AssignmentProbeCLIError("state_file_invalid") from exc

    def replace_state(self, rendered: bytes) -> None:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
        try:
            descriptor = os.open(
                STATE_INSTALL_NAME, flags, STATE_FILE_MODE, dir_fd=self._directory_fd
            )
        except FileExistsError as exc:
            raise AssignmentProbeCLIError("state_install_residue") from exc
        except OSError as exc:
            raise AssignmentProbeCLIError("state_write_failed") from exc
        try:
            os.fchmod(descriptor, STATE_FILE_MODE)
            view = memoryview(rendered)
            offset = 0
            while offset < len(view):
                written = os.write(descriptor, view[offset:])
                if written <= 0:
                    _fail("state_write_failed")
                offset += written
            os.fsync(descriptor)
            os.replace(
                STATE_INSTALL_NAME,
                STATE_NAME,
                src_dir_fd=self._directory_fd,
                dst_dir_fd=self._directory_fd,
            )
            os.fsync(self._directory_fd)
        except OSError as exc:
            raise AssignmentProbeCLIError("state_write_failed") from exc
        finally:
            os.close(descriptor)
        installed = self.read_state()
        if installed is None or assignment_manifest_chain_state_bytes(installed) != rendered:
            _fail("state_write_failed")

    def close(self) -> None:
        if self._lock_fd >= 0:
            try:
                fcntl.flock(self._lock_fd, fcntl.LOCK_UN)
            except OSError:
                pass
            os.close(self._lock_fd)
            self._lock_fd = -1
        if self._directory_fd >= 0:
            os.close(self._directory_fd)
            self._directory_fd = -1

    def __enter__(self) -> _StateRoot:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


def _resolve_prior_state(
    root: _StateRoot,
    policy: AssignmentManifestTrustPolicy,
    anchor: str,
) -> AssignmentManifestChainState:
    existing = root.read_state()
    if anchor == "genesis":
        if existing is not None or root.entries() - {LOCK_NAME}:
            _fail("state_anchor_stale")
        return build_initial_manifest_chain_state(policy)
    if existing is None:
        _fail("state_missing")
    if anchor == "current":
        pass
    elif _DIGEST.fullmatch(anchor) is None:
        _fail("state_anchor_invalid")
    elif existing.state_digest_sha256 != anchor:
        _fail("state_anchor_stale")
    if (
        existing.trust_policy_digest_sha256 != policy.trust_policy_digest_sha256
        or existing.central_authority_fingerprint_sha256
        != policy.central_authority_fingerprint_sha256
    ):
        _fail("state_binding_mismatch")
    return existing


def _output_target(path: str, *, state_root: str) -> tuple[str, str]:
    normalized = _normalized_absolute_path(path, code="output_path_unsafe")
    if normalized == state_root or normalized.startswith(state_root + "/"):
        _fail("output_path_unsafe")
    parent_path, name = normalized.rsplit("/", 1)
    if not name or name in {".", ".."}:
        _fail("output_path_unsafe")
    return parent_path or "/", name


def _preflight_output(path: str, *, state_root: str) -> None:
    parent_path, name = _output_target(path, state_root=state_root)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        parent_fd = os.open(parent_path, flags)
    except OSError as exc:
        raise AssignmentProbeCLIError("output_parent_unsafe") from exc
    try:
        if not _safe_parent(os.fstat(parent_fd)):
            _fail("output_parent_unsafe")
        try:
            os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        except OSError as exc:
            raise AssignmentProbeCLIError("output_unsafe") from exc
        _fail("output_exists")
    finally:
        os.close(parent_fd)


def _write_output(path: str, rendered: bytes, *, state_root: str) -> None:
    parent_path, name = _output_target(path, state_root=state_root)
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        parent_fd = os.open(parent_path, directory_flags)
    except OSError as exc:
        raise AssignmentProbeCLIError("output_parent_unsafe") from exc
    try:
        if not _safe_parent(os.fstat(parent_fd)):
            _fail("output_parent_unsafe")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
        try:
            descriptor = os.open(name, flags, STATE_FILE_MODE, dir_fd=parent_fd)
        except FileExistsError as exc:
            raise AssignmentProbeCLIError("output_exists") from exc
        except OSError as exc:
            raise AssignmentProbeCLIError("output_write_failed") from exc
        try:
            os.fchmod(descriptor, STATE_FILE_MODE)
            view = memoryview(rendered)
            offset = 0
            while offset < len(view):
                written = os.write(descriptor, view[offset:])
                if written <= 0:
                    _fail("output_write_failed")
                offset += written
            os.fsync(descriptor)
            os.fsync(parent_fd)
        except OSError as exc:
            raise AssignmentProbeCLIError("output_write_failed") from exc
        finally:
            os.close(descriptor)
    finally:
        os.close(parent_fd)


def _probe_url(
    manifest: ActiveAssignmentManifest,
    route_host: str,
    challenge_path: str,
    edge_origin: str | None,
) -> str:
    if edge_origin is not None:
        return f"{edge_origin}{challenge_path}"
    return f"{manifest.probe_scheme}://{route_host}:{manifest.probe_port}{challenge_path}"


def probe_manifest_deployments(
    manifest: ActiveAssignmentManifest,
    policy: AssignmentManifestTrustPolicy,
    transport: ProbeTransport,
    *,
    edge_origin: str | None,
    nonce_source: Callable[[], str] = lambda: secrets.token_hex(32),
) -> list[ProbeObservation]:
    """Issue exactly one bounded GET per published deployment route, in canonical order."""

    observations: list[ProbeObservation] = []
    for deployment in manifest.deployments:
        probe_nonce = nonce_source()
        result = transport.fetch(
            url=_probe_url(manifest, deployment.route_host, deployment.challenge_path, edge_origin),
            server_name=deployment.route_host,
            headers={
                "host": deployment.route_host,
                "accept": "*/*",
                "accept-encoding": "identity",
                "cache-control": "no-cache",
                "user-agent": USER_AGENT,
                PROBE_NONCE_HEADER: probe_nonce,
            },
            timeout_seconds=policy.probe_timeout_millis / 1000,
            max_bytes=policy.max_response_bytes,
        )
        observations.append(
            evaluate_probe_response(
                deployment,
                policy,
                probe_nonce=probe_nonce,
                result=result,
            )
        )
    return observations


def execute_assignment_probe(
    config: AssignmentProbeCLIConfig,
    *,
    transport_factory: TransportFactory = _default_transport_factory,
) -> AssignmentProbeCLIResult:
    """Verify one manifest publication, probe every route once, and seal the report."""

    if (
        isinstance(config.evaluation_epoch, bool)
        or not isinstance(config.evaluation_epoch, int)
        or not 0 <= config.evaluation_epoch <= MAX_EPOCH
        or isinstance(config.validator_uid, bool)
        or not isinstance(config.validator_uid, int)
        or not 0 <= config.validator_uid <= (1 << 16) - 1
        or not isinstance(config.validator_hotkey, str)
        or _HOTKEY.fullmatch(config.validator_hotkey) is None
    ):
        _fail("operator_context_invalid")
    edge_origin = (
        _validated_edge_origin(config.edge_origin) if config.edge_origin is not None else None
    )
    ssl_context = build_probe_ssl_context(config.tls_ca_file)
    transport = transport_factory(ssl_context)
    policy = _load_trust_policy(config.trust_policy)
    file_inputs: list[InputFile] = [config.trust_policy]
    if config.manifest.file is not None:
        file_inputs.append(config.manifest.file)
    file_inputs.extend(item.file for item in config.signatures if item.file is not None)
    input_paths = {
        _normalized_absolute_path(item.path, code="input_path_unsafe") for item in file_inputs
    }
    with _StateRoot(config.state_root) as root:
        if _normalized_absolute_path(config.report_output, code="output_path_unsafe") in (
            input_paths
        ):
            _fail("output_path_alias")
        _preflight_output(config.report_output, state_root=root.path)
        prior_state = _resolve_prior_state(root, policy, config.trusted_state_anchor)
        manifest, signatures = _load_publication(config, transport, policy)
        verification = verify_active_assignment_manifest(
            manifest,
            signatures,
            policy,
            prior_state,
            evaluation_epoch=config.evaluation_epoch,
        )
        state_advanced = not verification.reprobe
        if state_advanced:
            root.replace_state(assignment_manifest_chain_state_bytes(verification.next_chain_state))
        observations = probe_manifest_deployments(
            verification.manifest,
            policy,
            transport,
            edge_origin=edge_origin,
        )
        report = build_validator_probe_report(
            verification,
            policy,
            prior_state,
            observations,
            validator_uid=config.validator_uid,
            validator_hotkey=config.validator_hotkey,
            evaluation_epoch=config.evaluation_epoch,
            edge_origin_override=edge_origin is not None,
        )
        _write_output(
            config.report_output,
            validator_probe_report_bytes(report),
            state_root=root.path,
        )
    return AssignmentProbeCLIResult(
        report=report,
        next_chain_state=verification.next_chain_state,
        state_advanced=state_advanced,
    )


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        del message
        raise AssignmentProbeCLIError("usage")


def _unsigned_decimal(value: str) -> int:
    if (
        not value
        or not value.isascii()
        or not value.isdigit()
        or (len(value) > 1 and value.startswith("0"))
    ):
        raise argparse.ArgumentTypeError("invalid")
    parsed = int(value)
    if parsed > MAX_EPOCH:
        raise argparse.ArgumentTypeError("invalid")
    return parsed


def _parser() -> argparse.ArgumentParser:
    parser = _ArgumentParser(
        prog="misscomputer-assignment-probe",
        description="Bounded online public-validator probe of signed active assignments.",
        allow_abbrev=False,
        add_help=False,
    )
    parser.add_argument("--trust-policy", required=True)
    parser.add_argument("--trust-policy-sha256", required=True)
    manifest = parser.add_mutually_exclusive_group(required=True)
    manifest.add_argument("--manifest-file")
    manifest.add_argument("--manifest-url")
    parser.add_argument("--manifest-sha256")
    parser.add_argument("--signature-file", action="append", default=[])
    parser.add_argument("--signature-sha256", action="append", default=[])
    parser.add_argument("--signature-url", action="append", default=[])
    parser.add_argument("--evaluation-epoch", required=True, type=_unsigned_decimal)
    parser.add_argument("--validator-uid", required=True, type=_unsigned_decimal)
    parser.add_argument("--validator-hotkey", required=True)
    parser.add_argument("--state-root", required=True)
    parser.add_argument("--trusted-state-anchor", required=True)
    parser.add_argument("--report-output", required=True)
    parser.add_argument("--edge-origin")
    parser.add_argument("--tls-ca-file")
    return parser


def _config_from_arguments(arguments: argparse.Namespace) -> AssignmentProbeCLIConfig:
    signature_files = cast(list[str], arguments.signature_file)
    signature_digests = cast(list[str], arguments.signature_sha256)
    signature_urls = cast(list[str], arguments.signature_url)
    if len(signature_files) != len(signature_digests):
        _fail("signature_count_invalid")
    manifest_file = cast(str | None, arguments.manifest_file)
    manifest_digest = cast(str | None, arguments.manifest_sha256)
    if (manifest_file is None) != (manifest_digest is None):
        _fail("usage")
    manifest = (
        ManifestSource(file=InputFile(manifest_file, cast(str, manifest_digest)))
        if manifest_file is not None
        else ManifestSource(url=cast(str, arguments.manifest_url))
    )
    signatures = (
        *(
            SignatureSource(file=InputFile(path, digest))
            for path, digest in zip(signature_files, signature_digests, strict=True)
        ),
        *(SignatureSource(url=url) for url in signature_urls),
    )
    if not signatures:
        _fail("usage")
    return AssignmentProbeCLIConfig(
        trust_policy=InputFile(
            cast(str, arguments.trust_policy), cast(str, arguments.trust_policy_sha256)
        ),
        manifest=manifest,
        signatures=signatures,
        evaluation_epoch=cast(int, arguments.evaluation_epoch),
        validator_uid=cast(int, arguments.validator_uid),
        validator_hotkey=cast(str, arguments.validator_hotkey),
        state_root=cast(str, arguments.state_root),
        trusted_state_anchor=cast(str, arguments.trusted_state_anchor),
        report_output=cast(str, arguments.report_output),
        edge_origin=cast(str | None, arguments.edge_origin),
        tls_ca_file=cast(str | None, arguments.tls_ca_file),
    )


def run_cli(argv: Sequence[str]) -> int:
    """Run with stable statuses and without echoing arguments, paths, or content."""

    try:
        arguments = _parser().parse_args(list(argv))
        result = execute_assignment_probe(_config_from_arguments(arguments))
        report = result.report
        sys.stdout.write(
            f"PROBED status={report.status} deployments={report.deployment_count} "
            f"serving={report.serving_count} failed={report.failed_count} "
            f"next_state_sha256={result.next_chain_state.state_digest_sha256}\n"
        )
        return EXIT_OK if report.status == "serving" else EXIT_DEGRADED
    except AssignmentProbeError as exc:
        sys.stderr.write(f"REJECTED {exc.code}\n")
        return EXIT_REJECTED
    except AssignmentProbeCLIError as exc:
        sys.stderr.write(f"REJECTED {exc.code}\n")
        if exc.code == "usage":
            return EXIT_USAGE
        if exc.code == "probe_busy":
            return EXIT_BUSY
        return EXIT_REJECTED
    except CheckpointRelayCLIError as exc:
        sys.stderr.write(f"REJECTED {exc.code}\n")
        return EXIT_REJECTED
    except (ValidationError, TypeError, ValueError):
        sys.stderr.write("REJECTED input_contract_invalid\n")
        return EXIT_REJECTED
    except Exception:
        sys.stderr.write("ERROR internal_error\n")
        return EXIT_INTERNAL


def main() -> None:
    raise SystemExit(run_cli(sys.argv[1:]))


if __name__ == "__main__":
    main()
