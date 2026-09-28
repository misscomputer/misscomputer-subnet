# SPDX-License-Identifier: AGPL-3.0-only
"""Exact-leaf TLS validation and permissionless bootstrap helpers."""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import os
import ssl
import stat
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtendedKeyUsageOID

MAX_CERTIFICATE_BYTES = 64 << 10
MAX_CERTIFICATE_FILE_BYTES = 1 << 20
MAX_PRIVATE_KEY_BYTES = 1 << 20
MINIMUM_TLS_VERSION = ssl.TLSVersion.TLSv1_2


@dataclass(frozen=True, slots=True)
class MinerTLSConfig:
    cert_file: str
    key_file: str
    fingerprint_sha256: str
    leaf_der: bytes = field(repr=False)
    server_context: ssl.SSLContext = field(repr=False, compare=False)


def _read_regular_file(path_value: str, *, private_key: bool, limit: int) -> bytes:
    path = Path(path_value)
    try:
        before = path.lstat()
    except OSError as exc:
        kind = "key" if private_key else "certificate"
        raise ValueError(f"TLS {kind} file is not readable") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise ValueError("TLS files must be regular non-symlink files")
    if private_key and before.st_mode & 0o077:
        raise ValueError("TLS private key permissions must not grant group or other access")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        kind = "key" if private_key else "certificate"
        raise ValueError(f"TLS {kind} file is not readable") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_dev != before.st_dev
            or opened.st_ino != before.st_ino
            or (private_key and opened.st_mode & 0o077)
        ):
            raise ValueError("TLS file identity or private-key permissions changed during startup")
        with os.fdopen(descriptor, "rb", closefd=False) as source:
            payload = source.read(limit + 1)
        if not payload or len(payload) > limit:
            raise ValueError("TLS file is empty or exceeds its startup size limit")
        return payload
    finally:
        os.close(descriptor)


def _certificate_times(certificate: x509.Certificate) -> tuple[datetime, datetime]:
    # The pinned cryptography release exposes aware UTC properties. The
    # fallback keeps source compatibility with older system packages used by
    # lightweight operator checks, without normalizing signed protocol data.
    not_before = getattr(certificate, "not_valid_before_utc", None)
    not_after = getattr(certificate, "not_valid_after_utc", None)
    if not_before is None:
        not_before = certificate.not_valid_before.replace(tzinfo=UTC)
    if not_after is None:
        not_after = certificate.not_valid_after.replace(tzinfo=UTC)
    return not_before, not_after


def validate_leaf_certificate(der: bytes, *, now: datetime | None = None) -> x509.Certificate:
    if not der or len(der) > MAX_CERTIFICATE_BYTES:
        raise ValueError("TLS leaf certificate DER is empty or too large")
    try:
        certificate = x509.load_der_x509_certificate(der)
    except ValueError as exc:
        raise ValueError("TLS leaf certificate DER is malformed") from exc
    current = now or datetime.now(UTC)
    not_before, not_after = _certificate_times(certificate)
    if current < not_before:
        raise ValueError("TLS leaf certificate is not yet valid")
    if current >= not_after:
        raise ValueError("TLS leaf certificate is expired")
    try:
        basic_constraints = certificate.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value
    except x509.ExtensionNotFound as exc:
        raise ValueError("TLS leaf certificate must declare CA=false") from exc
    if basic_constraints.ca:
        # An exact trusted non-CA leaf cannot validate attacker-controlled
        # descendants, which makes leaf-only trust equivalent to an exact pin.
        raise ValueError("TLS leaf certificate must not be a CA certificate")
    try:
        usage = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound:
        usage = None
    if usage is not None and ExtendedKeyUsageOID.SERVER_AUTH not in usage:
        raise ValueError("TLS leaf certificate is not valid for server authentication")
    return certificate


def certificate_fingerprint_sha256(der: bytes) -> str:
    validate_leaf_certificate(der)
    return hashlib.sha256(der).hexdigest()


def _load_server_context(cert_pem: bytes, key_pem: bytes) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = MINIMUM_TLS_VERSION
    if not hasattr(os, "memfd_create"):
        raise ValueError("secure in-memory TLS context loading is unavailable on this platform")
    cert_fd = os.memfd_create("miner-tls-cert", flags=getattr(os, "MFD_CLOEXEC", 0))
    key_fd = os.memfd_create("miner-tls-key", flags=getattr(os, "MFD_CLOEXEC", 0))
    try:
        os.write(cert_fd, cert_pem)
        os.write(key_fd, key_pem)
        os.lseek(cert_fd, 0, os.SEEK_SET)
        os.lseek(key_fd, 0, os.SEEK_SET)
        context.load_cert_chain(f"/proc/self/fd/{cert_fd}", f"/proc/self/fd/{key_fd}")
    except (OSError, ssl.SSLError) as exc:
        raise ValueError("TLS certificate and private key do not form a loadable pair") from exc
    finally:
        os.close(cert_fd)
        os.close(key_fd)
    return context


def _require_certificate_only_pem(payload: bytes) -> None:
    """Reject private keys or unrelated PEM material in the public cert file."""
    begin = b"-----BEGIN CERTIFICATE-----"
    end = b"-----END CERTIFICATE-----"
    remaining = payload.strip()
    blocks = 0
    while remaining:
        if not remaining.startswith(begin):
            raise ValueError("TLS certificate file must contain only PEM certificates")
        end_at = remaining.find(end, len(begin))
        if end_at < 0:
            raise ValueError("TLS certificate file contains an incomplete PEM certificate")
        blocks += 1
        remaining = remaining[end_at + len(end) :].lstrip(b" \t\r\n")
    if blocks == 0:
        raise ValueError("TLS certificate file has no leaf certificate")


def validate_miner_tls_files(cert_file: str, key_file: str) -> MinerTLSConfig:
    cert_pem = _read_regular_file(cert_file, private_key=False, limit=MAX_CERTIFICATE_FILE_BYTES)
    key_pem = _read_regular_file(key_file, private_key=True, limit=MAX_PRIVATE_KEY_BYTES)
    _require_certificate_only_pem(cert_pem)
    try:
        certificates = x509.load_pem_x509_certificates(cert_pem)
    except ValueError as exc:
        raise ValueError("TLS certificate file does not contain valid PEM certificates") from exc
    if not certificates:
        raise ValueError("TLS certificate file has no leaf certificate")
    leaf = certificates[0]
    leaf_der = leaf.public_bytes(serialization.Encoding.DER)
    validate_leaf_certificate(leaf_der)
    try:
        private_key = serialization.load_pem_private_key(key_pem, password=None)
    except (TypeError, ValueError) as exc:
        raise ValueError("TLS private key must be an unencrypted valid PEM key") from exc
    public_format = serialization.PublicFormat.SubjectPublicKeyInfo
    certificate_public = leaf.public_key().public_bytes(serialization.Encoding.DER, public_format)
    private_public = private_key.public_key().public_bytes(
        serialization.Encoding.DER, public_format
    )
    if certificate_public != private_public:
        raise ValueError("TLS certificate and private key do not match")
    context = _load_server_context(cert_pem, key_pem)
    return MinerTLSConfig(
        cert_file=cert_file,
        key_file=key_file,
        fingerprint_sha256=hashlib.sha256(leaf_der).hexdigest(),
        leaf_der=leaf_der,
        server_context=context,
    )


def pinned_client_context(leaf_der: bytes) -> ssl.SSLContext:
    certificate = validate_leaf_certificate(leaf_der)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = MINIMUM_TLS_VERSION
    context.check_hostname = False
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(
        cadata=certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")
    )
    partial_chain = getattr(ssl, "VERIFY_X509_PARTIAL_CHAIN", 0)
    if partial_chain:
        context.verify_flags |= partial_chain
    return context


async def tls_leaf_preflight(host: str, port: int, *, timeout: float) -> bytes:
    if timeout <= 0:
        raise ValueError("TLS preflight timeout must be positive")
    bootstrap = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    bootstrap.minimum_version = MINIMUM_TLS_VERSION
    bootstrap.check_hostname = False
    bootstrap.verify_mode = ssl.CERT_NONE
    writer: asyncio.StreamWriter | None = None
    started = time.monotonic()
    try:
        _, connected_writer = await asyncio.wait_for(
            asyncio.open_connection(
                host,
                port,
                ssl=bootstrap,
                server_hostname=None,
                ssl_handshake_timeout=timeout,
            ),
            timeout=timeout,
        )
        writer = connected_writer
        ssl_object = connected_writer.get_extra_info("ssl_object")
        if not isinstance(ssl_object, ssl.SSLObject):
            raise ValueError("TLS preflight did not negotiate a TLS peer")
        der = ssl_object.getpeercert(binary_form=True)
        if not isinstance(der, bytes):
            raise ValueError("TLS preflight peer did not present a leaf certificate")
        validate_leaf_certificate(der)
        return der
    except TimeoutError as exc:
        raise TimeoutError("TLS preflight connection timed out") from exc
    finally:
        if writer is not None:
            writer.close()
            remaining = max(0.0, timeout - (time.monotonic() - started))
            if remaining > 0:
                # Cleanup errors and the cleanup bound itself are non-fatal,
                # but caller cancellation at this await must never be converted
                # into a successful DER preflight result.
                with contextlib.suppress(Exception):
                    await asyncio.wait_for(writer.wait_closed(), timeout=min(remaining, 1.0))
