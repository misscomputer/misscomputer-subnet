# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import errno
import hashlib
import ipaddress
import os
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

import misscomputer_subnet.score_checkpoint_relay_cli as relay_cli

_SMALL_ORDER_ED25519_PUBLIC_KEYS = {
    "y_zero": "00" * 32,
    "y_zero_sign": "00" * 31 + "80",
    "identity": "01" + "00" * 31,
    "identity_sign": "01" + "00" * 30 + "80",
    "order_eight_a": "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "order_eight_a_sign": ("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85"),
    "order_eight_b": "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "order_eight_b_sign": ("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"),
    "p_minus_one": "ec" + "ff" * 30 + "7f",
    "p_minus_one_sign": "ec" + "ff" * 30 + "ff",
    "noncanonical_zero": "ed" + "ff" * 30 + "7f",
    "noncanonical_zero_sign": "ed" + "ff" * 30 + "ff",
    "noncanonical_identity": "ee" + "ff" * 30 + "7f",
    "noncanonical_identity_sign": "ee" + "ff" * 30 + "ff",
}


@pytest.fixture(
    params=tuple(_SMALL_ORDER_ED25519_PUBLIC_KEYS.values()),
    ids=tuple(_SMALL_ORDER_ED25519_PUBLIC_KEYS),
)
def small_order_ed25519_public_key(request: pytest.FixtureRequest) -> bytes:
    return bytes.fromhex(request.param)


def write_certificate(
    root: Path,
    name: str,
    *,
    host: str = "127.0.0.1",
    not_before: datetime | None = None,
    not_after: datetime | None = None,
    key: ec.EllipticCurvePrivateKey | None = None,
    ca: bool = False,
) -> tuple[Path, Path, bytes, str]:
    current = datetime.now(UTC)
    private_key = key or ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
    serial = int.from_bytes(hashlib.sha256(name.encode()).digest()[:19], "big") or 1
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(serial)
        .not_valid_before(not_before or current - timedelta(minutes=1))
        .not_valid_after(not_after or current + timedelta(days=30))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(host))]),
            True,
        )
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()), False)
        .sign(private_key, hashes.SHA256())
    )
    cert_path = root / f"{name}.crt"
    key_path = root / f"{name}.key"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    os.chmod(cert_path, 0o644)
    os.chmod(key_path, 0o600)
    der = certificate.public_bytes(serialization.Encoding.DER)
    return cert_path, key_path, der, hashlib.sha256(der).hexdigest()


@pytest.fixture
def certificate_factory(
    tmp_path: Path,
) -> Callable[..., tuple[Path, Path, bytes, str]]:
    def factory(name: str, **values: object) -> tuple[Path, Path, bytes, str]:
        return write_certificate(tmp_path, name, **values)  # type: ignore[arg-type]

    return factory


@pytest.fixture
def unprivileged_linkat(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    """Refuse ``linkat(AT_EMPTY_PATH)`` exactly as Linux before 6.10 does for a caller
    without ``CAP_DAC_READ_SEARCH`` (``ENOENT``), and record every linkat flag word."""

    original = relay_cli._linkat
    flags_seen: list[int] = []

    def denied(olddirfd: int, oldpath: bytes, newdirfd: int, newpath: bytes, flags: int) -> int:
        flags_seen.append(flags)
        if flags & relay_cli._AT_EMPTY_PATH:
            return errno.ENOENT
        return original(olddirfd, oldpath, newdirfd, newpath, flags)

    monkeypatch.setattr(relay_cli, "_linkat", denied)
    return flags_seen
