# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import hashlib
import os
import sys
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from misscomputer_subnet import miner
from misscomputer_subnet.tls import validate_miner_tls_files

CertificateFactory = Callable[..., tuple[Path, Path, bytes, str]]


def test_valid_miner_tls_files_produce_stable_exact_leaf_pin(
    certificate_factory: CertificateFactory,
) -> None:
    cert, key, der, expected = certificate_factory("valid")
    first = validate_miner_tls_files(str(cert), str(key))
    second = validate_miner_tls_files(str(cert), str(key))
    assert first.fingerprint_sha256 == expected == hashlib.sha256(der).hexdigest()
    assert second.fingerprint_sha256 == first.fingerprint_sha256
    assert first.leaf_der == der
    assert "leaf_der" not in repr(first)


@pytest.mark.parametrize("when", ["expired", "not-yet-valid"])
def test_miner_rejects_noncurrent_certificate(
    certificate_factory: CertificateFactory, when: str
) -> None:
    current = datetime.now(UTC)
    if when == "expired":
        not_before, not_after = current - timedelta(days=2), current - timedelta(days=1)
    else:
        not_before, not_after = current + timedelta(days=1), current + timedelta(days=2)
    cert, key, _, _ = certificate_factory(when, not_before=not_before, not_after=not_after)
    with pytest.raises(ValueError, match="expired|not yet valid"):
        validate_miner_tls_files(str(cert), str(key))


def test_miner_rejects_mismatched_pair_and_ca_leaf(
    certificate_factory: CertificateFactory,
) -> None:
    cert, _, _, _ = certificate_factory("cert")
    _, other_key, _, _ = certificate_factory("other")
    with pytest.raises(ValueError, match="do not match"):
        validate_miner_tls_files(str(cert), str(other_key))

    ca_cert, ca_key, _, _ = certificate_factory("ca", ca=True)
    with pytest.raises(ValueError, match="must not be a CA"):
        validate_miner_tls_files(str(ca_cert), str(ca_key))


def test_miner_rejects_symlinks_nonregular_files_and_weak_key_mode(
    certificate_factory: CertificateFactory, tmp_path: Path
) -> None:
    cert, key, _, _ = certificate_factory("permissions")
    os.chmod(key, 0o640)
    with pytest.raises(ValueError, match="permissions"):
        validate_miner_tls_files(str(cert), str(key))
    os.chmod(key, 0o600)

    key_link = tmp_path / "linked.key"
    key_link.symlink_to(key)
    with pytest.raises(ValueError, match="non-symlink"):
        validate_miner_tls_files(str(cert), str(key_link))

    directory = tmp_path / "certificate-directory"
    directory.mkdir()
    with pytest.raises(ValueError, match="regular"):
        validate_miner_tls_files(str(directory), str(key))


def test_miner_rejects_encrypted_private_key(
    certificate_factory: CertificateFactory, tmp_path: Path
) -> None:
    cert, _, _, _ = certificate_factory("encrypted-cert")
    private_key = ec.generate_private_key(ec.SECP256R1())
    from cryptography.hazmat.primitives import serialization

    encrypted = tmp_path / "encrypted.key"
    encrypted.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(b"test-only-password"),
        )
    )
    os.chmod(encrypted, 0o600)
    with pytest.raises(ValueError, match="unencrypted"):
        validate_miner_tls_files(str(cert), str(encrypted))


def test_miner_rejects_private_material_hidden_in_public_certificate_file(
    certificate_factory: CertificateFactory,
) -> None:
    cert, key, _, _ = certificate_factory("mixed-public-file")
    cert.write_bytes(cert.read_bytes() + key.read_bytes())
    os.chmod(cert, 0o644)
    with pytest.raises(ValueError, match="only PEM certificates"):
        validate_miner_tls_files(str(cert), str(key))


@pytest.mark.parametrize(
    ("extra", "message"),
    [
        ([], "live miner startup requires"),
        (["--allow-insecure-mock-http"], "requires --mock-uri"),
        (["--mock-uri", "//Miner"], "live miner startup requires"),
        (
            [
                "--mock-uri",
                "//Miner",
                "--allow-insecure-mock-http",
                "--tls-cert-file",
                "/unused/cert",
            ],
            "cannot be combined",
        ),
    ],
)
def test_miner_startup_requires_tls_or_explicit_mock_http(
    monkeypatch: pytest.MonkeyPatch, extra: list[str], message: str
) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "misscomputer-miner",
            "--netuid",
            "24",
            "--bridge-secret-file",
            "/unused/bridge-secret",
            "--state-db",
            "/unused/state.db",
            *extra,
        ],
    )
    with pytest.raises(SystemExit, match=message):
        miner.main()
