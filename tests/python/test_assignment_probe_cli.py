# SPDX-License-Identifier: AGPL-3.0-only
"""The online organic hidden-probe CLI and its bounded HTTPS transport."""

from __future__ import annotations

import ast
import functools
import hashlib
import ipaddress
import json
import socket
import ssl
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import httpcore
import httpx
import pytest
from assignment_probe_context import FINALIZED_HEIGHT, label_digest, signer_keys
from bittensor.sp_core import Keypair
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from organic_context import (
    BLOG,
    EPOCH,
    EPOCH_START,
    SHOP,
    build_manifest,
    fixture_deployments,
    sign_attestation_v2,
    sign_manifest,
)

import misscomputer_subnet.assignment_probe_cli as probe_cli
import misscomputer_subnet.probe_transport as probe_transport
from misscomputer_subnet.assignment_probe import (
    AssignmentManifestSignatureEnvelope,
    AssignmentManifestTrustPolicy,
    assignment_manifest_signature_envelope_bytes,
    assignment_manifest_trust_policy_bytes,
    parse_assignment_manifest_chain_state,
)
from misscomputer_subnet.assignment_probe_cli import (
    EXIT_DEGRADED,
    EXIT_OK,
    EXIT_REJECTED,
    EXIT_USAGE,
    AssignmentProbeCLIConfig,
    AssignmentProbeCLIError,
    InputFile,
    ManifestSource,
    SignatureSource,
    WalletSelector,
    execute_assignment_probe,
    run_cli,
)
from misscomputer_subnet.organic_contracts import (
    ActiveAssignmentManifestV2,
    OrganicProbeAuthorization,
    organic_probe_message,
)
from misscomputer_subnet.organic_manifest import organic_assignment_manifest_bytes
from misscomputer_subnet.organic_probe import (
    attestation_v2_header,
    evaluate_organic_probe,
    parse_probe_authorization_header,
)
from misscomputer_subnet.organic_scoring import parse_organic_epoch_score

ROOT = Path(__file__).resolve().parents[2]
ROUTE_SUFFIX = "mock.local"
ROUTE_HOSTS = (f"{SHOP}.{ROUTE_SUFFIX}", f"{BLOG}.{ROUTE_SUFFIX}", "publication.mock.local")
VALIDATOR = Keypair.create_from_uri("//Alice")
BOB = Keypair.create_from_uri("//Bob")


def _write_pem(path: Path, payload: bytes, mode: int = 0o600) -> Path:
    path.write_bytes(payload)
    path.chmod(mode)
    return path


def write_certificate_chain(
    root: Path,
    *,
    dns_names: tuple[str, ...] = ROUTE_HOSTS,
    ip_address: str = "127.0.0.1",
) -> tuple[Path, Path, Path, str]:
    """Return (ca pem, leaf pem, leaf key pem, leaf sha256) for a local TLS fixture."""

    current = datetime.now(UTC)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fixture-ca")])
    ca_certificate = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(current - timedelta(minutes=1))
        .not_valid_after(current + timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), False)
        .sign(ca_key, hashes.SHA256())
    )
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    names: list[x509.GeneralName] = [x509.DNSName(name) for name in dns_names]
    names.append(x509.IPAddress(ipaddress.ip_address(ip_address)))
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, dns_names[0])]))
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(current - timedelta(minutes=1))
        .not_valid_after(current + timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName(names), False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), False
        )
        .sign(ca_key, hashes.SHA256())
    )
    ca_path = _write_pem(root / "ca.pem", ca_certificate.public_bytes(serialization.Encoding.PEM))
    leaf_path = _write_pem(root / "leaf.pem", leaf.public_bytes(serialization.Encoding.PEM))
    key_path = _write_pem(
        root / "leaf.key",
        leaf_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )
    leaf_digest = hashlib.sha256(leaf.public_bytes(serialization.Encoding.DER)).hexdigest()
    return ca_path, leaf_path, key_path, leaf_digest


@dataclass
class FixtureState:
    manifest: ActiveAssignmentManifestV2 | None = None
    #: route host -> behavior, one of: serving, app_status, edge_down, no_attestation.
    behaviors: dict[str, str] = field(default_factory=dict)
    documents: dict[str, bytes] = field(default_factory=dict)
    requests: list[tuple[str, str, dict[str, str]]] = field(default_factory=list)


class FixtureServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    state: FixtureState


class FixtureHandler(BaseHTTPRequestHandler):
    """A stand-in edge: verifies nothing, routes by the authorization to a scripted replica."""

    server: FixtureServer

    def log_message(self, *_: object) -> None:
        return

    def _respond(self, status: int, body: bytes, headers: list[tuple[str, str]]) -> None:
        self.send_response(status)
        for name, value in headers:
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            try:
                self.wfile.write(body)
            except OSError:
                pass

    def _handle(self) -> None:
        state = self.server.state
        headers = {key.lower(): value for key, value in self.headers.items()}
        state.requests.append((self.command, self.path, headers))
        if self.path in state.documents:
            self._respond(200, state.documents[self.path], [("Content-Type", "application/json")])
            return
        header = headers.get("x-miss-organic-probe-authorization")
        if header is None or state.manifest is None:
            self._respond(404, b"", [])
            return
        authorization = parse_probe_authorization_header(header)
        behavior = state.behaviors.get(headers.get("host", ""), "serving")
        if behavior == "edge_down":
            self._respond(502, b"bad gateway", [])
            return
        status = 503 if behavior == "app_status" else 200
        body = b"ok\n"
        response_headers = [("Content-Type", "text/plain"), ("X-Miss-Edge-Upstream", "replica")]
        if behavior != "no_attestation":
            attestation = sign_attestation_v2(
                state.manifest,
                authorization,
                status=status,
                body=b"" if self.command == "HEAD" else body,
            )
            response_headers.append(
                ("X-Miss-Probe-Attestation", attestation_v2_header(attestation))
            )
        self._respond(status, body, response_headers)

    def do_GET(self) -> None:  # noqa: N802 - http.server API
        self._handle()

    def do_HEAD(self) -> None:  # noqa: N802 - http.server API
        self._handle()


@dataclass(frozen=True)
class TLSFixture:
    server: FixtureServer
    port: int
    ca_path: Path
    leaf_sha256: str

    @property
    def origin(self) -> str:
        return f"https://127.0.0.1:{self.port}"


def start_server(root: Path, **certificate_values: Any) -> TLSFixture:
    root.mkdir(mode=0o700, exist_ok=True)
    ca_path, leaf_path, key_path, leaf_sha256 = write_certificate_chain(root, **certificate_values)
    server = FixtureServer(("127.0.0.1", 0), FixtureHandler)
    server.state = FixtureState()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(str(leaf_path), str(key_path))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return TLSFixture(server, server.server_address[1], ca_path, leaf_sha256)


@pytest.fixture
def tls_server(tmp_path: Path) -> Iterator[TLSFixture]:
    fixture = start_server(tmp_path / "tls")
    yield fixture
    fixture.server.shutdown()
    fixture.server.server_close()


def secure_write(path: Path, payload: bytes) -> Path:
    path.write_bytes(payload)
    path.chmod(0o600)
    return path


def input_file(path: Path) -> InputFile:
    return InputFile(str(path), hashlib.sha256(path.read_bytes()).hexdigest())


@dataclass
class Publication:
    policy: AssignmentManifestTrustPolicy
    manifest: ActiveAssignmentManifestV2
    policy_file: InputFile
    manifest_file: InputFile
    signature_files: tuple[InputFile, ...]
    seed_file: InputFile


def write_publication(
    root: Path,
    *,
    manifest: ActiveAssignmentManifestV2 | None = None,
    signatures: list[AssignmentManifestSignatureEnvelope] | None = None,
    manifest_bytes: bytes | None = None,
) -> Publication:
    root.mkdir(mode=0o700, exist_ok=True)
    keys = signer_keys()
    from assignment_probe_context import build_policy

    policy = build_policy(keys)
    manifest = manifest or build_manifest(policy, fixture_deployments())
    signatures = signatures or sign_manifest(manifest, keys)
    policy_path = secure_write(root / "policy.json", assignment_manifest_trust_policy_bytes(policy))
    manifest_path = secure_write(
        root / "manifest.json", manifest_bytes or organic_assignment_manifest_bytes(manifest)
    )
    signature_paths = tuple(
        secure_write(
            root / f"signature-{item.signer_key_id}.json",
            assignment_manifest_signature_envelope_bytes(item),
        )
        for item in signatures
    )
    seed_path = secure_write(root / "probe-seed.bin", hashlib.sha256(b"cli-seed").digest())
    return Publication(
        policy=policy,
        manifest=manifest,
        policy_file=input_file(policy_path),
        manifest_file=input_file(manifest_path),
        signature_files=tuple(input_file(path) for path in signature_paths),
        seed_file=input_file(seed_path),
    )


class FakeTime:
    """Wall clock that only advances when the CLI sleeps."""

    def __init__(self, start: float) -> None:
        self.now = start
        self.sleeps: list[float] = []

    def clock(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


def alice_signer(_wallet: WalletSelector) -> tuple[Callable[[bytes], bytes], str]:
    return VALIDATOR.sign, VALIDATOR.ss58_address


def probe_config(
    publication: Publication,
    fixture: TLSFixture,
    tmp_path: Path,
    *,
    name: str = "run",
    anchor: str = "genesis",
    epoch_index: int = EPOCH,
    current_finalized_height: int = FINALIZED_HEIGHT,
    manifest: ManifestSource | None = None,
    signatures: tuple[SignatureSource, ...] | None = None,
) -> AssignmentProbeCLIConfig:
    output = tmp_path / "output"
    output.mkdir(mode=0o700, exist_ok=True)
    archive = tmp_path / "manifests"
    archive.mkdir(mode=0o700, exist_ok=True)
    return AssignmentProbeCLIConfig(
        trust_policy=publication.policy_file,
        manifest=manifest or ManifestSource(file=publication.manifest_file),
        signatures=signatures
        or tuple(SignatureSource(file=item) for item in publication.signature_files),
        probe_seed=publication.seed_file,
        epoch_index=epoch_index,
        current_finalized_height=current_finalized_height,
        validator_hotkey=VALIDATOR.ss58_address,
        wallet=WalletSelector(name="validator", hotkey="default", path=str(tmp_path / "w")),
        state_root=str(tmp_path / "state"),
        trusted_state_anchor=anchor,
        epoch_output=str(output / f"{name}.json"),
        manifest_archive_dir=str(archive),
        edge_origin=fixture.origin,
        tls_ca_file=str(fixture.ca_path),
    )


def run_epoch(
    config: AssignmentProbeCLIConfig, *, start: float = EPOCH_START
) -> tuple[probe_cli.AssignmentProbeCLIResult, FakeTime]:
    fake = FakeTime(start)
    result = execute_assignment_probe(
        config, signer_factory=alice_signer, clock=fake.clock, sleep=fake.sleep
    )
    return result, fake


def assert_cli_rejected(code: str, function: Callable[[], object]) -> None:
    with pytest.raises(AssignmentProbeCLIError) as error:
        function()
    assert error.value.code == code


def probe_requests(fixture: TLSFixture) -> list[tuple[str, str, dict[str, str]]]:
    return [item for item in fixture.server.state.requests if item[1] not in {"/manifest"}]


def test_epoch_signs_every_probe_and_seals_a_scored_record_over_local_tls(
    tmp_path: Path, tls_server: TLSFixture
) -> None:
    publication = write_publication(tmp_path / "publication")
    tls_server.server.state.manifest = publication.manifest
    config = probe_config(publication, tls_server, tmp_path)
    result, fake = run_epoch(config)

    epoch = parse_organic_epoch_score(Path(config.epoch_output).read_bytes())
    assert epoch == result.epoch
    assert epoch.epoch_status == "scored" and result.skipped_probes == 0
    assert {(item.attempts, item.successes) for item in epoch.endpoints} == {(3, 3)}
    assert len(epoch.endpoints) == 6
    requests = probe_requests(tls_server)
    assert len(requests) == 18
    for method, path, headers in requests:
        authorization = parse_probe_authorization_header(
            headers["x-miss-organic-probe-authorization"]
        )
        assert isinstance(authorization, OrganicProbeAuthorization)
        # The edge verifies exactly this: the validator hotkey's sr25519 signature.
        assert Keypair(ss58_address=VALIDATOR.ss58_address).verify(
            organic_probe_message(authorization), bytes.fromhex(authorization.signature)
        )
        assert (method, path) == (authorization.method, authorization.path)
        assert headers["host"].endswith(f".{ROUTE_SUFFIX}")
    # Probes fire at private instants spread across the epoch, never all at once.
    assert fake.now < EPOCH_START + 300 and len(fake.sleeps) == 18
    state_bytes = (Path(config.state_root) / "state.json").read_bytes()
    state = parse_assignment_manifest_chain_state(state_bytes)
    assert state.last_manifest_digest_sha256 == publication.manifest.manifest_digest_sha256
    # The verified manifest is archived for the window coordinator's replay.
    archived = Path(config.manifest_archive_dir) / (
        f"{publication.manifest.manifest_digest_sha256}.json"
    )
    assert archived.read_bytes() == organic_assignment_manifest_bytes(publication.manifest)


def test_run_cli_reports_stable_status_and_exit_codes(
    tmp_path: Path,
    tls_server: TLSFixture,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    publication = write_publication(tmp_path / "publication")
    state = tls_server.server.state
    state.manifest = publication.manifest
    fake = FakeTime(EPOCH_START)
    monkeypatch.setattr(
        probe_cli,
        "execute_assignment_probe",
        functools.partial(
            execute_assignment_probe,
            signer_factory=alice_signer,
            clock=fake.clock,
            sleep=fake.sleep,
        ),
    )
    config = probe_config(publication, tls_server, tmp_path)
    assert run_cli(config_argv(config)) == EXIT_OK
    out = capsys.readouterr().out
    assert out.startswith(f"PROBED status=scored epoch={EPOCH} endpoints=6 observations=18 ")
    # A common-mode edge outage is recorded, not scored: exit degraded.
    state.behaviors = dict.fromkeys(ROUTE_HOSTS[:2], "edge_down")
    fake.now = EPOCH_START + 300
    later = probe_config(
        publication, tls_server, tmp_path, name="outage", anchor="current", epoch_index=EPOCH + 1
    )
    assert run_cli(config_argv(later)) == EXIT_DEGRADED
    assert "status=common_mode_unavailable" in capsys.readouterr().out
    assert run_cli(config_argv(later)) == EXIT_REJECTED
    assert capsys.readouterr().err == "REJECTED output_exists\n"
    assert run_cli(["--help"]) == EXIT_USAGE


def config_argv(config: AssignmentProbeCLIConfig) -> list[str]:
    values = [
        "--trust-policy",
        config.trust_policy.path,
        "--trust-policy-sha256",
        config.trust_policy.sha256,
    ]
    if config.manifest.file is not None:
        values += [
            "--manifest-file",
            config.manifest.file.path,
            "--manifest-sha256",
            config.manifest.file.sha256,
        ]
    else:
        values += ["--manifest-url", str(config.manifest.url)]
    for item in config.signatures:
        if item.file is not None:
            values += ["--signature-file", item.file.path, "--signature-sha256", item.file.sha256]
        else:
            values += ["--signature-url", str(item.url)]
    values += [
        "--probe-seed-file",
        config.probe_seed.path,
        "--probe-seed-sha256",
        config.probe_seed.sha256,
        "--epoch-index",
        str(config.epoch_index),
        "--finalized-height",
        str(config.current_finalized_height),
        "--validator-hotkey",
        config.validator_hotkey,
        "--wallet-name",
        config.wallet.name,
        "--wallet-hotkey",
        config.wallet.hotkey,
        "--wallet-path",
        config.wallet.path,
        "--state-root",
        config.state_root,
        "--trusted-state-anchor",
        config.trusted_state_anchor,
        "--epoch-output",
        config.epoch_output,
        "--manifest-archive-dir",
        config.manifest_archive_dir,
    ]
    if config.edge_origin is not None:
        values += ["--edge-origin", config.edge_origin]
    if config.tls_ca_file is not None:
        values += ["--tls-ca-file", config.tls_ca_file]
    return values


def test_application_failure_on_two_replicas_excludes_that_app(
    tmp_path: Path, tls_server: TLSFixture
) -> None:
    publication = write_publication(tmp_path / "publication")
    state = tls_server.server.state
    state.manifest = publication.manifest
    shop_host = f"{SHOP}.{ROUTE_SUFFIX}"
    state.behaviors = {shop_host: "app_status"}
    result, _ = run_epoch(probe_config(publication, tls_server, tmp_path))
    assert result.epoch.inconclusive_deployments == [SHOP]
    blog = [item for item in result.epoch.endpoints if item.deployment_id == BLOG]
    assert {item.disposition for item in blog} == {"eligible"}


def test_missing_attestation_is_the_miners_failure(tmp_path: Path, tls_server: TLSFixture) -> None:
    publication = write_publication(tmp_path / "publication")
    state = tls_server.server.state
    state.manifest = publication.manifest
    state.behaviors = {f"{BLOG}.{ROUTE_SUFFIX}": "no_attestation"}
    result, _ = run_epoch(probe_config(publication, tls_server, tmp_path))
    blog = [item for item in result.epoch.endpoints if item.deployment_id == BLOG]
    assert {(item.miner_failures, item.availability_numerator) for item in blog} == {(3, 0)}


def test_manifest_publication_can_be_fetched_from_explicit_urls(
    tmp_path: Path, tls_server: TLSFixture
) -> None:
    publication = write_publication(tmp_path / "publication")
    state = tls_server.server.state
    state.manifest = publication.manifest
    state.documents["/publication/manifest.json"] = Path(
        publication.manifest_file.path
    ).read_bytes()
    signatures = []
    for index, item in enumerate(publication.signature_files):
        state.documents[f"/publication/signature-{index}.json"] = Path(item.path).read_bytes()
        signatures.append(
            SignatureSource(url=f"{tls_server.origin}/publication/signature-{index}.json")
        )

    def config(name: str, url: str, anchor: str = "current") -> AssignmentProbeCLIConfig:
        return probe_config(
            publication,
            tls_server,
            tmp_path,
            name=name,
            anchor=anchor,
            manifest=ManifestSource(url=url),
            signatures=tuple(signatures),
        )

    result, _ = run_epoch(
        config("run", f"{tls_server.origin}/publication/manifest.json", "genesis")
    )
    assert result.epoch.epoch_status == "scored"
    state.documents["/publication/broken.json"] = b"{}\n"
    for name, url, code in (
        ("broken", f"{tls_server.origin}/publication/broken.json", "manifest_invalid"),
        (
            "missing",
            f"{tls_server.origin}/publication/absent.json",
            "manifest_fetch_status_invalid",
        ),
        ("plain", "http://127.0.0.1/manifest.json", "manifest_url_invalid"),
    ):
        assert_cli_rejected(code, lambda url=url, name=name: run_epoch(config(name, url)))


def test_rejected_publications_send_no_probe_and_write_nothing(
    tmp_path: Path, tls_server: TLSFixture
) -> None:
    publication = write_publication(tmp_path / "publication")
    tls_server.server.state.manifest = publication.manifest
    config = probe_config(publication, tls_server, tmp_path)
    wrong = WalletSelector(name="x", hotkey="y", path="/nonexistent")
    assert_cli_rejected(
        "wallet_hotkey_mismatch",
        lambda: execute_assignment_probe(
            replace(config, wallet=wrong),
            signer_factory=lambda _w: (VALIDATOR.sign, BOB.ss58_address),
            clock=FakeTime(EPOCH_START).clock,
            sleep=lambda _s: None,
        ),
    )
    assert_cli_rejected(
        "epoch_already_elapsed",
        lambda: run_epoch(config, start=EPOCH_START + 300),
    )
    tampered = write_publication(
        tmp_path / "tampered",
        signatures=sign_manifest(
            publication.manifest,
            {"auditor": signer_keys()["security"], "issuer": signer_keys()["issuer"]},
        ),
    )
    with pytest.raises(probe_cli.AssignmentProbeError) as rejected:
        run_epoch(probe_config(tampered, tls_server, tmp_path, name="tampered"))
    assert rejected.value.code == "signature_invalid"
    assert probe_requests(tls_server) == []
    assert not (Path(config.state_root) / "state.json").exists()
    assert not Path(config.epoch_output).exists()


def test_a_late_start_skips_elapsed_instants_instead_of_clustering_them(
    tmp_path: Path, tls_server: TLSFixture
) -> None:
    publication = write_publication(tmp_path / "publication")
    tls_server.server.state.manifest = publication.manifest
    result, _ = run_epoch(probe_config(publication, tls_server, tmp_path), start=EPOCH_START + 150)
    sent = len(probe_requests(tls_server))
    assert result.skipped_probes > 0 and sent == 18 - result.skipped_probes
    assert len(result.epoch.observations) == sent


def test_onboarding_anchor_and_reprobe_follow_the_append_only_state(
    tmp_path: Path, tls_server: TLSFixture
) -> None:
    keys = signer_keys()
    from assignment_probe_context import build_policy

    policy = build_policy(keys)
    head = build_manifest(
        policy, fixture_deployments(), sequence=3, previous=label_digest("predecessor")
    )
    publication = write_publication(tmp_path / "publication", manifest=head)
    tls_server.server.state.manifest = head
    first, _ = run_epoch(probe_config(publication, tls_server, tmp_path))
    assert first.state_advanced and first.next_chain_state.last_sequence == 3
    again, _ = run_epoch(
        probe_config(
            publication, tls_server, tmp_path, name="again", anchor="current", epoch_index=EPOCH + 1
        ),
        start=EPOCH_START + 300,
    )
    assert again.state_advanced is False
    assert_cli_rejected(
        "state_anchor_stale",
        lambda: run_epoch(probe_config(publication, tls_server, tmp_path, name="stale")),
    )


def test_probe_requires_the_finalized_height_and_refuses_expired_leases(
    tmp_path: Path, tls_server: TLSFixture, capsys: pytest.CaptureFixture[str]
) -> None:
    publication = write_publication(tmp_path / "publication")
    tls_server.server.state.manifest = publication.manifest
    config = probe_config(publication, tls_server, tmp_path)
    argv = config_argv(config)
    index = argv.index("--finalized-height")
    assert run_cli([*argv[:index], *argv[index + 2 :]]) == EXIT_USAGE
    assert capsys.readouterr().err == "REJECTED usage\n"
    earliest = min(r.expires_at_block for d in publication.manifest.deployments for r in d.replicas)
    with pytest.raises(probe_cli.AssignmentProbeError) as lease:
        run_epoch(replace(config, current_finalized_height=earliest))
    assert lease.value.code == "manifest_replica_lease_expired"
    assert not (Path(config.state_root) / "state.json").exists()
    assert probe_requests(tls_server) == []


def test_manifest_archive_is_write_once_and_refuses_a_conflicting_entry(
    tmp_path: Path, tls_server: TLSFixture
) -> None:
    publication = write_publication(tmp_path / "publication")
    tls_server.server.state.manifest = publication.manifest
    config = probe_config(publication, tls_server, tmp_path)
    archived = Path(config.manifest_archive_dir) / (
        f"{publication.manifest.manifest_digest_sha256}.json"
    )
    secure_write(archived, b"{}\n")
    assert_cli_rejected("manifest_archive_conflict", lambda: run_epoch(config))
    assert probe_requests(tls_server) == []
    assert not (Path(config.state_root) / "state.json").exists()
    archived.write_bytes(organic_assignment_manifest_bytes(publication.manifest))
    result, _ = run_epoch(config)
    assert result.epoch.epoch_status == "scored"


def test_cli_signs_only_through_the_purpose_limited_facade() -> None:
    project = (ROOT / "pyproject.toml").read_text()
    assert 'misscomputer-assignment-probe = "misscomputer_subnet.assignment_probe_cli:main"' in (
        project
    )
    source = (ROOT / "src" / "misscomputer_subnet" / "assignment_probe_cli.py").read_text()
    tree = ast.parse(source)
    identifiers: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            identifiers.add(node.id)
        elif isinstance(node, ast.Attribute):
            identifiers.add(node.attr)
    assert "sign_organic_probe_authorization" in identifiers
    assert not identifiers & {
        "Ed25519PrivateKey",
        "Popen",
        "set_weights",
        "sign_http_request",
        "sign_service_binding",
        "system",
        "urlopen",
    }
    module_level_calls = [
        node
        for node in tree.body
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)
    ]
    assert not module_level_calls


def test_hotkey_facade_refuses_anything_but_an_organic_probe_authorization() -> None:
    from misscomputer_subnet.auth import HotkeySigningFacade

    facade = object.__new__(HotkeySigningFacade)
    object.__setattr__(facade, "_HotkeySigningFacade__signer", VALIDATOR)
    object.__setattr__(facade, "_HotkeySigningFacade__hotkey", VALIDATOR.ss58_address)
    with pytest.raises(ValueError):
        facade.sign_organic_probe_authorization(b"weights\x00{}")
    message = b"miss.computer/misscomputer-subnet/organic-probe/v1\x00" + json.dumps({}).encode()
    assert VALIDATOR.verify(message, facade.sign_organic_probe_authorization(message))


class _FixedClock:
    """Monotonic clock that reads ``0`` at the request start and ``elapsed`` ever after."""

    def __init__(self, elapsed_seconds: float) -> None:
        self._elapsed = elapsed_seconds
        self.calls = 0

    def __call__(self) -> float:
        self.calls += 1
        return 0.0 if self.calls == 1 else self._elapsed


def _mock_transport(
    responder: Callable[[httpx.Request], httpx.Response],
) -> probe_cli.TransportBuilder:
    return lambda _context, _remaining: httpx.MockTransport(responder)


def _fetch(
    responder: Callable[[httpx.Request], httpx.Response],
    *,
    elapsed_seconds: float,
    budget_seconds: float = 0.1,
    max_bytes: int = 4_096,
) -> probe_cli.ProbeResponse | probe_cli.ProbeTransportFailure:
    transport = probe_cli.HttpsProbeTransport(
        ssl.create_default_context(),
        clock=_FixedClock(elapsed_seconds),
        transport_factory=_mock_transport(responder),
    )
    return transport.fetch(
        url="https://shop-k3j9x0q2ab.mock.local/healthz",
        server_name="shop-k3j9x0q2ab.mock.local",
        headers={"host": "shop-k3j9x0q2ab.mock.local"},
        timeout_seconds=budget_seconds,
        max_bytes=max_bytes,
    )


def _budget_context(
    **policy_values: Any,
) -> tuple[AssignmentManifestTrustPolicy, ActiveAssignmentManifestV2, OrganicProbeAuthorization]:
    from assignment_probe_context import build_policy
    from organic_context import authorize, endpoint

    policy = build_policy(
        signer_keys(), probe_timeout_millis=100, max_response_bytes=4_096, **policy_values
    )
    manifest = build_manifest(policy, fixture_deployments())
    authorization = authorize(
        manifest,
        endpoint(manifest, SHOP, "MinerA"),
        issued_at=EPOCH_START + 1,
        nonce=label_digest("budget-nonce"),
    )
    return policy, manifest, authorization


def _response_scenarios(
    manifest: ActiveAssignmentManifestV2, authorization: OrganicProbeAuthorization
) -> dict[str, Callable[[httpx.Request], httpx.Response]]:
    """One responder per response-derived outcome ``evaluate_organic_probe`` can reach."""

    body = b"ok\n"
    upstream = ("X-Miss-Edge-Upstream", "replica")

    def attested(status: int, content: bytes) -> tuple[str, str]:
        attestation = sign_attestation_v2(manifest, authorization, status=status, body=content)
        return ("X-Miss-Probe-Attestation", attestation_v2_header(attestation))

    def respond(
        status: int = 200,
        *,
        content: bytes = body,
        headers: list[tuple[str, str]] | None = None,
    ) -> Callable[[httpx.Request], httpx.Response]:
        return lambda _request: httpx.Response(
            status,
            stream=httpx.ByteStream(content),
            headers=[("Content-Length", str(len(content))), *(headers or [])],
        )

    return {
        "success": respond(headers=[upstream, attested(200, body)]),
        "tls_pin_mismatch": respond(headers=[upstream, attested(200, body)]),
        "edge_generated": respond(502, content=b"bad gateway"),
        "unexpected_status": respond(503, headers=[upstream, attested(503, body)]),
        "marker_missing": respond(content=b"boot", headers=[upstream, attested(200, b"boot")]),
        "response_oversized": respond(content=b"x" * 6_000, headers=[upstream]),
        "attestation_missing": respond(headers=[upstream]),
        "attestation_invalid": respond(
            headers=[upstream, attested(200, body), attested(200, body)]
        ),
    }


def test_transport_enforces_one_whole_request_budget_at_the_exact_boundary() -> None:
    """Every response-derived outcome fits the budget or becomes a timeout, at ms precision."""

    unpinned, manifest, authorization = _budget_context()
    pinned, pinned_manifest, pinned_authorization = _budget_context(
        pinned_edge_leaf_certificate_sha256=(label_digest("edge-leaf"),)
    )
    for code, responder in _response_scenarios(manifest, authorization).items():
        policy, target, request = (
            (pinned, pinned_manifest, pinned_authorization)
            if code == "tls_pin_mismatch"
            else (unpinned, manifest, authorization)
        )
        if code == "tls_pin_mismatch":
            responder = _response_scenarios(pinned_manifest, pinned_authorization)[code]
        at_budget = _fetch(responder, elapsed_seconds=0.1)
        assert at_budget.latency_millis == 100, code
        if code == "response_oversized":
            # Declared Content-Length above the ceiling is judged before the body.
            assert isinstance(at_budget, probe_cli.ProbeTransportFailure)
            assert at_budget.code == "response_oversized" and at_budget.response_status == 200
            observation = evaluate_organic_probe(target, policy, request, at_budget)
            assert observation.failure_code == "transport_error"
            continue
        assert isinstance(at_budget, probe_cli.ProbeResponse), code
        observation = evaluate_organic_probe(target, policy, request, at_budget)
        assert (observation.outcome, observation.failure_code) == (
            ("success", None) if code == "success" else ("failure", code)
        ), code
        assert observation.latency_millis == 100

        over_budget = _fetch(responder, elapsed_seconds=0.101)
        assert isinstance(over_budget, probe_cli.ProbeTransportFailure), code
        assert over_budget.code == "timeout" and over_budget.latency_millis == 101
        late = evaluate_organic_probe(target, policy, request, over_budget)
        assert (late.outcome, late.failure_code, late.latency_millis) == ("failure", "timeout", 101)

    def chunked(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, stream=httpx.ByteStream(b"y" * 5_000))

    streamed = _fetch(chunked, elapsed_seconds=0.1, max_bytes=64)
    assert isinstance(streamed, probe_cli.ProbeTransportFailure)
    assert (streamed.code, streamed.latency_millis) == ("response_oversized", 100)
    late_stream = _fetch(chunked, elapsed_seconds=0.101, max_bytes=64)
    assert isinstance(late_stream, probe_cli.ProbeTransportFailure)
    assert (late_stream.code, late_stream.latency_millis) == ("timeout", 101)

    def slow(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow origin", request=request)

    for elapsed, latency in ((0.05, 50), (0.1, 100), (0.25, 250)):
        result = _fetch(slow, elapsed_seconds=elapsed)
        assert isinstance(result, probe_cli.ProbeTransportFailure)
        assert (result.code, result.latency_millis) == (
            "timeout" if latency > 100 else "transport_error",
            latency,
        )

    def refused(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    result = _fetch(refused, elapsed_seconds=0.25)
    assert isinstance(result, probe_cli.ProbeTransportFailure)
    assert (result.code, result.latency_millis) == ("timeout", 250)

    budget = probe_cli.RequestBudget(0.1, clock=_FixedClock(0.0))
    assert budget.budget_millis == 100
    assert not budget.exhausted(100) and budget.exhausted(101)
    assert probe_cli.RequestBudget(5.0, clock=_FixedClock(0.0)).budget_millis == 5_000


def test_transport_sends_head_and_refuses_other_methods() -> None:
    seen: list[str] = []

    def record(request: httpx.Request) -> httpx.Response:
        seen.append(request.method)
        return httpx.Response(200, stream=httpx.ByteStream(b""), headers=[("Content-Length", "0")])

    transport = probe_cli.HttpsProbeTransport(
        ssl.create_default_context(), transport_factory=_mock_transport(record)
    )
    common: dict[str, Any] = {
        "url": f"https://{SHOP}.{ROUTE_SUFFIX}/healthz",
        "server_name": f"{SHOP}.{ROUTE_SUFFIX}",
        "headers": {},
        "timeout_seconds": 1.0,
        "max_bytes": 64,
    }
    assert isinstance(transport.fetch(**common, method="HEAD"), probe_cli.ProbeResponse)
    refused = transport.fetch(**common, method="POST")
    assert isinstance(refused, probe_cli.ProbeTransportFailure)
    assert seen == ["HEAD"]


class TrickleHandler(BaseHTTPRequestHandler):
    """Origin that stays inside every per-operation timeout while exceeding the budget."""

    def log_message(self, *_: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802 - http.server API
        try:
            if self.path.startswith("/trickle-headers"):
                for byte in b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n":
                    self.wfile.write(bytes([byte]))
                    self.wfile.flush()
                    time.sleep(0.03)
                self.wfile.write(b"ok")
            elif self.path.startswith("/trickle-body"):
                self.wfile.write(b"HTTP/1.1 200 OK\r\nContent-Length: 60\r\n\r\n")
                self.wfile.flush()
                for _ in range(60):
                    self.wfile.write(b"x")
                    self.wfile.flush()
                    time.sleep(0.03)
            else:
                self.wfile.write(b"HTTP/1.1 999 Odd\r\nContent-Length: 0\r\n\r\n")
        except OSError:
            pass


@pytest.fixture
def trickle_server(tmp_path: Path) -> Iterator[tuple[str, Path]]:
    root = tmp_path / "trickle"
    root.mkdir(mode=0o700)
    ca_path, leaf_path, key_path, _ = write_certificate_chain(root)
    server = ThreadingHTTPServer(("127.0.0.1", 0), TrickleHandler)
    server.daemon_threads = True
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(leaf_path), str(key_path))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"https://127.0.0.1:{server.server_address[1]}", ca_path
    server.shutdown()


def test_slow_trickle_origins_are_cut_off_at_the_whole_request_deadline(
    trickle_server: tuple[str, Path],
) -> None:
    """Header and body trickles inside every per-read timeout still end near the budget.

    A peer emitting one byte every 30ms never trips a 200ms per-read timeout,
    so only the cancellable wall-clock deadline bounds the request: both
    trickles must be reported as ``timeout`` within a small margin of 200ms
    instead of running for the seconds the trickle would take.
    """

    origin, ca_path = trickle_server
    transport = probe_cli.HttpsProbeTransport(ssl.create_default_context(cafile=str(ca_path)))
    for path in ("/trickle-headers", "/trickle-body"):
        started = time.monotonic()
        result = transport.fetch(
            url=f"{origin}{path}",
            server_name="shop-k3j9x0q2ab.mock.local",
            headers={"host": "shop-k3j9x0q2ab.mock.local"},
            timeout_seconds=0.2,
            max_bytes=4_096,
        )
        wall = time.monotonic() - started
        assert isinstance(result, probe_cli.ProbeTransportFailure), path
        assert result.code == "timeout", path
        assert 200 <= result.latency_millis, path
        assert wall < 0.75, (path, wall)  # trickles alone would take > 1.2s
    # A live origin answering with a wire status outside the contract is a
    # transport fault with no recorded status, not a crash and not a response.
    result = transport.fetch(
        url=f"{origin}/status-999",
        server_name="shop-k3j9x0q2ab.mock.local",
        headers={"host": "shop-k3j9x0q2ab.mock.local"},
        timeout_seconds=5.0,
        max_bytes=4_096,
    )
    assert isinstance(result, probe_cli.ProbeTransportFailure)
    assert (result.code, result.response_status) == ("transport_error", None)


def test_out_of_contract_wire_status_is_a_transport_fault_under_and_over_budget() -> None:
    """httpx accepts 600..999 on the wire; the contract does not, so it is never an observation."""

    policy, manifest, authorization = _budget_context()

    def odd(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(999, stream=httpx.ByteStream(b""), headers=[("Content-Length", "0")])

    within = _fetch(odd, elapsed_seconds=0.1)
    assert isinstance(within, probe_cli.ProbeTransportFailure)
    assert (within.code, within.response_status, within.latency_millis) == (
        "transport_error",
        None,
        100,
    )
    observation = evaluate_organic_probe(manifest, policy, authorization, within)
    assert (observation.failure_code, observation.response_status) == ("transport_error", None)
    over = _fetch(odd, elapsed_seconds=0.101)
    assert isinstance(over, probe_cli.ProbeTransportFailure)
    assert (over.code, over.latency_millis) == ("timeout", 101)
    leaked = probe_cli.ProbeResponse(
        status=600, headers=(), body=b"", latency_millis=5, tls_leaf_certificate_sha256=None
    )
    observation = evaluate_organic_probe(manifest, policy, authorization, leaked)
    assert (observation.outcome, observation.failure_code, observation.response_status) == (
        "failure",
        "transport_error",
        None,
    )


def _budget(seconds: float) -> Callable[[], float]:
    started = time.monotonic()
    return lambda: max(0.0, seconds - (time.monotonic() - started))


def test_name_resolution_and_every_address_dial_are_bounded_by_the_budget() -> None:
    """DNS that overruns and multi-address blackholes cost at most one budget.

    ``getaddrinfo`` cannot be cancelled, so the backend waits on it for exactly
    the remaining budget and abandons it; each resolved address is dialled with
    the time remaining at that instant, so three unreachable addresses do not
    receive three full timeouts.
    """

    def slow_resolver(host: str, port: int) -> list[probe_transport.ResolvedAddress]:
        time.sleep(0.35)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, ("127.0.0.1", port))]

    started = time.monotonic()
    backend = probe_transport.DeadlineNetworkBackend(_budget(0.1), resolver=slow_resolver)
    with pytest.raises(httpcore.ConnectTimeout):
        backend.connect_tcp("slow.invalid", 1, timeout=0.1)
    assert time.monotonic() - started < 0.25

    def three(host: str, port: int) -> list[probe_transport.ResolvedAddress]:
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, (f"10.255.255.{index}", port))
            for index in (1, 2, 3)
        ]

    dial_timeouts: list[float] = []

    def blackhole(
        address: probe_transport.ResolvedAddress, timeout: float, local_address: str | None
    ) -> socket.socket:
        dial_timeouts.append(timeout)
        time.sleep(timeout)
        raise TimeoutError("blackhole")

    started = time.monotonic()
    backend = probe_transport.DeadlineNetworkBackend(_budget(0.1), resolver=three, dialer=blackhole)
    with pytest.raises(httpcore.ConnectTimeout):
        backend.connect_tcp("blackhole.invalid", 9, timeout=0.1)
    elapsed = time.monotonic() - started
    assert elapsed < 0.2, elapsed
    assert dial_timeouts and dial_timeouts[0] <= 0.1
    assert all(
        later <= earlier for earlier, later in zip(dial_timeouts, dial_timeouts[1:], strict=False)
    )

    # A refused first address falls through to a reachable second one, still
    # inside the budget, and the resulting stream is a real socket stream.
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    def two(host: str, _port: int) -> list[probe_transport.ResolvedAddress]:
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, ("127.0.0.1", 1)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, ("127.0.0.1", port)),
        ]

    backend = probe_transport.DeadlineNetworkBackend(_budget(1.0), resolver=two)
    stream = backend.connect_tcp("two.invalid", port, timeout=1.0)
    assert isinstance(stream.get_extra_info("socket"), socket.socket)
    stream.close()
    listener.close()
    # Exhausted before resolving: refused without touching the resolver.
    backend = probe_transport.DeadlineNetworkBackend(lambda: 0.0, resolver=three)
    with pytest.raises(httpcore.ConnectTimeout):
        backend.connect_tcp("late.invalid", 9, timeout=0.1)


def test_partial_sends_recompute_the_remaining_budget_before_every_send() -> None:
    """A peer draining the socket just inside each send timeout cannot outlast the budget.

    httpcore loops ``send`` with one fixed timeout per call; the deadline stream
    re-derives the remaining budget before every ``send`` instead.
    """

    sender, receiver = socket.socketpair()
    sender.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4_096)
    receiver.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4_096)
    stop = threading.Event()

    def drain_slowly() -> None:
        # Frees a little buffer every 60ms: below a 100ms per-send timeout,
        # so httpcore's own loop would keep sending for the whole 4 MiB.
        while not stop.is_set():
            time.sleep(0.06)
            try:
                if not receiver.recv(4_096):
                    return
            except OSError:
                return

    drainer = threading.Thread(target=drain_slowly, daemon=True)
    drainer.start()
    try:
        started = time.monotonic()
        stream = probe_transport.DeadlineNetworkStream(
            probe_transport._SocketStream(sender), _budget(0.1)
        )
        with pytest.raises(httpcore.WriteTimeout):
            stream.write(b"x" * (4 << 20), timeout=0.1)
        assert time.monotonic() - started < 0.3
    finally:
        stop.set()
        sender.close()
        receiver.close()


def test_probe_transport_module_is_bounded_network_plumbing_only() -> None:
    """The socket-level module may open TCP/TLS under the caller's context and nothing more."""

    source = (ROOT / "src" / "misscomputer_subnet" / "probe_transport.py").read_text()
    tree = ast.parse(source)
    imported: set[str] = set()
    identifiers: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".", maxsplit=1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            imported.add(node.module.split(".", maxsplit=1)[0])
        elif isinstance(node, ast.Name):
            identifiers.add(node.id)
        elif isinstance(node, ast.Attribute):
            identifiers.add(node.attr)
    assert imported <= {
        "__future__",
        "collections",
        "contextlib",
        "httpcore",
        "httpx",
        "os",  # only register_at_fork: reset inherited resolver permits
        "select",
        "signal",  # SIGINT masking only during lease accounting
        "socket",
        "ssl",
        "threading",
        "time",
    }
    assert not identifiers & {
        "Ed25519PrivateKey",
        "Popen",
        "Wallet",
        "environ",
        "open",
        "set_weights",
        "sign",
        "subprocess",
        "system",
        "urlopen",
        "wallet",
    }
    assert {
        node.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == "os"
    } == {"register_at_fork"}
    assert "https://" not in source
    # The CLI itself stays free of raw sockets; it only composes this module.
    cli_source = (ROOT / "src" / "misscomputer_subnet" / "assignment_probe_cli.py").read_text()
    assert "import socket" not in cli_source and "import httpcore" not in cli_source


def test_blocked_name_resolutions_cannot_exceed_the_process_wide_slot_cap() -> None:
    """Permanently blocked lookups hold at most the slot cap in threads; the rest fail fast.

    ``getaddrinfo`` cannot be cancelled, so each overrun is abandoned on its
    helper thread; the slots bound how many such threads can exist at once,
    there is no queue, and a lookup that finds no free slot fails immediately
    with a connection error rather than a full budget wait.
    """

    release = threading.Event()

    def blocked(host: str, port: int) -> list[probe_transport.ResolvedAddress]:
        release.wait()
        return []

    slots = threading.BoundedSemaphore(4)
    prefix = "misscomputer-probe-resolve"
    before = sum(1 for thread in threading.enumerate() if thread.name.startswith(prefix))
    outcomes: list[tuple[str, float]] = []
    try:
        for _ in range(40):
            backend = probe_transport.DeadlineNetworkBackend(
                lambda: 0.02, resolver=blocked, resolution_slots=slots
            )
            started = time.monotonic()
            try:
                backend.connect_tcp("blocked.invalid", 1, timeout=0.02)
            except httpcore.ConnectTimeout:
                outcomes.append(("timeout", time.monotonic() - started))
            except httpcore.ConnectError:
                outcomes.append(("capacity", time.monotonic() - started))
        live = sum(1 for thread in threading.enumerate() if thread.name.startswith(prefix)) - before
        assert live <= 4, live
        assert [kind for kind, _ in outcomes[:4]] == ["timeout"] * 4
        assert {kind for kind, _ in outcomes[4:]} == {"capacity"}
        assert all(elapsed < 0.01 for kind, elapsed in outcomes if kind == "capacity")
        assert probe_transport.MAX_OUTSTANDING_RESOLUTIONS == 16
    finally:
        release.set()
    time.sleep(0.05)
    # Released lookups return their slots: new lookups get threads again.
    done = probe_transport.DeadlineNetworkBackend(
        lambda: 1.0,
        resolver=lambda host, port: [(socket.AF_INET, socket.SOCK_STREAM, 6, ("127.0.0.1", 1))],
        resolution_slots=slots,
    )
    with pytest.raises(httpcore.ConnectError, match="refused|Connection"):
        done.connect_tcp("released.invalid", 1, timeout=1.0)
