# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import ast
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
from assignment_probe_context import (
    BASE_EPOCH,
    EVALUATION_EPOCH,
    FINALIZED_HEIGHT,
    Context,
    attestation_header,
    build_manifest,
    build_policy,
    challenge_value,
    label_digest,
    make_context,
    miner_key,
    sign_attestation,
    sign_manifest,
)
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

import misscomputer_subnet.assignment_probe_cli as probe_cli
import misscomputer_subnet.probe_transport as probe_transport
from misscomputer_subnet.assignment_probe import (
    ActiveAssignmentManifest,
    ActiveDeploymentAssignment,
    AssignmentManifestSignatureEnvelope,
    AssignmentManifestTrustPolicy,
    active_assignment_manifest_bytes,
    assignment_manifest_signature_envelope_bytes,
    assignment_manifest_trust_policy_bytes,
    evaluate_probe_response,
    parse_assignment_manifest_chain_state,
    parse_validator_probe_report,
    verify_observation_policy_binding,
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
    execute_assignment_probe,
    persist_assignment_manifest_catch_up,
    run_cli,
)
from misscomputer_subnet.manifest_publication import (
    ManifestHistoryEntry,
    build_manifest_latest_pointer,
)

ROOT = Path(__file__).resolve().parents[2]
ROUTE_HOSTS = ("fixture-alpha.mock.local", "fixture-beta.mock.local", "publication.mock.local")


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
class RouteBehavior:
    deployment: ActiveDeploymentAssignment
    mode: str = "serving"
    attest_with: str | None = None
    build_id_header: bool = True


@dataclass
class FixtureState:
    routes: dict[str, RouteBehavior] = field(default_factory=dict)
    documents: dict[str, bytes] = field(default_factory=dict)
    requests: list[tuple[str, dict[str, str]]] = field(default_factory=list)


class FixtureServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    state: FixtureState


class FixtureHandler(BaseHTTPRequestHandler):
    server: FixtureServer

    def log_message(self, *_: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802 - http.server API
        state = self.server.state
        headers = {key.lower(): value for key, value in self.headers.items()}
        state.requests.append((self.path, headers))
        if self.path in state.documents:
            payload = state.documents[self.path]
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        route = state.routes.get(self.path)
        if route is None:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        deployment = route.deployment
        body = challenge_value(deployment.deployment_id).encode("ascii")
        if route.mode == "wrong_body":
            body = b"tampered"
        elif route.mode == "oversized":
            body = b"x" * 6_000
        elif route.mode == "sleep":
            time.sleep(1.5)
        status = 200
        if route.mode == "status_500":
            status = 500
        elif route.mode == "redirect":
            status = 302
            body = b""
        self.send_response(status)
        if route.mode == "redirect":
            self.send_header("Location", "https://elsewhere.mock.local/")
        self.send_header("Content-Type", "text/plain")
        self.send_header("Cache-Control", "private, no-store")
        if route.build_id_header:
            self.send_header("X-Build-ID", deployment.build_id)
        if route.attest_with is not None:
            nonce = headers.get("x-miss-probe-nonce", "")
            replica = next(
                item for item in deployment.replicas if item.miner_hotkey == route.attest_with
            )
            signer = miner_key(route.attest_with)
            if route.mode == "attest_wrong_key":
                signer = miner_key("MinerD")
            attestation = sign_attestation(
                deployment, replica, probe_nonce=nonce, signing_key=signer
            )
            self.send_header("X-Miss-Probe-Attestation", attestation_header(attestation))
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except OSError:
            pass


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
    (tmp_path / "tls").chmod(0o700)
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
    root: Path
    context: Context
    policy_file: InputFile
    manifest_file: InputFile
    signature_files: tuple[InputFile, ...]


def write_publication(
    root: Path,
    context: Context,
    *,
    manifest: ActiveAssignmentManifest | None = None,
    signatures: list[AssignmentManifestSignatureEnvelope] | None = None,
    policy: AssignmentManifestTrustPolicy | None = None,
) -> Publication:
    root.mkdir(mode=0o700, exist_ok=True)
    manifest = manifest or context.manifest
    signatures = signatures or context.signatures
    policy = policy or context.policy
    policy_path = secure_write(root / "policy.json", assignment_manifest_trust_policy_bytes(policy))
    manifest_path = secure_write(root / "manifest.json", active_assignment_manifest_bytes(manifest))
    signature_paths = tuple(
        secure_write(
            root / f"signature-{item.signer_key_id}.json",
            assignment_manifest_signature_envelope_bytes(item),
        )
        for item in signatures
    )
    return Publication(
        root=root,
        context=context,
        policy_file=input_file(policy_path),
        manifest_file=input_file(manifest_path),
        signature_files=tuple(input_file(path) for path in signature_paths),
    )


def configure_routes(
    fixture: TLSFixture,
    manifest: ActiveAssignmentManifest,
    *,
    alpha_mode: str = "serving",
    beta_mode: str = "serving",
    alpha_attest: str | None = "MinerA",
    beta_attest: str | None = "MinerC",
    beta_build_id_header: bool = True,
) -> None:
    alpha, beta = manifest.deployments
    fixture.server.state.routes = {
        alpha.challenge_path: RouteBehavior(alpha, alpha_mode, attest_with=alpha_attest),
        beta.challenge_path: RouteBehavior(
            beta, beta_mode, attest_with=beta_attest, build_id_header=beta_build_id_header
        ),
    }


def probe_config(
    publication: Publication,
    fixture: TLSFixture,
    tmp_path: Path,
    *,
    name: str = "run",
    anchor: str = "genesis",
    evaluation_epoch: int = EVALUATION_EPOCH,
    current_finalized_height: int = FINALIZED_HEIGHT,
    manifest: ManifestSource | None = None,
    signatures: tuple[SignatureSource, ...] | None = None,
    edge_origin: str | None = None,
    report_output: str | None = None,
) -> AssignmentProbeCLIConfig:
    output = tmp_path / "output"
    output.mkdir(mode=0o700, exist_ok=True)
    return AssignmentProbeCLIConfig(
        trust_policy=publication.policy_file,
        manifest=manifest or ManifestSource(file=publication.manifest_file),
        signatures=signatures
        or tuple(SignatureSource(file=item) for item in publication.signature_files),
        evaluation_epoch=evaluation_epoch,
        current_finalized_height=current_finalized_height,
        validator_uid=7,
        validator_hotkey="ValidatorA",
        state_root=str(tmp_path / "state"),
        trusted_state_anchor=anchor,
        report_output=report_output or str(output / f"{name}.json"),
        edge_origin=edge_origin if edge_origin is not None else fixture.origin,
        tls_ca_file=str(fixture.ca_path),
    )


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
        "--evaluation-epoch",
        str(config.evaluation_epoch),
        "--finalized-height",
        str(config.current_finalized_height),
        "--validator-uid",
        str(config.validator_uid),
        "--validator-hotkey",
        config.validator_hotkey,
        "--state-root",
        config.state_root,
        "--trusted-state-anchor",
        config.trusted_state_anchor,
        "--report-output",
        config.report_output,
    ]
    if config.edge_origin is not None:
        values += ["--edge-origin", config.edge_origin]
    if config.tls_ca_file is not None:
        values += ["--tls-ca-file", config.tls_ca_file]
    return values


def assert_cli_rejected(code: str, function: Callable[[], object]) -> None:
    with pytest.raises(AssignmentProbeCLIError) as error:
        function()
    assert error.value.code == code


def test_probe_reports_serving_over_local_tls_and_advances_state(
    tmp_path: Path, tls_server: TLSFixture
) -> None:
    context = make_context()
    publication = write_publication(tmp_path / "publication", context)
    configure_routes(tls_server, context.manifest)
    config = probe_config(publication, tls_server, tmp_path)
    result = execute_assignment_probe(config)
    report = result.report
    assert result.state_advanced is True
    assert report.status == "serving"
    assert report.edge_origin_override is True
    assert [item.outcome for item in report.observations] == ["serving", "serving"]
    alpha, beta = report.observations
    assert alpha.attestation_status == "verified"
    assert alpha.attestation is not None
    assert alpha.attestation.miner_hotkey == "MinerA"
    assert alpha.tls_leaf_certificate_sha256 == tls_server.leaf_sha256
    assert beta.attestation_status == "verified"
    assert beta.attestation is not None
    assert beta.attestation.miner_hotkey == "MinerC"
    assert beta.response_bytes == 64
    rendered = Path(config.report_output).read_bytes()
    assert parse_validator_probe_report(rendered) == report
    assert (Path(config.report_output).stat().st_mode & 0o777) == 0o600
    state_path = Path(config.state_root) / "state.json"
    assert parse_assignment_manifest_chain_state(state_path.read_bytes()) == result.next_chain_state
    assert (Path(config.state_root).stat().st_mode & 0o777) == 0o700
    seen = {path: headers for path, headers in tls_server.server.state.requests}
    for deployment in context.manifest.deployments:
        headers = seen[deployment.challenge_path]
        assert headers["host"] == deployment.route_host
        assert len(headers["x-miss-probe-nonce"]) == 64
        assert headers["accept-encoding"] == "identity"
    nonces = {headers["x-miss-probe-nonce"] for headers in seen.values()}
    assert len(nonces) == 2
    assert {item.probe_nonce for item in report.observations} == nonces


def test_run_cli_prints_stable_status_and_exit_codes(
    tmp_path: Path, tls_server: TLSFixture, capsys: pytest.CaptureFixture[str]
) -> None:
    context = make_context()
    publication = write_publication(tmp_path / "publication", context)
    configure_routes(tls_server, context.manifest)
    config = probe_config(publication, tls_server, tmp_path)
    assert run_cli(config_argv(config)) == EXIT_OK
    captured = capsys.readouterr()
    state = parse_assignment_manifest_chain_state(
        (Path(config.state_root) / "state.json").read_bytes()
    )
    assert captured.out == (
        "PROBED status=serving deployments=2 serving=2 failed=0 "
        f"next_state_sha256={state.state_digest_sha256}\n"
    )
    assert captured.err == ""

    configure_routes(tls_server, context.manifest, beta_mode="wrong_body")
    degraded = probe_config(
        publication, tls_server, tmp_path, name="degraded", anchor=state.state_digest_sha256
    )
    assert run_cli(config_argv(degraded)) == EXIT_DEGRADED
    captured = capsys.readouterr()
    assert captured.out.startswith("PROBED status=degraded deployments=2 serving=1 failed=1 ")
    report = parse_validator_probe_report(Path(degraded.report_output).read_bytes())
    assert report.manifest_reprobe is True
    assert report.observations[1].failure_code == "body_digest_mismatch"

    assert run_cli([]) == EXIT_USAGE
    assert capsys.readouterr().err == "REJECTED usage\n"
    assert run_cli(config_argv(degraded)) == EXIT_REJECTED
    assert capsys.readouterr().err == "REJECTED output_exists\n"
    stale = probe_config(
        publication,
        tls_server,
        tmp_path,
        name="stale",
        anchor=state.state_digest_sha256,
        evaluation_epoch=BASE_EPOCH + 3_600,
    )
    assert run_cli(config_argv(stale)) == EXIT_REJECTED
    assert capsys.readouterr().err == "REJECTED manifest_expired\n"
    assert not Path(stale.report_output).exists()


@pytest.mark.parametrize(
    ("alpha_mode", "alpha_attest", "beta_mode", "beta_header", "alpha_code", "beta_code"),
    [
        ("serving", None, "status_500", True, "attestation_missing", "unexpected_status"),
        (
            "attest_wrong_key",
            "MinerA",
            "redirect",
            True,
            "attestation_invalid",
            "redirect_rejected",
        ),
        ("serving", "MinerB", "oversized", True, None, "response_oversized"),
        ("serving", "MinerC", "serving", False, None, "build_id_header_mismatch"),
        ("serving", "MinerA", "sleep", True, None, "timeout"),
    ],
)
def test_degraded_outcomes_are_recorded_fail_closed(
    tmp_path: Path,
    tls_server: TLSFixture,
    alpha_mode: str,
    alpha_attest: str | None,
    beta_mode: str,
    beta_header: bool,
    alpha_code: str | None,
    beta_code: str,
) -> None:
    context = make_context()
    policy = build_policy(context.keys, probe_timeout_millis=500)
    manifest = build_manifest(policy, context.deployments)
    publication = write_publication(
        tmp_path / "publication",
        context,
        manifest=manifest,
        signatures=sign_manifest(manifest, context.keys),
        policy=policy,
    )
    configure_routes(
        tls_server,
        manifest,
        alpha_mode=alpha_mode,
        beta_mode=beta_mode,
        alpha_attest=alpha_attest,
        beta_build_id_header=beta_header,
    )
    result = execute_assignment_probe(probe_config(publication, tls_server, tmp_path))
    alpha, beta = result.report.observations
    assert result.report.status == "degraded"
    assert alpha.failure_code == alpha_code
    assert beta.failure_code == beta_code
    if alpha_code is None:
        assert alpha.attestation is not None
        assert alpha.attestation.miner_hotkey == alpha_attest
    if beta_code == "response_oversized":
        assert beta.response_status == 200
    if beta_code == "timeout":
        assert beta.response_status is None


def test_manifest_publication_can_be_fetched_from_explicit_urls(
    tmp_path: Path, tls_server: TLSFixture
) -> None:
    context = make_context()
    publication = write_publication(tmp_path / "publication", context)
    configure_routes(tls_server, context.manifest)
    documents = tls_server.server.state.documents
    documents["/publication/manifest.json"] = active_assignment_manifest_bytes(context.manifest)
    for item in context.signatures:
        documents[f"/publication/{item.signer_key_id}.json"] = (
            assignment_manifest_signature_envelope_bytes(item)
        )
    config = probe_config(
        publication,
        tls_server,
        tmp_path,
        manifest=ManifestSource(url=f"{tls_server.origin}/publication/manifest.json"),
        signatures=tuple(
            SignatureSource(url=f"{tls_server.origin}/publication/{item.signer_key_id}.json")
            for item in context.signatures
        ),
    )
    result = execute_assignment_probe(config)
    assert result.report.status == "serving"
    documents["/publication/manifest.json"] = b"{}\n"
    assert_cli_rejected(
        "manifest_invalid",
        lambda: execute_assignment_probe(
            probe_config(
                publication,
                tls_server,
                tmp_path,
                name="broken",
                anchor="current",
                manifest=ManifestSource(url=f"{tls_server.origin}/publication/manifest.json"),
                signatures=config.signatures,
            )
        ),
    )
    assert_cli_rejected(
        "manifest_fetch_status_invalid",
        lambda: execute_assignment_probe(
            probe_config(
                publication,
                tls_server,
                tmp_path,
                name="missing",
                anchor="current",
                manifest=ManifestSource(url=f"{tls_server.origin}/publication/absent.json"),
                signatures=config.signatures,
            )
        ),
    )
    assert_cli_rejected(
        "manifest_url_invalid",
        lambda: execute_assignment_probe(
            probe_config(
                publication,
                tls_server,
                tmp_path,
                name="plain",
                anchor="current",
                manifest=ManifestSource(url="http://127.0.0.1/manifest.json"),
                signatures=config.signatures,
            )
        ),
    )


def test_replay_rollback_and_equivocation_are_rejected_by_local_state(
    tmp_path: Path, tls_server: TLSFixture
) -> None:
    context = make_context()
    publication = write_publication(tmp_path / "publication", context)
    configure_routes(tls_server, context.manifest)
    first = execute_assignment_probe(probe_config(publication, tls_server, tmp_path))
    anchor = first.next_chain_state.state_digest_sha256
    second_manifest = build_manifest(
        context.policy,
        context.deployments,
        sequence=2,
        previous=context.manifest.manifest_digest_sha256,
        issued_at=BASE_EPOCH + 100,
        expires_at=BASE_EPOCH + 3_700,
        finalized_height=FINALIZED_HEIGHT + 5,
        finalized_block_hash=label_digest("block-two"),
    )
    second_publication = write_publication(
        tmp_path / "publication-two",
        context,
        manifest=second_manifest,
        signatures=sign_manifest(second_manifest, context.keys),
    )
    second = execute_assignment_probe(
        probe_config(second_publication, tls_server, tmp_path, name="second", anchor=anchor)
    )
    assert second.state_advanced is True
    assert second.report.manifest_sequence == 2
    anchor = second.next_chain_state.state_digest_sha256

    with pytest.raises(probe_cli.AssignmentProbeError) as rollback:
        execute_assignment_probe(
            probe_config(publication, tls_server, tmp_path, name="rollback", anchor=anchor)
        )
    assert rollback.value.code == "sequence_rollback"
    divergent = build_manifest(
        context.policy,
        context.deployments,
        sequence=2,
        previous=context.manifest.manifest_digest_sha256,
        issued_at=BASE_EPOCH + 101,
        expires_at=BASE_EPOCH + 3_700,
        finalized_height=FINALIZED_HEIGHT + 5,
        finalized_block_hash=label_digest("block-two"),
    )
    divergent_publication = write_publication(
        tmp_path / "publication-divergent",
        context,
        manifest=divergent,
        signatures=sign_manifest(divergent, context.keys),
    )
    with pytest.raises(probe_cli.AssignmentProbeError) as equivocation:
        execute_assignment_probe(
            probe_config(
                divergent_publication, tls_server, tmp_path, name="divergent", anchor=anchor
            )
        )
    assert equivocation.value.code == "same_sequence_divergence"
    state_path = Path(tmp_path / "state" / "state.json")
    assert parse_assignment_manifest_chain_state(state_path.read_bytes()) == (
        second.next_chain_state
    )
    assert not (tmp_path / "output" / "rollback.json").exists()
    assert not (tmp_path / "output" / "divergent.json").exists()


def test_locked_authenticated_catch_up_persists_across_restart(
    tmp_path: Path, tls_server: TLSFixture
) -> None:
    context = make_context()
    first_publication = write_publication(tmp_path / "publication-one", context)
    configure_routes(tls_server, context.manifest)
    first = execute_assignment_probe(probe_config(first_publication, tls_server, tmp_path))
    manifest_two = build_manifest(
        context.policy,
        context.deployments,
        sequence=2,
        previous=context.manifest.manifest_digest_sha256,
        issued_at=BASE_EPOCH + 100,
        expires_at=BASE_EPOCH + 3_700,
        finalized_height=FINALIZED_HEIGHT + 5,
        finalized_block_hash=label_digest("catch-up-two"),
    )
    signatures_two = tuple(sign_manifest(manifest_two, context.keys))
    from misscomputer_subnet.manifest_publication import replay_manifest_history

    history = (
        ManifestHistoryEntry(
            pointer=build_manifest_latest_pointer(manifest_two, signatures_two),
            manifest=manifest_two,
            signatures=signatures_two,
        ),
    )
    expected = replay_manifest_history(
        first.next_chain_state,
        history,
        context.policy,
        evaluation_epoch=BASE_EPOCH + 200,
    )
    persisted = persist_assignment_manifest_catch_up(
        state_root=str(tmp_path / "state"),
        trust_policy=context.policy,
        history=history,
        evaluation_epoch=BASE_EPOCH + 200,
        expected_anchor_sha256=first.next_chain_state.state_digest_sha256,
        expected_next_state_sha256=expected.state_digest_sha256,
    )
    assert persisted == expected

    manifest_three = build_manifest(
        context.policy,
        context.deployments,
        sequence=3,
        previous=manifest_two.manifest_digest_sha256,
        issued_at=BASE_EPOCH + 200,
        expires_at=BASE_EPOCH + 3_800,
        finalized_height=FINALIZED_HEIGHT + 10,
        finalized_block_hash=label_digest("catch-up-three"),
    )
    publication_three = write_publication(
        tmp_path / "publication-three",
        context,
        manifest=manifest_three,
        signatures=sign_manifest(manifest_three, context.keys),
    )
    configure_routes(tls_server, manifest_three)
    restarted = execute_assignment_probe(
        probe_config(
            publication_three,
            tls_server,
            tmp_path,
            name="restarted",
            anchor=expected.state_digest_sha256,
            evaluation_epoch=BASE_EPOCH + 200,
            current_finalized_height=FINALIZED_HEIGHT,
        )
    )
    assert restarted.next_chain_state.last_sequence == 3


def test_catch_up_expected_anchor_crash_recovery_and_locking(
    tmp_path: Path, tls_server: TLSFixture
) -> None:
    context = make_context()
    publication = write_publication(tmp_path / "publication", context)
    configure_routes(tls_server, context.manifest)
    first = execute_assignment_probe(probe_config(publication, tls_server, tmp_path))

    residue = tmp_path / "state" / probe_cli.STATE_INSTALL_NAME
    residue.write_bytes(b"partial")
    residue.chmod(0o600)
    original_state = (tmp_path / "state" / probe_cli.STATE_NAME).read_bytes()
    assert_cli_rejected(
        "catch_up_state_mismatch",
        lambda: persist_assignment_manifest_catch_up(
            state_root=str(tmp_path / "state"),
            trust_policy=context.policy,
            history=(),
            evaluation_epoch=EVALUATION_EPOCH,
            expected_anchor_sha256=first.next_chain_state.state_digest_sha256,
            expected_next_state_sha256="f" * 64,
        ),
    )
    assert (tmp_path / "state" / probe_cli.STATE_NAME).read_bytes() == original_state
    # A compare failure performs no installation; the next valid install safely
    # removes the interrupted temp before replacing the durable state.
    assert residue.read_bytes() == b"partial"

    persisted = persist_assignment_manifest_catch_up(
        state_root=str(tmp_path / "state"),
        trust_policy=context.policy,
        history=(),
        evaluation_epoch=EVALUATION_EPOCH,
        expected_anchor_sha256=first.next_chain_state.state_digest_sha256,
        expected_next_state_sha256=first.next_chain_state.state_digest_sha256,
    )
    assert persisted == first.next_chain_state
    assert not residue.exists()

    assert_cli_rejected(
        "state_anchor_stale",
        lambda: persist_assignment_manifest_catch_up(
            state_root=str(tmp_path / "state"),
            trust_policy=context.policy,
            history=(),
            evaluation_epoch=EVALUATION_EPOCH,
            expected_anchor_sha256="0" * 64,
            expected_next_state_sha256=first.next_chain_state.state_digest_sha256,
        ),
    )
    with probe_cli._StateRoot(str(tmp_path / "state")):
        assert_cli_rejected(
            "probe_busy",
            lambda: persist_assignment_manifest_catch_up(
                state_root=str(tmp_path / "state"),
                trust_policy=context.policy,
                history=(),
                evaluation_epoch=EVALUATION_EPOCH,
                expected_anchor_sha256=first.next_chain_state.state_digest_sha256,
                expected_next_state_sha256=first.next_chain_state.state_digest_sha256,
            ),
        )


def test_state_anchor_and_output_protections(tmp_path: Path, tls_server: TLSFixture) -> None:
    context = make_context()
    publication = write_publication(tmp_path / "publication", context)
    configure_routes(tls_server, context.manifest)
    first = execute_assignment_probe(probe_config(publication, tls_server, tmp_path))
    digest_anchor = first.next_chain_state.state_digest_sha256
    assert_cli_rejected(
        "state_anchor_stale",
        lambda: execute_assignment_probe(
            probe_config(publication, tls_server, tmp_path, name="genesis-again")
        ),
    )
    assert_cli_rejected(
        "state_anchor_stale",
        lambda: execute_assignment_probe(
            probe_config(publication, tls_server, tmp_path, name="wrong", anchor="0" * 64)
        ),
    )
    assert_cli_rejected(
        "state_anchor_invalid",
        lambda: execute_assignment_probe(
            probe_config(publication, tls_server, tmp_path, name="bad", anchor="not-a-digest")
        ),
    )
    assert_cli_rejected(
        "output_path_unsafe",
        lambda: execute_assignment_probe(
            probe_config(
                publication,
                tls_server,
                tmp_path,
                anchor=digest_anchor,
                report_output=str(tmp_path / "state" / "report.json"),
            )
        ),
    )
    assert_cli_rejected(
        "output_path_alias",
        lambda: execute_assignment_probe(
            probe_config(
                publication,
                tls_server,
                tmp_path,
                anchor=digest_anchor,
                report_output=publication.manifest_file.path,
            )
        ),
    )
    assert_cli_rejected(
        "trusted_digest_mismatch",
        lambda: execute_assignment_probe(
            replace(
                probe_config(
                    publication, tls_server, tmp_path, name="digest", anchor=digest_anchor
                ),
                trust_policy=InputFile(publication.policy_file.path, "0" * 64),
            )
        ),
    )
    assert_cli_rejected(
        "operator_context_invalid",
        lambda: execute_assignment_probe(
            replace(
                probe_config(
                    publication, tls_server, tmp_path, name="hotkey", anchor=digest_anchor
                ),
                validator_hotkey="not valid!",
            )
        ),
    )
    assert_cli_rejected(
        "edge_origin_invalid",
        lambda: execute_assignment_probe(
            probe_config(
                publication,
                tls_server,
                tmp_path,
                name="origin",
                anchor=digest_anchor,
                edge_origin="http://127.0.0.1:1/",
            )
        ),
    )
    replay = execute_assignment_probe(
        probe_config(publication, tls_server, tmp_path, name="current", anchor="current")
    )
    assert replay.state_advanced is False
    assert replay.report.manifest_reprobe is True


def test_wrong_certificate_host_and_pins_fail_closed(tmp_path: Path) -> None:
    context = make_context()
    fixture = start_server(tmp_path / "other", dns_names=("elsewhere.mock.local",))
    try:
        publication = write_publication(tmp_path / "publication", context)
        configure_routes(fixture, context.manifest)
        result = execute_assignment_probe(probe_config(publication, fixture, tmp_path))
        assert result.report.status == "degraded"
        assert {item.failure_code for item in result.report.observations} == {
            "tls_certificate_invalid"
        }
        assert all(item.tls_leaf_certificate_sha256 is None for item in result.report.observations)
    finally:
        fixture.server.shutdown()
        fixture.server.server_close()

    pinned_server = start_server(tmp_path / "pinned")
    try:
        pinned_policy = build_policy(
            context.keys, pinned_edge_leaf_certificate_sha256=(pinned_server.leaf_sha256,)
        )
        pinned_manifest = build_manifest(pinned_policy, context.deployments)
        pinned_publication = write_publication(
            tmp_path / "publication-pinned",
            context,
            manifest=pinned_manifest,
            signatures=sign_manifest(pinned_manifest, context.keys),
            policy=pinned_policy,
        )
        configure_routes(pinned_server, pinned_manifest)
        pinned_root = tmp_path / "pinned-run"
        pinned_root.mkdir(mode=0o700)
        result = execute_assignment_probe(
            probe_config(pinned_publication, pinned_server, pinned_root, name="pinned")
        )
        assert result.report.status == "serving"
        assert all(
            item.tls_leaf_certificate_sha256 == pinned_server.leaf_sha256
            for item in result.report.observations
        )
        wrong_pin_policy = build_policy(
            context.keys, pinned_edge_leaf_certificate_sha256=(label_digest("other-edge"),)
        )
        wrong_pin_manifest = build_manifest(wrong_pin_policy, context.deployments)
        wrong_publication = write_publication(
            tmp_path / "publication-wrong-pin",
            context,
            manifest=wrong_pin_manifest,
            signatures=sign_manifest(wrong_pin_manifest, context.keys),
            policy=wrong_pin_policy,
        )
        configure_routes(pinned_server, wrong_pin_manifest)
        wrong_root = tmp_path / "wrong-pin-run"
        wrong_root.mkdir(mode=0o700)
        result = execute_assignment_probe(
            probe_config(wrong_publication, pinned_server, wrong_root, name="wrong-pin")
        )
        assert {item.failure_code for item in result.report.observations} == {"tls_pin_mismatch"}
    finally:
        pinned_server.server.shutdown()
        pinned_server.server.server_close()


def test_unreachable_origin_is_a_recorded_failure_not_a_crash(tmp_path: Path) -> None:
    context = make_context()
    fixture = start_server(tmp_path / "closed")
    fixture.server.shutdown()
    fixture.server.server_close()
    publication = write_publication(tmp_path / "publication", context)
    result = execute_assignment_probe(probe_config(publication, fixture, tmp_path))
    assert result.report.status == "degraded"
    assert {item.failure_code for item in result.report.observations} == {"connection_failed"}


def test_default_tooling_is_inert_and_cli_has_no_authority_capabilities() -> None:
    project = (ROOT / "pyproject.toml").read_text()
    assert 'misscomputer-assignment-probe = "misscomputer_subnet.assignment_probe_cli:main"' in (
        project
    )
    source = (ROOT / "src" / "misscomputer_subnet" / "assignment_probe_cli.py").read_text()
    tree = ast.parse(source)
    identifiers: set[str] = set()
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            identifiers.add(node.id)
        elif isinstance(node, ast.Attribute):
            identifiers.add(node.attr)
        elif isinstance(node, ast.Import):
            imported.update(alias.name.split(".", maxsplit=1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            imported.add(node.module.split(".", maxsplit=1)[0])
    assert not imported & {"bittensor", "socket", "subprocess", "urllib3", "requests"}
    assert not identifiers & {
        "Ed25519PrivateKey",
        "Popen",
        "Wallet",
        "set_weights",
        "sign",
        "system",
        "urlopen",
        "wallet",
    }
    assert "miss.computer/" not in source.replace("miss.computer/misscomputer-subnet", "")
    assert "https://" not in source
    module_level_calls = [
        node
        for node in tree.body
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)
    ]
    assert not module_level_calls
    assert run_cli(["--help"]) == EXIT_USAGE


def test_probe_transport_classifies_failures_without_raising(tmp_path: Path) -> None:
    context = ssl.create_default_context()
    transport = probe_cli.HttpsProbeTransport(context)
    result = transport.fetch(
        url="https://127.0.0.1:1/__challenge/000000000000000000000000",
        server_name="fixture-alpha.mock.local",
        headers={"host": "fixture-alpha.mock.local"},
        timeout_seconds=1.0,
        max_bytes=64,
    )
    assert isinstance(result, probe_cli.ProbeTransportFailure)
    assert result.code == "connection_failed"
    assert json.dumps(result.code)
    del tmp_path


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
        url="https://fixture-alpha.mock.local/__challenge/000000000000000000000000",
        server_name="fixture-alpha.mock.local",
        headers={"host": "fixture-alpha.mock.local"},
        timeout_seconds=budget_seconds,
        max_bytes=max_bytes,
    )


def _response_scenarios(
    deployment: ActiveDeploymentAssignment, probe_nonce: str
) -> dict[str, Callable[[httpx.Request], httpx.Response]]:
    """One responder per response-derived outcome ``evaluate_probe_response`` can reach."""

    replica = deployment.replicas[0]
    body = challenge_value(deployment.deployment_id).encode("ascii")
    good = {"X-Build-ID": deployment.build_id}
    attestation = attestation_header(sign_attestation(deployment, replica, probe_nonce=probe_nonce))

    def respond(
        status: int = 200,
        *,
        content: bytes = body,
        headers: list[tuple[str, str]] | None = None,
    ) -> Callable[[httpx.Request], httpx.Response]:
        # A streamed body keeps the response readable through ``iter_raw`` and
        # lets the declared ``Content-Length`` be judged before the body.
        return lambda _request: httpx.Response(
            status,
            stream=httpx.ByteStream(content),
            headers=[("Content-Length", str(len(content))), *(headers or [])],
        )

    return {
        "serving": respond(headers=[*good.items(), ("X-Miss-Probe-Attestation", attestation)]),
        "tls_pin_mismatch": respond(
            headers=[*good.items(), ("X-Miss-Probe-Attestation", attestation)]
        ),
        "redirect_rejected": respond(302, content=b"", headers=[("Location", "https://x/")]),
        "unexpected_status": respond(500, content=b"no"),
        "response_oversized": respond(content=b"x" * 6_000, headers=list(good.items())),
        "body_digest_mismatch": respond(content=b"tampered", headers=list(good.items())),
        "build_id_header_mismatch": respond(headers=[("X-Build-ID", "0" * 24)]),
        "attestation_missing": respond(headers=list(good.items())),
        "attestation_invalid": respond(
            headers=[
                *good.items(),
                ("X-Miss-Probe-Attestation", attestation),
                ("X-Miss-Probe-Attestation", attestation),
            ]
        ),
    }


def test_transport_enforces_one_whole_request_budget_at_the_exact_boundary() -> None:
    """Every response-derived outcome fits the budget or becomes a timeout, at ms precision.

    With a 100ms budget, a request completing at exactly 100ms yields the
    response-derived outcome with ``latency_millis == 100``; at 101ms every
    one of them (serving and all eight response-derived failure codes,
    including a late oversized ``Content-Length``) is reported as
    ``ProbeTransportFailure("timeout")`` with the measured latency. Both are
    admissible under :func:`verify_observation_policy_binding` for the policy
    that set the budget, so the transport never emits an observation the
    report builder, the decision, or the parser would refuse.
    """

    context = make_context()
    deployment = context.deployments[0]
    probe_nonce = label_digest("budget-nonce")
    unpinned = build_policy(context.keys, probe_timeout_millis=100, max_response_bytes=4_096)
    pinned = build_policy(
        context.keys,
        probe_timeout_millis=100,
        max_response_bytes=4_096,
        pinned_edge_leaf_certificate_sha256=(label_digest("edge-leaf"),),
    )
    scenarios = _response_scenarios(deployment, probe_nonce)
    for code, responder in scenarios.items():
        policy = pinned if code == "tls_pin_mismatch" else unpinned
        at_budget = _fetch(responder, elapsed_seconds=0.1)
        assert at_budget.latency_millis == 100, code
        if code == "response_oversized":
            # Declared Content-Length above the ceiling is judged before the body.
            assert isinstance(at_budget, probe_cli.ProbeTransportFailure)
            assert at_budget.code == "response_oversized" and at_budget.response_status == 200
        else:
            assert isinstance(at_budget, probe_cli.ProbeResponse), code
        observation = evaluate_probe_response(
            deployment, policy, probe_nonce=probe_nonce, result=at_budget
        )
        assert (observation.outcome, observation.failure_code) == (
            ("serving", None) if code == "serving" else ("failed", code)
        )
        assert observation.latency_millis == 100
        verify_observation_policy_binding(observation, policy)

        over_budget = _fetch(responder, elapsed_seconds=0.101)
        assert isinstance(over_budget, probe_cli.ProbeTransportFailure), code
        assert over_budget.code == "timeout" and over_budget.latency_millis == 101
        assert over_budget.response_status == (
            302 if code == "redirect_rejected" else (500 if code == "unexpected_status" else 200)
        )
        late = evaluate_probe_response(
            deployment, policy, probe_nonce=probe_nonce, result=over_budget
        )
        assert (late.outcome, late.failure_code, late.latency_millis) == ("failed", "timeout", 101)
        verify_observation_policy_binding(late, policy)

    # A body that exceeds the ceiling only while streaming is response-derived too.
    def chunked(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, stream=httpx.ByteStream(b"y" * 5_000), headers={"X-Build-ID": deployment.build_id}
        )

    streamed = _fetch(chunked, elapsed_seconds=0.1, max_bytes=64)
    assert isinstance(streamed, probe_cli.ProbeTransportFailure)
    assert (streamed.code, streamed.latency_millis) == ("response_oversized", 100)
    late_stream = _fetch(chunked, elapsed_seconds=0.101, max_bytes=64)
    assert isinstance(late_stream, probe_cli.ProbeTransportFailure)
    assert (late_stream.code, late_stream.latency_millis) == ("timeout", 101)

    # Only whole-request expiry is timeout; early operation timeouts are transport faults.
    def slow(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow origin", request=request)

    for elapsed, latency in ((0.05, 50), (0.1, 100), (0.25, 250)):
        result = _fetch(slow, elapsed_seconds=elapsed)
        assert isinstance(result, probe_cli.ProbeTransportFailure)
        assert (result.code, result.latency_millis) == (
            "timeout" if latency > 100 else "transport_error",
            latency,
        )
        verify_observation_policy_binding(
            evaluate_probe_response(deployment, unpinned, probe_nonce=probe_nonce, result=result),
            unpinned,
        )

    def refused(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    result = _fetch(refused, elapsed_seconds=0.25)
    assert isinstance(result, probe_cli.ProbeTransportFailure)
    assert (result.code, result.latency_millis) == ("timeout", 250)

    # The budget is the policy's millisecond value, rounded once from seconds.
    budget = probe_cli.RequestBudget(0.1, clock=_FixedClock(0.0))
    assert budget.budget_millis == 100
    assert not budget.exhausted(100) and budget.exhausted(101)
    assert probe_cli.RequestBudget(5.0, clock=_FixedClock(0.0)).budget_millis == 5_000


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
            server_name="fixture-alpha.mock.local",
            headers={"host": "fixture-alpha.mock.local"},
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
        server_name="fixture-alpha.mock.local",
        headers={"host": "fixture-alpha.mock.local"},
        timeout_seconds=5.0,
        max_bytes=4_096,
    )
    assert isinstance(result, probe_cli.ProbeTransportFailure)
    assert (result.code, result.response_status) == ("transport_error", None)


def test_out_of_contract_wire_status_is_a_transport_fault_under_and_over_budget() -> None:
    """httpx accepts 600..999 on the wire; the contract does not, so it is never an observation."""

    context = make_context()
    deployment = context.deployments[0]
    policy = build_policy(context.keys, probe_timeout_millis=100)

    def odd(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(999, stream=httpx.ByteStream(b""), headers=[("Content-Length", "0")])

    within = _fetch(odd, elapsed_seconds=0.1)
    assert isinstance(within, probe_cli.ProbeTransportFailure)
    assert (within.code, within.response_status, within.latency_millis) == (
        "transport_error",
        None,
        100,
    )
    observation = evaluate_probe_response(
        deployment, policy, probe_nonce=label_digest("odd"), result=within
    )
    assert (observation.failure_code, observation.response_status) == ("transport_error", None)
    verify_observation_policy_binding(observation, policy)
    over = _fetch(odd, elapsed_seconds=0.101)
    assert isinstance(over, probe_cli.ProbeTransportFailure)
    assert (over.code, over.latency_millis) == ("timeout", 101)
    # The contract layer defends itself too, for transports that let it through.
    leaked = probe_cli.ProbeResponse(
        status=600, headers=(), body=b"", latency_millis=5, tls_leaf_certificate_sha256=None
    )
    observation = evaluate_probe_response(
        deployment, policy, probe_nonce=label_digest("odd"), result=leaked
    )
    assert (observation.outcome, observation.failure_code, observation.response_status) == (
        "failed",
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


def test_probe_requires_the_finalized_height_and_refuses_expired_leases(
    tmp_path: Path, tls_server: TLSFixture, capsys: pytest.CaptureFixture[str]
) -> None:
    """The CLI cannot run without the operator's finalized height, and a lapsed lease is fatal."""

    context = make_context()
    publication = write_publication(tmp_path / "publication", context)
    configure_routes(tls_server, context.manifest)
    earliest = min(
        replica.expires_at_block
        for item in context.manifest.deployments
        for replica in item.replicas
    )
    config = probe_config(publication, tls_server, tmp_path)
    argv = config_argv(config)
    index = argv.index("--finalized-height")
    assert run_cli([*argv[:index], *argv[index + 2 :]]) == EXIT_USAGE
    assert capsys.readouterr().err == "REJECTED usage\n"
    assert run_cli([*argv[:index], "--finalized-height", "-1", *argv[index + 2 :]]) == EXIT_USAGE
    capsys.readouterr()
    state_path = Path(config.state_root) / "state.json"
    assert not state_path.exists()
    expired = probe_config(
        publication, tls_server, tmp_path, name="expired", current_finalized_height=earliest
    )
    with pytest.raises(probe_cli.AssignmentProbeError) as lease:
        execute_assignment_probe(expired)
    assert lease.value.code == "manifest_replica_lease_expired"
    assert not state_path.exists()
    assert not Path(expired.report_output).exists()
    assert_cli_rejected(
        "operator_context_invalid",
        lambda: execute_assignment_probe(replace(expired, current_finalized_height=-1)),
    )
    leased = probe_config(
        publication, tls_server, tmp_path, name="leased", current_finalized_height=earliest - 1
    )
    result = execute_assignment_probe(leased)
    assert result.state_advanced is True
    assert state_path.exists()
