# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import ast
import hashlib
import ipaddress
import json
import ssl
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

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
from misscomputer_subnet.assignment_probe import (
    ActiveAssignmentManifest,
    ActiveDeploymentAssignment,
    AssignmentManifestSignatureEnvelope,
    AssignmentManifestTrustPolicy,
    active_assignment_manifest_bytes,
    assignment_manifest_signature_envelope_bytes,
    assignment_manifest_trust_policy_bytes,
    parse_assignment_manifest_chain_state,
    parse_validator_probe_report,
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
    run_cli,
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
    beta_build_id_header: bool = True,
) -> None:
    alpha, beta = manifest.deployments
    fixture.server.state.routes = {
        alpha.challenge_path: RouteBehavior(alpha, alpha_mode, attest_with=alpha_attest),
        beta.challenge_path: RouteBehavior(beta, beta_mode, build_id_header=beta_build_id_header),
    }


def probe_config(
    publication: Publication,
    fixture: TLSFixture,
    tmp_path: Path,
    *,
    name: str = "run",
    anchor: str = "genesis",
    evaluation_epoch: int = EVALUATION_EPOCH,
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
    assert beta.attestation_status == "not_required"
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
