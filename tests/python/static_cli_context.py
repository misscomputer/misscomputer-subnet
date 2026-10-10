# SPDX-License-Identifier: AGPL-3.0-only
"""End-to-end fixtures for ``misscomputer-assignment-probe --static-sites on``.

One in-process transport stands in for the network: it serves the public
static index, answers organic probes like the organic CLI fixture edge (a
healthy replica signing attestation v2), and forwards static probes to the
independent :class:`static_context.FakeStaticEdge` replica. Manifests v2 and
v3 are signed with the fixture central keys under their own domains.
"""

from __future__ import annotations

import base64
import hashlib
import json
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from assignment_probe_context import (
    BASE_EPOCH,
    FINALIZED_BLOCK_HASH,
    FINALIZED_EPOCH,
    FINALIZED_HEIGHT,
    PROBE_PORT,
    ROUTE_SUFFIX,
    build_policy,
    label_digest,
    signer_keys,
)
from bittensor.sp_core import Keypair
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from organic_context import (
    EPOCH,
    EPOCH_START,
    build_manifest,
    fixture_deployments,
    sign_attestation_v2,
    sign_manifest,
)
from static_context import (
    FILES,
    MINER_KEYS,
    SERVER,
    FakeStaticEdge,
    manifest_document,
    raw_public,
    release_bytes,
    revocation_evidence_bytes,
    revocation_policy_bytes,
    revocation_snapshot_bytes,
    sha,
    site_digest,
    stored,
    trust_policy,
)

import misscomputer_subnet.assignment_probe_cli as probe_cli
from misscomputer_subnet import organic_contracts as oc
from misscomputer_subnet.assignment_probe import (
    MANIFEST_PURPOSE,
    MANIFEST_SIGNATURE_ENVELOPE_SCHEMA,
    AssignmentManifestSignatureEnvelope,
    AssignmentManifestTrustPolicy,
    ProbeResponse,
    ProbeTransportFailure,
    assignment_manifest_signature_envelope_bytes,
    assignment_manifest_trust_policy_bytes,
)
from misscomputer_subnet.assignment_probe_cli import (
    AssignmentProbeCLIConfig,
    InputFile,
    ManifestSource,
    SignatureSource,
    WalletSelector,
)
from misscomputer_subnet.contract_codec import digest, model_document
from misscomputer_subnet.organic_contracts import (
    ActiveAssignmentManifestV2,
    ActiveAssignmentManifestV3,
)
from misscomputer_subnet.organic_manifest import (
    assignment_manifest_v3_bytes,
    assignment_manifest_v3_signature_message,
    organic_assignment_manifest_bytes,
)
from misscomputer_subnet.organic_probe import (
    attestation_v2_header,
    parse_probe_authorization_header,
)
from misscomputer_subnet.static_index import (
    StaticEndpointTarget,
    static_index_manifest_key,
    static_index_release_key,
    static_site_release_trust_policy_bytes,
)
from misscomputer_subnet.static_runtime import StaticSitesConfig

VALIDATOR = Keypair.create_from_uri("//Alice")
INDEX_ORIGIN = "https://index.mock.local"
STATIC_ID = "site-a"
STATIC_HOTKEYS = tuple(sorted(MINER_KEYS))


def secure_write(path: Path, payload: bytes) -> Path:
    path.write_bytes(payload)
    path.chmod(0o600)
    return path


def input_file(path: Path) -> InputFile:
    return InputFile(str(path), hashlib.sha256(path.read_bytes()).hexdigest())


def static_deployment_document(site: str, release: bytes) -> dict[str, Any]:
    replicas = []
    for uid, hotkey in enumerate(STATIC_HOTKEYS, start=1):
        nonce = sha(hotkey.encode())[:32]
        replicas.append(
            {
                "miner_uid": uid,
                "miner_hotkey": hotkey,
                "miner_service_public_key": raw_public(MINER_KEYS[hotkey]).hex(),
                "miner_tls_certificate_sha256": label_digest(f"tls-{hotkey}"),
                "generation": 1,
                "assignment_nonce": nonce,
                "replica_id": f"{STATIC_ID}-{hotkey}",
                "endpoint_id": f"{STATIC_ID}-{hotkey}-g1-{nonce}",
                "ticket_digest": "sha256:" + sha(f"ticket-{hotkey}".encode()),
                "receipt_digest": "sha256:" + sha(f"receipt-{hotkey}".encode()),
                "chain_block": FINALIZED_HEIGHT - 10,
                "expires_at_block": FINALIZED_HEIGHT + 600,
                "activated_at_epoch": BASE_EPOCH - 900,
                "expires_at_epoch": BASE_EPOCH + 3_000,
                "route_state": "active",
            }
        )
    unsigned: dict[str, Any] = {
        "deployment_id": STATIC_ID,
        "route_host": f"{STATIC_ID}.{ROUTE_SUFFIX}",
        "workload_kind": "static-site-v1",
        "artifact_digest": None,
        "health": None,
        "site_digest": site,
        "release_digest": "sha256:" + sha(release),
        "server_implementation_digest": SERVER,
        "attestation_requirement": "miner_service_key_v2",
        "replicas": replicas,
    }
    return {**unsigned, "assignment_digest_sha256": digest(unsigned)}


def oci_deployment_document(deployment: oc.OrganicDeploymentAssignment) -> dict[str, Any]:
    """A v2 OCI deployment re-expressed as v3 (static members ``null``)."""

    unsigned = {
        **model_document(deployment, exclude={"assignment_digest_sha256"}),
        "workload_kind": "oci-image-v1",
        "site_digest": None,
        "release_digest": None,
        "server_implementation_digest": None,
    }
    return {**unsigned, "assignment_digest_sha256": digest(unsigned)}


def build_v3_manifest(
    policy: AssignmentManifestTrustPolicy, deployments: list[dict[str, Any]], **header: Any
) -> ActiveAssignmentManifestV3:
    ordered = sorted(deployments, key=lambda item: str(item["deployment_id"]))
    unsigned: dict[str, Any] = {
        "schema": "miss.computer/misscomputer-subnet/active-assignment-manifest",
        "schema_version": 3,
        "purpose": "active_assignment_manifest_publication_v3",
        "network": policy.network,
        "netuid": policy.netuid,
        "central_authority_fingerprint_sha256": policy.central_authority_fingerprint_sha256,
        "trust_policy_digest_sha256": policy.trust_policy_digest_sha256,
        "finalized_height": FINALIZED_HEIGHT,
        "finalized_block_hash": FINALIZED_BLOCK_HASH,
        "finalized_epoch": FINALIZED_EPOCH,
        "sequence": 1,
        "previous_manifest_digest_sha256": None,
        "issued_at_epoch": BASE_EPOCH - 60,
        "expires_at_epoch": BASE_EPOCH + 1_800,
        "route_host_suffix": ROUTE_SUFFIX,
        "probe_scheme": policy.probe_scheme,
        "probe_port": PROBE_PORT,
        "deployments": ordered,
        "assignment_vector_digest_sha256": digest(ordered),
        **header,
    }
    return ActiveAssignmentManifestV3.model_validate(
        {**unsigned, "manifest_digest_sha256": digest(unsigned)}
    )


def sign_v3(
    manifest: ActiveAssignmentManifestV3,
    keys: Mapping[str, Ed25519PrivateKey],
    *,
    message: bytes | None = None,
) -> list[AssignmentManifestSignatureEnvelope]:
    bound = assignment_manifest_v3_signature_message(manifest)
    signed = bound if message is None else message
    return [
        AssignmentManifestSignatureEnvelope.model_validate(
            {
                "schema": MANIFEST_SIGNATURE_ENVELOPE_SCHEMA,
                "schema_version": 1,
                "purpose": MANIFEST_PURPOSE,
                "algorithm": "ed25519",
                "signer_key_id": key_id,
                "manifest_digest_sha256": manifest.manifest_digest_sha256,
                "signed_message_digest_sha256": hashlib.sha256(bound).hexdigest(),
                "signature_base64": base64.b64encode(keys[key_id].sign(signed)).decode("ascii"),
            }
        )
        for key_id in ("auditor", "issuer")
    ]


@dataclass
class StaticWorld:
    """The in-process network: index objects, organic replicas and the static edge."""

    organic: ActiveAssignmentManifestV2
    edge: FakeStaticEdge
    documents: dict[str, bytes]
    calls: list[tuple[str, str]] = field(default_factory=list)

    def fetch(
        self,
        *,
        url: str,
        server_name: str,
        headers: Mapping[str, str],
        timeout_seconds: float,
        max_bytes: int,
        method: str = "GET",
    ) -> ProbeResponse | ProbeTransportFailure:
        header = headers.get(oc.ORGANIC_PROBE_AUTHORIZATION_HEADER)
        if header is None:
            self.calls.append(("index", url))
            key = url.removeprefix(INDEX_ORIGIN + "/")
            if key in self.documents:
                return ProbeResponse(200, (), self.documents[key], 3, None)
            return ProbeResponse(404, (), b"", 3, None)
        authorization = parse_probe_authorization_header(header)
        if authorization.endpoint_id.startswith(f"{STATIC_ID}-"):
            self.calls.append(("static", authorization.endpoint_id))
            return self.edge.fetch(
                url=url,
                server_name=server_name,
                headers=headers,
                timeout_seconds=timeout_seconds,
                max_bytes=max_bytes,
                method=method,
            )
        self.calls.append(("organic", authorization.endpoint_id))
        body = b"ok\n"
        attestation = sign_attestation_v2(
            self.organic, authorization, status=200, body=b"" if method == "HEAD" else body
        )
        return ProbeResponse(
            200,
            (
                ("Content-Type", "text/plain"),
                ("X-Miss-Edge-Upstream", "replica"),
                ("X-Miss-Probe-Attestation", attestation_v2_header(attestation)),
            ),
            body if method == "GET" else b"",
            5,
            None,
        )


@dataclass
class StaticPublication:
    root: Path
    policy: AssignmentManifestTrustPolicy
    organic: ActiveAssignmentManifestV2
    v3: ActiveAssignmentManifestV3
    world: StaticWorld
    policy_file: InputFile
    manifest_file: InputFile
    signature_files: tuple[InputFile, ...]
    seed_file: InputFile
    v3_file: InputFile
    v3_signature_files: tuple[InputFile, ...]
    release_policy_file: InputFile
    revocation_policy_file: Path
    revocation_snapshot_file: Path


#: The default snapshot is issued an hour before the run: fresh, revoking nothing.
REVOCATION_ISSUED_EPOCH = EPOCH_START - 3_600


def write_static_publication(
    root: Path,
    *,
    v3_bytes: bytes | None = None,
    v3_signatures: list[AssignmentManifestSignatureEnvelope] | None = None,
    publish_index: bool = True,
    release_override: bytes | None = None,
) -> StaticPublication:
    root.mkdir(mode=0o700, exist_ok=True)
    keys = signer_keys()
    policy = build_policy(keys)
    organic = build_manifest(policy, fixture_deployments())
    site_manifest = stored(manifest_document(FILES))
    site = site_digest(site_manifest)
    release = release_bytes(site)
    v3 = build_v3_manifest(
        policy,
        [
            static_deployment_document(site, release),
            oci_deployment_document(fixture_deployments()[0]),
        ],
    )
    documents: dict[str, bytes] = {}
    if publish_index:
        documents[static_index_manifest_key(site)] = site_manifest
        documents[static_index_release_key("sha256:" + sha(release))] = release_override or release
    static = next(item for item in v3.deployments if item.workload_kind == "static-site-v1")
    edge = FakeStaticEdge(
        site,
        files=FILES,
        endpoints=tuple(
            StaticEndpointTarget(
                endpoint_id=replica.endpoint_id,
                generation=replica.generation,
                miner_uid=replica.miner_uid,
                miner_hotkey=replica.miner_hotkey,
                miner_service_public_key=replica.miner_service_public_key,
                ticket_digest=replica.ticket_digest,
            )
            for replica in static.replicas
        ),
    )
    world = StaticWorld(organic=organic, edge=edge, documents=documents)

    def write(name: str, payload: bytes) -> InputFile:
        return input_file(secure_write(root / name, payload))

    return StaticPublication(
        root=root,
        policy=policy,
        organic=organic,
        v3=v3,
        world=world,
        policy_file=write("policy.json", assignment_manifest_trust_policy_bytes(policy)),
        manifest_file=write("manifest.json", organic_assignment_manifest_bytes(organic)),
        signature_files=tuple(
            write(
                f"signature-{item.signer_key_id}.json",
                assignment_manifest_signature_envelope_bytes(item),
            )
            for item in sign_manifest(organic, keys)
        ),
        seed_file=write("probe-seed.bin", hashlib.sha256(b"cli-seed").digest()),
        v3_file=write("manifest-v3.json", v3_bytes or assignment_manifest_v3_bytes(v3)),
        v3_signature_files=tuple(
            write(
                f"v3-signature-{item.signer_key_id}.json",
                assignment_manifest_signature_envelope_bytes(item),
            )
            for item in (v3_signatures or sign_v3(v3, keys))
        ),
        release_policy_file=write(
            "static-release-policy.json", static_site_release_trust_policy_bytes(trust_policy())
        ),
        revocation_policy_file=secure_write(
            root / "static-revocation-policy.json", revocation_policy_bytes()
        ),
        revocation_snapshot_file=secure_write(
            root / "static-revocation-snapshot.json",
            revocation_evidence_bytes(revocation_snapshot_bytes(1, REVOCATION_ISSUED_EPOCH)),
        ),
    )


def retarget_test581(publication: StaticPublication) -> None:
    """Rebind the publication's manifest trust policy and signed v3 head to ``test``/581."""

    unsigned = model_document(publication.policy, exclude={"trust_policy_digest_sha256"})
    unsigned.update({"network": "test", "netuid": 581})
    policy = AssignmentManifestTrustPolicy.model_validate(
        {**unsigned, "trust_policy_digest_sha256": digest(unsigned)}
    )
    v3 = build_v3_manifest(policy, [model_document(item) for item in publication.v3.deployments])
    root = publication.root
    publication.policy_file = input_file(
        secure_write(root / "test581-policy.json", assignment_manifest_trust_policy_bytes(policy))
    )
    publication.v3_file = input_file(
        secure_write(root / "test581-v3.json", assignment_manifest_v3_bytes(v3))
    )
    publication.v3_signature_files = tuple(
        input_file(
            secure_write(
                root / f"test581-{item.signer_key_id}.json",
                assignment_manifest_signature_envelope_bytes(item),
            )
        )
        for item in sign_v3(v3, signer_keys())
    )


def cli_config(
    publication: StaticPublication, run: Path, *, static: bool = True, anchor: str = "genesis"
) -> AssignmentProbeCLIConfig:
    for name in ("output", "manifests", "static-manifests", "evidence"):
        (run / name).mkdir(mode=0o700, parents=True, exist_ok=True)
    static_config = (
        StaticSitesConfig(
            manifest=ManifestSource(file=publication.v3_file),
            signatures=tuple(SignatureSource(file=item) for item in publication.v3_signature_files),
            state_root=str(run / "static-state"),
            trusted_state_anchor=anchor,
            release_trust_policy=publication.release_policy_file,
            server_implementation_digest=SERVER,
            index_origin=INDEX_ORIGIN,
            manifest_archive_dir=str(run / "static-manifests"),
            epoch_output=str(run / "output" / "static-epoch.json"),
            journal=str(run / "evidence" / "static-journal.jsonl"),
            revocation_policy=str(publication.revocation_policy_file),
            revocation_policy_digest=json.loads(publication.revocation_policy_file.read_bytes())[
                "digest_sha256"
            ],
            revocation_snapshot=str(publication.revocation_snapshot_file),
        )
        if static
        else None
    )
    return AssignmentProbeCLIConfig(
        trust_policy=publication.policy_file,
        manifest=ManifestSource(file=publication.manifest_file),
        signatures=tuple(SignatureSource(file=item) for item in publication.signature_files),
        probe_seed=publication.seed_file,
        epoch_index=EPOCH,
        current_finalized_height=FINALIZED_HEIGHT,
        validator_hotkey=VALIDATOR.ss58_address,
        wallet=WalletSelector(name="validator", hotkey="default", path=str(run / "w")),
        state_root=str(run / "state"),
        trusted_state_anchor=anchor,
        epoch_output=str(run / "output" / "epoch.json"),
        manifest_archive_dir=str(run / "manifests"),
        edge_origin=None,
        tls_ca_file=None,
        static_sites=static_config,
    )


def config_argv(config: AssignmentProbeCLIConfig) -> list[str]:
    values = [
        "--trust-policy", config.trust_policy.path,
        "--trust-policy-sha256", config.trust_policy.sha256,
        "--manifest-file", str(config.manifest.file.path if config.manifest.file else ""),
        "--manifest-sha256", str(config.manifest.file.sha256 if config.manifest.file else ""),
    ]  # fmt: skip
    for item in config.signatures:
        assert item.file is not None
        values += ["--signature-file", item.file.path, "--signature-sha256", item.file.sha256]
    values += [
        "--probe-seed-file", config.probe_seed.path,
        "--probe-seed-sha256", config.probe_seed.sha256,
        "--epoch-index", str(config.epoch_index),
        "--finalized-height", str(config.current_finalized_height),
        "--validator-hotkey", config.validator_hotkey,
        "--wallet-name", config.wallet.name,
        "--wallet-hotkey", config.wallet.hotkey,
        "--wallet-path", config.wallet.path,
        "--state-root", config.state_root,
        "--trusted-state-anchor", config.trusted_state_anchor,
        "--epoch-output", config.epoch_output,
        "--manifest-archive-dir", config.manifest_archive_dir,
    ]  # fmt: skip
    static = config.static_sites
    if static is None:
        return values
    assert static.manifest.file is not None
    values += [
        "--static-sites", "on",
        "--static-manifest-file", static.manifest.file.path,
        "--static-manifest-sha256", static.manifest.file.sha256,
        "--static-state-root", static.state_root,
        "--static-trusted-state-anchor", static.trusted_state_anchor,
        "--static-release-trust-policy", static.release_trust_policy.path,
        "--static-release-trust-policy-sha256", static.release_trust_policy.sha256,
        "--static-server-implementation-digest", static.server_implementation_digest,
        "--static-index-origin", static.index_origin,
        "--static-manifest-archive-dir", static.manifest_archive_dir,
        "--static-epoch-output", static.epoch_output,
        "--static-journal", static.journal,
    ]  # fmt: skip
    if static.revocation_policy is not None:
        values += [
            "--static-release-revocation-policy", static.revocation_policy,
            "--static-release-revocation-policy-digest", str(static.revocation_policy_digest),
        ]  # fmt: skip
    if static.revocation_snapshot is not None:
        values += ["--static-release-revocation-snapshot", static.revocation_snapshot]
    for item in static.signatures:
        assert item.file is not None
        values += [
            "--static-signature-file", item.file.path,
            "--static-signature-sha256", item.file.sha256,
        ]  # fmt: skip
    return values


class FakeTime:
    """Fast-forward each concurrent scheduler's clock independently."""

    def __init__(self, start: float) -> None:
        self.start = start
        self.local = threading.local()

    def clock(self) -> float:
        return getattr(self.local, "now", self.start)

    def sleep(self, seconds: float) -> None:
        self.local.now = self.clock() + seconds


def alice_signer(_wallet: WalletSelector) -> tuple[Callable[[bytes], bytes], str]:
    return VALIDATOR.sign, VALIDATOR.ss58_address


def execute(
    config: AssignmentProbeCLIConfig, world: StaticWorld
) -> probe_cli.AssignmentProbeCLIResult:
    fake = FakeTime(EPOCH_START)
    return probe_cli.execute_assignment_probe(
        config,
        transport_factory=lambda _context: world,
        signer_factory=alice_signer,
        clock=fake.clock,
        sleep=fake.sleep,
    )
