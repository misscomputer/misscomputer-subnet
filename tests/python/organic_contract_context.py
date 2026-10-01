# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic builders for public organic wire-contract goldens.

``python tests/python/organic_contract_context.py --write`` regenerates
``contracts/{schemas,fixtures}`` for public miner and verifier contracts; tests
assert the committed bytes equal this output, and the Go suite independently
round-trips and verifies the same bytes.

Ed25519 service keys are the RFC 8032 section 7.1 TEST 1 (validator) and
TEST 2 (miner) keys. The validator hotkey is the well-known ``//Alice``
sr25519 development key; sr25519 signatures are randomized, so the probe
authorization signature below was produced once and is pinned verbatim.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import BaseModel

from misscomputer_subnet import organic_contracts as oc
from misscomputer_subnet.contract_codec import canonical_json, digest

ROOT = Path(__file__).resolve().parents[2]
CONTRACTS = ROOT / "contracts"

VALIDATOR_SEED = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
VALIDATOR_PUBLIC = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
MINER_SEED = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
MINER_PUBLIC = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
VALIDATOR_HOTKEY = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"  # //Alice sr25519
MINER_HOTKEY = "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty"  # //Bob sr25519
PROBE_AUTHORIZATION_SIGNATURE = (
    "ca611278f4d3b13fd2e46b2407eca13eb55087e52e634bb67d75d1611fcf7c5e"
    "50b307fcd74cb6ac382419df12b1fd7e169a67b09bcc2877d0bc37763dd10481"
)

ROUTE_LABEL = "hello-world-k3j9x0q2ab"
ROUTE_HOST = f"{ROUTE_LABEL}.on.miss.computer"
ASSIGNMENT_NONCE = "c0634d1e9b2f4a7788d1e0f5a6b7c8d9"
TLS_LEAF = "3a1f" + "0" * 56 + "beef"


def label_digest(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode("ascii")).hexdigest()


def label_hex(label: str, length: int = 64) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()[:length]


def ed25519_sign(seed_hex: str, message: bytes) -> str:
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex)).sign(message).hex()


OCI_MANIFEST = {
    "digest": label_digest("oci-manifest"),
    "media_type": oc.OCI_MANIFEST_MEDIA_TYPE,
    "size": 1187,
}
OCI_CONFIG = {
    "digest": label_digest("oci-config"),
    "media_type": oc.OCI_CONFIG_MEDIA_TYPE,
    "size": 6391,
}
GZIP_LAYER = {
    "diff_id": label_digest("layer-0-uncompressed"),
    "digest": label_digest("layer-0"),
    "media_type": oc.OCI_LAYER_TAR_GZIP,
    "size": 29124558,
    "uncompressed_size": 80233472,
}
TAR_LAYER = {
    "diff_id": label_digest("layer-1"),
    "digest": label_digest("layer-1"),
    "media_type": oc.OCI_LAYER_TAR,
    "size": 4213780,
    "uncompressed_size": 4213780,
}
HEALTH = {
    "method": "GET",
    "path": "/",
    "expected_statuses": [200],
    "response_marker": None,
    "successes_required": 2,
    "interval_millis": 2000,
    "probe_timeout_millis": 5000,
    "startup_timeout_millis": 60000,
}


def artifact_manifest() -> dict[str, Any]:
    return {
        "schema": "miss.computer/misscomputer-subnet/artifact-manifest",
        "schema_version": 2,
        "workload_type": "oci-image-v1",
        "platform": {"architecture": "amd64", "os": "linux"},
        "oci_manifest": dict(OCI_MANIFEST),
        "config": dict(OCI_CONFIG),
        "layers": [dict(GZIP_LAYER), dict(TAR_LAYER)],
        "uncompressed_bytes": GZIP_LAYER["uncompressed_size"] + TAR_LAYER["uncompressed_size"],
    }


ARTIFACT_BYTES = canonical_json(artifact_manifest()) + b"\n"
ARTIFACT_DIGEST = oc.artifact_digest(ARTIFACT_BYTES)
MANIFEST_KEY = oc.manifest_key(ARTIFACT_DIGEST)


def subnet_binding() -> dict[str, Any]:
    """Keys in Go ``protocol.SubnetBinding`` declaration order."""

    return {
        "network": "finney",
        "netuid": 24,
        "validator_hotkey": VALIDATOR_HOTKEY,
        "miner_hotkey": MINER_HOTKEY,
        "miner_uid": 17,
        "miner_axon_url": "https://203.0.113.7:8091",
        "miner_transport": "https",
        "miner_tls_certificate_sha256": TLS_LEAF,
        "chain_block": 5123456,
        "epoch": 14231,
        "expires_at_block": 5123481,
        "validator_service_public_key": VALIDATOR_PUBLIC,
        "miner_service_public_key": MINER_PUBLIC,
    }


def _go_marshal(value: dict[str, Any]) -> bytes:
    """Go ``encoding/json`` bytes for a struct whose fields are in dict order.

    Valid for the fixture's values only: none contains ``<``, ``>``, ``&`` or
    non-ASCII, which Go would escape differently.
    """

    return json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def unsigned_ticket() -> dict[str, Any]:
    """Keys in Go ``protocol.TicketV4`` declaration order (signature omitted)."""

    return {
        "version": "deployment.v4",
        "deployment_id": ROUTE_LABEL,
        "generation": 1,
        "image_digest": ARTIFACT_DIGEST,
        "manifest_key": MANIFEST_KEY,
        "miner_id": MINER_HOTKEY,
        "route_host": ROUTE_HOST,
        "assignment_nonce": ASSIGNMENT_NONCE,
        "workload": {
            "kind": "oci-image-v1",
            "container_port": 8080,
            "runtime_profile": "small-v1",
            "env": {"HOST": "0.0.0.0", "PORT": "8080"},  # noqa: S104
        },
        "resources": dict(oc.SMALL_V1_RESOURCES),
        "health": {**HEALTH, "failure_threshold": 2},
        "issued_at": "2026-09-26T00:14:06.120418Z",
        "expires_at": "2026-09-26T00:19:06.120418Z",
        "subnet": subnet_binding(),
    }


def ticket() -> dict[str, Any]:
    unsigned = unsigned_ticket()
    return {**unsigned, "signature": ed25519_sign(VALIDATOR_SEED, _go_marshal(unsigned))}


REPLICA_ID = f"{ROUTE_LABEL}-{MINER_HOTKEY}"
ENDPOINT_ID = f"{REPLICA_ID}-g1-{ASSIGNMENT_NONCE}"


def unsigned_receipt() -> dict[str, Any]:
    """Keys in Go ``protocol.ReceiptV4`` declaration order (signature omitted)."""

    return {
        "version": "deployment.v4",
        "deployment_id": ROUTE_LABEL,
        "generation": 1,
        "assignment_nonce": ASSIGNMENT_NONCE,
        "miner_id": MINER_HOTKEY,
        "replica_id": REPLICA_ID,
        "endpoint_id": ENDPOINT_ID,
        "image_digest": ARTIFACT_DIGEST,
        "manifest_key": MANIFEST_KEY,
        "loaded_image_config_digest": OCI_CONFIG["digest"],
        "route_host": ROUTE_HOST,
        "stage": "ready",
        "error_code": None,
        "error": "",
        "assignment_seen": "2026-09-26T00:14:06.52Z",
        "pull_started": "2026-09-26T00:14:06.61Z",
        "pull_completed": "2026-09-26T00:14:31.004Z",
        "runtime_started": "2026-09-26T00:14:33.1Z",
        "health_passed": "2026-09-26T00:14:37.25Z",
        "subnet": subnet_binding(),
    }


def receipt() -> dict[str, Any]:
    unsigned = unsigned_receipt()
    return {**unsigned, "signature": ed25519_sign(MINER_SEED, _go_marshal(unsigned))}


def validator_binding() -> dict[str, Any]:
    return {
        "protocol": "service-binding.v2",
        "role": "validator",
        "transport": "local",
        "transport_certificate_sha256": None,
        "network": "finney",
        "netuid": 24,
        "hotkey": VALIDATOR_HOTKEY,
        "uid": 0,
        "service_public_key": VALIDATOR_PUBLIC,
        "generation": 11,
        "valid_from_block": 5123456,
        "expires_at_block": 5123600,
        "challenge": f"validator-service:{VALIDATOR_PUBLIC}",
        "signature": "0" * 128,
    }


def deploy_synapse() -> dict[str, Any]:
    return {
        "protocol": "subnet-synapse.v3",
        "request_id": "0123456789abcdef0123456789abcdef",
        "current_block": 5123457,
        "caller_hotkey": VALIDATOR_HOTKEY,
        "validator_binding": validator_binding(),
        "ticket": ticket(),
    }


def deploy_response() -> dict[str, Any]:
    return {
        "protocol": "subnet-synapse.v3",
        "request_id": "0123456789abcdef0123456789abcdef",
        "result": {"receipt": receipt(), "endpoint_id": ENDPOINT_ID},
        "idempotent": False,
    }


def status_response() -> dict[str, Any]:
    return {
        "protocol": "subnet-synapse.v3",
        "request_id": "fedcba9876543210fedcba9876543210",
        "status": "ready",
        "receipt": receipt(),
    }


def bridge_assign() -> dict[str, Any]:
    return {
        "protocol": "subnet-synapse.v3",
        "request_id": "0123456789abcdef0123456789abcdef",
        "ticket": ticket(),
    }


def edge_runtime_request() -> dict[str, Any]:
    return {
        "body_sha256": hashlib.sha256(b'{"hello":"world"}').hexdigest(),
        "endpoint_id": ENDPOINT_ID,
        "method": "POST",
        "nonce": "5f1d2c3b4a5968778695a4b3c2d1e0f0",
        "path": "/api/items/a%20b",
        "query": "page=2&sort=desc",
        "timestamp": 1790381646120418000,
    }


TICKET_DIGEST = "sha256:" + digest(ticket())
RECEIPT_DIGEST = "sha256:" + digest(receipt())


def _manifest_replica(uid: int, hotkey: str, nonce: str, public_key: str) -> dict[str, Any]:
    replica = f"{ROUTE_LABEL}-{hotkey}"
    own = hotkey == MINER_HOTKEY
    return {
        "miner_uid": uid,
        "miner_hotkey": hotkey,
        "miner_service_public_key": public_key,
        "miner_tls_certificate_sha256": TLS_LEAF if own else label_hex(f"tls-{hotkey}"),
        "generation": 1,
        "assignment_nonce": nonce,
        "replica_id": replica,
        "endpoint_id": f"{replica}-g1-{nonce}",
        "ticket_digest": TICKET_DIGEST if own else label_digest(f"ticket-{hotkey}"),
        "receipt_digest": RECEIPT_DIGEST if own else label_digest(f"receipt-{hotkey}"),
        "chain_block": 5123456,
        "expires_at_block": 5123481,
        "activated_at_epoch": 1790381740,
        "expires_at_epoch": 1790382046,
        "route_state": "active",
    }


def sealed(document: dict[str, Any], field: str) -> dict[str, Any]:
    unsigned = {key: value for key, value in document.items() if key != field}
    return {**unsigned, field: digest(unsigned)}


def active_assignment_manifest() -> dict[str, Any]:
    replicas = [
        _manifest_replica(
            9,
            "5DAAnrj7VHTznn2AWBemMuyBwZWs6FNFjdyVXUeYum3PTXFy",
            label_hex("nonce-dave", 32),
            label_hex("service-dave"),
        ),
        _manifest_replica(17, MINER_HOTKEY, ASSIGNMENT_NONCE, MINER_PUBLIC),
        _manifest_replica(
            23,
            "5FLSigC9HGRKVhB9FiEo4Y3koPsNmBmLJbpXg2mp1hXcS59Y",
            label_hex("nonce-charlie", 32),
            label_hex("service-charlie"),
        ),
    ]
    assignment = sealed(
        {
            "deployment_id": ROUTE_LABEL,
            "route_host": ROUTE_HOST,
            "artifact_digest": ARTIFACT_DIGEST,
            "health": {
                key: HEALTH[key]
                for key in ("method", "path", "expected_statuses", "response_marker")
            },
            "attestation_requirement": "miner_service_key_v2",
            "replicas": replicas,
        },
        "assignment_digest_sha256",
    )
    return sealed(
        {
            "schema": "miss.computer/misscomputer-subnet/active-assignment-manifest",
            "schema_version": 2,
            "purpose": "active_assignment_manifest_publication_v2",
            "network": "finney",
            "netuid": 24,
            "central_authority_fingerprint_sha256": label_hex("central-authority"),
            "trust_policy_digest_sha256": label_hex("trust-policy-v2"),
            "finalized_height": 5123460,
            "finalized_block_hash": label_hex("block-5123460"),
            "finalized_epoch": 14231,
            "sequence": 1,
            "previous_manifest_digest_sha256": None,
            "issued_at_epoch": 1790381760,
            "expires_at_epoch": 1790381940,
            "route_host_suffix": "on.miss.computer",
            "probe_scheme": "https",
            "probe_port": 443,
            "deployments": [assignment],
            "assignment_vector_digest_sha256": digest([assignment]),
        },
        "manifest_digest_sha256",
    )


#: Static-site contract §3.5 site, §7.1 release and implementation digests.
STATIC_ROUTE_LABEL = "static-docs-m4p9qx7c2a"
STATIC_SITE_DIGEST = "sha256:9db3b2a4b3f18c1d31fd7d3348f83e1dfde21163d5aca540fd2f63d6b88ab77f"
STATIC_RELEASE_DIGEST = "sha256:a3ea17b8d08367ae5e971b7ee495cfae6d6bbaff9483f4396fe21189086ae19c"
STATIC_SERVER_DIGEST = "sha256:" + "ab" * 32


def _static_replica(uid: int, hotkey: str, public_key: str) -> dict[str, Any]:
    replica = f"{STATIC_ROUTE_LABEL}-{hotkey}"
    nonce = label_hex(f"static-nonce-{hotkey}", 32)
    return {
        **_manifest_replica(uid, hotkey, nonce, public_key),
        "replica_id": replica,
        "endpoint_id": f"{replica}-g1-{nonce}",
        "ticket_digest": label_digest(f"static-ticket-{hotkey}"),
        "receipt_digest": label_digest(f"static-receipt-{hotkey}"),
    }


def active_assignment_manifest_v3() -> dict[str, Any]:
    """One ``oci-image-v1`` deployment equal to the v2 golden's and one static site."""

    v2 = active_assignment_manifest()
    oci = {
        key: value
        for key, value in v2["deployments"][0].items()
        if key != "assignment_digest_sha256"
    }
    oci = sealed(
        {
            **oci,
            "workload_kind": "oci-image-v1",
            "site_digest": None,
            "release_digest": None,
            "server_implementation_digest": None,
        },
        "assignment_digest_sha256",
    )
    static = sealed(
        {
            "deployment_id": STATIC_ROUTE_LABEL,
            "route_host": f"{STATIC_ROUTE_LABEL}.on.miss.computer",
            "workload_kind": "static-site-v1",
            "artifact_digest": None,
            "health": None,
            "site_digest": STATIC_SITE_DIGEST,
            "release_digest": STATIC_RELEASE_DIGEST,
            "server_implementation_digest": STATIC_SERVER_DIGEST,
            "attestation_requirement": "miner_service_key_v2",
            "replicas": [
                _static_replica(
                    9,
                    "5DAAnrj7VHTznn2AWBemMuyBwZWs6FNFjdyVXUeYum3PTXFy",
                    label_hex("service-dave"),
                ),
                _static_replica(17, MINER_HOTKEY, MINER_PUBLIC),
            ],
        },
        "assignment_digest_sha256",
    )
    deployments = [oci, static]
    header = {
        key: value
        for key, value in v2.items()
        if key not in {"deployments", "assignment_vector_digest_sha256", "manifest_digest_sha256"}
    }
    return sealed(
        {
            **header,
            "schema_version": 3,
            "purpose": "active_assignment_manifest_publication_v3",
            "deployments": deployments,
            "assignment_vector_digest_sha256": digest(deployments),
        },
        "manifest_digest_sha256",
    )


def _v3_case(mutate: Any, *, reseal: bool = True) -> dict[str, Any]:
    """The v3 golden with ``mutate(document)`` applied, optionally resealed.

    Resealing recomputes the deployment, vector and manifest digests so a
    model-level case fails only for its pinned reason.
    """

    document = json.loads(json.dumps(active_assignment_manifest_v3()))
    mutate(document)
    if not reseal:
        return document
    document["deployments"] = [
        sealed(item, "assignment_digest_sha256") for item in document["deployments"]
    ]
    document["assignment_vector_digest_sha256"] = digest(document["deployments"])
    return sealed(document, "manifest_digest_sha256")


def _set(path: tuple[Any, ...], value: Any) -> Any:
    def mutate(document: dict[str, Any]) -> None:
        target: Any = document
        for key in path[:-1]:
            target = target[key]
        if value is _DELETE:
            del target[path[-1]]
        else:
            target[path[-1]] = value

    return mutate


_DELETE = object()


def _static_on_other_route(document: dict[str, Any]) -> None:
    replica = document["deployments"][1]["replicas"][0]
    replica["endpoint_id"] = replica["endpoint_id"].replace(STATIC_ROUTE_LABEL, ROUTE_LABEL)


def _static_first(document: dict[str, Any]) -> None:
    document["deployments"].reverse()


#: case -> (expect, code, document). Schema cases carry the pydantic error type.
MANIFEST_V3_NEGATIVE: dict[str, tuple[str, str, Any]] = {
    "static-artifact-digest-present": (
        "schema",
        "none_required",
        lambda: _v3_case(_set(("deployments", 1, "artifact_digest"), ARTIFACT_DIGEST)),
    ),
    "static-health-present": (
        "schema",
        "none_required",
        lambda: _v3_case(
            _set(
                ("deployments", 1, "health"),
                active_assignment_manifest()["deployments"][0]["health"],
            )
        ),
    ),
    "static-release-digest-null": (
        "schema",
        "string_type",
        lambda: _v3_case(_set(("deployments", 1, "release_digest"), None)),
    ),
    "oci-site-digest-present": (
        "schema",
        "none_required",
        lambda: _v3_case(_set(("deployments", 0, "site_digest"), STATIC_SITE_DIGEST)),
    ),
    "workload-kind-unknown": (
        "schema",
        "union_tag_invalid",
        lambda: _v3_case(_set(("deployments", 1, "workload_kind"), "static-site-v2")),
    ),
    "v2-deployment-shape": (
        "schema",
        "union_tag_not_found",
        lambda: _v3_case(
            _set(("deployments", 0), dict(active_assignment_manifest()["deployments"][0]))
        ),
    ),
    "unknown-static-member": (
        "schema",
        "extra_forbidden",
        lambda: _v3_case(_set(("deployments", 1, "fallback"), None)),
    ),
    "purpose-v2": (
        "schema",
        "literal_error",
        lambda: _v3_case(_set(("purpose",), "active_assignment_manifest_publication_v2")),
    ),
    "schema-version-2": (
        "schema",
        "literal_error",
        lambda: _v3_case(_set(("schema_version",), 2)),
    ),
    "static-binding-changed-without-reseal": (
        "model",
        "assignment_digest_sha256_mismatch",
        lambda: _v3_case(
            _set(("deployments", 1, "site_digest"), label_digest("another-site")), reseal=False
        ),
    ),
    "static-replica-identity-invalid": (
        "model",
        "assignment_replica_identity_invalid",
        lambda: _v3_case(_static_on_other_route),
    ),
    "static-route-host-mismatch": (
        "model",
        "manifest_route_host_invalid",
        lambda: _v3_case(_set(("deployments", 1, "route_host"), "static.on.miss.computer")),
    ),
    "deployments-not-canonical": (
        "model",
        "manifest_deployments_not_canonical",
        lambda: _v3_case(_static_first),
    ),
}


def negative_v3(case: str) -> dict[str, Any]:
    expect, code, build = MANIFEST_V3_NEGATIVE[case]
    return {
        "case": case,
        "code": code,
        "contract": "active-assignment-manifest.v3",
        "document": build(),
        "expect": expect,
        "schema_version": 1,
    }


def unsigned_probe_authorization() -> dict[str, Any]:
    return {
        "schema": "miss.computer/misscomputer-subnet/organic-probe-authorization",
        "schema_version": 1,
        "validator_hotkey": VALIDATOR_HOTKEY,
        "endpoint_id": ENDPOINT_ID,
        "generation": 1,
        "method": "GET",
        "path": "/",
        "nonce": label_hex("probe-nonce-1"),
        "issued_at": "2026-09-26T00:17:12Z",
    }


def probe_authorization() -> dict[str, Any]:
    return {**unsigned_probe_authorization(), "signature": PROBE_AUTHORIZATION_SIGNATURE}


def probe_attestation() -> dict[str, Any]:
    unsigned = {
        "schema": "miss.computer/misscomputer-subnet/miner-probe-attestation",
        "schema_version": 2,
        "endpoint_id": ENDPOINT_ID,
        "generation": 1,
        "ticket_digest": TICKET_DIGEST,
        "artifact_digest": ARTIFACT_DIGEST,
        "validator_hotkey": VALIDATOR_HOTKEY,
        "probe_nonce": label_hex("probe-nonce-1"),
        "request_method": "GET",
        "request_path": "/",
        "response_status": 200,
        "response_body_sha256": hashlib.sha256(b"hello world\n").hexdigest(),
        "response_header_sha256": oc.response_header_sha256(
            [("Content-Type", "text/plain; charset=utf-8"), ("Content-Length", "12")]
        ),
        "observed_at": "2026-09-26T00:17:12.410233Z",
    }
    model = oc.MinerProbeAttestationV2.model_validate({**unsigned, "signature_hex": "0" * 128})
    message = oc.miner_probe_attestation_v2_message(model)
    return {**unsigned, "signature_hex": ed25519_sign(MINER_SEED, message)}


FIXTURE_BUILDERS: dict[str, Any] = {
    "artifact-manifest.v2": artifact_manifest,
    "deployment-ticket.v4": ticket,
    "deployment-receipt.v4": receipt,
    "deploy.v3": deploy_synapse,
    "deploy-response.v3": deploy_response,
    "status-response.v3": status_response,
    "bridge-assign.v3": bridge_assign,
    "edge-runtime-request.v1": edge_runtime_request,
    "active-assignment-manifest.v2": active_assignment_manifest,
    "active-assignment-manifest.v3": active_assignment_manifest_v3,
    "organic-probe-authorization.v1": probe_authorization,
    "miner-probe-attestation.v2": probe_attestation,
}


def vectors() -> dict[str, Any]:
    """Cross-language digest and signature vectors (contract section 16, item 2)."""

    request = oc.EdgeRuntimeRequest.model_validate(edge_runtime_request())
    edge_message = oc.edge_runtime_request_message(request)
    edge_signature = ed25519_sign(VALIDATOR_SEED, edge_message)
    authorization = oc.OrganicProbeAuthorization.model_validate(probe_authorization())
    attestation = oc.MinerProbeAttestationV2.model_validate(probe_attestation())
    return {
        "schema": "miss.computer/misscomputer-subnet/organic-contract-vectors",
        "schema_version": 1,
        "keys": {
            "miner_service": {"public_key_hex": MINER_PUBLIC, "seed_hex": MINER_SEED},
            "validator_hotkey_ss58": VALIDATOR_HOTKEY,
            "validator_service": {"public_key_hex": VALIDATOR_PUBLIC, "seed_hex": VALIDATOR_SEED},
        },
        "artifact_manifest": {
            "artifact_digest": ARTIFACT_DIGEST,
            "fixture": "artifact-manifest.v2.json",
            "manifest_key": MANIFEST_KEY,
        },
        "ticket": {"fixture": "deployment-ticket.v4.json", "ticket_digest": TICKET_DIGEST},
        "edge_runtime_request": {
            "fixture": "edge-runtime-request.v1.json",
            "header_value": oc.edge_authorization_header_value(request, edge_signature),
            "message_sha256": hashlib.sha256(edge_message).hexdigest(),
            "signature_hex": edge_signature,
        },
        "organic_probe_authorization": {
            "fixture": "organic-probe-authorization.v1.json",
            "message_hex": oc.organic_probe_message(authorization).hex(),
        },
        "miner_probe_attestation": {
            "fixture": "miner-probe-attestation.v2.json",
            "message_sha256": hashlib.sha256(
                oc.miner_probe_attestation_v2_message(attestation)
            ).hexdigest(),
        },
    }


def schema_bytes(model: type[BaseModel]) -> bytes:
    rendered = json.dumps(model.model_json_schema(), indent=2, sort_keys=True, ensure_ascii=True)
    return (rendered + "\n").encode("ascii")


def generated_tree() -> dict[str, bytes]:
    """Every organic contract file, keyed by its path under ``contracts/``."""

    tree: dict[str, bytes] = {}
    for stem, model in oc.CONTRACT_MODELS.items():
        tree[f"schemas/{stem}.schema.json"] = schema_bytes(model)
        tree[f"fixtures/{stem}.json"] = canonical_json(FIXTURE_BUILDERS[stem]()) + b"\n"
    tree["fixtures/organic-contract-vectors.v1.json"] = canonical_json(vectors()) + b"\n"
    for case in MANIFEST_V3_NEGATIVE:
        path = f"negative/active-assignment-manifest.v3/{case}.json"
        tree[path] = canonical_json(negative_v3(case)) + b"\n"
    return tree


def main() -> None:
    if sys.argv[1:] != ["--write"]:
        raise SystemExit("usage: organic_contract_context.py --write")
    for relative, payload in sorted(generated_tree().items()):
        path = CONTRACTS / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)


if __name__ == "__main__":
    main()
