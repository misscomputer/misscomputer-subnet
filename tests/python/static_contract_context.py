# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic builders for the public static-site-v1 contract goldens.

``python tests/python/static_contract_context.py --write`` regenerates the
static entries of ``contracts/{schemas,fixtures}``; tests assert the committed
bytes equal this output, and the Go suite independently decodes, verifies and
re-derives the same bytes and digests.

The site is the static-site contract §3.5 worked example, so ``site_digest``
equals the contract's published value. Keys are the RFC 8032 keys of the
organic goldens.
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path
from typing import Any

from organic_contract_context import (
    ASSIGNMENT_NONCE,
    MINER_HOTKEY,
    MINER_PUBLIC,
    MINER_SEED,
    VALIDATOR_HOTKEY,
    VALIDATOR_PUBLIC,
    VALIDATOR_SEED,
    ed25519_sign,
    schema_bytes,
    subnet_binding,
    validator_binding,
)

from misscomputer_subnet import static_contracts as sc
from misscomputer_subnet.contract_codec import canonical_json

ROOT = Path(__file__).resolve().parents[2]
CONTRACTS = ROOT / "contracts"

ROUTE_LABEL = "hello-world-k3j9x0q2ab"
ROUTE_HOST = f"{ROUTE_LABEL}.on.miss.computer"
#: §7.1 example release digest and implementation digest placeholder.
RELEASE_DIGEST = "sha256:9b96232b299069fe8b2dc546f9db0943c43dfefb48f79d15d28ee7b28a031830"
SERVER_IMPLEMENTATION_DIGEST = "sha256:" + "ab" * 32
REQUEST_ID = "0123456789abcdef0123456789abcdef"

#: §3.5 worked example bodies.
BODIES: dict[str, bytes] = {
    "/assets/app.js": b'console.log("hello");\n',
    "/docs/index.html": b"<!doctype html><title>docs</title>\n",
    "/empty.txt": b"",
    "/index.html": b'<!doctype html><title>hello</title><script src="/assets/app.js"></script>\n',
}


def site_manifest() -> dict[str, Any]:
    return {
        "fallback": {"kind": sc.FALLBACK_KIND, "target": "/index.html"},
        "files": [
            {
                "body_sha256": hashlib.sha256(body).hexdigest(),
                "content_length": len(body),
                "content_type": sc.content_type_for(path),
                "path": path,
            }
            for path, body in sorted(BODIES.items())
        ],
        "handler": sc.HANDLER_VERSION,
        "schema": "miss.computer/misscomputer-subnet/static-site-manifest",
        "schema_version": 1,
    }


SITE_BYTES = canonical_json(site_manifest()) + b"\n"
SITE_DIGEST = sc.site_digest(SITE_BYTES)
REPLICA_ID = f"{ROUTE_LABEL}-{MINER_HOTKEY}"
ENDPOINT_ID = f"{REPLICA_ID}-g1-{ASSIGNMENT_NONCE}"


def _signed(domain: bytes, seed: str, unsigned: dict[str, Any]) -> dict[str, Any]:
    signature = ed25519_sign(seed, domain + b"\x00" + canonical_json(unsigned))
    return {**unsigned, "signature": signature}


def ticket() -> dict[str, Any]:
    return _signed(
        sc.TICKET_SIGNING_DOMAIN,
        VALIDATOR_SEED,
        {
            "assignment_nonce": ASSIGNMENT_NONCE,
            "deployment_id": ROUTE_LABEL,
            "expires_at": "2026-09-30T00:19:06.120418Z",
            "generation": 1,
            "issued_at": "2026-09-30T00:14:06.120418Z",
            "miner_id": MINER_HOTKEY,
            "release_digest": RELEASE_DIGEST,
            "route_host": ROUTE_HOST,
            "schema": "miss.computer/misscomputer-subnet/static-deployment-ticket",
            "schema_version": 1,
            "server_implementation_digest": SERVER_IMPLEMENTATION_DIGEST,
            "site_digest": SITE_DIGEST,
            "site_manifest_key": sc.site_manifest_key(SITE_DIGEST),
            "subnet": subnet_binding(),
            "workload_kind": sc.WORKLOAD_KIND,
        },
    )


TICKET_DIGEST = "sha256:" + hashlib.sha256(canonical_json(ticket())).hexdigest()


def receipt() -> dict[str, Any]:
    return _signed(
        sc.RECEIPT_SIGNING_DOMAIN,
        MINER_SEED,
        {
            "assignment_nonce": ASSIGNMENT_NONCE,
            "assignment_seen": "2026-09-30T00:14:06.52Z",
            "deployment_id": ROUTE_LABEL,
            "endpoint_id": ENDPOINT_ID,
            "error": "",
            "error_code": None,
            "fetch_completed": "2026-09-30T00:14:07.004Z",
            "fetch_started": "2026-09-30T00:14:06.61Z",
            "generation": 1,
            "miner_id": MINER_HOTKEY,
            "release_digest": RELEASE_DIGEST,
            "replica_id": REPLICA_ID,
            "route_host": ROUTE_HOST,
            "schema": "miss.computer/misscomputer-subnet/static-deployment-receipt",
            "schema_version": 1,
            "server_implementation_digest": SERVER_IMPLEMENTATION_DIGEST,
            "serving_started": "2026-09-30T00:14:07.1Z",
            "site_digest": SITE_DIGEST,
            "stage": "ready",
            "subnet": subnet_binding(),
            "ticket_digest": TICKET_DIGEST,
            "verified_file_count": len(BODIES),
            "verified_total_bytes": sum(len(body) for body in BODIES.values()),
        },
    )


RECEIPT_DIGEST = "sha256:" + hashlib.sha256(canonical_json(receipt())).hexdigest()


def deploy() -> dict[str, Any]:
    return {
        "protocol": sc.SYNAPSE_VERSION,
        "request_id": REQUEST_ID,
        "current_block": 5123457,
        "caller_hotkey": VALIDATOR_HOTKEY,
        "validator_binding": validator_binding(),
        "ticket": ticket(),
    }


def local_assign() -> dict[str, Any]:
    return {**deploy(), "binding_verified": True}


def bridge_assign() -> dict[str, Any]:
    return {"protocol": sc.SYNAPSE_VERSION, "request_id": REQUEST_ID, "ticket": ticket()}


def deploy_response() -> dict[str, Any]:
    return {
        "protocol": sc.SYNAPSE_VERSION,
        "request_id": REQUEST_ID,
        "endpoint_id": ENDPOINT_ID,
        "receipt": receipt(),
        "idempotent": False,
    }


def status() -> dict[str, Any]:
    return {
        "protocol": sc.SYNAPSE_VERSION,
        "request_id": "fedcba9876543210fedcba9876543210",
        "current_block": 5123460,
        "caller_hotkey": VALIDATOR_HOTKEY,
        "endpoint_id": ENDPOINT_ID,
    }


def status_response() -> dict[str, Any]:
    return {
        "protocol": sc.SYNAPSE_VERSION,
        "request_id": "fedcba9876543210fedcba9876543210",
        "status": "ready",
        "receipt": receipt(),
    }


FIXTURE_BUILDERS: dict[str, Any] = {
    "static-site-manifest.v1": site_manifest,
    "static-deployment-ticket.v1": ticket,
    "static-deployment-receipt.v1": receipt,
    "static-deploy.v1": deploy,
    "static-local-assign.v1": local_assign,
    "static-bridge-assign.v1": bridge_assign,
    "static-deploy-response.v1": deploy_response,
    "static-status.v1": status,
    "static-status-response.v1": status_response,
}


def vectors() -> dict[str, Any]:
    """Cross-language identity and signature vectors for the static documents."""

    unsigned_ticket = {key: value for key, value in ticket().items() if key != "signature"}
    unsigned_receipt = {key: value for key, value in receipt().items() if key != "signature"}
    return {
        "schema": "miss.computer/misscomputer-subnet/static-contract-vectors",
        "schema_version": 1,
        "keys": {
            "miner_service": {"public_key_hex": MINER_PUBLIC, "seed_hex": MINER_SEED},
            "validator_service": {"public_key_hex": VALIDATOR_PUBLIC, "seed_hex": VALIDATOR_SEED},
        },
        "site_manifest": {
            "fixture": "static-site-manifest.v1.json",
            "site_digest": SITE_DIGEST,
            "site_manifest_key": sc.site_manifest_key(SITE_DIGEST),
            "stored_bytes": len(SITE_BYTES),
        },
        "ticket": {
            "fixture": "static-deployment-ticket.v1.json",
            "signed_message_sha256": hashlib.sha256(
                sc.TICKET_SIGNING_DOMAIN + b"\x00" + canonical_json(unsigned_ticket)
            ).hexdigest(),
            "ticket_digest": TICKET_DIGEST,
        },
        "receipt": {
            "endpoint_id": ENDPOINT_ID,
            "fixture": "static-deployment-receipt.v1.json",
            "receipt_digest": RECEIPT_DIGEST,
            "signed_message_sha256": hashlib.sha256(
                sc.RECEIPT_SIGNING_DOMAIN + b"\x00" + canonical_json(unsigned_receipt)
            ).hexdigest(),
        },
    }


def _changed(document: dict[str, Any], **changes: Any) -> dict[str, Any]:
    return {**document, **changes}


def _without(document: dict[str, Any], *keys: str) -> dict[str, Any]:
    return {key: value for key, value in document.items() if key not in keys}


def _manifest_with(**changes: Any) -> dict[str, Any]:
    return _changed(site_manifest(), **changes)


def _file(path: str, content_type: str | None = None) -> dict[str, Any]:
    return {
        "body_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "content_length": 0,
        "content_type": content_type or sc.content_type_for(path),
        "path": path,
    }


INDEX_FILE = site_manifest()["files"][3]

#: ``(contract, case, expect, code, document)``; ``expect`` is ``schema`` when
#: the JSON Schema alone rejects the document, else ``model``.
NEGATIVE_CASES: list[tuple[str, str, str, str, Any]] = [
    (
        "static-site-manifest.v1",
        "case-fold-collision",
        "model",
        "static_case_fold_collision",
        _manifest_with(files=[_file("/A.txt"), _file("/a.txt"), INDEX_FILE]),
    ),
    (
        "static-site-manifest.v1",
        "file-directory-collision",
        "model",
        "static_file_directory_collision",
        _manifest_with(files=[_file("/a"), _file("/a/b.txt"), INDEX_FILE]),
    ),
    (
        "static-site-manifest.v1",
        "index-missing",
        "model",
        "static_index_missing",
        _manifest_with(fallback=None, files=[_file("/a.txt")]),
    ),
    (
        "static-site-manifest.v1",
        "content-type-not-policy",
        "model",
        "static_content_type_invalid",
        _manifest_with(files=[_file("/a.txt", sc.HTML_TYPE), INDEX_FILE]),
    ),
    (
        "static-site-manifest.v1",
        "path-lowercase-escape",
        "model",
        "static_path_invalid",
        _manifest_with(files=[_file("/a%2fb.txt"), INDEX_FILE]),
    ),
    (
        "static-site-manifest.v1",
        "fallback-not-html",
        "model",
        "static_fallback_invalid",
        _manifest_with(fallback={"kind": sc.FALLBACK_KIND, "target": "/assets/app.js"}),
    ),
    (
        "static-deployment-ticket.v1",
        "deployment-v4-version-member",
        "schema",
        "extra_forbidden",
        _changed(ticket(), version="deployment.v4"),
    ),
    (
        "static-deployment-ticket.v1",
        "oci-workload-kind",
        "schema",
        "literal_error",
        _changed(ticket(), workload_kind="oci-image-v1"),
    ),
    (
        "static-deployment-ticket.v1",
        "miner-uid-omitted",
        "schema",
        "missing",
        _changed(ticket(), subnet=_without(subnet_binding(), "miner_uid")),
    ),
    (
        "static-deployment-ticket.v1",
        "route-host-mismatch",
        "model",
        "route_host_mismatch",
        _changed(ticket(), route_host="other-k3j9x0q2ab.on.miss.computer"),
    ),
    (
        "static-deployment-ticket.v1",
        "site-manifest-key-mismatch",
        "model",
        "site_manifest_key_mismatch",
        _changed(ticket(), site_manifest_key="v1/static-sites/" + "0" * 64 + ".json"),
    ),
    (
        "static-deployment-ticket.v1",
        "window-inverted",
        "model",
        "ticket_window_invalid",
        _changed(ticket(), expires_at="2026-09-30T00:14:06.120418Z"),
    ),
    (
        "static-deployment-receipt.v1",
        "ready-without-counts",
        "model",
        "verified_counts_invalid",
        _changed(receipt(), verified_file_count=None, verified_total_bytes=None),
    ),
    (
        "static-deployment-receipt.v1",
        "failed-without-error-code",
        "model",
        "receipt_error_code_invalid",
        _changed(receipt(), stage="failed", verified_file_count=None, verified_total_bytes=None),
    ),
    (
        "static-deployment-receipt.v1",
        "v4-error-code",
        "schema",
        "literal_error",
        _changed(
            receipt(),
            stage="failed",
            error_code="artifact_fetch_failed",
            verified_file_count=None,
            verified_total_bytes=None,
        ),
    ),
    (
        "static-deploy.v1",
        "v3-envelope",
        "schema",
        "literal_error",
        _changed(deploy(), protocol="subnet-synapse.v3"),
    ),
]


def negative_tree() -> dict[str, bytes]:
    tree: dict[str, bytes] = {}
    for contract, case, expect, code, document in NEGATIVE_CASES:
        wrapper = {
            "case": case,
            "code": code,
            "contract": contract,
            "document": document,
            "expect": expect,
            "schema_version": 1,
        }
        tree[f"negative/{contract}/{case}.json"] = canonical_json(wrapper) + b"\n"
    return tree


def generated_tree() -> dict[str, bytes]:
    """Every static contract file, keyed by its path under ``contracts/``."""

    tree: dict[str, bytes] = {}
    for stem, model in sc.STATIC_CONTRACT_MODELS.items():
        tree[f"schemas/{stem}.schema.json"] = schema_bytes(model)
        tree[f"fixtures/{stem}.json"] = canonical_json(FIXTURE_BUILDERS[stem]()) + b"\n"
    tree["fixtures/static-contract-vectors.v1.json"] = canonical_json(vectors()) + b"\n"
    tree.update(negative_tree())
    return tree


def main() -> None:
    if sys.argv[1:] != ["--write"]:
        raise SystemExit("usage: static_contract_context.py --write")
    for relative, payload in sorted(generated_tree().items()):
        path = CONTRACTS / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)


if __name__ == "__main__":
    main()
