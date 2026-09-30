# SPDX-License-Identifier: AGPL-3.0-only
"""Shared builders and an independent fake static replica for static-site tests.

The fake replica implements the v1 serving rules on its own (exact path,
``/index.html`` directory index, extension-less navigation fallback, fixed
404) so tests never take their expected responses from the code under test.
"""

from __future__ import annotations

import base64
import hashlib
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from misscomputer_subnet import organic_contracts as oc
from misscomputer_subnet.assignment_probe import ProbeResponse, ProbeTransportFailure
from misscomputer_subnet.contract_codec import canonical_json
from misscomputer_subnet.organic_probe import (
    attestation_v2_header,
    parse_probe_authorization_header,
)
from misscomputer_subnet.static_index import (
    StaticDeploymentTarget,
    StaticEndpointTarget,
    StaticReleaseKey,
    StaticServerProfile,
    StaticSiteTrustPolicy,
    build_static_site_trust_policy,
)

NOW = 1_800_000_000
SERVER = "sha256:" + hashlib.sha256(b"pinned-static-handler").hexdigest()
PRODUCER = "railpack-static-v1"
NOT_FOUND_BODY = b"404 page not found\n"
VALIDATOR = "5ValidatorHotkey"
SEED = bytes(range(32))

FILES: dict[str, tuple[bytes, str]] = {
    "/index.html": (b"<!doctype html><title>home</title>", "text/html; charset=utf-8"),
    "/docs/index.html": (b"<!doctype html><title>docs</title>", "text/html; charset=utf-8"),
    "/app.js": (b"console.log('app');\n", "text/javascript; charset=utf-8"),
    "/logo.png": (b"\x89PNG\r\n\x1a\n" + b"\x00" * 64, "image/png"),
}


def sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def key(label: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(sha(label.encode()).encode()[:32])


def raw_public(private: Ed25519PrivateKey) -> bytes:
    return private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


RELEASE_KEY = key("release-authority")
MINER_KEYS = {hotkey: key(hotkey) for hotkey in ("5MinerA", "5MinerB", "5MinerC")}


def release_key(
    label: str = "release-a", private: Ed25519PrivateKey = RELEASE_KEY, **overrides: Any
) -> StaticReleaseKey:
    public = raw_public(private)
    return StaticReleaseKey.model_validate(
        {
            "key_id": label,
            "algorithm": "ed25519",
            "public_key_base64": base64.b64encode(public).decode(),
            "public_key_sha256": sha(public),
            "valid_from_epoch": NOW - 1_000,
            "valid_until_epoch": NOW + 100_000,
            "revoked_at_epoch": None,
            **overrides,
        }
    )


def trust_policy(**overrides: Any) -> StaticSiteTrustPolicy:
    fields: dict[str, Any] = {
        "threshold": 1,
        "release_keys": [release_key()],
        "approved_producer_policy_versions": [PRODUCER],
        "server_profiles": [
            StaticServerProfile(
                server_implementation_digest=SERVER,
                not_found_content_type="text/plain; charset=utf-8",
                not_found_size_bytes=len(NOT_FOUND_BODY),
                not_found_sha256=sha(NOT_FOUND_BODY),
            )
        ],
        "valid_from_epoch": NOW - 1_000,
        "valid_until_epoch": NOW + 100_000,
    }
    fields.update(overrides)
    return build_static_site_trust_policy(**fields)


def manifest_document(
    files: Mapping[str, tuple[bytes, str]] = FILES,
    *,
    fallback: str | None = "/index.html",
    **overrides: Any,
) -> dict[str, Any]:
    return {
        "schema": "miss.computer/misscomputer-subnet/static-site-manifest",
        "schema_version": 1,
        "workload_kind": "static-site-v1",
        "producer_policy_version": PRODUCER,
        "files": [
            {"path": path, "size_bytes": len(body), "sha256": sha(body), "content_type": kind}
            for path, (body, kind) in sorted(files.items())
        ],
        "navigation_fallback_path": fallback,
        **overrides,
    }


def canonical_bytes(document: Mapping[str, Any]) -> bytes:
    return canonical_json(dict(document)) + b"\n"


def release_bytes(
    site_digest: str,
    *,
    signers: tuple[tuple[str, Ed25519PrivateKey], ...] = (("release-a", RELEASE_KEY),),
    producer: str = PRODUCER,
    server: str = SERVER,
) -> bytes:
    signed = {
        "schema": "miss.computer/misscomputer-subnet/static-site-release",
        "schema_version": 1,
        "purpose": "static_site_release_v1",
        "site_digest": site_digest,
        "producer_policy_version": producer,
        "server_implementation_digest": server,
    }
    message = (
        b"miss.computer/misscomputer-subnet/static-site-release/v1/ed25519\x00"
        + canonical_json(signed)
    )
    signatures = [
        {
            "signer_key_id": key_id,
            "signature_base64": base64.b64encode(private.sign(message)).decode(),
        }
        for key_id, private in sorted(signers, key=lambda item: item[0])
    ]
    return canonical_bytes({**signed, "signatures": signatures})


def endpoint(hotkey: str, *, uid: int, generation: int = 1) -> StaticEndpointTarget:
    nonce = sha(hotkey.encode())[:32]
    return StaticEndpointTarget(
        endpoint_id=f"site-a-{hotkey}-g{generation}-{nonce}",
        generation=generation,
        miner_uid=uid,
        miner_hotkey=hotkey,
        miner_service_public_key=raw_public(MINER_KEYS[hotkey]).hex(),
        ticket_digest="sha256:" + sha(f"ticket-{hotkey}".encode()),
    )


def target(site_digest: str) -> StaticDeploymentTarget:
    return StaticDeploymentTarget(
        deployment_id="site-a",
        route_host="site-a.on.miss.computer",
        site_digest=site_digest,
        endpoints=[
            endpoint(hotkey, uid=uid) for uid, hotkey in enumerate(sorted(MINER_KEYS), start=1)
        ],
    )


def timestamp(epoch: int) -> str:
    return oc.format_timestamp(datetime.fromtimestamp(epoch, UTC))


@dataclass
class FakeStaticEdge:
    """Serves every endpoint of one site through the pinned-handler rules.

    ``faults`` maps an endpoint id to a callable that may rewrite the honest
    ``(status, headers, body, attested_status, attested_body, nonce)`` tuple,
    or return a transport failure.
    """

    site_digest: str
    files: Mapping[str, tuple[bytes, str]] = field(default_factory=lambda: FILES)
    fallback: str | None = "/index.html"
    faults: dict[str, Callable[..., Any]] = field(default_factory=dict)
    hold_seconds: float = 0.0
    calls: list[tuple[str, str, str]] = field(default_factory=list)
    active: int = 0
    max_active: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def _serve(self, path: str) -> tuple[int, bytes, str]:
        routes = dict(self.files)
        for name, value in self.files.items():
            if name.endswith("/index.html"):
                routes[name[: -len("index.html")]] = value
        if path in routes:
            body, kind = routes[path]
            return 200, body, kind
        if self.fallback is not None and "." not in path.rsplit("/", 1)[-1]:
            body, kind = self.files[self.fallback]
            return 200, body, kind
        return 404, NOT_FOUND_BODY, "text/plain; charset=utf-8"

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
        with self._lock:
            self.active += 1
            self.max_active = max(self.max_active, self.active)
        try:
            if self.hold_seconds:
                time.sleep(self.hold_seconds)
            return self._respond(headers, method)
        finally:
            with self._lock:
                self.active -= 1

    def _respond(
        self, headers: Mapping[str, str], method: str
    ) -> ProbeResponse | ProbeTransportFailure:
        authorization = parse_probe_authorization_header(
            headers[oc.ORGANIC_PROBE_AUTHORIZATION_HEADER]
        )
        self.calls.append((authorization.endpoint_id, method, authorization.path))
        status, body, kind = self._serve(authorization.path)
        response_headers = [
            ("content-type", kind),
            ("content-length", str(len(body))),
            ("x-content-type-options", "nosniff"),
            ("cache-control", "private, no-store"),
        ]
        wire = body if method == "GET" else b""
        state: dict[str, Any] = {
            "status": status,
            "headers": response_headers,
            "body": wire,
            "attested_status": status,
            "attested_body": wire,
            "nonce": authorization.nonce,
            "ticket_digest": None,
            "attest": True,
            "upstream": True,
            "signing_key": None,
        }
        fault = self.faults.get(authorization.endpoint_id)
        if fault is not None:
            outcome = fault(state)
            if isinstance(outcome, ProbeTransportFailure):
                return outcome
        endpoint_target = next(
            item
            for item in target(self.site_digest).endpoints
            if item.endpoint_id == authorization.endpoint_id
        )
        extra: list[tuple[str, str]] = []
        if state["upstream"]:
            extra.append(("x-miss-edge-upstream", "replica"))
        if state["upstream"] and state["attest"]:
            document = {
                "schema": "miss.computer/misscomputer-subnet/miner-probe-attestation",
                "schema_version": 2,
                "endpoint_id": endpoint_target.endpoint_id,
                "generation": endpoint_target.generation,
                "ticket_digest": state["ticket_digest"] or endpoint_target.ticket_digest,
                "artifact_digest": f"sha256:{self.site_digest}",
                "validator_hotkey": authorization.validator_hotkey,
                "probe_nonce": state["nonce"],
                "request_method": method,
                "request_path": authorization.path,
                "response_status": state["attested_status"],
                "response_body_sha256": sha(state["attested_body"]),
                "response_header_sha256": oc.response_header_sha256(state["headers"]),
                "observed_at": authorization.issued_at,
                "signature_hex": "00" * 64,
            }
            unsigned = oc.MinerProbeAttestationV2.model_validate(document)
            private = state["signing_key"] or MINER_KEYS[endpoint_target.miner_hotkey]
            signed = oc.MinerProbeAttestationV2.model_validate(
                {
                    **document,
                    "signature_hex": private.sign(
                        oc.miner_probe_attestation_v2_message(unsigned)
                    ).hex(),
                }
            )
            extra.append(("x-miss-probe-attestation", attestation_v2_header(signed)))
        return ProbeResponse(
            status=state["status"],
            headers=tuple(state["headers"]) + tuple(extra),
            body=state["body"],
            latency_millis=5,
            tls_leaf_certificate_sha256=None,
        )
