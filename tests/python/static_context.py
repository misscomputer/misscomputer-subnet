# SPDX-License-Identifier: AGPL-3.0-only
"""Shared builders and an independent fake static replica for static-site tests.

The default site is the static-site contract §3.5 worked example, released as
in §7.1. The fake replica implements the handler rules on its own (exact
route, ``/index.html`` directory index, fallback for a last segment without
``.``, fixed 404, normative headers) so tests never take their expected
responses from the code under test.
"""

from __future__ import annotations

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
    StaticSiteReleaseTrustPolicy,
    build_static_site_release_trust_policy,
)

#: §7.1 example: seed 0x07 * 32, key id, implementation digest, issue time.
RELEASE_KEY = Ed25519PrivateKey.from_private_bytes(b"\x07" * 32)
RELEASE_KEY_ID = "static-release-example"
SERVER = "sha256:" + "ab" * 32
ISSUED_AT = "2026-09-30T00:00:00Z"
ISSUED_EPOCH = 1_790_726_400
PRODUCER = "static-producer-policy.v2"
NOT_FOUND = (b"Not Found\n", "text/plain; charset=utf-8")
VALIDATOR = "5ValidatorHotkey"
SEED = bytes(range(32))
HTML = "text/html; charset=utf-8"

#: §3.5 file set.
FILES: dict[str, tuple[bytes, str]] = {
    "/index.html": (
        b'<!doctype html><title>hello</title><script src="/assets/app.js"></script>\n',
        HTML,
    ),
    "/assets/app.js": (b'console.log("hello");\n', "text/javascript; charset=utf-8"),
    "/docs/index.html": (b"<!doctype html><title>docs</title>\n", HTML),
    "/empty.txt": (b"", "text/plain; charset=utf-8"),
}
SPA = {"kind": "spa-html-v1", "target": "/index.html"}


def sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def stored(document: Mapping[str, Any]) -> bytes:
    return canonical_json(dict(document)) + b"\n"


def raw_public(private: Ed25519PrivateKey) -> bytes:
    return private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def key(label: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(label.encode()).digest())


MINER_KEYS = {hotkey: key(hotkey) for hotkey in ("5MinerA", "5MinerB", "5MinerC")}


def manifest_document(
    files: Mapping[str, tuple[bytes, str]] = FILES,
    *,
    fallback: Mapping[str, str] | None = SPA,
    **overrides: Any,
) -> dict[str, Any]:
    return {
        "fallback": None if fallback is None else dict(fallback),
        "files": [
            {
                "body_sha256": sha(body),
                "content_length": len(body),
                "content_type": content_type,
                "path": path,
            }
            for path, (body, content_type) in sorted(files.items())
        ],
        "handler": "static-handler.v1",
        "schema": "miss.computer/misscomputer-subnet/static-site-manifest",
        "schema_version": 1,
        **overrides,
    }


def site_digest(manifest: bytes) -> str:
    return "sha256:" + sha(manifest)


def release_bytes(
    site: str,
    *,
    private: Ed25519PrivateKey = RELEASE_KEY,
    key_id: str = RELEASE_KEY_ID,
    **overrides: Any,
) -> bytes:
    unsigned = {
        "issued_at": ISSUED_AT,
        "producer_policy_version": PRODUCER,
        "schema": "miss.computer/misscomputer-subnet/static-site-release",
        "schema_version": 1,
        "server_implementation_digest": SERVER,
        "signer_key_id": key_id,
        "site_digest": site,
        **overrides,
    }
    message = (
        b"miss.computer/misscomputer-subnet/static-site-release/v1/ed25519\x00"
        + canonical_json(unsigned)
    )
    return stored({**unsigned, "signature": private.sign(message).hex()})


def release_key(**overrides: Any) -> StaticReleaseKey:
    return StaticReleaseKey.model_validate(
        {
            "key_id": RELEASE_KEY_ID,
            "algorithm": "ed25519",
            "public_key_hex": raw_public(RELEASE_KEY).hex(),
            "valid_from_epoch": ISSUED_EPOCH - 86_400,
            "valid_until_epoch": ISSUED_EPOCH + 86_400,
            **overrides,
        }
    )


def trust_policy(*keys: StaticReleaseKey) -> StaticSiteReleaseTrustPolicy:
    return build_static_site_release_trust_policy(
        policy_id="static-release-test", trusted_keys=list(keys) or [release_key()]
    )


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


def target(
    site: str, release: bytes, *, server: str = SERVER, release_digest: str | None = None
) -> StaticDeploymentTarget:
    return StaticDeploymentTarget(
        deployment_id="site-a",
        route_host="site-a.on.miss.computer",
        site_digest=site,
        release_digest=release_digest or "sha256:" + sha(release),
        server_implementation_digest=server,
        endpoints=[
            endpoint(hotkey, uid=uid) for uid, hotkey in enumerate(sorted(MINER_KEYS), start=1)
        ],
    )


def timestamp(epoch: int) -> str:
    return oc.format_timestamp(datetime.fromtimestamp(epoch, UTC))


@dataclass
class FakeStaticEdge:
    """Serves every endpoint of one site through the static handler rules.

    ``faults`` maps an endpoint id to a callable that may rewrite the honest
    response ``state`` in place or return a transport failure.
    """

    site: str
    files: Mapping[str, tuple[bytes, str]] = field(default_factory=lambda: FILES)
    fallback: str | None = "/index.html"
    faults: dict[str, Callable[..., Any]] = field(default_factory=dict)
    hold_seconds: float = 0.0
    calls: list[tuple[str, str, str]] = field(default_factory=list)
    endpoints: tuple[StaticEndpointTarget, ...] = ()
    active: int = 0
    max_active: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def _serve(self, path: str) -> tuple[int, bytes, str]:
        routes = dict(self.files)
        for name, value in self.files.items():
            if name.endswith("/index.html"):
                routes[name[: -len("index.html")]] = value
        if path in routes:
            body, content_type = routes[path]
            return 200, body, content_type
        if self.fallback is not None and "." not in path.rsplit("/", 1)[-1]:
            body, content_type = self.files[self.fallback]
            return 200, body, content_type
        return 404, *NOT_FOUND

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
        status, body, content_type = self._serve(authorization.path)
        normative = [
            ("Cache-Control", "private, no-store"),
            ("Content-Length", str(len(body))),
            ("Content-Type", content_type),
            ("X-Content-Type-Options", "nosniff"),
        ]
        wire = body if method == "GET" else b""
        state: dict[str, Any] = {
            "status": status,
            "headers": normative,
            "extra_headers": [("Date", "Wed, 30 Sep 2026 00:00:00 GMT")],
            "body": wire,
            "attested_status": status,
            "attested_body": wire,
            "attested_headers": normative,
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
        replica = next(
            item for item in self.endpoints if item.endpoint_id == authorization.endpoint_id
        )
        hop: list[tuple[str, str]] = []
        if state["upstream"]:
            hop.append(("X-Miss-Edge-Upstream", "replica"))
        if state["upstream"] and state["attest"]:
            document = {
                "schema": "miss.computer/misscomputer-subnet/miner-probe-attestation",
                "schema_version": 2,
                "endpoint_id": replica.endpoint_id,
                "generation": replica.generation,
                "ticket_digest": state["ticket_digest"] or replica.ticket_digest,
                "artifact_digest": self.site,
                "validator_hotkey": authorization.validator_hotkey,
                "probe_nonce": state["nonce"],
                "request_method": method,
                "request_path": authorization.path,
                "response_status": state["attested_status"],
                "response_body_sha256": sha(state["attested_body"]),
                "response_header_sha256": oc.response_header_sha256(state["attested_headers"]),
                "observed_at": authorization.issued_at,
                "signature_hex": "00" * 64,
            }
            unsigned = oc.MinerProbeAttestationV2.model_validate(document)
            private = state["signing_key"] or MINER_KEYS[replica.miner_hotkey]
            signature = private.sign(oc.miner_probe_attestation_v2_message(unsigned)).hex()
            signed = oc.MinerProbeAttestationV2.model_validate(
                {**document, "signature_hex": signature}
            )
            hop.append(("X-Miss-Probe-Attestation", attestation_v2_header(signed)))
        return ProbeResponse(
            status=state["status"],
            headers=tuple(state["headers"]) + tuple(state["extra_headers"]) + tuple(hop),
            body=state["body"],
            latency_millis=5,
            tls_leaf_certificate_sha256=None,
        )
