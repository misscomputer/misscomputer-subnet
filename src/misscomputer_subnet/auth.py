# SPDX-License-Identifier: AGPL-3.0-only
"""Remote btauth/1 and local bridge authentication helpers."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import json
import secrets
import sqlite3
import threading
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any, TypeVar
from urllib.parse import urlsplit

import bittensor as bt
import httpx
from pydantic import BaseModel

from .protocol import ServiceKeyBinding

BRIDGE_VERSION = "1"
BRIDGE_MAX_BODY = 1 << 20
BRIDGE_ERROR_CODE_MAX = 128
BRIDGE_ERROR_MESSAGE_MAX = 1024


def load_secret(path: str | None, env_value: str | None = None) -> bytes:
    value = Path(path).read_bytes().strip() if path else (env_value or "").encode().strip()
    if len(value) < 32:
        raise ValueError("bridge secret must contain at least 32 bytes")
    return value


def _bridge_payload(timestamp: str, nonce: str, method: str, target: str, body: bytes) -> bytes:
    digest = hashlib.sha256(body).hexdigest()
    return "\n".join(("miss-bridge/1", timestamp, nonce, method.upper(), target, digest)).encode()


def bridge_headers(
    secret: bytes,
    *,
    method: str,
    target: str,
    body: bytes,
    now_ns: int | None = None,
    nonce: str | None = None,
) -> dict[str, str]:
    if len(secret) < 32:
        raise ValueError("bridge secret is too short")
    timestamp = str(time.time_ns() if now_ns is None else now_ns)
    request_nonce = nonce or secrets.token_urlsafe(18)
    signature = hmac.new(
        secret,
        _bridge_payload(timestamp, request_nonce, method, target, body),
        hashlib.sha256,
    ).hexdigest()
    return {
        "X-Miss-Bridge-Version": BRIDGE_VERSION,
        "X-Miss-Bridge-Timestamp": timestamp,
        "X-Miss-Bridge-Nonce": request_nonce,
        "X-Miss-Bridge-Signature": signature,
    }


T = TypeVar("T", bound=BaseModel)


class BridgeError(RuntimeError):
    def __init__(self, code: str, message: str, retryable: bool, status_code: int) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.retryable = retryable
        self.status_code = status_code


def _bounded_error_text(value: Any, fallback: str, limit: int) -> str:
    if not isinstance(value, str) or not value:
        return fallback
    return value[:limit]


def _response_error(response: httpx.Response) -> BridgeError:
    fallback_message = f"HTTP {response.status_code}"
    try:
        payload = response.json()
    except (ValueError, UnicodeDecodeError, RecursionError):
        payload = None
    if not isinstance(payload, Mapping):
        return BridgeError("bridge_error", fallback_message, False, response.status_code)
    detail = payload.get("error")
    if not isinstance(detail, Mapping):
        return BridgeError("bridge_error", fallback_message, False, response.status_code)
    return BridgeError(
        _bounded_error_text(detail.get("code"), "bridge_error", BRIDGE_ERROR_CODE_MAX),
        _bounded_error_text(detail.get("message"), fallback_message, BRIDGE_ERROR_MESSAGE_MAX),
        detail.get("retryable") is True,
        response.status_code,
    )


class BridgeClient:
    """Bounded application-level client; every retry receives a fresh nonce."""

    def __init__(
        self,
        base_url: str,
        secret: bytes,
        *,
        timeout: float = 15.0,
        retries: int = 1,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.base_url = loopback_bridge_url(base_url)
        self.secret = secret
        self.timeout = timeout
        self.retries = retries
        self.transport = transport

    async def request(
        self,
        method: str,
        path: str,
        *,
        value: BaseModel | Mapping[str, Any] | None = None,
        response_model: type[T] | None = None,
    ) -> T | dict[str, Any]:
        body = b""
        if value is not None:
            raw = value.model_dump(mode="json") if isinstance(value, BaseModel) else dict(value)
            body = json.dumps(raw, separators=(",", ":")).encode()
        last_error: Exception | None = None
        for attempt in range(self.retries + 1):
            headers = bridge_headers(self.secret, method=method, target=path, body=body)
            if body:
                headers["Content-Type"] = "application/json"
            try:
                async with httpx.AsyncClient(
                    base_url=self.base_url,
                    timeout=self.timeout,
                    transport=self.transport,
                    follow_redirects=False,
                    trust_env=False,
                ) as client:
                    response = await client.request(method, path, content=body, headers=headers)
                if len(response.content) > BRIDGE_MAX_BODY:
                    raise RuntimeError("bridge response exceeds the one-MiB limit")
                if response.is_success:
                    if response_model:
                        return response_model.model_validate_json(response.content)
                    payload = response.json()
                    if not isinstance(payload, dict):
                        raise RuntimeError("bridge returned a non-object JSON response")
                    return {str(key): value for key, value in payload.items()}
                error = _response_error(response)
                if not error.retryable:
                    raise error
                last_error = error
            except (httpx.TransportError, httpx.TimeoutException, BridgeError) as exc:
                last_error = exc
                if isinstance(exc, BridgeError) and not exc.retryable:
                    raise
            if attempt < self.retries:
                await asyncio.sleep(0.1 * (attempt + 1))
        raise RuntimeError("bridge request failed") from last_error


def loopback_bridge_url(value: str) -> str:
    """Reject configurations that would send the bridge HMAC off-host."""
    parsed = urlsplit(value.rstrip("/"))
    try:
        address = ipaddress.ip_address(parsed.hostname or "")
        port = parsed.port
    except ValueError as exc:
        raise ValueError("bridge URL must use an explicit loopback IP and port") from exc
    if (
        parsed.scheme != "http"
        or not address.is_loopback
        or port is None
        or not 1 <= port <= 65_535
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("bridge URL must use an explicit loopback IP and port")
    return value.rstrip("/")


class HotkeySigningFacade:
    """Purpose-limited hotkey operations for neuron application code.

    The resolved SDK signer remains private.  In particular this facade does
    not implement ``bittensor.Signer`` and cannot be passed to
    ``Subtensor.execute`` as an extrinsic signer.  This is an in-process API
    boundary, not protection from arbitrary code running as the wallet user.
    """

    __slots__ = ("__signer", "__hotkey")

    def __init__(self, wallet: Any) -> None:
        signer = bt.resolve_signer(wallet, role="hotkey")
        self.__signer = signer
        self.__hotkey = str(signer.ss58_address)

    @property
    def hotkey(self) -> str:
        return self.__hotkey

    def sign_service_binding(self, binding: ServiceKeyBinding) -> ServiceKeyBinding:
        unsigned = binding.model_copy(update={"signature": ""})
        if binding.hotkey != self.__hotkey:
            raise ValueError("service binding hotkey differs from the signing wallet")
        signature = bytes(self.__signer.sign(unsigned.signing_payload())).hex()
        return unsigned.model_copy(update={"signature": signature})

    def sign_http_request(
        self,
        *,
        method: str,
        path: str,
        body: bytes,
        receiver_ss58: str,
    ) -> dict[str, str]:
        return bt.http_auth.sign(
            self.__signer,
            method=method,
            path=path,
            body=body,
            receiver_ss58=receiver_ss58,
        )


class HotkeyAuth(httpx.Auth):
    requires_request_body = True
    __slots__ = ("__signing", "receiver")

    def __init__(self, signing: HotkeySigningFacade, receiver_ss58: str) -> None:
        self.__signing = signing
        self.receiver = receiver_ss58

    def auth_flow(self, request: httpx.Request) -> Any:
        request.headers.update(
            self.__signing.sign_http_request(
                method=request.method,
                path=request.url.raw_path.decode(),
                body=request.content,
                receiver_ss58=self.receiver,
            )
        )
        yield request


class SQLiteNonceStore:
    """Durable btauth replay storage implementing the SDK NonceStore protocol."""

    def __init__(self, path: str, retention: float = 60.0) -> None:
        self.path = path
        self.retention_ns = int(retention * 1_000_000_000)
        self._lock = threading.Lock()
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA busy_timeout=5000")
            connection.execute(
                """CREATE TABLE IF NOT EXISTS btauth_nonces (
                hotkey TEXT NOT NULL, nonce_ns INTEGER NOT NULL, expires_at_ns INTEGER NOT NULL,
                PRIMARY KEY(hotkey, nonce_ns))"""
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5.0)
        connection.execute("PRAGMA busy_timeout=5000")
        return connection

    def check_and_store(self, hotkey_ss58: str, nonce_ns: int) -> bool:
        now_ns = time.time_ns()
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("DELETE FROM btauth_nonces WHERE expires_at_ns <= ?", (now_ns,))
            try:
                connection.execute(
                    "INSERT INTO btauth_nonces VALUES(?,?,?)",
                    (hotkey_ss58, nonce_ns, now_ns + self.retention_ns),
                )
            except sqlite3.IntegrityError:
                connection.rollback()
                return False
            connection.commit()
            return True


class SQLiteBridgeReplay:
    def __init__(self, path: str) -> None:
        self.path = path
        self._lock = threading.Lock()
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA busy_timeout=5000")
            connection.execute(
                """CREATE TABLE IF NOT EXISTS python_bridge_nonces (
                nonce TEXT PRIMARY KEY, expires_at_ns INTEGER NOT NULL)"""
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5.0)
        connection.execute("PRAGMA busy_timeout=5000")
        return connection

    def reserve(self, nonce: str, expires_at_ns: int) -> bool:
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "DELETE FROM python_bridge_nonces WHERE expires_at_ns <= ?",
                (time.time_ns(),),
            )
            try:
                connection.execute(
                    "INSERT INTO python_bridge_nonces VALUES(?,?)",
                    (nonce, expires_at_ns),
                )
            except sqlite3.IntegrityError:
                connection.rollback()
                return False
            connection.commit()
            return True


def verify_bridge_headers(
    secret: bytes,
    headers: Mapping[str, str],
    *,
    method: str,
    target: str,
    body: bytes,
    replay: SQLiteBridgeReplay,
    now_ns: int | None = None,
    max_age_seconds: float = 10.0,
) -> None:
    normalized = {key.lower(): value for key, value in headers.items()}
    if normalized.get("x-miss-bridge-version") != BRIDGE_VERSION:
        raise ValueError("unsupported bridge authentication version")
    timestamp = normalized.get("x-miss-bridge-timestamp", "")
    nonce = normalized.get("x-miss-bridge-nonce", "")
    provided = normalized.get("x-miss-bridge-signature", "")
    if not timestamp or not nonce or not provided:
        raise ValueError("missing bridge authentication headers")
    try:
        timestamp_ns = int(timestamp)
    except ValueError as exc:
        raise ValueError("invalid bridge timestamp") from exc
    current = time.time_ns() if now_ns is None else now_ns
    max_age_ns = int(max_age_seconds * 1_000_000_000)
    if timestamp_ns < current - max_age_ns or timestamp_ns > current + 2_000_000_000:
        raise ValueError("stale bridge request")
    expected = hmac.new(
        secret,
        _bridge_payload(timestamp, nonce, method, target, body),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(provided, expected):
        raise ValueError("invalid bridge signature")
    if not replay.reserve(nonce, current + max_age_ns + 2_000_000_000):
        raise ValueError("replayed bridge request")


def sign_service_binding(binding: ServiceKeyBinding, signer: Any) -> ServiceKeyBinding:
    if isinstance(signer, HotkeySigningFacade):
        return signer.sign_service_binding(binding)
    unsigned = binding.model_copy(update={"signature": ""})
    # Current Bittensor accepts Wallet, Keypair, KeyedWallet, and custom
    # Signer values through this single resolver. A live bt.Wallet itself has
    # no direct sign() method, unlike the deterministic mock Keypair.
    resolved = bt.resolve_signer(signer, role="hotkey")
    if str(resolved.ss58_address) != binding.hotkey:
        raise ValueError("service binding hotkey differs from the signing wallet")
    signature = bytes(resolved.sign(unsigned.signing_payload())).hex()
    return unsigned.model_copy(update={"signature": signature})


def verify_service_binding(
    binding: ServiceKeyBinding,
    *,
    expected_hotkey: str,
    expected_role: str,
    expected_network: str,
    expected_netuid: int,
    expected_challenge: str,
    expected_transport: str,
    expected_transport_certificate_sha256: str | None,
    current_block: int,
) -> None:
    if (
        binding.hotkey != expected_hotkey
        or binding.role != expected_role
        or binding.network != expected_network
        or binding.netuid != expected_netuid
        or binding.challenge != expected_challenge
        or binding.transport != expected_transport
        or binding.transport_certificate_sha256 != expected_transport_certificate_sha256
    ):
        raise ValueError("service binding identity, challenge, or transport mismatch")
    if current_block < binding.valid_from_block or current_block >= binding.expires_at_block:
        raise ValueError("service binding is not current")
    try:
        signature = bytes.fromhex(binding.signature.removeprefix("0x"))
    except ValueError as exc:
        raise ValueError("service binding signature is malformed") from exc
    unsigned = binding.model_copy(update={"signature": ""})
    if not bt.sp_core.verify(unsigned.signing_payload(), signature, binding.hotkey):
        raise ValueError("service binding hotkey signature is invalid")
