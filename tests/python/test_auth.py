# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import time

import httpx
import pytest

from misscomputer_subnet.auth import (
    BridgeClient,
    BridgeError,
    SQLiteBridgeReplay,
    bridge_headers,
    loopback_bridge_url,
    verify_bridge_headers,
)


def test_loopback_hmac_binds_body_path_and_replay(tmp_path: object) -> None:
    path = str(tmp_path) + "/state.db"
    replay = SQLiteBridgeReplay(path)
    secret = b"s" * 32
    body = b'{"ticket":"exact"}'
    now = time.time_ns()
    headers = bridge_headers(
        secret,
        method="POST",
        target="/v1/assignments",
        body=body,
        now_ns=now,
        nonce="one-time-nonce",
    )
    verify_bridge_headers(
        secret,
        headers,
        method="POST",
        target="/v1/assignments",
        body=body,
        replay=replay,
        now_ns=now,
    )
    with pytest.raises(ValueError, match="replayed"):
        verify_bridge_headers(
            secret,
            headers,
            method="POST",
            target="/v1/assignments",
            body=body,
            replay=replay,
            now_ns=now,
        )
    new_headers = bridge_headers(
        secret,
        method="POST",
        target="/v1/assignments",
        body=body,
        now_ns=now,
        nonce="different-nonce",
    )
    with pytest.raises(ValueError, match="signature"):
        verify_bridge_headers(
            secret,
            new_headers,
            method="POST",
            target="/v1/deactivate",
            body=body,
            replay=replay,
            now_ns=now,
        )


def test_bridge_client_url_cannot_send_hmac_off_host() -> None:
    assert loopback_bridge_url("http://127.0.0.1:9101/") == "http://127.0.0.1:9101"
    assert loopback_bridge_url("http://[::1]:9201") == "http://[::1]:9201"
    for value in (
        "http://localhost:9101",
        "http://10.0.0.2:9101",
        "https://127.0.0.1:9101",
        "http://user@127.0.0.1:9101",
        "http://127.0.0.1:9101/path",
    ):
        with pytest.raises(ValueError, match="loopback"):
            loopback_bridge_url(value)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "body",
    [
        b"not-json-" + b"untrusted-marker" * 4096,
        b"[]",
        b"[" * 10_000 + b"0" + b"]" * 10_000,
        b'{"error":' + b"9" * 5_000 + b"}",
    ],
)
async def test_bridge_client_maps_malformed_error_bodies_without_reflection(body: bytes) -> None:
    async def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(httpx.codes.BAD_GATEWAY, content=body)

    client = BridgeClient(
        "http://127.0.0.1:9101",
        b"s" * 32,
        retries=0,
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(BridgeError) as raised:
        await client.request("GET", "/v1/capabilities")
    error = raised.value
    assert error.code == "bridge_error"
    assert error.status_code == httpx.codes.BAD_GATEWAY
    assert error.retryable is False
    assert str(error) == "bridge_error: HTTP 502"
    assert "untrusted-marker" not in str(error)


@pytest.mark.asyncio
async def test_bridge_client_bounds_structured_error_fields() -> None:
    async def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            httpx.codes.BAD_REQUEST,
            json={
                "error": {
                    "code": "c" * 1024,
                    "message": "m" * 4096,
                    "retryable": "true",
                }
            },
        )

    client = BridgeClient(
        "http://127.0.0.1:9101",
        b"s" * 32,
        retries=0,
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(BridgeError) as raised:
        await client.request("GET", "/v1/capabilities")
    assert len(raised.value.code) == 128
    assert len(str(raised.value)) == 128 + 2 + 1024
    assert raised.value.retryable is False
