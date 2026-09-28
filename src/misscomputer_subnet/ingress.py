# SPDX-License-Identifier: AGPL-3.0-only
"""Bounded ASGI request-body ingestion for every public miner route."""

from __future__ import annotations

import asyncio
import contextlib
from time import monotonic

from fastapi import HTTPException, Request

DEFAULT_BODY_IDLE_TIMEOUT = 2.0
DEFAULT_BODY_TOTAL_TIMEOUT = 15.0


def _declared_length(request: Request, max_bytes: int) -> int | None:
    raw_headers = request.scope.get("headers", [])
    lengths = [value for key, value in raw_headers if key.lower() == b"content-length"]
    transfer_encoding = any(key.lower() == b"transfer-encoding" for key, _ in raw_headers)
    if transfer_encoding and lengths:
        raise HTTPException(
            status_code=400,
            detail="request has conflicting body framing",
            headers={"Connection": "close"},
        )
    if len(lengths) > 1:
        raise HTTPException(
            status_code=400,
            detail="request has ambiguous content length",
            headers={"Connection": "close"},
        )
    if not lengths:
        return None
    try:
        rendered = lengths[0].decode("ascii")
        declared = int(rendered)
    except (UnicodeDecodeError, ValueError) as exc:
        raise HTTPException(
            status_code=400,
            detail="request has an invalid content length",
            headers={"Connection": "close"},
        ) from exc
    if declared < 0 or rendered != str(declared):
        raise HTTPException(
            status_code=400,
            detail="request has an invalid content length",
            headers={"Connection": "close"},
        )
    if declared > max_bytes:
        raise HTTPException(
            status_code=413,
            detail="request body exceeds one MiB",
            headers={"Connection": "close"},
        )
    return declared


async def read_request_body(
    request: Request,
    *,
    max_bytes: int,
    idle_timeout: float = DEFAULT_BODY_IDLE_TIMEOUT,
    total_timeout: float = DEFAULT_BODY_TOTAL_TIMEOUT,
) -> bytes:
    """Read at most ``max_bytes + 1`` bytes with idle and total deadlines."""

    if max_bytes < 1 or idle_timeout <= 0 or total_timeout <= 0:
        raise ValueError("request body bounds and deadlines must be positive")
    declared = _declared_length(request, max_bytes)
    stream = request.stream()
    deadline = monotonic() + total_timeout
    body = bytearray()
    try:
        while True:
            remaining_total = deadline - monotonic()
            if remaining_total <= 0:
                raise HTTPException(
                    status_code=408,
                    detail="request body total deadline exceeded",
                    headers={"Connection": "close"},
                )
            try:
                chunk = await asyncio.wait_for(
                    anext(stream), timeout=min(idle_timeout, remaining_total)
                )
            except StopAsyncIteration:
                break
            except TimeoutError as exc:
                detail = (
                    "request body total deadline exceeded"
                    if monotonic() >= deadline
                    else "request body idle deadline exceeded"
                )
                raise HTTPException(
                    status_code=408,
                    detail=detail,
                    headers={"Connection": "close"},
                ) from exc
            remaining = max_bytes + 1 - len(body)
            if remaining > 0:
                body.extend(chunk[:remaining])
            if len(body) > max_bytes or len(chunk) > remaining:
                raise HTTPException(
                    status_code=413,
                    detail="request body exceeds one MiB",
                    headers={"Connection": "close"},
                )
        if declared is not None and len(body) != declared:
            raise HTTPException(
                status_code=400,
                detail="request body length differs from content length",
                headers={"Connection": "close"},
            )
        return bytes(body)
    finally:
        # Closing the ASGI iterator releases a pending receive on cancellation.
        # CancelledError is intentionally not suppressed.
        with contextlib.suppress(Exception):
            await stream.aclose()
