# SPDX-License-Identifier: AGPL-3.0-only
"""Own Bittensor 11.1.0 RPC transports before their awaited initialization.

The pinned SDK's RpcSubstrate publishes primary and lazy archive interfaces
only after initialize(). Its narrow exception cleanup misses cancellation and
malformed metadata. Keep an independent ownership list at the synchronous
interface factory seam; this also makes failure of one close unable to strand
another transport. No SDK files are patched and no write/signing API is added.
"""

from __future__ import annotations

from contextlib import suppress
from typing import Any

from bittensor._substrate import RpcSubstrate
from bittensor._transport.interface import SubstrateConnection
from bittensor.settings import (
    default_archive_endpoints,
    default_fallback_endpoints,
    resolve_endpoint,
)

from .async_lifecycle import drain_cleanup


class _OwnedRpcSubstrate(RpcSubstrate):
    def __init__(self, network: str, *, pinned: bool) -> None:
        resolved_network, endpoint = resolve_endpoint(network)
        super().__init__(
            endpoint,
            fallback_endpoints=(
                []
                if pinned
                else [
                    url for url in default_fallback_endpoints(resolved_network) if url != endpoint
                ]
            ),
            archive_endpoints=[] if pinned else default_archive_endpoints(resolved_network),
        )
        self._owned_interfaces: list[SubstrateConnection] = []

    def _interface(self, endpoint: str, fallbacks: list[str]) -> SubstrateConnection:
        raw = super()._interface(endpoint, fallbacks)
        self._owned_interfaces.append(raw)
        return raw

    async def connect(self) -> None:
        try:
            await super().connect()
        except BaseException as primary:
            try:
                await self.close()
            except BaseException:
                primary.add_note("rpc_initialization_cleanup_failed")
            raise

    async def _archive(self) -> SubstrateConnection | None:
        try:
            return await super()._archive()
        except BaseException as primary:
            try:
                await self.close()
            except BaseException:
                primary.add_note("rpc_archive_cleanup_failed")
            raise

    async def _close_owned(self) -> None:
        # RpcSession.close() clears its websocket slot after suppressing an
        # ordinary websocket.close() failure. Capture every lower ownership
        # layer before asking the SDK to close or clearing our published slots.
        retirements = [self._capture_retirement(raw) for raw in self._owned_interfaces]
        self._owned_interfaces = []
        self._substrate = None
        self._archive_substrate = None
        primary: BaseException | None = None
        for raw, session, websocket, transport, supervisor in reversed(retirements):
            failure: BaseException | None = None
            try:
                await raw.close()
            except BaseException as exc:
                failure = exc
            try:
                await self._retire_session(session, websocket, transport, supervisor)
            except BaseException as exc:
                if failure is None:
                    failure = exc
                else:
                    failure.add_note("rpc_transport_fallback_cleanup_failed")
            if failure is not None:
                if primary is None:
                    primary = failure
                else:
                    primary.add_note("rpc_additional_transport_cleanup_failed")
        if primary is not None:
            raise primary

    @staticmethod
    def _capture_retirement(raw: SubstrateConnection) -> tuple[Any, ...]:
        session = raw._session
        websocket = session._ws
        return raw, session, websocket, getattr(websocket, "transport", None), session._supervisor

    @staticmethod
    async def _retire_session(
        session: Any,
        websocket: Any,
        transport: Any,
        supervisor: Any,
    ) -> None:
        """Drain the captured SDK layers without trusting mutable SDK slots."""

        primary: BaseException | None = None

        def failed(exc: BaseException) -> None:
            nonlocal primary
            if primary is None:
                primary = exc
            else:
                primary.add_note("rpc_transport_fallback_cleanup_failed")

        session._closing = True
        if supervisor is not None:
            with suppress(BaseException):
                supervisor.cancel()
            with suppress(BaseException):
                await supervisor
        if websocket is not None:
            try:
                await websocket.close()
            except BaseException as exc:
                failed(exc)
        abort = getattr(transport, "abort", None)
        if callable(abort):
            try:
                abort()
            except BaseException as exc:
                failed(exc)
        wait_closed = getattr(websocket, "wait_closed", None)
        if callable(wait_closed):
            try:
                await wait_closed()
            except BaseException as exc:
                failed(exc)
        if session._supervisor is supervisor:
            session._supervisor = None
        if session._ws is websocket:
            session._ws = None
        try:
            # Finish the SDK's pending-request and subscription shutdown after
            # lower-layer retirement, including when its first close stopped
            # before those logical resources were drained.
            await session.close()
        except BaseException as exc:
            failed(exc)
        if primary is not None:
            raise primary

    async def close(self) -> None:
        await drain_cleanup(self._close_owned(), name="bittensor-transport-cleanup")
