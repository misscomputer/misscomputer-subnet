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
from dataclasses import dataclass
from typing import Any

from bittensor._substrate import RpcSubstrate
from bittensor._transport.interface import SubstrateConnection
from bittensor.settings import (
    default_archive_endpoints,
    default_fallback_endpoints,
    resolve_endpoint,
)

from .async_lifecycle import drain_cleanup


@dataclass(slots=True)
class _RpcInterfaceOwnership:
    raw: SubstrateConnection
    session: Any
    websockets: list[tuple[Any, Any]]


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
        self._owned_interfaces: list[_RpcInterfaceOwnership] = []

    def _interface(self, endpoint: str, fallbacks: list[str]) -> SubstrateConnection:
        raw = super()._interface(endpoint, fallbacks)
        session = raw._session
        connect = session._connect
        websockets: list[tuple[Any, Any]] = []

        async def connect_owned(url: str) -> Any:
            # Closed transports no longer need fallback ownership; retain any
            # ambiguous entry so a failed SDK reconnect close is never lost.
            websockets[:] = [
                (owned_websocket, transport)
                for owned_websocket, transport in websockets
                if not self._connection_retired(owned_websocket, transport)
            ]
            websocket = await connect(url)
            # No await is allowed between acquisition and retention: the SDK
            # may immediately initiate cleanup when later initialization fails.
            websockets.append((websocket, getattr(websocket, "transport", None)))
            return websocket

        session._connect = connect_owned
        self._owned_interfaces.append(
            _RpcInterfaceOwnership(raw=raw, session=session, websockets=websockets)
        )
        return raw

    @staticmethod
    def _connection_retired(websocket: Any, transport: Any) -> bool:
        """Return true only after the lower-layer connection is actually gone."""

        connection_lost = getattr(websocket, "connection_lost_waiter", None)
        done = getattr(connection_lost, "done", None)
        if callable(done):
            with suppress(BaseException):
                if done():
                    return True
        get_extra_info = getattr(transport, "get_extra_info", None)
        if callable(get_extra_info):
            with suppress(BaseException):
                sock = get_extra_info("socket")
                fileno = getattr(sock, "fileno", None)
                if callable(fileno) and fileno() < 0:
                    return True
        return False

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
        owned = self._owned_interfaces
        self._owned_interfaces = []

        # Freeze every session before the first await. Otherwise a supervisor
        # later in the list can reconnect while an earlier interface is being
        # closed and replace the websocket captured for its own retirement.
        supervisors: list[Any] = []
        for ownership in owned:
            ownership.session._closing = True
            supervisor = ownership.session._supervisor
            supervisors.append(supervisor)
            if supervisor is not None:
                with suppress(BaseException):
                    supervisor.cancel()

        # RpcSession.close() clears its websocket slot after suppressing an
        # ordinary websocket.close() failure. Retain all connections captured
        # at the dial seam, including ones an earlier SDK cleanup forgot.
        retirements = [
            self._capture_retirement(ownership, supervisor)
            for ownership, supervisor in zip(owned, supervisors, strict=True)
        ]
        self._substrate = None
        self._archive_substrate = None
        primary: BaseException | None = None
        for raw, session, websockets, supervisor in reversed(retirements):
            failure: BaseException | None = None
            try:
                await raw.close()
            except BaseException as exc:
                failure = exc
            try:
                await self._retire_session(session, websockets, supervisor)
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
    def _capture_retirement(
        ownership: _RpcInterfaceOwnership, supervisor: Any
    ) -> tuple[SubstrateConnection, Any, tuple[tuple[Any, Any], ...], Any]:
        current = ownership.session._ws
        websockets = list(ownership.websockets)
        if current is not None and not any(websocket is current for websocket, _ in websockets):
            websockets.append((current, getattr(current, "transport", None)))
        return ownership.raw, ownership.session, tuple(websockets), supervisor

    @staticmethod
    async def _retire_session(
        session: Any,
        websockets: tuple[tuple[Any, Any], ...],
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
        for websocket, transport in reversed(websockets):
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
        if any(session._ws is websocket for websocket, _ in websockets):
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
