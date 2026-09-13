# SPDX-License-Identifier: AGPL-3.0-only
"""Own Bittensor 11.1.0 RPC transports before their awaited initialization.

The pinned SDK's RpcSubstrate publishes primary and lazy archive interfaces
only after initialize(). Its narrow exception cleanup misses cancellation and
malformed metadata. Keep an independent ownership list at the synchronous
interface factory seam; this also makes failure of one close unable to strand
another transport. No SDK files are patched and no write/signing API is added.
"""

from __future__ import annotations

import asyncio
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
    retiring: bool = False


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
        self._close_task: asyncio.Task[None] | None = None
        self._lifecycle_lock = asyncio.Lock()
        self._owned_interfaces: list[_RpcInterfaceOwnership] = []
        self._retiring = False

    def _interface(self, endpoint: str, fallbacks: list[str]) -> SubstrateConnection:
        if self._retiring:
            raise ConnectionError("RPC transport is closing")
        raw = super()._interface(endpoint, fallbacks)
        session = raw._session
        connect = session._connect
        websockets: list[tuple[Any, Any]] = []
        ownership = _RpcInterfaceOwnership(raw=raw, session=session, websockets=websockets)

        async def connect_owned(url: str) -> Any:
            if self._ownership_retiring(ownership):
                raise ConnectionError("RPC transport is closing")
            # Closed transports no longer need fallback ownership; retain any
            # ambiguous entry so a failed SDK reconnect close is never lost.
            websockets[:] = [
                (owned_websocket, transport)
                for owned_websocket, transport in websockets
                if not self._connection_retired(owned_websocket, transport)
            ]
            websocket = await connect(url)
            if self._ownership_retiring(ownership):
                # Shutdown may have taken its immutable connection snapshot
                # while this dial was awaiting. Retire the late acquisition at
                # the publication seam instead of returning it to RpcSession.
                await self._retire_late_connection(websocket, getattr(websocket, "transport", None))
                raise ConnectionError("RPC transport is closing")
            # No await is allowed between acquisition and retention: the SDK
            # may immediately initiate cleanup when later initialization fails.
            websockets.append((websocket, getattr(websocket, "transport", None)))
            return websocket

        session._connect = connect_owned
        self._owned_interfaces.append(ownership)
        return raw

    @staticmethod
    def _ownership_retiring(ownership: _RpcInterfaceOwnership) -> bool:
        # Read through a call so type analysis does not treat the value as
        # immutable across the connection await above.
        return ownership.retiring

    @staticmethod
    async def _retire_late_connection(websocket: Any, transport: Any) -> None:
        """Best-effort fixed-point cleanup for a dial completed during close."""

        with suppress(BaseException):
            await websocket.close()
        abort = getattr(transport, "abort", None)
        if callable(abort):
            with suppress(BaseException):
                abort()
        wait_closed = getattr(websocket, "wait_closed", None)
        if callable(wait_closed):
            with suppress(BaseException):
                await wait_closed()

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
        async with self._lifecycle_lock:
            if self._retiring or self._close_task is not None:
                raise ConnectionError("RPC transport is closing")
        try:
            await super().connect()
            async with self._lifecycle_lock:
                if self._retiring or self._close_task is not None:
                    raise ConnectionError("RPC transport is closing")
        except BaseException as primary:
            try:
                await self.close()
            except BaseException:
                primary.add_note("rpc_initialization_cleanup_failed")
            raise

    async def _archive(self) -> SubstrateConnection | None:
        async with self._lifecycle_lock:
            if self._retiring or self._close_task is not None:
                raise ConnectionError("RPC transport is closing")
        try:
            archive = await super()._archive()
            async with self._lifecycle_lock:
                if self._retiring or self._close_task is not None:
                    raise ConnectionError("RPC transport is closing")
            return archive
        except BaseException as primary:
            try:
                await self.close()
            except BaseException:
                primary.add_note("rpc_archive_cleanup_failed")
            raise

    async def _close_owned(self) -> None:
        self._retiring = True
        owned = self._owned_interfaces
        self._owned_interfaces = []

        # Freeze every session before the first await. Otherwise a supervisor
        # later in the list can reconnect while an earlier interface is being
        # closed and replace the websocket captured for its own retirement.
        supervisors: list[Any] = []
        for ownership in owned:
            ownership.retiring = True
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
        await drain_cleanup(self._request_close(), name="bittensor-transport-cleanup")

    async def _request_close(self) -> None:
        async with self._lifecycle_lock:
            closing = self._close_task
            if closing is None:
                # Publish one immutable retirement before ownership is removed.
                # Initialization, archive, and owner-close paths all join it.
                self._retiring = True
                closing = asyncio.create_task(
                    self._close_owned(),
                    name="bittensor-transport-retirement",
                )
                self._close_task = closing
        try:
            await closing
        finally:
            async with self._lifecycle_lock:
                if self._close_task is closing and closing.done():
                    self._close_task = None
