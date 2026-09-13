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
from collections.abc import Awaitable, Callable
from contextlib import suppress
from dataclasses import dataclass
from typing import Any, TypeVar

from bittensor._substrate import RpcSubstrate
from bittensor._transport.interface import SubstrateConnection
from bittensor.settings import (
    default_archive_endpoints,
    default_fallback_endpoints,
    resolve_endpoint,
)

from .async_lifecycle import drain_cleanup

T = TypeVar("T")


@dataclass(slots=True)
class _RpcInterfaceOwnership:
    raw: SubstrateConnection
    session: Any
    websockets: list[tuple[Any, Any]]
    operation: _RpcOperationOwnership | None
    retiring: bool = False


@dataclass(slots=True)
class _RpcOperationOwnership:
    task: asyncio.Task[Any]
    completion: asyncio.Future[None]
    depth: int = 1


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
        self._operations: dict[asyncio.Task[Any], _RpcOperationOwnership] = {}
        self._owned_interfaces: list[_RpcInterfaceOwnership] = []
        self._retiring = False

    def _interface(self, endpoint: str, fallbacks: list[str]) -> SubstrateConnection:
        if self._retiring and not self._current_operation_admitted():
            raise ConnectionError("RPC transport is closing")
        raw = super()._interface(endpoint, fallbacks)
        session = raw._session
        connect = session._connect
        websockets: list[tuple[Any, Any]] = []
        current = asyncio.current_task()
        operation = self._operations.get(current) if current is not None else None
        ownership = _RpcInterfaceOwnership(
            raw=raw,
            session=session,
            websockets=websockets,
            operation=operation,
        )

        async def connect_owned(url: str) -> Any:
            if self._ownership_retiring(ownership) or (
                self._retiring and not self._interface_operation_admitted(ownership)
            ):
                raise ConnectionError("RPC transport is closing")
            # Closed transports no longer need fallback ownership; retain any
            # ambiguous entry so a failed SDK reconnect close is never lost.
            websockets[:] = [
                (owned_websocket, transport)
                for owned_websocket, transport in websockets
                if not self._connection_retired(owned_websocket, transport)
            ]
            websocket = await connect(url)
            if self._ownership_retiring(ownership) or (
                self._retiring and not self._interface_operation_admitted(ownership)
            ):
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

    def _current_operation_admitted(self) -> bool:
        current = asyncio.current_task()
        return current is not None and current in self._operations

    def _interface_operation_admitted(self, ownership: _RpcInterfaceOwnership) -> bool:
        operation = ownership.operation
        return operation is not None and self._operations.get(operation.task) is operation

    async def _admit_operation(self) -> _RpcOperationOwnership:
        current = asyncio.current_task()
        if current is None:
            raise RuntimeError("RPC operation has no owning task")
        async with self._lifecycle_lock:
            ownership = self._operations.get(current)
            if ownership is not None:
                ownership.depth += 1
                return ownership
            if self._retiring or self._close_task is not None:
                raise ConnectionError("RPC transport is closing")
            ownership = _RpcOperationOwnership(
                task=current,
                completion=asyncio.get_running_loop().create_future(),
            )
            self._operations[current] = ownership
            return ownership

    async def _release_operation(self, ownership: _RpcOperationOwnership) -> None:
        async with self._lifecycle_lock:
            current = self._operations.get(ownership.task)
            if current is not ownership:
                return
            ownership.depth -= 1
            if ownership.depth == 0:
                del self._operations[ownership.task]
                if not ownership.completion.done():
                    ownership.completion.set_result(None)

    async def _drain_operations(self, caller: asyncio.Task[Any] | None) -> None:
        """Wait to a fixed point for every admitted operation except our caller."""

        while True:
            async with self._lifecycle_lock:
                pending = tuple(
                    ownership.completion
                    for ownership in self._operations.values()
                    if ownership.task is not caller and not ownership.completion.done()
                )
            if not pending:
                return
            await asyncio.gather(
                *(asyncio.shield(completion) for completion in pending),
                return_exceptions=True,
            )

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

    async def _read(self, op: Callable[[SubstrateConnection], Awaitable[T]]) -> T:
        ownership = await self._admit_operation()
        try:
            return await super()._read(op)
        finally:
            await self._release_operation(ownership)

    async def _archive(self) -> SubstrateConnection | None:
        ownership = await self._admit_operation()
        try:
            try:
                return await super()._archive()
            except BaseException as primary:
                try:
                    await self.close()
                except BaseException:
                    primary.add_note("rpc_archive_cleanup_failed")
                raise
        finally:
            await self._release_operation(ownership)

    async def _close_owned(self, caller: asyncio.Task[Any] | None) -> None:
        self._retiring = True
        await self._drain_operations(caller)
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
        caller = asyncio.current_task()
        await drain_cleanup(
            self._request_close(caller),
            name="bittensor-transport-cleanup",
        )

    async def _request_close(self, caller: asyncio.Task[Any] | None) -> None:
        async with self._lifecycle_lock:
            closing = self._close_task
            created = closing is None
            if closing is None:
                # Publish one immutable retirement before ownership is removed.
                # Initialization, archive, and owner-close paths all join it.
                self._retiring = True
                closing = asyncio.create_task(
                    self._close_owned(caller),
                    name="bittensor-transport-retirement",
                )
                self._close_task = closing
            caller_is_operation = caller is not None and caller in self._operations
        if caller_is_operation and not created:
            # An operation that encounters a failure during an externally
            # initiated close must unwind and release its completion token;
            # joining that close here would make the close wait on itself.
            return
        try:
            await closing
        finally:
            async with self._lifecycle_lock:
                if self._close_task is closing and closing.done():
                    self._close_task = None
