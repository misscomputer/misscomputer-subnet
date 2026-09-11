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
        owned, self._owned_interfaces = self._owned_interfaces, []
        self._substrate = None
        self._archive_substrate = None
        primary: BaseException | None = None
        for raw in reversed(owned):
            try:
                await raw.close()
            except BaseException as exc:
                # RpcSession.close() awaits its supervisor before closing the
                # websocket. Malformed inbound RPC data can kill that task
                # with an unexpected exception, which close() re-raises at
                # that await and therefore never performs socket shutdown.
                # Retire the pinned SDK session directly before forgetting
                # this application-owned interface.
                await self._retire_failed_session(raw, exc)
                if primary is None:
                    primary = exc
        if primary is not None:
            raise primary

    @staticmethod
    async def _retire_failed_session(raw: SubstrateConnection, primary: BaseException) -> None:
        session = raw._session
        supervisor = session._supervisor
        session._closing = True
        if supervisor is not None:
            supervisor.cancel()
            with suppress(BaseException):
                await supervisor
            session._supervisor = None
        try:
            await session.close()
        except BaseException:
            primary.add_note("rpc_transport_fallback_cleanup_failed")

    async def close(self) -> None:
        await drain_cleanup(self._close_owned(), name="bittensor-transport-cleanup")
