# SPDX-License-Identifier: AGPL-3.0-only
"""Bittensor v11 signed-HTTP miner neuron around the local Go miner agent."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import logging
import os
import time
from collections import defaultdict, deque
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote

import bittensor as bt
import httpx
import uvicorn
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from .auth import (
    BRIDGE_MAX_BODY,
    BridgeClient,
    HotkeySigningFacade,
    SQLiteNonceStore,
    bridge_headers,
    load_secret,
    sign_service_binding,
    verify_service_binding,
)
from .chain import (
    BittensorChain,
    ChainQuery,
    MetagraphSnapshot,
    MetagraphState,
    MockChain,
    load_mock_peers,
)
from .ingress import DEFAULT_BODY_IDLE_TIMEOUT, DEFAULT_BODY_TOTAL_TIMEOUT, read_request_body
from .logging import configure_logging
from .protocol import (
    SYNAPSE_VERSION,
    CapabilitiesResponse,
    CapabilitiesSynapse,
    DeactivateResponse,
    DeactivateSynapse,
    DeployResponse,
    DeploySynapse,
    LocalCapabilities,
    ServiceKeyBinding,
    StatusResponse,
    StatusSynapse,
)
from .tls import MinerTLSConfig, validate_miner_tls_files

LOGGER = logging.getLogger("misscomputer_subnet.miner")
RUNTIME_MAX_RESPONSE = 1 << 20
RUNTIME_READ_CHUNK = 64 << 10
MINER_INGRESS_CONCURRENCY = 64
MINER_KEEP_ALIVE_SECONDS = 5
MINER_H11_MAX_INCOMPLETE_EVENT = 64 << 10


@dataclass(frozen=True, slots=True)
class Caller:
    hotkey: str
    priority: float


class AuthorizationPolicy:
    def __init__(
        self,
        state: MetagraphState,
        *,
        min_validator_stake: float,
        max_requests_per_window: int = 120,
        window_seconds: float = 60.0,
    ) -> None:
        self.state = state
        self.min_validator_stake = min_validator_stake
        self.max_requests = max_requests_per_window
        self.window_seconds = window_seconds
        self.requests: dict[str, deque[float]] = defaultdict(deque)
        self._lock = asyncio.Lock()

    async def authorize(self, hotkey: str) -> Caller:
        snapshot = await self.state.get()
        neuron = snapshot.by_hotkey(hotkey)
        if neuron is None or not neuron.active:
            raise HTTPException(status_code=403, detail="caller is not active on this subnet")
        if not neuron.validator_permit:
            raise HTTPException(status_code=403, detail="caller lacks a validator permit")
        if neuron.tao_stake < self.min_validator_stake:
            raise HTTPException(status_code=403, detail="caller stake is below policy minimum")
        now = time.monotonic()
        async with self._lock:
            history = self.requests[hotkey]
            while history and history[0] <= now - self.window_seconds:
                history.popleft()
            if len(history) >= self.max_requests:
                raise HTTPException(status_code=429, detail="validator request rate exceeded")
            history.append(now)
        return Caller(hotkey=hotkey, priority=max(neuron.tao_stake, 0.0))


class PriorityGate:
    """A bounded worker gate that wakes highest-stake verified callers first."""

    def __init__(self, capacity: int) -> None:
        self.capacity = max(capacity, 1)
        self.active = 0
        self.sequence = 0
        self.waiters: list[tuple[float, int, asyncio.Future[None]]] = []
        self.lock = asyncio.Lock()

    @asynccontextmanager
    async def slot(self, priority: float) -> AsyncIterator[None]:
        future: asyncio.Future[None] | None = None
        async with self.lock:
            if self.active < self.capacity and not self.waiters:
                self.active += 1
            else:
                self.sequence += 1
                future = asyncio.get_running_loop().create_future()
                self.waiters.append((-priority, self.sequence, future))
                self.waiters.sort(key=lambda item: (item[0], item[1]))
        if future is not None:
            try:
                await asyncio.shield(future)
            except asyncio.CancelledError:
                async with self.lock:
                    if future in (item[2] for item in self.waiters):
                        self.waiters = [item for item in self.waiters if item[2] is not future]
                    else:
                        self._release_locked()
                raise
        try:
            yield
        finally:
            async with self.lock:
                self._release_locked()

    def _release_locked(self) -> None:
        while self.waiters:
            _, _, next_future = self.waiters.pop(0)
            if not next_future.done():
                next_future.set_result(None)
                return
        self.active -= 1


class MinerNeuron:
    def __init__(
        self,
        *,
        chain: ChainQuery,
        hotkey_signer: HotkeySigningFacade,
        network: str,
        netuid: int,
        configured_uid: int | None,
        bridge: BridgeClient,
        nonce_store: SQLiteNonceStore,
        min_validator_stake: float,
        sync_interval: float,
        max_concurrency: int,
        mock_http: bool,
        tls_config: MinerTLSConfig | None,
        capability_fault_file: str | None = None,
        body_idle_timeout: float = DEFAULT_BODY_IDLE_TIMEOUT,
        body_total_timeout: float = DEFAULT_BODY_TOTAL_TIMEOUT,
    ) -> None:
        if mock_http == (tls_config is not None):
            raise ValueError("miner must use either validated TLS or explicit mock HTTP")
        self.chain = chain
        self.hotkey_signer = hotkey_signer
        self.hotkey = hotkey_signer.hotkey
        self.network = network
        self.netuid = netuid
        self.uid = configured_uid
        self.bridge = bridge
        self.nonce_store = nonce_store
        self.state = MetagraphState()
        self.authorization = AuthorizationPolicy(
            self.state, min_validator_stake=min_validator_stake
        )
        self.gate = PriorityGate(max_concurrency)
        self.sync_interval = sync_interval
        self.mock_http = mock_http
        self.tls_config = tls_config
        self.body_idle_timeout = body_idle_timeout
        self.body_total_timeout = body_total_timeout
        # Mock-only deterministic fault injection: while this file exists the
        # capability handshake fails, but deploy/status/deactivate keep
        # serving. The mock subnet uses it to pin the exact window in which a
        # discovery refresh omits an assigned miner.
        self.capability_fault_file = capability_fault_file
        self.ready = asyncio.Event()
        self.stop = asyncio.Event()
        self.app = FastAPI(lifespan=self._lifespan)
        self.app.add_exception_handler(ValidationError, self._validation_error)
        self._routes()

    @staticmethod
    async def _validation_error(_: Request, exc: Exception) -> JSONResponse:
        assert isinstance(exc, ValidationError)
        return JSONResponse(
            status_code=400,
            content={"detail": "request does not match the Synapse contract"},
        )

    @asynccontextmanager
    async def _lifespan(self, _: FastAPI) -> AsyncIterator[None]:
        await self.chain.open()
        task = asyncio.create_task(self._sync_loop(), name="metagraph-sync")
        try:
            yield
        finally:
            self.stop.set()
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
            await self.chain.close()

    async def _sync_loop(self) -> None:
        while not self.stop.is_set():
            try:
                snapshot = await self.chain.sync()
                own = snapshot.by_hotkey(self.hotkey)
                if own is None or not own.active:
                    self.ready.clear()
                    LOGGER.error("miner hotkey is not registered", extra={"hotkey": self.hotkey})
                elif self.uid is not None and own.uid != self.uid:
                    self.ready.clear()
                    LOGGER.error(
                        "configured UID differs from metagraph",
                        extra={"hotkey": self.hotkey, "block": snapshot.block},
                    )
                else:
                    self.uid = own.uid
                    await self.state.set(snapshot)
                    self.ready.set()
                    LOGGER.info(
                        "metagraph synchronized",
                        extra={"hotkey": self.hotkey, "block": snapshot.block},
                    )
            except Exception:
                self.ready.clear()
                LOGGER.exception("metagraph synchronization failed")
            try:
                await asyncio.wait_for(self.stop.wait(), timeout=self.sync_interval)
            except TimeoutError:
                pass

    async def _body(self, request: Request) -> bytes:
        return await read_request_body(
            request,
            max_bytes=BRIDGE_MAX_BODY,
            idle_timeout=self.body_idle_timeout,
            total_timeout=self.body_total_timeout,
        )

    async def _authenticated(self, request: Request, body: bytes) -> Caller:
        if not self.ready.is_set():
            raise HTTPException(status_code=503, detail="metagraph is not ready")
        target = request.scope["raw_path"].decode()
        if request.scope["query_string"]:
            target += "?" + request.scope["query_string"].decode()
        try:
            verified = bt.http_auth.verify(
                request.headers,
                body,
                method=request.method,
                path=target,
                self_hotkey_ss58=self.hotkey,
                nonce_store=self.nonce_store,
            )
        except bt.http_auth.AuthError as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc
        return await self.authorization.authorize(str(verified.hotkey_ss58))

    async def _snapshot_for(self, current_block: int) -> MetagraphSnapshot:
        snapshot = await self.state.get()
        if current_block + 2 < snapshot.block or current_block > snapshot.block + 2:
            raise HTTPException(status_code=409, detail="request block is stale or from the future")
        return snapshot

    def _routes(self) -> None:
        @self.app.get("/healthz")
        async def health() -> Response:
            return Response(status_code=204 if self.ready.is_set() else 503)

        @self.app.post("/api/v1/capabilities", response_model=CapabilitiesResponse)
        async def capabilities(request: Request) -> CapabilitiesResponse:
            body = await self._body(request)
            if self.capability_fault_file:
                faulted = await asyncio.to_thread(Path(self.capability_fault_file).exists)
                if faulted:
                    raise HTTPException(status_code=503, detail="mock capability fault injected")
            caller = await self._authenticated(request, body)
            synapse = CapabilitiesSynapse.model_validate_json(body)
            if (
                synapse.caller_hotkey != caller.hotkey
                or synapse.network != self.network
                or synapse.netuid != self.netuid
            ):
                raise HTTPException(
                    status_code=403, detail="capability request identity differs from ingress"
                )
            snapshot = await self._snapshot_for(synapse.chain_block)
            local = await self.bridge.request(
                "GET", "/v1/capabilities", response_model=LocalCapabilities
            )
            assert isinstance(local, LocalCapabilities)
            if (
                local.network != self.network
                or local.netuid != self.netuid
                or local.miner_hotkey != self.hotkey
                or local.miner_uid != self.uid
                or local.transport != ("http" if self.mock_http else "https")
                or local.transport_certificate_sha256
                != (None if self.tls_config is None else self.tls_config.fingerprint_sha256)
            ):
                raise HTTPException(status_code=500, detail="local Go identity is misconfigured")
            binding = sign_service_binding(
                ServiceKeyBinding(
                    role="miner",
                    transport="http" if self.mock_http else "https",
                    transport_certificate_sha256=(
                        None if self.tls_config is None else self.tls_config.fingerprint_sha256
                    ),
                    network=self.network,
                    netuid=self.netuid,
                    hotkey=self.hotkey,
                    uid=self.uid,
                    service_public_key=local.service_public_key,
                    generation=snapshot.block + 1,
                    valid_from_block=snapshot.block,
                    expires_at_block=snapshot.block + max(snapshot.tempo * 2, 12),
                    challenge=synapse.challenge,
                ),
                self.hotkey_signer,
            )
            return CapabilitiesResponse(
                request_id=synapse.request_id,
                miner_hotkey=self.hotkey,
                miner_uid=self.uid,
                features=local.features,
                max_body_bytes=local.max_body_bytes,
                service_binding=binding,
            )

        @self.app.post("/api/v1/deploy", response_model=DeployResponse)
        async def deploy(request: Request) -> DeployResponse:
            body = await self._body(request)
            caller = await self._authenticated(request, body)
            synapse = DeploySynapse.model_validate_json(body)
            if synapse.caller_hotkey != caller.hotkey:
                raise HTTPException(
                    status_code=403, detail="body caller differs from btauth caller"
                )
            snapshot = await self._snapshot_for(synapse.current_block)
            expected_challenge = "validator-service:" + synapse.validator_binding.service_public_key
            try:
                verify_service_binding(
                    synapse.validator_binding,
                    expected_hotkey=caller.hotkey,
                    expected_role="validator",
                    expected_network=self.network,
                    expected_netuid=self.netuid,
                    expected_challenge=expected_challenge,
                    expected_transport="local",
                    expected_transport_certificate_sha256=None,
                    # The signed request block is authoritative after
                    # _snapshot_for has bounded it to the local metagraph by
                    # two blocks. A miner one block behind must not reject a
                    # binding whose valid_from_block is the validator's block.
                    current_block=synapse.current_block,
                )
            except ValueError as exc:
                raise HTTPException(status_code=403, detail=str(exc)) from exc
            binding = synapse.ticket.subnet
            validator = snapshot.by_hotkey(caller.hotkey)
            if (
                validator is None
                or synapse.validator_binding.uid != validator.uid
                or binding.validator_hotkey != caller.hotkey
                or binding.miner_hotkey != self.hotkey
                or binding.miner_uid != self.uid
                or binding.network != self.network
                or binding.netuid != self.netuid
                or binding.miner_transport != ("http" if self.mock_http else "https")
                or binding.miner_tls_certificate_sha256
                != (None if self.tls_config is None else self.tls_config.fingerprint_sha256)
                or binding.validator_service_public_key
                != synapse.validator_binding.service_public_key
                or binding.epoch != binding.chain_block // max(snapshot.tempo, 1)
                or binding.chain_block > snapshot.block + 2
                or snapshot.block >= binding.expires_at_block
            ):
                raise HTTPException(status_code=403, detail="ticket Bittensor identity mismatch")
            local_request = {
                "protocol": SYNAPSE_VERSION,
                "request_id": synapse.request_id,
                # The btauth-signed validator block is authoritative after
                # _snapshot_for bounded it to this miner's view. Forwarding
                # the older local block would incorrectly reject a valid
                # service binding when this miner is one block behind.
                "current_block": synapse.current_block,
                "caller_hotkey": caller.hotkey,
                "binding_verified": True,
                "validator_binding": synapse.validator_binding.model_dump(mode="json"),
                "ticket": synapse.ticket.model_dump(mode="json"),
            }
            async with self.gate.slot(caller.priority):
                result = await self.bridge.request(
                    "POST",
                    "/v1/assignments",
                    value=local_request,
                    response_model=DeployResponse,
                )
            assert isinstance(result, DeployResponse)
            return result

        @self.app.post("/api/v1/status", response_model=StatusResponse)
        async def status(request: Request) -> StatusResponse:
            body = await self._body(request)
            caller = await self._authenticated(request, body)
            synapse = StatusSynapse.model_validate_json(body)
            if synapse.caller_hotkey != caller.hotkey:
                raise HTTPException(status_code=403, detail="caller mismatch")
            snapshot = await self._snapshot_for(synapse.current_block)
            local = synapse.model_copy(update={"current_block": snapshot.block})
            result = await self.bridge.request(
                "POST", "/v1/status", value=local, response_model=StatusResponse
            )
            assert isinstance(result, StatusResponse)
            return result

        @self.app.post("/api/v1/deactivate", response_model=DeactivateResponse)
        async def deactivate(request: Request) -> DeactivateResponse:
            body = await self._body(request)
            caller = await self._authenticated(request, body)
            synapse = DeactivateSynapse.model_validate_json(body)
            if synapse.caller_hotkey != caller.hotkey:
                raise HTTPException(status_code=403, detail="caller mismatch")
            snapshot = await self._snapshot_for(synapse.current_block)
            local = synapse.model_copy(update={"current_block": snapshot.block})
            result = await self.bridge.request(
                "POST", "/v1/deactivate", value=local, response_model=DeactivateResponse
            )
            assert isinstance(result, DeactivateResponse)
            return result

        @self.app.api_route(
            "/runtime/{endpoint_id}/{runtime_path:path}",
            methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"],
        )
        async def runtime_proxy(endpoint_id: str, runtime_path: str, request: Request) -> Response:
            body = await self._body(request)
            escaped_endpoint = quote(endpoint_id, safe="-._~")
            escaped_path = quote(runtime_path, safe="/-._~")
            target = f"/v1/runtime/{escaped_endpoint}/{escaped_path}"
            headers = bridge_headers(
                self.bridge.secret,
                method=request.method,
                target=target,
                body=body,
            )
            # Never let HTTPX transparently inflate an attacker-controlled
            # runtime response before the public-path size bound is applied.
            headers["Accept-Encoding"] = "identity"
            async with httpx.AsyncClient(
                base_url=self.bridge.base_url,
                timeout=self.bridge.timeout,
                transport=self.bridge.transport,
                follow_redirects=False,
                trust_env=False,
            ) as client:
                async with client.stream(
                    request.method, target, content=body, headers=headers
                ) as upstream:
                    content_encoding = upstream.headers.get("content-encoding", "").strip().lower()
                    if content_encoding and content_encoding != "identity":
                        raise HTTPException(
                            status_code=502,
                            detail="encoded runtime responses are not supported",
                        )
                    declared_length = upstream.headers.get("content-length")
                    if request.method != "HEAD" and declared_length is not None:
                        try:
                            oversized = int(declared_length) > RUNTIME_MAX_RESPONSE
                        except ValueError:
                            oversized = False
                        if oversized:
                            raise HTTPException(
                                status_code=502,
                                detail="runtime response exceeds one MiB",
                            )
                    chunks: list[bytes] = []
                    response_size = 0
                    async for chunk in upstream.aiter_raw(chunk_size=RUNTIME_READ_CHUNK):
                        response_size += len(chunk)
                        if response_size > RUNTIME_MAX_RESPONSE:
                            raise HTTPException(
                                status_code=502,
                                detail="runtime response exceeds one MiB",
                            )
                        chunks.append(chunk)
                    content = b"".join(chunks)
                    status_code = upstream.status_code
                    safe_headers = {
                        key: value
                        for key, value in upstream.headers.items()
                        if key.lower() in {"content-type", "cache-control", "x-build-id"}
                    }
            return Response(
                content=content,
                status_code=status_code,
                headers=safe_headers,
            )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--netuid", type=int, required=True)
    parser.add_argument("--subtensor-network", default=os.getenv("BT_NETWORK", "finney"))
    parser.add_argument("--wallet-name", default=os.getenv("BT_WALLET", "default"))
    parser.add_argument("--wallet-hotkey", default=os.getenv("BT_WALLET_HOTKEY", "default"))
    parser.add_argument(
        "--wallet-path", default=os.getenv("BT_WALLET_PATH", "~/.bittensor/wallets")
    )
    parser.add_argument("--uid", type=int)
    parser.add_argument("--axon-host", default="0.0.0.0")  # noqa: S104 - public neuron ingress
    parser.add_argument("--axon-port", type=int, default=8091)
    parser.add_argument("--tls-cert-file")
    parser.add_argument("--tls-key-file")
    parser.add_argument(
        "--allow-insecure-mock-http",
        action="store_true",
        help="serve HTTP only for an explicitly configured mock chain",
    )
    parser.add_argument("--go-agent-url", default="http://127.0.0.1:9101")
    parser.add_argument("--bridge-secret-file", required=True)
    parser.add_argument("--state-db", required=True)
    parser.add_argument("--min-validator-stake", type=float, default=1_000.0)
    parser.add_argument("--sync-interval", type=float, default=12.0)
    parser.add_argument("--max-concurrency", type=int, default=4)
    parser.add_argument("--mock-uri")
    parser.add_argument("--mock-peers")
    parser.add_argument("--mock-capability-fault-file")
    parser.add_argument("--log-level", default="INFO")
    return parser


def make_chain(args: argparse.Namespace) -> tuple[ChainQuery, HotkeySigningFacade]:
    if args.mock_uri:
        if not args.mock_peers:
            raise ValueError("--mock-peers is required with --mock-uri")
        chain = MockChain(
            network=args.subtensor_network,
            netuid=args.netuid,
            own_uri=args.mock_uri,
            peers=load_mock_peers(args.mock_peers),
        )
        return chain, chain.hotkey_signer
    query = BittensorChain(
        network=args.subtensor_network,
        netuid=args.netuid,
    )
    signer = HotkeySigningFacade(
        bt.Wallet(
            args.wallet_name,
            args.wallet_hotkey,
            path=os.path.expanduser(args.wallet_path),
        )
    )
    return query, signer


def main() -> None:
    args = build_parser().parse_args()
    if args.mock_capability_fault_file and not args.mock_uri:
        raise SystemExit("--mock-capability-fault-file is a mock-only flag and requires --mock-uri")
    if args.allow_insecure_mock_http:
        if not args.mock_uri:
            raise SystemExit("--allow-insecure-mock-http requires --mock-uri")
        if args.tls_cert_file or args.tls_key_file:
            raise SystemExit("mock HTTP cannot be combined with TLS certificate options")
        tls_config = None
    else:
        if not args.tls_cert_file or not args.tls_key_file:
            raise SystemExit("live miner startup requires --tls-cert-file and --tls-key-file")
        try:
            tls_config = validate_miner_tls_files(args.tls_cert_file, args.tls_key_file)
        except ValueError as exc:
            raise SystemExit(str(exc)) from exc
    configure_logging(args.log_level)
    secret = load_secret(args.bridge_secret_file)
    chain, hotkey_signer = make_chain(args)
    neuron = MinerNeuron(
        chain=chain,
        hotkey_signer=hotkey_signer,
        network=args.subtensor_network,
        netuid=args.netuid,
        configured_uid=args.uid,
        bridge=BridgeClient(args.go_agent_url, secret, timeout=120.0, retries=0),
        nonce_store=SQLiteNonceStore(args.state_db),
        min_validator_stake=args.min_validator_stake,
        sync_interval=args.sync_interval,
        max_concurrency=args.max_concurrency,
        mock_http=args.allow_insecure_mock_http,
        tls_config=tls_config,
        capability_fault_file=args.mock_capability_fault_file,
    )
    if tls_config is None:
        uvicorn.run(
            neuron.app,
            host=args.axon_host,
            port=args.axon_port,
            log_config=None,
            limit_concurrency=MINER_INGRESS_CONCURRENCY,
            timeout_keep_alive=MINER_KEEP_ALIVE_SECONDS,
            h11_max_incomplete_event_size=MINER_H11_MAX_INCOMPLETE_EVENT,
        )
        return
    # Load the validated bytes into an in-memory SSLContext before serving.
    # Uvicorn's public Config API still receives the operator paths so it
    # enables TLS protocol handling, but the context used by the server is the
    # exact already-validated material and is not affected by a later path swap.
    config = uvicorn.Config(
        neuron.app,
        host=args.axon_host,
        port=args.axon_port,
        log_config=None,
        ssl_certfile=tls_config.cert_file,
        ssl_keyfile=tls_config.key_file,
        limit_concurrency=MINER_INGRESS_CONCURRENCY,
        timeout_keep_alive=MINER_KEEP_ALIVE_SECONDS,
        h11_max_incomplete_event_size=MINER_H11_MAX_INCOMPLETE_EVENT,
    )
    config.load()
    config.ssl = tls_config.server_context
    uvicorn.Server(config).run()


if __name__ == "__main__":
    main()
