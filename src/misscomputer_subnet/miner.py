# SPDX-License-Identifier: AGPL-3.0-only
"""Bittensor v11 signed-HTTP miner neuron around the local Go miner agent."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import logging
import math
import os
import re
import time
from collections import defaultdict, deque
from collections.abc import AsyncIterator, Collection, Iterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path

import bittensor as bt
import httpx
import uvicorn
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from . import organic_contracts, sandbox_transport, static_contracts
from .auth import (
    BRIDGE_MAX_BODY,
    BridgeClient,
    BridgeError,
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
from .operator_policy import configured_operator_hotkeys, validate_operator_hotkeys
from .organic_contracts import SYNAPSE_VERSION as ORGANIC_SYNAPSE_VERSION
from .organic_contracts import (
    DeployResponseV3,
    DeploySynapseV3,
    StatusResponseV3,
    parse_document,
)
from .protocol import (
    CapabilitiesResponse,
    CapabilitiesSynapse,
    DeactivateResponse,
    DeactivateSynapse,
    LocalCapabilities,
    ServiceKeyBinding,
    StatusSynapse,
    SubnetBinding,
)
from .sandbox_transport import (
    LocalSandboxOpsRequestV1,
    LocalSandboxRequestV1,
    SandboxDocumentHeader,
    SandboxOpsResponseV1,
    SandboxOpsSynapseV1,
    SandboxResponseV1,
    SandboxSynapseV1,
)
from .static_contracts import (
    LocalStaticAssignRequestV1,
    StaticDeployResponseV1,
    StaticDeploySynapseV1,
    StaticStatusResponseV1,
    StaticStatusSynapseV1,
)
from .tls import MinerTLSConfig, validate_miner_tls_files

LOGGER = logging.getLogger("misscomputer_subnet.miner")
# Miner-hop response bound: at least the public edge's 16 MiB limit (§8).
RUNTIME_MAX_RESPONSE = 16 << 20
RUNTIME_READ_CHUNK = 64 << 10
RUNTIME_METHODS = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
# The edge -> miner request signature (§6.9). The Go agent is the only
# verifier; this hop forwards the header verbatim and only rejects requests
# that cannot possibly be authorized.
EDGE_AUTHORIZATION_HEADER = organic_contracts.EDGE_AUTHORIZATION_HEADER.lower()
# A validator probe authorization the edge already verified; the Go agent
# binds attestation v2 to it and strips it before the workload.
ORGANIC_PROBE_AUTHORIZATION_HEADER = organic_contracts.ORGANIC_PROBE_AUTHORIZATION_HEADER.lower()
# The miner-probe-attestation v2 the Go agent signed for an authorized probe.
PROBE_ATTESTATION_HEADER = organic_contracts.PROBE_ATTESTATION_HEADER.lower()
AGENT_ENDPOINT_UNAVAILABLE_HEADER = organic_contracts.AGENT_ENDPOINT_UNAVAILABLE_HEADER.lower()
RUNTIME_ENDPOINT_ID = re.compile(r"[A-Za-z0-9-]{1,256}")
# Request and response headers that never cross a proxy hop. Content-Length
# is recomputed from the exact buffered body.
HOP_BY_HOP_HEADERS = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-connection",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "content-length",
        "host",
    }
)
# The only X-Miss-* request headers forwarded to the Go agent.
RUNTIME_FORWARDED_MISS_HEADERS = frozenset(
    {EDGE_AUTHORIZATION_HEADER, ORGANIC_PROBE_AUTHORIZATION_HEADER}
)
MINER_INGRESS_CONCURRENCY = 64
MINER_KEEP_ALIVE_SECONDS = 5
MINER_H11_MAX_INCOMPLETE_EVENT = 64 << 10

# Sandbox-ops admission at this hop (docs/sandbox-ops-admission.md). Tenant
# ops reach the miner from the same validator hotkey as lease renewals and
# the capability handshake. Every request keeps the same authentication and
# identity checks; ops differ only in where their rate is counted and in
# never waiting for a worker.
#
# The route a handler serves fixes its rate class. On the ops route only, an
# authenticated, well-formed exec_cancel without payload from the body's own
# caller is counted in a separate cancel reserve; every other op request,
# malformed or not, is an ordinary op. No request member names a class, a
# bucket or a bound, and every class is counted per validator hotkey.
RATE_CLASS_DEFAULT = "default"
RATE_CLASS_SANDBOX_OPS = "sandbox-ops"
RATE_CLASS_SANDBOX_OPS_CANCEL = "sandbox-ops-cancel"
# Ops are counted in their own window and never use the shared one. A sync
# exec polls two exec_read ops per pass with a 500 ms pause, so at most
# 4 ops/s per exec; 30/s on average sustains several polled execs. These are
# candidate defaults pending lab measurement, not adopted throughput.
SANDBOX_OPS_MAX_REQUESTS_PER_WINDOW = 300
SANDBOX_OPS_WINDOW_SECONDS = 10.0
# Cancels in the same window length, never spent by ordinary ops and never
# spending theirs: enough to cancel a full agent in-flight bound (64) once per
# window, at most 6.4 extra ops/s. A cancel flood is refused like an ops
# flood. Candidate default pending lab measurement.
SANDBOX_OPS_CANCEL_MAX_REQUESTS_PER_WINDOW = 64
# Ops forwarded to the agent at once. Beyond it an op is refused at once:
# the agent refuses a full in-flight bound immediately, so a queue here would
# only add stale work and hold ingress.
SANDBOX_OPS_CONCURRENCY = 32
# Further admissions for exec_cancel only, so a full ops capacity never
# keeps a tenant from stopping an exec.
SANDBOX_OPS_CANCEL_HEADROOM = 4
# Ingress tasks that ops and the assignment gate together never take:
# lease lifecycle waiting for the gate, capability handshakes, status,
# deactivation and the runtime proxy.
SANDBOX_OPS_INGRESS_RESERVE = 16
# Definitive refusals before any agent contact (HTTP 429, nothing forwarded).
SANDBOX_OPS_RATE_EXCEEDED = "sandbox_ops_rate_exceeded"
SANDBOX_OPS_CAPACITY_EXHAUSTED = "sandbox_ops_capacity_exhausted"
SANDBOX_OPS_CAPACITY_RETRY_AFTER = 1
# An agent answer that arrived after dispatch but does not validate. The op or
# document may already have run, so the tenant sees an upstream failure (>= 500),
# never a definitive 400 or refusal (R23-PYGAP-01).
SANDBOX_AGENT_ANSWER_INVALID = "sandbox_agent_answer_invalid"


def _connection_tokens(headers: list[tuple[bytes, bytes]]) -> set[str]:
    tokens: set[str] = set()
    for name, value in headers:
        if name.lower() == b"connection":
            tokens.update(
                token.strip().lower()
                for token in value.decode("latin-1").split(",")
                if token.strip()
            )
    return tokens


def runtime_request_headers(raw: list[tuple[bytes, bytes]]) -> list[tuple[bytes, bytes]]:
    """End-to-end request headers forwarded byte-for-byte to the Go agent."""

    dropped = _connection_tokens(raw)
    forwarded: list[tuple[bytes, bytes]] = []
    for name_bytes, value_bytes in raw:
        name = name_bytes.decode("latin-1").lower()
        if name in HOP_BY_HOP_HEADERS or name in dropped:
            continue
        if name.startswith("x-miss-") and name not in RUNTIME_FORWARDED_MISS_HEADERS:
            continue
        forwarded.append((name.encode("latin-1"), value_bytes))
    return forwarded


def runtime_response_headers(
    raw: list[tuple[bytes, bytes]], *, status_code: int
) -> list[tuple[bytes, bytes]]:
    """End-to-end response headers, repeated values preserved (Set-Cookie)."""

    dropped = _connection_tokens(raw)
    endpoint_state = [
        value
        for name, value in raw
        if name.lower().decode("latin-1") == AGENT_ENDPOINT_UNAVAILABLE_HEADER
    ]
    allow_endpoint_unavailable = status_code == 404 and endpoint_state == [
        organic_contracts.AGENT_ENDPOINT_UNAVAILABLE_VALUE.encode()
    ]
    kept: list[tuple[bytes, bytes]] = []
    for name, value in raw:
        lowered = name.lower().decode("latin-1")
        if lowered in HOP_BY_HOP_HEADERS or lowered in dropped:
            continue
        # Only the agent-signed probe attestation and the exact inactive
        # endpoint signal may cross this hop. The Go agent strips workload
        # copies of both reserved headers before proxying an application.
        if (
            lowered.startswith("x-miss-")
            and lowered != PROBE_ATTESTATION_HEADER
            and not (lowered == AGENT_ENDPOINT_UNAVAILABLE_HEADER and allow_endpoint_unavailable)
        ):
            continue
        kept.append((lowered.encode("latin-1"), value))
    return kept


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
        operator_hotkeys: Collection[str] = (),
        max_requests_per_window: int = 120,
        window_seconds: float = 60.0,
    ) -> None:
        self.operator_hotkeys = validate_operator_hotkeys(operator_hotkeys)
        self.state = state
        self.min_validator_stake = min_validator_stake
        self.max_requests = max_requests_per_window
        self.window_seconds = window_seconds
        self.requests: dict[str, deque[float]] = defaultdict(deque)
        self.ops_requests: dict[str, deque[float]] = defaultdict(deque)
        self.cancel_requests: dict[str, deque[float]] = defaultdict(deque)
        self._lock = asyncio.Lock()

    async def authorize(self, hotkey: str, *, rate_class: str = RATE_CLASS_DEFAULT) -> Caller:
        caller = await self.identify(hotkey)
        await self.admit(hotkey, rate_class)
        return caller

    async def identify(self, hotkey: str) -> Caller:
        """The operator, registration, permit and stake checks every request
        passes before it is counted in any rate window."""

        if hotkey not in self.operator_hotkeys:
            raise HTTPException(status_code=403, detail="caller is not a configured operator")
        snapshot = await self.state.get()
        # Metagraph active tracks recent weight updates, not registration.
        matches = tuple(neuron for neuron in snapshot.neurons if neuron.hotkey == hotkey)
        if len(matches) != 1:
            raise HTTPException(
                status_code=403, detail="caller is not uniquely registered on this subnet"
            )
        neuron = matches[0]
        if not neuron.validator_permit:
            raise HTTPException(status_code=403, detail="caller lacks a validator permit")
        if neuron.tao_stake < self.min_validator_stake:
            raise HTTPException(status_code=403, detail="caller stake is below policy minimum")
        return Caller(hotkey=hotkey, priority=max(neuron.tao_stake, 0.0))

    async def admit(self, hotkey: str, rate_class: str) -> None:
        """Count one identified request in its class's window, or refuse it."""

        now = time.monotonic()
        if rate_class == RATE_CLASS_SANDBOX_OPS:
            await self._admit_op(
                self.ops_requests, SANDBOX_OPS_MAX_REQUESTS_PER_WINDOW, hotkey, now
            )
            return
        if rate_class == RATE_CLASS_SANDBOX_OPS_CANCEL:
            await self._admit_op(
                self.cancel_requests, SANDBOX_OPS_CANCEL_MAX_REQUESTS_PER_WINDOW, hotkey, now
            )
            return
        if rate_class != RATE_CLASS_DEFAULT:
            raise ValueError(f"unknown rate class {rate_class!r}")
        async with self._lock:
            history = self.requests[hotkey]
            while history and history[0] <= now - self.window_seconds:
                history.popleft()
            if len(history) >= self.max_requests:
                raise HTTPException(status_code=429, detail="validator request rate exceeded")
            history.append(now)

    async def _admit_op(
        self, windows: dict[str, deque[float]], bound: int, hotkey: str, now: float
    ) -> None:
        """Count one op in the caller's window of its op class; a full window
        is a definitive refusal before any agent contact."""

        async with self._lock:
            history = windows[hotkey]
            while history and history[0] <= now - SANDBOX_OPS_WINDOW_SECONDS:
                history.popleft()
            if len(history) >= bound:
                retry_after = max(1, math.ceil(history[0] + SANDBOX_OPS_WINDOW_SECONDS - now))
                raise HTTPException(
                    status_code=429,
                    detail=SANDBOX_OPS_RATE_EXCEEDED,
                    headers={"Retry-After": str(retry_after)},
                )
            history.append(now)


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


class OpsAdmission:
    """Admission of sandbox ops to the agent that never waits.

    Ops do not queue, so no op waits behind another and nothing waits behind
    an op. An exec_cancel may also use a small headroom beyond the capacity.
    Admission is decided without an await, so it needs no lock on one loop.
    """

    def __init__(self, capacity: int, cancel_headroom: int) -> None:
        self.capacity = capacity
        self.cancel_headroom = cancel_headroom
        self.active = 0

    @contextlib.contextmanager
    def slot(self, *, cancel: bool) -> Iterator[bool]:
        limit = self.capacity + (self.cancel_headroom if cancel else 0)
        if self.active >= limit:
            yield False
            return
        self.active += 1
        try:
            yield True
        finally:
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
        operator_hotkeys: Collection[str] = (),
        capability_fault_file: str | None = None,
        body_idle_timeout: float = DEFAULT_BODY_IDLE_TIMEOUT,
        body_total_timeout: float = DEFAULT_BODY_TOTAL_TIMEOUT,
        sandbox_leases: bool = False,
        sandbox_reservation_replay: bool = False,
        sandbox_ops: bool = False,
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
            self.state,
            min_validator_stake=min_validator_stake,
            operator_hotkeys=operator_hotkeys,
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
        # Default off: without it no /api/v1/sandbox/* route exists.
        if sandbox_reservation_replay and not sandbox_leases:
            raise ValueError("sandbox reservation replay requires sandbox leases")
        if sandbox_ops and not sandbox_leases:
            raise ValueError("sandbox ops require sandbox leases")
        if sandbox_ops and (
            SANDBOX_OPS_CONCURRENCY
            + SANDBOX_OPS_CANCEL_HEADROOM
            + max(max_concurrency, 1)
            + SANDBOX_OPS_INGRESS_RESERVE
            > MINER_INGRESS_CONCURRENCY
        ):
            raise ValueError(
                "sandbox ops capacity, cancel headroom and --max-concurrency leave too little "
                f"of the {MINER_INGRESS_CONCURRENCY}-request ingress for lease lifecycle"
            )
        self.ops_admission = OpsAdmission(SANDBOX_OPS_CONCURRENCY, SANDBOX_OPS_CANCEL_HEADROOM)
        self.sandbox_leases = sandbox_leases
        self.sandbox_reservation_replay = sandbox_reservation_replay
        self.sandbox_ops = sandbox_ops
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
                # Weight-update inactivity must not take a registered miner offline.
                own_matches = tuple(
                    neuron for neuron in snapshot.neurons if neuron.hotkey == self.hotkey
                )
                if len(own_matches) != 1:
                    self.ready.clear()
                    LOGGER.error(
                        "miner hotkey is not uniquely registered", extra={"hotkey": self.hotkey}
                    )
                elif sum(neuron.uid == own_matches[0].uid for neuron in snapshot.neurons) != 1:
                    self.ready.clear()
                    LOGGER.error("miner UID identity conflicts", extra={"hotkey": self.hotkey})
                elif self.uid is not None and own_matches[0].uid != self.uid:
                    self.ready.clear()
                    LOGGER.error(
                        "configured UID differs from metagraph",
                        extra={"hotkey": self.hotkey, "block": snapshot.block},
                    )
                else:
                    own = own_matches[0]
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
        return await self.authorization.authorize(await self._verified_hotkey(request, body))

    async def _verified_hotkey(self, request: Request, body: bytes) -> str:
        """The btauth-verified caller of ``body``; nothing counted yet."""

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
        return str(verified.hotkey_ss58)

    async def _snapshot_for(self, current_block: int) -> MetagraphSnapshot:
        snapshot = await self.state.get()
        if current_block + 2 < snapshot.block or current_block > snapshot.block + 2:
            raise HTTPException(status_code=409, detail="request block is stale or from the future")
        return snapshot

    async def _verify_assignment_identity(
        self,
        caller_hotkey: str,
        current_block: int,
        validator_binding: ServiceKeyBinding,
        binding: SubnetBinding,
    ) -> None:
        """Bind a validator assignment to btauth, the metagraph and this miner.

        Every assignment kind (deployment.v4 and static-deployment v1) shares
        these checks before anything reaches the Go agent.
        """

        snapshot = await self._snapshot_for(current_block)
        expected_challenge = "validator-service:" + validator_binding.service_public_key
        try:
            verify_service_binding(
                validator_binding,
                expected_hotkey=caller_hotkey,
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
                current_block=current_block,
            )
        except ValueError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        validator = snapshot.by_hotkey(caller_hotkey)
        if (
            validator is None
            or validator_binding.uid != validator.uid
            or binding.validator_hotkey != caller_hotkey
            or binding.miner_hotkey != self.hotkey
            or binding.miner_uid != self.uid
            or binding.network != self.network
            or binding.netuid != self.netuid
            or binding.miner_transport != ("http" if self.mock_http else "https")
            or binding.miner_tls_certificate_sha256
            != (None if self.tls_config is None else self.tls_config.fingerprint_sha256)
            or binding.validator_service_public_key != validator_binding.service_public_key
            or binding.epoch != binding.chain_block // max(snapshot.tempo, 1)
            or binding.chain_block > snapshot.block + 2
            or snapshot.block >= binding.expires_at_block
        ):
            raise HTTPException(status_code=403, detail="ticket Bittensor identity mismatch")

    async def _static_bridge(
        self,
        path: str,
        value: LocalStaticAssignRequestV1 | StaticStatusSynapseV1,
        response_model: type[StaticDeployResponseV1] | type[StaticStatusResponseV1],
    ) -> StaticDeployResponseV1 | StaticStatusResponseV1:
        """Forward one static request to Go, keeping its stable error code.

        A miner whose agent runs with ``--static-sites off`` answers
        ``static_disabled``; the validator treats that as ineligibility
        (capability misreport), never as a fault.
        """

        try:
            result = await self.bridge.request(
                "POST", path, value=value, response_model=response_model
            )
        except BridgeError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.code) from exc
        assert isinstance(result, (StaticDeployResponseV1, StaticStatusResponseV1))
        return result

    async def _sandbox_forward(
        self, kind: str, request: Request, *, replay: bool = False
    ) -> SandboxResponseV1:
        """Forward one validator-signed sandbox document to the Go agent.

        The same btauth and Bittensor identity checks as a static ticket run
        before agent contact; the Go agent verifies the document itself. An
        agent running with the sandbox lane off answers ``sandbox_disabled``,
        which keeps its stable code here (ineligible, not a fault).
        """

        body = await self._body(request)
        caller = await self._authenticated(request, body)
        if _envelope_protocol(body) != sandbox_transport.SYNAPSE_VERSION:
            raise HTTPException(
                status_code=422,
                detail="only subnet-sandbox-synapse.v1 sandbox documents are accepted",
            )
        try:
            synapse = parse_document(body, SandboxSynapseV1)
            header = sandbox_transport.document_header(synapse.document, kind)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        if synapse.caller_hotkey != caller.hotkey:
            raise HTTPException(status_code=403, detail="body caller differs from btauth caller")
        await self._verify_assignment_identity(
            caller.hotkey, synapse.current_block, synapse.validator_binding, header.subnet
        )
        local = LocalSandboxRequestV1(
            protocol=sandbox_transport.SYNAPSE_VERSION,
            request_id=synapse.request_id,
            current_block=synapse.current_block,
            caller_hotkey=caller.hotkey,
            binding_verified=True,
            validator_binding=synapse.validator_binding,
            document=synapse.document,
        )
        async with self.gate.slot(caller.priority):
            try:
                result = await self.bridge.request(
                    "POST",
                    f"/v1/sandbox/{kind}" + ("/replay" if replay else ""),
                    value=local,
                    response_model=SandboxResponseV1,
                )
            except BridgeError as exc:
                raise HTTPException(status_code=exc.status_code, detail=exc.code) from exc
            except ValidationError as exc:
                raise HTTPException(status_code=502, detail=SANDBOX_AGENT_ANSWER_INVALID) from exc
        assert isinstance(result, SandboxResponseV1)
        try:
            if result.request_id != synapse.request_id:
                raise ValueError(sandbox_transport.SANDBOX_RECEIPT_MISMATCH)
            sandbox_transport.receipt_answers(result.receipt, header, kind)
        except ValueError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        return result

    async def _sandbox_ops_forward(self, request: Request) -> SandboxOpsResponseV1:
        """Forward one validator-signed op request and its payload to the Go
        agent, after the same btauth and identity checks as a lease document.
        The agent verifies the document and the payload binding.

        Ops are counted in their own rate window and admitted without waiting
        (OpsAdmission), never through the gate lease lifecycle and assignments
        use. A well-formed exec_cancel is counted in its own bounded reserve
        instead. A full window or capacity is a definitive 429 before any
        agent contact; an agent answer keeps its own status, which may be
        unknown."""

        body = await self._body(request)
        caller = await self.authorization.identify(await self._verified_hotkey(request, body))
        try:
            synapse, header = _ops_request(body)
        except HTTPException:
            # Not decodable as an op: always counted as an ordinary op.
            await self.authorization.admit(caller.hotkey, RATE_CLASS_SANDBOX_OPS)
            raise
        cancel = _is_exec_cancel(synapse, caller.hotkey)
        await self.authorization.admit(
            caller.hotkey, RATE_CLASS_SANDBOX_OPS_CANCEL if cancel else RATE_CLASS_SANDBOX_OPS
        )
        if synapse.caller_hotkey != caller.hotkey:
            raise HTTPException(status_code=403, detail="body caller differs from btauth caller")
        await self._verify_assignment_identity(
            caller.hotkey, synapse.current_block, synapse.validator_binding, header.subnet
        )
        local = LocalSandboxOpsRequestV1(
            protocol=sandbox_transport.OPS_SYNAPSE_VERSION,
            request_id=synapse.request_id,
            current_block=synapse.current_block,
            caller_hotkey=caller.hotkey,
            binding_verified=True,
            validator_binding=synapse.validator_binding,
            document=synapse.document,
            payload_b64=synapse.payload_b64,
        )
        with self.ops_admission.slot(cancel=cancel) as admitted:
            if not admitted:
                raise HTTPException(
                    status_code=429,
                    detail=SANDBOX_OPS_CAPACITY_EXHAUSTED,
                    headers={"Retry-After": str(SANDBOX_OPS_CAPACITY_RETRY_AFTER)},
                )
            try:
                result = await self.bridge.request(
                    "POST", "/v1/sandbox/ops", value=local, response_model=SandboxOpsResponseV1
                )
            except BridgeError as exc:
                raise HTTPException(status_code=exc.status_code, detail=exc.code) from exc
            except ValidationError as exc:
                raise HTTPException(status_code=502, detail=SANDBOX_AGENT_ANSWER_INVALID) from exc
        assert isinstance(result, SandboxOpsResponseV1)
        try:
            if result.request_id != synapse.request_id:
                raise ValueError(sandbox_transport.SANDBOX_RECEIPT_MISMATCH)
            sandbox_transport.op_receipt_answers(result.receipt, header)
        except ValueError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        return result

    def _sandbox_route(self, kind: str) -> None:
        async def forward(request: Request) -> SandboxResponseV1:
            return await self._sandbox_forward(kind, request)

        self.app.add_api_route(
            f"/api/v1/sandbox/{kind}",
            forward,
            methods=["POST"],
            response_model=None,
            name=f"sandbox_{kind}",
        )

    def _routes(self) -> None:
        if self.sandbox_reservation_replay:

            @self.app.post("/api/v1/sandbox/reservations/replay", response_model=None)
            async def replay_reservation(request: Request) -> SandboxResponseV1:
                return await self._sandbox_forward("reservations", request, replay=True)

        if self.sandbox_leases:
            for kind in sandbox_transport.DOCUMENT_SCHEMAS:
                self._sandbox_route(kind)
        if self.sandbox_ops:
            self.app.add_api_route(
                "/api/v1/sandbox/ops",
                self._sandbox_ops_forward,
                methods=["POST"],
                response_model=None,
                name="sandbox_ops",
            )

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
                    # Delegate now for the authenticated, admitted request snapshot;
                    # this is not an assertion of historical metagraph membership.
                    # Keep generation and expiry miner-derived across fresh challenges.
                    valid_from_block=min(snapshot.block, synapse.chain_block),
                    expires_at_block=snapshot.block + max(snapshot.tempo * 2, 12),
                    challenge=synapse.challenge,
                ),
                self.hotkey_signer,
            )
            return CapabilitiesResponse(
                request_id=synapse.request_id,
                miner_hotkey=self.hotkey,
                miner_uid=self.uid,
                features=[
                    feature
                    for feature in local.features
                    if (
                        feature != sandbox_transport.REPLAY_CAPABILITY_FEATURE
                        or self.sandbox_reservation_replay
                    )
                    and (feature != sandbox_transport.OPS_CAPABILITY_FEATURE or self.sandbox_ops)
                ],
                max_body_bytes=local.max_body_bytes,
                service_binding=binding,
            )

        @self.app.post("/api/v1/deploy", response_model=None)
        async def deploy(request: Request) -> DeployResponseV3:
            body = await self._body(request)
            caller = await self._authenticated(request, body)
            # Only subnet-synapse.v3 envelopes carrying deployment.v4 organic
            # tickets are assignments; the synthetic v2 envelope is retired.
            if _envelope_protocol(body) != ORGANIC_SYNAPSE_VERSION:
                raise HTTPException(
                    status_code=422,
                    detail="only subnet-synapse.v3 organic assignments are accepted",
                )
            try:
                synapse = parse_document(body, DeploySynapseV3)
            except ValueError as exc:
                raise HTTPException(status_code=422, detail=str(exc)) from exc
            if synapse.caller_hotkey != caller.hotkey:
                raise HTTPException(
                    status_code=403, detail="body caller differs from btauth caller"
                )
            await self._verify_assignment_identity(
                caller.hotkey,
                synapse.current_block,
                synapse.validator_binding,
                synapse.ticket.subnet,
            )
            local_request = {
                "protocol": ORGANIC_SYNAPSE_VERSION,
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
                    response_model=DeployResponseV3,
                )
            assert isinstance(result, DeployResponseV3)
            return result

        @self.app.post("/api/v1/status", response_model=None)
        async def status(request: Request) -> StatusResponseV3:
            body = await self._body(request)
            caller = await self._authenticated(request, body)
            synapse = StatusSynapse.model_validate_json(body)
            if synapse.caller_hotkey != caller.hotkey:
                raise HTTPException(status_code=403, detail="caller mismatch")
            snapshot = await self._snapshot_for(synapse.current_block)
            local = synapse.model_copy(update={"current_block": snapshot.block})
            # The agent answers status only as status-response v3.
            payload = await self.bridge.request(
                "POST", "/v1/status", value=local, response_model=StatusResponseV3
            )
            assert isinstance(payload, StatusResponseV3)
            return payload

        @self.app.post("/api/v1/static/deploy", response_model=None)
        async def static_deploy(request: Request) -> StaticDeployResponseV1:
            body = await self._body(request)
            caller = await self._authenticated(request, body)
            # Static tickets travel only in subnet-static-synapse.v1; the
            # organic route above never accepts one and this route never
            # accepts a deployment.v4 ticket.
            if _envelope_protocol(body) != static_contracts.SYNAPSE_VERSION:
                raise HTTPException(
                    status_code=422,
                    detail="only subnet-static-synapse.v1 static assignments are accepted",
                )
            try:
                synapse = parse_document(body, StaticDeploySynapseV1)
            except ValueError as exc:
                raise HTTPException(status_code=422, detail=str(exc)) from exc
            if synapse.caller_hotkey != caller.hotkey:
                raise HTTPException(
                    status_code=403, detail="body caller differs from btauth caller"
                )
            await self._verify_assignment_identity(
                caller.hotkey,
                synapse.current_block,
                synapse.validator_binding,
                synapse.ticket.subnet,
            )
            local = LocalStaticAssignRequestV1(
                protocol=static_contracts.SYNAPSE_VERSION,
                request_id=synapse.request_id,
                current_block=synapse.current_block,
                caller_hotkey=caller.hotkey,
                binding_verified=True,
                validator_binding=synapse.validator_binding,
                ticket=synapse.ticket,
            )
            async with self.gate.slot(caller.priority):
                result = await self._static_bridge(
                    "/v1/static/assignments", local, StaticDeployResponseV1
                )
            assert isinstance(result, StaticDeployResponseV1)
            return result

        @self.app.post("/api/v1/static/status", response_model=None)
        async def static_status(request: Request) -> StaticStatusResponseV1:
            body = await self._body(request)
            caller = await self._authenticated(request, body)
            try:
                synapse = parse_document(body, StaticStatusSynapseV1)
            except ValueError as exc:
                raise HTTPException(status_code=422, detail=str(exc)) from exc
            if synapse.caller_hotkey != caller.hotkey:
                raise HTTPException(status_code=403, detail="caller mismatch")
            snapshot = await self._snapshot_for(synapse.current_block)
            local = synapse.model_copy(update={"current_block": snapshot.block})
            result = await self._static_bridge("/v1/static/status", local, StaticStatusResponseV1)
            assert isinstance(result, StaticStatusResponseV1)
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
            methods=RUNTIME_METHODS,
        )
        async def runtime_proxy(endpoint_id: str, runtime_path: str, request: Request) -> Response:
            del runtime_path  # the exact escaped suffix comes from raw_path
            if RUNTIME_ENDPOINT_ID.fullmatch(endpoint_id) is None:
                raise HTTPException(status_code=404, detail="runtime endpoint not found")
            # Fail closed before reading a body or contacting the agent when
            # the edge-runtime-request signature cannot possibly be valid.
            if len(request.headers.getlist(EDGE_AUTHORIZATION_HEADER)) != 1:
                raise HTTPException(
                    status_code=401, detail="edge runtime authorization is required"
                )
            prefix = f"/runtime/{endpoint_id}/".encode()
            raw_path: bytes = request.scope.get("raw_path") or b""
            query: bytes = request.scope.get("query_string") or b""
            if not raw_path.startswith(prefix):
                raise HTTPException(status_code=404, detail="runtime endpoint not found")
            try:
                target = "/v1/runtime/" + endpoint_id + raw_path[len(prefix) - 1 :].decode("ascii")
                if query:
                    target += "?" + query.decode("ascii")
            except UnicodeDecodeError as exc:
                raise HTTPException(status_code=400, detail="runtime target is not ASCII") from exc
            body = await self._body(request)
            header_items = runtime_request_headers(list(request.headers.raw))
            header_items.extend(
                (name.encode("ascii"), value.encode("ascii"))
                for name, value in bridge_headers(
                    self.bridge.secret,
                    method=request.method,
                    target=target,
                    body=body,
                ).items()
            )
            async with httpx.AsyncClient(
                base_url=self.bridge.base_url,
                timeout=self.bridge.timeout,
                transport=self.bridge.transport,
                follow_redirects=False,
                trust_env=False,
            ) as client:
                # Never invent Accept, Accept-Encoding, User-Agent or
                # Connection values on the application's behalf.
                client.headers.clear()
                # The target extension sends the exact path and query bytes the
                # edge signed; httpx URL parsing would normalize dot segments
                # and re-encode characters.
                outbound = client.build_request(
                    request.method,
                    target,
                    content=body,
                    headers=header_items,
                    extensions={"target": target.encode("ascii")},
                )
                try:
                    upstream = await client.send(outbound, stream=True)
                except httpx.HTTPError as exc:
                    raise HTTPException(status_code=502, detail="runtime unavailable") from exc
                try:
                    declared_length = upstream.headers.get("content-length")
                    if request.method != "HEAD" and declared_length is not None:
                        try:
                            oversized = int(declared_length) > RUNTIME_MAX_RESPONSE
                        except ValueError:
                            oversized = False
                        if oversized:
                            raise HTTPException(
                                status_code=502,
                                detail="runtime response exceeds the miner limit",
                            )
                    # aiter_raw never decodes Content-Encoding: compressed
                    # application responses pass through unmodified and the
                    # limit applies to encoded bytes.
                    chunks: list[bytes] = []
                    response_size = 0
                    async for chunk in upstream.aiter_raw(chunk_size=RUNTIME_READ_CHUNK):
                        response_size += len(chunk)
                        if response_size > RUNTIME_MAX_RESPONSE:
                            raise HTTPException(
                                status_code=502,
                                detail="runtime response exceeds the miner limit",
                            )
                        chunks.append(chunk)
                except httpx.HTTPError as exc:
                    raise HTTPException(status_code=502, detail="runtime unavailable") from exc
                finally:
                    await upstream.aclose()
                content = b"".join(chunks)
                status_code = upstream.status_code
                headers = runtime_response_headers(
                    list(upstream.headers.raw), status_code=status_code
                )
            response = Response(content=content, status_code=status_code)
            if status_code < 200 or status_code in (204, 304):
                length_header: list[tuple[bytes, bytes]] = []
            elif request.method == "HEAD":
                # A HEAD response keeps the entity length the agent declared.
                length_header = (
                    [(b"content-length", declared_length.encode("latin-1"))]
                    if declared_length is not None
                    else []
                )
            else:
                length_header = [(b"content-length", str(len(content)).encode())]
            response.raw_headers = headers + length_header
            return response


def _ops_request(body: bytes) -> tuple[SandboxOpsSynapseV1, SandboxDocumentHeader]:
    """Decode one op request and its routing header; 422 if it is not one."""

    if _envelope_protocol(body) != sandbox_transport.OPS_SYNAPSE_VERSION:
        raise HTTPException(
            status_code=422,
            detail="only subnet-sandbox-ops-synapse.v1 op requests are accepted",
        )
    try:
        synapse = parse_document(body, SandboxOpsSynapseV1)
        return synapse, sandbox_transport.op_header(synapse.document)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


def _is_exec_cancel(synapse: SandboxOpsSynapseV1, caller_hotkey: str) -> bool:
    """Whether a decoded op request may use the exec_cancel reserves.

    Only the exact op kind from the btauth-verified caller's own document, and
    never with a payload (the agent refuses a payload on exec_cancel), so no
    other request can claim the reserve.
    """

    return (
        synapse.caller_hotkey == caller_hotkey
        and synapse.document.get("op") == "exec_cancel"
        and synapse.payload_b64 is None
    )


def _envelope_protocol(body: bytes) -> str | None:
    """Return a deploy body's protocol member without trusting the rest."""

    try:
        payload = json.loads(body)
    except ValueError:
        return None
    value = payload.get("protocol") if isinstance(payload, dict) else None
    return value if isinstance(value, str) else None


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
    parser.add_argument(
        "--operator-hotkey",
        action="append",
        help="allowed operator SS58 hotkey (repeatable); overrides MC_OPERATOR_HOTKEYS",
    )
    parser.add_argument("--min-validator-stake", type=float, default=1_000.0)
    parser.add_argument("--sync-interval", type=float, default=12.0)
    parser.add_argument("--max-concurrency", type=int, default=4)
    parser.add_argument("--mock-uri")
    parser.add_argument("--mock-peers")
    parser.add_argument(
        "--mock-tempo", type=int, help="explicit mock-only block tempo (default 12)"
    )
    parser.add_argument("--mock-capability-fault-file")
    parser.add_argument(
        "--sandbox-leases",
        choices=("on", "off"),
        default="off",
        help="forward subnet-sandbox-synapse.v1 documents to the Go agent (default off)",
    )
    parser.add_argument(
        "--sandbox-reservation-replay",
        choices=("on", "off"),
        default="off",
        help="existing-hold-only replay; requires --sandbox-leases on",
    )
    parser.add_argument(
        "--sandbox-ops",
        choices=("on", "off"),
        default="off",
        help="forward subnet-sandbox-ops-synapse.v1 op requests; requires --sandbox-leases on",
    )
    parser.add_argument("--log-level", default="INFO")
    return parser


def make_chain(args: argparse.Namespace) -> tuple[ChainQuery, HotkeySigningFacade]:
    mock_tempo = getattr(args, "mock_tempo", None)
    if mock_tempo is not None and (not args.mock_uri or mock_tempo < 1):
        raise ValueError("--mock-tempo requires --mock-uri and a positive tempo")
    if args.mock_uri:
        if not args.mock_peers:
            raise ValueError("--mock-peers is required with --mock-uri")
        chain = MockChain(
            network=args.subtensor_network,
            netuid=args.netuid,
            own_uri=args.mock_uri,
            peers=load_mock_peers(args.mock_peers),
            tempo=12 if mock_tempo is None else mock_tempo,
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
    try:
        operator_hotkeys = configured_operator_hotkeys(
            args.operator_hotkey, os.getenv("MC_OPERATOR_HOTKEYS")
        )
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
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
    try:
        neuron = MinerNeuron(
            chain=chain,
            hotkey_signer=hotkey_signer,
            network=args.subtensor_network,
            netuid=args.netuid,
            configured_uid=args.uid,
            bridge=BridgeClient(args.go_agent_url, secret, timeout=120.0, retries=0),
            nonce_store=SQLiteNonceStore(args.state_db),
            min_validator_stake=args.min_validator_stake,
            operator_hotkeys=operator_hotkeys,
            sync_interval=args.sync_interval,
            max_concurrency=args.max_concurrency,
            mock_http=args.allow_insecure_mock_http,
            tls_config=tls_config,
            capability_fault_file=args.mock_capability_fault_file,
            sandbox_leases=args.sandbox_leases == "on",
            sandbox_reservation_replay=args.sandbox_reservation_replay == "on",
            sandbox_ops=args.sandbox_ops == "on",
        )
    except ValueError as exc:
        # The neuron refuses this configuration at startup, fail closed. Report
        # its message as a clean exit, as the other startup refusals do.
        raise SystemExit(str(exc)) from exc
    if tls_config is None:
        uvicorn.run(
            neuron.app,
            host=args.axon_host,
            port=args.axon_port,
            log_config=None,
            limit_concurrency=MINER_INGRESS_CONCURRENCY,
            timeout_keep_alive=MINER_KEEP_ALIVE_SECONDS,
            h11_max_incomplete_event_size=MINER_H11_MAX_INCOMPLETE_EVENT,
            server_header=False,
            date_header=False,
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
        # Application responses carry their own Server/Date headers through
        # the runtime proxy; the axon must not add duplicates.
        server_header=False,
        date_header=False,
    )
    config.load()
    config.ssl = tls_config.server_context
    uvicorn.Server(config).run()


if __name__ == "__main__":
    main()
