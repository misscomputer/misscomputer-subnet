# SPDX-License-Identifier: AGPL-3.0-only
"""Bittensor v11 validator neuron and local Go dendrite bridge."""

from __future__ import annotations

import argparse
import asyncio
import base64
import contextlib
import hashlib
import hmac
import ipaddress
import json
import logging
import math
import os
import secrets
import sqlite3
import sys
import threading
import time
from collections import Counter, deque
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field, replace
from typing import Any, TypeVar
from urllib.parse import quote, urlsplit

import bittensor as bt
import httpx
import uvicorn
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ValidationError

from .auth import (
    BRIDGE_MAX_BODY,
    BridgeClient,
    BridgeError,
    HotkeyAuth,
    HotkeySigningFacade,
    SQLiteBridgeReplay,
    load_secret,
    sign_service_binding,
    verify_bridge_headers,
    verify_service_binding,
)
from .chain import (
    ChainQuery,
    MetagraphSnapshot,
    MetagraphState,
    MockChain,
    NeuronRecord,
    load_mock_peers,
)
from .chain_quorum import build_chain_query, json_stderr_alert
from .logging import configure_logging
from .netpolicy import canonical_public_address
from .protocol import (
    SYNAPSE_VERSION,
    BridgeAssignRequest,
    BridgeDeactivateRequest,
    CapabilitiesResponse,
    CapabilitiesSynapse,
    ChainState,
    ControlCapabilities,
    DeactivateResponse,
    DeactivateSynapse,
    DeployResponse,
    DeploySynapse,
    MinerRegistration,
    MinerSet,
    ServiceKeyBinding,
    SubnetBinding,
)
from .tls import MAX_CERTIFICATE_BYTES, pinned_client_context, tls_leaf_preflight
from .weight_plan import (
    WEIGHT_PLAN_PROTOCOL_VERSION_KEY,
    WeightPlan,
    build_weight_plan,
    write_weight_plan_atomic,
)

LOGGER = logging.getLogger("misscomputer_subnet.validator")
DISCOVERY_FAILURE_LOG_LIMIT = 8
PUBLICATION_LANE_SCHEMA_VERSION = 1
PUBLICATION_RECORD_MAC_DOMAIN = "miss.computer/misscomputer-subnet/publication-record/v1"
MAX_HISTORICAL_PUBLICATIONS = 512
MAX_PERSISTED_PUBLICATIONS = MAX_HISTORICAL_PUBLICATIONS + 2
MAX_PUBLICATION_NEURONS = 4_096
MAX_PUBLICATION_MINERS = 4_096
MAX_PUBLICATION_PAYLOAD_BYTES = 4 << 20
MAX_TOTAL_PUBLICATION_PAYLOAD_BYTES = 256 << 20
MAX_SQLITE_INTEGER = (1 << 63) - 1
PUBLIC_AXON_REJECTION = (
    "live metagraph axon must not target a private or local special-purpose address"
)
ResponseT = TypeVar("ResponseT", bound=BaseModel)
DiscoveryIdentity = tuple[str, int, str]


class _AmbiguousMinerRegistration(RuntimeError):
    """A registration may have committed even though its response was lost."""


@dataclass(frozen=True, slots=True)
class RemoteMiner:
    neuron: NeuronRecord
    axon_url: str
    binding: ServiceKeyBinding
    certificate_der: bytes | None = field(repr=False)


@dataclass(frozen=True, slots=True)
class DiscoveryCandidate:
    neuron: NeuronRecord
    axon_url: str

    @property
    def identity(self) -> DiscoveryIdentity:
        return (self.neuron.hotkey, self.neuron.uid, self.axon_url)


@dataclass(frozen=True, slots=True)
class _PublicationLane:
    publication_id: str
    snapshot: MetagraphSnapshot
    validator_binding: ServiceKeyBinding
    miners: tuple[tuple[str, RemoteMiner], ...]
    ticket_expires_at_block: int
    drain_only: bool = False

    def miner(self, hotkey: str) -> RemoteMiner | None:
        return next((remote for key, remote in self.miners if key == hotkey), None)

    def miner_map(self) -> dict[str, RemoteMiner]:
        return dict(self.miners)

    @property
    def authorized_expires_at_block(self) -> int:
        if not self.miners:
            return self.ticket_expires_at_block
        return max(
            min(self.ticket_expires_at_block, remote.binding.expires_at_block)
            for _, remote in self.miners
        )


@dataclass(frozen=True, slots=True)
class _TicketHandle:
    publication_id: str
    remote: RemoteMiner
    snapshot: MetagraphSnapshot
    validator_binding: ServiceKeyBinding
    ticket_expires_at_block: int
    authorized_expires_at_block: int
    # Retired and inventory-reconciled handles are exact Go-committed drain
    # authority. Their transport identity is checked against the ticket, but a
    # later metagraph removal/rebind must not invalidate an already-issued one.
    drain_only: bool = False


@dataclass(frozen=True, slots=True)
class _StoredPublication:
    publication_id: str
    schema_version: int
    block: int
    authorized_expires_at_block: int
    committed: bool
    drain_only: bool
    payload_sha256: str
    payload: str
    record_mac: str

    @property
    def authenticated(self) -> bool:
        return bool(self.record_mac)


def _publication_record_mac_key(
    secret: bytes,
    *,
    network: str,
    netuid: int,
    validator_hotkey: str,
) -> bytes:
    """Derive a validator-specific key without persisting the bridge secret."""

    if len(secret) < 32:
        raise ValueError("publication authentication secret must contain at least 32 bytes")
    identity = json.dumps(
        {
            "domain": PUBLICATION_RECORD_MAC_DOMAIN,
            "network": network,
            "netuid": netuid,
            "validator_hotkey": validator_hotkey,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    return hmac.new(
        secret,
        PUBLICATION_RECORD_MAC_DOMAIN.encode("ascii") + b"\x00key\x00" + identity,
        hashlib.sha256,
    ).digest()


def _publication_record_mac(
    key: bytes,
    *,
    publication_id: str,
    schema_version: int,
    block: int,
    authorized_expires_at_block: int,
    committed: bool,
    drain_only: bool,
    payload_sha256: str,
    payload: str,
) -> str:
    """Authenticate every durable authority field (excluding the MAC itself)."""

    record = json.dumps(
        {
            "authorized_expires_at_block": authorized_expires_at_block,
            "block": block,
            "committed": committed,
            "domain": PUBLICATION_RECORD_MAC_DOMAIN,
            "drain_only": drain_only,
            "payload": payload,
            "payload_sha256": payload_sha256,
            "publication_id": publication_id,
            "schema_version": schema_version,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    return hmac.new(key, record, hashlib.sha256).hexdigest()


class _PublicationLaneStore:
    """Bounded durable exact-publication tuples sharing the validator state DB."""

    _LEGACY_COLUMNS = {
        "publication_id",
        "block",
        "authorized_expires_at_block",
        "committed",
        "payload",
    }
    _VERSIONED_COLUMNS_WITHOUT_DRAIN = _LEGACY_COLUMNS | {
        "schema_version",
        "payload_sha256",
    }
    _PRE_AUTH_COLUMNS = _VERSIONED_COLUMNS_WITHOUT_DRAIN | {"drain_only"}
    _COLUMNS = _PRE_AUTH_COLUMNS | {"record_mac"}

    def __init__(
        self,
        path: str,
        *,
        authentication_secret: bytes,
        network: str,
        netuid: int,
        validator_hotkey: str,
    ) -> None:
        self.path = path
        self._lock = threading.Lock()
        self._record_mac_key = _publication_record_mac_key(
            authentication_secret,
            network=network,
            netuid=netuid,
            validator_hotkey=validator_hotkey,
        )
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA busy_timeout=5000")
            connection.execute("BEGIN IMMEDIATE")
            columns = {
                str(row[1])
                for row in connection.execute(
                    "PRAGMA table_info(validator_publication_lanes)"
                ).fetchall()
            }
            if not columns:
                connection.execute(
                    """CREATE TABLE validator_publication_lanes (
                    publication_id TEXT PRIMARY KEY,
                    schema_version INTEGER NOT NULL
                        CHECK(schema_version = 1),
                    block INTEGER NOT NULL,
                    authorized_expires_at_block INTEGER NOT NULL,
                    committed INTEGER NOT NULL CHECK(committed IN (0, 1)),
                    drain_only INTEGER NOT NULL CHECK(drain_only IN (0, 1)),
                    payload_sha256 TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    record_mac TEXT NOT NULL DEFAULT ''
                        CHECK(record_mac = '' OR length(record_mac) = 64))"""
                )
            elif columns == self._LEGACY_COLUMNS:
                # Migrate the unpublished pre-versioned layout in place. The
                # transaction makes the column additions and checksums
                # all-or-nothing across process interruption.
                self._validate_bounds(connection)
                connection.execute(
                    """ALTER TABLE validator_publication_lanes
                    ADD COLUMN schema_version INTEGER NOT NULL DEFAULT 1
                    CHECK(schema_version = 1)"""
                )
                connection.execute(
                    """ALTER TABLE validator_publication_lanes
                    ADD COLUMN payload_sha256 TEXT NOT NULL DEFAULT ''"""
                )
                for publication_id, payload in connection.execute(
                    "SELECT publication_id, payload FROM validator_publication_lanes"
                ).fetchall():
                    if not isinstance(publication_id, str) or not isinstance(payload, str):
                        raise RuntimeError("legacy durable publication row is malformed")
                    connection.execute(
                        """UPDATE validator_publication_lanes
                        SET payload_sha256=? WHERE publication_id=?""",
                        (hashlib.sha256(payload.encode("utf-8")).hexdigest(), publication_id),
                    )
                connection.execute(
                    """ALTER TABLE validator_publication_lanes
                    ADD COLUMN drain_only INTEGER NOT NULL DEFAULT 1
                    CHECK(drain_only IN (0, 1))"""
                )
                connection.execute(
                    "UPDATE validator_publication_lanes SET drain_only=0 WHERE committed=0"
                )
            elif columns == self._VERSIONED_COLUMNS_WITHOUT_DRAIN:
                self._validate_bounds(connection)
                connection.execute(
                    """ALTER TABLE validator_publication_lanes
                    ADD COLUMN drain_only INTEGER NOT NULL DEFAULT 1
                    CHECK(drain_only IN (0, 1))"""
                )
                connection.execute(
                    "UPDATE validator_publication_lanes SET drain_only=0 WHERE committed=0"
                )
            elif columns == self._PRE_AUTH_COLUMNS:
                self._validate_bounds(connection)
                connection.execute(
                    """ALTER TABLE validator_publication_lanes
                    ADD COLUMN record_mac TEXT NOT NULL DEFAULT ''
                    CHECK(record_mac = '' OR length(record_mac) = 64)"""
                )
            elif columns != self._COLUMNS:
                raise RuntimeError("durable publication schema is unsupported")
            if columns in (self._LEGACY_COLUMNS, self._VERSIONED_COLUMNS_WITHOUT_DRAIN):
                connection.execute(
                    """ALTER TABLE validator_publication_lanes
                    ADD COLUMN record_mac TEXT NOT NULL DEFAULT ''
                    CHECK(record_mac = '' OR length(record_mac) = 64)"""
                )
            connection.commit()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5.0)
        connection.execute("PRAGMA busy_timeout=5000")
        return connection

    @staticmethod
    def _payload_size(payload: str) -> int:
        try:
            size = len(payload.encode("ascii"))
        except UnicodeEncodeError as exc:
            raise RuntimeError("durable publication payload must be canonical ASCII") from exc
        if size > MAX_PUBLICATION_PAYLOAD_BYTES:
            raise RuntimeError("durable publication payload exceeds its row bound")
        return size

    @staticmethod
    def _validate_identity(
        *, publication_id: str, block: int, authorized_expires_at_block: int
    ) -> None:
        try:
            digest = bytes.fromhex(publication_id)
        except ValueError as exc:
            raise RuntimeError("durable publication identity is malformed") from exc
        if len(digest) != hashlib.sha256().digest_size or len(publication_id) != 64:
            raise RuntimeError("durable publication identity is malformed")
        if (
            not isinstance(block, int)
            or isinstance(block, bool)
            or not 0 <= block <= MAX_SQLITE_INTEGER
            or not isinstance(authorized_expires_at_block, int)
            or isinstance(authorized_expires_at_block, bool)
            or not block < authorized_expires_at_block <= MAX_SQLITE_INTEGER
        ):
            raise RuntimeError("durable publication block window is malformed")

    @staticmethod
    def _validate_bounds(connection: sqlite3.Connection) -> tuple[int, int]:
        row = connection.execute(
            """SELECT COUNT(*),
            COALESCE(SUM(length(CAST(payload AS BLOB))), 0)
            FROM validator_publication_lanes"""
        ).fetchone()
        if (
            row is None
            or not isinstance(row[0], int)
            or isinstance(row[0], bool)
            or not isinstance(row[1], int)
            or isinstance(row[1], bool)
        ):
            raise RuntimeError("durable publication bounds are malformed")
        count, total_bytes = row
        if count > MAX_PERSISTED_PUBLICATIONS:
            raise RuntimeError("durable publication history exceeds its deterministic bound")
        if total_bytes > MAX_TOTAL_PUBLICATION_PAYLOAD_BYTES:
            raise RuntimeError("durable publication payload total exceeds its bound")
        oversized = connection.execute(
            """SELECT 1 FROM validator_publication_lanes
            WHERE typeof(payload) != 'text'
            OR length(CAST(payload AS BLOB)) > ? LIMIT 1""",
            (MAX_PUBLICATION_PAYLOAD_BYTES,),
        ).fetchone()
        if oversized is not None:
            raise RuntimeError("durable publication payload row is malformed or oversized")
        return count, total_bytes

    def _record_mac(
        self,
        *,
        publication_id: str,
        schema_version: int,
        block: int,
        authorized_expires_at_block: int,
        committed: bool,
        drain_only: bool,
        payload_sha256: str,
        payload: str,
    ) -> str:
        return _publication_record_mac(
            self._record_mac_key,
            publication_id=publication_id,
            schema_version=schema_version,
            block=block,
            authorized_expires_at_block=authorized_expires_at_block,
            committed=committed,
            drain_only=drain_only,
            payload_sha256=payload_sha256,
            payload=payload,
        )

    def _record_from_row(self, row: tuple[Any, ...]) -> _StoredPublication:
        if (
            len(row) != 9
            or not isinstance(row[0], str)
            or row[1] != PUBLICATION_LANE_SCHEMA_VERSION
            or not isinstance(row[2], int)
            or isinstance(row[2], bool)
            or not isinstance(row[3], int)
            or isinstance(row[3], bool)
            or row[4] not in (0, 1)
            or row[5] not in (0, 1)
            or not isinstance(row[6], str)
            or not isinstance(row[7], str)
            or not isinstance(row[8], str)
            or (row[4] == 0 and row[5] != 0)
        ):
            raise RuntimeError("durable publication row is malformed")
        publication_id = row[0]
        block = row[2]
        authorized_expires_at_block = row[3]
        committed = bool(row[4])
        drain_only = bool(row[5])
        payload_sha256 = row[6]
        payload = row[7]
        record_mac = row[8]
        self._validate_identity(
            publication_id=publication_id,
            block=block,
            authorized_expires_at_block=authorized_expires_at_block,
        )
        self._payload_size(payload)
        if (
            len(payload_sha256) != 64
            or hashlib.sha256(payload.encode("ascii")).hexdigest() != payload_sha256
        ):
            raise RuntimeError("durable publication payload checksum is invalid")
        if record_mac:
            try:
                digest = bytes.fromhex(record_mac)
            except ValueError as exc:
                raise RuntimeError("durable publication record authenticator is malformed") from exc
            if len(record_mac) != 64 or len(digest) != hashlib.sha256().digest_size:
                raise RuntimeError("durable publication record authenticator is malformed")
            expected = self._record_mac(
                publication_id=publication_id,
                schema_version=row[1],
                block=block,
                authorized_expires_at_block=authorized_expires_at_block,
                committed=committed,
                drain_only=drain_only,
                payload_sha256=payload_sha256,
                payload=payload,
            )
            if not hmac.compare_digest(record_mac, expected):
                raise RuntimeError("durable publication record authenticator is invalid")
        return _StoredPublication(
            publication_id=publication_id,
            schema_version=row[1],
            block=block,
            authorized_expires_at_block=authorized_expires_at_block,
            committed=committed,
            drain_only=drain_only,
            payload_sha256=payload_sha256,
            payload=payload,
            record_mac=record_mac,
        )

    def save(
        self,
        *,
        publication_id: str,
        block: int,
        authorized_expires_at_block: int,
        payload: str,
        committed: bool,
        drain_only: bool,
    ) -> None:
        self._validate_identity(
            publication_id=publication_id,
            block=block,
            authorized_expires_at_block=authorized_expires_at_block,
        )
        if not isinstance(committed, bool) or not isinstance(drain_only, bool):
            raise RuntimeError("durable publication state marker is malformed")
        if not committed and drain_only:
            raise RuntimeError("uncommitted durable publication cannot be drain-only")
        payload_bytes = self._payload_size(payload)
        payload_sha256 = hashlib.sha256(payload.encode("ascii")).hexdigest()
        record_mac = self._record_mac(
            publication_id=publication_id,
            schema_version=PUBLICATION_LANE_SCHEMA_VERSION,
            block=block,
            authorized_expires_at_block=authorized_expires_at_block,
            committed=committed,
            drain_only=drain_only,
            payload_sha256=payload_sha256,
            payload=payload,
        )
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                """SELECT publication_id, schema_version, block,
                authorized_expires_at_block, committed, drain_only,
                payload_sha256, payload, record_mac
                FROM validator_publication_lanes WHERE publication_id=?""",
                (publication_id,),
            ).fetchone()
            if existing is not None:
                stored = self._record_from_row(existing)
                if (
                    stored.block != block
                    or stored.authorized_expires_at_block != authorized_expires_at_block
                    or stored.payload_sha256 != payload_sha256
                    or stored.payload != payload
                ):
                    raise RuntimeError("publication identity conflicts with durable exact tuple")
                if committed:
                    connection.execute(
                        """UPDATE validator_publication_lanes
                        SET committed=1, drain_only=?, record_mac=?
                        WHERE publication_id=?""",
                        (int(drain_only), record_mac, publication_id),
                    )
                elif not stored.authenticated:
                    raise RuntimeError(
                        "unauthenticated durable publication requires exact reconciliation"
                    )
            else:
                if committed:
                    connection.execute(
                        """DELETE FROM validator_publication_lanes
                        WHERE committed=0 AND publication_id<>?""",
                        (publication_id,),
                    )
                count, total_bytes = self._validate_bounds(connection)
                if count >= MAX_PERSISTED_PUBLICATIONS:
                    raise RuntimeError("durable publication history bound is exhausted")
                if total_bytes + payload_bytes > MAX_TOTAL_PUBLICATION_PAYLOAD_BYTES:
                    raise RuntimeError("durable publication payload total bound is exhausted")
                connection.execute(
                    """INSERT INTO validator_publication_lanes(
                    publication_id, schema_version, block,
                    authorized_expires_at_block, committed, drain_only,
                    payload_sha256, payload, record_mac) VALUES(?,?,?,?,?,?,?,?,?)""",
                    (
                        publication_id,
                        PUBLICATION_LANE_SCHEMA_VERSION,
                        block,
                        authorized_expires_at_block,
                        int(committed),
                        int(drain_only),
                        payload_sha256,
                        payload,
                        record_mac,
                    ),
                )
            if committed:
                previous_rows = connection.execute(
                    """SELECT publication_id, schema_version, block,
                    authorized_expires_at_block, committed, drain_only,
                    payload_sha256, payload, record_mac
                    FROM validator_publication_lanes
                    WHERE committed=1 AND publication_id<>?""",
                    (publication_id,),
                ).fetchall()
                for previous_row in previous_rows:
                    previous = self._record_from_row(previous_row)
                    if not previous.authenticated:
                        # A pre-authentication row is never promoted to trusted
                        # history merely because a different lane commits.
                        connection.execute(
                            "DELETE FROM validator_publication_lanes WHERE publication_id=?",
                            (previous.publication_id,),
                        )
                        continue
                    if previous.drain_only:
                        continue
                    previous_mac = self._record_mac(
                        publication_id=previous.publication_id,
                        schema_version=previous.schema_version,
                        block=previous.block,
                        authorized_expires_at_block=(previous.authorized_expires_at_block),
                        committed=True,
                        drain_only=True,
                        payload_sha256=previous.payload_sha256,
                        payload=previous.payload,
                    )
                    connection.execute(
                        """UPDATE validator_publication_lanes
                        SET drain_only=1, record_mac=? WHERE publication_id=?""",
                        (previous_mac, previous.publication_id),
                    )
                connection.execute(
                    """DELETE FROM validator_publication_lanes
                    WHERE committed=0 AND publication_id<>?""",
                    (publication_id,),
                )
            connection.commit()

    def load(self) -> list[_StoredPublication]:
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._validate_bounds(connection)
            rows = connection.execute(
                """SELECT publication_id, schema_version, block,
                authorized_expires_at_block, committed, drain_only,
                payload_sha256, payload, record_mac
                FROM validator_publication_lanes ORDER BY block, publication_id""",
            ).fetchall()
            connection.commit()
        return [self._record_from_row(row) for row in rows]

    def delete_uncommitted(self, publication_id: str) -> None:
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "DELETE FROM validator_publication_lanes WHERE publication_id=? AND committed=0",
                (publication_id,),
            )

    def delete_all_uncommitted(self) -> None:
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("DELETE FROM validator_publication_lanes WHERE committed=0")

    def delete_unauthenticated(self) -> None:
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("DELETE FROM validator_publication_lanes WHERE record_mac=''")

    def prune_expired(self, current_block: int, protected: set[str]) -> None:
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            if protected:
                placeholders = ",".join("?" for _ in protected)
                connection.execute(
                    f"""DELETE FROM validator_publication_lanes
                    WHERE authorized_expires_at_block<=?
                    AND publication_id NOT IN ({placeholders})""",  # noqa: S608
                    (current_block, *sorted(protected)),
                )
            else:
                connection.execute(
                    """DELETE FROM validator_publication_lanes
                    WHERE authorized_expires_at_block<=?""",
                    (current_block,),
                )


def _miner_set_publication_id(block: int, registrations: list[MinerRegistration]) -> str:
    """Match Go's versioned exact-identity publication digest."""

    identities = [
        {
            "hotkey": registration.hotkey,
            "uid": registration.uid,
            "axon_url": registration.axon_url,
            "service_key": registration.service_binding.service_public_key,
            "transport": registration.service_binding.transport,
            "tls_pin": registration.service_binding.transport_certificate_sha256,
        }
        for registration in sorted(registrations, key=lambda item: item.hotkey)
    ]
    payload = json.dumps(
        {"version": 1, "block": block, "miners": identities},
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


@dataclass(frozen=True, slots=True)
class DiscoveryBackoff:
    failures: int
    retry_at_round: int


@dataclass(frozen=True, slots=True)
class AdmissionStats:
    candidate_count: int
    invalid_axon: int
    conflicted_hotkey: int
    conflicted_uid: int
    conflicted_axon: int


class ValidatorNeuron:
    def __init__(
        self,
        *,
        chain: ChainQuery,
        hotkey_signer: HotkeySigningFacade,
        network: str,
        netuid: int,
        bridge: BridgeClient,
        bridge_secret: bytes,
        state_db: str,
        bridge_url: str,
        sync_interval: float,
        dendrite_timeout: float,
        dendrite_retries: int,
        weight_interval: float,
        version_key: int,
        weight_plan_path: str | None = None,
        allow_private_axons: bool = False,
        mock_http_axons: bool = False,
        dendrite_transport: httpx.AsyncBaseTransport | None = None,
        discovery_concurrency: int = 16,
        discovery_max_attempts: int = 64,
        discovery_attempt_timeout: float = 10.0,
        discovery_refresh_timeout: float = 30.0,
        discovery_backoff_base_rounds: int = 1,
        discovery_backoff_max_rounds: int = 16,
    ) -> None:
        if discovery_concurrency < 1:
            raise ValueError("discovery concurrency must be positive")
        if discovery_max_attempts < 1:
            raise ValueError("discovery max attempts must be positive")
        if discovery_attempt_timeout <= 0 or discovery_refresh_timeout <= 0:
            raise ValueError("discovery timeouts must be positive")
        if discovery_backoff_base_rounds < 1:
            raise ValueError("discovery backoff base must be positive")
        if discovery_backoff_max_rounds < discovery_backoff_base_rounds:
            raise ValueError("discovery backoff max must not be smaller than its base")
        if dendrite_transport is not None and not mock_http_axons:
            raise ValueError("custom dendrite transports are restricted to explicit mock HTTP")
        if (
            isinstance(sync_interval, bool)
            or not isinstance(sync_interval, (int, float))
            or isinstance(weight_interval, bool)
            or not isinstance(weight_interval, (int, float))
            or not math.isfinite(float(sync_interval))
            or not math.isfinite(float(weight_interval))
            or sync_interval <= 0
            or weight_interval <= 0
        ):
            raise ValueError("sync and weight-plan intervals must be positive")
        if (
            isinstance(version_key, bool)
            or not isinstance(version_key, int)
            or not 0 <= version_key <= (1 << 64) - 1
        ):
            raise ValueError("weight-plan version key must be an unsigned 64-bit integer")
        self.chain = chain
        self.hotkey_signer = hotkey_signer
        self.hotkey = hotkey_signer.hotkey
        self.network = network
        self.netuid = netuid
        self.bridge = bridge
        self.bridge_secret = bridge_secret
        self.bridge_replay = SQLiteBridgeReplay(state_db)
        self.bridge_url = bridge_url.rstrip("/")
        self._publication_store = _PublicationLaneStore(
            state_db,
            authentication_secret=bridge_secret,
            network=network,
            netuid=netuid,
            validator_hotkey=self.hotkey,
        )
        self.sync_interval = sync_interval
        self.dendrite_timeout = dendrite_timeout
        self.dendrite_retries = dendrite_retries
        self.weight_interval = weight_interval
        self.version_key = version_key
        self.weight_plan_path = weight_plan_path
        self.allow_private_axons = allow_private_axons
        self.mock_http_axons = mock_http_axons
        self.dendrite_transport = dendrite_transport
        self.discovery_concurrency = discovery_concurrency
        self.discovery_max_attempts = discovery_max_attempts
        self.discovery_attempt_timeout = discovery_attempt_timeout
        self.discovery_refresh_timeout = discovery_refresh_timeout
        self.discovery_backoff_base_rounds = discovery_backoff_base_rounds
        self.discovery_backoff_max_rounds = discovery_backoff_max_rounds
        self.state = MetagraphState()
        self.ready = asyncio.Event()
        self.fully_synced = asyncio.Event()
        self.stop = asyncio.Event()
        self._miners: dict[str, RemoteMiner] = {}
        # Go commits a chain/miner pair only when it accepts the exact miner-set
        # publication. Keep the Python snapshot and validator binding from that
        # same transaction under _lock instead of consulting the newer staging
        # metagraph while Go can still issue tickets from the prior pair.
        self._committed_snapshot: MetagraphSnapshot | None = None
        self._committed_validator_binding: ServiceKeyBinding | None = None
        self._inventory_committed_handles: set[int] = set()
        self._committed_publication: _PublicationLane | None = None
        # Staged before Go installs the matching scheduler set. Ticket-exact
        # bridge resolution consults both maps until publication is acknowledged.
        self._staged_miners: dict[str, RemoteMiner] | None = None
        self._staged_miner_block: int | None = None
        self._staged_snapshot: MetagraphSnapshot | None = None
        self._staged_validator_binding: ServiceKeyBinding | None = None
        self._staged_publication: _PublicationLane | None = None
        # Every superseded Go publication retains one immutable, coherent
        # snapshot/miner/validator tuple. This includes publications whose
        # miner transport envelopes are byte-for-byte unchanged.
        self._historical_publications: list[_PublicationLane] = []
        # Rows written before complete-record authentication are parsed and
        # signature-checked but confer no authority. Exact Go inventory may
        # reconcile one current lane; otherwise they remain fail-closed.
        self._quarantined_publications: dict[str, _PublicationLane] = {}
        # A staged record is durable before the Go POST. After response loss it
        # remains non-authoritative until exact inventory reconciliation proves
        # that Go committed that publication.
        self._ambiguous_publications: dict[str, _PublicationLane] = {}
        # Last-known authenticated transport handles, retained across discovery
        # refreshes so cleanup of an exact issued ticket survives a transient
        # handshake failure. They authorize work only when an exact Go inventory
        # acknowledgement proves the handle was committed before a Python restart.
        self._cleanup_miners: dict[str, RemoteMiner] = {}
        self._validator_binding: ServiceKeyBinding | None = None
        self._lock = asyncio.Lock()
        # Publication calls are serialized across response loss/cancellation.
        # A later refresh must reconcile the one retained ambiguous stage
        # before it can install a replacement lane.
        self._publication_lock = asyncio.Lock()
        self._discovery_round = 0
        self._discovery_queue: deque[DiscoveryIdentity] = deque()
        self._discovery_backoff: dict[DiscoveryIdentity, DiscoveryBackoff] = {}
        self._discovery_inflight: set[DiscoveryIdentity] = set()
        self._last_weight_plan_block = -1
        self._restore_durable_publications()
        self.app = FastAPI(lifespan=self._lifespan)
        self.app.add_exception_handler(HTTPException, self._http_error)
        self.app.add_exception_handler(ValidationError, self._validation_error)
        self._routes()

    @staticmethod
    async def _http_error(_: Request, exc: Exception) -> JSONResponse:
        assert isinstance(exc, HTTPException)
        message = str(exc.detail)[:512]
        codes = {
            400: "invalid_request",
            401: "unauthorized",
            403: "identity_mismatch",
            404: "not_found",
            409: "stale_or_replayed",
            413: "request_too_large",
            422: "request_rejected",
            429: "rate_limited",
            502: "dendrite_upstream",
            503: "not_ready",
            504: "dendrite_timeout",
        }
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": {
                    "code": codes.get(exc.status_code, "bridge_error"),
                    "message": message,
                    "retryable": exc.status_code in {429, 502, 503, 504},
                }
            },
        )

    @staticmethod
    async def _validation_error(_: Request, exc: Exception) -> JSONResponse:
        assert isinstance(exc, ValidationError)
        return JSONResponse(
            status_code=400,
            content={
                "error": {
                    "code": "invalid_request",
                    "message": "request does not match the bridge contract",
                    "retryable": False,
                }
            },
        )

    @asynccontextmanager
    async def _lifespan(self, _: FastAPI) -> AsyncIterator[None]:
        await self.chain.open()
        task = asyncio.create_task(self._block_loop(), name="validator-block-loop")
        try:
            yield
        finally:
            self.stop.set()
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
            await self.chain.close()

    async def _block_loop(self) -> None:
        while not self.stop.is_set():
            try:
                snapshot = await self.chain.sync()
                validator, candidates, admission = self._admit_snapshot(snapshot)
                # Admission and monotonic/reorg checks run before either local
                # plane stages the new snapshot. A rejected chain view can
                # therefore never displace the last committed scheduling view.
                await self.state.set(snapshot)
                self._log_admission(snapshot, admission)
                capabilities = await self.bridge.request(
                    "GET", "/v1/capabilities", response_model=ControlCapabilities
                )
                assert isinstance(capabilities, ControlCapabilities)
                validator_binding = sign_service_binding(
                    ServiceKeyBinding(
                        role="validator",
                        transport="local",
                        transport_certificate_sha256=None,
                        network=self.network,
                        netuid=self.netuid,
                        hotkey=self.hotkey,
                        uid=validator.uid,
                        service_public_key=capabilities.service_public_key,
                        generation=snapshot.block + 1,
                        valid_from_block=snapshot.block,
                        expires_at_block=snapshot.block + max(snapshot.tempo * 2, 12),
                        challenge="validator-service:" + capabilities.service_public_key,
                    ),
                    self.hotkey_signer,
                )
                await self.bridge.request(
                    "POST",
                    "/v1/chain-state",
                    value=ChainState(
                        protocol=SYNAPSE_VERSION,
                        network=self.network,
                        netuid=self.netuid,
                        block=snapshot.block,
                        epoch=snapshot.epoch,
                        tempo=snapshot.tempo,
                        validator_hotkey=self.hotkey,
                        validator_binding=validator_binding,
                    ),
                )
                async with self._lock:
                    self._validator_binding = validator_binding
                # Restart recovery may synchronously call this bridge while a
                # miner is being registered, so the authenticated local plane
                # must be ready before discovery posts registrations to Go.
                self.ready.set()
                discovered = await self._discover_miners(snapshot, candidates=candidates)
                await self._publish_miner_snapshot(
                    snapshot,
                    discovered,
                    validator_binding=validator_binding,
                )
                self.fully_synced.set()
                LOGGER.info(
                    "validator block synchronized",
                    extra={
                        "hotkey": self.hotkey,
                        "block": snapshot.block,
                        "finalized": snapshot.finalized,
                    },
                )
                if snapshot.block != self._last_weight_plan_block:
                    try:
                        await self._prepare_weight_plan(snapshot)
                    except Exception:
                        # Invalid scoring data or an unsafe output target must
                        # produce no plan, but it must not revoke an already
                        # authenticated scheduling/discovery publication.
                        LOGGER.exception(
                            "weight plan preparation failed closed",
                            extra={"block": snapshot.block, "netuid": self.netuid},
                        )
            except Exception:
                async with self._lock:
                    has_committed_view = self._committed_publication is not None
                if not has_committed_view:
                    self.ready.clear()
                    self.fully_synced.clear()
                LOGGER.exception("validator block loop failed")
            try:
                await asyncio.wait_for(self.stop.wait(), timeout=self.sync_interval)
            except TimeoutError:
                pass

    def _admit_snapshot(
        self, snapshot: MetagraphSnapshot
    ) -> tuple[NeuronRecord, tuple[DiscoveryCandidate, ...], AdmissionStats]:
        """Validate identity records and quarantine peer-record conflicts.

        The validator identity itself must be globally unambiguous. Conflicts
        confined to miner records are failed closed as a group instead of
        letting one miner cause a discovery-wide outage. No stake, owner, or
        configured hotkey list participates in candidate selection.
        """
        if snapshot.network != self.network or snapshot.netuid != self.netuid:
            raise RuntimeError("metagraph identity differs from configured subnet")
        active = tuple(neuron for neuron in snapshot.neurons if neuron.active)
        hotkey_counts = Counter(neuron.hotkey for neuron in active)
        uid_counts = Counter(neuron.uid for neuron in active)
        validator_matches = tuple(neuron for neuron in active if neuron.hotkey == self.hotkey)
        if len(validator_matches) != 1:
            raise RuntimeError("validator hotkey identity is missing or duplicated")
        validator = validator_matches[0]
        if not validator.validator_permit:
            raise RuntimeError("validator hotkey is not active with a validator permit")
        if not 0 <= validator.uid <= 65_535 or uid_counts[validator.uid] != 1:
            raise RuntimeError("validator UID identity conflicts in metagraph")

        normalized: list[DiscoveryCandidate] = []
        axon_counts: Counter[str] = Counter()
        invalid_axon = 0
        for neuron in active:
            if not neuron.axon:
                if neuron.hotkey != self.hotkey:
                    invalid_axon += 1
                continue
            try:
                axon_url = _axon_url(
                    neuron.axon,
                    allow_private=self.allow_private_axons,
                    mock_http=self.mock_http_axons,
                )
            except ValueError:
                if neuron.hotkey != self.hotkey:
                    invalid_axon += 1
                continue
            # Axons are scheduling identities even on the configured
            # validator's own record or malformed peer records, so any
            # candidate sharing one fails closed. A chain-assigned validator
            # permit is deliberately not a miner-role filter: only this
            # validator's exact hotkey is excluded from candidate admission.
            axon_counts[axon_url] += 1
            if neuron.hotkey == self.hotkey:
                continue
            if not neuron.hotkey or not 0 <= neuron.uid <= 65_535:
                invalid_axon += 1
                continue
            normalized.append(DiscoveryCandidate(neuron=neuron, axon_url=axon_url))

        candidates = tuple(
            sorted(
                (
                    candidate
                    for candidate in normalized
                    if hotkey_counts[candidate.neuron.hotkey] == 1
                    and uid_counts[candidate.neuron.uid] == 1
                    and axon_counts[candidate.axon_url] == 1
                ),
                key=lambda candidate: (candidate.neuron.uid, candidate.neuron.hotkey),
            )
        )
        return (
            validator,
            candidates,
            AdmissionStats(
                candidate_count=len(candidates),
                invalid_axon=invalid_axon,
                conflicted_hotkey=sum(count for count in hotkey_counts.values() if count > 1),
                conflicted_uid=sum(count for count in uid_counts.values() if count > 1),
                conflicted_axon=sum(count for count in axon_counts.values() if count > 1),
            ),
        )

    @staticmethod
    def _log_admission(snapshot: MetagraphSnapshot, stats: AdmissionStats) -> None:
        if not (
            stats.invalid_axon
            or stats.conflicted_hotkey
            or stats.conflicted_uid
            or stats.conflicted_axon
        ):
            return
        LOGGER.warning(
            "metagraph records quarantined",
            extra={
                "block": snapshot.block,
                "candidate_count": stats.candidate_count,
                "invalid_axon_count": stats.invalid_axon,
                "hotkey_conflict_count": stats.conflicted_hotkey,
                "uid_conflict_count": stats.conflicted_uid,
                "axon_conflict_count": stats.conflicted_axon,
            },
        )

    async def _discover_miners(
        self,
        snapshot: MetagraphSnapshot,
        *,
        candidates: tuple[DiscoveryCandidate, ...] | None = None,
    ) -> dict[str, RemoteMiner]:
        """Refresh capability bindings with bounded work and fair rotation."""
        started = time.monotonic()
        deadline = started + self.discovery_refresh_timeout
        if candidates is None:
            _, candidates, admission = self._admit_snapshot(snapshot)
            self._log_admission(snapshot, admission)
        self._discovery_round += 1
        round_number = self._discovery_round
        candidate_by_identity = {candidate.identity: candidate for candidate in candidates}
        identities = set(candidate_by_identity)

        # Preserve queue order for surviving identities and append new/rebound
        # identities deterministically. Each claim scans by rotating inspected
        # identities; a full scan of skipped identities restores their order,
        # while a successful claim leaves the next identity at the head. Thus
        # the next refresh resumes after the last claimed prefix even when the
        # whole-refresh deadline cancels its workers.
        self._discovery_queue = deque(
            identity for identity in self._discovery_queue if identity in identities
        )
        queued = set(self._discovery_queue)
        for candidate in candidates:
            if candidate.identity not in queued:
                self._discovery_queue.append(candidate.identity)
                queued.add(candidate.identity)
        self._discovery_backoff = {
            identity: backoff
            for identity, backoff in self._discovery_backoff.items()
            if identity in identities
        }

        async with self._lock:
            published = dict(self._miners)
        discovered = {
            candidate.neuron.hotkey: prior
            for candidate in candidates
            if (prior := published.get(candidate.neuron.hotkey)) is not None
            and candidate.identity not in self._discovery_backoff
            and self._remote_matches_candidate(prior, candidate)
            and snapshot.block < prior.binding.expires_at_block
        }

        attempted = 0
        claimed_identities: set[DiscoveryIdentity] = set()
        succeeded: set[str] = set()
        failures: list[tuple[int, str, str]] = []
        backoff_skipped: set[DiscoveryIdentity] = set()

        def claim() -> DiscoveryCandidate | None:
            nonlocal attempted
            if attempted >= self.discovery_max_attempts:
                return None
            for _ in range(len(self._discovery_queue)):
                identity = self._discovery_queue.popleft()
                self._discovery_queue.append(identity)
                candidate = candidate_by_identity.get(identity)
                if candidate is None or identity in claimed_identities:
                    continue
                backoff = self._discovery_backoff.get(identity)
                if backoff is not None and round_number < backoff.retry_at_round:
                    backoff_skipped.add(identity)
                    continue
                attempted += 1
                claimed_identities.add(identity)
                return candidate
            return None

        def fail(candidate: DiscoveryCandidate, kind: str) -> None:
            previous = self._discovery_backoff.get(candidate.identity)
            failure_count = (previous.failures if previous is not None else 0) + 1
            exponent = min(failure_count - 1, 30)
            delay = min(
                self.discovery_backoff_max_rounds,
                self.discovery_backoff_base_rounds * (1 << exponent),
            )
            self._discovery_backoff[candidate.identity] = DiscoveryBackoff(
                failures=failure_count,
                retry_at_round=round_number + delay + 1,
            )
            failures.append((candidate.neuron.uid, candidate.neuron.hotkey, kind))

        async def attempt(candidate: DiscoveryCandidate) -> RemoteMiner:
            result = await self._handshake(snapshot, candidate.neuron)
            # Retain the authenticated cleanup handle before Go learns about
            # the registration: restart recovery may synchronously call back
            # into the deactivate bridge while registration is in flight.
            async with self._lock:
                prior_cleanup = self._cleanup_miners.get(candidate.neuron.hotkey)
                self._cleanup_miners[candidate.neuron.hotkey] = result
            registration = self._registration_for(
                result,
                network=self.network,
                netuid=self.netuid,
                bridge_url=self.bridge_url,
            )
            try:
                await self.bridge.request(
                    "POST",
                    "/v1/miners",
                    value=registration,
                )
            except BridgeError:
                # A structured, non-retryable response proves that Go did not
                # commit this registration. Roll the temporary callback
                # handle back to the exact prior accepted identity.
                async with self._lock:
                    if self._cleanup_miners.get(candidate.neuron.hotkey) is result:
                        if prior_cleanup is None:
                            self._cleanup_miners.pop(candidate.neuron.hotkey, None)
                        else:
                            self._cleanup_miners[candidate.neuron.hotkey] = prior_cleanup
                raise
            except asyncio.CancelledError as exc:
                # Cancellation can race after Go's durable commit but before
                # its response reaches Python. Abort the whole publication;
                # never send a snapshot that could discard the committed pin.
                raise _AmbiguousMinerRegistration(
                    "miner registration completion is ambiguous"
                ) from exc
            except Exception as exc:
                try:
                    if await self._registration_is_published(registration):
                        return result
                except asyncio.CancelledError as cancelled:
                    raise _AmbiguousMinerRegistration(
                        "miner registration completion is ambiguous"
                    ) from cancelled
                except Exception:
                    raise _AmbiguousMinerRegistration(
                        "miner registration completion is ambiguous"
                    ) from exc
                # A transport/retryable failure is not proof that Go rolled
                # back: its atomic commit precedes the HTTP response. Keep the
                # exact staged cleanup handle and abort this refresh. A later
                # exact readback/re-registration reconciles both planes.
                raise _AmbiguousMinerRegistration(
                    "miner registration completion is ambiguous"
                ) from exc
            return result

        async def worker() -> None:
            while (candidate := claim()) is not None:
                # An unresolved refresh is not evidence that an exact,
                # unexpired carried binding became unsafe. Explicit attempt
                # failure evicts it below; cancellation leaves it unchanged.
                self._discovery_inflight.add(candidate.identity)
                try:
                    result = await asyncio.wait_for(
                        attempt(candidate), timeout=self.discovery_attempt_timeout
                    )
                except _AmbiguousMinerRegistration:
                    raise
                except asyncio.CancelledError:
                    # The enclosing whole-refresh deadline (or caller
                    # shutdown) cancelled an otherwise unresolved worker. It
                    # neither invalidates an exact carried binding nor counts
                    # as miner failure/backoff.
                    raise
                except Exception as exc:
                    discovered.pop(candidate.neuron.hotkey, None)
                    fail(candidate, self._discovery_failure_kind(exc))
                else:
                    discovered[candidate.neuron.hotkey] = result
                    succeeded.add(candidate.neuron.hotkey)
                    self._discovery_backoff.pop(candidate.identity, None)
                finally:
                    self._discovery_inflight.discard(candidate.identity)

        worker_count = min(
            self.discovery_concurrency,
            self.discovery_max_attempts,
            len(candidates),
        )
        workers = [
            asyncio.create_task(worker(), name=f"miner-discovery-{index}")
            for index in range(worker_count)
        ]
        timed_out = False
        if workers:
            try:
                _, pending = await asyncio.wait(
                    workers, timeout=max(0.0, deadline - time.monotonic())
                )
            except asyncio.CancelledError:
                for task in workers:
                    task.cancel()
                await asyncio.gather(*workers, return_exceptions=True)
                raise
            timed_out = bool(pending)
            for task in pending:
                task.cancel()
            worker_results = await asyncio.gather(*workers, return_exceptions=True)
            ambiguity = next(
                (
                    result
                    for result in worker_results
                    if isinstance(result, _AmbiguousMinerRegistration)
                ),
                None,
            )
            if ambiguity is not None:
                raise ambiguity

        await self._prune_cleanup_handles(snapshot)
        for _, hotkey, kind in sorted(failures)[:DISCOVERY_FAILURE_LOG_LIMIT]:
            LOGGER.warning(
                "miner capability refresh failed",
                extra={
                    "hotkey": hotkey,
                    "block": snapshot.block,
                    "discovery_failure": kind,
                },
            )
        LOGGER.info(
            "miner discovery refresh completed",
            extra={
                "block": snapshot.block,
                "candidate_count": len(candidates),
                "attempt_count": attempted,
                "success_count": len(succeeded),
                "failure_count": len(failures),
                "carried_count": len(discovered) - len(succeeded),
                "backoff_count": len(backoff_skipped),
                "elapsed_ms": min(int((time.monotonic() - started) * 1000), 2_147_483_647),
                "refresh_timed_out": timed_out,
            },
        )
        return discovered

    @staticmethod
    def _registration_for(
        remote: RemoteMiner, *, network: str, netuid: int, bridge_url: str
    ) -> MinerRegistration:
        return MinerRegistration(
            protocol=SYNAPSE_VERSION,
            network=network,
            netuid=netuid,
            hotkey=remote.neuron.hotkey,
            uid=remote.neuron.uid,
            axon_url=remote.axon_url,
            bridge_url=bridge_url,
            service_binding=remote.binding,
            transport_certificate_der_base64=(
                ""
                if remote.certificate_der is None
                else base64.b64encode(remote.certificate_der).decode("ascii")
            ),
        )

    def _new_publication_lane(
        self,
        snapshot: MetagraphSnapshot,
        miners: dict[str, RemoteMiner],
        validator_binding: ServiceKeyBinding,
        *,
        drain_only: bool,
    ) -> _PublicationLane:
        if (
            not isinstance(snapshot.block, int)
            or isinstance(snapshot.block, bool)
            or not 0 <= snapshot.block <= MAX_SQLITE_INTEGER
            or not isinstance(snapshot.tempo, int)
            or isinstance(snapshot.tempo, bool)
            or snapshot.tempo < 1
            or not isinstance(snapshot.finalized, bool)
            or len(snapshot.neurons) > MAX_PUBLICATION_NEURONS
            or len(miners) > MAX_PUBLICATION_MINERS
        ):
            raise RuntimeError("publication snapshot exceeds its deterministic bounds")
        validator, candidates, _ = self._admit_snapshot(snapshot)
        candidates_by_hotkey = {candidate.neuron.hotkey: candidate for candidate in candidates}
        if (
            snapshot.network != self.network
            or snapshot.netuid != self.netuid
            or validator_binding.role != "validator"
            or validator_binding.network != self.network
            or validator_binding.netuid != self.netuid
            or validator_binding.hotkey != self.hotkey
            or validator_binding.uid != validator.uid
            or not (
                validator_binding.valid_from_block
                <= snapshot.block
                < validator_binding.expires_at_block
            )
        ):
            raise RuntimeError("publication validator tuple is not coherent")
        ordered = tuple(sorted(miners.items()))
        for hotkey, remote in ordered:
            candidate = candidates_by_hotkey.get(hotkey)
            if (
                hotkey != remote.neuron.hotkey
                or candidate is None
                or candidate.neuron != remote.neuron
                or candidate.axon_url != remote.axon_url
                or not self._remote_matches_candidate(remote, candidate)
                or remote.binding.role != "miner"
                or remote.binding.hotkey != hotkey
                or remote.binding.uid != remote.neuron.uid
                or remote.binding.network != self.network
                or remote.binding.netuid != self.netuid
                or (
                    remote.certificate_der is not None
                    and len(remote.certificate_der) > MAX_CERTIFICATE_BYTES
                )
                or not (
                    remote.binding.valid_from_block
                    <= snapshot.block
                    < remote.binding.expires_at_block
                )
            ):
                raise RuntimeError("publication miner tuple is not coherent")
        registrations = [
            self._registration_for(
                remote,
                network=self.network,
                netuid=self.netuid,
                bridge_url=self.bridge_url,
            )
            for _, remote in ordered
        ]
        ticket_expires_at_block = min(
            snapshot.block + max(snapshot.tempo, 12),
            validator_binding.expires_at_block,
            MAX_SQLITE_INTEGER,
        )
        if ticket_expires_at_block <= snapshot.block:
            raise RuntimeError("publication ticket window is empty")
        return _PublicationLane(
            publication_id=_miner_set_publication_id(snapshot.block, registrations),
            snapshot=snapshot,
            validator_binding=validator_binding,
            miners=ordered,
            ticket_expires_at_block=ticket_expires_at_block,
            drain_only=drain_only,
        )

    @staticmethod
    def _neuron_payload(neuron: NeuronRecord) -> dict[str, Any]:
        return {
            "uid": neuron.uid,
            "hotkey": neuron.hotkey,
            "validator_permit": neuron.validator_permit,
            "tao_stake": float(neuron.tao_stake),
            "axon": neuron.axon,
            "active": neuron.active,
        }

    def _publication_payload(self, lane: _PublicationLane) -> str:
        payload = {
            "version": 1,
            "publication_id": lane.publication_id,
            "snapshot": {
                "network": lane.snapshot.network,
                "netuid": lane.snapshot.netuid,
                "block": lane.snapshot.block,
                "tempo": lane.snapshot.tempo,
                "finalized": lane.snapshot.finalized,
                "neurons": [self._neuron_payload(neuron) for neuron in lane.snapshot.neurons],
            },
            "validator_binding": lane.validator_binding.model_dump(mode="json"),
            "miners": [
                {
                    "hotkey": hotkey,
                    "neuron": self._neuron_payload(remote.neuron),
                    "axon_url": remote.axon_url,
                    "binding": remote.binding.model_dump(mode="json"),
                    "certificate_der_base64": (
                        None
                        if remote.certificate_der is None
                        else base64.b64encode(remote.certificate_der).decode("ascii")
                    ),
                }
                for hotkey, remote in lane.miners
            ],
            "ticket_expires_at_block": lane.ticket_expires_at_block,
        }
        encoded = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        if len(encoded) > MAX_PUBLICATION_PAYLOAD_BYTES:
            raise RuntimeError("publication payload exceeds its deterministic bound")
        return encoded

    @staticmethod
    def _neuron_from_payload(value: Any) -> NeuronRecord:
        if not isinstance(value, dict):
            raise RuntimeError("durable publication neuron is malformed")
        uid = value.get("uid")
        hotkey = value.get("hotkey")
        validator_permit = value.get("validator_permit")
        tao_stake = value.get("tao_stake")
        axon = value.get("axon")
        active = value.get("active")
        if (
            not isinstance(uid, int)
            or isinstance(uid, bool)
            or not 0 <= uid <= 65_535
            or not isinstance(hotkey, str)
            or not hotkey
            or not isinstance(validator_permit, bool)
            or not isinstance(tao_stake, int | float)
            or isinstance(tao_stake, bool)
            or not math.isfinite(float(tao_stake))
            or (axon is not None and (not isinstance(axon, str) or not axon))
            or not isinstance(active, bool)
        ):
            raise RuntimeError("durable publication neuron is malformed")
        return NeuronRecord(
            uid=uid,
            hotkey=hotkey,
            validator_permit=validator_permit,
            tao_stake=float(tao_stake),
            axon=axon,
            active=active,
        )

    def _publication_from_record(self, record: _StoredPublication) -> _PublicationLane:
        try:
            raw = json.loads(record.payload)
        except (json.JSONDecodeError, RecursionError) as exc:
            raise RuntimeError("durable publication payload is malformed") from exc
        if not isinstance(raw, dict) or raw.get("version") != 1:
            raise RuntimeError("durable publication payload version is unsupported")
        snapshot_raw = raw.get("snapshot")
        miners_raw = raw.get("miners")
        if not isinstance(snapshot_raw, dict) or not isinstance(miners_raw, list):
            raise RuntimeError("durable publication tuple is malformed")
        network = snapshot_raw.get("network")
        netuid = snapshot_raw.get("netuid")
        block = snapshot_raw.get("block")
        tempo = snapshot_raw.get("tempo")
        finalized = snapshot_raw.get("finalized")
        neurons_raw = snapshot_raw.get("neurons")
        if (
            not isinstance(network, str)
            or not network
            or network != self.network
            or not isinstance(netuid, int)
            or isinstance(netuid, bool)
            or netuid != self.netuid
            or not isinstance(block, int)
            or isinstance(block, bool)
            or not 0 <= block <= MAX_SQLITE_INTEGER
            or not isinstance(tempo, int)
            or isinstance(tempo, bool)
            or tempo < 1
            or not isinstance(finalized, bool)
            or not isinstance(neurons_raw, list)
            or len(neurons_raw) > MAX_PUBLICATION_NEURONS
            or len(miners_raw) > MAX_PUBLICATION_MINERS
        ):
            raise RuntimeError("durable publication snapshot is malformed")
        snapshot = MetagraphSnapshot(
            network=network,
            netuid=netuid,
            block=block,
            tempo=tempo,
            neurons=tuple(self._neuron_from_payload(item) for item in neurons_raw),
            finalized=finalized,
        )
        try:
            validator_binding = ServiceKeyBinding.model_validate(raw.get("validator_binding"))
        except ValidationError as exc:
            raise RuntimeError("durable validator binding is malformed") from exc
        remotes: dict[str, RemoteMiner] = {}
        for item in miners_raw:
            if not isinstance(item, dict):
                raise RuntimeError("durable publication miner is malformed")
            hotkey = item.get("hotkey")
            axon_url = item.get("axon_url")
            certificate_value = item.get("certificate_der_base64")
            if (
                not isinstance(hotkey, str)
                or not hotkey
                or hotkey in remotes
                or not isinstance(axon_url, str)
                or not axon_url
                or (certificate_value is not None and not isinstance(certificate_value, str))
            ):
                raise RuntimeError("durable publication miner is malformed")
            try:
                binding = ServiceKeyBinding.model_validate(item.get("binding"))
                certificate_der = (
                    None
                    if certificate_value is None
                    else base64.b64decode(certificate_value, validate=True)
                )
            except (ValidationError, ValueError) as exc:
                raise RuntimeError("durable publication miner binding is malformed") from exc
            remote_neuron = self._neuron_from_payload(item.get("neuron"))
            if remote_neuron.hotkey != hotkey:
                raise RuntimeError("durable publication miner hotkey conflicts")
            remotes[hotkey] = RemoteMiner(
                neuron=remote_neuron,
                axon_url=axon_url,
                binding=binding,
                certificate_der=certificate_der,
            )
        lane = self._new_publication_lane(
            snapshot,
            remotes,
            validator_binding,
            drain_only=True,
        )
        if (
            raw.get("publication_id") != lane.publication_id
            or raw.get("ticket_expires_at_block") != lane.ticket_expires_at_block
            or record.publication_id != lane.publication_id
            or record.block != lane.snapshot.block
            or record.authorized_expires_at_block != lane.authorized_expires_at_block
            or self._publication_payload(lane) != record.payload
        ):
            raise RuntimeError("durable publication exact tuple failed integrity checks")
        return lane

    def _verify_restored_publication(
        self,
        lane: _PublicationLane,
        verified: set[tuple[str, bytes, str]],
    ) -> None:
        bindings = (lane.validator_binding, *(remote.binding for _, remote in lane.miners))
        for binding in bindings:
            key = (binding.hotkey, binding.signing_payload(), binding.signature)
            if key in verified:
                continue
            try:
                verify_service_binding(
                    binding,
                    expected_hotkey=binding.hotkey,
                    expected_role=binding.role,
                    expected_network=self.network,
                    expected_netuid=self.netuid,
                    expected_challenge=binding.challenge,
                    expected_transport=binding.transport,
                    expected_transport_certificate_sha256=(binding.transport_certificate_sha256),
                    current_block=lane.snapshot.block,
                )
            except ValueError as exc:
                raise RuntimeError("durable publication binding signature is invalid") from exc
            verified.add(key)

    def _persist_publication(
        self,
        lane: _PublicationLane,
        *,
        committed: bool,
        drain_only: bool,
    ) -> None:
        self._publication_store.save(
            publication_id=lane.publication_id,
            block=lane.snapshot.block,
            authorized_expires_at_block=lane.authorized_expires_at_block,
            payload=self._publication_payload(lane),
            committed=committed,
            drain_only=drain_only,
        )

    def _restore_durable_publications(self) -> None:
        records = self._publication_store.load()
        authenticated = [record for record in records if record.authenticated]
        committed_count = sum(record.committed for record in authenticated)
        ambiguous_count = len(authenticated) - committed_count
        if committed_count > MAX_HISTORICAL_PUBLICATIONS + 1:
            raise RuntimeError("durable committed publication history exceeds its bound")
        if ambiguous_count > 1:
            raise RuntimeError("durable publication state has conflicting ambiguous rows")
        if sum(record.committed and not record.drain_only for record in authenticated) > 1:
            raise RuntimeError("durable publication state has conflicting current rows")
        verified: set[tuple[str, bytes, str]] = set()
        for record in records:
            lane = self._publication_from_record(record)
            self._verify_restored_publication(lane, verified)
            if not record.authenticated:
                self._quarantined_publications[lane.publication_id] = replace(lane, drain_only=True)
            elif record.committed:
                self._historical_publications.append(replace(lane, drain_only=True))
            else:
                self._ambiguous_publications[lane.publication_id] = replace(lane, drain_only=False)
        self._historical_publications.sort(
            key=lambda item: (item.snapshot.block, item.publication_id)
        )

    def _prune_historical_publications_locked(self, current_block: int) -> None:
        self._historical_publications = [
            lane
            for lane in self._historical_publications
            if current_block < lane.authorized_expires_at_block
        ]
        transient_limit = MAX_HISTORICAL_PUBLICATIONS + int(self._committed_publication is None)
        if len(self._historical_publications) > transient_limit:
            raise RuntimeError("unexpired publication history exceeds its deterministic bound")
        protected = set(self._ambiguous_publications)
        if self._committed_publication is not None:
            protected.add(self._committed_publication.publication_id)
        if self._staged_publication is not None:
            protected.add(self._staged_publication.publication_id)
        self._publication_store.prune_expired(current_block, protected)

    def _ensure_historical_capacity_locked(self, replacement: _PublicationLane) -> None:
        self._prune_historical_publications_locked(replacement.snapshot.block)
        prior = self._committed_publication
        retained = sum(
            lane.publication_id != replacement.publication_id
            for lane in self._historical_publications
        )
        additional = int(
            prior is not None
            and prior.publication_id != replacement.publication_id
            and replacement.snapshot.block < prior.authorized_expires_at_block
        )
        if retained + additional > MAX_HISTORICAL_PUBLICATIONS:
            raise RuntimeError("unexpired publication history bound is exhausted")

    def _stage_publication_locked(
        self,
        snapshot: MetagraphSnapshot,
        stage: dict[str, RemoteMiner],
        validator_binding: ServiceKeyBinding | None = None,
    ) -> _PublicationLane:
        if (
            self._staged_publication is not None
            or self._ambiguous_publications
            or self._quarantined_publications
        ):
            raise RuntimeError("another publication must be reconciled before staging")
        validator_binding = validator_binding or self._validator_binding
        if validator_binding is None:
            raise RuntimeError("validator service binding is unavailable for publication")
        lane = self._new_publication_lane(
            snapshot,
            stage,
            validator_binding,
            drain_only=False,
        )
        self._ensure_historical_capacity_locked(lane)
        self._persist_publication(lane, committed=False, drain_only=False)
        self._ambiguous_publications[lane.publication_id] = lane
        self._staged_publication = lane
        self._staged_miners = stage
        self._staged_miner_block = snapshot.block
        self._staged_snapshot = snapshot
        self._staged_validator_binding = validator_binding
        return lane

    def _clear_staged_publication_locked(
        self, lane: _PublicationLane, *, delete_durable: bool = True
    ) -> None:
        if self._staged_publication is not lane:
            return
        self._staged_publication = None
        self._staged_miners = None
        self._staged_miner_block = None
        self._staged_snapshot = None
        self._staged_validator_binding = None
        self._ambiguous_publications.pop(lane.publication_id, None)
        if delete_durable:
            self._publication_store.delete_uncommitted(lane.publication_id)

    def _discard_ambiguous_publications_locked(self) -> None:
        if self._staged_publication is not None:
            raise RuntimeError("active publication stage cannot be discarded as restart state")
        self._ambiguous_publications.clear()
        self._publication_store.delete_all_uncommitted()

    def _discard_quarantined_publications_locked(self) -> None:
        self._quarantined_publications.clear()
        self._publication_store.delete_unauthenticated()

    def _known_publications_locked(self) -> dict[str, _PublicationLane]:
        known = {lane.publication_id: lane for lane in self._historical_publications}
        known.update(self._ambiguous_publications)
        if self._committed_publication is not None:
            known[self._committed_publication.publication_id] = self._committed_publication
        if self._staged_publication is not None:
            known[self._staged_publication.publication_id] = self._staged_publication
        return known

    @staticmethod
    def _inventory_is_explicitly_not_ready(value: Any) -> bool:
        return isinstance(value, dict) and value.get("ready") is False

    async def _publish_miner_snapshot(
        self,
        snapshot: MetagraphSnapshot,
        discovered: dict[str, RemoteMiner],
        *,
        validator_binding: ServiceKeyBinding | None = None,
    ) -> None:
        async with self._publication_lock:
            await self._reconcile_before_staging(snapshot)
            await self._publish_miner_snapshot_serialized(
                snapshot,
                discovered,
                validator_binding=validator_binding,
            )

    async def _reconcile_before_staging(self, latest_snapshot: MetagraphSnapshot) -> None:
        """Resolve an older ambiguous lane before allowing its replacement."""

        async with self._lock:
            staged = self._staged_publication
            committed = self._committed_publication
            restart_reconciliation = (
                staged is None
                and committed is None
                and bool(
                    self._historical_publications
                    or self._ambiguous_publications
                    or self._quarantined_publications
                    or self._cleanup_miners
                )
            )
        if staged is None and not restart_reconciliation:
            return
        try:
            inventory = await self.bridge.request("GET", "/v1/miners")
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            raise _AmbiguousMinerRegistration(
                "existing miner-set publication could not be reconciled"
            ) from exc

        if staged is None:
            # An explicit not-ready inventory proves there is no older Go
            # publication to preserve. A ready inventory must reconstruct an
            # exact digest-checked lane before the new POST can supersede it.
            if self._inventory_is_explicitly_not_ready(inventory):
                async with self._lock:
                    if self._staged_publication is not None:
                        raise _AmbiguousMinerRegistration(
                            "publication stage appeared during restart reconciliation"
                        )
                    self._discard_ambiguous_publications_locked()
                    self._discard_quarantined_publications_locked()
                return
            if await self._reconcile_committed_inventory(inventory, latest_snapshot) is None:
                raise _AmbiguousMinerRegistration(
                    "restart miner-set inventory could not be reconciled"
                )
            return

        if self._inventory_matches_publication(inventory, staged):
            async with self._lock:
                if self._staged_publication is not staged:
                    raise _AmbiguousMinerRegistration(
                        "retained miner-set stage changed during reconciliation"
                    )
                self._commit_miner_view_locked(
                    staged.snapshot,
                    staged.miner_map(),
                    staged.validator_binding,
                    inventory_drain=False,
                    publication=staged,
                )
            return

        committed_matches = committed is not None and self._inventory_matches_publication(
            inventory, committed
        )
        inventory_not_ready = self._inventory_is_explicitly_not_ready(inventory)
        if not committed_matches and not inventory_not_ready:
            raise _AmbiguousMinerRegistration(
                "retained miner-set publication digest remains ambiguous"
            )
        # Exact inventory proves the staged POST did not replace Go's prior
        # publication. Roll back only that same retained object.
        async with self._lock:
            self._clear_staged_publication_locked(staged)

    async def _publish_miner_snapshot_serialized(
        self,
        snapshot: MetagraphSnapshot,
        discovered: dict[str, RemoteMiner],
        *,
        validator_binding: ServiceKeyBinding | None,
    ) -> None:
        """Stage Python handles before Go can issue tickets from the new set."""

        stage = dict(discovered)
        async with self._lock:
            publication = self._stage_publication_locked(
                snapshot,
                stage,
                validator_binding=validator_binding,
            )
        request = MinerSet(
            protocol=SYNAPSE_VERSION,
            network=self.network,
            netuid=self.netuid,
            block=snapshot.block,
            hotkeys=sorted(stage),
        )
        inventory_confirmed = False
        try:
            acknowledgement = await self.bridge.request(
                "POST", "/v1/miners/snapshot", value=request
            )
        except BridgeError:
            async with self._lock:
                self._clear_staged_publication_locked(publication)
            raise
        except asyncio.CancelledError:
            # Commit may already have occurred. Retain both exact maps so any
            # ticket Go actually signed resolves without authorizing any other
            # identity; the next refresh/inventory read reconciles the stage.
            raise
        except Exception as exc:
            try:
                inventory = await self.bridge.request("GET", "/v1/miners")
            except asyncio.CancelledError:
                raise
            except Exception as reconcile_exc:
                raise _AmbiguousMinerRegistration(
                    "miner-set publication completion is ambiguous"
                ) from reconcile_exc
            if not self._inventory_matches_publication(inventory, publication):
                async with self._lock:
                    committed = self._committed_publication
                rollback_proven = (
                    committed is not None
                    and self._inventory_matches_publication(inventory, committed)
                ) or self._inventory_is_explicitly_not_ready(inventory)
                if not rollback_proven:
                    raise _AmbiguousMinerRegistration(
                        "miner-set publication digest remains ambiguous"
                    ) from exc
                async with self._lock:
                    self._clear_staged_publication_locked(publication)
                raise RuntimeError("Go miner-set publication was not acknowledged") from exc
            acknowledgement = inventory
            inventory_confirmed = True
        if not inventory_confirmed and not self._acknowledges_stage(
            acknowledgement, snapshot.block, stage
        ):
            # A malformed/lost success response is ambiguous, not a reason to
            # discard handles that Go may already be scheduling.
            try:
                inventory = await self.bridge.request("GET", "/v1/miners")
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                raise _AmbiguousMinerRegistration(
                    "miner-set acknowledgement could not be reconciled"
                ) from exc
            if not self._inventory_matches_publication(inventory, publication):
                raise _AmbiguousMinerRegistration("miner-set acknowledgement is ambiguous")
        async with self._lock:
            if self._staged_publication is publication:
                self._commit_miner_view_locked(
                    snapshot,
                    stage,
                    publication.validator_binding,
                    inventory_drain=False,
                    publication=publication,
                )
                return
            committed = self._committed_publication
            if committed is None or not self._same_publication_tuple(committed, publication):
                raise RuntimeError("miner-set stage was superseded before acknowledgement")

    @staticmethod
    def _same_publication_tuple(left: _PublicationLane, right: _PublicationLane) -> bool:
        return (
            left.publication_id == right.publication_id
            and left.snapshot == right.snapshot
            and left.validator_binding == right.validator_binding
            and left.miners == right.miners
            and left.ticket_expires_at_block == right.ticket_expires_at_block
        )

    def _commit_miner_view_locked(
        self,
        snapshot: MetagraphSnapshot,
        miners: dict[str, RemoteMiner],
        validator_binding: ServiceKeyBinding,
        *,
        inventory_drain: bool,
        publication: _PublicationLane | None = None,
    ) -> None:
        """Atomically install one exact snapshot/handle/binding publication."""

        lane = publication or self._new_publication_lane(
            snapshot,
            miners,
            validator_binding,
            drain_only=inventory_drain,
        )
        if (
            lane.snapshot is not snapshot
            or lane.validator_binding is not validator_binding
            or lane.miner_map() != miners
        ):
            raise RuntimeError("committed publication differs from its exact staged tuple")
        if self._staged_publication is not None and self._staged_publication is not lane:
            raise RuntimeError("cannot commit a publication over another active stage")
        self._ensure_historical_capacity_locked(lane)
        self._persist_publication(
            lane,
            committed=True,
            drain_only=inventory_drain,
        )
        prior = self._committed_publication
        self._historical_publications = [
            retained
            for retained in self._historical_publications
            if retained.publication_id not in {lane.publication_id}
        ]
        if (
            prior is not None
            and prior.publication_id != lane.publication_id
            and snapshot.block < prior.authorized_expires_at_block
        ):
            self._historical_publications.append(replace(prior, drain_only=True))
        self._historical_publications.sort(
            key=lambda item: (item.snapshot.block, item.publication_id)
        )
        committed_lane = replace(lane, drain_only=inventory_drain)
        if self._staged_publication is lane:
            self._clear_staged_publication_locked(lane, delete_durable=False)
        self._ambiguous_publications.clear()
        self._quarantined_publications.clear()
        self._committed_publication = committed_lane
        self._miners = committed_lane.miner_map()
        self._committed_snapshot = committed_lane.snapshot
        self._committed_validator_binding = committed_lane.validator_binding
        self._inventory_committed_handles = (
            {id(remote) for remote in self._miners.values()} if inventory_drain else set()
        )
        self._staged_publication = None
        self._staged_miners = None
        self._staged_miner_block = None
        self._staged_snapshot = None
        self._staged_validator_binding = None
        self._prune_historical_publications_locked(snapshot.block)

    def _stage_registrations(self, stage: dict[str, RemoteMiner]) -> list[MinerRegistration]:
        return [
            self._registration_for(
                remote,
                network=self.network,
                netuid=self.netuid,
                bridge_url=self.bridge_url,
            )
            for remote in stage.values()
        ]

    def _acknowledges_stage(self, value: Any, block: int, stage: dict[str, RemoteMiner]) -> bool:
        return (
            isinstance(value, dict)
            and value.get("block") == block
            and value.get("miners") == len(stage)
            and value.get("publication_id")
            == _miner_set_publication_id(block, self._stage_registrations(stage))
        )

    @staticmethod
    def _same_transport_identity(left: RemoteMiner, right: RemoteMiner) -> bool:
        return (
            left.neuron.hotkey == right.neuron.hotkey
            and left.neuron.uid == right.neuron.uid
            and left.axon_url == right.axon_url
            and left.binding.service_public_key == right.binding.service_public_key
            and left.binding.transport == right.binding.transport
            and left.binding.transport_certificate_sha256
            == right.binding.transport_certificate_sha256
        )

    @classmethod
    def _same_binding_envelope(cls, left: RemoteMiner, right: RemoteMiner) -> bool:
        return cls._same_transport_identity(left, right) and left.binding == right.binding

    def _inventory_matches_stage(
        self, value: Any, block: int, stage: dict[str, RemoteMiner]
    ) -> bool:
        if (
            not isinstance(value, dict)
            or value.get("block") != block
            or value.get("ready") is not True
            or not isinstance(value.get("publication_id"), str)
            or not value["publication_id"]
        ):
            return False
        raw_miners = value.get("miners")
        if not isinstance(raw_miners, list):
            return False
        try:
            actual = {
                registration.hotkey: registration
                for item in raw_miners
                for registration in (MinerRegistration.model_validate(item),)
            }
        except ValidationError:
            return False
        expected_registrations = self._stage_registrations(stage)
        expected = {registration.hotkey: registration for registration in expected_registrations}
        return (
            len(actual) == len(raw_miners)
            and actual == expected
            and value["publication_id"] == _miner_set_publication_id(block, expected_registrations)
        )

    def _inventory_matches_publication(self, value: Any, publication: _PublicationLane) -> bool:
        return (
            isinstance(value, dict)
            and value.get("publication_id") == publication.publication_id
            and self._inventory_matches_stage(
                value,
                publication.snapshot.block,
                publication.miner_map(),
            )
        )

    async def _reconcile_committed_inventory(
        self, value: Any, latest_snapshot: MetagraphSnapshot
    ) -> dict[str, RemoteMiner] | None:
        """Atomically rebuild Python's committed handles from exact Go inventory."""

        if (
            not isinstance(value, dict)
            or value.get("ready") is not True
            or not isinstance(value.get("block"), int)
            or isinstance(value.get("block"), bool)
            or value["block"] < 0
            or value["block"] > latest_snapshot.block
            or not isinstance(value.get("miners"), list)
        ):
            return None
        try:
            registrations = [MinerRegistration.model_validate(item) for item in value["miners"]]
        except ValidationError:
            return None
        if len({registration.hotkey for registration in registrations}) != len(
            registrations
        ) or value.get("publication_id") != _miner_set_publication_id(
            value["block"], registrations
        ):
            return None
        async with self._lock:
            publication_id = value["publication_id"]
            assert isinstance(publication_id, str)
            known = self._known_publications_locked()
            exact = known.get(publication_id)
            if exact is not None:
                if not self._inventory_matches_publication(value, exact):
                    return None
                if self._committed_publication is exact:
                    return exact.miner_map()
                staged = self._staged_publication
                if staged is not None and exact is not staged:
                    # A GET can race an in-flight POST. Seeing the prior exact
                    # inventory must never erase the retained stage: Go may
                    # commit it immediately after this read.
                    return None
                self._commit_miner_view_locked(
                    exact.snapshot,
                    exact.miner_map(),
                    exact.validator_binding,
                    inventory_drain=exact is not staged,
                    publication=exact,
                )
                return exact.miner_map()
            quarantined = self._quarantined_publications.get(publication_id)
            if quarantined is not None:
                if self._staged_publication is not None or not self._inventory_matches_publication(
                    value, quarantined
                ):
                    return None
                # The unauthenticated row itself grants no ticket authority.
                # Exact current Go inventory supplies the missing commit fact;
                # the transaction below writes a fresh MAC and discards every
                # other unauthenticated row before memory becomes authoritative.
                self._commit_miner_view_locked(
                    quarantined.snapshot,
                    quarantined.miner_map(),
                    quarantined.validator_binding,
                    inventory_drain=True,
                    publication=quarantined,
                )
                return quarantined.miner_map()
            if self._staged_publication is not None:
                return None
            # Without a durable exact tuple, recovery is permitted only when
            # the inventory names the very snapshot/binding currently in hand.
            # An older Go block must never borrow the latest tempo or validator
            # service binding merely because the miner transport still matches.
            if value["block"] != latest_snapshot.block:
                return None
            reconciled: dict[str, RemoteMiner] = {}
            for registration in registrations:
                retained = self._cleanup_miners.get(registration.hotkey)
                if retained is None or not self._registration_has_remote_identity(
                    registration, retained
                ):
                    return None
                binding = registration.service_binding
                try:
                    verify_service_binding(
                        binding,
                        expected_hotkey=retained.neuron.hotkey,
                        expected_role="miner",
                        expected_network=self.network,
                        expected_netuid=self.netuid,
                        expected_challenge=binding.challenge,
                        expected_transport=retained.binding.transport,
                        expected_transport_certificate_sha256=(
                            retained.binding.transport_certificate_sha256
                        ),
                        current_block=binding.valid_from_block,
                    )
                except ValueError:
                    return None
                if binding.uid != retained.neuron.uid:
                    return None
                reconciled[registration.hotkey] = RemoteMiner(
                    neuron=retained.neuron,
                    axon_url=retained.axon_url,
                    binding=binding,
                    certificate_der=retained.certificate_der,
                )
            validator_binding = self._validator_binding
            if validator_binding is None:
                return None
            try:
                recovered = self._new_publication_lane(
                    latest_snapshot,
                    reconciled,
                    validator_binding,
                    drain_only=True,
                )
            except RuntimeError:
                return None
            if not self._inventory_matches_publication(value, recovered):
                return None
            self._commit_miner_view_locked(
                latest_snapshot,
                reconciled,
                validator_binding,
                inventory_drain=True,
                publication=recovered,
            )
            return dict(reconciled)

    def _registration_has_remote_identity(
        self, registration: MinerRegistration, remote: RemoteMiner
    ) -> bool:
        return (
            registration.protocol == SYNAPSE_VERSION
            and registration.network == self.network
            and registration.netuid == self.netuid
            and registration.bridge_url == self.bridge_url
            and registration.hotkey == remote.neuron.hotkey
            and registration.uid == remote.neuron.uid
            and registration.axon_url == remote.axon_url
            and registration.service_binding.service_public_key == remote.binding.service_public_key
            and registration.service_binding.transport == remote.binding.transport
            and registration.service_binding.transport_certificate_sha256
            == remote.binding.transport_certificate_sha256
        )

    async def _registration_is_published(self, expected: MinerRegistration) -> bool:
        """Reconcile an acknowledgement lost after Go's atomic registration commit."""
        payload = await self.bridge.request("GET", "/v1/miners/" + quote(expected.hotkey, safe=""))
        registration = MinerRegistration.model_validate(payload)
        return registration == expected

    def _remote_matches_candidate(self, remote: RemoteMiner, candidate: DiscoveryCandidate) -> bool:
        expected_transport = "http" if self.mock_http_axons else "https"
        expected_pin = (
            None
            if remote.certificate_der is None
            else hashlib.sha256(remote.certificate_der).hexdigest()
        )
        return (
            remote.neuron.hotkey == candidate.neuron.hotkey
            and remote.neuron.uid == candidate.neuron.uid
            and remote.axon_url == candidate.axon_url
            and remote.binding.transport == expected_transport
            and remote.binding.transport_certificate_sha256 == expected_pin
            and (remote.certificate_der is None) == self.mock_http_axons
        )

    @staticmethod
    def _discovery_failure_kind(exc: Exception) -> str:
        if isinstance(exc, (TimeoutError, asyncio.TimeoutError)):
            return "attempt_timeout"
        if isinstance(exc, httpx.TimeoutException):
            return "transport_timeout"
        if isinstance(exc, httpx.HTTPStatusError):
            return f"http_{exc.response.status_code // 100}xx"
        if isinstance(exc, ValueError):
            return "invalid_response"
        if isinstance(exc, (httpx.HTTPError, RuntimeError)):
            return "upstream_error"
        return "internal_error"

    def _admit_cleanup_identity(
        self,
        snapshot: MetagraphSnapshot,
        *,
        hotkey: str,
        uid: int | None,
        axon_url: str,
    ) -> DiscoveryCandidate | None:
        """Resolve one exact chain identity for deactivate-only authority.

        Cleanup admission is intentionally independent of schedule admission.
        It requires exactly one active record for the retained hotkey, an
        assignment-matching UID that is unique across active records, and the
        same canonical axon. Axon uniqueness and ``validator_permit`` do not
        participate: a third party copying the victim's axon can quarantine
        new scheduling but cannot suppress cleanup to the unchanged victim.
        """
        if (
            snapshot.network != self.network
            or snapshot.netuid != self.netuid
            or hotkey == self.hotkey
            or uid is None
        ):
            return None
        active = tuple(neuron for neuron in snapshot.neurons if neuron.active)
        matches = tuple(neuron for neuron in active if neuron.hotkey == hotkey)
        if len(matches) != 1:
            return None
        current = matches[0]
        if (
            current.uid != uid
            or not 0 <= current.uid <= 65_535
            or sum(neuron.uid == uid for neuron in active) != 1
            or not current.axon
        ):
            return None
        try:
            current_axon = _axon_url(
                current.axon,
                allow_private=self.allow_private_axons,
                mock_http=self.mock_http_axons,
            )
            assignment_axon = _axon_url(
                axon_url,
                allow_private=self.allow_private_axons,
                mock_http=self.mock_http_axons,
            )
        except ValueError:
            return None
        if assignment_axon != axon_url or current_axon != assignment_axon:
            return None
        return DiscoveryCandidate(neuron=current, axon_url=current_axon)

    def _cleanup_handle_is_current(self, remote: RemoteMiner, snapshot: MetagraphSnapshot) -> bool:
        binding = remote.binding
        return (
            self._admit_cleanup_identity(
                snapshot,
                hotkey=remote.neuron.hotkey,
                uid=remote.neuron.uid,
                axon_url=remote.axon_url,
            )
            is not None
            and binding.role == "miner"
            and binding.network == self.network
            and binding.netuid == self.netuid
            and binding.hotkey == remote.neuron.hotkey
            and binding.uid == remote.neuron.uid
            and binding.transport == ("http" if self.mock_http_axons else "https")
            and binding.transport_certificate_sha256
            == (
                None
                if remote.certificate_der is None
                else hashlib.sha256(remote.certificate_der).hexdigest()
            )
            and binding.valid_from_block <= snapshot.block < binding.expires_at_block
        )

    async def _prune_cleanup_handles(self, snapshot: MetagraphSnapshot) -> None:
        """Drop retained cleanup handles that could never be used fail-open.

        A handle survives transient handshake omissions only while the miner
        keeps the exact identity that authenticated it: the same hotkey at the
        same UID and axon on the current metagraph, with an unexpired service
        binding. This cleanup-only check deliberately ignores schedule-only
        axon quarantine and validator permits. Anything else requires a fresh
        successful handshake, which also bounds the retained map to the size
        of the metagraph.
        """
        async with self._lock:
            for hotkey in list(self._cleanup_miners):
                retained = self._cleanup_miners[hotkey]
                if not self._cleanup_handle_is_current(retained, snapshot):
                    del self._cleanup_miners[hotkey]

    async def _handshake(self, snapshot: MetagraphSnapshot, neuron: NeuronRecord) -> RemoteMiner:
        challenge = secrets.token_urlsafe(32)
        request_id = secrets.token_hex(16)
        axon_url = _axon_url(
            neuron.axon or "",
            allow_private=self.allow_private_axons,
            mock_http=self.mock_http_axons,
        )
        certificate_der: bytes | None = None
        certificate_pin: str | None = None
        if not self.mock_http_axons:
            parsed_axon = urlsplit(axon_url)
            assert parsed_axon.hostname is not None and parsed_axon.port is not None
            certificate_der = await tls_leaf_preflight(
                parsed_axon.hostname,
                parsed_axon.port,
                timeout=min(self.dendrite_timeout, 10.0),
            )
            certificate_pin = hashlib.sha256(certificate_der).hexdigest()
        synapse = CapabilitiesSynapse(
            request_id=request_id,
            network=self.network,
            netuid=self.netuid,
            chain_block=snapshot.block,
            caller_hotkey=self.hotkey,
            challenge=challenge,
        )
        response = await self._signed_post(
            axon_url,
            neuron.hotkey,
            "/api/v1/capabilities",
            synapse,
            CapabilitiesResponse,
            timeout=min(self.dendrite_timeout, 15.0),
            certificate_der=certificate_der,
        )
        if response.request_id != request_id or response.miner_hotkey != neuron.hotkey:
            raise ValueError("capability response identity mismatch")
        if response.miner_uid != neuron.uid:
            raise ValueError("capability response UID mismatch")
        verify_service_binding(
            response.service_binding,
            expected_hotkey=neuron.hotkey,
            expected_role="miner",
            expected_network=self.network,
            expected_netuid=self.netuid,
            expected_challenge=challenge,
            expected_transport="http" if self.mock_http_axons else "https",
            expected_transport_certificate_sha256=certificate_pin,
            current_block=snapshot.block,
        )
        if response.service_binding.uid != neuron.uid:
            raise ValueError("service binding UID mismatch")
        return RemoteMiner(
            neuron=neuron,
            axon_url=axon_url,
            binding=response.service_binding,
            certificate_der=certificate_der,
        )

    async def _signed_post(
        self,
        base_url: str,
        receiver_hotkey: str,
        path: str,
        value: Any,
        response_model: type[ResponseT],
        *,
        timeout: float | None = None,
        certificate_der: bytes | None = None,
    ) -> ResponseT:
        parsed_base = urlsplit(base_url)
        if parsed_base.scheme == "https":
            if certificate_der is None:
                raise ValueError("HTTPS miner request is missing its exact leaf certificate")
            verify: bool | Any = pinned_client_context(certificate_der)
        elif parsed_base.scheme == "http" and self.mock_http_axons:
            if certificate_der is not None:
                raise ValueError("mock HTTP miner request must not carry TLS certificate material")
            verify = True
        else:
            raise ValueError("miner requests require pinned HTTPS or explicit mock HTTP")
        body = json.dumps(value.model_dump(mode="json"), separators=(",", ":")).encode()
        last_error: Exception | None = None
        for attempt in range(self.dendrite_retries + 1):
            try:
                async with httpx.AsyncClient(
                    base_url=base_url,
                    timeout=timeout or self.dendrite_timeout,
                    transport=self.dendrite_transport,
                    verify=verify,
                    follow_redirects=False,
                    trust_env=False,
                ) as client:
                    async with client.stream(
                        "POST",
                        path,
                        content=body,
                        headers={
                            "Content-Type": "application/json",
                            "Accept-Encoding": "identity",
                        },
                        auth=HotkeyAuth(self.hotkey_signer, receiver_hotkey),
                    ) as streamed:
                        content_encoding = streamed.headers.get("Content-Encoding", "identity")
                        if content_encoding.lower().strip() not in {"", "identity"}:
                            raise RuntimeError("encoded miner responses are not accepted")
                        content_length = streamed.headers.get("Content-Length")
                        if content_length is not None:
                            try:
                                declared_length = int(content_length)
                            except ValueError as exc:
                                raise RuntimeError(
                                    "miner response has an invalid content length"
                                ) from exc
                            if declared_length < 0 or declared_length > BRIDGE_MAX_BODY:
                                raise RuntimeError("miner response exceeds one MiB")
                        content = bytearray()
                        if streamed.is_stream_consumed:
                            # Mock/custom transports may return an eagerly
                            # materialized response even when ``stream=True``.
                            # Live HTTP responses take the raw-stream branch.
                            if len(streamed.content) > BRIDGE_MAX_BODY:
                                raise RuntimeError("miner response exceeds one MiB")
                            content.extend(streamed.content)
                        else:
                            async for chunk in streamed.aiter_raw():
                                if len(content) + len(chunk) > BRIDGE_MAX_BODY:
                                    raise RuntimeError("miner response exceeds one MiB")
                                content.extend(chunk)
                        response = httpx.Response(
                            streamed.status_code,
                            headers=streamed.headers,
                            content=bytes(content),
                            request=streamed.request,
                            extensions=streamed.extensions,
                        )
                if 300 <= response.status_code < 500:
                    response.raise_for_status()
                if response.status_code >= 500:
                    raise RuntimeError(f"miner returned HTTP {response.status_code}")
                return response_model.model_validate_json(response.content)
            except httpx.HTTPStatusError:
                # Auth, identity, validation, and replay failures are semantic;
                # retrying them cannot make the same request acceptable.
                raise
            except (httpx.HTTPError, ValueError, RuntimeError) as exc:
                last_error = exc
            if attempt < self.dendrite_retries:
                await asyncio.sleep(0.15 * (attempt + 1))
        raise RuntimeError("signed miner request failed") from last_error

    async def _forward_signed_post(
        self,
        base_url: str,
        receiver_hotkey: str,
        path: str,
        value: Any,
        response_model: type[ResponseT],
        *,
        timeout: float | None = None,
        certificate_der: bytes | None = None,
    ) -> ResponseT:
        """Translate remote dendrite failures into the stable local bridge envelope."""
        try:
            return await self._signed_post(
                base_url,
                receiver_hotkey,
                path,
                value,
                response_model,
                timeout=timeout,
                certificate_der=certificate_der,
            )
        except httpx.HTTPStatusError as exc:
            detail = "miner rejected the signed request"
            try:
                payload = exc.response.json()
                if isinstance(payload, dict):
                    remote_detail = payload.get("detail")
                    if isinstance(remote_detail, str) and remote_detail:
                        detail = remote_detail[:512]
            except ValueError:
                pass
            raise HTTPException(status_code=exc.response.status_code, detail=detail) from exc
        except RuntimeError as exc:
            cause: BaseException | None = exc
            timed_out = False
            while cause is not None:
                if isinstance(cause, httpx.TimeoutException):
                    timed_out = True
                    break
                cause = cause.__cause__
            status = 504 if timed_out else 502
            message = "miner request timed out" if timed_out else "miner transport failed"
            raise HTTPException(status_code=status, detail=message) from exc

    async def _prepare_weight_plan(self, snapshot: MetagraphSnapshot) -> WeightPlan | None:
        # The block loop may be much faster in mock mode; avoid querying more
        # frequently than the explicitly configured interval in chain blocks.
        block_interval = max(1, math.ceil(self.weight_interval / max(self.sync_interval, 0.1)))
        if (
            self._last_weight_plan_block >= 0
            and snapshot.block - self._last_weight_plan_block < block_interval
        ):
            return None
        if snapshot.network != self.network or snapshot.netuid != self.netuid:
            raise RuntimeError("weight-plan snapshot differs from configured subnet")
        payload = await self.bridge.request("GET", "/v1/weights?hours=24")
        if not isinstance(payload, dict) or payload.get("dry_run") is not True:
            raise RuntimeError("Go control returned an invalid weight envelope")
        plan = build_weight_plan(
            snapshot=snapshot,
            validator_hotkey=self.hotkey,
            rows=payload.get("weights"),
            version_key=self.version_key,
        )
        if self.weight_plan_path is None:
            LOGGER.info(
                "weight plan dry-run summary (contents redacted)",
                extra={
                    "block": plan.snapshot.block,
                    "netuid": plan.netuid,
                    "entry_count": len(plan.weights),
                    "digest_sha256": plan.digest_sha256,
                },
            )
        else:
            changed = write_weight_plan_atomic(plan, self.weight_plan_path)
            LOGGER.info(
                "weight plan persisted (contents redacted)",
                extra={
                    "block": plan.snapshot.block,
                    "netuid": plan.netuid,
                    "entry_count": len(plan.weights),
                    "digest_sha256": plan.digest_sha256,
                    "changed": changed,
                },
            )
        self._last_weight_plan_block = snapshot.block
        return plan

    async def _verify_local_bridge(self, request: Request) -> bytes:
        body = await request.body()
        if len(body) > BRIDGE_MAX_BODY:
            raise HTTPException(status_code=413, detail="request body exceeds one MiB")
        target = request.scope["raw_path"].decode()
        if request.scope["query_string"]:
            target += "?" + request.scope["query_string"].decode()
        try:
            verify_bridge_headers(
                self.bridge_secret,
                request.headers,
                method=request.method,
                target=target,
                body=body,
                replay=self.bridge_replay,
            )
        except ValueError as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc
        return body

    async def _remote(
        self, hotkey: str
    ) -> tuple[RemoteMiner, ServiceKeyBinding, MetagraphSnapshot]:
        """Resolve an exact current miner from a successful discovery binding.

        An unexpired published binding may remain usable while its exact chain
        identity is ordinarily revalidated. Actual handshake failure enters
        backoff immediately; churn or current admission failure is rejected
        independently below.
        """
        if not self.ready.is_set():
            raise HTTPException(status_code=503, detail="validator is not synchronized")
        async with self._lock:
            publication = self._committed_publication
            if (
                publication is None
                and self._committed_snapshot is not None
                and self._committed_validator_binding is not None
            ):
                # Compatibility adapters may install the three legacy fields
                # directly. Reconstruct a coherent ephemeral tuple through the
                # same strict validator; production commits always populate
                # _committed_publication.
                try:
                    publication = self._new_publication_lane(
                        self._committed_snapshot,
                        dict(self._miners),
                        self._committed_validator_binding,
                        drain_only=False,
                    )
                except RuntimeError:
                    publication = None
            remote = None if publication is None else publication.miner(hotkey)
        if publication is None or remote is None:
            raise HTTPException(status_code=404, detail="miner is not capability-bound")
        if publication.drain_only:
            raise HTTPException(status_code=409, detail="miner publication is drain-only")
        snapshot = publication.snapshot
        binding = publication.validator_binding
        _, candidates, _ = self._admit_snapshot(snapshot)
        current = next(
            (candidate for candidate in candidates if candidate.neuron.hotkey == hotkey),
            None,
        )
        if current is None:
            raise HTTPException(
                status_code=404, detail="miner is not eligible in the current metagraph"
            )
        if not self._remote_matches_candidate(remote, current):
            raise HTTPException(
                status_code=403, detail="miner identity changed since its capability handshake"
            )
        if current.identity in self._discovery_backoff:
            raise HTTPException(
                status_code=409, detail="miner capability refresh has not succeeded"
            )
        if snapshot.block >= remote.binding.expires_at_block:
            raise HTTPException(status_code=409, detail="miner service binding expired")
        return remote, binding, snapshot

    @staticmethod
    def _ticket_matches_remote(ticket: SubnetBinding, remote: RemoteMiner) -> bool:
        return (
            ticket.miner_hotkey == remote.neuron.hotkey
            and ticket.miner_uid == remote.neuron.uid
            and ticket.miner_axon_url == remote.axon_url
            and ticket.miner_transport == remote.binding.transport
            and ticket.miner_tls_certificate_sha256 == remote.binding.transport_certificate_sha256
            and ticket.miner_service_public_key == remote.binding.service_public_key
        )

    @classmethod
    def _ticket_matches_handle(cls, ticket: SubnetBinding, handle: _TicketHandle) -> bool:
        snapshot = handle.snapshot
        binding = handle.validator_binding
        return (
            cls._ticket_matches_remote(ticket, handle.remote)
            and ticket.network == snapshot.network == binding.network
            and ticket.netuid == snapshot.netuid == binding.netuid
            and ticket.validator_hotkey == binding.hotkey
            and ticket.validator_service_public_key == binding.service_public_key
            and ticket.chain_block == snapshot.block
            and ticket.epoch == snapshot.epoch
            and ticket.expires_at_block == handle.ticket_expires_at_block
            and binding.role == "validator"
            and binding.valid_from_block <= ticket.chain_block < binding.expires_at_block
            and handle.remote.binding.valid_from_block
            <= ticket.chain_block
            < handle.remote.binding.expires_at_block
        )

    @staticmethod
    def _ticket_handle(publication: _PublicationLane, hotkey: str) -> _TicketHandle | None:
        remote = publication.miner(hotkey)
        if remote is None:
            return None
        return _TicketHandle(
            publication_id=publication.publication_id,
            remote=remote,
            snapshot=publication.snapshot,
            validator_binding=publication.validator_binding,
            ticket_expires_at_block=publication.ticket_expires_at_block,
            authorized_expires_at_block=min(
                publication.ticket_expires_at_block,
                remote.binding.expires_at_block,
            ),
            drain_only=publication.drain_only,
        )

    def _ticket_handles_locked(self, hotkey: str) -> list[_TicketHandle]:
        publications: list[_PublicationLane] = []
        if self._committed_publication is not None:
            publications.append(self._committed_publication)
        if self._staged_publication is not None:
            publications.append(self._staged_publication)
        publications.extend(self._historical_publications)
        handles: list[_TicketHandle] = []
        seen: set[str] = set()
        for publication in publications:
            if publication.publication_id in seen:
                continue
            handle = self._ticket_handle(publication, hotkey)
            if handle is not None:
                handles.append(handle)
                seen.add(publication.publication_id)
        return handles

    async def _remote_for_ticket(
        self, hotkey: str, ticket: SubnetBinding
    ) -> tuple[RemoteMiner, ServiceKeyBinding, MetagraphSnapshot]:
        """Resolve a Go-issued ticket against its exact atomic publication lane."""

        if not self.ready.is_set():
            raise HTTPException(status_code=503, detail="validator is not synchronized")
        latest_snapshot = await self.state.get()
        async with self._lock:
            handles = self._ticket_handles_locked(hotkey)
            retained = self._cleanup_miners.get(hotkey)
            ambiguous = tuple(self._ambiguous_publications.values())
            restart_needs_reconciliation = self._committed_publication is None and bool(
                handles or ambiguous or self._quarantined_publications or retained
            )
            self._prune_historical_publications_locked(latest_snapshot.block)

        retained_needs_reconciliation = (
            retained is not None
            and not any(item.remote is retained for item in handles)
            and self._ticket_matches_remote(ticket, retained)
        )
        ambiguous_needs_reconciliation = any(
            (handle := self._ticket_handle(publication, hotkey)) is not None
            and self._ticket_matches_handle(ticket, handle)
            for publication in ambiguous
        )
        if (
            retained_needs_reconciliation
            or ambiguous_needs_reconciliation
            or restart_needs_reconciliation
        ):
            # After only the Python process restarts, Go may still be issuing
            # tickets from its last committed publication while Python rebuilds
            # its handles. Reconcile the candidate against Go's exact, versioned
            # inventory before treating it as committed; a cleanup-only handle
            # can never authorize work by itself.
            try:
                inventory = await self.bridge.request("GET", "/v1/miners")
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                if not any(self._ticket_matches_handle(ticket, item) for item in handles):
                    raise HTTPException(
                        status_code=503,
                        detail="committed miner inventory could not be reconciled",
                    ) from exc
            else:
                await self._reconcile_committed_inventory(inventory, latest_snapshot)
                async with self._lock:
                    handles = self._ticket_handles_locked(hotkey)
        if not handles:
            raise HTTPException(status_code=404, detail="miner is not capability-bound")
        identity_matches = [
            item for item in handles if self._ticket_matches_remote(ticket, item.remote)
        ]
        if not identity_matches:
            raise HTTPException(
                status_code=403,
                detail=(
                    "ticket identity differs from committed, staged, and reconciled "
                    "capability handles"
                ),
            )
        exact = [item for item in identity_matches if self._ticket_matches_handle(ticket, item)]
        if not exact:
            raise HTTPException(
                status_code=403,
                detail="ticket subnet fields do not match one exact publication lane",
            )
        valid: list[_TicketHandle] = []
        for item in exact:
            remote = item.remote
            if latest_snapshot.block >= item.authorized_expires_at_block:
                continue
            if not item.drain_only:
                _, candidates, _ = self._admit_snapshot(item.snapshot)
                current = next(
                    (candidate for candidate in candidates if candidate.neuron.hotkey == hotkey),
                    None,
                )
                if current is None or not self._remote_matches_candidate(remote, current):
                    continue
            valid.append(item)
        if not valid:
            raise HTTPException(
                status_code=409, detail="ticket capability handle is stale or expired"
            )
        valid.sort(key=lambda item: item.publication_id)
        selected = valid[0]
        if any(
            item.remote != selected.remote
            or item.snapshot != selected.snapshot
            or item.validator_binding != selected.validator_binding
            for item in valid[1:]
        ):
            raise HTTPException(status_code=409, detail="ticket publication lane is ambiguous")
        return selected.remote, selected.validator_binding, selected.snapshot

    async def _cleanup_remote(
        self, hotkey: str, local: BridgeDeactivateRequest
    ) -> tuple[RemoteMiner, ServiceKeyBinding, MetagraphSnapshot]:
        """Resolve transport authority for cleanup of an existing assignment.

        Go intentionally retains the Assigner for an active assignment even
        when one discovery refresh transiently omits its miner, so exact
        ticket-bound deactivation falls back to the retained authenticated
        handshake handle. Resolution is bound to the assignment's exact
        authenticated identity (hotkey, UID, axon, and service-key
        fingerprint), never to the hotkey alone: a same-hotkey rebind to a
        different identity must never receive another assignment's cleanup.
        The fallback is deactivate-only and fail-closed: the miner must still
        hold that same identity on the current metagraph and an unexpired
        service binding. Among exact-identity handles, a fresh valid
        handshake handle is deliberately preferred over an expired published
        one so registration-time recovery after a long control outage cannot
        loop on binding expiry.
        """
        if not self.ready.is_set():
            raise HTTPException(status_code=503, detail="validator is not synchronized")
        if local.miner_hotkey != hotkey:
            raise HTTPException(
                status_code=403, detail="cleanup identity does not match the target miner"
            )
        snapshot = await self.state.get()
        async with self._lock:
            published = self._miners.get(hotkey)
            retained = self._cleanup_miners.get(hotkey)
            binding = self._validator_binding
        candidates = [handle for handle in (published, retained) if handle is not None]
        if not candidates or binding is None:
            raise HTTPException(status_code=404, detail="miner is not capability-bound")
        current = self._admit_cleanup_identity(
            snapshot,
            hotkey=hotkey,
            uid=local.miner_uid,
            axon_url=local.axon_url,
        )
        if current is None:
            active_matches = tuple(
                neuron for neuron in snapshot.neurons if neuron.active and neuron.hotkey == hotkey
            )
            if not active_matches:
                raise HTTPException(
                    status_code=404, detail="miner is no longer registered on this subnet"
                )
            raise HTTPException(
                status_code=403,
                detail="assignment identity is ambiguous or differs from the current chain record",
            )
        matching = [
            handle
            for handle in candidates
            if self._remote_matches_candidate(handle, current)
            and handle.neuron.uid == local.miner_uid
            and handle.axon_url == local.axon_url
            and handle.binding.uid == local.miner_uid
            and handle.binding.service_public_key == local.miner_service_public_key
            and handle.binding.transport == local.miner_transport
            and handle.binding.transport_certificate_sha256 == local.miner_tls_certificate_sha256
        ]
        if not matching:
            raise HTTPException(
                status_code=403,
                detail="assignment identity is not the capability-bound miner identity",
            )
        valid: list[RemoteMiner] = []
        for handle in matching:
            try:
                verify_service_binding(
                    handle.binding,
                    expected_hotkey=hotkey,
                    expected_role="miner",
                    expected_network=self.network,
                    expected_netuid=self.netuid,
                    expected_challenge=handle.binding.challenge,
                    expected_transport=local.miner_transport,
                    expected_transport_certificate_sha256=(local.miner_tls_certificate_sha256),
                    current_block=snapshot.block,
                )
            except ValueError:
                continue
            valid.append(handle)
        if not valid:
            raise HTTPException(status_code=409, detail="miner service binding is not current")
        remote = max(
            valid,
            key=lambda handle: (
                handle.binding.expires_at_block,
                handle.binding.generation,
                handle.binding.valid_from_block,
            ),
        )
        return remote, binding, snapshot

    def _routes(self) -> None:
        @self.app.get("/healthz")
        async def health() -> Response:
            return Response(status_code=204 if self.fully_synced.is_set() else 503)

        @self.app.post("/v1/miners/{hotkey}/deploy", response_model=DeployResponse)
        async def deploy_bridge(hotkey: str, request: Request) -> DeployResponse:
            body = await self._verify_local_bridge(request)
            local = BridgeAssignRequest.model_validate_json(body)
            ticket_binding = local.ticket.subnet
            remote, validator_binding, snapshot = await self._remote_for_ticket(
                hotkey, ticket_binding
            )
            if (
                local.ticket.miner_id != hotkey
                or ticket_binding.miner_hotkey != hotkey
                or ticket_binding.miner_uid != remote.neuron.uid
                # The signed assignment-time axon must be the handshake axon
                # that will receive this work; a legacy ticket without it
                # fails closed. This keeps later exact-identity cleanup and
                # restart recovery bound to the axon that ran the workload.
                or ticket_binding.miner_axon_url != remote.axon_url
                or ticket_binding.miner_transport != remote.binding.transport
                or ticket_binding.miner_tls_certificate_sha256
                != remote.binding.transport_certificate_sha256
                or ticket_binding.network != self.network
                or ticket_binding.netuid != self.netuid
                or ticket_binding.miner_service_public_key != remote.binding.service_public_key
                or ticket_binding.validator_hotkey != self.hotkey
                or ticket_binding.validator_service_public_key
                != validator_binding.service_public_key
                or ticket_binding.epoch != ticket_binding.chain_block // max(snapshot.tempo, 1)
                or ticket_binding.chain_block > snapshot.block + 2
                or snapshot.block >= ticket_binding.expires_at_block
            ):
                raise HTTPException(
                    status_code=403, detail="Go ticket binding differs from handshake"
                )
            synapse = DeploySynapse(
                request_id=local.request_id,
                current_block=snapshot.block,
                caller_hotkey=self.hotkey,
                validator_binding=validator_binding,
                ticket=local.ticket,
            )
            return await self._forward_signed_post(
                remote.axon_url,
                hotkey,
                "/api/v1/deploy",
                synapse,
                DeployResponse,
                certificate_der=remote.certificate_der,
            )

        @self.app.post("/v1/miners/{hotkey}/deactivate", response_model=DeactivateResponse)
        async def deactivate_bridge(hotkey: str, request: Request) -> DeactivateResponse:
            body = await self._verify_local_bridge(request)
            local = BridgeDeactivateRequest.model_validate_json(body)
            remote, _, snapshot = await self._cleanup_remote(hotkey, local)
            synapse = DeactivateSynapse(
                request_id=local.request_id,
                current_block=snapshot.block,
                caller_hotkey=self.hotkey,
                endpoint_id=local.endpoint_id,
                deployment_id=local.deployment_id,
            )
            return await self._forward_signed_post(
                remote.axon_url,
                hotkey,
                "/api/v1/deactivate",
                synapse,
                DeactivateResponse,
                timeout=min(self.dendrite_timeout, 20.0),
                certificate_der=remote.certificate_der,
            )


def _axon_url(value: str, *, allow_private: bool = False, mock_http: bool = False) -> str:
    if not value or value != value.strip() or any(ord(character) < 0x20 for character in value):
        raise ValueError("metagraph axon must be an explicit host and port")
    if "?" in value or "#" in value:
        # urlsplit represents empty query/fragment delimiters as empty
        # strings, so reject their syntax before parsing as well.
        raise ValueError("metagraph axon must not contain query or fragment syntax")
    if "://" in value:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"}:
            raise ValueError("metagraph axon uses an unsupported scheme")
    else:
        parsed = urlsplit("//" + value)
    if (
        not parsed.hostname
        or "%" in parsed.hostname
        or parsed.port is None
        or not 1 <= parsed.port <= 65_535
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path != ""
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("metagraph axon must be an explicit host and port without URL data")
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError as exc:
        if not allow_private:
            raise ValueError("live metagraph axon host must be a numeric IP") from exc
        host = parsed.hostname.lower()
    else:
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
            raise ValueError("metagraph axon must not use an IPv4-mapped IPv6 identity")
        if allow_private:
            rendered = address.compressed
        else:
            try:
                rendered = canonical_public_address(parsed.hostname)
            except ValueError as exc:
                raise ValueError(PUBLIC_AXON_REJECTION) from exc
        host = f"[{rendered}]" if address.version == 6 else rendered
    scheme = "http" if mock_http else "https"
    return f"{scheme}://{host}:{parsed.port}"


def _loopback_bind(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_loopback
    except ValueError:
        return False


def _http_host(host: str) -> str:
    """Render an already-validated numeric host for an HTTP authority."""
    return f"[{host}]" if ":" in host else host


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--netuid", type=int, required=True)
    parser.add_argument("--subtensor-network", default=os.getenv("BT_NETWORK", "finney"))
    parser.add_argument(
        "--rpc-endpoint",
        action="append",
        default=[],
        help="independent RPC endpoint; repeat at least twice for finalized agreement",
    )
    parser.add_argument("--rpc-max-finalized-lag", type=int, default=8)
    parser.add_argument("--wallet-name", default=os.getenv("BT_WALLET", "default"))
    parser.add_argument("--wallet-hotkey", default=os.getenv("BT_WALLET_HOTKEY", "default"))
    parser.add_argument(
        "--wallet-path", default=os.getenv("BT_WALLET_PATH", "~/.bittensor/wallets")
    )
    parser.add_argument("--bridge-host", default="127.0.0.1")
    parser.add_argument("--bridge-port", type=int, default=9200)
    parser.add_argument("--go-control-url", default="http://127.0.0.1:9201")
    parser.add_argument("--bridge-secret-file", required=True)
    parser.add_argument("--state-db", required=True)
    parser.add_argument("--sync-interval", type=float, default=12.0)
    parser.add_argument("--dendrite-timeout", type=float, default=130.0)
    parser.add_argument("--dendrite-retries", type=int, default=1)
    parser.add_argument(
        "--discovery-concurrency",
        type=int,
        default=16,
        help="maximum concurrent capability/registration workers",
    )
    parser.add_argument(
        "--discovery-max-attempts-per-refresh",
        type=int,
        default=64,
        help="maximum unique miner identities attempted per refresh",
    )
    parser.add_argument(
        "--discovery-attempt-timeout",
        type=float,
        default=10.0,
        help="seconds allowed for one capability handshake plus registration",
    )
    parser.add_argument(
        "--discovery-refresh-timeout",
        type=float,
        default=30.0,
        help="seconds allowed for the complete bounded discovery refresh",
    )
    parser.add_argument(
        "--discovery-backoff-base-rounds",
        type=int,
        default=1,
        help="refresh rounds skipped after a first failed identity attempt",
    )
    parser.add_argument(
        "--discovery-backoff-max-rounds",
        type=int,
        default=16,
        help="maximum deterministic exponential backoff in refresh rounds",
    )
    parser.add_argument("--weight-interval", type=float, default=360.0)
    parser.add_argument(
        "--version-key",
        type=int,
        default=WEIGHT_PLAN_PROTOCOL_VERSION_KEY,
    )
    parser.add_argument(
        "--weight-plan-path",
        help="optional durable 0600 canonical plan file for a future one-shot executor",
    )
    parser.add_argument(
        "--enable-weight-submission",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument("--confirm-network", help=argparse.SUPPRESS)
    parser.add_argument("--confirm-netuid", type=int, help=argparse.SUPPRESS)
    parser.add_argument("--mock-uri")
    parser.add_argument("--mock-peers")
    parser.add_argument("--allow-private-axons", action="store_true")
    parser.add_argument(
        "--allow-insecure-mock-http",
        action="store_true",
        help="use HTTP axons only for an explicitly configured mock chain",
    )
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
    query = build_chain_query(
        network=args.subtensor_network,
        netuid=args.netuid,
        rpc_endpoints=args.rpc_endpoint,
        max_finalized_lag=args.rpc_max_finalized_lag,
        alert_sink=json_stderr_alert,
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
    if "--enable-weight-submission" in sys.argv[1:]:
        raise SystemExit(
            "--enable-weight-submission has been removed: the long-running validator cannot "
            "execute weights; use --weight-plan-path to prepare a canonical plan for the "
            "separate one-shot executor planned for a later release"
        )
    args = build_parser().parse_args()
    if args.allow_private_axons and not args.mock_uri:
        raise SystemExit("--allow-private-axons is restricted to --mock-uri")
    if args.allow_insecure_mock_http and not args.mock_uri:
        raise SystemExit("--allow-insecure-mock-http requires --mock-uri")
    if not _loopback_bind(args.bridge_host):
        raise SystemExit("validator bridge host must be an explicit loopback IP")
    if not 1 <= args.bridge_port <= 65_535:
        raise SystemExit("validator bridge port must be in [1,65535]")
    if (
        args.discovery_concurrency < 1
        or args.discovery_max_attempts_per_refresh < 1
        or args.discovery_attempt_timeout <= 0
        or args.discovery_refresh_timeout <= 0
        or args.discovery_backoff_base_rounds < 1
        or args.discovery_backoff_max_rounds < args.discovery_backoff_base_rounds
    ):
        raise SystemExit("validator discovery bounds/backoff configuration is invalid")
    if (
        not math.isfinite(args.sync_interval)
        or not math.isfinite(args.weight_interval)
        or args.sync_interval <= 0
        or args.weight_interval <= 0
    ):
        raise SystemExit("validator sync and weight-plan intervals must be positive")
    if not 0 <= args.version_key <= (1 << 64) - 1:
        raise SystemExit("weight-plan version key must be an unsigned 64-bit integer")
    configure_logging(args.log_level)
    secret = load_secret(args.bridge_secret_file)
    try:
        chain, hotkey_signer = make_chain(args)
    except ValueError as exc:
        raise SystemExit("validator RPC configuration is invalid") from exc
    neuron = ValidatorNeuron(
        chain=chain,
        hotkey_signer=hotkey_signer,
        network=args.subtensor_network,
        netuid=args.netuid,
        bridge=BridgeClient(args.go_control_url, secret, timeout=180.0, retries=1),
        bridge_secret=secret,
        state_db=args.state_db,
        bridge_url=f"http://{_http_host(args.bridge_host)}:{args.bridge_port}",
        sync_interval=args.sync_interval,
        dendrite_timeout=args.dendrite_timeout,
        dendrite_retries=args.dendrite_retries,
        weight_interval=args.weight_interval,
        version_key=args.version_key,
        weight_plan_path=args.weight_plan_path,
        allow_private_axons=args.allow_private_axons or bool(args.mock_uri),
        mock_http_axons=args.allow_insecure_mock_http,
        discovery_concurrency=args.discovery_concurrency,
        discovery_max_attempts=args.discovery_max_attempts_per_refresh,
        discovery_attempt_timeout=args.discovery_attempt_timeout,
        discovery_refresh_timeout=args.discovery_refresh_timeout,
        discovery_backoff_base_rounds=args.discovery_backoff_base_rounds,
        discovery_backoff_max_rounds=args.discovery_backoff_max_rounds,
    )
    uvicorn.run(neuron.app, host=args.bridge_host, port=args.bridge_port, log_config=None)


if __name__ == "__main__":
    main()
