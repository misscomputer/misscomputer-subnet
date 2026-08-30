# SPDX-License-Identifier: AGPL-3.0-only
"""Canonical, peer-authenticated Unix protocol for one weight-signing request."""

from __future__ import annotations

import asyncio
import json
import os
import secrets
import socket
import stat
import struct
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal, cast

from .weight_executor import (
    ExecutionVector,
    ExecutionWeight,
    OmittedWeight,
    SubmissionResult,
    WeightExecutionError,
    _safe_error_code,
    _safe_reference,
    _validate_digest,
    _validate_public_network,
    _validate_public_text,
    _validate_uint,
)
from .weight_plan import _canonical_json

WEIGHT_SIGNER_REQUEST_SCHEMA = "miss.computer/misscomputer-subnet/weight-signer-request"
WEIGHT_SIGNER_RESPONSE_SCHEMA = "miss.computer/misscomputer-subnet/weight-signer-response"
WEIGHT_SIGNER_PROTOCOL_VERSION = 2
MAX_SIGNER_MESSAGE_BYTES = 1_048_576
MAX_SIGNER_TIMEOUT_SECONDS = 3_600.0


class SignerProtocolError(WeightExecutionError):
    """A malformed, unauthenticated, unsafe, or unavailable signer boundary."""


def _exact_mapping(
    value: object,
    *,
    field_name: str,
    keys: frozenset[str],
) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise SignerProtocolError("signer_protocol_invalid", f"{field_name} has an invalid shape")
    return value


def _canonical_document(rendered: bytes, *, field_name: str) -> Mapping[str, object]:
    if not rendered or len(rendered) > MAX_SIGNER_MESSAGE_BYTES or not rendered.endswith(b"\n"):
        raise SignerProtocolError("signer_protocol_invalid", f"{field_name} framing is invalid")

    def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, item in pairs:
            if key in result:
                raise SignerProtocolError(
                    "signer_protocol_invalid", f"{field_name} contains duplicate keys"
                )
            result[key] = item
        return result

    try:
        document = json.loads(rendered.decode("ascii"), object_pairs_hook=unique_object)
    except SignerProtocolError:
        raise
    except (ValueError, UnicodeDecodeError, RecursionError) as exc:
        raise SignerProtocolError(
            "signer_protocol_invalid", f"{field_name} is not canonical JSON"
        ) from exc
    if not isinstance(document, Mapping) or rendered != _canonical_json(document) + b"\n":
        raise SignerProtocolError(
            "signer_protocol_invalid", f"{field_name} bytes are not canonical"
        )
    return document


@dataclass(frozen=True, slots=True)
class SignerRequest:
    request_id: str
    network: str
    netuid: int
    validator_hotkey: str
    plan_digest_sha256: str
    execution_digest_sha256: str
    execution_vector: ExecutionVector

    def __post_init__(self) -> None:
        _validate_digest(self.request_id, "signer request ID")
        _validate_public_network(self.network, "signer request network")
        _validate_uint(self.netuid, "signer request netuid", 65_535)
        _validate_public_text(self.validator_hotkey, "signer request validator hotkey")
        _validate_digest(self.plan_digest_sha256, "signer request plan digest")
        _validate_digest(self.execution_digest_sha256, "signer request execution digest")
        if self.execution_vector.network != self.network:
            raise SignerProtocolError("signer_protocol_invalid", "vector network does not match")
        if self.execution_vector.netuid != self.netuid:
            raise SignerProtocolError("signer_protocol_invalid", "vector netuid does not match")
        if self.execution_vector.validator_hotkey != self.validator_hotkey:
            raise SignerProtocolError("signer_protocol_invalid", "vector validator does not match")
        if self.execution_vector.plan_digest_sha256 != self.plan_digest_sha256:
            raise SignerProtocolError(
                "signer_protocol_invalid", "vector plan digest does not match"
            )
        if self.execution_vector.digest_sha256 != self.execution_digest_sha256:
            raise SignerProtocolError("signer_protocol_invalid", "vector digest does not match")

    def document(self) -> dict[str, object]:
        return {
            "execution_digest_sha256": self.execution_digest_sha256,
            "execution_vector": self.execution_vector.document(),
            "netuid": self.netuid,
            "network": self.network,
            "plan_digest_sha256": self.plan_digest_sha256,
            "request_id": self.request_id,
            "schema": WEIGHT_SIGNER_REQUEST_SCHEMA,
            "schema_version": WEIGHT_SIGNER_PROTOCOL_VERSION,
            "validator_hotkey": self.validator_hotkey,
        }

    def canonical_bytes(self) -> bytes:
        return _canonical_json(self.document()) + b"\n"

    @classmethod
    def from_bytes(cls, rendered: bytes) -> SignerRequest:
        document = _exact_mapping(
            _canonical_document(rendered, field_name="signer request"),
            field_name="signer request",
            keys=frozenset(
                {
                    "execution_digest_sha256",
                    "execution_vector",
                    "netuid",
                    "network",
                    "plan_digest_sha256",
                    "request_id",
                    "schema",
                    "schema_version",
                    "validator_hotkey",
                }
            ),
        )
        if document["schema"] != WEIGHT_SIGNER_REQUEST_SCHEMA:
            raise SignerProtocolError("signer_protocol_invalid", "signer request schema is invalid")
        if document["schema_version"] != WEIGHT_SIGNER_PROTOCOL_VERSION:
            raise SignerProtocolError(
                "signer_protocol_invalid", "signer request version is invalid"
            )
        vector_document = _exact_mapping(
            document["execution_vector"],
            field_name="signer execution vector",
            keys=frozenset(
                {
                    "digest_sha256",
                    "netuid",
                    "network",
                    "omitted",
                    "plan_digest_sha256",
                    "schema",
                    "schema_version",
                    "validator_hotkey",
                    "version_key",
                    "weights",
                }
            ),
        )
        try:
            raw_weights = cast(list[object], vector_document["weights"])
            raw_omitted = cast(list[object], vector_document["omitted"])
            weights_list: list[ExecutionWeight] = []
            for item in raw_weights:
                weight = _exact_mapping(
                    item,
                    field_name="signer execution weight",
                    keys=frozenset({"hotkey", "planned_uid", "uid", "weight"}),
                )
                weights_list.append(
                    ExecutionWeight(
                        hotkey=cast(str, weight["hotkey"]),
                        planned_uid=cast(int, weight["planned_uid"]),
                        uid=cast(int, weight["uid"]),
                        weight=cast(float, weight["weight"]),
                    )
                )
            omitted_list: list[OmittedWeight] = []
            for item in raw_omitted:
                omission = _exact_mapping(
                    item,
                    field_name="signer omitted weight",
                    keys=frozenset({"hotkey", "planned_uid"}),
                )
                omitted_list.append(
                    OmittedWeight(
                        hotkey=cast(str, omission["hotkey"]),
                        planned_uid=cast(int, omission["planned_uid"]),
                    )
                )
            vector = ExecutionVector(
                plan_digest_sha256=vector_document["plan_digest_sha256"],  # type: ignore[arg-type]
                network=vector_document["network"],  # type: ignore[arg-type]
                netuid=vector_document["netuid"],  # type: ignore[arg-type]
                validator_hotkey=vector_document["validator_hotkey"],  # type: ignore[arg-type]
                version_key=vector_document["version_key"],  # type: ignore[arg-type]
                weights=tuple(weights_list),
                omitted=tuple(omitted_list),
            )
        except (TypeError, WeightExecutionError) as exc:
            raise SignerProtocolError(
                "signer_protocol_invalid", "signer execution vector is invalid"
            ) from exc
        if vector_document["digest_sha256"] != vector.digest_sha256:
            raise SignerProtocolError("signer_protocol_invalid", "vector digest is invalid")
        return cls(
            request_id=document["request_id"],  # type: ignore[arg-type]
            network=document["network"],  # type: ignore[arg-type]
            netuid=document["netuid"],  # type: ignore[arg-type]
            validator_hotkey=document["validator_hotkey"],  # type: ignore[arg-type]
            plan_digest_sha256=document["plan_digest_sha256"],  # type: ignore[arg-type]
            execution_digest_sha256=document["execution_digest_sha256"],  # type: ignore[arg-type]
            execution_vector=vector,
        )


SignerResponseStatus = Literal["confirmed", "rejected", "ambiguous"]


@dataclass(frozen=True, slots=True)
class SignerResponse:
    request_id: str
    status: SignerResponseStatus
    extrinsic_ref: str | None = None
    error_code: str | None = None

    def __post_init__(self) -> None:
        _validate_digest(self.request_id, "signer response request ID")
        if self.status not in {"confirmed", "rejected", "ambiguous"}:
            raise SignerProtocolError(
                "signer_protocol_invalid", "signer response status is invalid"
            )
        if self.extrinsic_ref is not None and _safe_reference(self.extrinsic_ref) is None:
            raise SignerProtocolError(
                "signer_protocol_invalid", "signer response reference is invalid"
            )
        if self.error_code is not None and _safe_error_code(self.error_code) != self.error_code:
            raise SignerProtocolError(
                "signer_protocol_invalid", "signer response error code is invalid"
            )
        if self.status == "confirmed":
            if self.extrinsic_ref is None or self.error_code is not None:
                raise SignerProtocolError(
                    "signer_protocol_invalid", "confirmed signer response is incomplete"
                )
        elif self.error_code is None or self.extrinsic_ref is not None:
            raise SignerProtocolError(
                "signer_protocol_invalid", "rejected signer response is incomplete"
            )

    def document(self) -> dict[str, object]:
        return {
            "error_code": self.error_code,
            "extrinsic_ref": self.extrinsic_ref,
            "request_id": self.request_id,
            "schema": WEIGHT_SIGNER_RESPONSE_SCHEMA,
            "schema_version": WEIGHT_SIGNER_PROTOCOL_VERSION,
            "status": self.status,
        }

    def canonical_bytes(self) -> bytes:
        return _canonical_json(self.document()) + b"\n"

    @classmethod
    def from_bytes(cls, rendered: bytes) -> SignerResponse:
        document = _exact_mapping(
            _canonical_document(rendered, field_name="signer response"),
            field_name="signer response",
            keys=frozenset(
                {
                    "error_code",
                    "extrinsic_ref",
                    "request_id",
                    "schema",
                    "schema_version",
                    "status",
                }
            ),
        )
        if document["schema"] != WEIGHT_SIGNER_RESPONSE_SCHEMA:
            raise SignerProtocolError(
                "signer_protocol_invalid", "signer response schema is invalid"
            )
        if document["schema_version"] != WEIGHT_SIGNER_PROTOCOL_VERSION:
            raise SignerProtocolError(
                "signer_protocol_invalid", "signer response version is invalid"
            )
        return cls(
            request_id=document["request_id"],  # type: ignore[arg-type]
            status=document["status"],  # type: ignore[arg-type]
            extrinsic_ref=document["extrinsic_ref"],  # type: ignore[arg-type]
            error_code=document["error_code"],  # type: ignore[arg-type]
        )


def unix_peer_uid(connection: socket.socket) -> int:
    if not hasattr(socket, "SO_PEERCRED"):
        raise SignerProtocolError(
            "signer_peer_unavailable", "Unix peer credentials are unavailable"
        )
    try:
        credentials = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        _, uid, _ = struct.unpack("3i", credentials)
    except (OSError, struct.error) as exc:
        raise SignerProtocolError(
            "signer_peer_unavailable", "Unix peer credentials are unavailable"
        ) from exc
    return int(uid)


def validate_socket_inode(path: str, *, owner_uid: int) -> os.stat_result:
    try:
        value = os.lstat(path)
    except OSError as exc:
        raise SignerProtocolError("signer_socket_unsafe", "signer socket is unavailable") from exc
    if (
        not stat.S_ISSOCK(value.st_mode)
        or value.st_uid != owner_uid
        or value.st_nlink != 1
        or stat.S_IMODE(value.st_mode) & 0o007
    ):
        raise SignerProtocolError("signer_socket_unsafe", "signer socket is unsafe")
    return value


def socket_path_exists(path: str) -> bool:
    return os.path.lexists(path)


async def read_message(reader: asyncio.StreamReader) -> bytes:
    try:
        rendered = await reader.readuntil(b"\n")
    except (asyncio.IncompleteReadError, asyncio.LimitOverrunError) as exc:
        raise SignerProtocolError(
            "signer_protocol_invalid", "signer message framing is invalid"
        ) from exc
    if len(rendered) > MAX_SIGNER_MESSAGE_BYTES:
        raise SignerProtocolError("signer_protocol_invalid", "signer message is too large")
    return rendered


class UnixWeightSignerClient:
    """Wallet-free executor adapter pinned to one Unix signer UID."""

    __slots__ = (
        "_reader",
        "_writer",
        "hotkey",
        "signer_uid",
        "socket_path",
        "timeout_seconds",
    )

    def __init__(
        self,
        *,
        socket_path: str,
        signer_uid: int,
        hotkey: str,
        timeout_seconds: float,
    ) -> None:
        if not os.path.isabs(socket_path):
            raise SignerProtocolError("signer_socket_unsafe", "signer socket path must be absolute")
        _validate_uint(signer_uid, "signer UID", 2**32 - 2)
        _validate_public_text(hotkey, "signer hotkey")
        if not 0.0 < float(timeout_seconds) <= MAX_SIGNER_TIMEOUT_SECONDS:
            raise SignerProtocolError("invalid_submission_timeout", "signer timeout is invalid")
        self.socket_path = socket_path
        self.signer_uid = signer_uid
        self.hotkey = hotkey
        self.timeout_seconds = float(timeout_seconds)
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None

    async def open(self) -> None:
        if self._writer is not None:
            raise SignerProtocolError("signer_protocol_invalid", "signer client is already open")
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self.timeout_seconds
        while True:
            try:
                before = validate_socket_inode(self.socket_path, owner_uid=self.signer_uid)
                reader, writer = await asyncio.open_unix_connection(self.socket_path)
            except SignerProtocolError as exc:
                if socket_path_exists(self.socket_path):
                    raise
                if loop.time() >= deadline:
                    raise SignerProtocolError(
                        "signer_unavailable", "signer socket did not become available"
                    ) from exc
                await asyncio.sleep(min(0.05, max(deadline - loop.time(), 0.0)))
                continue
            except OSError as exc:
                if loop.time() >= deadline:
                    raise SignerProtocolError(
                        "signer_unavailable", "signer is unavailable"
                    ) from exc
                await asyncio.sleep(min(0.05, max(deadline - loop.time(), 0.0)))
                continue
            try:
                raw_socket = writer.get_extra_info("socket")
                if raw_socket is None or unix_peer_uid(raw_socket) != self.signer_uid:
                    raise SignerProtocolError(
                        "signer_peer_mismatch", "signer peer UID does not match"
                    )
                after = validate_socket_inode(self.socket_path, owner_uid=self.signer_uid)
                if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                    raise SignerProtocolError(
                        "signer_socket_unsafe", "signer socket changed during connection"
                    )
            except Exception:
                writer.close()
                await writer.wait_closed()
                raise
            self._reader = reader
            self._writer = writer
            return

    async def close(self) -> None:
        writer = self._writer
        self._reader = None
        self._writer = None
        if writer is not None:
            writer.close()
            await writer.wait_closed()

    async def submit(self, vector: ExecutionVector) -> SubmissionResult:
        reader = self._reader
        writer = self._writer
        if reader is None or writer is None:
            raise SignerProtocolError("signer_unavailable", "signer client is not open")
        request = SignerRequest(
            request_id=secrets.token_hex(32),
            network=vector.network,
            netuid=vector.netuid,
            validator_hotkey=vector.validator_hotkey,
            plan_digest_sha256=vector.plan_digest_sha256,
            execution_digest_sha256=vector.digest_sha256,
            execution_vector=vector,
        )
        try:
            async with asyncio.timeout(self.timeout_seconds):
                writer.write(request.canonical_bytes())
                await writer.drain()
                response = SignerResponse.from_bytes(await read_message(reader))
        except TimeoutError as exc:
            raise SignerProtocolError("signer_timeout", "signer response timed out") from exc
        except SignerProtocolError:
            raise
        except OSError as exc:
            raise SignerProtocolError("signer_unavailable", "signer is unavailable") from exc
        if response.request_id != request.request_id:
            raise SignerProtocolError(
                "signer_protocol_invalid", "signer response request ID does not match"
            )
        if response.status == "ambiguous":
            raise SignerProtocolError(
                "submission_ambiguous",
                "signer reported an ambiguous submission that requires reconciliation",
            )
        return SubmissionResult(
            success=response.status == "confirmed",
            extrinsic_ref=response.extrinsic_ref,
            error_code=response.error_code,
        )
