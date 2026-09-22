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

from .async_lifecycle import drain_cleanup
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
        elif self.status == "rejected":
            if self.error_code is None or self.extrinsic_ref is not None:
                raise SignerProtocolError(
                    "signer_protocol_invalid", "rejected signer response is incomplete"
                )
        elif self.error_code is None:
            raise SignerProtocolError(
                "signer_protocol_invalid", "ambiguous signer response is incomplete"
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


@dataclass(slots=True)
class _SignerSubmitOperation:
    task: asyncio.Task[object]
    completion: asyncio.Future[None]
    generation: int
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter


class SignerSocketUnavailable(SignerProtocolError):
    """The signer socket was absent in the exact metadata observation."""


class SignerSocketPublicationPending(SignerProtocolError):
    """The exact safe socket observation retained its private staging link."""


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


def validate_socket_metadata(value: os.stat_result, *, owner_uid: int) -> os.stat_result:
    """Classify one socket metadata observation without re-reading its path."""

    if (
        not stat.S_ISSOCK(value.st_mode)
        or value.st_uid != owner_uid
        or stat.S_IMODE(value.st_mode) & 0o007
    ):
        raise SignerProtocolError("signer_socket_unsafe", "signer socket is unsafe")
    if value.st_nlink == 2:
        raise SignerSocketPublicationPending(
            "signer_publication_pending", "signer socket publication is still in progress"
        )
    if value.st_nlink != 1:
        raise SignerProtocolError("signer_socket_unsafe", "signer socket is unsafe")
    return value


def validate_socket_inode(path: str, *, owner_uid: int) -> os.stat_result:
    """Pin one owner-confined Unix socket inode without following symlinks."""

    try:
        value = os.lstat(path)
    except FileNotFoundError as exc:
        raise SignerSocketUnavailable("signer_unavailable", "signer socket is unavailable") from exc
    except OSError as exc:
        raise SignerProtocolError("signer_socket_unsafe", "signer socket is unavailable") from exc
    return validate_socket_metadata(value, owner_uid=owner_uid)


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
        "_close_task",
        "_generation",
        "_lifecycle_lock",
        "_open_task",
        "_operations",
        "_reader",
        "_retiring",
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
        self._close_task: asyncio.Task[None] | None = None
        self._generation = 0
        self._lifecycle_lock = asyncio.Lock()
        self._open_task: asyncio.Task[None] | None = None
        self._operations: dict[asyncio.Task[object], _SignerSubmitOperation] = {}
        self._reader: asyncio.StreamReader | None = None
        self._retiring = False
        self._writer: asyncio.StreamWriter | None = None

    async def open(self) -> None:
        async with self._lifecycle_lock:
            if self._retiring or self._close_task is not None:
                raise SignerProtocolError("signer_protocol_invalid", "signer client is retiring")
            if self._writer is not None or self._open_task is not None:
                raise SignerProtocolError(
                    "signer_protocol_invalid", "signer client is already open"
                )
            self._generation += 1
            generation = self._generation
            opening = asyncio.create_task(
                self._finish_open(generation),
                name="weight-signer-open",
            )
            self._open_task = opening
        try:
            await opening
        except BaseException as primary:
            try:
                await drain_cleanup(
                    self._retire_open(opening, generation),
                    name="weight-signer-open-cleanup",
                )
            except BaseException:
                primary.add_note("signer_initialization_cleanup_failed")
            raise

    async def _finish_open(self, generation: int) -> None:
        current = asyncio.current_task()
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self.timeout_seconds
        try:
            while True:
                try:
                    before = validate_socket_inode(self.socket_path, owner_uid=self.signer_uid)
                except (SignerSocketPublicationPending, SignerSocketUnavailable) as exc:
                    if loop.time() >= deadline:
                        raise SignerProtocolError(
                            "signer_unavailable", "signer socket did not become available"
                        ) from exc
                    await asyncio.sleep(min(0.05, max(deadline - loop.time(), 0.0)))
                    continue
                try:
                    reader, writer = await asyncio.open_unix_connection(self.socket_path)
                except OSError as exc:
                    if socket_path_exists(self.socket_path):
                        raise SignerProtocolError(
                            "signer_socket_unsafe", "signer socket is unsafe"
                        ) from exc
                    if loop.time() >= deadline:
                        raise SignerProtocolError(
                            "signer_unavailable", "signer is unavailable"
                        ) from exc
                    await asyncio.sleep(min(0.05, max(deadline - loop.time(), 0.0)))
                    continue
                # Retain the acquired writer before another task can begin
                # retirement at the next await boundary.
                self._reader = reader
                self._writer = writer
                raw_socket = writer.get_extra_info("socket")
                if raw_socket is None or unix_peer_uid(raw_socket) != self.signer_uid:
                    raise SignerProtocolError(
                        "signer_peer_mismatch", "signer peer UID does not match"
                    )
                try:
                    after = validate_socket_inode(self.socket_path, owner_uid=self.signer_uid)
                except (SignerSocketPublicationPending, SignerSocketUnavailable) as exc:
                    raise SignerProtocolError(
                        "signer_socket_unsafe", "signer socket changed during connection"
                    ) from exc
                if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                    raise SignerProtocolError(
                        "signer_socket_unsafe", "signer socket changed during connection"
                    )
                async with self._lifecycle_lock:
                    if self._generation != generation or self._retiring:
                        raise SignerProtocolError(
                            "signer_protocol_invalid", "signer open was superseded by close"
                        )
                return
        finally:
            async with self._lifecycle_lock:
                if self._open_task is current:
                    self._open_task = None

    async def _retire_open(
        self,
        opening: asyncio.Task[None],
        generation: int,
    ) -> None:
        opening.cancel()
        async with self._lifecycle_lock:
            closing: asyncio.Task[None] | None = None
            if self._generation == generation:
                closing = self._close_task
                if closing is None and (self._writer is not None or self._open_task is opening):
                    closing = self._begin_close(self._writer, opening, generation)
                elif self._open_task is opening:
                    self._open_task = None
        if closing is None:
            await asyncio.gather(opening, return_exceptions=True)
            return
        await self._join_close(closing)

    async def close(self) -> None:
        caller = asyncio.current_task()
        if caller is not None and caller in self._operations:
            raise SignerProtocolError(
                "signer_protocol_invalid", "signer request cannot close its own client"
            )
        await drain_cleanup(self._request_close(), name="weight-signer-cleanup")

    async def _request_close(self) -> None:
        async with self._lifecycle_lock:
            closing = self._close_task
            if closing is None:
                writer = self._writer
                opening = self._open_task
                if writer is None and opening is None and not self._operations:
                    return
                closing = self._begin_close(writer, opening, self._generation)
        await self._join_close(closing)

    def _begin_close(
        self,
        writer: asyncio.StreamWriter | None,
        opening: asyncio.Task[None] | None,
        generation: int,
    ) -> asyncio.Task[None]:
        """Publish one generation-bound retirement while holding the lock."""

        self._retiring = True
        if opening is not None:
            opening.cancel()
        operations = tuple(
            operation
            for operation in self._operations.values()
            if operation.generation == generation and (writer is None or operation.writer is writer)
        )
        for operation in operations:
            if not operation.completion.done():
                operation.task.cancel()
        transport = writer.transport if writer is not None else None
        self._reader = None
        self._writer = None
        if self._open_task is opening:
            self._open_task = None
        closing = asyncio.create_task(
            self._finish_close(writer, transport, opening, operations, generation),
            name="weight-signer-retirement",
        )
        self._close_task = closing
        return closing

    async def _join_close(self, closing: asyncio.Task[None]) -> None:
        try:
            await closing
        finally:
            async with self._lifecycle_lock:
                if self._close_task is closing and closing.done():
                    self._close_task = None

    async def _finish_close(
        self,
        writer: asyncio.StreamWriter | None,
        transport: asyncio.BaseTransport | None,
        opening: asyncio.Task[None] | None,
        operations: tuple[_SignerSubmitOperation, ...],
        generation: int,
    ) -> None:
        primary: BaseException | None = None
        try:
            try:
                await self._retire_writer(writer, transport)
            except BaseException as exc:
                primary = exc
            if opening is not None:
                await asyncio.gather(opening, return_exceptions=True)
            await self._drain_submit_operations(operations)
            # A cancellation-resistant dial can acquire and publish after
            # _begin_close captured an empty writer slot. The generation gate
            # remains closed while the completed opener is drained, so repeat
            # ownership discovery until that generation has no writer left.
            while True:
                async with self._lifecycle_lock:
                    if self._generation != generation:
                        late_writer = None
                    else:
                        late_writer = self._writer
                        self._reader = None
                        self._writer = None
                if late_writer is None:
                    break
                try:
                    await self._retire_writer(late_writer, late_writer.transport)
                except BaseException as exc:
                    if primary is None:
                        primary = exc
                    else:
                        primary.add_note("signer_late_writer_retirement_failed")
            if primary is not None:
                raise primary
        finally:
            async with self._lifecycle_lock:
                if self._generation == generation:
                    self._retiring = False

    async def _retire_writer(
        self,
        writer: asyncio.StreamWriter | None,
        transport: asyncio.BaseTransport | None,
    ) -> None:
        """Independently close, abort, and boundedly drain one writer."""

        if writer is None:
            return
        primary: BaseException | None = None

        def failed(exc: BaseException, note: str) -> None:
            nonlocal primary
            if primary is None:
                primary = exc
            else:
                primary.add_note(note)

        try:
            writer.close()
        except BaseException as exc:
            failed(exc, "signer_writer_close_failed")
        abort = getattr(transport, "abort", None)
        if callable(abort):
            try:
                abort()
            except BaseException as exc:
                failed(exc, "signer_transport_abort_failed")
        try:
            async with asyncio.timeout(self.timeout_seconds):
                await writer.wait_closed()
        except BaseException as exc:
            failed(exc, "signer_writer_retirement_failed")
        if primary is not None:
            raise primary

    def _admit_submit(self) -> _SignerSubmitOperation:
        """Capture one complete request scope before its first await."""

        current = asyncio.current_task()
        if current is None:
            raise SignerProtocolError(
                "signer_protocol_invalid", "signer request has no owning task"
            )
        if self._retiring or self._close_task is not None:
            raise SignerProtocolError("signer_protocol_invalid", "signer client is retiring")
        reader = self._reader
        writer = self._writer
        if reader is None or writer is None:
            raise SignerProtocolError("signer_unavailable", "signer client is not open")
        if current in self._operations:
            raise SignerProtocolError(
                "signer_protocol_invalid", "signer task already owns a request"
            )
        operation = _SignerSubmitOperation(
            task=current,
            completion=asyncio.get_running_loop().create_future(),
            generation=self._generation,
            reader=reader,
            writer=writer,
        )
        self._operations[current] = operation
        return operation

    def _release_submit(self, operation: _SignerSubmitOperation) -> None:
        if self._operations.get(operation.task) is operation:
            del self._operations[operation.task]
        if not operation.completion.done():
            operation.completion.set_result(None)

    @staticmethod
    async def _drain_submit_operations(
        operations: tuple[_SignerSubmitOperation, ...],
    ) -> None:
        pending = tuple(
            operation.completion for operation in operations if not operation.completion.done()
        )
        if pending:
            await asyncio.gather(
                *(asyncio.shield(completion) for completion in pending),
                return_exceptions=True,
            )

    async def submit(self, vector: ExecutionVector) -> SubmissionResult:
        operation = self._admit_submit()
        try:
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
                    operation.writer.write(request.canonical_bytes())
                    await operation.writer.drain()
                    response = SignerResponse.from_bytes(await read_message(operation.reader))
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
                error = SignerProtocolError(
                    "submission_ambiguous",
                    "signer reported an ambiguous submission that requires reconciliation",
                )
                # The response was canonical, request-bound, and received from the
                # pinned signer UID. Preserve its safe signed-extrinsic reference
                # while retaining ambiguous effect certainty.
                error.extrinsic_ref = response.extrinsic_ref
                raise error
            return SubmissionResult(
                success=response.status == "confirmed",
                extrinsic_ref=response.extrinsic_ref,
                error_code=response.error_code,
            )
        finally:
            # No await: repeated cancellation cannot strand this completion.
            self._release_submit(operation)
