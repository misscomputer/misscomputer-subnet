# SPDX-License-Identifier: AGPL-3.0-only
"""Separately privileged one-shot weight signer for one confirmed WeightPlan.

The signer is the only component that loads a validator hotkey for weight
submission. It serves exactly one peer-UID-authenticated weight-signer v2
request over an owner-confined Unix socket and then exits. It never signs
request-supplied data: it reloads its own copy of the plan, derives the
execution vector from its own finalized chain reads, requires the request to
match that derivation exactly, records a durable in-progress receipt, and only
then constructs its wallet and SDK client. There is no general signing API.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import math
import os
import secrets
import socket
import stat
import sys
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass, field
from typing import Any, Literal, Protocol

from .chain_quorum import build_chain_query, json_stderr_alert
from .weight_executor import (
    AuditAttempt,
    AuditStateError,
    AuditStateStore,
    ExecutionChain,
    ExecutionVector,
    WeightExecutionError,
    _safe_error_code,
    _safe_reference,
    _utc_now,
    _validate_digest,
    _validate_public_network,
    _validate_public_text,
    _validate_uint,
    derive_execution_vector,
)
from .weight_plan import (
    WEIGHT_PLAN_PROTOCOL_VERSION_KEY,
    WeightPlan,
    WeightPlanError,
    WeightPlanTargetError,
    _pin_directory_chain,
    _PinnedDirectoryChain,
    _secure_file_location,
    load_weight_plan,
    snapshot_identity_fingerprint,
)
from .weight_signer_protocol import (
    MAX_SIGNER_MESSAGE_BYTES,
    SignerProtocolError,
    SignerRequest,
    SignerResponse,
    unix_peer_uid,
)

SIGNER_SOCKET_MODE = 0o660
MAX_SIGNER_WAIT_SECONDS = 86_400.0
MAX_SIGNER_SUBMISSION_SECONDS = 3_600.0
_UNIX_PATH_LIMIT = 107

SignerStatus = Literal["confirmed", "rejected", "ambiguous"]


class WeightSignerError(RuntimeError):
    """A sanitized signer failure; ``status`` states submission effect certainty."""

    def __init__(self, code: str, message: str, *, status: SignerStatus = "rejected") -> None:
        super().__init__(message)
        self.code = code
        self.status: SignerStatus = status


def _require_seconds(value: object, name: str, maximum: float) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or not 0.0 < float(value) <= maximum
    ):
        raise WeightSignerError("signer_configuration_invalid", f"{name} is invalid")
    return float(value)


@dataclass(frozen=True, slots=True)
class SignerConfig:
    """Operator-confirmed identity of the one plan this signer may submit."""

    plan_path: str
    audit_state_path: str
    socket_path: str
    executor_uid: int
    network: str
    netuid: int
    validator_hotkey: str
    confirm_plan_digest: str
    confirm_execution_digest: str
    socket_gid: int | None = None
    accept_timeout_seconds: float = 900.0
    request_timeout_seconds: float = 120.0
    submission_timeout_seconds: float = 150.0

    def __post_init__(self) -> None:
        for name in ("plan_path", "audit_state_path", "socket_path"):
            value = getattr(self, name)
            if not isinstance(value, str) or not os.path.isabs(value):
                raise WeightSignerError(
                    "signer_configuration_invalid", f"{name} must be an absolute path"
                )
        paths = {
            os.path.normpath(self.plan_path),
            os.path.normpath(self.audit_state_path),
            os.path.normpath(self.socket_path),
        }
        if len(paths) != 3:
            raise WeightSignerError(
                "signer_configuration_invalid", "plan, audit, and socket paths must differ"
            )
        try:
            _validate_uint(self.executor_uid, "executor UID", 2**32 - 2)
            if self.socket_gid is not None:
                _validate_uint(self.socket_gid, "socket GID", 2**32 - 2)
            _validate_public_network(self.network, "signer network")
            _validate_uint(self.netuid, "signer netuid", 65_535)
            _validate_public_text(self.validator_hotkey, "signer validator hotkey")
            _validate_digest(self.confirm_plan_digest, "confirmed plan digest")
            _validate_digest(self.confirm_execution_digest, "confirmed execution digest")
        except WeightExecutionError as exc:
            raise WeightSignerError("signer_configuration_invalid", str(exc)) from exc
        _require_seconds(self.accept_timeout_seconds, "accept timeout", MAX_SIGNER_WAIT_SECONDS)
        _require_seconds(self.request_timeout_seconds, "request timeout", MAX_SIGNER_WAIT_SECONDS)
        _require_seconds(
            self.submission_timeout_seconds,
            "submission timeout",
            MAX_SIGNER_SUBMISSION_SECONDS,
        )


def require_separate_identity(*, signer_uid: int, executor_uid: int) -> None:
    """The signer must be neither root nor the executor's OS account."""

    if signer_uid == 0:
        raise WeightSignerError("signer_identity_unsafe", "the signer must not run as root")
    if signer_uid == executor_uid:
        raise WeightSignerError(
            "signer_identity_unsafe", "the signer and executor must be different OS users"
        )


@dataclass(frozen=True, slots=True)
class SubmissionOutcome:
    """Effect certainty of one SDK submission, without free-form chain text."""

    status: SignerStatus
    extrinsic_ref: str | None = None
    error_code: str | None = None

    def __post_init__(self) -> None:
        if self.status not in {"confirmed", "rejected", "ambiguous"}:
            raise ValueError("submission outcome status is invalid")
        if self.extrinsic_ref is not None and _safe_reference(self.extrinsic_ref) is None:
            raise ValueError("submission outcome reference is invalid")
        if self.error_code is not None and _safe_error_code(self.error_code) != self.error_code:
            raise ValueError("submission outcome error code is invalid")
        if self.status == "confirmed" and (self.extrinsic_ref is None or self.error_code):
            raise ValueError("confirmed submission outcome is incomplete")
        if self.status != "confirmed" and self.error_code is None:
            raise ValueError("unconfirmed submission outcome lacks an error code")


class WeightSubmission(Protocol):
    """The wallet-holding submission capability, constructed only after admission."""

    hotkey: str

    async def open(self) -> None: ...

    async def close(self) -> None: ...

    async def submit(self, vector: ExecutionVector) -> SubmissionOutcome: ...


class _CommitRevealRefused(Exception):
    """Raised by the intent build before any signing when a timelocked commit is chosen."""


def _plaintext_set_weights_type() -> type[Any]:
    import bittensor as bt
    from bittensor.intents.base import BuiltCall

    class PlaintextSetWeights(bt.SetWeights):  # type: ignore[misc]
        """``SetWeights`` that fails at build time instead of committing timelocked weights."""

        async def build(self, substrate: Any, wallet: Any) -> Any:
            built = await super().build(substrate, wallet)
            if isinstance(built, BuiltCall):
                raise _CommitRevealRefused("commit-reveal weights are unsupported")
            return built

    return PlaintextSetWeights


class BittensorWeightSubmission:
    """One zero-retry ``SetWeights`` execution through the pinned Bittensor SDK."""

    def __init__(
        self,
        *,
        netuid: int,
        version_key: int,
        wallet_factory: Callable[[], tuple[Any, str]],
        client_factory: Callable[[], Any],
        intent_type: Callable[[], type[Any]] = _plaintext_set_weights_type,
    ) -> None:
        self.netuid = netuid
        self.version_key = version_key
        self.hotkey = ""
        self._wallet_factory = wallet_factory
        self._client_factory = client_factory
        self._intent_type = intent_type
        self._wallet: Any = None
        self._client: Any = None
        self._submitted = False

    async def open(self) -> None:
        if self._wallet is not None or self._client is not None:
            raise WeightSignerError("submission_unavailable", "submission is already open")
        self._wallet, hotkey = self._wallet_factory()
        self.hotkey = str(hotkey)
        client = self._client_factory()
        self._client = client
        await client.connect()

    async def close(self) -> None:
        client, self._client = self._client, None
        self._wallet = None
        if client is not None:
            result = client.close()
            if hasattr(result, "__await__"):
                await result

    async def submit(self, vector: ExecutionVector) -> SubmissionOutcome:
        if self._client is None or self._wallet is None:
            raise WeightSignerError("submission_unavailable", "submission is not open")
        if self._submitted:
            raise WeightSignerError("submission_unavailable", "submission was already used")
        if vector.netuid != self.netuid or vector.version_key != self.version_key:
            raise WeightSignerError("submission_unavailable", "vector identity is unexpected")
        self._submitted = True
        intent = self._intent_type()(
            netuid=vector.netuid,
            uids=[item.uid for item in vector.weights],
            weights=[item.weight for item in vector.weights],
            version_key=vector.version_key,
        )
        try:
            result = await self._client.execute(
                intent,
                self._wallet,
                retries=0,
                wait_for_inclusion=True,
                wait_for_finalization=True,
            )
        except _CommitRevealRefused:
            # Raised by our own build override inside plan(), before the SDK
            # resolves a signer: nothing was signed or submitted.
            return SubmissionOutcome("rejected", error_code="commit_reveal_unsupported")
        except Exception:
            # An SDK preflight failure cannot be distinguished from a failure
            # after signing by the exception alone.
            return SubmissionOutcome("ambiguous", error_code="submission_exception")
        return classify_extrinsic_result(result)


def classify_extrinsic_result(result: Any) -> SubmissionOutcome:
    """Map an SDK ``ExtrinsicResult`` to effect certainty, failing toward ambiguity."""

    success = getattr(result, "success", None)
    reference = _safe_reference(getattr(result, "extrinsic_id", None))
    data = getattr(result, "data", None)
    if isinstance(data, Mapping) and "reveal_round" in data:
        # A timelocked commit is not applied weights; never record it as confirmed.
        return SubmissionOutcome("ambiguous", reference, "commit_reveal_submitted")
    if success is True:
        if reference is None:
            return SubmissionOutcome("ambiguous", None, "missing_extrinsic_reference")
        return SubmissionOutcome("confirmed", reference, None)
    if success is False and reference is not None:
        # Included in a block with a failed dispatch: definitively not applied.
        return SubmissionOutcome("rejected", reference, "chain_rejected")
    # A failure without an inclusion reference may be a pool rejection or a
    # lost subscription after the extrinsic entered the pool.
    return SubmissionOutcome("ambiguous", None, "submission_not_included")


class _PublishedSocket:
    """Bind privately, then publish one owner-confined listening socket by hard link."""

    def __init__(self, path: str, *, socket_gid: int) -> None:
        self._chain: _PinnedDirectoryChain | None = None
        self._listener: socket.socket | None = None
        self._staging: str | None = None
        self._identity: tuple[int, int] | None = None
        try:
            parent, self._name = _secure_file_location(path)
            self._chain = _pin_directory_chain(parent)
        except (OSError, WeightPlanTargetError) as exc:
            raise WeightSignerError("signer_socket_unsafe", "socket directory is unsafe") from exc
        try:
            self._publish(socket_gid)
        except BaseException:
            self.close()
            raise

    def _publish(self, socket_gid: int) -> None:
        assert self._chain is not None
        directory_fd = self._chain.parent_fd
        directory = os.fstat(directory_fd)
        if directory.st_uid != os.geteuid() or stat.S_IMODE(directory.st_mode) & 0o027:
            raise WeightSignerError(
                "signer_socket_unsafe",
                "socket directory must be signer-owned without group write or other access",
            )
        if _lexists(directory_fd, self._name):
            raise WeightSignerError("signer_socket_exists", "signer socket path already exists")
        staging = f".{self._name}.staging-{secrets.token_hex(8)}"
        bind_path = f"/proc/self/fd/{directory_fd}/{staging}"
        if len(os.fsencode(bind_path)) > _UNIX_PATH_LIMIT:
            raise WeightSignerError("signer_socket_unsafe", "signer socket name is too long")
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM | socket.SOCK_CLOEXEC)
        self._listener = listener
        previous = os.umask(0o177)
        try:
            listener.bind(bind_path)
        except OSError as exc:
            raise WeightSignerError("signer_socket_unsafe", "signer socket bind failed") from exc
        finally:
            os.umask(previous)
        self._staging = staging
        try:
            listener.listen(8)
            listener.setblocking(False)
            os.chown(staging, -1, socket_gid, dir_fd=directory_fd, follow_symlinks=False)
            os.chmod(staging, SIGNER_SOCKET_MODE, dir_fd=directory_fd)
            staged = os.stat(staging, dir_fd=directory_fd, follow_symlinks=False)
            if (
                not stat.S_ISSOCK(staged.st_mode)
                or staged.st_uid != os.geteuid()
                or staged.st_gid != socket_gid
                or stat.S_IMODE(staged.st_mode) != SIGNER_SOCKET_MODE
                or staged.st_nlink != 1
            ):
                raise WeightSignerError("signer_socket_unsafe", "staged signer socket is unsafe")
            os.link(
                staging,
                self._name,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
                follow_symlinks=False,
            )
            self._identity = (staged.st_dev, staged.st_ino)
            os.unlink(staging, dir_fd=directory_fd)
            self._staging = None
            published = os.stat(self._name, dir_fd=directory_fd, follow_symlinks=False)
            if (published.st_dev, published.st_ino) != self._identity or published.st_nlink != 1:
                raise WeightSignerError("signer_socket_unsafe", "published socket changed")
        except FileExistsError as exc:
            raise WeightSignerError(
                "signer_socket_exists", "signer socket path already exists"
            ) from exc
        except OSError as exc:
            raise WeightSignerError(
                "signer_socket_unsafe", "signer socket publication failed"
            ) from exc

    @property
    def listener(self) -> socket.socket:
        if self._listener is None:
            raise WeightSignerError("signer_socket_unsafe", "signer socket is closed")
        return self._listener

    def retire(self) -> None:
        """Remove the public name and stop listening; established peers are unaffected."""

        chain = self._chain
        staging, self._staging = self._staging, None
        identity, self._identity = self._identity, None
        try:
            if chain is not None and chain.descriptors:
                directory_fd = chain.parent_fd
                if staging is not None:
                    # A random private name in the signer-only directory.
                    with suppress(FileNotFoundError):
                        os.unlink(staging, dir_fd=directory_fd)
                if identity is not None:
                    # Remove the public name only while it is still our inode.
                    with suppress(FileNotFoundError):
                        current = os.stat(self._name, dir_fd=directory_fd, follow_symlinks=False)
                        if (current.st_dev, current.st_ino) == identity:
                            os.unlink(self._name, dir_fd=directory_fd)
        finally:
            listener, self._listener = self._listener, None
            if listener is not None:
                listener.close()

    def close(self) -> None:
        try:
            self.retire()
        finally:
            chain, self._chain = self._chain, None
            if chain is not None:
                chain.close()


def _lexists(directory_fd: int, name: str) -> bool:
    try:
        os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return False
    return True


@dataclass(slots=True)
class SignerRunResult:
    status: SignerStatus
    plan_digest_sha256: str
    error_code: str | None = None
    extrinsic_ref: str | None = None
    execution_digest_sha256: str | None = None
    request_id: str | None = None
    attempt_id: str | None = None
    rejected_peer_count: int = 0
    audit_error_code: str | None = None
    response_error_code: str | None = None
    cleanup_error_codes: list[str] = field(default_factory=list)

    def document(self) -> dict[str, object]:
        document: dict[str, object] = {
            "attempt_id": self.attempt_id,
            "error_code": self.error_code,
            "execution_digest_sha256": self.execution_digest_sha256,
            "extrinsic_ref": self.extrinsic_ref,
            "plan_digest_sha256": self.plan_digest_sha256,
            "rejected_peer_count": self.rejected_peer_count,
            "request_id": self.request_id,
            "status": self.status,
        }
        if self.audit_error_code is not None:
            document["audit_error_code"] = self.audit_error_code
        if self.response_error_code is not None:
            document["response_error_code"] = self.response_error_code
        if self.cleanup_error_codes:
            document["cleanup_error_codes"] = list(self.cleanup_error_codes)
        return document


def _load_confirmed_plan(config: SignerConfig) -> WeightPlan:
    try:
        plan = load_weight_plan(config.plan_path)
    except (WeightPlanError, OSError) as exc:
        raise WeightSignerError("invalid_plan", "signer plan verification failed") from exc
    if plan.digest_sha256 != config.confirm_plan_digest:
        raise WeightSignerError(
            "plan_digest_confirmation_required", "signer plan differs from the confirmed digest"
        )
    if plan.network != config.network:
        raise WeightSignerError("wrong_network", "signer plan network differs")
    if plan.netuid != config.netuid:
        raise WeightSignerError("wrong_netuid", "signer plan netuid differs")
    if plan.validator_hotkey != config.validator_hotkey:
        raise WeightSignerError("wrong_validator", "signer plan validator differs")
    if plan.version_key != WEIGHT_PLAN_PROTOCOL_VERSION_KEY:
        raise WeightSignerError("unsupported_version_key", "plan version key is unsupported")
    return plan


async def _accept_authorized(
    listener: socket.socket,
    *,
    executor_uid: int,
    timeout_seconds: float,
    result: SignerRunResult,
) -> socket.socket:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout_seconds
    while True:
        remaining = deadline - loop.time()
        if remaining <= 0:
            raise WeightSignerError("request_timeout", "no authorized executor connected")
        try:
            async with asyncio.timeout(remaining):
                connection, _ = await loop.sock_accept(listener)
        except TimeoutError as exc:
            raise WeightSignerError("request_timeout", "no authorized executor connected") from exc
        try:
            peer_uid = unix_peer_uid(connection)
        except SignerProtocolError:
            peer_uid = None
        if peer_uid == executor_uid:
            connection.setblocking(False)
            return connection
        result.rejected_peer_count += 1
        print(
            json.dumps({"alert_code": "signer_peer_rejected", "peer_uid": peer_uid}),
            file=sys.stderr,
        )
        connection.close()


async def _read_request(connection: socket.socket, timeout_seconds: float) -> bytes:
    loop = asyncio.get_running_loop()
    received = bytearray()
    try:
        async with asyncio.timeout(timeout_seconds):
            while b"\n" not in received:
                chunk = await loop.sock_recv(connection, 65_536)
                if not chunk:
                    break
                received += chunk
                if len(received) > MAX_SIGNER_MESSAGE_BYTES:
                    break
    except TimeoutError as exc:
        raise WeightSignerError("request_timeout", "signer request timed out") from exc
    except OSError as exc:
        raise WeightSignerError("request_invalid", "signer request was not received") from exc
    end = received.find(b"\n")
    if end < 0 or end + 1 != len(received) or len(received) > MAX_SIGNER_MESSAGE_BYTES:
        raise WeightSignerError("request_invalid", "signer request framing is invalid")
    return bytes(received)


def _admit_request_identity(request: SignerRequest, plan: WeightPlan) -> None:
    if (
        request.network != plan.network
        or request.netuid != plan.netuid
        or request.validator_hotkey != plan.validator_hotkey
        or request.plan_digest_sha256 != plan.digest_sha256
    ):
        raise WeightSignerError("request_plan_mismatch", "request does not name the signer plan")


def _admit_request_vector(
    request: SignerRequest,
    vector: ExecutionVector,
    config: SignerConfig,
) -> None:
    if (
        request.execution_digest_sha256 != vector.digest_sha256
        or request.execution_vector != vector
    ):
        raise WeightSignerError(
            "execution_vector_mismatch", "request vector differs from the signer derivation"
        )
    if vector.digest_sha256 != config.confirm_execution_digest:
        raise WeightSignerError(
            "execution_digest_confirmation_required",
            "derived vector differs from the confirmed execution digest",
        )


def _as_signer_error(exc: BaseException, fallback: str) -> WeightSignerError:
    if isinstance(exc, WeightSignerError):
        return exc
    if isinstance(exc, WeightExecutionError):
        return WeightSignerError(exc.code, str(exc))
    return WeightSignerError(fallback, "signer operation failed")


async def _derive_current(
    plan: WeightPlan, chain: ExecutionChain, config: SignerConfig
) -> tuple[Any, ExecutionVector]:
    snapshot = await chain.sync()
    vector = derive_execution_vector(
        plan,
        snapshot,
        network=config.network,
        netuid=config.netuid,
        validator_hotkey=config.validator_hotkey,
    )
    if await chain.commit_reveal_enabled(snapshot.block):
        raise WeightSignerError(
            "commit_reveal_unsupported", "commit-reveal weights are unsupported by this signer"
        )
    return snapshot, vector


@dataclass(slots=True)
class _SignerResources:
    chain: ExecutionChain
    store: AuditStateStore | None = None
    publication: _PublishedSocket | None = None
    connection: socket.socket | None = None
    submission: WeightSubmission | None = None
    chain_opened: bool = False

    async def close(self, result: SignerRunResult) -> None:
        def failed(code: str) -> None:
            result.cleanup_error_codes.append(code)

        if self.connection is not None:
            try:
                self.connection.close()
            except BaseException:
                failed("connection_cleanup_failed")
        if self.publication is not None:
            try:
                self.publication.close()
            except BaseException:
                failed("socket_cleanup_failed")
        if self.submission is not None:
            try:
                await self.submission.close()
            except BaseException:
                failed("submission_cleanup_failed")
        if self.chain_opened:
            try:
                await self.chain.close()
            except BaseException:
                failed("chain_cleanup_failed")
        if self.store is not None:
            try:
                self.store.close()
            except BaseException:
                failed("audit_cleanup_failed")


async def run_weight_signer(
    config: SignerConfig,
    *,
    chain: ExecutionChain,
    submission_factory: Callable[[WeightPlan], WeightSubmission],
    clock: Callable[[], str] = _utc_now,
) -> SignerRunResult:
    """Serve one authorized request, submit at most once, and durably record the effect."""

    plan = _load_confirmed_plan(config)
    result = SignerRunResult(status="rejected", plan_digest_sha256=plan.digest_sha256)
    resources = _SignerResources(chain)
    try:
        await _serve(config, plan, resources, result, submission_factory, clock)
    finally:
        task = asyncio.create_task(resources.close(result), name="weight-signer-cleanup")
        while not task.done():
            try:
                await asyncio.shield(task)
            except asyncio.CancelledError:
                result.cleanup_error_codes.append("cleanup_cancelled")
        task.result()
    return result


async def _serve(
    config: SignerConfig,
    plan: WeightPlan,
    resources: _SignerResources,
    result: SignerRunResult,
    submission_factory: Callable[[WeightPlan], WeightSubmission],
    clock: Callable[[], str],
) -> None:
    try:
        store = resources.store = AuditStateStore(config.audit_state_path)
    except AuditStateError as exc:
        raise WeightSignerError(exc.code, "signer audit state is unavailable") from exc
    if store.blocking_attempt(plan.digest_sha256) is not None:
        raise WeightSignerError(
            "idempotency_blocked", "this plan has a prior non-retryable or unresolved attempt"
        )
    gid = os.getegid() if config.socket_gid is None else config.socket_gid
    publication = resources.publication = _PublishedSocket(config.socket_path, socket_gid=gid)
    connection = resources.connection = await _accept_authorized(
        publication.listener,
        executor_uid=config.executor_uid,
        timeout_seconds=config.accept_timeout_seconds,
        result=result,
    )
    try:
        rendered = await _read_request(connection, config.request_timeout_seconds)
    finally:
        # One-shot: stop listening once the admitted peer is served. The name is
        # kept until the request arrives because the client re-validates the
        # published inode after connecting and before it sends.
        publication.retire()
    try:
        request = SignerRequest.from_bytes(rendered)
    except SignerProtocolError as exc:
        raise WeightSignerError("request_invalid", "signer request is invalid") from exc
    result.request_id = request.request_id

    async def respond(response: SignerResponse) -> None:
        loop = asyncio.get_running_loop()
        try:
            async with asyncio.timeout(config.request_timeout_seconds):
                await loop.sock_sendall(connection, response.canonical_bytes())
        except (OSError, TimeoutError):
            result.response_error_code = "response_delivery_failed"

    async def reject(error: WeightSignerError) -> None:
        result.status = "rejected"
        result.error_code = error.code
        await respond(SignerResponse(request.request_id, "rejected", None, error.code))

    try:
        _admit_request_identity(request, plan)
        try:
            resources.chain_opened = True
            await resources.chain.open()
            snapshot, vector = await _derive_current(plan, resources.chain, config)
        except Exception as exc:
            raise _as_signer_error(exc, "chain_preflight_failed") from exc
        result.execution_digest_sha256 = vector.digest_sha256
        _admit_request_vector(request, vector, config)
        try:
            attempt = store.start_attempt(
                vector,
                preflight_block=snapshot.block,
                timestamp=clock(),
                attempt_nonce=request.request_id,
            )
        except AuditStateError as exc:
            raise WeightSignerError(exc.code, "signer audit receipt was not recorded") from exc
    except WeightSignerError as error:
        await reject(error)
        return
    result.attempt_id = attempt.attempt_id

    # Everything below owns a durable attempt. The wallet and SDK client are
    # constructed only now, after the in-progress receipt is installed.
    try:
        try:
            submission = resources.submission = submission_factory(plan)
            await submission.open()
        except Exception as exc:
            raise WeightSignerError("submission_unavailable", "signing is unavailable") from exc
        if submission.hotkey != config.validator_hotkey:
            raise WeightSignerError(
                "signer_hotkey_mismatch", "signer wallet does not match the plan validator"
            )
        try:
            send_snapshot, send_vector = await _derive_current(plan, resources.chain, config)
        except Exception as exc:
            raise _as_signer_error(exc, "pre_send_state_unavailable") from exc
        if send_snapshot.block < snapshot.block or (
            send_snapshot.block == snapshot.block
            and snapshot_identity_fingerprint(send_snapshot)
            != snapshot_identity_fingerprint(snapshot)
        ):
            raise WeightSignerError("pre_send_state_changed", "chain state changed before send")
        if send_vector != vector:
            raise WeightSignerError(
                "pre_send_state_changed", "the execution vector changed before send"
            )
    except WeightSignerError as error:
        _record_pre_send_failure(store, attempt, error.code, clock, result)
        await reject(error)
        return

    try:
        attempt = store.mark_submission_started(
            attempt.attempt_id,
            send_check_block=send_snapshot.block,
            timestamp=clock(),
        )
    except BaseException as exc:
        # The in-progress receipt remains replay-blocking; nothing was signed.
        result.audit_error_code = "audit_persistence_failed"
        await reject(WeightSignerError("audit_state_unsafe", "send marker was not recorded"))
        if not isinstance(exc, Exception):
            raise
        return

    try:
        async with asyncio.timeout(config.submission_timeout_seconds):
            outcome = await submission.submit(send_vector)
        if not isinstance(outcome, SubmissionOutcome):
            raise TypeError("submission returned an unsupported outcome")
    except TimeoutError:
        outcome = SubmissionOutcome("ambiguous", None, "submission_timeout")
    except Exception:
        outcome = SubmissionOutcome("ambiguous", None, "submission_exception")
    _record_outcome(store, attempt, outcome, clock, result)
    result.status = outcome.status
    result.error_code = outcome.error_code
    result.extrinsic_ref = outcome.extrinsic_ref
    await respond(
        SignerResponse(
            request.request_id,
            outcome.status,
            None if outcome.status == "rejected" else outcome.extrinsic_ref,
            outcome.error_code,
        )
    )


def _record_pre_send_failure(
    store: AuditStateStore,
    attempt: AuditAttempt,
    code: str,
    clock: Callable[[], str],
    result: SignerRunResult,
) -> None:
    try:
        store.finish_attempt(
            attempt.attempt_id,
            status="failed",
            outcome="pre_send_failure",
            extrinsic_ref=None,
            error_code=code,
            timestamp=clock(),
        )
    except Exception:
        result.audit_error_code = "audit_persistence_failed"


def _record_outcome(
    store: AuditStateStore,
    attempt: AuditAttempt,
    outcome: SubmissionOutcome,
    clock: Callable[[], str],
    result: SignerRunResult,
) -> None:
    status: Literal["confirmed", "failed", "ambiguous"] = (
        "failed" if outcome.status == "rejected" else outcome.status
    )
    try:
        store.finish_attempt(
            attempt.attempt_id,
            status=status,
            outcome="definite_failure" if outcome.status == "rejected" else outcome.status,
            extrinsic_ref=outcome.extrinsic_ref,
            error_code=outcome.error_code,
            timestamp=clock(),
        )
    except BaseException:
        # Never retry a write against a possibly replaced inode. The durable
        # submission_started marker already blocks any replay.
        result.audit_error_code = "audit_persistence_failed"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", required=True, help="signer-owned mode-0600 WeightPlan copy")
    parser.add_argument("--audit-state", required=True, help="signer-owned durable audit ledger")
    parser.add_argument("--socket", required=True, help="Unix socket path to publish")
    parser.add_argument("--socket-gid", type=int, help="group allowed to connect (default: egid)")
    parser.add_argument("--executor-uid", type=int, required=True)
    parser.add_argument("--subtensor-network", default=os.getenv("BT_NETWORK", "finney"))
    parser.add_argument("--netuid", type=int, required=True)
    parser.add_argument("--validator-hotkey", required=True, help="expected public hotkey")
    parser.add_argument("--confirm-plan-digest", required=True)
    parser.add_argument("--confirm-execution-digest", required=True)
    parser.add_argument("--rpc-endpoint", action="append", default=[])
    parser.add_argument("--rpc-max-finalized-lag", type=int, default=8)
    parser.add_argument(
        "--submit-endpoint",
        help="single ws(s) endpoint for submission (default: the network's endpoint)",
    )
    parser.add_argument("--wallet-name", required=True)
    parser.add_argument("--wallet-hotkey", required=True)
    parser.add_argument("--wallet-path", default="~/.bittensor/wallets")
    parser.add_argument("--accept-timeout", type=float, default=900.0)
    parser.add_argument("--request-timeout", type=float, default=120.0)
    parser.add_argument("--submission-timeout", type=float, default=150.0)
    return parser


def _config_from_args(args: argparse.Namespace) -> SignerConfig:
    return SignerConfig(
        plan_path=args.plan,
        audit_state_path=args.audit_state,
        socket_path=args.socket,
        socket_gid=args.socket_gid,
        executor_uid=args.executor_uid,
        network=args.subtensor_network,
        netuid=args.netuid,
        validator_hotkey=args.validator_hotkey,
        confirm_plan_digest=args.confirm_plan_digest,
        confirm_execution_digest=args.confirm_execution_digest,
        accept_timeout_seconds=args.accept_timeout,
        request_timeout_seconds=args.request_timeout,
        submission_timeout_seconds=args.submission_timeout,
    )


def _sdk_submission_factory(
    args: argparse.Namespace,
) -> Callable[[WeightPlan], WeightSubmission]:
    endpoint = args.submit_endpoint or args.subtensor_network
    wallet_path = os.path.expanduser(args.wallet_path)

    def wallet_factory() -> tuple[Any, str]:
        import bittensor as bt

        wallet = bt.Wallet(args.wallet_name, args.wallet_hotkey, path=wallet_path)
        return wallet, str(bt.resolve_signer(wallet, role="hotkey").ss58_address)

    def client_factory() -> Any:
        import bittensor as bt

        from .chain_transport import _OwnedRpcSubstrate

        # Pinned: no transport fallback endpoint may receive the extrinsic.
        return bt.Client(endpoint, substrate=_OwnedRpcSubstrate(endpoint, pinned=True))

    def factory(plan: WeightPlan) -> WeightSubmission:
        return BittensorWeightSubmission(
            netuid=plan.netuid,
            version_key=plan.version_key,
            wallet_factory=wallet_factory,
            client_factory=client_factory,
        )

    return factory


EXIT_CODES: dict[SignerStatus, int] = {"confirmed": 0, "rejected": 2, "ambiguous": 3}


def main() -> None:
    args = build_parser().parse_args()
    try:
        config = _config_from_args(args)
        require_separate_identity(signer_uid=os.geteuid(), executor_uid=config.executor_uid)
        try:
            chain = build_chain_query(
                network=config.network,
                netuid=config.netuid,
                rpc_endpoints=args.rpc_endpoint,
                max_finalized_lag=args.rpc_max_finalized_lag,
                alert_sink=json_stderr_alert,
            )
        except ValueError as exc:
            raise WeightSignerError(
                "rpc_configuration_invalid", "redundant RPC configuration is invalid"
            ) from exc
        result = asyncio.run(
            run_weight_signer(
                config,
                chain=chain,
                submission_factory=_sdk_submission_factory(args),
            )
        )
    except WeightSignerError as exc:
        print(
            json.dumps({"error_code": exc.code, "status": exc.status}, sort_keys=True),
            file=sys.stderr,
        )
        raise SystemExit(2) from None
    rendered = json.dumps(result.document(), sort_keys=True, separators=(",", ":"))
    print(rendered, file=sys.stdout if result.status == "confirmed" else sys.stderr)
    code = EXIT_CODES[result.status]
    if code == 0 and result.audit_error_code is not None:
        code = 3
    raise SystemExit(code)


if __name__ == "__main__":
    main()
