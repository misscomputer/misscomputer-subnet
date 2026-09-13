# SPDX-License-Identifier: AGPL-3.0-only
"""PR13 round-8 protocol compatibility and chain-retirement regressions."""

from __future__ import annotations

import asyncio
import json
import os
import sys
import threading
from pathlib import Path
from typing import Any

import bittensor
import pytest
from bittensor._substrate import RpcSubstrate
from bittensor._transport.interface import SubstrateConnection
from bittensor._transport.runtime import RuntimeManager
from jsonschema import Draft202012Validator
from test_weight_executor import (
    VALIDATOR,
    SequenceChain,
    acknowledged,
    metagraph,
    persist_plan,
)
from websockets.asyncio.client import ClientConnection
from websockets.asyncio.server import serve

import misscomputer_subnet.weight_executor as executor
import misscomputer_subnet.weight_signer_protocol as signer
from misscomputer_subnet.chain import BittensorChain

ROOT = Path(__file__).resolve().parents[2]


def _response_document(
    *,
    request_id: str,
    status: str,
    extrinsic_ref: str | None,
    error_code: str | None,
) -> dict[str, object]:
    return {
        "error_code": error_code,
        "extrinsic_ref": extrinsic_ref,
        "request_id": request_id,
        "schema": signer.WEIGHT_SIGNER_RESPONSE_SCHEMA,
        "schema_version": signer.WEIGHT_SIGNER_PROTOCOL_VERSION,
        "status": status,
    }


@pytest.mark.parametrize(
    ("status", "extrinsic_ref", "error_code"),
    [
        ("confirmed", "103-2", None),
        ("rejected", None, "not_authorized"),
        ("ambiguous", None, "submission_timeout"),
        ("ambiguous", "103-2", "submission_timeout"),
    ],
)
def test_v2_schema_and_parser_share_strict_response_semantics(
    status: str,
    extrinsic_ref: str | None,
    error_code: str | None,
) -> None:
    document = _response_document(
        request_id="ab" * 32,
        status=status,
        extrinsic_ref=extrinsic_ref,
        error_code=error_code,
    )
    schema = json.loads(
        (ROOT / "contracts/schemas/weight-signer-response.v2.schema.json").read_text()
    )
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(document)
    rendered = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"
    parsed = signer.SignerResponse.from_bytes(rendered)
    assert parsed.document() == document
    assert parsed.canonical_bytes() == rendered


@pytest.mark.parametrize(
    ("status", "extrinsic_ref", "error_code"),
    [
        ("confirmed", None, None),
        ("confirmed", "103-2", "unexpected_error"),
        ("rejected", "103-2", "not_authorized"),
        ("rejected", None, None),
        ("ambiguous", "103-2", None),
        ("ambiguous", "not canonical\n", "submission_timeout"),
    ],
)
def test_v2_parser_rejects_noncanonical_status_reference_combinations(
    status: str,
    extrinsic_ref: str | None,
    error_code: str | None,
) -> None:
    document = _response_document(
        request_id="ab" * 32,
        status=status,
        extrinsic_ref=extrinsic_ref,
        error_code=error_code,
    )
    schema = json.loads(
        (ROOT / "contracts/schemas/weight-signer-response.v2.schema.json").read_text()
    )
    assert not Draft202012Validator(schema).is_valid(document)
    rendered = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"
    with pytest.raises(signer.SignerProtocolError):
        signer.SignerResponse.from_bytes(rendered)


def _start_independent_v2_producer(
    socket_path: Path, extrinsic_ref: str | None
) -> tuple[threading.Thread, threading.Event, threading.Event, list[BaseException]]:
    ready = threading.Event()
    stop = threading.Event()
    failures: list[BaseException] = []

    def target() -> None:
        async def run() -> None:
            served = asyncio.Event()

            async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
                try:
                    raw_request = await reader.readuntil(b"\n")
                    request = json.loads(raw_request)
                    assert request["schema"] == signer.WEIGHT_SIGNER_REQUEST_SCHEMA
                    assert request["schema_version"] == 2
                    # This producer deliberately does not use SignerResponse. It
                    # models a separately distributed signer emitting canonical
                    # v2 bytes after signing extrinsic 103-2 while terminal
                    # submission confirmation remains unavailable.
                    document = _response_document(
                        request_id=request["request_id"],
                        status="ambiguous",
                        extrinsic_ref=extrinsic_ref,
                        error_code="submission_timeout",
                    )
                    writer.write(
                        json.dumps(document, sort_keys=True, separators=(",", ":")).encode("ascii")
                        + b"\n"
                    )
                    await writer.drain()
                    await reader.read()
                except BaseException as exc:
                    failures.append(exc)
                finally:
                    writer.close()
                    await writer.wait_closed()
                    served.set()

            server = await asyncio.start_unix_server(handle, path=socket_path)
            os.chmod(socket_path, 0o600)
            ready.set()
            try:
                served_waiter = asyncio.create_task(served.wait())
                stop_waiter = asyncio.create_task(asyncio.to_thread(stop.wait))
                _, pending = await asyncio.wait(
                    {served_waiter, stop_waiter}, return_when=asyncio.FIRST_COMPLETED
                )
                stop.set()
                for waiter in pending:
                    waiter.cancel()
                await asyncio.gather(*pending, return_exceptions=True)
            finally:
                server.close()
                await server.wait_closed()

        try:
            asyncio.run(run())
        except BaseException as exc:
            failures.append(exc)
            ready.set()

    thread = threading.Thread(target=target, name="independent-v2-signer", daemon=True)
    thread.start()
    return thread, ready, stop, failures


@pytest.mark.parametrize("extrinsic_ref", ["103-2", None], ids=["reference", "null-control"])
@pytest.mark.parametrize("audit_failure", [False, True], ids=["audit-ok", "audit-fails"])
def test_independent_v2_producer_reference_reaches_audit_and_cli(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    extrinsic_ref: str | None,
    audit_failure: bool,
) -> None:
    if os.getenv("MISSCOMPUTER_REQUIRE_INSTALLED_WHEEL") == "1":
        assert not Path(signer.__file__).resolve().is_relative_to(ROOT / "src")
    plan, plan_path = persist_plan(tmp_path)
    audit_path = tmp_path / "audit.json"
    socket_path = tmp_path / "s"
    thread, ready, stop, failures = _start_independent_v2_producer(socket_path, extrinsic_ref)
    assert socket_path.parent == tmp_path
    assert ready.wait(2)
    assert not failures
    assert socket_path.exists()

    argv = [
        "misscomputer-weight-executor",
        "--plan",
        str(plan_path),
        "--subtensor-network",
        "finney",
        "--netuid",
        "24",
        "--validator-hotkey",
        VALIDATOR,
        "--execute",
        "--confirm-network",
        "finney",
        "--confirm-netuid",
        "24",
        "--confirm-plan-digest",
        plan.digest_sha256,
        "--audit-state",
        str(audit_path),
        "--signer-socket",
        str(socket_path),
        "--signer-uid",
        str(os.getuid()),
        "--submission-timeout",
        "1",
    ]
    try:
        with monkeypatch.context() as patch:
            real_finish_attempt = executor.AuditStateStore.finish_attempt

            def finish_attempt(
                store: executor.AuditStateStore,
                attempt_id: str,
                *,
                status: executor.AuditStatus,
                outcome: executor.ReceiptOutcome,
                extrinsic_ref: str | None,
                error_code: str | None,
                timestamp: str,
            ) -> executor.AuditAttempt:
                if audit_failure and status == "ambiguous":
                    raise OSError("audit-persistence-sentinel")
                return real_finish_attempt(
                    store,
                    attempt_id,
                    status=status,
                    outcome=outcome,
                    extrinsic_ref=extrinsic_ref,
                    error_code=error_code,
                    timestamp=timestamp,
                )

            patch.setattr(sys, "argv", argv)
            patch.setattr(executor.AuditStateStore, "finish_attempt", finish_attempt)
            patch.setattr(
                executor,
                "build_chain_query",
                lambda **_: SequenceChain(metagraph(block=102)),
            )
            for key, value in acknowledged().items():
                patch.setenv(key, value)
            with pytest.raises(SystemExit) as escaped:
                executor.main()
        assert escaped.value.code == 2
        captured = capsys.readouterr()
        assert captured.out == ""
        diagnostic = json.loads(captured.err)
        expected_diagnostic: dict[str, object] = {
            "error_code": "submission_ambiguous",
            "status": "ambiguous",
        }
        if extrinsic_ref is not None:
            expected_diagnostic["extrinsic_ref"] = extrinsic_ref
        if audit_failure:
            expected_diagnostic["audit_error_code"] = "audit_persistence_failed"
        assert diagnostic == expected_diagnostic
        with executor.AuditStateStore(audit_path) as store:
            attempt = store.blocking_attempt(plan.digest_sha256)
            assert attempt is not None
            if audit_failure:
                assert attempt.status == "in_progress"
                assert attempt.receipt is None
            else:
                assert attempt.status == "ambiguous"
                assert attempt.receipt is not None
                assert attempt.receipt.extrinsic_ref == extrinsic_ref
                assert attempt.receipt.error_code == "submission_exception"
    finally:
        stop.set()
        thread.join(timeout=3)
    assert not thread.is_alive()
    assert not failures


class CloseSentinel(BaseException):
    pass


@pytest.mark.parametrize("close_error", [False, True], ids=["success", "error"])
@pytest.mark.parametrize("repeated_cancel", [False, True], ids=["ordinary", "cancelled"])
async def test_repeated_chain_close_joins_real_sdk_retirement_and_blocks_reopen(
    monkeypatch: pytest.MonkeyPatch,
    close_error: bool,
    repeated_cancel: bool,
) -> None:
    assert bittensor.__version__ == "11.1.0"
    connections: list[SubstrateConnection] = []
    server_connections: list[Any] = []
    close_started, release_close = asyncio.Event(), asyncio.Event()
    real_interface = RpcSubstrate._interface
    real_client_close = bittensor.Client.close
    original_error = CloseSentinel("original-client-close-error")
    close_calls = 0

    def interface(self: Any, *args: Any) -> SubstrateConnection:
        raw = real_interface(self, *args)
        connections.append(raw)
        return raw

    async def warm_codec(*args: Any, **kwargs: Any) -> None:
        return None

    async def handle(websocket: Any) -> None:
        server_connections.append(websocket)
        await websocket.wait_closed()

    monkeypatch.setattr(RpcSubstrate, "_interface", interface)
    monkeypatch.setattr(RuntimeManager, "codec_at", warm_codec)
    monkeypatch.setattr(bittensor.config, "token_symbols_fresh", lambda _: True)
    monkeypatch.setattr(bittensor.config, "load_token_symbols", lambda _: {})
    async with serve(handle, "127.0.0.1", 0) as server:
        before_tasks = {task for task in asyncio.all_tasks() if task.get_name() == "rpc-session"}
        before_fds = set(os.listdir("/proc/self/fd"))
        endpoint = f"ws://127.0.0.1:{server.sockets[0].getsockname()[1]}"
        chain = BittensorChain(network="finney", netuid=24, rpc_endpoint=endpoint)
        await chain.open()
        client = chain._BittensorChain__client
        raw = connections[0]
        websocket = raw._session._ws
        assert isinstance(websocket, ClientConnection)
        client_socket = websocket.transport.get_extra_info("socket")
        supervisor = raw._session._supervisor
        assert client_socket is not None and client_socket.fileno() >= 0
        assert supervisor is not None and not supervisor.done()

        async def delayed_client_close(candidate: Any) -> None:
            nonlocal close_calls
            if candidate is not client:
                await real_client_close(candidate)
                return
            close_calls += 1
            close_started.set()
            await release_close.wait()
            await real_client_close(candidate)
            if close_error:
                raise original_error

        monkeypatch.setattr(bittensor.Client, "close", delayed_client_close)
        first = asyncio.create_task(chain.close(), name="review-chain-close-first")
        second: asyncio.Task[None] | None = None
        reopen_error: BaseException | None = None
        try:
            await asyncio.wait_for(close_started.wait(), 2)
            second = asyncio.create_task(chain.close(), name="review-chain-close-second")
            await asyncio.sleep(0)
            if repeated_cancel:
                for _ in range(3):
                    second.cancel()
                    await asyncio.sleep(0)
            completed_early, _ = await asyncio.wait({second}, timeout=0.1)
            try:
                await chain.open()
            except BaseException as exc:
                reopen_error = exc
            assert not completed_early, "repeated close returned before Client.close retired"
            assert isinstance(reopen_error, RuntimeError), "reopen was admitted during retirement"
        finally:
            release_close.set()
            if second is None:
                results = await asyncio.gather(first, return_exceptions=True)
            else:
                results = await asyncio.gather(first, second, return_exceptions=True)
            await asyncio.gather(chain.close(), return_exceptions=True)
            for connection in connections:
                await asyncio.gather(connection.close(), return_exceptions=True)
            for peer in server_connections:
                peer.transport.abort()
            await asyncio.gather(
                *(peer.wait_closed() for peer in server_connections), return_exceptions=True
            )

        assert len(results) == 2
        if close_error:
            assert results[0] is original_error
            assert results[1] is original_error
        else:
            assert results[0] is None
            if repeated_cancel:
                assert isinstance(results[1], asyncio.CancelledError)
            else:
                assert results[1] is None
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        after_tasks = {task for task in asyncio.all_tasks() if task.get_name() == "rpc-session"}
        after_fds = set(os.listdir("/proc/self/fd"))
        assert close_calls == 1
        assert chain._BittensorChain__client is None
        assert raw._session._ws is None
        assert raw._session._supervisor is None or raw._session._supervisor.done()
        assert client_socket.fileno() < 0
        assert after_tasks == before_tasks
        assert after_fds == before_fds
