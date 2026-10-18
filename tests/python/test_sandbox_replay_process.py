# SPDX-License-Identifier: AGPL-3.0-only
"""Fresh-process replay over actual HMAC -> btauth -> HMAC -> Go/SQLite.

The Go test fixture substitutes only the unused isolation backend. It signs
original test documents and independently verifies actual Go receipts. This
is not the disposable runtime-kill/two-minute canary or host-isolation proof.
"""

from __future__ import annotations

import asyncio
import contextlib
import copy
import json
import os
import shutil
import socket
import sqlite3
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest

from misscomputer_subnet.auth import BridgeClient, bridge_headers, sign_service_binding
from misscomputer_subnet.chain import MockChain, MockPeer
from misscomputer_subnet.organic_contracts import format_timestamp
from misscomputer_subnet.protocol import ServiceKeyBinding
from misscomputer_subnet.validator import ValidatorNeuron

ROOT = Path(__file__).resolve().parents[2]
SECRET = b"sandbox-replay-local-test-secret-32"


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def stop_process(process: subprocess.Popen[str]) -> None:
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)


async def wait_http(url: str, process: subprocess.Popen[str], expected: int) -> None:
    async with httpx.AsyncClient(trust_env=False) as client:
        async with asyncio.timeout(30):
            while True:
                assert process.poll() is None, "fixture process exited"
                try:
                    if (await client.get(url, timeout=1)).status_code == expected:
                        return
                except httpx.HTTPError:
                    pass
                await asyncio.sleep(0.05)


def sandbox_rows(path: Path) -> list[Any]:
    with contextlib.closing(sqlite3.connect(f"file:{path}?mode=ro", uri=True)) as db:
        return [
            db.execute(query).fetchall()
            for query in (
                "SELECT * FROM sandbox_holds ORDER BY 1",
                "SELECT * FROM sandbox_leases ORDER BY 1",
                "SELECT * FROM sandbox_release_fences ORDER BY 1",
            )
        ]


@pytest.mark.asyncio
async def test_fresh_validator_replays_real_hold_without_runtime_or_scheduling(
    tmp_path: Path,
) -> None:
    """History alone cannot schedule; fresh current authority can only observe.

    Primary ownership: cross-process authentication/restore/dispatch, not a
    duplicate simulation of Go hold semantics. Every receipt is made and
    signature/digest-checked by the actual Go protocol implementation.
    """
    go = shutil.which("go") or "/usr/local/go/bin/go"
    if not await asyncio.to_thread(Path(go).is_file):
        pytest.skip("Go toolchain required for Python/Go contract proof")
    binary = tmp_path / "agent-test"
    built = await asyncio.create_subprocess_exec(
        go, "test", "-c", "-o", str(binary), "./cmd/miner-agent", cwd=ROOT
    )
    assert await built.wait() == 0
    fixture = await asyncio.to_thread(
        subprocess.Popen,  # exact local test binary
        [str(binary), "-test.run=^TestSandboxReplayProcessFixture$"],
        env={**os.environ, "MC_REPLAY_FIXTURE_DIR": str(tmp_path)},
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    processes: list[subprocess.Popen[str]] = []
    try:
        assert fixture.stdout is not None and fixture.stdin is not None
        async with asyncio.timeout(10):
            info = json.loads(await asyncio.to_thread(fixture.stdout.readline))

        async def command(value: dict[str, Any]) -> Any:
            assert fixture.stdout is not None and fixture.stdin is not None
            fixture.stdin.write(json.dumps(value) + "\n")
            fixture.stdin.flush()
            async with asyncio.timeout(10):
                return json.loads(await asyncio.to_thread(fixture.stdout.readline))

        miner_port, validator_port, dead_runtime_port = free_port(), free_port(), free_port()
        miner_url = f"http://127.0.0.1:{miner_port}"
        validator_url = f"http://127.0.0.1:{validator_port}"
        runtime_url = f"http://127.0.0.1:{dead_runtime_port}"
        secret_file = tmp_path / "secret"
        secret_file.write_bytes(SECRET)
        peers = (
            MockPeer("//Alice", 0, None, True, 10_000),
            MockPeer("//Bob", 1, miner_url, False, 100),
        )
        peers_file = tmp_path / "peers.json"
        peers_file.write_text(
            json.dumps(
                [
                    {
                        "uri": p.uri,
                        "uid": p.uid,
                        "axon": p.axon,
                        "validator_permit": p.validator_permit,
                        "tao_stake": p.tao_stake,
                    }
                    for p in peers
                ]
            )
        )
        common = [
            "--netuid",
            "24",
            "--operator-hotkey",
            peers[0].hotkey,
            "--subtensor-network",
            "local",
            "--mock-peers",
            str(peers_file),
            "--mock-tempo",
            "180",
            "--allow-insecure-mock-http",
            "--bridge-secret-file",
            str(secret_file),
            "--sandbox-leases",
            "on",
            "--sandbox-reservation-replay",
            "on",
            "--sync-interval",
            "1",
        ]
        with (tmp_path / "miner.log").open("w") as log:
            miner = await asyncio.to_thread(
                subprocess.Popen,  # exact installed module, loopback only
                [
                    sys.executable,
                    "-m",
                    "misscomputer_subnet.miner",
                    *common,
                    "--mock-uri",
                    "//Bob",
                    "--axon-host",
                    "127.0.0.1",
                    "--axon-port",
                    str(miner_port),
                    "--uid",
                    "1",
                    "--go-agent-url",
                    info["url"],
                    "--state-db",
                    str(tmp_path / "miner.db"),
                ],
                stdout=log,
                stderr=log,
                text=True,
            )
        processes.append(miner)
        await wait_http(miner_url + "/healthz", miner, 204)

        # Seed a genuine signed/committed publication using the production
        # owner and a live capability handshake. This is explicit test history,
        # not a claim that a Go runtime acknowledged an interrupted publication.
        chain = MockChain(network="local", netuid=24, own_uri="//Alice", peers=peers, tempo=180)
        old = ValidatorNeuron(
            chain=chain,
            hotkey_signer=chain.hotkey_signer,
            network="local",
            netuid=24,
            bridge=BridgeClient(runtime_url, SECRET, timeout=1, retries=0),
            bridge_secret=SECRET,
            state_db=str(tmp_path / "validator.db"),
            bridge_url=validator_url,
            sync_interval=1,
            dendrite_timeout=3,
            dendrite_retries=0,
            allow_private_axons=True,
            mock_http_axons=True,
            sandbox_leases=True,
            sandbox_reservation_replay=True,
        )
        snapshot = await chain.sync()
        remote = await old._handshake(snapshot, snapshot.neurons[1])
        binding = sign_service_binding(
            ServiceKeyBinding(
                role="validator",
                transport="local",
                transport_certificate_sha256=None,
                network="local",
                netuid=24,
                hotkey=chain.hotkey,
                uid=0,
                service_public_key=info["validator_key"],
                generation=snapshot.block + 1,
                valid_from_block=snapshot.block,
                expires_at_block=snapshot.block + 360,
                challenge="validator-service:" + info["validator_key"],
            ),
            chain.hotkey_signer,
        )
        old._commit_miner_view_locked(
            snapshot, {remote.neuron.hotkey: remote}, binding, inventory_drain=False
        )
        old.ready.set()
        await old.state.set(snapshot)
        vectors = json.loads(
            (ROOT / "pkg/protocol/testdata/sandbox-lease-v1-vectors.json").read_text()
        )
        document = copy.deepcopy(vectors["reservation"])
        now = datetime.now(UTC)
        document.update(
            miner_id=remote.neuron.hotkey,
            issued_at=format_timestamp(now),
            hold_expires_at=format_timestamp(now + timedelta(minutes=2)),
        )
        document["subnet"].update(
            network="local",
            netuid=24,
            validator_hotkey=chain.hotkey,
            miner_hotkey=remote.neuron.hotkey,
            miner_uid=1,
            miner_axon_url=miner_url,
            miner_transport="http",
            miner_tls_certificate_sha256=None,
            validator_service_public_key=info["validator_key"],
            miner_service_public_key=info["miner_key"],
            chain_block=snapshot.block,
            epoch=snapshot.epoch,
            expires_at_block=snapshot.block + 180,
        )
        document = await command({"operation": "sign", "reservation": document})
        value = {
            "protocol": "subnet-sandbox-synapse.v1",
            "request_id": "original",
            "document": document,
        }
        normal_path = f"/v1/miners/{remote.neuron.hotkey}/sandbox-reservations"
        replay_path = normal_path + "/replay"

        async def post(
            client: httpx.AsyncClient, path: str, value: dict[str, Any]
        ) -> httpx.Response:
            body = json.dumps(value, separators=(",", ":")).encode()
            return await client.post(
                path,
                content=body,
                headers=bridge_headers(SECRET, method="POST", target=path, body=body),
            )

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=old.app), base_url=validator_url
        ) as client:
            initial = await post(client, normal_path, value)
        assert initial.status_code == 200, initial.text
        assert initial.json()["receipt"]["stage"] == "held"
        assert await command(
            {"operation": "verify", "reservation": document, "receipt": initial.json()["receipt"]}
        ) == {"verified": True}
        before = sandbox_rows(tmp_path / "agent.db")
        assert len(before[0]) == 1 and before[1:] == [[], []]
        del old
        with (tmp_path / "validator.log").open("w") as log:
            restarted = await asyncio.to_thread(
                subprocess.Popen,  # exact installed module, loopback only
                [
                    sys.executable,
                    "-m",
                    "misscomputer_subnet.validator",
                    *common,
                    "--mock-uri",
                    "//Alice",
                    "--bridge-port",
                    str(validator_port),
                    "--go-control-url",
                    runtime_url,
                    "--allow-private-axons",
                    "--state-db",
                    str(tmp_path / "validator.db"),
                    "--dendrite-timeout",
                    "3",
                    "--dendrite-retries",
                    "0",
                ],
                stdout=log,
                stderr=log,
                text=True,
            )
        processes.append(restarted)
        await wait_http(validator_url + "/healthz", restarted, 503)
        async with httpx.AsyncClient(base_url=validator_url, trust_env=False, timeout=10) as client:
            async with asyncio.timeout(20):
                while True:
                    replay = await post(client, replay_path, value)
                    if replay.status_code != 503:
                        break
                    await asyncio.sleep(0.1)
            assert replay.status_code == 200, replay.text
            assert replay.json()["receipt"]["stage"] == "held"
            assert await command(
                {
                    "operation": "verify",
                    "reservation": document,
                    "receipt": replay.json()["receipt"],
                }
            ) == {"verified": True}
            absent = copy.deepcopy(document)
            absent["sandbox_id"] = "sbx-" + "e" * 32
            absent["reservation_nonce"] = "e" * 32
            absent = await command({"operation": "sign", "reservation": absent})
            refused = await post(client, replay_path, {**value, "document": absent})
            assert refused.status_code == 404, refused.text
            assert refused.json()["error"]["code"] == "sandbox_replay_hold_absent"
            # This artificial expired document tests cross-hop error coding,
            # not the original-hold two-minute canary or its attribution proof.
            expired = copy.deepcopy(absent)
            expired["issued_at"] = format_timestamp(now - timedelta(minutes=2))
            expired["hold_expires_at"] = format_timestamp(now - timedelta(minutes=1))
            expired = await command({"operation": "sign", "reservation": expired})
            refused = await post(client, replay_path, {**value, "document": expired})
            assert refused.status_code == 410, refused.text
            assert refused.json()["error"]["code"] == "expired_assignment"
            assert (await post(client, normal_path, value)).status_code == 503
            assert (await client.get("/healthz")).status_code == 503
        assert sandbox_rows(tmp_path / "agent.db") == before
        assert restarted.pid != os.getpid()
        async with httpx.AsyncClient(trust_env=False) as client:
            with pytest.raises(httpx.ConnectError):
                await client.get(runtime_url, timeout=1)
    finally:
        for process in reversed(processes):
            await asyncio.to_thread(stop_process, process)
        if fixture.stdin is not None:
            fixture.stdin.close()
        try:
            code = await asyncio.to_thread(fixture.wait, timeout=10)
        except subprocess.TimeoutExpired:
            await asyncio.to_thread(stop_process, fixture)
            raise
        assert code == 0, (fixture.stdout.read() if fixture.stdout else "") + (
            fixture.stderr.read() if fixture.stderr else ""
        )
