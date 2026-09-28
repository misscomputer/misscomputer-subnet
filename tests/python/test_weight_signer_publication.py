# SPDX-License-Identifier: AGPL-3.0-only
"""Real-filesystem regressions for signer socket publication."""

from __future__ import annotations

import asyncio
import os
import stat
from pathlib import Path

import pytest

from misscomputer_subnet.weight_signer_protocol import (
    SignerProtocolError,
    SignerSocketPublicationPending,
    UnixWeightSignerClient,
    validate_socket_inode,
    validate_socket_metadata,
)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("mode", stat.S_IFLNK | 0o600),
        ("uid", os.geteuid() + 1),
        ("mode", stat.S_IFSOCK | 0o607),
        ("nlink", 0),
        ("nlink", 3),
    ],
)
def test_nonpublication_socket_metadata_remains_terminal(field: str, value: int) -> None:
    fields = list(os.stat_result((stat.S_IFSOCK | 0o600, 1, 1, 1, os.geteuid(), 0, 0, 0, 0, 0)))
    fields[{"mode": 0, "nlink": 3, "uid": 4}[field]] = value

    with pytest.raises(SignerProtocolError, match="^signer socket is unsafe$") as caught:
        validate_socket_metadata(os.stat_result(fields), owner_uid=os.geteuid())

    assert type(caught.value) is SignerProtocolError


async def test_client_retries_real_two_link_socket_publication(tmp_path: Path) -> None:
    """A real staging hard link is retryable only before a connection exists."""

    socket_path = tmp_path / "signer.sock"
    staging_path = tmp_path / "signer.staging.sock"
    accepted = asyncio.Event()

    async def handle(_reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        accepted.set()
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_unix_server(handle, path=socket_path)
    socket_path.chmod(0o600)
    os.link(socket_path, staging_path)
    observed = os.lstat(socket_path)
    assert observed.st_nlink == 2
    with pytest.raises(SignerSocketPublicationPending):
        validate_socket_inode(str(socket_path), owner_uid=os.geteuid())

    client = UnixWeightSignerClient(
        socket_path=str(socket_path),
        signer_uid=os.geteuid(),
        hotkey="Validator",
        timeout_seconds=1.0,
    )
    opening = asyncio.create_task(client.open())
    try:
        await asyncio.sleep(0.1)
        assert not opening.done()
        assert not accepted.is_set()
        staging_path.unlink()
        await asyncio.wait_for(opening, 1.0)
        await asyncio.wait_for(accepted.wait(), 1.0)
        assert os.lstat(socket_path).st_nlink == 1
    finally:
        staging_path.unlink(missing_ok=True)
        await client.close()
        server.close()
        await server.wait_closed()
