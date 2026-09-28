# SPDX-License-Identifier: AGPL-3.0-only
"""Whole-request probe budget cutoff on the real transport backend."""

from __future__ import annotations

import socket

import httpcore
import pytest

from misscomputer_subnet import probe_transport as t


@pytest.mark.parametrize("elapsed", [0.1005, 0.101])
def test_real_backend_cutoff(elapsed: float) -> None:
    now = [0.0]
    budget = t.RequestBudget(0.1, clock=lambda: now[0])
    now[0] = elapsed
    # Real TCP dial + socket stream; only DNS and the monotonic clock are injected.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(1)
        port = listener.getsockname()[1]
        backend = t.DeadlineNetworkBackend(
            budget.remaining_seconds,
            resolver=lambda h, p: [(socket.AF_INET, socket.SOCK_STREAM, 0, ("127.0.0.1", port))],
        )
        if elapsed == 0.101:
            assert budget.latency_millis() == 101 and budget.exhausted(101)
            assert budget.remaining_seconds() == 0
            with pytest.raises(httpcore.ConnectTimeout):
                backend.connect_tcp("invalid", port)
        else:
            assert budget.latency_millis() == 100 and not budget.exhausted(100)
            assert budget.remaining_seconds() == pytest.approx(0.0005)
            stream = backend.connect_tcp("invalid", port)
            try:
                peer, _ = listener.accept()
                with peer:
                    peer.sendall(b"ok")
                    assert stream.read(2) == b"ok"
                    stream.write(b"yes")
                    assert peer.recv(3) == b"yes"
                    now[0] = 0.101
                    with pytest.raises(httpcore.ReadTimeout):
                        stream.read(1)
                    with pytest.raises(httpcore.WriteTimeout):
                        stream.write(b"late")
            finally:
                stream.close()
