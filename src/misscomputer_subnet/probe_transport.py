# SPDX-License-Identifier: AGPL-3.0-only
"""Whole-request-deadline HTTPS plumbing for the public validator probe.

Everything here exists to make one policy budget, ``probe_timeout_millis``,
govern a probe request end to end: :class:`RequestBudget` measures it on one
monotonic clock with an exact millisecond boundary, and
:class:`DeadlineNetworkBackend` owns name resolution, address dialling, the
TLS handshake, and every socket read and write so that each is bounded by the
time remaining rather than by httpx's per-operation timeouts. No socket is ever
closed from another thread, so a stale read can never consume a reused file
descriptor. This module opens TCP connections and TLS sessions under the
caller's ``ssl.SSLContext`` and nothing else: no signing, wallets, chain,
process, or file capability.
"""

from __future__ import annotations

import os
import select
import signal
import socket
import ssl
import threading
import time
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager

import httpcore
import httpx


class RequestBudget:
    """One absolute whole-request budget, measured on one monotonic clock.

    Exact-boundary semantics, shared with
    :func:`~misscomputer_subnet.assignment_probe.verify_observation_policy_binding`:
    latency is the whole-request elapsed time in whole milliseconds (floor),
    the budget is the policy's ``probe_timeout_millis`` (``timeout_seconds``
    rounded to the millisecond), and a response-derived outcome is admissible
    only while ``latency_millis <= budget_millis``. A latency of exactly the
    budget is a response; one millisecond more is a ``timeout``. Latency is
    measured once per decision, so the value recorded is the value judged.
    The continuous I/O deadline is (budget_millis + 1) / 1000, matching that
    floor-inclusive interval rather than expiring one millisecond too early.
    """

    __slots__ = ("_clock", "_started", "budget_millis")

    def __init__(self, timeout_seconds: float, *, clock: Callable[[], float]) -> None:
        self._clock = clock
        self._started = clock()
        self.budget_millis = max(0, round(timeout_seconds * 1000))

    def latency_millis(self) -> int:
        return max(0, int((self._clock() - self._started) * 1000))

    def exhausted(self, latency_millis: int) -> bool:
        return latency_millis > self.budget_millis

    def remaining_seconds(self) -> float:
        """Seconds until floor(elapsed milliseconds) exceeds the budget; never negative."""

        return max(0.0, (self.budget_millis + 1) / 1000 - (self._clock() - self._started))


#: httpcore's socket option shape, restated so no private module is imported.
SOCKET_OPTION = (
    tuple[int, int, int] | tuple[int, int, bytes | bytearray] | tuple[int, int, None, int]
)


class DeadlineNetworkStream(httpcore.NetworkStream):
    """A socket stream whose every operation is bounded by the remaining request budget.

    httpcore applies one timeout per read or write, so a peer that trickles
    bytes just inside it can hold a request open indefinitely. This wrapper
    clamps every operation's timeout to ``min(per-operation, remaining)`` and
    raises the matching httpcore timeout when nothing remains, so the whole
    request, across TLS, headers, and body, ends at the budget. It never
    closes a socket from another thread, so no file descriptor can be reused
    under a still-blocked read.
    """

    def __init__(self, inner: httpcore.NetworkStream, remaining: Callable[[], float]) -> None:
        self._inner = inner
        self._remaining = remaining

    def _bounded(self, timeout: float | None, expired: type[Exception]) -> float:
        remaining = self._remaining()
        if remaining <= 0.0:
            raise expired("whole-request budget exhausted")
        return remaining if timeout is None else min(timeout, remaining)

    def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        return self._inner.read(max_bytes, timeout=self._bounded(timeout, httpcore.ReadTimeout))

    def write(self, buffer: bytes, timeout: float | None = None) -> None:
        # httpcore loops ``send`` with one timeout per call, so a peer that
        # drains the socket just fast enough could stretch a partial send far
        # past the budget; every ``send`` here is bounded by the time left.
        sock = self._inner.get_extra_info("socket")
        if not isinstance(sock, socket.socket):  # pragma: no cover - non-socket test streams
            self._inner.write(buffer, timeout=self._bounded(timeout, httpcore.WriteTimeout))
            return
        view = memoryview(buffer)
        while view:
            sock.settimeout(self._bounded(timeout, httpcore.WriteTimeout))
            try:
                sent = sock.send(view)
            except TimeoutError as exc:
                raise httpcore.WriteTimeout(str(exc)) from exc
            except OSError as exc:
                raise httpcore.WriteError(str(exc)) from exc
            if sent == 0:
                raise httpcore.WriteError("socket closed during write")
            view = view[sent:]

    def close(self) -> None:
        self._inner.close()

    def start_tls(
        self,
        ssl_context: ssl.SSLContext,
        server_hostname: str | None = None,
        timeout: float | None = None,
    ) -> httpcore.NetworkStream:
        upgraded = self._inner.start_tls(
            ssl_context,
            server_hostname=server_hostname,
            timeout=self._bounded(timeout, httpcore.ConnectTimeout),
        )
        return DeadlineNetworkStream(upgraded, self._remaining)

    def get_extra_info(self, info: str) -> object:
        return self._inner.get_extra_info(info)


#: One resolved address: ``(family, type, proto, sockaddr)``.
ResolvedAddress = tuple[socket.AddressFamily, socket.SocketKind, int, tuple[object, ...]]
Resolver = Callable[[str, int], list[ResolvedAddress]]
Dialer = Callable[[ResolvedAddress, float, str | None], socket.socket]


def _resolve_addresses(host: str, port: int) -> list[ResolvedAddress]:
    return [
        (family, kind, proto, tuple(sockaddr))
        for family, kind, proto, _canonical, sockaddr in socket.getaddrinfo(
            host, port, type=socket.SOCK_STREAM
        )
    ]


def _dial_address(
    address: ResolvedAddress, timeout: float, local_address: str | None
) -> socket.socket:
    family, kind, proto, sockaddr = address
    sock = socket.socket(family, kind, proto)
    try:
        sock.settimeout(timeout)
        if local_address is not None:
            sock.bind((local_address, 0))
        sock.connect(sockaddr)
    except BaseException:
        sock.close()
        raise
    return sock


class _SocketStream(httpcore.NetworkStream):
    """A plain blocking-socket stream with httpcore's exception mapping."""

    def __init__(self, sock: socket.socket) -> None:
        self._sock = sock

    def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        try:
            self._sock.settimeout(timeout)
            return self._sock.recv(max_bytes)
        except TimeoutError as exc:
            raise httpcore.ReadTimeout(str(exc)) from exc
        except OSError as exc:
            raise httpcore.ReadError(str(exc)) from exc

    def write(self, buffer: bytes, timeout: float | None = None) -> None:
        view = memoryview(buffer)
        while view:
            try:
                self._sock.settimeout(timeout)
                view = view[self._sock.send(view) :]
            except TimeoutError as exc:
                raise httpcore.WriteTimeout(str(exc)) from exc
            except OSError as exc:
                raise httpcore.WriteError(str(exc)) from exc

    def close(self) -> None:
        self._sock.close()

    def start_tls(
        self,
        ssl_context: ssl.SSLContext,
        server_hostname: str | None = None,
        timeout: float | None = None,
    ) -> httpcore.NetworkStream:
        try:
            self._sock.settimeout(timeout)
            upgraded = ssl_context.wrap_socket(self._sock, server_hostname=server_hostname)
        except TimeoutError as exc:
            raise httpcore.ConnectTimeout(str(exc)) from exc
        except OSError as exc:
            raise httpcore.ConnectError(str(exc)) from exc
        return _SocketStream(upgraded)

    def get_extra_info(self, info: str) -> object:
        if info == "ssl_object" and isinstance(self._sock, ssl.SSLSocket):
            return self._sock
        if info == "socket":
            return self._sock
        if info == "client_addr":
            return self._sock.getsockname()
        if info == "server_addr":
            return self._sock.getpeername()
        if info == "is_readable":
            readable, _, _ = select.select([self._sock], [], [], 0)
            return bool(readable)
        return None


#: Name resolutions that may be in flight at once, process-wide. ``getaddrinfo``
#: cannot be cancelled, so a lookup that overruns its budget is abandoned on its
#: helper thread; this bounds how many such threads can exist, and a request
#: that finds no slot fails fast instead of queueing.
MAX_OUTSTANDING_RESOLUTIONS = 16
_RESOLUTION_SLOTS = threading.BoundedSemaphore(MAX_OUTSTANDING_RESOLUTIONS)


def _reset_resolution_slots_after_fork() -> None:
    # Parent workers do not survive fork. Never inherit their held permits or
    # mutexes; existing default backends resolve the process-local pool on use.
    global _RESOLUTION_SLOTS
    _RESOLUTION_SLOTS = threading.BoundedSemaphore(MAX_OUTSTANDING_RESOLUTIONS)


os.register_at_fork(after_in_child=_reset_resolution_slots_after_fork)


@contextmanager
def _lease_transition() -> Iterator[None]:
    """Defer SIGINT across the semaphore/state update, not across DNS or waits.

    Python delivers signal handlers on the main thread. Masking SIGINT here
    closes the acquire-before-record and mark-before-release interruption
    windows. A pending interrupt is delivered after the invariant is restored.
    Arbitrary interpreter thread-exception injection is not a supported API.
    """

    if threading.current_thread() is not threading.main_thread():
        yield
        return
    previous = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT})
    try:
        yield
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous)


class _ResolutionLease:
    """Exactly-once creator -> worker ownership, with cancellation before claim."""

    def __init__(self, slots: threading.BoundedSemaphore) -> None:
        self._slots = slots
        self._lock = threading.Lock()
        self._state = "new"

    def acquire(self) -> None:
        with _lease_transition(), self._lock:
            if not self._slots.acquire(blocking=False):
                raise httpcore.ConnectError("resolver capacity exhausted")
            self._state = "creator"

    def claim(self) -> bool:
        with self._lock:
            if self._state != "creator":
                return False
            self._state = "worker"
            return True

    def cancel(self) -> None:
        with _lease_transition(), self._lock:
            if self._state == "creator":
                self._state = "released"
                self._slots.release()

    def finish(self) -> None:
        with _lease_transition(), self._lock:
            if self._state == "worker":
                self._state = "released"
                self._slots.release()


class DeadlineNetworkBackend(httpcore.NetworkBackend):
    """The synchronous httpcore backend with every connection bounded by one budget.

    Name resolution and dialing are owned here rather than delegated to
    ``socket.create_connection``: ``getaddrinfo`` runs on a helper thread that
    the caller waits on for exactly the remaining budget (the call itself
    cannot be cancelled and involves no file descriptor, so abandoning it is
    safe), and each resolved address is dialled with the budget remaining at
    that instant, so three unreachable addresses cost one budget, not three.
    Helper threads are drawn from a process-wide pool of
    ``MAX_OUTSTANDING_RESOLUTIONS`` slots with no queue: while that many
    lookups are still blocked, a new request fails fast with a connection
    error rather than adding another thread. ``resolver``, ``dialer``, and
    ``resolution_slots`` exist so every path can be tested deterministically.
    """

    def __init__(
        self,
        remaining: Callable[[], float],
        *,
        resolver: Resolver = _resolve_addresses,
        dialer: Dialer = _dial_address,
        resolution_slots: threading.BoundedSemaphore | None = None,
    ) -> None:
        self._remaining = remaining
        self._resolver = resolver
        self._dialer = dialer
        self._slots = resolution_slots

    def _resolve_within_budget(self, host: str, port: int) -> list[ResolvedAddress]:
        if self._remaining() <= 0.0:
            raise httpcore.ConnectTimeout("whole-request budget exhausted")
        # Allocate every fallible object before admission. The creator owns
        # the lease until the worker claims it under the same lock used by
        # cancellation. A launched-but-not-yet-running worker may be cancelled
        # safely: it will then never enter the resolver.
        outcome: list[list[ResolvedAddress] | BaseException] = []
        done = threading.Event()
        lease = _ResolutionLease(self._slots or _RESOLUTION_SLOTS)

        def resolve() -> None:
            try:
                if not lease.claim():
                    return
                try:
                    outcome.append(self._resolver(host, port))
                except BaseException as exc:
                    outcome.append(exc)
            finally:
                # Signaling failure cannot leak a completed lookup's permit.
                try:
                    done.set()
                finally:
                    lease.finish()

        worker = threading.Thread(target=resolve, name="misscomputer-probe-resolve", daemon=True)
        try:
            lease.acquire()
            if self._remaining() <= 0.0:
                raise httpcore.ConnectTimeout("whole-request budget exhausted")
            worker.start()
            remaining = self._remaining()
            if remaining <= 0.0 or not done.wait(timeout=remaining) or not outcome:
                raise httpcore.ConnectTimeout("name resolution exceeded the whole-request budget")
            if self._remaining() <= 0.0:
                raise httpcore.ConnectTimeout("name resolution exceeded the whole-request budget")
            result = outcome[0]
            if isinstance(result, BaseException):
                raise httpcore.ConnectError(str(result)) from result
            if not result:
                raise httpcore.ConnectError("name resolved to no addresses")
            return result
        finally:
            # This can release only creator ownership. Once claimed, even an
            # asynchronous exception from Thread.start leaves the worker owner.
            lease.cancel()

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[SOCKET_OPTION] | None = None,
    ) -> httpcore.NetworkStream:
        addresses = self._resolve_within_budget(host, port)
        last_error: Exception | None = None
        for address in addresses:
            remaining = self._remaining()
            if remaining <= 0.0:
                raise httpcore.ConnectTimeout("whole-request budget exhausted")
            try:
                sock = self._dialer(
                    address,
                    remaining if timeout is None else min(timeout, remaining),
                    local_address,
                )
            except TimeoutError as exc:
                last_error = httpcore.ConnectTimeout(str(exc))
                continue
            except OSError as exc:
                last_error = httpcore.ConnectError(str(exc))
                continue
            try:
                for option in socket_options or ():
                    sock.setsockopt(*option)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                if self._remaining() <= 0.0:
                    raise httpcore.ConnectTimeout("whole-request budget exhausted")
                return DeadlineNetworkStream(_SocketStream(sock), self._remaining)
            except BaseException:
                sock.close()
                raise
        raise last_error or httpcore.ConnectError("no address could be dialled")

    def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Iterable[SOCKET_OPTION] | None = None,
    ) -> httpcore.NetworkStream:  # pragma: no cover - probes never use unix sockets
        raise httpcore.ConnectError("unix sockets are not probe targets")

    def sleep(self, seconds: float) -> None:  # pragma: no cover - retries are disabled
        time.sleep(seconds)


class _DeadlineHTTPTransport(httpx.HTTPTransport):
    """``httpx.HTTPTransport`` whose connection pool uses :class:`DeadlineNetworkBackend`."""

    def __init__(self, context: ssl.SSLContext, remaining: Callable[[], float]) -> None:
        super().__init__(verify=context, retries=0, http2=False, trust_env=False)
        self._pool = httpcore.ConnectionPool(
            ssl_context=context,
            max_connections=1,
            max_keepalive_connections=0,
            http1=True,
            http2=False,
            retries=0,
            network_backend=DeadlineNetworkBackend(remaining),
        )


TransportBuilder = Callable[[ssl.SSLContext, Callable[[], float]], httpx.BaseTransport]


def default_httpx_transport(
    context: ssl.SSLContext, remaining: Callable[[], float]
) -> httpx.BaseTransport:
    return _DeadlineHTTPTransport(context, remaining)
