"""Bounded local HTTP server for the HOL Guard control plane.

The native runtime already uses bounded queues. The surrounding HTTP server must
not create an unbounded Python thread per accepted socket, otherwise a local
request flood or slow client can exhaust memory and file descriptors before the
native admission controls run.
"""

from __future__ import annotations

import ipaddress
import json
import os
import socket
import threading
from dataclasses import dataclass
from http.server import ThreadingHTTPServer
from typing import Any, cast

_DEFAULT_ACTIVE_REQUESTS = 64
_DEFAULT_LISTEN_BACKLOG = 128
_DEFAULT_SOCKET_TIMEOUT_SECONDS = 5.0
_MAX_ACTIVE_REQUESTS = 256
_MAX_LISTEN_BACKLOG = 512
_MAX_SOCKET_TIMEOUT_SECONDS = 30.0
_OVERLOAD_REQUEST_DRAIN_LIMIT_BYTES = 16 * 1024
_OVERLOAD_REQUEST_DRAIN_TIMEOUT_SECONDS = 0.05


def _bounded_int(name: str, default: int, maximum: int) -> int:
    value = os.environ.get(name)
    if value is None:
        return default
    try:
        parsed = int(value)
    except ValueError:
        return default
    return max(1, min(parsed, maximum))


def _bounded_float(name: str, default: float, maximum: float) -> float:
    value = os.environ.get(name)
    if value is None:
        return default
    try:
        parsed = float(value)
    except ValueError:
        return default
    return max(0.25, min(parsed, maximum))


@dataclass(frozen=True, slots=True)
class DaemonAdmissionSnapshot:
    active: int
    high_water: int
    accepted: int
    rejected: int
    client_aborts: int
    timeouts: int
    non_loopback_rejections: int

    def to_dict(self) -> dict[str, int]:
        return {
            "active": self.active,
            "high_water": self.high_water,
            "accepted": self.accepted,
            "rejected": self.rejected,
            "client_aborts": self.client_aborts,
            "timeouts": self.timeouts,
            "non_loopback_rejections": self.non_loopback_rejections,
        }


class _Metrics:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.active = 0
        self.high_water = 0
        self.accepted = 0
        self.rejected = 0
        self.client_aborts = 0
        self.timeouts = 0
        self.non_loopback_rejections = 0

    def acquired(self) -> None:
        with self.lock:
            self.active += 1
            self.accepted += 1
            self.high_water = max(self.high_water, self.active)

    def released(self) -> None:
        with self.lock:
            self.active -= 1

    def rejected_overload(self) -> None:
        with self.lock:
            self.rejected += 1

    def rejected_non_loopback(self) -> None:
        with self.lock:
            self.non_loopback_rejections += 1

    def abort(self) -> None:
        with self.lock:
            self.client_aborts += 1

    def timeout(self) -> None:
        with self.lock:
            self.timeouts += 1

    def snapshot(self) -> DaemonAdmissionSnapshot:
        with self.lock:
            return DaemonAdmissionSnapshot(
                active=self.active,
                high_water=self.high_water,
                accepted=self.accepted,
                rejected=self.rejected,
                client_aborts=self.client_aborts,
                timeouts=self.timeouts,
                non_loopback_rejections=self.non_loopback_rejections,
            )


_METRICS = _Metrics()


def _loopback(client_address: object) -> bool:
    if not isinstance(client_address, tuple) or not client_address:
        return False
    host = client_address[0]
    if not isinstance(host, str):
        return False
    try:
        return ipaddress.ip_address(host.split("%", 1)[0]).is_loopback
    except ValueError:
        return False


def _overload_response() -> bytes:
    payload = json.dumps(
        {
            "error": "daemon_overloaded",
            "message": "HOL Guard is busy. Retry the unchanged request shortly.",
            "retryable": True,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return (
        b"HTTP/1.1 503 Service Unavailable\r\n"
        b"Connection: close\r\n"
        b"Content-Type: application/json\r\n"
        b"Cache-Control: no-store\r\n"
        b"Retry-After: 1\r\n" + f"Content-Length: {len(payload)}\r\n\r\n".encode("ascii") + payload
    )


def _drain_overload_request(request: socket.socket) -> None:
    # Drain only a bounded request header so Windows can deliver the 503 before close.

    request.settimeout(_OVERLOAD_REQUEST_DRAIN_TIMEOUT_SECONDS)
    remaining = _OVERLOAD_REQUEST_DRAIN_LIMIT_BYTES
    trailing = b""
    while remaining > 0:
        try:
            chunk = request.recv(min(4096, remaining))
        except OSError:
            return
        if not chunk:
            return
        remaining -= len(chunk)
        combined = trailing + chunk
        if b"\r\n\r\n" in combined or b"\n\n" in combined:
            return
        trailing = combined[-3:]


class BoundedThreadingHTTPServer(ThreadingHTTPServer):
    """Loopback-only HTTP server with bounded active request threads."""

    daemon_threads = True
    block_on_close = False
    allow_reuse_address = True
    allow_reuse_port = False
    request_queue_size = _bounded_int(
        "HOL_GUARD_DAEMON_LISTEN_BACKLOG",
        _DEFAULT_LISTEN_BACKLOG,
        _MAX_LISTEN_BACKLOG,
    )

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._BaseServer__shutdown_request = False
        capacity = _bounded_int(
            "HOL_GUARD_DAEMON_MAX_ACTIVE_REQUESTS",
            _DEFAULT_ACTIVE_REQUESTS,
            _MAX_ACTIVE_REQUESTS,
        )
        self._guard_slots = threading.BoundedSemaphore(capacity)
        self._guard_socket_timeout = _bounded_float(
            "HOL_GUARD_DAEMON_SOCKET_TIMEOUT_SECONDS",
            _DEFAULT_SOCKET_TIMEOUT_SECONDS,
            _MAX_SOCKET_TIMEOUT_SECONDS,
        )

    def request_serve_stop(self) -> None:
        """Request loop termination without waiting for loop entry.

        ``BaseServer.shutdown`` waits for ``serve_forever`` to acknowledge the
        request, which deadlocks if startup has not entered the loop yet. The
        loop reads this flag both before and after polling, so setting it is
        safe on either side of loop entry.
        """
        self._BaseServer__shutdown_request = True

    def verify_request(self, request: Any, client_address: Any) -> bool:
        if not _loopback(client_address):
            _METRICS.rejected_non_loopback()
            return False
        return super().verify_request(request, cast(Any, client_address))

    def process_request(self, request: Any, client_address: Any) -> None:
        request_socket = cast(socket.socket, request)
        if not self._guard_admit_request(request_socket):
            return
        try:
            super().process_request(request_socket, client_address)
        except BaseException:
            self._guard_release_request()
            raise

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            super().process_request_thread(request, cast(Any, client_address))
        finally:
            self._guard_release_request()

    def _guard_admit_request(self, request: socket.socket) -> bool:
        if not self._guard_slots.acquire(blocking=False):
            _METRICS.rejected_overload()
            self._reject_overload(request)
            self.shutdown_request(request)
            return False
        _METRICS.acquired()
        request.settimeout(self._guard_socket_timeout)
        return True

    def _guard_release_request(self) -> None:
        self._guard_slots.release()
        _METRICS.released()

    def handle_error(self, request: Any, client_address: Any) -> None:
        error = cast(BaseException | None, __import__("sys").exception())
        if isinstance(error, socket.timeout):
            _METRICS.timeout()
            return
        if isinstance(error, (BrokenPipeError, ConnectionAbortedError, ConnectionResetError)):
            _METRICS.abort()
            return
        if isinstance(error, OSError) and error.errno in {
            getattr(__import__("errno"), "EPIPE", -1),
            getattr(__import__("errno"), "ECONNABORTED", -1),
            getattr(__import__("errno"), "ECONNRESET", -1),
            getattr(__import__("errno"), "ETIMEDOUT", -1),
        }:
            _METRICS.abort()
            return
        super().handle_error(request, cast(Any, client_address))

    def _reject_overload(self, request: socket.socket) -> None:
        try:
            _drain_overload_request(request)
            request.settimeout(0.25)
            request.sendall(_overload_response())
        except OSError:
            _METRICS.abort()


def daemon_admission_snapshot() -> dict[str, int]:
    """Return aggregate counters without request, address, path, or payload data."""

    return _METRICS.snapshot().to_dict()


__all__ = [
    "BoundedThreadingHTTPServer",
    "DaemonAdmissionSnapshot",
    "daemon_admission_snapshot",
]
