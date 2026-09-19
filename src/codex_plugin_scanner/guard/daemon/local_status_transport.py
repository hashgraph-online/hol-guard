"""Bounded authenticated reads from an allowlist of local daemon status routes."""

from __future__ import annotations

import json
import socket
import time
from collections.abc import Callable
from contextlib import closing, suppress
from http.client import HTTPConnection, HTTPException
from threading import Timer
from urllib.parse import urlsplit


def _interrupt_health_socket(stream: socket.socket) -> None:
    """Interrupt a blocked header/body read when the whole probe deadline expires."""
    # A completed request may already have closed its socket.
    with suppress(OSError):
        stream.shutdown(socket.SHUT_RDWR)


def read_local_status(
    daemon_url: str,
    auth_token: str,
    *,
    path: str,
    deadline_seconds: float = 1.0,
    connection_factory: Callable[..., HTTPConnection] = HTTPConnection,
) -> dict[str, object] | None:
    """Read bounded authenticated health details over direct, non-redirecting loopback IPC."""
    if path not in {"/v1/healthz/details", "/v1/cloud-review"} or not 0 < deadline_seconds <= 1.0:
        return None
    try:
        parsed = urlsplit(daemon_url)
        if (
            parsed.scheme != "http"
            or parsed.hostname not in {"127.0.0.1", "::1"}
            or parsed.port is None
            or not 1 <= parsed.port <= 65_535
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            return None
        # HTTPConnection neither consults proxy environment variables nor follows
        # redirects. Never forward the daemon token to a redirected authority.
        deadline = time.monotonic() + deadline_seconds
        with closing(connection_factory(parsed.hostname, parsed.port, timeout=deadline_seconds)) as connection:
            connection.connect()
            stream = connection.sock
            remaining = deadline - time.monotonic()
            if stream is None or remaining <= 0:
                return None
            interrupt = Timer(remaining, _interrupt_health_socket, args=(stream,))
            interrupt.daemon = True
            interrupt.start()
            try:
                connection.request("GET", path, headers={"X-Guard-Token": auth_token})
                response = connection.getresponse()
                if response.status != 200:
                    return None
                content = response.read(65_537)
            finally:
                interrupt.cancel()
        if time.monotonic() >= deadline:
            return None
        if len(content) > 65_536:
            return None
        payload = json.loads(content.decode("utf-8"))
        return payload if isinstance(payload, dict) else None
    except (OSError, ValueError, HTTPException):
        return None
