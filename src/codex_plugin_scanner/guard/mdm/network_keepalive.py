"""Reused HTTPS connections for authenticated Guard requests.

``urllib`` opens a new TCP and TLS connection for every request and asks the
server to close it afterwards. Guard's command queue makes several small
authenticated calls per Cloud Review decision (lease, ack, result), so each one
paid a fresh handshake. This handler keeps finished connections for a short
idle window and hands them to the next request for the same host.
"""

from __future__ import annotations

import http.client
import ssl
import threading
import time
import urllib.error
import urllib.request
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

# Shorter than common server and proxy keep-alive timeouts, so a pooled socket
# is rarely closed by the far end before it is reused.
_IDLE_SECONDS = 4.0
_MAX_IDLE_PER_HOST = 8
# A reused socket the server already closed fails on first use with one of
# these. The request is retried once on a fresh connection.
_STALE_SOCKET_ERRORS = (
    http.client.RemoteDisconnected,
    ConnectionResetError,
    ConnectionAbortedError,
    BrokenPipeError,
)


class _ConnectionPool:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._idle: dict[object, list[tuple[float, http.client.HTTPConnection]]] = {}

    def take(self, key: object) -> http.client.HTTPConnection | None:
        expired: list[http.client.HTTPConnection] = []
        found: http.client.HTTPConnection | None = None
        now = time.monotonic()
        with self._lock:
            idle = self._idle.get(key, [])
            while idle:
                released_at, connection = idle.pop()
                if now - released_at <= _IDLE_SECONDS and connection.sock is not None:
                    found = connection
                    break
                expired.append(connection)
        for connection in expired:
            connection.close()
        return found

    def give(self, key: object, connection: http.client.HTTPConnection) -> None:
        overflow: list[http.client.HTTPConnection] = []
        with self._lock:
            idle = self._idle.setdefault(key, [])
            idle.append((time.monotonic(), connection))
            while len(idle) > _MAX_IDLE_PER_HOST:
                overflow.append(idle.pop(0)[1])
        for stale in overflow:
            stale.close()

    def clear(self) -> None:
        with self._lock:
            connections = [connection for idle in self._idle.values() for _released, connection in idle]
            self._idle.clear()
        for connection in connections:
            connection.close()


_POOL = _ConnectionPool()


class _PooledResponse(http.client.HTTPResponse):
    """Returns its connection to the pool once the body was read in full."""

    _release: Callable[[bool], None] | None = None

    def close(self) -> None:
        # http.client drops ``fp`` when the body has been consumed to the end;
        # anything else leaves unread bytes on the socket, so it cannot be reused.
        complete = self.fp is None and not self.will_close
        super().close()
        release, self._release = self._release, None
        if release is not None:
            release(complete)


def _request_headers(request: urllib.request.Request) -> dict[str, str]:
    headers = dict(request.unredirected_hdrs)
    headers.update({name: value for name, value in request.headers.items() if name not in headers})
    headers["Connection"] = "keep-alive"
    return {name.title(): value for name, value in headers.items()}


def open_keepalive(
    request: urllib.request.Request,
    *,
    key: object,
    connect: Callable[[str, float | None], http.client.HTTPConnection],
    pool: _ConnectionPool = _POOL,
) -> http.client.HTTPResponse:
    """Send ``request`` on a pooled connection, mirroring ``AbstractHTTPHandler.do_open``."""
    if not request.host:
        raise urllib.error.URLError("no host given")
    timeout = request.timeout
    headers = _request_headers(request)
    pool_key = (key, request.host)
    for attempt in range(2):
        connection = pool.take(pool_key) if attempt == 0 else None
        reused = connection is not None
        if connection is None:
            connection = connect(request.host, timeout)
            connection.response_class = _PooledResponse
        else:
            connection.timeout = timeout
            if connection.sock is not None:
                connection.sock.settimeout(timeout)
        try:
            connection.request(
                request.get_method(),
                request.selector,
                request.data,
                headers,
                encode_chunked=request.has_header("Transfer-encoding"),
            )
            response = connection.getresponse()
        except _STALE_SOCKET_ERRORS as error:
            connection.close()
            if reused:
                continue
            raise urllib.error.URLError(error) from error
        except OSError as error:
            connection.close()
            raise urllib.error.URLError(error) from error
        except BaseException:
            connection.close()
            raise

        def release(reusable: bool, connection: http.client.HTTPConnection = connection) -> None:
            if reusable:
                pool.give(pool_key, connection)
            else:
                connection.close()

        if isinstance(response, _PooledResponse):
            response._release = release
        response.url = request.get_full_url()  # type: ignore[attr-defined]
        response.msg = response.reason  # type: ignore[assignment]
        return response
    raise AssertionError("unreachable")


class KeepAliveHTTPSHandler(urllib.request.HTTPSHandler):
    """``HTTPSHandler`` that reuses connections; proxied requests keep the stock path."""

    def __init__(self, context: ssl.SSLContext) -> None:
        super().__init__(context=context)
        self._keepalive_context = context

    def https_open(self, req: urllib.request.Request) -> http.client.HTTPResponse:
        if getattr(req, "_tunnel_host", None):
            return super().https_open(req)
        context = self._keepalive_context

        def connect(host: str, timeout: float | None) -> http.client.HTTPConnection:
            return http.client.HTTPSConnection(host, timeout=timeout, context=context)

        return open_keepalive(req, key=context, connect=connect)


def clear_keepalive_connections() -> None:
    _POOL.clear()


__all__ = ["KeepAliveHTTPSHandler", "clear_keepalive_connections", "open_keepalive"]
