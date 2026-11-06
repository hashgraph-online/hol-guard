"""HTTPS probing pinned to an already validated network address."""

from __future__ import annotations

import http.client
import socket
import ssl
import threading
import time
import urllib.parse


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, hostname: str, port: int, address: str, *, deadline: float) -> None:
        self._tls_context = ssl.create_default_context()
        super().__init__(hostname, port, timeout=_remaining_seconds(deadline), context=self._tls_context)
        self._pinned_address = address
        self._deadline = deadline

    def connect(self) -> None:
        raw_socket = socket.create_connection(
            (self._pinned_address, self.port),
            _remaining_seconds(self._deadline),
        )
        try:
            raw_socket.settimeout(_remaining_seconds(self._deadline))
            self.sock = self._tls_context.wrap_socket(raw_socket, server_hostname=self.host)
        except BaseException:
            raw_socket.close()
            raise


def _remaining_seconds(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("HTTPS probe exceeded its total deadline")
    return remaining


def resolve_host_addresses(hostname: str, port: int, *, timeout_seconds: float) -> tuple[str, ...]:
    """Resolve a hostname without allowing the platform resolver to overrun the caller's deadline."""
    resolved: list[tuple[str, ...]] = []
    errors: list[Exception] = []
    finished = threading.Event()

    def resolve() -> None:
        try:
            records = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
            resolved.append(tuple(str(item[4][0]).split("%", 1)[0] for item in records if item[4]))
        except Exception as error:
            errors.append(error)
        finally:
            finished.set()

    threading.Thread(target=resolve, name="hol-guard-dns", daemon=True).start()
    if not finished.wait(max(timeout_seconds, 0.0)):
        raise TimeoutError("hostname resolution exceeded its deadline")
    if errors:
        raise errors[0]
    return resolved[0] if resolved else ()


def probe_pinned_https(
    parsed: urllib.parse.ParseResult,
    addresses: tuple[str, ...],
    *,
    timeout_seconds: float,
) -> int:
    """Issue one GET without redirects or a second hostname resolution."""
    hostname = parsed.hostname
    if hostname is None or not addresses:
        raise ValueError("validated HTTPS hostname and address are required")
    port = parsed.port or 443
    target = urllib.parse.urlunparse(("", "", parsed.path or "/", parsed.params, parsed.query, ""))
    deadline = time.monotonic() + timeout_seconds
    last_error: OSError | ssl.SSLError | None = None
    for address in addresses:
        connection = _PinnedHTTPSConnection(hostname, port, address, deadline=deadline)
        try:
            connection.timeout = _remaining_seconds(deadline)
            connection.request("GET", target)
            if connection.sock is not None:
                connection.sock.settimeout(_remaining_seconds(deadline))
            response = connection.getresponse()
            return response.status
        except (OSError, ssl.SSLError) as error:
            last_error = error
        finally:
            connection.close()
    if last_error is not None:
        raise last_error
    raise OSError("no validated HTTPS address was reachable")
