"""Restricted, redirect-aware downloads for approved external archives.

Only an already-approved source URL may reach this module. Every destination,
redirect, DNS answer, connected peer, TLS hostname, header set, response body,
and deadline is independently checked before a mode-0400 digest-bound blob is
returned. Ambient proxies, cookies, and authorization are never consulted.
"""

from __future__ import annotations

import http.client
import os as os
import socket
import ssl
import time
import urllib.parse
from contextlib import suppress
from pathlib import Path

from ..mdm.network import managed_ssl_context
from .restricted_archive_contract import (
    RestrictedArchiveDownload,
    RestrictedArchiveDownloadResult,
    RestrictedArchiveFailure,
    _CanonicalDestination,
    _ReadableResponse,
    _RestrictedDownloadError,
)
from .restricted_archive_deadline import _call_with_deadline, _remaining_seconds
from .restricted_archive_destination import (
    _canonical_destination,
    _resolve_public_addresses,
    _same_ip,
    canonical_external_https_archive_source,
    is_external_https_archive_source,
)
from .restricted_archive_stream import (
    _response_header,
    _validate_response_headers,
    _write_bounded_response,
)

_DEFAULT_MAX_BYTES = 6 * 1024 * 1024
_DEFAULT_MAX_REDIRECTS = 4
_DEFAULT_TIMEOUT_SECONDS = 3.0
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})


class _PinnedHTTPSResponse:
    def __init__(self, response: http.client.HTTPResponse, tls_socket: ssl.SSLSocket, *, deadline: float) -> None:
        self._response = response
        self._tls_socket = tls_socket
        self._deadline = deadline
        self.status = response.status

    def read(self, amount: int = -1) -> bytes:
        self._tls_socket.settimeout(_remaining_seconds(self._deadline))
        return _call_with_deadline(
            lambda: self._response.read1(amount),
            deadline=self._deadline,
            cancel=self._tls_socket.close,
        )

    def get_header(self, name: str) -> str | None:
        return self._response.getheader(name)

    def header_items(self) -> tuple[tuple[str, str], ...]:
        return tuple(self._response.getheaders())

    def set_timeout(self, timeout: float) -> None:
        self._tls_socket.settimeout(timeout)

    def close(self) -> None:
        try:
            self._response.close()
        finally:
            self._tls_socket.close()


def _open_pinned_https_response(
    destination: _CanonicalDestination,
    address: str,
    *,
    deadline: float,
) -> _ReadableResponse:
    raw_socket: socket.socket | None = None
    tls_socket: ssl.SSLSocket | None = None
    try:
        raw_socket = socket.create_connection(
            (address, destination.port),
            timeout=_remaining_seconds(deadline),
        )
        peer = raw_socket.getpeername()
        if not isinstance(peer, tuple) or not peer or not isinstance(peer[0], str) or not _same_ip(peer[0], address):
            raise _RestrictedDownloadError(
                "external_archive_dns_rebinding",
                "External archive connection did not use the validated DNS address.",
            )
        socket_to_wrap = raw_socket
        tls_socket = _call_with_deadline(
            lambda: managed_ssl_context().wrap_socket(socket_to_wrap, server_hostname=destination.hostname),
            deadline=deadline,
            cancel=socket_to_wrap.close,
        )
        raw_socket = None
        tls_socket.settimeout(_remaining_seconds(deadline))
        tls_peer = tls_socket.getpeername()
        if (
            not isinstance(tls_peer, tuple)
            or not tls_peer
            or not isinstance(tls_peer[0], str)
            or not _same_ip(tls_peer[0], address)
        ):
            raise _RestrictedDownloadError(
                "external_archive_dns_rebinding",
                "External archive TLS connection did not use the validated DNS address.",
            )
        request = (
            f"GET {destination.request_target} HTTP/1.1\r\n"
            f"Host: {destination.host_header}\r\n"
            "Accept: application/octet-stream\r\n"
            "Accept-Encoding: identity\r\n"
            "Connection: close\r\n"
            "User-Agent: hol-guard-restricted-archive/1\r\n\r\n"
        )
        tls_socket.settimeout(_remaining_seconds(deadline))
        tls_socket.sendall(request.encode("ascii"))
        _ = _remaining_seconds(deadline)
        response = http.client.HTTPResponse(tls_socket)
        try:
            _call_with_deadline(
                response.begin,
                deadline=deadline,
                cancel=tls_socket.close,
            )
        except (http.client.HTTPException, http.client.LineTooLong):
            raise _RestrictedDownloadError(
                "external_archive_response_headers_invalid",
                "External archive response headers were malformed or exceeded Guard's limit.",
            ) from None
        pinned_response = _PinnedHTTPSResponse(response, tls_socket, deadline=deadline)
        tls_socket = None
        return pinned_response
    except _RestrictedDownloadError:
        raise
    except (ssl.SSLError, RuntimeError, ValueError):
        raise _RestrictedDownloadError(
            "external_archive_tls_error",
            "External archive TLS verification failed.",
        ) from None
    except (OSError, http.client.HTTPException):
        raise _RestrictedDownloadError(
            "external_archive_connection_failed",
            "External archive connection failed.",
        ) from None
    finally:
        if tls_socket is not None:
            tls_socket.close()
        if raw_socket is not None:
            raw_socket.close()


def _open_destination(
    destination: _CanonicalDestination,
    addresses: tuple[str, ...],
    *,
    deadline: float,
) -> _ReadableResponse:
    last_failure: _RestrictedDownloadError | None = None
    for address in addresses:
        try:
            return _open_pinned_https_response(
                destination,
                address,
                deadline=deadline,
            )
        except _RestrictedDownloadError as error:
            if error.code == "external_archive_dns_rebinding":
                raise
            last_failure = error
    if last_failure is not None:
        raise last_failure
    raise _RestrictedDownloadError(
        "external_archive_connection_failed",
        "External archive connection failed.",
    )


def download_restricted_archive(
    source_url: str,
    *,
    max_bytes: int = _DEFAULT_MAX_BYTES,
    max_redirects: int = _DEFAULT_MAX_REDIRECTS,
    timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS,
    temp_dir: Path | None = None,
) -> RestrictedArchiveDownloadResult:
    """Download one approved archive through a direct, public-HTTPS-only path."""

    if max_bytes <= 0 or max_redirects < 0 or timeout_seconds <= 0:
        return RestrictedArchiveFailure(
            code="external_archive_download_policy_invalid",
            message="External archive download policy is invalid.",
        )
    deadline = time.monotonic() + timeout_seconds
    current_url = source_url
    response: _ReadableResponse | None = None
    try:
        for redirect_count in range(max_redirects + 1):
            destination = _canonical_destination(current_url)
            addresses = _resolve_public_addresses(destination, deadline=deadline)
            response = _open_destination(destination, addresses, deadline=deadline)
            _validate_response_headers(response)
            if response.status in _REDIRECT_STATUSES:
                location = _response_header(response, "Location")
                response.close()
                response = None
                if redirect_count >= max_redirects:
                    raise _RestrictedDownloadError(
                        "external_archive_redirect_limit",
                        "External archive exceeded Guard's redirect limit.",
                    )
                if location is None or not location.strip():
                    raise _RestrictedDownloadError(
                        "external_archive_redirect_rejected",
                        "External archive redirect did not provide a valid destination.",
                    )
                redirect_url = urllib.parse.urljoin(destination.url, location.strip())
                try:
                    current_url = _canonical_destination(redirect_url).url
                except _RestrictedDownloadError:
                    raise _RestrictedDownloadError(
                        "external_archive_redirect_rejected",
                        "External archive redirect did not provide a valid public HTTPS destination.",
                    ) from None
                continue
            if response.status != 200:
                raise _RestrictedDownloadError(
                    "external_archive_http_error",
                    "External archive server returned a non-success response.",
                )
            return _write_bounded_response(
                response,
                source_url=source_url,
                final_url=destination.url,
                deadline=deadline,
                max_bytes=max_bytes,
                temp_dir=temp_dir,
            )
        raise _RestrictedDownloadError(
            "external_archive_redirect_limit",
            "External archive exceeded Guard's redirect limit.",
        )
    except _RestrictedDownloadError as error:
        return RestrictedArchiveFailure(code=error.code, message=error.message)
    except http.client.IncompleteRead:
        return RestrictedArchiveFailure(
            code="external_archive_incomplete_response",
            message="External archive response ended before the body completed.",
        )
    except http.client.HTTPException:
        return RestrictedArchiveFailure(
            code="external_archive_connection_failed",
            message="External archive connection failed.",
        )
    except TimeoutError:
        return RestrictedArchiveFailure(
            code="external_archive_download_timeout",
            message="External archive download exceeded Guard's time limit.",
        )
    except ssl.SSLError:
        return RestrictedArchiveFailure(
            code="external_archive_tls_error",
            message="External archive TLS verification failed.",
        )
    except OSError:
        return RestrictedArchiveFailure(
            code="external_archive_connection_failed",
            message="External archive connection failed.",
        )
    except ValueError:
        return RestrictedArchiveFailure(
            code="external_archive_destination_rejected",
            message="External archive destination is not a canonical public HTTPS URL.",
        )
    finally:
        if response is not None:
            with suppress(OSError, http.client.HTTPException):
                response.close()


__all__ = [
    "RestrictedArchiveDownload",
    "RestrictedArchiveDownloadResult",
    "RestrictedArchiveFailure",
    "canonical_external_https_archive_source",
    "download_restricted_archive",
    "is_external_https_archive_source",
]
