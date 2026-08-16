"""urllib-compatible managed opener with first-class HTTPS proxy transport."""

from __future__ import annotations

import io
import ssl
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from email.message import Message
from typing import Protocol

from urllib3 import ProxyManager
from urllib3.exceptions import HTTPError as Urllib3HTTPError
from urllib3.exceptions import SSLError as Urllib3SSLError
from urllib3.response import BaseHTTPResponse


class ManagedResponse(Protocol):
    headers: Mapping[str, str]
    status: int

    def geturl(self) -> str: ...

    def read(self, amt: int | None = None) -> bytes: ...

    def close(self) -> None: ...

    def __enter__(self) -> ManagedResponse: ...

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: object | None,
    ) -> None: ...


class ManagedOpener(Protocol):
    def open(
        self,
        request: str | urllib.request.Request,
        timeout: float | None = None,
    ) -> ManagedResponse: ...


class _UrllibResponse:
    """Small response adapter exposing the urllib surface Guard call sites use."""

    def __init__(self, response: BaseHTTPResponse, url: str) -> None:
        self._response = response
        self._url = url
        self.headers: Mapping[str, str] = response.headers
        self.status = response.status

    def geturl(self) -> str:
        return self._url

    def read(self, amt: int | None = None) -> bytes:
        return self._response.read(amt)

    def close(self) -> None:
        self._response.close()

    def __enter__(self) -> _UrllibResponse:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: object | None,
    ) -> None:
        self.close()


def _message_headers(headers: Mapping[str, str]) -> Message:
    message = Message()
    for name, value in headers.items():
        message[name] = value
    return message


def _contains_tls_failure(error: BaseException) -> bool:
    pending: list[BaseException] = [error]
    seen: set[int] = set()
    while pending:
        current = pending.pop()
        identity = id(current)
        if identity in seen:
            continue
        seen.add(identity)
        if isinstance(current, (ssl.SSLError, Urllib3SSLError)):
            return True
        for attribute in ("reason", "original_error", "__cause__", "__context__"):
            nested = getattr(current, attribute, None)
            if isinstance(nested, BaseException):
                pending.append(nested)
    return False


def _request_parts(
    request: str | urllib.request.Request,
) -> tuple[str, str, bytes | None, dict[str, str]]:
    if isinstance(request, urllib.request.Request):
        data = request.data
        if data is None:
            body = None
        elif isinstance(data, bytes):
            body = data
        elif isinstance(data, bytearray):
            body = bytes(data)
        elif isinstance(data, memoryview):
            body = data.tobytes()
        else:
            raise ValueError("managed_request_body_must_be_bytes")
        return request.full_url, request.get_method(), body, dict(request.header_items())
    return request, "GET", None, {}


class ManagedUrlOpener:
    """Route through managed proxies without consulting process proxy/bypass state."""

    def __init__(
        self,
        *,
        direct_opener: urllib.request.OpenerDirector,
        proxy_urls: Mapping[str, str],
        ssl_context: ssl.SSLContext,
        proxy_headers: Mapping[str, str] | None = None,
        allow_redirects: bool = True,
    ) -> None:
        self._direct_opener = direct_opener
        self._proxy_urls = dict(proxy_urls)
        self._ssl_context = ssl_context
        self._proxy_headers = dict(proxy_headers or {})
        self._allow_redirects = allow_redirects
        self._managers: dict[str, ProxyManager] = {}

    def _manager(self, proxy_url: str) -> ProxyManager:
        manager = self._managers.get(proxy_url)
        if manager is None:
            manager = ProxyManager(
                proxy_url,
                proxy_headers=self._proxy_headers,
                proxy_ssl_context=self._ssl_context,
                ssl_context=self._ssl_context,
            )
            self._managers[proxy_url] = manager
        return manager

    def open(
        self,
        request: str | urllib.request.Request,
        timeout: float | None = None,
    ) -> ManagedResponse:
        url, method, body, headers = _request_parts(request)
        scheme = urllib.parse.urlsplit(url).scheme.lower()
        proxy_url = self._proxy_urls.get(scheme)
        if proxy_url is None:
            return self._direct_opener.open(request, timeout=timeout)
        manager = self._manager(proxy_url)
        try:
            if timeout is None:
                response = manager.request(
                    method,
                    url,
                    body=body,
                    headers=headers,
                    preload_content=False,
                    redirect=self._allow_redirects,
                )
            else:
                response = manager.request(
                    method,
                    url,
                    body=body,
                    headers=headers,
                    preload_content=False,
                    redirect=self._allow_redirects,
                    timeout=timeout,
                )
        except Urllib3HTTPError as exc:
            if _contains_tls_failure(exc):
                raise urllib.error.URLError(ssl.SSLError("managed_tls_request_failed")) from exc
            raise urllib.error.URLError("managed_proxy_request_failed") from exc
        if response.status >= 400 or (not self._allow_redirects and 300 <= response.status < 400):
            status = response.status
            reason = str(response.reason or "managed_http_error")
            response_headers = _message_headers(response.headers)
            response_body = response.read()
            response.close()
            raise urllib.error.HTTPError(
                url,
                status,
                reason,
                response_headers,
                io.BytesIO(response_body),
            )
        return _UrllibResponse(response, url)


__all__ = ["ManagedOpener", "ManagedResponse", "ManagedUrlOpener"]
