"""Shared GitHub API JSON request helper for reporting and submission flows."""

from __future__ import annotations

import json
from http.client import HTTPMessage
from typing import IO, cast
from urllib.error import URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

REQUEST_TIMEOUT_SECONDS = 30
_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


def _validated_github_api_host(url: str) -> str:
    """Reject non-HTTPS API destinations so auth tokens are never sent in cleartext."""

    split = urlsplit(url)
    host = (split.hostname or "").lower()
    if split.scheme != "https" and host not in _LOOPBACK_HOSTS:
        raise URLError(f"refusing non-HTTPS GitHub API destination: {url}")
    return host


class _SameHostRedirectHandler(HTTPRedirectHandler):
    """Keep authenticated API requests on their validated host across redirects."""

    def __init__(self, allowed_host: str) -> None:
        super().__init__()
        self.allowed_host = allowed_host

    def redirect_request(
        self, req: Request, fp: object, code: int, msg: str, headers: object, newurl: str
    ) -> Request | None:
        split = urlsplit(newurl)
        target_host = (split.hostname or "").lower()
        if target_host != self.allowed_host:
            raise URLError(f"refusing cross-host GitHub API redirect to {newurl}")
        if split.scheme != "https" and target_host not in _LOOPBACK_HOSTS:
            raise URLError(f"refusing downgraded GitHub API redirect to {newurl}")
        return super().redirect_request(
            req,
            cast("IO[bytes]", fp),
            code,
            msg,
            cast("HTTPMessage", headers),
            newurl,
        )


def github_request_json(
    method: str,
    url: str,
    token: str,
    payload: dict[str, object] | None = None,
    *,
    user_agent: str,
) -> dict[str, object] | list[dict[str, object]]:
    """Perform a GitHub API JSON request with Guard's standard header set."""

    allowed_host = _validated_github_api_host(url)
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    request = Request(url, data=data, method=method)
    request.add_header("Accept", "application/vnd.github+json")
    request.add_header("Authorization", f"Bearer {token}")
    request.add_header("User-Agent", user_agent)
    if data is not None:
        request.add_header("Content-Type", "application/json")
    opener = build_opener(_SameHostRedirectHandler(allowed_host))
    with opener.open(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
        return json.loads(response.read().decode("utf-8"))
