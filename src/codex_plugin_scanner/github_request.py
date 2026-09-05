"""Shared GitHub API JSON request helper for reporting and submission flows."""

from __future__ import annotations

import json
from urllib.request import Request, urlopen

REQUEST_TIMEOUT_SECONDS = 30


def github_request_json(
    method: str,
    url: str,
    token: str,
    payload: dict[str, object] | None = None,
    *,
    user_agent: str,
) -> dict[str, object] | list[dict[str, object]]:
    """Perform a GitHub API JSON request with Guard's standard header set."""

    data = None if payload is None else json.dumps(payload).encode("utf-8")
    request = Request(url, data=data, method=method)
    request.add_header("Accept", "application/vnd.github+json")
    request.add_header("Authorization", f"Bearer {token}")
    request.add_header("User-Agent", user_agent)
    if data is not None:
        request.add_header("Content-Type", "application/json")
    with urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
        return json.loads(response.read().decode("utf-8"))
