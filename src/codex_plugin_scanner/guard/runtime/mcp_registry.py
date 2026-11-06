"""Bounded read-only search of the official public MCP server registry.

This module fetches one search page from the fixed registry origin. The native
runtime reads it (the ``mcp_registry_page`` runner authority kind): strict
JSON, the listing Guard shows, and only the pinned, literal stdio recipes
Codex can own as package options. When the native runtime cannot answer, the
registry counts as unavailable.
"""

from __future__ import annotations

import base64
import urllib.error
import urllib.parse
import urllib.request
from typing import cast

from ..mdm.network import managed_urlopen

_ENDPOINT = "https://registry.modelcontextprotocol.io/v0.1/servers"
_MAX_BYTES = 512_000


def search_mcp_registry(query: str) -> dict[str, object]:
    if not isinstance(query, str) or not 2 <= len(query.strip()) <= 80 or any(ord(char) < 32 for char in query):
        raise ValueError("invalid_registry_search")
    url = _ENDPOINT + "?" + urllib.parse.urlencode({"search": query.strip(), "version": "latest", "limit": 20})
    try:
        with managed_urlopen(
            urllib.request.Request(url, headers={"Accept": "application/json"}),
            timeout=5,
            allow_redirects=False,
        ) as response:
            content_type = next(
                (value for key, value in response.headers.items() if key.lower() == "content-type"),
                "",
            )
            if response.status != 200 or content_type.split(";", 1)[0].strip().lower() != "application/json":
                raise ValueError("registry_unavailable")
            raw = response.read(_MAX_BYTES + 1)
    except (OSError, urllib.error.URLError, ValueError) as error:
        raise ValueError("registry_unavailable") from error
    if len(raw) > _MAX_BYTES:
        raise ValueError("registry_response_too_large")
    from ..native_runner_authority import NativeRunnerAuthorityError, native_runner_authority

    try:
        answer = native_runner_authority("mcp_registry_page", {"body": base64.b64encode(raw).decode("ascii")})
    except NativeRunnerAuthorityError as error:
        raise ValueError("registry_unavailable") from error
    listing = answer.get("listing")
    if not isinstance(listing, dict):
        raise ValueError("registry_response_invalid")
    return cast("dict[str, object]", listing)
