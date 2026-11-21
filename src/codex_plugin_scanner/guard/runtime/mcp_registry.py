"""Bounded read-only search of the official public MCP server registry.

The native runtime (the ``mcp_registry_search`` runner authority kind) checks
the query, fetches one search page from the fixed registry origin under the
machine's managed network policy and reads it: strict JSON, the listing Guard
shows, and only the pinned, literal stdio recipes Codex can own as package
options. When the native runtime cannot answer, the registry counts as
unavailable.
"""

from __future__ import annotations

from typing import cast

# The native fetch waits up to 5 seconds for the registry; the resident call
# needs room for that and for reading the page.
_SEARCH_TIMEOUT_SECONDS = 10.0


def search_mcp_registry(query: str) -> dict[str, object]:
    if not isinstance(query, str):
        raise ValueError("invalid_registry_search")
    from ..native_runner_authority import NativeRunnerAuthorityError, native_runner_authority

    try:
        answer = native_runner_authority(
            "mcp_registry_search", {"query": query}, timeout_seconds=_SEARCH_TIMEOUT_SECONDS
        )
    except NativeRunnerAuthorityError as error:
        raise ValueError("registry_unavailable") from error
    listing = answer.get("listing")
    if not isinstance(listing, dict):
        raise ValueError(str(answer.get("error") or "registry_response_invalid"))
    return cast("dict[str, object]", listing)
