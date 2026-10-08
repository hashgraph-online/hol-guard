"""Mechanical adapter for native MCP stdio discovery evidence."""

from __future__ import annotations

import shlex
import threading
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from .local_mcp_probe_env import (
    is_package_shim_executable as is_package_shim_executable,
)
from .local_mcp_probe_env import probe_env as probe_env
from .local_mcp_probe_env import probe_search_path as probe_search_path

MCP_PROBE_TIMEOUT_SECONDS = 6.0
MCP_PACKAGE_PROBE_TIMEOUT_SECONDS = 20.0
MCP_PROBE_OUTPUT_LIMIT = 1_000_000
MAX_MCP_PROBE_TOOLS = 100


class NativeMcpAuthorityError(RuntimeError):
    """Native MCP authority failed; Python must not launch an unreviewed server."""


@dataclass(frozen=True, slots=True)
class McpCatalogResult:
    """Bounded discovery evidence; a partial inventory is never a complete one."""

    tools: tuple[dict[str, object], ...] = ()
    complete: bool = False
    reason: str | None = None
    pages: int = 0
    protocol_version: str | None = None
    server_info: dict[str, object] | None = None
    capabilities: dict[str, object] | None = None
    cache_ttl_ms: int = 0
    cache_scope: Literal["private", "public"] = "private"
    cache_received_at: str | None = None
    skills: tuple[dict[str, object], ...] = ()
    skills_complete: bool | None = None
    skills_reason: str | None = None


def _native_catalog_result(payload: dict[str, object]) -> McpCatalogResult | None:
    """Deserialize native discovery evidence without a Python transport fallback."""
    status = payload.get("status")
    if status not in ("ok", "failed"):
        return None
    tools = payload.get("tools")
    protocol_version = payload.get("protocol_version")
    server_info = payload.get("server_info")
    capabilities = payload.get("capabilities")
    if not isinstance(tools, list) or len(tools) > MAX_MCP_PROBE_TOOLS:
        return None
    if any(not isinstance(tool, dict) or any(not isinstance(key, str) for key in tool) for tool in tools):
        return None
    if protocol_version is not None and not isinstance(protocol_version, str):
        return None
    if server_info is not None and not isinstance(server_info, dict):
        return None
    if capabilities is not None and not isinstance(capabilities, dict):
        return None
    complete = payload.get("complete")
    reason = payload.get("reason")
    pages = payload.get("pages", 0)
    cache_ttl_ms = payload.get("cache_ttl_ms", 0)
    cache_scope = payload.get("cache_scope", "private")
    cache_received_at = payload.get("cache_received_at")
    skills = payload.get("skills", ())
    skills_complete = payload.get("skills_complete")
    skills_reason = payload.get("skills_reason")
    if not isinstance(complete, bool):
        return None
    if status == "failed" and (complete or not reason):
        return None
    if reason is not None and not isinstance(reason, str):
        return None
    if not isinstance(pages, int) or not isinstance(cache_ttl_ms, int):
        return None
    if cache_scope not in ("private", "public"):
        return None
    if cache_received_at is not None and not isinstance(cache_received_at, str):
        return None
    if not isinstance(skills, (list, tuple)):
        return None
    if skills_complete is not None and not isinstance(skills_complete, bool):
        return None
    if skills_reason is not None and not isinstance(skills_reason, str):
        return None
    return McpCatalogResult(
        tools=tuple(tools),
        complete=complete,
        reason=reason,
        pages=pages,
        protocol_version=protocol_version,
        server_info=server_info,
        capabilities=capabilities,
        cache_ttl_ms=cache_ttl_ms,
        cache_scope=cache_scope,
        cache_received_at=cache_received_at,
        skills=tuple(skills),
        skills_complete=skills_complete,
        skills_reason=skills_reason,
    )


def _shlex_join_safe(argv: list[str]) -> str:
    try:
        return shlex.join(argv)
    except Exception:
        return " ".join(argv)


def run_mcp_catalog(
    argv: Sequence[str],
    *,
    timeout: float = MCP_PROBE_TIMEOUT_SECONDS,
    extra_env: Mapping[str, str] | None = None,
    cancel: threading.Event | None = None,
    connection_identity_hash: str | None = None,
    guard_home: Path | None = None,
) -> McpCatalogResult:
    """Discover tools while retaining bounded partial results and their cause."""

    if not argv or any(not part or "\x00" in part for part in argv):
        return McpCatalogResult(reason="invalid_launch")
    if cancel is not None and cancel.is_set():
        return McpCatalogResult(reason="cancelled")
    from .. import native_execution as _native_execution
    from ..config import resolve_guard_home

    _native_result = _native_execution.mcp_stdio_probe_native(
        _shlex_join_safe(list(argv)),
        cwd=Path.cwd(),
        extra_env=extra_env,
        guard_home=guard_home if guard_home is not None else resolve_guard_home(),
        timeout_seconds=timeout,
        connection_identity_hash=connection_identity_hash,
        cancel=cancel,
    )
    if _native_result is not None:
        native_catalog = _native_catalog_result(_native_result)
        if native_catalog is not None:
            return native_catalog
    raise NativeMcpAuthorityError("Native MCP discovery authority is unavailable or malformed")


def run_mcp_tools_list(
    argv: Sequence[str],
    *,
    timeout: float = MCP_PROBE_TIMEOUT_SECONDS,
    extra_env: Mapping[str, str] | None = None,
) -> list[dict[str, object]] | None:
    """Return tools for complete discovery, or None for an incomplete catalog.

    Unavailable or malformed native authority raises NativeMcpAuthorityError;
    there is no Python discovery fallback.
    """

    catalog = run_mcp_catalog(argv, timeout=timeout, extra_env=extra_env)
    return list(catalog.tools) if catalog.complete else None
