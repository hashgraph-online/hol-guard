"""Reviewed Codex MCP setup through its version-checked configuration API."""

from __future__ import annotations

import os
import shutil
from collections.abc import Callable, Mapping
from typing import cast

from .codex_mcp_setup import CodexMcpSetupReceipt, install_reviewed_codex_mcp
from .mcp_registry import search_mcp_registry

# The only stdio runtimes the registry page turns into package recipes.
_PACKAGE_RUNTIMES = ("npx", "uvx")

_SELECTION_KEYS = ("registry_name", "version", "endpoint", "package_identifier", "package_version", "setup_name")


def _reviewed_candidate(kind: str, payload: dict[str, object]) -> dict[str, object]:
    """Check a registry selection, then bind it to one fresh listing entry.

    The runtime (``mcp_registry_setup``) checks the selection before anything
    is fetched, matches it against the listing and digests the recipe.
    """
    from ..native_runner_authority import native_runner_authority

    request: dict[str, object] = {"kind": kind, "selection": {key: payload.get(key) for key in _SELECTION_KEYS}}
    checked = native_runner_authority("mcp_registry_setup", request)
    query = checked.get("query")
    if not isinstance(query, str):
        raise ValueError(str(checked.get("error") or "registry_setup_listing_changed"))
    request["results"] = search_mcp_registry(query).get("results")
    if kind == "package":
        found = {name: shutil.which(name) for name in _PACKAGE_RUNTIMES}
        request["commands"] = {name: path for name, path in found.items() if path and os.path.isabs(path)}
    answer = native_runner_authority("mcp_registry_setup", request)
    candidate = answer.get("candidate")
    if not isinstance(candidate, dict):
        raise ValueError(str(answer.get("error") or "registry_setup_listing_changed"))
    return cast("dict[str, object]", candidate)


def reviewed_codex_setup_candidate(payload: dict[str, object]) -> dict[str, object]:
    return _reviewed_candidate("remote", payload)


def install_codex_remote_mcp(
    candidate: Mapping[str, object],
    *,
    on_installed: Callable[[CodexMcpSetupReceipt], None] | None = None,
    on_version_chain: Callable[[str, list[tuple[str, str]]], None] | None = None,
) -> str:
    executable = shutil.which("codex")
    if executable is None:
        raise ValueError("codex_host_unavailable")
    name, endpoint = candidate.get("setup_name"), candidate.get("endpoint")
    if not isinstance(name, str) or not isinstance(endpoint, str):
        raise ValueError("invalid_codex_setup_selection")
    return install_reviewed_codex_mcp(
        executable, name, {"url": endpoint}, on_installed=on_installed, on_version_chain=on_version_chain
    )


def reviewed_codex_package_candidate(payload: dict[str, object]) -> dict[str, object]:
    """Bind a local stdio recipe to a fresh registry listing and runtime path."""
    return _reviewed_candidate("package", payload)


def install_codex_package_mcp(
    candidate: Mapping[str, object],
    *,
    on_installed: Callable[[CodexMcpSetupReceipt], None] | None = None,
    on_version_chain: Callable[[str, list[tuple[str, str]]], None] | None = None,
) -> str:
    """Configure a reviewed pinned recipe; Codex owns first launch and auth."""
    executable = shutil.which("codex")
    if executable is None:
        raise ValueError("codex_host_unavailable")
    name, command, arguments = candidate["setup_name"], candidate["command"], candidate["arguments"]
    if (
        not isinstance(name, str)
        or not isinstance(command, str)
        or not os.path.isabs(command)
        or not isinstance(arguments, list)
        or not all(isinstance(argument, str) for argument in arguments)
    ):
        raise ValueError("invalid_codex_package_selection")
    return install_reviewed_codex_mcp(
        executable,
        name,
        {"command": command, "args": arguments},
        on_installed=on_installed,
        on_version_chain=on_version_chain,
    )
