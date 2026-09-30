"""Refresh managed OpenCode support after an installed Guard update."""

from __future__ import annotations

import json
import sqlite3

from ..adapters.base import HarnessContext
from ..adapters.opencode_pretool import (
    global_plugin_path,
    install_pretool_plugin,
    managed_plugin_path,
    pretool_plugin_source,
)
from ..adapters.opencode_proxy_refresh import refresh_opencode_proxy_launchers
from ..store import GuardStore
from .managed_install_context import managed_install_context as _repair_context_from_managed_install


def _refresh_opencode_pretool_plugin(
    *,
    context: HarnessContext,
    store: GuardStore,
) -> str | None:
    try:
        managed_install = store.get_managed_install("opencode")
    except (json.JSONDecodeError, sqlite3.Error):
        return None
    if managed_install is None or not bool(managed_install.get("active")):
        return None
    try:
        repair_context, _ = _repair_context_from_managed_install(context, managed_install)
    except ValueError as error:
        return f"Could not inspect OpenCode pretool plugin during update: {error}"
    companion_warning: str | None = None
    refreshed_proxies = 0
    config_warnings: list[str] = []
    try:
        refreshed_proxies = refresh_opencode_proxy_launchers(repair_context, warnings=config_warnings)
        if config_warnings:
            companion_warning = "Could not refresh OpenCode MCP companion launchers in every config: " + " ".join(
                dict.fromkeys(config_warnings)
            )
    except (OSError, RuntimeError, ValueError) as error:
        companion_warning = f"Could not refresh OpenCode MCP companion launchers during update: {error}"
    global_path = global_plugin_path(repair_context)
    managed_path = managed_plugin_path(repair_context)
    try:
        expected_source = pretool_plugin_source(repair_context)
    except (OSError, RuntimeError) as error:
        return f"Could not inspect OpenCode pretool plugin during update: {error}"
    try:
        global_source = global_path.read_text(encoding="utf-8") if global_path.is_file() else ""
        managed_source = managed_path.read_text(encoding="utf-8") if managed_path.is_file() else ""
    except OSError as error:
        return f"Could not inspect OpenCode pretool plugin during update: {error}"
    if global_source == expected_source and managed_source == expected_source:
        refresh_note = (
            "Refreshed OpenCode MCP companion launchers. Restart OpenCode to load them." if refreshed_proxies else None
        )
        parts = [part for part in (companion_warning, refresh_note) if part]
        return " ".join(parts) if parts else None
    try:
        install_pretool_plugin(repair_context)
    except (OSError, RuntimeError) as error:
        return f"Could not refresh OpenCode pretool plugin during update: {error}"
    plugin_note = "Refreshed the OpenCode pretool plugin during update. Restart OpenCode to load it."
    return f"{companion_warning} {plugin_note}" if companion_warning else plugin_note
