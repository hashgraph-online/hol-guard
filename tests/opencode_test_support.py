"""OpenCode pretool plugin helpers for tests, answered by the native ``harness_adapter`` kind."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any
from unittest.mock import patch

from codex_plugin_scanner.guard.harness_context import HarnessContext
from codex_plugin_scanner.guard.native_harness_client import ask

_PLUGIN_FILE = "hol-guard-pretool.ts"


def _refresh(context: HarnessContext) -> dict[str, Any]:
    return ask("plugin_refresh", context, harness="opencode")


def refresh_opencode_proxy_launchers(context: HarnessContext, *, warnings: list[str] | None = None) -> int:
    """Refresh the companion launchers as the native ``refresh_apply`` op does; return how many changed."""
    answer = ask("refresh_apply", context, harness="opencode")
    if warnings is not None:
        warnings.extend(str(warning) for warning in answer["warnings"])
    return int(answer["refreshed"])


def pretool_plugin_source(context: HarnessContext) -> str:
    return str(_refresh(context)["source"])


def managed_plugin_path(context: HarnessContext) -> Path:
    return context.guard_home / "opencode" / "plugins" / _PLUGIN_FILE


def global_plugin_path(context: HarnessContext) -> Path:
    return context.home_dir / ".config" / "opencode" / "plugins" / _PLUGIN_FILE


def install_pretool_plugin(context: HarnessContext) -> dict[str, str]:
    """Write the rendered plugin to its managed and global paths."""
    refresh = _refresh(context)
    paths = [Path(str(path)) for path in refresh["paths"]]
    for path in paths:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(str(refresh["source"]), encoding="utf-8")
    return {"managed_plugin_path": str(paths[0]), "global_plugin_path": str(paths[1])}


def config_uses_guard_proxy(context: HarnessContext, config: Path) -> bool:
    # The native op detects the loaded configs itself; OPENCODE_CONFIG points it at this one.
    with patch.dict(os.environ, {"OPENCODE_CONFIG": str(config)}):
        answer = ask("protection", context, harness="opencode")
    return bool(json.loads(str(answer["checks"]))["mcp_proxy_configured"])
