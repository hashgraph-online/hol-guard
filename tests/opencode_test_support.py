"""OpenCode pretool plugin helpers for tests, answered by the native ``harness_adapter`` kind."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.native_harness import ask
from codex_plugin_scanner.guard.adapters.opencode_runtime import plugin_render_args

_PLUGIN_FILE = "hol-guard-pretool.ts"


def _refresh(context: HarnessContext) -> dict[str, Any]:
    return ask("plugin_refresh", context, harness="opencode", plugin=plugin_render_args(context))


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
    answer = ask("protection", context, harness="opencode", managed_active=True, config_paths=[str(config)])
    return bool(json.loads(str(answer["checks"]))["mcp_proxy_configured"])
