"""Cursor local action payload helpers."""

from __future__ import annotations

import json
from pathlib import Path

from ..adapters.base import HarnessContext
from ..adapters.cursor_cli import cursor_cli_detected, cursor_cli_shim_installed
from ..adapters.mcp_servers import is_guard_proxy_command
from ..store import GuardStore


def cursor_local_action_payload(
    *,
    action: str,
    surface: str | None,
    context: HarnessContext,
    protected: bool | None = None,
    protected_surfaces: tuple[str, ...] = (),
) -> dict[str, object]:
    selected_surface = _cursor_surface(surface)
    selected_protected_surfaces = protected_surfaces
    if protected is not None and protected:
        selected_protected_surfaces = ("editor", "cli")
    statuses = _cursor_surface_statuses(context, protected_surfaces=selected_protected_surfaces)
    selected_status = next(item["status"] for item in statuses if item["surface"] == selected_surface)
    action_scope = f"cursor:{selected_surface}:{action}"
    return {
        "app_id": "cursor",
        "action": action,
        "surface": selected_surface,
        "status": selected_status,
        "surface_statuses": statuses,
        "sync": {
            "surface": selected_surface,
            "status": selected_status,
            "lastSeenAt": None,
            "lastReceiptSyncedAt": None,
            "daemonReachability": "local",
            "protectedLocationId": None,
        },
        "evidence": {
            "receiptId": None,
            "artifactId": action_scope,
            "actionScope": action_scope,
            "surface": selected_surface,
            "redactedPath": _cursor_redacted_path(context, selected_surface),
            "policyDecision": "monitor",
        },
    }


def cursor_install_surface(surface: str | None) -> str:
    if surface is None:
        return "all"
    return _cursor_surface(surface)


def cursor_protected_surfaces(managed_installs: list[dict[str, object]]) -> tuple[str, ...]:
    surfaces: list[str] = []
    for managed_install in managed_installs:
        surface = managed_install.get("surface")
        if isinstance(surface, str) and surface in {"editor", "cli"} and surface not in surfaces:
            surfaces.append(surface)
            continue
        manifest = managed_install.get("manifest")
        if not isinstance(manifest, dict):
            continue
        manifest_surfaces = manifest.get("surfaces")
        if isinstance(manifest_surfaces, list):
            for value in manifest_surfaces:
                if isinstance(value, str) and value in {"editor", "cli"} and value not in surfaces:
                    surfaces.append(value)
        manifest_surface = manifest.get("surface")
        if (
            isinstance(manifest_surface, str)
            and manifest_surface in {"editor", "cli"}
            and manifest_surface not in surfaces
        ):
            surfaces.append(manifest_surface)
        elif manifest_surface == "all":
            for value in ("editor", "cli"):
                if value not in surfaces:
                    surfaces.append(value)
    return tuple(surfaces)


def cursor_protected_surfaces_from_store(
    harness: str,
    store: GuardStore | None,
    detection: dict[str, object],
) -> tuple[str, ...]:
    if not bool(detection["installed"]):
        return ()
    managed = store.get_managed_install(harness) if store is not None else None
    if not isinstance(managed, dict):
        return ("editor", "cli")
    return cursor_protected_surfaces([managed])


def _cursor_surface(surface: str | None) -> str:
    if surface is None:
        return "editor"
    if surface in {"editor", "cli"}:
        return surface
    raise ValueError(f"Unsupported Cursor surface: {surface}")


def _cursor_surface_statuses(
    context: HarnessContext,
    *,
    protected_surfaces: tuple[str, ...],
) -> list[dict[str, str]]:
    editor_detected = any(path.exists() for path in _cursor_editor_config_paths(context))
    cli_detected = _cursor_cli_detected(context)
    protected = set(protected_surfaces)
    editor_protected = "editor" in protected or _cursor_editor_protected(context)
    cli_protected = "cli" in protected or _cursor_cli_protected(context)
    return [
        {
            "surface": "editor",
            "status": _cursor_status(editor_detected, protected=editor_protected),
        },
        {
            "surface": "cli",
            "status": _cursor_status(cli_detected, protected=cli_protected),
        },
    ]


def _cursor_status(detected: bool, *, protected: bool) -> str:
    if protected and detected:
        return "protected"
    if detected:
        return "detected_unprotected"
    return "not_detected"


def _cursor_redacted_path(context: HarnessContext, surface: str) -> str:
    if surface == "cli":
        return "PATH:guard-cursor-agent|guard-cursor"
    workspace_path = context.workspace_dir / ".cursor" / "mcp.json" if context.workspace_dir is not None else None
    if workspace_path is not None and workspace_path.exists():
        return "$WORKSPACE/.cursor/mcp.json"
    return "$HOME/.cursor/mcp.json"


def _cursor_editor_config_paths(context: HarnessContext) -> tuple[Path, ...]:
    paths: list[Path] = []
    if context.workspace_dir is not None:
        paths.append(context.workspace_dir / ".cursor" / "mcp.json")
    paths.append(context.home_dir / ".cursor" / "mcp.json")
    return tuple(paths)


def _cursor_cli_detected(context: HarnessContext) -> bool:
    return cursor_cli_detected(context)


def _cursor_editor_protected(context: HarnessContext) -> bool:
    for config_path in _cursor_editor_config_paths(context):
        try:
            payload = json.loads(config_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(payload, dict):
            continue
        mcp_servers = payload.get("mcpServers")
        if not isinstance(mcp_servers, dict):
            continue
        for server_config in mcp_servers.values():
            if not isinstance(server_config, dict):
                continue
            command = server_config.get("command")
            args = tuple(str(value) for value in server_config.get("args", []) if isinstance(value, str))
            if is_guard_proxy_command(command if isinstance(command, str) else None, args):
                return True
    return False


def _cursor_cli_protected(context: HarnessContext) -> bool:
    return cursor_cli_shim_installed(context)
