"""Helpers for Guard harness install and uninstall flows."""

from __future__ import annotations

import glob as globlib
import json
from pathlib import Path

from ..adapters import get_adapter, list_adapters
from ..adapters.base import HarnessAdapter, HarnessContext
from ..adapters.contracts import contract_for
from ..adapters.cursor import CursorHarnessAdapter
from ..consumer import detect_all
from ..runtime.skill_protection import build_skill_identity, detect_skill_content_risk
from ..store import GuardStore
from .cursor_actions import (
    cursor_install_surface,
    cursor_local_action_payload,
    cursor_protected_surfaces,
    cursor_protected_surfaces_from_store,
)

_HARNESS_OBSERVED_COPY = {
    "protected": "Active Guard protection is installed.",
    "found": "Observed locally, not protected by Guard yet.",
    "not_found": "Not installed on this machine.",
}


def apply_managed_install(
    command: str,
    requested_harness: str | None,
    install_all: bool,
    context: HarnessContext,
    store: GuardStore,
    workspace: str | None,
    now: str,
    *,
    surface: str | None = None,
) -> dict[str, object]:
    targets = _resolve_targets(command, requested_harness, install_all, context, store)
    active = command == "install"
    managed_installs: list[dict[str, object]] = []
    for harness in targets:
        adapter = get_adapter(harness)
        canonical_harness = adapter.harness
        if isinstance(adapter, CursorHarnessAdapter):
            selected_surface = cursor_install_surface(surface)
            manifest = (
                adapter.install(context, surface=selected_surface)
                if active
                else adapter.uninstall(context, surface=selected_surface)
            )
        else:
            manifest = adapter.install(context) if active else adapter.uninstall(context)
        store.set_managed_install(canonical_harness, active, workspace, manifest, now)
        managed_install = store.get_managed_install(canonical_harness)
        if managed_install is not None:
            managed_installs.append(_managed_install_payload(managed_install))
    payload: dict[str, object] = {
        "managed_installs": managed_installs,
        "auto_detected": requested_harness is None or install_all,
    }
    if len(managed_installs) == 1:
        payload["managed_install"] = managed_installs[0]
    if active and context.workspace_dir is not None:
        skill_scan = scan_workspace_skills(context.workspace_dir, store, now)
        if skill_scan:
            payload["skill_scan"] = skill_scan
    if len(managed_installs) == 1 and (requested_harness == "cursor" or managed_installs[0].get("harness") == "cursor"):
        payload["cursor_action"] = cursor_local_action_payload(
            action=command,
            surface=surface,
            context=context,
            protected_surfaces=cursor_protected_surfaces(managed_installs) if active else (),
        )
    return payload


def _managed_install_payload(managed_install: dict[str, object]) -> dict[str, object]:
    payload = dict(managed_install)
    harness = str(payload.get("harness") or "")
    protection_contract = contract_for(harness)
    if protection_contract is not None:
        payload["native_hooks"] = protection_contract.native_approval
        payload["browser_fallback"] = protection_contract.browser_fallback
        payload["primary_integration"] = "native_hooks" if protection_contract.native_approval else "browser_fallback"
    manifest = payload.get("manifest")
    if isinstance(manifest, dict):
        for key in ("config_path", "managed_config_path", "shim_path", "shim_command", "mode", "surface", "surfaces"):
            value = manifest.get(key)
            if value is not None:
                payload[key] = value
    return payload


def list_harness_setup_items(context: HarnessContext, store: GuardStore | None = None) -> list[dict[str, object]]:
    items: list[dict[str, object]] = []
    for adapter in list_adapters():
        detection = _safe_setup_detection(adapter, context, store)
        detected = detection["installed"] or detection["command_available"] or bool(detection["config_paths"])
        if detection["installed"]:
            status = "protected"
        elif detected:
            status = "found"
        else:
            status = "not_found"
        observed_copy = _HARNESS_OBSERVED_COPY[status]
        items.append(
            {
                "harness": adapter.harness,
                "status": status,
                "observed_copy": observed_copy,
                "installed": detection["installed"],
                "command_available": detection["command_available"],
                "config_paths": detection["config_paths"],
                "artifact_count": 0,
                **adapter.setup_contract().to_dict(),
            }
        )
    return items


def build_harness_setup_plan(
    action: str,
    requested_harness: str,
    context: HarnessContext,
    *,
    dry_run: bool,
    surface: str | None = None,
) -> dict[str, object]:
    adapter = get_adapter(requested_harness)
    contract = adapter.setup_contract()
    if action == "repair":
        steps = adapter.repair_steps()
    elif action == "uninstall":
        steps = ()
    else:
        steps = adapter.setup_steps()
    payload: dict[str, object] = {
        "harness": adapter.harness,
        "action": action,
        "dry_run": dry_run,
        "contract": contract.to_dict(),
        "steps": [step.to_dict() for step in steps],
        "workspace": str(context.workspace_dir) if context.workspace_dir is not None else None,
    }
    if dry_run and action in {"connect", "repair"}:
        payload["dry_run_effect"] = (
            "No app config was changed and Guard Cloud was not connected. "
            f"Run hol-guard apps {action} {adapter.harness} without --dry-run to finish setup."
        )
    if action == "uninstall":
        confirmation_phrase = uninstall_confirmation_token(adapter.harness)
        payload["confirmation_phrase"] = confirmation_phrase
        payload["confirm_command"] = f"hol-guard apps disconnect {adapter.harness} --confirm {confirmation_phrase}"
        payload["steps"] = [
            {
                "step_id": "disconnect",
                "title": f"Disconnect {contract.display_name}",
                "body": "Remove Guard managed config for this app.",
                "command": ["hol-guard", "apps", "disconnect", adapter.harness],
                "writes_config": True,
                "requires_confirmation": True,
            }
        ]
    if adapter.harness == "cursor":
        payload["cursor_action"] = cursor_local_action_payload(
            action=action,
            surface=surface,
            context=context,
            protected_surfaces=(),
        )
    return payload


def build_harness_verification(
    requested_harness: str,
    context: HarnessContext,
    store: GuardStore | None = None,
    surface: str | None = None,
    action: str = "test",
) -> dict[str, object]:
    adapter = get_adapter(requested_harness)
    detection = _safe_setup_detection(adapter, context, store)
    verification: dict[str, object] = {
        "checked": True,
        "writes_config": False,
        "installed": detection["installed"],
        "command_available": detection["command_available"],
        "config_paths": detection["config_paths"],
        "artifact_count": 0,
        "warnings": [],
        "steps": [step.to_dict() for step in adapter.verify_steps()],
    }
    if adapter.harness == "opencode":
        verification.update(_opencode_protection_checks(context, store))
    payload: dict[str, object] = {
        "harness": adapter.harness,
        "safe": True,
        "contract": adapter.setup_contract().to_dict(),
        "verification": verification,
    }
    if adapter.harness == "cursor":
        payload["cursor_action"] = cursor_local_action_payload(
            action=action,
            surface=surface,
            context=context,
            protected_surfaces=cursor_protected_surfaces_from_store(
                adapter.harness,
                store,
                detection,
            ),
        )
    return payload


def uninstall_confirmation_token(harness: str) -> str:
    return f"disconnect-{harness}"


def _native_mcp_server_names(config_path: Path) -> set[str]:
    from ...ecosystems.opencode import _load_json_or_jsonc

    payload, parse_error, _ = _load_json_or_jsonc(config_path)
    if parse_error or not isinstance(payload, dict):
        return set()
    mcp = payload.get("mcp")
    if not isinstance(mcp, dict):
        return set()
    return {
        name
        for name in mcp
        if isinstance(name, str) and not name.startswith("hol-guard::")
    }


def _opencode_protection_checks(context: HarnessContext, store: GuardStore | None) -> dict[str, object]:
    from ..adapters.opencode import OpenCodeHarnessAdapter
    from ..adapters.opencode_artifacts import runtime_config_path
    from ..adapters.opencode_pretool import (
        global_plugin_path,
        opencode_config_has_mcp_servers,
        opencode_config_uses_guard_proxy,
    )

    adapter = OpenCodeHarnessAdapter()
    managed = store.get_managed_install("opencode") if store is not None else None
    config_path = adapter._managed_install_config_path(context)
    shim_path = context.guard_home / "bin" / "guard-opencode"
    plugin_path = global_plugin_path(context)
    loaded_config_paths = [
        Path(path)
        for path in adapter.detect(context).config_paths
        if Path(path).is_file()
    ] or ([config_path] if config_path.is_file() else [])
    has_loaded_mcp = any(opencode_config_has_mcp_servers(path) for path in loaded_config_paths)
    if not has_loaded_mcp:
        mcp_proxy_configured = False
    else:
        mcp_proxy_configured = all(
            (not opencode_config_has_mcp_servers(path)) or opencode_config_uses_guard_proxy(path)
            for path in loaded_config_paths
        )
        runtime_overlay_path = runtime_config_path(context)
        if not mcp_proxy_configured and runtime_overlay_path.is_file():
            try:
                runtime_payload = json.loads(runtime_overlay_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                runtime_payload = {}
            runtime_mcp = runtime_payload.get("mcp")
            if isinstance(runtime_mcp, dict) and runtime_mcp:
                managed_server_names = {
                    name
                    for path in loaded_config_paths
                    if opencode_config_has_mcp_servers(path)
                    for name in _native_mcp_server_names(path)
                }
                mcp_proxy_configured = managed_server_names.issubset(set(runtime_mcp))
    has_unproxied_mcp = has_loaded_mcp and not mcp_proxy_configured
    warnings: list[str] = []
    if not (managed and managed.get("active")):
        warnings.append("Run `hol-guard install opencode` to activate Guard-managed OpenCode protection.")
    if not plugin_path.is_file():
        warnings.append(
            "OpenCode pretool plugin is missing from ~/.config/opencode/plugins/. Re-run `hol-guard install opencode`."
        )
    if not config_path.is_file():
        warnings.append(
            "OpenCode root config is missing at ~/.config/opencode/opencode.json. Re-run `hol-guard install opencode`."
        )
    if has_unproxied_mcp:
        warnings.append(
            "OpenCode MCP servers are not routed through hol-guard companion servers or the runtime overlay. "
            "Re-run `hol-guard install opencode`."
        )
    if not shim_path.is_file():
        warnings.append(
            f"guard-opencode launcher shim is missing. Add {context.guard_home / 'bin'} to PATH or launch with "
            "`hol-guard run opencode` for pre-launch checks."
        )
    return {
        "pretool_plugin_installed": plugin_path.is_file(),
        "mcp_proxy_configured": mcp_proxy_configured,
        "launch_shim_installed": shim_path.is_file(),
        "managed_install_active": bool(managed and managed.get("active")),
        "warnings": warnings,
        "ready": not warnings,
    }


def _safe_setup_detection(
    adapter: HarnessAdapter,
    context: HarnessContext,
    store: GuardStore | None,
) -> dict[str, object]:
    managed = store.get_managed_install(adapter.harness) if store is not None else None
    protection_contract = contract_for(adapter.harness)
    config_paths = protection_contract.config_paths if protection_contract is not None else ()
    return {
        "installed": bool(managed and managed.get("active")),
        "command_available": adapter.resolved_executable(context) is not None,
        "config_paths": _existing_contract_config_paths(config_paths, context),
    }


def _existing_contract_config_paths(config_paths: tuple[str, ...], context: HarnessContext) -> list[str]:
    existing: list[str] = []
    for config_path in config_paths:
        for candidate in _contract_config_path_candidates(config_path, context):
            if candidate.exists():
                existing.append(str(candidate))
    return sorted(dict.fromkeys(existing))


def _contract_config_path_candidates(config_path: str, context: HarnessContext) -> tuple[Path, ...]:
    expanded_path = _expand_contract_config_path(config_path, context)
    if globlib.has_magic(str(expanded_path)):
        return tuple(sorted(Path(path) for path in globlib.glob(str(expanded_path))))
    return (expanded_path,)


def _expand_contract_config_path(config_path: str, context: HarnessContext) -> Path:
    path = Path(config_path)
    if path.parts and path.parts[0] == "~":
        return context.home_dir.joinpath(*path.parts[1:])
    if path.is_absolute():
        return path
    return context.home_dir / path


def scan_workspace_skills(
    workspace_dir: Path,
    store: GuardStore,
    now: str,
) -> list[dict[str, object]]:
    """Scan SKILL.md files in workspace and return risk summaries for any findings."""
    results: list[dict[str, object]] = []
    skills_dirs = [
        workspace_dir / ".codex" / "skills",
        workspace_dir / ".agents" / "skills",
        workspace_dir / "skills",
    ]
    for skills_dir in skills_dirs:
        if not skills_dir.is_dir():
            continue
        for skill_path in sorted(skills_dir.rglob("SKILL.md")):
            try:
                content = skill_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            identity = build_skill_identity(content, skill_path=str(skill_path))
            artifact_id = f"skill-path:{skill_path}"
            stored = store.get_snapshot("skill_scan", artifact_id)
            stored_hash = stored.get("identity_hash") if stored else None
            if stored_hash == identity.identity_hash:
                continue
            signals = detect_skill_content_risk(content, skill_path=str(skill_path))
            store.save_snapshot(
                "skill_scan",
                artifact_id,
                {"identity_hash": identity.identity_hash, "skill_path": str(skill_path)},
                identity.identity_hash,
                now,
            )
            if signals:
                results.append(
                    {
                        "skill_path": str(skill_path.relative_to(workspace_dir)),
                        "identity_hash": identity.identity_hash,
                        "risk_count": len(signals),
                        "severities": sorted({s.severity for s in signals}),
                        "signal_ids": [s.signal_id for s in signals],
                    }
                )
    return results


def _resolve_targets(
    command: str,
    requested_harness: str | None,
    install_all: bool,
    context: HarnessContext,
    store: GuardStore,
) -> list[str]:
    if requested_harness is not None and install_all:
        raise ValueError("Pass either a harness or --all, not both.")
    if requested_harness is not None and not install_all:
        return [get_adapter(requested_harness).harness]
    if not install_all:
        action = "install" if command == "install" else "uninstall"
        raise ValueError(f"Guard {action} requires a harness or --all.")
    detected = {
        detection.harness
        for detection in detect_all(context)
        if detection.installed
        or detection.command_available
        or len(detection.config_paths) > 0
        or len(detection.artifacts) > 0
    }
    if command == "uninstall":
        detected.update(
            str(item.get("harness"))
            for item in store.list_managed_installs()
            if bool(item.get("active")) and isinstance(item.get("harness"), str)
        )
    targets = sorted(detected)
    if targets:
        return targets
    action = "install" if command == "install" else "remove"
    raise ValueError(
        f"No supported harnesses were detected for Guard {action}. Pass a harness explicitly or configure one first."
    )


__all__ = [
    "apply_managed_install",
    "build_harness_setup_plan",
    "build_harness_verification",
    "list_harness_setup_items",
    "scan_workspace_skills",
    "uninstall_confirmation_token",
]
