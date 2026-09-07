"""Helpers for Guard harness install and uninstall flows."""

from __future__ import annotations

import glob as globlib
import json
from collections.abc import Sequence
from pathlib import Path

from ..adapters import get_adapter, list_adapters
from ..adapters.base import HarnessAdapter, HarnessContext
from ..adapters.cline import ClineHarnessAdapter
from ..adapters.contracts import contract_for
from ..adapters.cursor import CursorHarnessAdapter
from ..agent_safety_guidance import install_agent_safety_guidance, uninstall_agent_safety_guidance
from ..managed_install_proof import bind_managed_install_proof
from ..runtime.mcp_skill_firewall import build_mcp_skill_firewall_fingerprints, portal_skill_identity
from ..runtime.skill_protection import build_skill_identity, detect_skill_content_risk, skill_identity_metadata
from ..store import GuardStore
from .cursor_actions import (
    cursor_install_surface,
    cursor_local_action_payload,
    cursor_protected_surfaces,
    cursor_protected_surfaces_from_store,
)
from .install_targets import _resolve_targets

_HARNESS_OBSERVED_COPY = {
    "protected": "Active Guard protection is installed.",
    "found": "Observed locally, not protected by Guard yet.",
    "not_found": "Not installed on this machine.",
}


def _apply_adapter_management(
    adapter: HarnessAdapter,
    context: HarnessContext,
    *,
    active: bool,
    surface: str | None,
) -> dict[str, object]:
    """Apply one adapter mutation while honoring declared surface capabilities."""

    if surface is None:
        if isinstance(adapter, CursorHarnessAdapter):
            selected_surface = cursor_install_surface(None)
            return (
                adapter.install(context, surface=selected_surface)
                if active
                else adapter.uninstall(context, surface=selected_surface)
            )
        return adapter.install(context) if active else adapter.uninstall(context)

    setup_contract = adapter.setup_contract()
    if surface not in setup_contract.surface_capabilities:
        raise ValueError(f"Unsupported {setup_contract.display_name} surface: {surface}")
    if isinstance(adapter, CursorHarnessAdapter):
        selected_surface = cursor_install_surface(surface)
        return (
            adapter.install(context, surface=selected_surface)
            if active
            else adapter.uninstall(context, surface=selected_surface)
        )
    if isinstance(adapter, ClineHarnessAdapter):
        return adapter.install(context, surface=surface) if active else adapter.uninstall(context, surface=surface)
    raise ValueError(f"Unsupported {setup_contract.display_name} surface: {surface}")


def apply_managed_install(
    command: str,
    requested_harness: str | Sequence[str] | None,
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
        manifest = _apply_adapter_management(
            adapter,
            context,
            active=active,
            surface=surface,
        )
        if active:
            manifest = bind_managed_install_proof(manifest, context)
        store.set_managed_install(canonical_harness, active, workspace, manifest, now)
        managed_install = store.get_managed_install(canonical_harness)
        if managed_install is not None:
            managed_installs.append(_managed_install_payload(managed_install))
    payload: dict[str, object] = {
        "managed_installs": managed_installs,
        "auto_detected": requested_harness is None or install_all,
    }
    if active and managed_installs:
        payload["agent_safety_guidance"] = install_agent_safety_guidance(context.home_dir)
    elif managed_installs and not any(bool(item.get("active")) for item in store.list_managed_installs()):
        payload["agent_safety_guidance"] = uninstall_agent_safety_guidance(context.home_dir)
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
        for key in (
            "config_path",
            "managed_config_path",
            "shim_path",
            "shim_paths",
            "shim_command",
            "shim_commands",
            "mode",
            "surface",
            "surfaces",
        ):
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
    if adapter.harness == "grok":
        verification.update(_grok_protection_checks(context))
    if isinstance(adapter, ClineHarnessAdapter):
        runtime_probe = adapter.runtime_probe(context)
        verification["runtime"] = runtime_probe or {}
        verification["warnings"] = adapter.diagnostic_warnings(adapter.detect(context), runtime_probe)
        active_transport = runtime_probe.get("active_transport") if isinstance(runtime_probe, dict) else None
        requested_transport = surface if surface in {"hooks", "plugin"} else active_transport
        state_key = "plugin" if requested_transport == "plugin" else "native_hooks"
        runtime_state = runtime_probe.get(state_key) if isinstance(runtime_probe, dict) else None
        verification["active_transport"] = active_transport
        verification["requested_transport"] = requested_transport
        verification["ready"] = bool(
            requested_transport == active_transport
            and isinstance(runtime_state, dict)
            and runtime_state.get("ready") is True
        )
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
    return {name for name in mcp if isinstance(name, str) and not name.startswith("hol-guard::")}


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
    loaded_config_paths = [Path(path) for path in adapter.detect(context).config_paths if Path(path).is_file()] or (
        [config_path] if config_path.is_file() else []
    )
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


def _grok_pretool_is_catchall(pretool_hook: Path) -> bool:
    if not pretool_hook.is_file():
        return False
    try:
        payload = json.loads(pretool_hook.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    if not isinstance(payload, dict):
        return False
    hooks = payload.get("hooks")
    if not isinstance(hooks, dict):
        return False
    entries = hooks.get("PreToolUse")
    if not isinstance(entries, list) or len(entries) != 1 or not isinstance(entries[0], dict):
        return False
    matcher = entries[0].get("matcher")
    if matcher not in {None, ""}:
        return False
    nested = entries[0].get("hooks")
    if not isinstance(nested, list) or len(nested) != 1 or not isinstance(nested[0], dict):
        return False
    command = nested[0].get("command")
    return nested[0].get("type") == "command" and isinstance(command, str) and _grok_hook_command_is_guard(command)


def _grok_hook_command_is_guard(command: str) -> bool:
    lowered = command.lower()
    tokens = lowered.replace("=", " ").replace(",", " ").split()
    if not tokens:
        return False
    first = tokens[0].rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    if first in {"echo", "true", "false", "printf", ":"}:
        return False
    return "hook" in lowered and (
        "hol-guard" in tokens
        or any(token.endswith("/hol-guard") or token.endswith("\\hol-guard") for token in tokens)
        or "__guard-bounded-hook" in lowered
        or "__guard-cursor-hook" in lowered
        or "bounded_cli_hook_bridge" in lowered
        or "codex_plugin_scanner.guard" in lowered
    )


def _grok_prompt_hook_is_observe(prompt_hook: Path) -> bool:
    if not prompt_hook.is_file():
        return False
    try:
        payload = json.loads(prompt_hook.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    if not isinstance(payload, dict):
        return False
    hooks = payload.get("hooks")
    if not isinstance(hooks, dict):
        return False
    required = ("UserPromptSubmit", "SubagentStart", "SessionStart")
    return all(_grok_event_has_command_hook(hooks.get(event_name)) for event_name in required)


def _grok_event_has_command_hook(entries: object) -> bool:
    if not isinstance(entries, list) or not entries:
        return False
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        nested = entry.get("hooks")
        if not isinstance(nested, list):
            continue
        for hook_entry in nested:
            if not isinstance(hook_entry, dict) or hook_entry.get("type") != "command":
                continue
            command = hook_entry.get("command")
            if isinstance(command, str) and _grok_hook_command_is_guard(command):
                return True
    return False


def _grok_managed_config_is_active(managed_text: str) -> bool:
    from ..adapters.grok_config import GUARD_MANAGED_BEGIN, GUARD_MANAGED_END

    start = managed_text.find(GUARD_MANAGED_BEGIN)
    stop = managed_text.find(GUARD_MANAGED_END)
    if start < 0 or stop <= start:
        return False
    for line in managed_text[start:stop].splitlines():
        active = line.split("#", 1)[0].strip()
        if "Read(**/.grok/auth/**)" in active:
            return True
    return False


def grok_hooks_protection_ready(context: HarnessContext) -> bool:
    """Return whether live Grok hook files and managed permission rules are active."""

    checks = _grok_protection_checks(context)
    warnings = checks.get("warnings")
    warning_items = warnings if isinstance(warnings, list) else []
    hook_warnings = [
        warning
        for warning in warning_items
        if isinstance(warning, str) and "shim" not in warning.lower() and "launcher" not in warning.lower()
    ]
    return (
        checks.get("pretool_catchall_installed") is True
        and checks.get("prompt_hook_installed") is True
        and checks.get("managed_config_installed") is True
        and not hook_warnings
    )


def _grok_protection_checks(context: HarnessContext) -> dict[str, object]:
    from ..adapters.grok import GrokHarnessAdapter

    adapter = GrokHarnessAdapter()
    hooks_dir = adapter._hooks_dir(context)
    managed_config = adapter._managed_config_path(context)
    pretool_hook = hooks_dir / "hol-guard-pretooluse.json"
    prompt_hook = hooks_dir / "hol-guard-prompt.json"
    warnings: list[str] = []
    if not pretool_hook.is_file() or not prompt_hook.is_file():
        warnings.append("Grok Guard hook files are missing from ~/.grok/hooks/. Re-run `hol-guard apps connect grok`.")
    elif not _grok_pretool_is_catchall(pretool_hook):
        warnings.append(
            "Grok Guard pre-tool hook still uses a stale per-tool matcher list. Re-run `hol-guard apps repair grok`."
        )
    elif not _grok_prompt_hook_is_observe(prompt_hook):
        warnings.append(
            "Grok Guard observe hooks are missing prompt, session, or subagent events. "
            "Re-run `hol-guard apps repair grok`."
        )
    managed_text = managed_config.read_text(encoding="utf-8") if managed_config.is_file() else ""
    if not managed_config.is_file() or not _grok_managed_config_is_active(managed_text):
        warnings.append(
            "Grok managed permission rules are missing from ~/.grok/managed_config.toml. "
            "Re-run `hol-guard apps connect grok`."
        )
    elif "Read(~/" in managed_text:
        warnings.append(
            "Grok managed deny rules still use literal home prefixes that Grok does not expand. "
            "Re-run `hol-guard apps repair grok`."
        )
    shim_path = context.guard_home / "bin" / "guard-grok"
    if not shim_path.is_file():
        warnings.append(
            f"guard-grok launcher shim is missing. Add {context.guard_home / 'bin'} to PATH or launch with "
            "`hol-guard run grok` for pre-launch checks."
        )
    return {
        "pretool_hook_installed": pretool_hook.is_file(),
        "prompt_hook_installed": prompt_hook.is_file(),
        "pretool_catchall_installed": _grok_pretool_is_catchall(pretool_hook),
        "managed_config_installed": managed_config.is_file(),
        "launch_shim_installed": shim_path.is_file(),
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
            skill_metadata = skill_identity_metadata(identity)
            firewall = build_mcp_skill_firewall_fingerprints(
                skill=portal_skill_identity(identity),
            )
            if stored_hash == identity.identity_hash:
                continue
            signals = detect_skill_content_risk(content, skill_path=str(skill_path))
            store.save_snapshot(
                "skill_scan",
                artifact_id,
                {
                    "identity_hash": identity.identity_hash,
                    "skill_path": str(skill_path),
                    "mcp_skill_identity": skill_metadata,
                    "mcpSkillFirewall": firewall,
                },
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


__all__ = [
    "apply_managed_install",
    "build_harness_setup_plan",
    "build_harness_verification",
    "list_harness_setup_items",
    "scan_workspace_skills",
    "uninstall_confirmation_token",
]
