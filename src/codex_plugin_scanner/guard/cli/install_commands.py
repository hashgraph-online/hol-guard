"""Helpers for Guard harness install and uninstall flows."""

from __future__ import annotations

import glob as globlib
from collections.abc import Sequence
from pathlib import Path

from ..adapters import get_adapter, list_adapters
from ..adapters.base import HarnessAdapter, HarnessContext
from ..adapters.cline import ClineHarnessAdapter
from ..adapters.contracts import contract_for
from ..adapters.cursor import CursorHarnessAdapter
from ..agent_safety_guidance import install_agent_safety_guidance, uninstall_agent_safety_guidance
from ..managed_install_proof import bind_managed_install_proof, verify_managed_install_proof
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
from .managed_install_payload import managed_install_payload as _managed_install_payload
from .native_install_checks import _grok_event_has_command_hook as _grok_event_has_command_hook
from .native_install_checks import _grok_hook_command_is_guard as _grok_hook_command_is_guard
from .native_install_checks import _grok_managed_config_is_active as _grok_managed_config_is_active
from .native_install_checks import _grok_pretool_is_catchall as _grok_pretool_is_catchall
from .native_install_checks import _grok_prompt_hook_is_observe as _grok_prompt_hook_is_observe
from .native_install_checks import _grok_protection_checks as _grok_protection_checks
from .native_install_checks import _native_mcp_server_names as _native_mcp_server_names
from .native_install_checks import _opencode_protection_checks as _opencode_protection_checks
from .native_install_checks import grok_hooks_protection_ready as grok_hooks_protection_ready

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
                "body": (
                    "Remove Paseo's receipt and launcher. Shared native provider protection remains installed."
                    if adapter.harness == "paseo"
                    else "Remove Guard managed config for this app."
                ),
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


def _safe_setup_detection(
    adapter: HarnessAdapter,
    context: HarnessContext,
    store: GuardStore | None,
) -> dict[str, object]:
    managed = store.get_managed_install(adapter.harness) if store is not None else None
    if adapter.harness == "paseo":
        diagnostics = adapter.diagnostics(context)
        return {
            "installed": bool(
                managed
                and managed.get("active")
                and diagnostics.get("setup_status") == "active"
                and verify_managed_install_proof(managed.get("manifest"), context) is True
            ),
            "command_available": diagnostics.get("command_available", False),
            "config_paths": diagnostics.get("config_paths", []),
        }
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
