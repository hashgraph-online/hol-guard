"""Helpers for Guard harness install and uninstall flows."""

from __future__ import annotations

import os
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from ..harness.base import HarnessAdapter, HarnessContext
from ..harness.native_harness import ask as native_ask
from ..harness.registry import get_adapter, list_adapters
from ..runtime_transition import assert_transition_mutation_allowed
from ..store import GuardStore
from .claude_settings_target import claude_settings_target
from .cursor_actions import (
    cursor_install_surface,
    cursor_local_action_payload,
    cursor_protected_surfaces,
    cursor_protected_surfaces_from_store,
)
from .install_targets import _resolve_targets
from .managed_install_payload import managed_install_payload as _managed_install_payload
from .native_install_checks import _grok_hook_command_is_guard as _grok_hook_command_is_guard
from .native_install_checks import _grok_protection_checks as _grok_protection_checks
from .native_install_checks import _opencode_protection_checks as _opencode_protection_checks
from .native_install_checks import grok_hooks_protection_ready as grok_hooks_protection_ready
from .native_managed_install import native_managed_install

_HARNESS_OBSERVED_COPY = {
    "protected": "Active Guard protection is installed.",
    "needs_repair": "Guard protection is installed but its setup check failed. Run hol-guard repair.",
    "found": "Observed locally, not protected by Guard yet.",
    "not_found": "Not installed on this machine.",
}


def _selected_surface(adapter: HarnessAdapter, context: HarnessContext, surface: str | None) -> str | None:
    """The surface an adapter mutation uses, honoring the capabilities its contract declares."""

    if surface is None:
        return cursor_install_surface(None, context) if adapter.harness == "cursor" else None
    setup_contract = adapter.setup_contract()
    if surface not in setup_contract.surface_capabilities:
        raise ValueError(f"Unsupported {setup_contract.display_name} surface: {surface}")
    if adapter.harness == "cursor":
        return cursor_install_surface(surface, context)
    if adapter.harness == "cline":
        return surface
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
    # The native runtime installs each app, records its row and journals every write in one installation
    # transaction over the Guard home; this process only names the targets and the facts it alone knows.
    assert_transition_mutation_allowed(context.guard_home)
    adapters = [
        get_adapter(harness) for harness in _resolve_targets(command, requested_harness, install_all, context, store)
    ]
    active = command == "install"
    targets: list[dict[str, object]] = []
    for adapter in adapters:
        selected = _selected_surface(adapter, context, surface)
        target: dict[str, object] = {"harness": adapter.harness}
        if selected is not None:
            target["surface"] = selected
        targets.append(target)
    rows, guidance = native_managed_install(
        command, targets, context, workspace=workspace, now=now, source=store.guard_source
    )
    managed_installs = [_managed_install_payload(row) for row in rows]
    payload: dict[str, object] = {
        "managed_installs": managed_installs,
        "auto_detected": requested_harness is None or install_all,
    }
    if guidance is not None:
        payload["agent_safety_guidance"] = guidance
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
            protected_surfaces=cursor_protected_surfaces(managed_installs, context) if active else (),
        )
    return payload


def list_harness_setup_items(context: HarnessContext, store: GuardStore | None = None) -> list[dict[str, object]]:
    items: list[dict[str, object]] = []
    for adapter in list_adapters():
        detection = _safe_setup_detection(adapter, context, store, use_fleet_check=True)
        detected = detection["installed"] or detection["command_available"] or bool(detection["config_paths"])
        if detection["needs_repair"]:
            status = "needs_repair"
        elif detection["installed"]:
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
    if adapter.harness == "claude-code" and action in {"connect", "repair"}:
        payload["settings_target"] = claude_settings_target(context)
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
    if adapter.harness == "cline":
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
                store,
                detection,
                context,
            ),
        )
    return payload


def uninstall_confirmation_token(harness: str) -> str:
    return f"disconnect-{harness}"


def _safe_setup_detection(
    adapter: HarnessAdapter,
    context: HarnessContext,
    store: GuardStore | None,
    *,
    use_fleet_check: bool = False,
) -> dict[str, object]:
    """Detect an app's Guard setup; the runtime reads the store and decides.

    Only the app list sets ``use_fleet_check``, so it matches what Guard Cloud shows. Verification
    (``apps test`` and headless checks) keeps reading the install record and runs its own checks.
    """
    fields: dict[str, Any] = {
        "store_home": None if store is None else str(store.guard_home),
        "use_fleet_check": use_fleet_check,
    }
    if adapter.harness == "paseo":
        diagnostics = adapter.diagnostics(context)
        fields["diagnostics"] = {
            key: diagnostics[key] for key in ("setup_status", "command_available", "config_paths") if key in diagnostics
        }
    return native_ask("setup_detection", context, harness=adapter.harness, **fields)


_SKILLS_TIMEOUT_SECONDS = 60.0


def _skills_unavailable() -> list[dict[str, object]]:
    # The install is already applied: a runtime that does not answer leaves the
    # skills unscanned, reported as such, never as clean.
    return [
        {
            "skill_path": ".",
            "identity_hash": None,
            "status": "unscanned",
            "risk_count": None,
            "severities": [],
            "signal_ids": [],
            "scan_error": "native_workspace_skills_scan_unavailable",
        }
    ]


def scan_workspace_skills(
    workspace_dir: Path,
    store: GuardStore,
    now: str,
) -> list[dict[str, object]]:
    """Scan SKILL.md files in workspace and return risk summaries for any findings.

    The native runtime finds, describes and scans the skills, reads what the store holds for each and saves the
    identity of those that changed. This only names the workspace and the store."""
    from ..native_runner_authority import NativeRunnerAuthorityError

    workspace = Path(os.path.abspath(workspace_dir))
    context = HarnessContext(home_dir=Path.home(), workspace_dir=workspace, guard_home=store.guard_home)
    try:
        answer = native_ask(
            "workspace_skills_scan",
            context,
            timeout_seconds=_SKILLS_TIMEOUT_SECONDS,
            workspace_dir=str(workspace),
            now=now,
            source=store.guard_source,
        )
    except NativeRunnerAuthorityError:
        return _skills_unavailable()
    results = answer.get("skill_scan")
    if not isinstance(results, list):
        return _skills_unavailable()
    return [dict(result) for result in results if isinstance(result, dict)]


__all__ = [
    "apply_managed_install",
    "build_harness_setup_plan",
    "build_harness_verification",
    "list_harness_setup_items",
    "scan_workspace_skills",
    "uninstall_confirmation_token",
]
