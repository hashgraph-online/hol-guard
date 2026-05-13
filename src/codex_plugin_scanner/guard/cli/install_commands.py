"""Helpers for Guard harness install and uninstall flows."""

from __future__ import annotations

import glob as globlib
from pathlib import Path

from ..adapters import get_adapter, list_adapters
from ..adapters.base import HarnessAdapter, HarnessContext
from ..adapters.contracts import contract_for
from ..consumer import detect_all
from ..runtime.skill_protection import build_skill_identity, detect_skill_content_risk
from ..store import GuardStore


def apply_managed_install(
    command: str,
    requested_harness: str | None,
    install_all: bool,
    context: HarnessContext,
    store: GuardStore,
    workspace: str | None,
    now: str,
) -> dict[str, object]:
    targets = _resolve_targets(command, requested_harness, install_all, context, store)
    active = command == "install"
    managed_installs: list[dict[str, object]] = []
    for harness in targets:
        adapter = get_adapter(harness)
        canonical_harness = adapter.harness
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
        for key in ("config_path", "managed_config_path", "shim_path", "mode"):
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
        items.append(
            {
                "harness": adapter.harness,
                "status": status,
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
    return payload


def build_harness_verification(
    requested_harness: str,
    context: HarnessContext,
    store: GuardStore | None = None,
) -> dict[str, object]:
    adapter = get_adapter(requested_harness)
    detection = _safe_setup_detection(adapter, context, store)
    return {
        "harness": adapter.harness,
        "safe": True,
        "contract": adapter.setup_contract().to_dict(),
        "verification": {
            "checked": True,
            "writes_config": False,
            "installed": detection["installed"],
            "command_available": detection["command_available"],
            "config_paths": detection["config_paths"],
            "artifact_count": 0,
            "warnings": [],
            "steps": [step.to_dict() for step in adapter.verify_steps()],
        },
    }


def uninstall_confirmation_token(harness: str) -> str:
    return f"disconnect-{harness}"


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
