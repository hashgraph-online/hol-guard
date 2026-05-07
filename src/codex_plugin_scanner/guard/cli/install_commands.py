"""Helpers for Guard harness install and uninstall flows."""

from __future__ import annotations

from pathlib import Path

from ..adapters import get_adapter
from ..adapters.base import HarnessContext
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
            managed_installs.append(managed_install)
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
            artifact_id = f"skill:{identity.skill_hash[:16]}"
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


__all__ = ["apply_managed_install", "scan_workspace_skills"]
