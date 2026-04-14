"""Bootstrap helpers for first-run Guard onboarding."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from ..adapters import get_adapter
from ..adapters.base import HarnessContext
from ..config import GuardConfig
from ..daemon import ensure_guard_daemon
from ..store import GuardStore
from .install_commands import apply_managed_install
from .product import build_guard_start_payload

GUARD_COMMAND = "hol-guard"
DEFAULT_ALIAS_NAME = "guardp"


def build_guard_bootstrap_payload(
    *,
    context: HarnessContext,
    store: GuardStore,
    config: GuardConfig,
    requested_harness: str | None,
    skip_install: bool,
    alias_name: str,
    write_shell_alias: bool,
) -> dict[str, object]:
    payload = build_guard_start_payload(context, store, config)
    daemon_url = ensure_guard_daemon(context.guard_home)
    recommended_harness = _resolve_harness(payload, requested_harness)
    bootstrap_install = _build_bootstrap_install(
        requested_harness=recommended_harness,
        skip_install=skip_install,
        context=context,
        store=store,
    )
    alias = _build_alias_payload(context.guard_home, alias_name, write_shell_alias)
    payload["approval_center_url"] = daemon_url
    payload["approval_center_reachable"] = True
    payload["bootstrap_install"] = bootstrap_install
    payload["shell_alias"] = alias
    payload["next_steps"] = _build_bootstrap_steps(
        harness=recommended_harness,
        bootstrap_install=bootstrap_install,
        alias=alias,
    )
    store.add_event(
        "bootstrap",
        {
            "recommended_harness": recommended_harness,
            "installed_harness": bootstrap_install.get("harness"),
            "approval_center_url": daemon_url,
            "alias_name": alias_name,
            "alias_written": alias["written"],
        },
        _now(),
    )
    return payload


def _resolve_harness(payload: dict[str, object], requested_harness: str | None) -> str | None:
    if isinstance(requested_harness, str) and requested_harness.strip():
        return requested_harness.strip()
    recommended_harness = payload.get("recommended_harness")
    return recommended_harness if isinstance(recommended_harness, str) and recommended_harness.strip() else None


def _build_bootstrap_install(
    *,
    requested_harness: str | None,
    skip_install: bool,
    context: HarnessContext,
    store: GuardStore,
) -> dict[str, object]:
    if requested_harness is None:
        return {
            "installed": False,
            "reason": "no_harness_detected",
        }
    get_adapter(requested_harness)
    if skip_install:
        return {
            "installed": False,
            "harness": requested_harness,
            "reason": "skipped_by_flag",
        }
    managed_install = store.get_managed_install(requested_harness)
    if managed_install is not None and bool(managed_install.get("active")):
        return {
            "installed": False,
            "harness": requested_harness,
            "reason": "already_managed",
            "managed_install": managed_install,
        }
    install_payload = apply_managed_install(
        "install",
        requested_harness,
        False,
        context,
        store,
        str(context.workspace_dir) if context.workspace_dir is not None else None,
        _now(),
    )
    managed_install = install_payload.get("managed_install")
    return {
        "installed": True,
        "harness": requested_harness,
        "managed_install": managed_install,
    }


def _build_alias_payload(guard_home: Path, alias_name: str, write_shell_alias: bool) -> dict[str, object]:
    snippet = f"alias {alias_name}='{GUARD_COMMAND} protect'"
    alias_path = guard_home / "shell-aliases.sh"
    if write_shell_alias:
        alias_path.write_text(f"{snippet}\n", encoding="utf-8")
    return {
        "name": alias_name,
        "snippet": snippet,
        "path": str(alias_path),
        "written": write_shell_alias,
    }


def _build_bootstrap_steps(
    *,
    harness: str | None,
    bootstrap_install: dict[str, object],
    alias: dict[str, object],
) -> list[dict[str, str]]:
    if harness is None:
        return [
            {
                "title": "Detect a supported harness",
                "command": f"{GUARD_COMMAND} detect",
                "detail": (
                    "Install Codex, Claude Code, Copilot CLI, Cursor, Gemini, or OpenCode first, then rerun bootstrap."
                ),
            }
        ]
    install_reason = str(bootstrap_install.get("reason") or "")
    install_title = (
        f"Guard is already managing {harness}"
        if install_reason == "already_managed"
        else f"Run the first protected {harness} session"
    )
    install_detail = (
        f"Use {GUARD_COMMAND} run {harness} --dry-run to record the current tool state."
        if install_reason == "already_managed"
        else f"Bootstrap already installed Guard for {harness}. Dry-run it once before the next real launch."
    )
    alias_detail = (
        f"Source {alias['path']} if you want a short wrapper alias in this shell."
        if bool(alias.get("written"))
        else f"Optional shortcut: {alias['snippet']}"
    )
    return [
        {
            "title": install_title,
            "command": f"{GUARD_COMMAND} run {harness} --dry-run",
            "detail": install_detail,
        },
        {
            "title": "Use install-time protection",
            "command": str(alias["snippet"]),
            "detail": alias_detail,
        },
        {
            "title": "Review queued approvals later",
            "command": f"{GUARD_COMMAND} approvals",
            "detail": "Open the approval center only when Guard pauses a new or changed artifact.",
        },
    ]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


__all__ = ["DEFAULT_ALIAS_NAME", "build_guard_bootstrap_payload"]
