"""Versioned, privacy-safe projection consumed by HOL Guard Desktop."""

from __future__ import annotations

import argparse
import importlib.metadata
import json
import sys
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, TextIO

if TYPE_CHECKING:
    from pathlib import Path

    from ..adapters.base import HarnessContext
    from ..config import GuardConfig
    from ..store import GuardStore

from ..dashboard_launcher import build_desktop_dashboard_session_url, desktop_bootstrap_is_preflight
from ._commands_shared import *  # noqa: F403

DESKTOP_BOOTSTRAP_SCHEMA = "guard-desktop-bootstrap.v1"
_MAX_PENDING_APPROVALS = 20
_MAX_RECENT_RECEIPTS = 20

_APP_NAMES = {
    "antigravity": "Antigravity",
    "claude-code": "Claude Code",
    "codex": "Codex",
    "copilot": "GitHub Copilot",
    "cursor": "Cursor",
    "gemini": "Gemini CLI",
    "hermes": "Hermes",
    "opencode": "OpenCode",
}
_EDITOR_HARNESSES = frozenset({"antigravity", "cursor"})
_HOSTED_HARNESSES = frozenset({"hermes"})


def _core_version() -> str:
    try:
        return importlib.metadata.version("hol-guard")
    except importlib.metadata.PackageNotFoundError:
        return "0.0.0+unknown"


def _text(value: object) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _int(value: object, default: int = 0) -> int:
    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return default
    return default


def _bool(value: object) -> bool:
    return value is True


def _harness_kind(harness: str) -> str:
    if harness in _EDITOR_HARNESSES:
        return "editor"
    if harness in _HOSTED_HARNESSES:
        return "hosted"
    return "cli"


def _app_projection(item: dict[str, object], *, runtime_active: bool) -> dict[str, object]:
    harness = _text(item.get("harness")) or "unknown"
    installed = _bool(item.get("installed"))
    command_available = _bool(item.get("command_available"))
    artifact_count = _int(item.get("artifact_count"))
    review_count = _int(item.get("review_count"))
    warning_count = _int(item.get("warning_count"))
    managed = _bool(item.get("managed"))
    detected = installed or command_available or artifact_count > 0

    if managed and not runtime_active:
        protection = "needs_repair"
        detail = "Guard management is installed, but local enforcement is unavailable until the runtime is active."
    elif managed and review_count == 0 and warning_count == 0:
        protection = "protected"
        detail = "Guard management is installed and the latest local check is clean."
    elif managed:
        protection = "needs_repair"
        detail = "Guard management is installed, but the local configuration needs attention."
    elif detected:
        protection = "detected"
        detail = "The app was detected and can be connected to Guard."
    else:
        protection = "not_installed"
        detail = "The app was not detected on this machine."

    return {
        "id": harness,
        "name": _APP_NAMES.get(harness, harness.replace("-", " ").title()),
        "kind": _harness_kind(harness),
        "detected": detected,
        "protection": protection,
        "version": None,
        "lastVerifiedAt": None,
        "detail": detail,
    }


def _risk_projection(request: dict[str, object]) -> str:
    candidates = (
        request.get("risk"),
        request.get("severity"),
        request.get("risk_level"),
        request.get("policy_action"),
    )
    combined = " ".join(value.lower() for value in candidates if isinstance(value, str))
    if "critical" in combined:
        return "critical"
    if "high" in combined or "deny" in combined or "block" in combined:
        return "high"
    if "medium" in combined or "review" in combined or "ask" in combined:
        return "medium"
    return "low"


def _pending_approval_projection(request: dict[str, object]) -> dict[str, object] | None:
    request_id = _text(request.get("request_id")) or _text(request.get("id"))
    if request_id is None:
        return None
    harness = _text(request.get("harness")) or "unknown"
    scope = _text(request.get("recommended_scope")) or "request"
    return {
        "id": request_id,
        "harness": harness,
        "title": f"{_APP_NAMES.get(harness, harness.replace('-', ' ').title())} request",
        "summary": "A protected local action needs your decision.",
        "risk": _risk_projection(request),
        "createdAt": _text(request.get("created_at")),
        "scope": scope,
    }


def _receipt_decision(receipt: dict[str, object]) -> str:
    value = (
        _text(receipt.get("policy_decision"))
        or _text(receipt.get("decision"))
        or _text(receipt.get("action"))
        or "observed"
    ).lower()
    if "block" in value or "deny" in value:
        return "blocked"
    if "allow" in value or "approve" in value:
        return "allowed"
    if "review" in value or "ask" in value or "pending" in value:
        return "review"
    return "observed"


def _receipt_projection(receipt: dict[str, object]) -> dict[str, object] | None:
    receipt_id = _text(receipt.get("receipt_id")) or _text(receipt.get("id"))
    if receipt_id is None:
        return None
    harness = _text(receipt.get("harness")) or "unknown"
    decision = _receipt_decision(receipt)
    return {
        "id": receipt_id,
        "decision": decision,
        "harness": harness,
        "title": f"{_APP_NAMES.get(harness, harness.replace('-', ' ').title())} {decision} decision",
        "summary": f"Local Guard recorded a {decision} decision.",
        "createdAt": _text(receipt.get("timestamp")) or _text(receipt.get("created_at")),
        "verified": True,
    }


def _is_today(value: object, today: str) -> bool:
    return isinstance(value, str) and value.startswith(today)


def _cloud_projection(status_payload: dict[str, object]) -> dict[str, object]:
    state = _text(status_payload.get("cloud_state")) or "local_only"
    last_sync = _text(status_payload.get("last_sync_at"))
    if state == "local_only":
        status = "not_connected"
        detail = "Cloud is optional. Local protection remains available without it."
    elif state == "paired_waiting":
        status = "syncing"
        detail = "Guard Cloud pairing is complete and the first sync is pending."
    elif state in {"connected", "active", "synced"}:
        status = "connected"
        detail = "Guard Cloud is connected."
    else:
        status = "error"
        detail = "Guard Cloud needs attention. Local protection continues independently."
    return {
        "status": status,
        "workspaceName": None,
        "lastSyncAt": last_sync,
        "detail": detail,
    }


def _presentation_projection(config: GuardConfig) -> dict[str, object]:
    from ..presentation_mode import resolve_presentation_mode

    resolved = resolve_presentation_mode(
        local_value=config.presentation_mode,
        local_explicit=config.presentation_mode_explicit,
        local_schema_version=config.presentation_schema_version,
        revision=config.presentation_revision,
        writable=True,
    )
    return {
        "mode": resolved.value,
        "source": resolved.source,
        "explicit": resolved.explicit,
        "canWrite": resolved.writable,
        "schemaVersion": resolved.schema_version,
        "revision": resolved.revision,
        "diagnostic": resolved.diagnostic,
    }


def build_desktop_bootstrap_payload(
    *,
    status_payload: dict[str, object],
    pending_requests: list[dict[str, object]],
    approval_history: list[dict[str, object]],
    receipts: list[dict[str, object]],
    core_version: str,
    oldest_pending_at: str | None = None,
    resolved_today_count: int | None = None,
    receipt_summary: dict[str, object] | None = None,
    presentation: dict[str, object] | None = None,
) -> dict[str, object]:
    runtime_status = _text(status_payload.get("runtime_status")) or "offline"
    runtime_active = runtime_status == "active"
    harness_items = status_payload.get("harnesses")
    harnesses = harness_items if isinstance(harness_items, list) else []
    apps = [_app_projection(item, runtime_active=runtime_active) for item in harnesses if isinstance(item, dict)]

    managed_harnesses = _int(status_payload.get("managed_harnesses"))
    pending_count = _int(status_payload.get("pending_approvals"), len(pending_requests))
    protected_count = sum(1 for app in apps if app["protection"] == "protected")
    needs_repair = any(app["protection"] == "needs_repair" for app in apps)

    if managed_harnesses == 0:
        protection_state = "not_configured"
        protection_detail = "No detected app is currently managed by Guard."
        desktop_status = "setup_required"
        message = "Connect a detected AI app to start local protection."
    elif runtime_status != "active":
        protection_state = "degraded"
        protection_detail = "Guard-managed apps exist, but the local runtime is not active."
        desktop_status = "attention_required"
        message = "Guard is installed, but the local runtime needs attention."
    elif needs_repair or protected_count < managed_harnesses:
        protection_state = "partial"
        protection_detail = "Some Guard-managed apps need repair or verification."
        desktop_status = "attention_required"
        message = "Some protected apps need attention."
    elif pending_count > 0:
        protection_state = "protected"
        protection_detail = "Guard is active and enforcing local policy."
        desktop_status = "attention_required"
        message = "Guard is active. One or more requests need your decision."
    else:
        protection_state = "protected"
        protection_detail = "Guard is active and enforcing local policy."
        desktop_status = "ready"
        message = "Guard is active and this machine is protected."

    pending_projections = [
        projection
        for projection in (_pending_approval_projection(item) for item in pending_requests[:_MAX_PENDING_APPROVALS])
        if projection is not None
    ]
    receipt_projections = [
        projection
        for projection in (_receipt_projection(item) for item in receipts[:_MAX_RECENT_RECEIPTS])
        if projection is not None
    ]

    today = datetime.now(timezone.utc).date().isoformat()
    resolved_today = (
        resolved_today_count
        if isinstance(resolved_today_count, int) and not isinstance(resolved_today_count, bool)
        else sum(
            1
            for item in approval_history
            if _is_today(item.get("resolved_at"), today) and item.get("status") != "pending"
        )
    )
    oldest_pending = oldest_pending_at or min(
        (created for item in pending_requests if (created := _text(item.get("created_at"))) is not None),
        default=None,
    )
    if isinstance(receipt_summary, dict):
        blocked_today = _int(receipt_summary.get("blocked"))
        approved_today = _int(receipt_summary.get("approved"))
        latest_at = _text(receipt_summary.get("latest_at"))
    else:
        blocked_today = sum(
            1
            for item in receipts
            if _receipt_decision(item) == "blocked"
            and _is_today(item.get("timestamp") or item.get("created_at"), today)
        )
        approved_today = sum(
            1
            for item in receipts
            if _receipt_decision(item) == "allowed"
            and _is_today(item.get("timestamp") or item.get("created_at"), today)
        )
        latest_at = next(
            (
                value
                for item in receipts
                if (value := _text(item.get("timestamp")) or _text(item.get("created_at"))) is not None
            ),
            None,
        )

    return {
        "schema": DESKTOP_BOOTSTRAP_SCHEMA,
        "coreVersion": core_version,
        "status": desktop_status,
        "runtimeSource": "adopted_running" if runtime_status == "active" else "external",
        "message": message,
        "daemon": {"running": runtime_status == "active"},
        "protection": {"state": protection_state, "detail": protection_detail},
        "apps": apps,
        "approvals": {
            "pending": pending_count,
            "resolvedToday": resolved_today,
            "oldestPendingAt": oldest_pending,
        },
        "pendingApprovals": pending_projections,
        "receipts": {
            "total": _int(status_payload.get("receipt_count"), len(receipts)),
            "blockedToday": blocked_today,
            "approvedToday": approved_today,
            "latestAt": latest_at,
        },
        "recentReceipts": receipt_projections,
        "cloud": _cloud_projection(status_payload),
        "dashboard": {"available": True, "launchCommandSupported": True},
        "presentation": presentation
        or {
            "mode": "everyday",
            "source": "default",
            "explicit": False,
            "canWrite": False,
            "schemaVersion": 1,
            "revision": 0,
            "diagnostic": "presentation_not_supported_by_core",
        },
    }


def _run_guard_desktop_command(
    args: argparse.Namespace,
    *,
    guard_home: Path | None = None,
    workspace: Path | None = None,
    context: HarnessContext | None = None,
    store: GuardStore | None = None,
    config: GuardConfig | None = None,
    input_text: str | None = None,
    output_stream: TextIO | None = None,
) -> int:
    del workspace, input_text
    if getattr(args, "desktop_command", None) == "dashboard-update":
        from ..daemon.dashboard_update_runner import main as dashboard_update_main

        resolved_home = getattr(args, "guard_home", None) or guard_home
        if resolved_home is None:
            print("Guard dashboard update requires --guard-home.", file=sys.stderr)
            return 2
        argv = [
            "--guard-home",
            str(resolved_home),
            "--daemon-pid",
            str(args.daemon_pid),
            "--daemon-port",
            str(args.daemon_port),
            "--update-token",
            str(args.update_token),
        ]
        if bool(getattr(args, "force_pypi_reinstall", False)):
            argv.append("--force-pypi-reinstall")
        if bool(getattr(args, "alpha", False)):
            argv.append("--alpha")
        return dashboard_update_main(argv)
    desktop_command = getattr(args, "desktop_command", None)
    if desktop_command == "presentation-set":
        if config is None:
            raise RuntimeError("Guard Desktop presentation update requires local Guard config")
        from ..config import update_guard_settings

        resolved_home = getattr(args, "guard_home", None) or guard_home or config.guard_home
        update_payload: dict[str, object] = {
            "presentation_mode": args.mode,
            "presentation_mode_explicit": True,
        }
        if getattr(args, "expected_revision", None) is not None:
            update_payload["presentation_revision"] = args.expected_revision
        updated = update_guard_settings(
            resolved_home,
            update_payload,
            event_source="desktop-presentation",
            skip_approval_gate=True,
        )
        projected = _presentation_projection(updated)
        if bool(getattr(args, "json", False)):
            print(json.dumps(projected, sort_keys=True), file=output_stream or sys.stdout)
        return 0
    if desktop_command != "bootstrap":
        print("Choose desktop bootstrap or presentation-set.", file=sys.stderr)
        return 2
    if context is None or store is None or config is None:
        raise RuntimeError("Guard Desktop bootstrap requires local Guard context")

    resolved_guard_home = guard_home or context.guard_home
    # Start/adopt the matching local runtime before projecting protection.
    # Candidate preflight must not spawn a disposable-home daemon.
    if desktop_bootstrap_is_preflight():
        session_url = None
    else:
        session_url = build_desktop_dashboard_session_url(guard_home=resolved_guard_home)
    status_payload = importlib.import_module(".product", __package__).build_guard_status_payload(
        context,
        store,
        config,
    )
    now = datetime.now(timezone.utc)
    day_start = datetime.combine(now.date(), datetime.min.time(), tzinfo=timezone.utc)
    day_end = day_start + timedelta(days=1)
    day_start_text = day_start.isoformat()
    day_end_text = day_end.isoformat()

    pending_requests = store.list_approval_requests(status="pending", limit=_MAX_PENDING_APPROVALS)
    oldest_pending_at = store.oldest_approval_request_created_at(status="pending")
    resolved_today_count = store.count_approval_requests(
        status="resolved",
        resolved_at_from=day_start_text,
        resolved_at_before=day_end_text,
    )
    receipts = store.list_receipts(limit=_MAX_RECENT_RECEIPTS)
    receipt_summary = store.receipt_summary_between(start_at=day_start_text, before_at=day_end_text)
    payload = build_desktop_bootstrap_payload(
        status_payload=status_payload,
        pending_requests=pending_requests,
        approval_history=[],
        receipts=receipts,
        core_version=_core_version(),
        oldest_pending_at=oldest_pending_at,
        resolved_today_count=resolved_today_count,
        receipt_summary=receipt_summary,
        presentation=_presentation_projection(config),
    )
    dashboard = payload.get("dashboard")
    if isinstance(dashboard, dict):
        if session_url is not None:
            dashboard["sessionUrl"] = session_url
        dashboard["canonical"] = True
    print(json.dumps(payload, sort_keys=True), file=output_stream or sys.stdout)
    return 0


__all__ = [
    "DESKTOP_BOOTSTRAP_SCHEMA",
    "_run_guard_desktop_command",
    "build_desktop_bootstrap_payload",
]
