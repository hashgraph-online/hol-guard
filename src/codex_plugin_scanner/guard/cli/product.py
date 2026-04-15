"""Guard product-facing onboarding and status payloads."""

from __future__ import annotations

from datetime import datetime, timezone
from urllib.parse import urlparse

from ..adapters import get_adapter
from ..adapters.base import HarnessContext
from ..config import GuardConfig
from ..consumer import detect_all, evaluate_detection
from ..daemon import load_guard_daemon_url
from ..models import HarnessDetection
from ..store import GuardStore

HARNESS_PRIORITY = ("codex", "claude-code", "copilot", "cursor", "antigravity", "gemini", "opencode")
GUARD_COMMAND = "hol-guard"
GUARD_DASHBOARD_URL = "https://hol.org/guard"
GUARD_CONNECT_URL = f"{GUARD_DASHBOARD_URL}/connect"


def build_guard_start_payload(
    context: HarnessContext,
    store: GuardStore,
    config: GuardConfig,
) -> dict[str, object]:
    """Build a first-run Guard onboarding payload."""

    return _build_guard_product_payload(context, store, config, include_steps=True)


def build_guard_status_payload(
    context: HarnessContext,
    store: GuardStore,
    config: GuardConfig,
) -> dict[str, object]:
    """Build an ongoing Guard status payload."""

    return _build_guard_product_payload(context, store, config, include_steps=False)


def build_guard_connect_payload(
    context: HarnessContext,
    store: GuardStore,
    config: GuardConfig,
    *,
    credentials_saved: bool = False,
    sync_attempted: bool = False,
    sync_succeeded: bool = False,
    sync_error: str | None = None,
) -> dict[str, object]:
    """Build a pairing-aware Guard connect payload."""

    payload = _build_guard_product_payload(context, store, config, include_steps=False)
    payload.update(
        {
            "credentials_saved": credentials_saved,
            "sync_attempted": sync_attempted,
            "sync_succeeded": sync_succeeded,
            "sync_error": sync_error,
        }
    )
    payload["next_steps"] = _build_connect_steps(payload)
    return payload


def _build_guard_product_payload(
    context: HarnessContext,
    store: GuardStore,
    config: GuardConfig,
    *,
    include_steps: bool,
) -> dict[str, object]:
    detections = detect_all(context)
    harnesses = [_summarize_harness(detection, store, config) for detection in detections]
    recommended = _recommended_harness(harnesses)
    receipt_count = store.count_receipts()
    managed_harnesses = sum(1 for item in harnesses if item["managed"] is True)
    runtime_state = store.get_runtime_state()
    approval_center_url = load_guard_daemon_url(context.guard_home)
    payload: dict[str, object] = {
        "generated_at": _now(),
        "guard_home": str(context.guard_home),
        "workspace": str(context.workspace_dir) if context.workspace_dir is not None else None,
        "sync_configured": store.get_sync_credentials() is not None,
        "receipt_count": receipt_count,
        "pending_approvals": store.count_approval_requests(),
        "approval_center_url": approval_center_url,
        "runtime_state": runtime_state,
        "runtime_status": _resolve_runtime_status(runtime_state, approval_center_url),
        "managed_harnesses": managed_harnesses,
        "recommended_harness": recommended["harness"] if recommended is not None else None,
        "harnesses": harnesses,
    }
    payload.update(_build_cloud_context(store))
    if include_steps:
        payload["next_steps"] = _build_next_steps(recommended, payload)
    return payload


def _summarize_harness(
    detection: HarnessDetection,
    store: GuardStore,
    config: GuardConfig,
) -> dict[str, object]:
    evaluation = evaluate_detection(detection, store, config, default_action="allow", persist=False)
    approval_flow = get_adapter(detection.harness).approval_flow()
    managed_install = store.get_managed_install(detection.harness)
    review_count = sum(1 for artifact in evaluation["artifacts"] if bool(artifact["changed"]))
    managed = bool(managed_install and managed_install.get("active"))
    shim_path = None
    if managed_install is not None:
        manifest = managed_install.get("manifest")
        if isinstance(manifest, dict):
            shim_path = manifest.get("shim_path")
    next_action = _resolve_next_action(detection, managed, review_count)
    return {
        "harness": detection.harness,
        "installed": detection.installed,
        "command_available": detection.command_available,
        "artifact_count": len(detection.artifacts),
        "review_count": review_count,
        "warning_count": len(detection.warnings),
        "managed": managed,
        "shim_path": str(shim_path) if isinstance(shim_path, str) else None,
        "config_paths": list(detection.config_paths),
        "next_action": next_action,
        "install_command": f"{GUARD_COMMAND} install {detection.harness}",
        "run_command": f"{GUARD_COMMAND} run {detection.harness} --dry-run",
        "review_command": f"{GUARD_COMMAND} diff {detection.harness}",
        "receipts_command": f"{GUARD_COMMAND} receipts",
        "approval_flow": approval_flow,
    }


def _recommended_harness(harnesses: list[dict[str, object]]) -> dict[str, object] | None:
    if not harnesses:
        return None
    priority = {name: index for index, name in enumerate(HARNESS_PRIORITY)}
    return min(
        harnesses,
        key=lambda item: (
            0 if bool(item["installed"]) else 1,
            0 if bool(item["command_available"]) else 1,
            priority.get(str(item["harness"]), len(HARNESS_PRIORITY)),
        ),
    )


def _resolve_next_action(detection: HarnessDetection, managed: bool, review_count: int) -> str:
    if not managed:
        if not detection.installed and not detection.command_available:
            return "install-harness"
        return "install"
    if review_count > 0:
        return "review"
    return "run"


def _build_next_steps(recommended: dict[str, object] | None, payload: dict[str, object]) -> list[dict[str, str]]:
    if recommended is None:
        return [
            {
                "title": "Install a supported harness",
                "command": f"{GUARD_COMMAND} detect",
                "detail": (
                    "Guard did not find a local harness config yet. Start by installing "
                    "Codex, Claude Code, Copilot CLI, Cursor, Antigravity, Gemini, or OpenCode."
                ),
            }
        ]
    steps = [_install_or_review_step(recommended), _run_step(recommended), _receipts_step()]
    steps.append(_approvals_step())
    steps.append(
        _connect_or_dashboard_step(
            str(payload.get("cloud_state") or "local_only"),
            str(payload.get("connect_url") or GUARD_CONNECT_URL),
            str(payload.get("dashboard_url") or GUARD_DASHBOARD_URL),
        )
    )
    return steps


def _resolve_runtime_status(runtime_state: dict[str, object] | None, approval_center_url: str | None) -> str:
    if approval_center_url:
        return "active"
    if runtime_state is not None:
        return "stale"
    return "offline"


def _build_cloud_context(store: GuardStore) -> dict[str, object]:
    credentials = store.get_sync_credentials()
    sync_url = credentials["sync_url"] if credentials is not None else None
    dashboard_url, connect_url = _resolve_guard_urls(sync_url)
    advisories = store.list_cached_advisories(limit=3)
    alert_preferences = _coerce_payload_dict(store.get_sync_payload("alert_preferences"))
    remote_policy = _coerce_payload_dict(store.get_sync_payload("policy"))
    team_policy_pack = _coerce_payload_dict(store.get_sync_payload("team_policy_pack"))
    sync_summary = _coerce_payload_dict(store.get_sync_payload("sync_summary"))
    last_sync_at = _optional_string(sync_summary.get("synced_at"))
    remote_payload_active = bool(advisories or alert_preferences or remote_policy or team_policy_pack)
    cloud_state = _resolve_cloud_state(
        sync_configured=credentials is not None,
        sync_completed=bool(sync_summary),
        remote_payload_active=remote_payload_active,
    )
    return {
        "cloud_state": cloud_state,
        "cloud_state_label": _cloud_state_label(cloud_state),
        "cloud_state_detail": _cloud_state_detail(cloud_state, connect_url, dashboard_url),
        "sync_url": sync_url,
        "dashboard_url": dashboard_url,
        "connect_url": connect_url,
        "connect_command": f"{GUARD_COMMAND} connect --sync-url <url> --token <token>",
        "sync_command": f"{GUARD_COMMAND} sync",
        "last_sync_at": last_sync_at,
        "advisory_count": len(advisories),
        "advisory_headline": _advisory_headline(advisories),
        "remote_policy_active": bool(remote_policy),
        "alert_preferences_active": bool(alert_preferences),
        "watchlist_enabled": bool(alert_preferences.get("watchlistEnabled")),
        "team_alerts_enabled": bool(alert_preferences.get("teamAlertsEnabled")),
        "team_policy_active": bool(team_policy_pack),
        "team_policy_name": _optional_string(team_policy_pack.get("name")),
        "team_policy_updated_at": _optional_string(team_policy_pack.get("updatedAt")),
    }


def _build_connect_steps(payload: dict[str, object]) -> list[dict[str, str]]:
    cloud_state = str(payload.get("cloud_state") or "local_only")
    recommended = _recommended_summary(payload)
    dashboard_url = str(payload.get("dashboard_url") or GUARD_DASHBOARD_URL)
    connect_url = str(payload.get("connect_url") or GUARD_CONNECT_URL)
    steps: list[dict[str, str]]
    if cloud_state == "local_only":
        steps = [
            {
                "title": "Generate a Guard Cloud token",
                "command": connect_url,
                "detail": (
                    "Open the Guard connect page, copy the sync URL and short-lived token, then pair this runtime."
                ),
            },
            {
                "title": "Pair this runtime",
                "command": str(
                    payload.get("connect_command") or f"{GUARD_COMMAND} connect --sync-url <url> --token <token>"
                ),
                "detail": (
                    "Save the credentials locally and pull down the first Guard Cloud policy bundle in one step."
                ),
            },
        ]
        if recommended is not None:
            steps.append(_run_step(recommended))
        return steps
    if cloud_state == "paired_waiting":
        steps = [
            {
                "title": "Pull the first cloud sync",
                "command": str(payload.get("sync_command") or f"{GUARD_COMMAND} sync"),
                "detail": (
                    "Finish the first sync so this machine has Guard Cloud history, advisories, and team defaults."
                ),
            }
        ]
        if int(payload.get("receipt_count") or 0) == 0 and recommended is not None:
            steps.append(_run_step(recommended))
        steps.append(
            {
                "title": "Open the Guard dashboard",
                "command": dashboard_url,
                "detail": "Use the signed-in dashboard to confirm pairing and watch your first device appear.",
            }
        )
        return steps
    steps = [
        {
            "title": "Open the Guard dashboard",
            "command": dashboard_url,
            "detail": "Review receipts, devices, changes, and upgrade prompts from the signed-in command center.",
        }
    ]
    if int(payload.get("pending_approvals") or 0) > 0:
        steps.append(_approvals_step())
    elif recommended is not None and str(recommended.get("next_action")) == "review":
        steps.append(_install_or_review_step(recommended))
    else:
        steps.append(
            {
                "title": "Check local Guard status",
                "command": f"{GUARD_COMMAND} status",
                "detail": "See what is protected locally, what synced last, and what Guard thinks you should do next.",
            }
        )
    if bool(payload.get("team_policy_active")):
        steps.append(
            {
                "title": "Inspect synced team policy",
                "command": f"{GUARD_COMMAND} policies",
                "detail": "Confirm the shared workspace policy Guard pulled down for this machine.",
            }
        )
    elif int(payload.get("advisory_count") or 0) > 0:
        steps.append(
            {
                "title": "Review Guard advisories",
                "command": f"{GUARD_COMMAND} advisories",
                "detail": "Inspect the latest premium trust signals and publisher changes Guard cached locally.",
            }
        )
    return steps


def _connect_or_dashboard_step(cloud_state: str, connect_url: str, dashboard_url: str) -> dict[str, str]:
    if cloud_state == "local_only":
        return {
            "title": "Optional sync later",
            "command": connect_url,
            "detail": (
                "Keep receipts local by default, then use the Guard connect page when you want "
                "shared history, trust checks, or team policy."
            ),
        }
    return {
        "title": "Open the Guard dashboard",
        "command": dashboard_url,
        "detail": "Guard Cloud is already paired. Use the signed-in dashboard for devices, receipts, and upgrades.",
    }


def _recommended_summary(payload: dict[str, object]) -> dict[str, object] | None:
    recommended_harness = payload.get("recommended_harness")
    if not isinstance(recommended_harness, str):
        return None
    for harness in payload.get("harnesses", []):
        if isinstance(harness, dict) and harness.get("harness") == recommended_harness:
            return harness
    return None


def _resolve_guard_urls(sync_url: str | None) -> tuple[str, str]:
    if not isinstance(sync_url, str) or not sync_url:
        return GUARD_DASHBOARD_URL, GUARD_CONNECT_URL
    parsed = urlparse(sync_url)
    if not parsed.scheme or not parsed.netloc:
        return GUARD_DASHBOARD_URL, GUARD_CONNECT_URL
    origin = f"{parsed.scheme}://{parsed.netloc}"
    return f"{origin}/guard", f"{origin}/guard/connect"


def _resolve_cloud_state(*, sync_configured: bool, sync_completed: bool, remote_payload_active: bool) -> str:
    if not sync_configured:
        return "local_only"
    if not sync_completed and not remote_payload_active:
        return "paired_waiting"
    return "paired_active"


def _cloud_state_label(cloud_state: str) -> str:
    labels = {
        "local_only": "Local only",
        "paired_waiting": "Connected, waiting for first sync",
        "paired_active": "Connected and active",
    }
    return labels.get(cloud_state, "Local only")


def _cloud_state_detail(cloud_state: str, connect_url: str, dashboard_url: str) -> str:
    if cloud_state == "paired_waiting":
        return (
            "Guard Cloud credentials are saved, but this machine has not finished a full sync yet. "
            f"Run `{GUARD_COMMAND} sync` or reopen {connect_url} to finish the pairing loop."
        )
    if cloud_state == "paired_active":
        return (
            "Guard is paired with Guard Cloud. Use the local CLI for protection and the signed-in dashboard "
            f"at {dashboard_url} for receipts, devices, upgrades, and team workflows."
        )
    return (
        "Receipts stay on this machine until you choose to pair Guard Cloud. "
        f"Start from {connect_url} when you want shared history, trust advisories, or team policy."
    )


def _coerce_payload_dict(payload: dict[str, object] | list[object] | None) -> dict[str, object]:
    return payload if isinstance(payload, dict) else {}


def _advisory_headline(advisories: list[dict[str, object]]) -> str | None:
    if not advisories:
        return None
    headline = advisories[0].get("headline")
    return headline if isinstance(headline, str) and headline else None


def _optional_string(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _install_or_review_step(recommended: dict[str, object]) -> dict[str, str]:
    harness = str(recommended["harness"])
    next_action = str(recommended["next_action"])
    if next_action == "review":
        return {
            "title": f"Review changed {harness} tools",
            "command": str(recommended["review_command"]),
            "detail": "Guard found changes since the last approval. Review them before the next launch.",
        }
    if next_action == "install-harness":
        return {
            "title": f"Install {harness}",
            "command": f"{GUARD_COMMAND} detect",
            "detail": "Guard needs a local harness install before it can protect launches.",
        }
    return {
        "title": f"Install Guard for {harness}",
        "command": str(recommended["install_command"]),
        "detail": "Create a local launcher shim so Guard runs before the harness starts.",
    }


def _run_step(recommended: dict[str, object]) -> dict[str, str]:
    harness = str(recommended["harness"])
    return {
        "title": "Run Guard before launch",
        "command": str(recommended["run_command"]),
        "detail": f"Dry-run {harness} once so Guard records the current tool state before you rely on it.",
    }


def _receipts_step() -> dict[str, str]:
    return {
        "title": "Inspect receipts",
        "command": f"{GUARD_COMMAND} receipts",
        "detail": "See what Guard approved, blocked, or flagged after local runs.",
    }


def _approvals_step() -> dict[str, str]:
    return {
        "title": "Resolve queued approvals",
        "command": f"{GUARD_COMMAND} approvals",
        "detail": "Use the local approval center or the approvals queue when a harness session cannot prompt inline.",
    }


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


__all__ = ["build_guard_connect_payload", "build_guard_start_payload", "build_guard_status_payload"]
