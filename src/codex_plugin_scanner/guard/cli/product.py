"""Guard product-facing onboarding and status payloads."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from ..adapters import get_adapter
from ..adapters.base import HarnessContext
from ..config import GuardConfig
from ..consumer import detect_all
from ..consumer.service import diff_artifact
from ..daemon import load_guard_daemon_url
from ..models import GuardArtifact, HarnessDetection
from ..redaction import redact_local_path
from ..store import GuardStore
from ..synced_policy import synced_policy_bundle_validation
from .connect_flow import (
    CONNECT_COMMAND,
    CONNECT_REPAIR_COMMAND,
    CONNECT_STATUS_COMMAND,
    _int_payload_value,
    connect_recovery_command,
    connect_retry_refresh_race_from_reason,
    connect_state_requires_oauth,
    normalize_connect_state_for_missing_oauth,
    resolve_guard_cloud_repair_detail,
    resolve_guard_cloud_state,
)

HARNESS_PRIORITY = ("codex", "claude-code", "copilot", "hermes", "cursor", "antigravity", "gemini", "opencode")
GUARD_COMMAND = "hol-guard"
GUARD_DASHBOARD_URL = "https://hol.org/guard"
GUARD_CONNECT_URL = f"{GUARD_DASHBOARD_URL}/connect"
GUARD_INBOX_URL = f"{GUARD_DASHBOARD_URL}/inbox"
GUARD_FLEET_URL = f"{GUARD_DASHBOARD_URL}/protect"


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
    harnesses = [_summarize_harness(detection, store, config, context.home_dir) for detection in detections]
    recommended = _recommended_harness(harnesses)
    receipt_count = store.count_receipts()
    managed_harnesses = sum(1 for item in harnesses if item["managed"] is True)
    runtime_state = store.get_runtime_state()
    approval_center_url = load_guard_daemon_url(context.guard_home)
    payload: dict[str, object] = {
        "generated_at": _now(),
        "guard_home": _redacted_path(context.guard_home, context.home_dir),
        "workspace": _redacted_path(context.workspace_dir, context.home_dir),
        "sync_configured": store.get_cloud_sync_profile() is not None,
        "oauth_storage_health": store.get_oauth_local_credential_health(),
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
    home_dir: Path,
) -> dict[str, object]:
    managed_install = store.get_managed_install(detection.harness)
    approval_flow = get_adapter(detection.harness).approval_flow(managed_install=managed_install)
    review_count = _count_review_artifacts(store, detection.artifacts, detection.harness)
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
        "shim_path": _redacted_path(shim_path, home_dir) if isinstance(shim_path, str) else None,
        "config_paths": [_redacted_path(config_path, home_dir) for config_path in detection.config_paths],
        "next_action": next_action,
        "install_command": f"{GUARD_COMMAND} install {detection.harness}",
        "run_command": f"{GUARD_COMMAND} run {detection.harness} --dry-run",
        "review_command": f"{GUARD_COMMAND} diff {detection.harness}",
        "receipts_command": f"{GUARD_COMMAND} receipts",
        "approval_flow": approval_flow,
    }


def _count_review_artifacts(store: GuardStore, artifacts: tuple[GuardArtifact, ...], harness: str) -> int:
    previous_snapshots = store.list_snapshots(harness)
    return sum(
        1
        for artifact in artifacts
        if bool(diff_artifact(previous_snapshots.get(artifact.artifact_id), artifact)["changed"])
    )


def _redacted_path(path: str | Path | None, home_dir: Path) -> str | None:
    if path is None:
        return None
    return redact_local_path(str(path), home_dir=home_dir)


def _recommended_harness(harnesses: list[dict[str, object]]) -> dict[str, object] | None:
    if not harnesses:
        return None
    priority = {name: index for index, name in enumerate(HARNESS_PRIORITY)}
    return min(
        harnesses,
        key=lambda item: (
            0 if bool(item["installed"]) else 1,
            0 if _int_payload_value(item, "artifact_count", 0) > 0 else 1,
            _approval_experience_rank(item.get("approval_flow")),
            priority.get(str(item["harness"]), len(HARNESS_PRIORITY)),
            0 if bool(item["command_available"]) else 1,
        ),
    )


def _approval_experience_rank(flow: object) -> int:
    if not isinstance(flow, dict):
        return 4
    prompt_channel = str(flow.get("prompt_channel") or "browser")
    tier = str(flow.get("tier") or "approval-center")
    auto_open_browser = bool(flow.get("auto_open_browser", True))
    if prompt_channel in {"native", "hook"} and tier in {"native-harness", "native-or-center", "mixed"}:
        return 0
    if prompt_channel in {"native", "hook"} and not auto_open_browser:
        return 1
    if not auto_open_browser:
        return 2
    if tier == "approval-center":
        return 3
    return 4


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
                    "Codex, Claude Code, Copilot CLI, Hermes, Cursor, Antigravity, Gemini, or OpenCode."
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
    cloud_profile = store.get_cloud_sync_profile()
    oauth_storage_health = store.get_oauth_local_credential_health()
    oauth_repair_required = (
        bool(oauth_storage_health.get("configured")) and oauth_storage_health.get("state") == "degraded"
    )
    sync_url = cloud_profile["sync_url"] if cloud_profile is not None else None
    dashboard_url, connect_url, inbox_url, fleet_url = _resolve_guard_urls(sync_url)
    advisories = store.list_cached_advisories(limit=3)
    alert_preferences = _coerce_payload_dict(store.get_sync_payload("alert_preferences"))
    policy_bundle, cached_policy_bundle_error = synced_policy_bundle_validation(store)
    policy_bundle = policy_bundle or {}
    policy_defaults = policy_bundle.get("policyDefaults")
    remote_policy = _coerce_payload_dict(policy_defaults if isinstance(policy_defaults, dict) else None)
    policy_bundle_last_error = _coerce_payload_dict(store.get_sync_payload("policy_bundle_last_error"))
    headless_sync_summary = _coerce_payload_dict(store.get_sync_payload("headless_app_sync_summary"))
    live_request_sync_state = _coerce_payload_dict(store.get_sync_payload("guard_live_request_sync_state"))
    cloud_auth_expired = (
        policy_bundle_last_error.get("reason") == "auth_expired"
        or headless_sync_summary.get("status") == "auth_expired"
        or live_request_sync_state.get("state") == "auth_expired"
    )
    oauth_repair_required = oauth_repair_required or cloud_auth_expired
    sync_summary = _coerce_payload_dict(store.get_sync_payload("sync_summary"))
    last_sync_at = _optional_string(sync_summary.get("synced_at"))
    effective_connect_state = store.get_effective_guard_connect_state(now=_now())
    latest_connect_state = normalize_connect_state_for_missing_oauth(
        latest_state=effective_connect_state,
        oauth_storage_health=oauth_storage_health,
        oauth_required=connect_state_requires_oauth(
            latest_state=effective_connect_state,
            cloud_profile=cloud_profile,
        ),
    )
    connect_retry_required = _connect_retry_required(latest_connect_state)
    connect_retry_refresh_race = _connect_retry_refresh_race(latest_connect_state)
    remote_payload_active = bool(advisories or alert_preferences or remote_policy)
    cloud_state = resolve_guard_cloud_state(
        sync_configured=cloud_profile is not None,
        sync_completed=bool(sync_summary),
        remote_payload_active=remote_payload_active,
        oauth_repair_required=oauth_repair_required,
        connect_retry_required=connect_retry_required,
    )
    return {
        "cloud_state": cloud_state,
        "cloud_state_label": _cloud_state_label(cloud_state),
        "cloud_state_detail": _cloud_state_detail(
            cloud_state,
            connect_url,
            dashboard_url,
            oauth_repair_required=oauth_repair_required,
            connect_retry_required=connect_retry_required,
            connect_retry_refresh_race=connect_retry_refresh_race,
            shared_proof_recorded=bool(sync_summary) or remote_payload_active,
        ),
        "sync_url": sync_url,
        "dashboard_url": dashboard_url,
        "inbox_url": inbox_url,
        "fleet_url": fleet_url,
        "connect_url": connect_url,
        "connect_command": CONNECT_COMMAND,
        "connect_status_command": CONNECT_STATUS_COMMAND,
        "connect_repair_command": CONNECT_REPAIR_COMMAND,
        "connect_recovery_command": connect_recovery_command(latest_connect_state),
        "latest_connect_state": latest_connect_state,
        "sync_command": f"{GUARD_COMMAND} sync",
        "last_sync_at": last_sync_at,
        "advisory_count": len(advisories),
        "advisory_headline": _advisory_headline(advisories),
        "remote_policy_active": bool(remote_policy),
        "cloud_policy_bundle_hash": _optional_string(policy_bundle.get("bundleHash")),
        "cloud_policy_bundle_version": _optional_string(policy_bundle.get("bundleVersion")),
        "cloud_policy_rollout_state": _optional_string(policy_bundle.get("rolloutState")),
        "cloud_policy_sync_error": cached_policy_bundle_error
        or _optional_string(policy_bundle_last_error.get("reason")),
        "alert_preferences_active": bool(alert_preferences),
        "watchlist_enabled": bool(alert_preferences.get("watchlistEnabled")),
        "team_alerts_enabled": bool(alert_preferences.get("teamAlertsEnabled")),
        "team_policy_active": False,
        "team_policy_name": None,
        "team_policy_updated_at": None,
    }


def _build_connect_steps(payload: dict[str, object]) -> list[dict[str, str]]:
    cloud_state = str(payload.get("cloud_state") or "local_only")
    recommended = _recommended_summary(payload)
    dashboard_url = str(payload.get("dashboard_url") or GUARD_DASHBOARD_URL)
    connect_url = str(payload.get("connect_url") or GUARD_CONNECT_URL)
    inbox_url = str(payload.get("inbox_url") or GUARD_INBOX_URL)
    fleet_url = str(payload.get("fleet_url") or GUARD_FLEET_URL)
    steps: list[dict[str, str]]
    if cloud_state == "local_only":
        steps = [
            {
                "title": "Run Guard connect",
                "command": str(payload.get("connect_command") or f"{GUARD_COMMAND} connect"),
                "detail": (
                    "Start the local pairing flow, open the browser automatically, and wait for Guard Cloud to pair "
                    "this machine."
                ),
            },
            {
                "title": "Complete browser sign-in",
                "command": connect_url,
                "detail": (
                    "Sign in on the Guard connect page if prompted. Guard will resume and run the first sync once the "
                    "browser pairing finishes."
                ),
            },
        ]
        if recommended is not None:
            steps.append(_run_step(recommended))
        steps.append(
            {
                "title": "Open Guard Home",
                "command": dashboard_url,
                "detail": (
                    "Home stays useful before sync is on. Use it to watch this machine "
                    "and decide when shared memory becomes worth it."
                ),
            }
        )
        return steps
    if cloud_state == "paired_waiting":
        steps = [
            {
                "title": "Finish the first cloud sync",
                "command": str(payload.get("sync_command") or f"{GUARD_COMMAND} sync"),
                "detail": (
                    "Keep Local Guard running so it can finish the first cloud sync automatically. "
                    "Use the sync command only when you want to force the retry now."
                ),
            }
        ]
        if _int_payload_value(payload, "receipt_count", 0) == 0 and recommended is not None:
            steps.append(_run_step(recommended))
        steps.append(
            {
                "title": "Open Guard Fleet",
                "command": fleet_url,
                "detail": (
                    "Fleet is the fastest place to confirm the connected machine while "
                    "the first shared proof is still warming up."
                ),
            }
        )
        return steps
    if _int_payload_value(payload, "pending_approvals", 0) > 0:
        steps = [
            {
                "title": "Open Guard Inbox",
                "command": inbox_url,
                "detail": "Inbox is the fastest place to resolve live review pressure after this machine connects.",
            },
            _approvals_step(),
        ]
    elif recommended is not None and str(recommended.get("next_action")) == "review":
        steps = [
            {
                "title": "Open Guard Inbox",
                "command": inbox_url,
                "detail": (
                    "Guard already sees review pressure. Start in Inbox, then drop back "
                    "to the local approval center only when needed."
                ),
            },
            _install_or_review_step(recommended),
        ]
    else:
        steps = [
            {
                "title": "Check local Guard status",
                "command": f"{GUARD_COMMAND} status",
                "detail": "Review local protection health, recent sync, and Guard's recommended next step.",
            }
        ]
    steps.insert(
        0,
        {
            "title": "Open Guard Home",
            "command": dashboard_url,
            "detail": "Review Home, Inbox, Fleet, Evidence, and upgrade prompts from the signed-in command center.",
        },
    )
    if bool(payload.get("team_policy_active")):
        steps.append(
            {
                "title": "Inspect synced team policy",
                "command": f"{GUARD_COMMAND} policies",
                "detail": "Confirm the shared workspace policy Guard pulled down for this machine.",
            }
        )
    elif _int_payload_value(payload, "advisory_count", 0) > 0:
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
            "title": "Optional cloud connect",
            "command": f"{GUARD_COMMAND} connect",
            "detail": (
                "Keep local protection free by default, then run one command when you want shared inbox state, "
                "fleet continuity, evidence, or team policy."
            ),
        }
    return {
        "title": "Open Guard Home",
        "command": dashboard_url,
        "detail": (
            "Guard Cloud is already paired. Use the signed-in command center for Home, Fleet, Evidence, and upgrades."
        ),
    }


def _recommended_summary(payload: dict[str, object]) -> dict[str, object] | None:
    recommended_harness = payload.get("recommended_harness")
    if not isinstance(recommended_harness, str):
        return None
    harnesses = payload.get("harnesses")
    for harness in harnesses if isinstance(harnesses, list) else []:
        if isinstance(harness, dict) and harness.get("harness") == recommended_harness:
            return harness
    return None


def _resolve_guard_urls(sync_url: str | None) -> tuple[str, str, str, str]:
    if not isinstance(sync_url, str) or not sync_url:
        return GUARD_DASHBOARD_URL, GUARD_CONNECT_URL, GUARD_INBOX_URL, GUARD_FLEET_URL
    parsed = urlparse(sync_url)
    if not parsed.scheme or not parsed.netloc:
        return GUARD_DASHBOARD_URL, GUARD_CONNECT_URL, GUARD_INBOX_URL, GUARD_FLEET_URL
    origin = f"{parsed.scheme}://{parsed.netloc}"
    return (
        f"{origin}/guard",
        f"{origin}/guard/connect",
        f"{origin}/guard/inbox",
        f"{origin}/guard/protect",
    )


def _cloud_state_label(cloud_state: str) -> str:
    labels = {
        "local_only": "Local only",
        "paired_waiting": "Connected, waiting for first sync",
        "paired_active": "Connected and active",
    }
    return labels.get(cloud_state, "Local only")


def _cloud_state_detail(
    cloud_state: str,
    connect_url: str,
    dashboard_url: str,
    *,
    oauth_repair_required: bool = False,
    connect_retry_required: bool = False,
    connect_retry_refresh_race: bool = False,
    shared_proof_recorded: bool = False,
) -> str:
    if oauth_repair_required:
        return (
            "Guard Cloud sign-in on this machine is incomplete. "
            f"Run `{GUARD_COMMAND} connect` or reopen {connect_url} to repair local authorization and resume sync."
        )
    if connect_retry_refresh_race:
        return (
            "Local Guard remains available. The first shared Guard Cloud proof stalled after a refresh-token "
            f"race. Run `{GUARD_COMMAND} connect` or reopen {connect_url} when you want shared proof restored."
        )
    if connect_retry_required:
        return resolve_guard_cloud_repair_detail(
            shared_proof_recorded=shared_proof_recorded,
            first_sync_message=(
                "Guard Cloud connection on this machine needs repair before the first shared proof can land. "
                f"Run `{GUARD_COMMAND} connect` or reopen {connect_url} to repair the first sync."
            ),
            resume_message=(
                "Guard Cloud connection on this machine needs repair before shared proof can resume. "
                f"Run `{GUARD_COMMAND} connect` or reopen {connect_url} to restore sync."
            ),
        )
    if cloud_state == "paired_waiting":
        return (
            "Guard Cloud credentials are saved, but this machine has not finished the first shared sync yet. "
            f"Keep Local Guard running so it can retry automatically, or run "
            f"`{GUARD_COMMAND} sync` to force a retry now."
        )
    if cloud_state == "paired_active":
        return (
            "Guard is paired with Guard Cloud. Use the local CLI for protection and the signed-in command center "
            f"at {dashboard_url} for Home, Inbox, Fleet, Evidence, upgrades, and team workflows."
        )
    return (
        "Receipts stay on this machine until you choose to pair Guard Cloud. "
        f"Run `{GUARD_COMMAND} connect` when you want shared history, trust advisories, or team policy."
    )


def _coerce_payload_dict(payload: dict[str, object] | list[object] | None) -> dict[str, object]:
    return payload if isinstance(payload, dict) else {}


def _connect_retry_required(latest_state: dict[str, object] | None) -> bool:
    if latest_state is None:
        return False
    status = _optional_string(latest_state.get("status"))
    milestone = _optional_string(latest_state.get("milestone"))
    return status == "retry_required" or milestone == "first_sync_failed"


def _connect_retry_refresh_race(latest_state: dict[str, object] | None) -> bool:
    if latest_state is None or not _connect_retry_required(latest_state):
        return False
    return connect_retry_refresh_race_from_reason(_optional_string(latest_state.get("reason")))


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
