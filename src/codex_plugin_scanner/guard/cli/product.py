"""Guard product-facing onboarding and status payloads.

The store reads and harness detection stay here; the native runtime
(`guard_product_copy`) decides the next actions, the recommended harness, the
runtime status, the Guard Cloud copy and URLs and the next steps.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..adapters import get_adapter
from ..adapters.base import HarnessContext, _artifact_uses_guard
from ..config import GuardConfig
from ..consumer import detect_all
from ..daemon.runtime_peer import load_guard_daemon_endpoint_url
from ..models import HarnessDetection
from ..redaction import redact_local_path
from ..runtime.connector_setup_items import connector_setup_status
from ..store import GuardStore
from ..synced_policy import synced_policy_bundle_validation
from .connect_flow import (
    CONNECT_COMMAND,
    CONNECT_REPAIR_COMMAND,
    CONNECT_STATUS_COMMAND,
    connect_recovery_command,
    connect_retry_refresh_race_from_state,
    connect_retry_required_from_state,
    connect_state_requires_oauth,
    normalize_connect_state_for_missing_oauth,
    resolve_guard_cloud_state,
)
from .status_review_count import count_review_artifacts

_LOGGER = logging.getLogger(__name__)
GUARD_COMMAND = "hol-guard"
_PRODUCT_COPY_UNAVAILABLE = (
    "Guard could not load its status copy from the native runtime. Run `hol-guard doctor` to repair it."
)
_HARNESS_COPY_FIELDS = ("next_action", "install_command", "run_command", "review_command", "receipts_command")
_URL_FIELDS = ("dashboard_url", "inbox_url", "fleet_url", "connect_url")


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
    *,
    scan_installed_apps: bool = True,
) -> dict[str, object]:
    """Build an ongoing Guard status payload."""

    return _build_guard_product_payload(
        context,
        store,
        config,
        include_steps=False,
        scan_installed_apps=scan_installed_apps,
    )


def _build_guard_product_payload(
    context: HarnessContext,
    store: GuardStore,
    config: GuardConfig,
    *,
    include_steps: bool,
    scan_installed_apps: bool = True,
) -> dict[str, object]:
    if scan_installed_apps:
        detections = detect_all(context)
        facts = [_summarize_harness(detection, store, context.home_dir) for detection in detections]
    else:
        facts = _harnesses_from_managed_installs(store, context.home_dir)
    receipt_count = store.count_receipts()
    runtime_state = store.get_runtime_state()
    approval_center_url = load_guard_daemon_endpoint_url(context.guard_home)
    cloud_facts, cloud_context = _build_cloud_context(store)
    copy = _product_copy(
        context,
        facts,
        cloud_facts,
        approval_center_url=approval_center_url,
        runtime_state_present=runtime_state is not None,
        include_steps=include_steps,
    )
    harnesses = [_with_copy(item, item_copy) for item, item_copy in zip(facts, copy["harnesses"], strict=True)]
    recommended = copy["recommended"]
    managed_harnesses = sum(1 for item in harnesses if item["managed"] is True)
    from ..harness_posture import harness_posture_summary
    from ..protection_coverage import protection_is_in_effect
    from ..protection_posture import protection_status_fields

    payload: dict[str, object] = {
        "generated_at": _now(),
        **protection_status_fields(posture=config.protection_posture, mode=config.mode),
        # The posture alone cannot tell a reader whether anything is registered
        # to apply it, so state that separately rather than leaving it implied.
        "protection_in_effect": protection_is_in_effect(harnesses),
        **harness_posture_summary(config),
        "guard_home": _redacted_path(context.guard_home, context.home_dir),
        "workspace": _redacted_path(context.workspace_dir, context.home_dir),
        "sync_configured": store.get_cloud_sync_profile() is not None,
        "oauth_storage_health": store.get_oauth_local_credential_health(),
        "receipt_count": receipt_count,
        "pending_approvals": store.count_approval_requests(),
        "approval_center_url": approval_center_url,
        "runtime_state": runtime_state,
        "runtime_status": copy["runtime_status"],
        "managed_harnesses": managed_harnesses,
        "recommended_harness": harnesses[recommended]["harness"] if isinstance(recommended, int) else None,
        "harnesses": harnesses,
        "connector_setup": connector_setup_status(store, approval_center_url),
        "cloud_state": cloud_facts["cloud_state"],
        "cloud_state_label": copy["cloud_state_label"],
        "cloud_state_detail": copy["cloud_state_detail"],
        "sync_url": cloud_facts["sync_url"],
        **{field: copy[field] for field in _URL_FIELDS},
        **cloud_context,
    }
    if include_steps:
        payload["next_steps"] = copy["next_steps"]
    return payload


def _product_copy(
    context: HarnessContext,
    facts: list[dict[str, object]],
    cloud_facts: dict[str, Any],
    *,
    approval_center_url: str | None,
    runtime_state_present: bool,
    include_steps: bool,
) -> dict[str, Any]:
    """Ask the native runtime for the product copy.

    The copy is display only, so an unavailable runtime reports it as
    unavailable rather than guessing the next action.
    """
    from ..native_runner_authority import NativeRunnerAuthorityError, native_runner_authority

    reply: object = None
    try:
        reply = native_runner_authority(
            "guard_product_copy",
            {
                "harnesses": [
                    {
                        "harness": item["harness"],
                        "installed": item["installed"],
                        "command_available": item["command_available"],
                        "managed": item["managed"],
                        "scanned": item["artifacts_scanned"],
                        "artifact_count": item["artifact_count"],
                        "review_count": item["review_count"],
                        "warning_count": item["warning_count"],
                        "approval_flow": item["approval_flow"],
                    }
                    for item in facts
                ],
                **cloud_facts,
                "approval_center_url": approval_center_url,
                "runtime_state_present": runtime_state_present,
                "include_steps": include_steps,
            },
            guard_home=context.guard_home,
        )
    except NativeRunnerAuthorityError as error:
        _LOGGER.debug("guard product copy unavailable: %s", error)
    if isinstance(reply, dict):
        copies = reply.get("harnesses")
        if isinstance(copies, list) and len(copies) == len(facts) and all(isinstance(item, dict) for item in copies):
            return reply
    return {
        "harnesses": [dict.fromkeys(_HARNESS_COPY_FIELDS) for _ in facts],
        "recommended": None,
        "runtime_status": "unavailable",
        "cloud_state_label": "Status unavailable",
        "cloud_state_detail": _PRODUCT_COPY_UNAVAILABLE,
        **dict.fromkeys(_URL_FIELDS),
        "next_steps": [
            {"title": "Repair Guard", "command": f"{GUARD_COMMAND} doctor", "detail": _PRODUCT_COPY_UNAVAILABLE}
        ],
    }


def _with_copy(item: dict[str, object], item_copy: dict[str, Any]) -> dict[str, object]:
    summary = {key: value for key, value in item.items() if key != "approval_flow"}
    summary.update((field, item_copy.get(field)) for field in _HARNESS_COPY_FIELDS)
    summary["approval_flow"] = item["approval_flow"]
    return summary


def _summarize_harness(
    detection: HarnessDetection,
    store: GuardStore,
    home_dir: Path,
) -> dict[str, object]:
    managed_install = store.get_managed_install(detection.harness)
    approval_flow = get_adapter(detection.harness).approval_flow(managed_install=managed_install)
    review_count = count_review_artifacts(store, detection.artifacts, detection.harness)
    managed = bool(managed_install and managed_install.get("active"))
    guard_registered = any(_artifact_uses_guard(artifact) for artifact in detection.artifacts)
    shim_path = None
    if managed_install is not None:
        manifest = managed_install.get("manifest")
        if isinstance(manifest, dict):
            shim_path = manifest.get("shim_path")
    return {
        "harness": detection.harness,
        "installed": detection.installed,
        "command_available": detection.command_available,
        "artifact_count": len(detection.artifacts),
        "artifacts_scanned": True,
        "guard_registered": guard_registered,
        "review_count": review_count,
        "warning_count": len(detection.warnings),
        "managed": managed,
        "shim_path": _redacted_path(shim_path, home_dir) if isinstance(shim_path, str) else None,
        "config_paths": [_redacted_path(config_path, home_dir) for config_path in detection.config_paths],
        "approval_flow": approval_flow,
    }


def _harnesses_from_managed_installs(store: GuardStore, home_dir: Path) -> list[dict[str, object]]:
    summaries: list[dict[str, object]] = []
    for install in store.list_managed_installs():
        summary = _summarize_managed_install(install, home_dir)
        if summary is not None:
            summaries.append(summary)
    return summaries


def _summarize_managed_install(install: dict[str, object], home_dir: Path) -> dict[str, object] | None:
    harness = str(install.get("harness") or "").strip()
    if not harness:
        return None
    try:
        adapter = get_adapter(harness)
    except ValueError:
        return None
    managed = bool(install.get("active"))
    manifest = install.get("manifest")
    shim_path = manifest.get("shim_path") if isinstance(manifest, dict) else None
    approval_flow = adapter.approval_flow(managed_install=install)
    warning_count = _managed_install_warning_count(
        managed=managed,
        manifest=manifest if isinstance(manifest, dict) else None,
    )
    return {
        "harness": harness,
        "installed": managed,
        "command_available": managed,
        "artifact_count": 0,
        "artifacts_scanned": False,
        "review_count": 0,
        "warning_count": warning_count,
        "managed": managed,
        "shim_path": _redacted_path(shim_path, home_dir) if isinstance(shim_path, str) else None,
        "config_paths": [],
        "approval_flow": approval_flow,
    }


def _managed_install_warning_count(*, managed: bool, manifest: dict[str, object] | None) -> int:
    if not managed or manifest is None:
        return 0
    missing = 0
    for key in (
        "shim_path",
        "windows_shim_path",
        "shim_dir",
        "config_path",
        "managed_config_path",
        "runtime_config_path",
        "root_path",
        "settings_path",
    ):
        candidate = manifest.get(key)
        if not isinstance(candidate, str) or not candidate.strip():
            continue
        if not Path(candidate).expanduser().exists():
            missing += 1
    return missing


def _redacted_path(path: str | Path | None, home_dir: Path) -> str | None:
    if path is None:
        return None
    return redact_local_path(str(path), home_dir=home_dir)


def _build_cloud_context(store: GuardStore) -> tuple[dict[str, Any], dict[str, object]]:
    """Read the Guard Cloud facts the native copy needs and the rest of the cloud context."""
    cloud_profile = store.get_cloud_sync_profile()
    oauth_storage_health = store.get_oauth_local_credential_health()
    oauth_repair_required = (
        bool(oauth_storage_health.get("configured")) and oauth_storage_health.get("state") == "degraded"
    )
    sync_url = cloud_profile["sync_url"] if cloud_profile is not None else None
    advisories = store.list_cached_advisories(limit=3)
    alert_preferences = _coerce_payload_dict(store.get_sync_payload("alert_preferences"))
    policy_bundle, cached_policy_bundle_error = synced_policy_bundle_validation(store)
    policy_bundle = policy_bundle or {}
    policy_defaults = policy_bundle.get("policyDefaults")
    remote_policy = _coerce_payload_dict(policy_defaults if isinstance(policy_defaults, dict) else None)
    policy_bundle_last_error = _coerce_payload_dict(store.get_sync_payload("policy_bundle_last_error"))
    headless_sync_summary = _coerce_payload_dict(store.get_sync_payload("headless_app_sync_summary"))
    cloud_review_sync_state = _coerce_payload_dict(store.get_sync_payload("guard_cloud_review_sync_state"))
    cloud_auth_expired = (
        policy_bundle_last_error.get("reason") == "auth_expired"
        or headless_sync_summary.get("status") == "auth_expired"
        or cloud_review_sync_state.get("state") == "auth_expired"
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
    connect_retry_required = connect_retry_required_from_state(latest_connect_state)
    remote_payload_active = bool(advisories or alert_preferences or remote_policy)
    cloud_state = resolve_guard_cloud_state(
        sync_configured=cloud_profile is not None,
        sync_completed=bool(sync_summary),
        remote_payload_active=remote_payload_active,
        oauth_repair_required=oauth_repair_required,
        connect_retry_required=connect_retry_required,
    )
    facts: dict[str, Any] = {
        "cloud_state": cloud_state,
        "sync_url": sync_url if isinstance(sync_url, str) else None,
        "oauth_repair_required": oauth_repair_required,
        "connect_retry_required": connect_retry_required,
        "connect_retry_refresh_race": connect_retry_refresh_race_from_state(latest_connect_state),
        "shared_proof_recorded": bool(sync_summary) or remote_payload_active,
    }
    context: dict[str, object] = {
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
    return facts, context


def _coerce_payload_dict(payload: dict[str, object] | list[object] | None) -> dict[str, object]:
    return payload if isinstance(payload, dict) else {}


def _advisory_headline(advisories: list[dict[str, object]]) -> str | None:
    if not advisories:
        return None
    headline = advisories[0].get("headline")
    return headline if isinstance(headline, str) and headline else None


def _optional_string(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


__all__ = ["build_guard_start_payload", "build_guard_status_payload"]
