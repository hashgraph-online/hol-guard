"""Guard product-facing onboarding and status payloads."""

from __future__ import annotations

from pathlib import Path

from ..adapters import get_adapter
from ..adapters.base import HarnessContext
from ..config import GuardConfig
from ..consumer import detect_all
from ..consumer.service import diff_artifact
from ..daemon.runtime_peer import load_guard_daemon_endpoint_url
from ..models import GuardArtifact, HarnessDetection
from ..redaction import redact_local_path
from ..store import GuardStore
from .connect_flow import _int_payload_value
from .product_cloud import (
    GUARD_COMMAND,
    GUARD_CONNECT_URL,
    GUARD_DASHBOARD_URL,
    _approvals_step,
    _build_cloud_context,
    _build_connect_steps,
    _connect_or_dashboard_step,
    _install_or_review_step,
    _now,
    _receipts_step,
    _run_step,
)

HARNESS_PRIORITY = ("codex", "claude-code", "copilot", "hermes", "cursor", "antigravity", "gemini", "opencode")


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
    scan_installed_apps: bool = True,
) -> dict[str, object]:
    if scan_installed_apps:
        detections = detect_all(context)
        harnesses = [_summarize_harness(detection, store, config, context.home_dir) for detection in detections]
    else:
        harnesses = _harnesses_from_managed_installs(store, context.home_dir)
    recommended = _recommended_harness(harnesses)
    receipt_count = store.count_receipts()
    managed_harnesses = sum(1 for item in harnesses if item["managed"] is True)
    runtime_state = store.get_runtime_state()
    approval_center_url = load_guard_daemon_endpoint_url(context.guard_home)
    from ..protection_posture import protection_status_fields

    payload: dict[str, object] = {
        "generated_at": _now(),
        **protection_status_fields(posture=config.protection_posture, mode=config.mode),
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
        "review_count": 0,
        "warning_count": warning_count,
        "managed": managed,
        "shim_path": _redacted_path(shim_path, home_dir) if isinstance(shim_path, str) else None,
        "config_paths": [],
        "next_action": "run" if managed and warning_count == 0 else "install" if not managed else "review",
        "install_command": f"{GUARD_COMMAND} install {harness}",
        "run_command": f"{GUARD_COMMAND} run {harness} --dry-run",
        "review_command": f"{GUARD_COMMAND} diff {harness}",
        "receipts_command": f"{GUARD_COMMAND} receipts",
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


__all__ = ["build_guard_connect_payload", "build_guard_start_payload", "build_guard_status_payload"]
