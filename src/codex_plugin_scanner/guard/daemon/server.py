"""Local Guard daemon helpers."""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import inspect
import io
import json
import mimetypes
import os
import platform
import secrets
import tempfile
import threading
import time
import uuid
import webbrowser
from collections.abc import Mapping
from contextlib import suppress
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, TypedDict, TypeGuard, cast
from urllib.parse import parse_qs, parse_qsl, unquote, urlencode, urlparse, urlunparse

from ...version import __version__
from ..action_lattice import is_guard_action as _is_guard_action
from ..adapters import get_adapter
from ..adapters.base import HarnessContext
from ..aibom_cli import _AIBOM_AUTO_SYNC_INTERVAL_SECONDS, sync_aibom_snapshots_if_due
from ..approval_gate import (
    ApprovalGateError,
    begin_totp_enrollment,
    confirm_totp_enrollment,
    disable_totp,
    require_high_risk,
)
from ..approval_gate import (
    input_from_mapping as approval_gate_input_from_mapping,
)
from ..approval_gate import (
    public_config as approval_gate_public_config,
)
from ..approval_gate import (
    revoke_cooldown as revoke_approval_gate_cooldown,
)
from ..approval_gate import (
    update_settings as update_approval_gate_settings,
)
from ..approval_gate import (
    validate_settings_update as validate_approval_gate_settings,
)
from ..approvals import (
    ApprovalRequestAlreadyResolvedError,
    ApprovalRequestNotFoundError,
    apply_approval_resolution,
    build_approval_browser_url,
    build_runtime_snapshot,
    bulk_allow_read_only_once,
)
from ..cli.connect_flow import (
    CONNECT_SYNC_AUTH_CONTEXT_KEY,
    _build_sync_auth_context,
    _persist_oauth_local_credentials,
    exchange_guard_authorization_code,
    resolve_connect_url,
    resolve_guard_oauth_client_config,
    start_guard_browser_session,
)
from ..cli.install_commands import (
    apply_managed_install,
    build_harness_setup_plan,
    build_harness_verification,
    list_harness_setup_items,
    uninstall_confirmation_token,
)
from ..cli.update_commands import build_guard_update_status_payload
from ..cloud_exception_requests import (
    CloudExceptionRequestError,
    fetch_cloud_exception_requests,
    submit_cloud_exception_request,
)
from ..codex_resume import (
    ResumeNotSupportedError,
    defer_request_resume_to_live_hook,
    get_request_resume_status,
    retry_request_resume,
)
from ..config import (
    GuardConfig,
    editable_guard_settings,
    load_guard_config,
    reset_guard_settings,
    update_guard_settings,
)
from ..desktop_notifications import (
    desktop_notification_setup_payload,
    ensure_desktop_notification_setup,
    macos_notification_guidance,
)
from ..harness_resume import resume_harness_operation, safe_resume_metadata
from ..insights_share import publish_insights_share
from ..local_dashboard_session import LOCAL_DASHBOARD_SESSION_AUDIENCE, build_local_dashboard_session_token
from ..local_supply_chain import (
    build_workspace_audit_payload,
    managed_install_audit_workspace_dirs,
    resolve_package_firewall_entitlement_with_refresh,
    resolve_supply_chain_audit_workspace_dir,
    sync_supply_chain_cloud_state,
)
from ..models import DECISION_SCOPE_VALUES, DecisionScope, PolicyDecision
from ..package_firewall_action_rate_limit import PackageFirewallActionRateLimiter
from ..package_firewall_entitlement import (
    package_firewall_action_states,
    package_firewall_available_actions,
    package_firewall_block_details,
    package_firewall_operation_allowed,
    resolve_package_firewall_entitlement,
)
from ..package_firewall_receipts import package_firewall_receipt_metadata
from ..package_shim_status import record_package_shim_audit_result
from ..policy_bundle_trusted_keys import (
    policy_bundle_keyring_payload,
    validate_synced_policy_bundle,
)
from ..receipts.manager import build_receipt
from ..review_contracts import (
    GuardReviewContractError,
    guard_review_oauth_metadata,
    validate_remote_approval_request_binding,
    validated_remote_approval_envelope,
)
from ..runtime.approval_attention import ApprovalAttentionCoordinator
from ..runtime.live_request_sync import LiveRequestSyncWorker, start_cloud_sync_sync_worker, stop_cloud_sync_sync_worker
from ..runtime.runner import (
    GuardSyncAuthorizationExpiredError,
    GuardSyncNotAvailableError,
    GuardSyncNotConfiguredError,
    _build_policy_bundle_decisions,
    _daemon_version_supported,
    _guard_device_metadata,
    _persist_cloud_exceptions,
    _policy_bundle_acknowledgement_payload,
    _policy_bundle_is_version_downgrade,
    _resolve_guard_sync_auth_context,
    prepare_guard_cloud_connect_authorization,
    repair_guard_cloud_connect_storage,
    sync_local_guard_cloud_proof,
    sync_supply_chain_bundle,
)
from ..runtime.surface_server import GuardSurfaceRuntime
from ..shims import (
    activate_package_shims,
    package_shim_status,
    package_shim_supported_managers,
    probe_package_shim_intercepts,
    uninstall_package_shims,
)
from ..stable_digest import stable_digest_hex
from ..store import GuardStore
from ..store_approvals import InvalidApprovalCursorError
from ..store_evidence import (
    clear_evidence,
    count_evidence,
    evidence_record_to_dict,
    export_evidence_csv,
    export_evidence_json,
    list_evidence,
)
from .command_queue_worker import CommandQueueWorker, start_command_queue_worker, stop_command_queue_worker
from .dashboard_update import merge_dashboard_update_progress, schedule_guard_dashboard_update
from .discovery import (
    DAEMON_DISCOVERY_CHALLENGE_TTL_SECONDS,
    DAEMON_DISCOVERY_PROTOCOL_VERSION,
    authenticated_challenge_payload,
    load_authenticated_daemon_state,
    load_daemon_discovery_key,
)
from .manager import (
    GUARD_DAEMON_COMPATIBILITY_VERSION,
    clear_guard_daemon_state_if_current,
    load_guard_daemon_auth_token,
    repair_approval_center_locator,
    write_guard_daemon_state,
)

_HEADLESS_CLOUD_SYNC_STATE_LOCK = threading.Lock()
_HEADLESS_CLOUD_SYNC_IN_FLIGHT: set[str] = set()
_AUDIT_REMEDIATION_ACTIONS = {"package_shim_path"}
_SUPPLY_CHAIN_PACKAGE_ACTIONS = {
    "activate",
    "install",
    "repair",
    "test",
    "audit",
    "sync",
    "remove",
    "uninstall",
    "connect",
    "open-shell",
}
_SUPPLY_CHAIN_CONNECT_POLL_AFTER_MS = 1_500
_SUPPLY_CHAIN_CONNECT_WAIT_TIMEOUT_SECONDS = 180
_LOCAL_DASHBOARD_SESSION_REFRESH_GRACE_SECONDS = 7 * 24 * 60 * 60
_DEFAULT_HEADLESS_CLOUD_SYNC_INTERVAL_SECONDS = 30.0
_DEFAULT_HEADLESS_CLOUD_SYNC_BACKOFF_SECONDS = 10.0
_AIBOM_REFRESH_STOP_JOIN_TIMEOUT_SECONDS = 5.0


class _HookPathValidationError(ValueError):
    def __init__(self, parameter: str, reason: str) -> None:
        self.parameter = parameter
        self.reason = reason
        parameter_slug = parameter.replace("-", "_")
        super().__init__(f"invalid_hook_{parameter_slug}_path")
        self.code = f"invalid_hook_{parameter_slug}_path"


def _headless_cloud_sync_store_key(store: GuardStore) -> str:
    return str(store.guard_home.expanduser().resolve())


def _build_snapshot_payload(context: HarnessContext) -> dict[str, object]:
    """Return a lightweight snapshot dict including package manager shim coverage."""
    status = package_shim_status(context)
    return {
        "package_manager_coverage": {
            "detected_managers": status.get("detected_managers", []),
            "path_active": status.get("active_managers", []),
            "shims_installed": status.get("active_managers", []),
            "undetected_managers": status.get("undetected_managers", []),
            "unsupported_managers": [],
        }
    }


def _is_decision_scope(value: str) -> TypeGuard[DecisionScope]:
    return value in DECISION_SCOPE_VALUES


def _is_string_object_dict(value: object) -> TypeGuard[dict[str, object]]:
    return isinstance(value, dict) and all(isinstance(key, str) for key in value)


class _CursorReceiptContext(TypedDict):
    action_scope: str
    artifact_name: str
    capabilities_summary: str
    changed_capability: str
    scanner_evidence: dict[str, object]
    source_scope: str
    summary: dict[str, object]


class _GuardDaemonHttpServer(ThreadingHTTPServer):
    store: GuardStore
    runtime: GuardSurfaceRuntime
    auth_token: str
    runtime_host: str
    runtime_session_id: str
    runtime_started_at: str
    idle_timeout_seconds: float | None
    last_activity_monotonic: float
    start_monotonic: float
    active_stream_clients: int
    active_stream_clients_lock: threading.Lock
    package_firewall_connect_state: dict[str, object] | None
    package_firewall_connect_state_lock: threading.Lock
    guard_cloud_connect_state: dict[str, object] | None
    guard_cloud_connect_state_lock: threading.Lock
    guard_cloud_browser_session_lock: threading.Lock
    package_firewall_action_rate_limiter: PackageFirewallActionRateLimiter
    package_firewall_session_nonces: dict[str, float]
    package_firewall_session_nonces_lock: threading.Lock
    approval_attention: ApprovalAttentionCoordinator
    daemon_discovery_challenges: dict[str, dict[str, object]]
    daemon_discovery_challenges_lock: threading.Lock

    def __init__(
        self,
        server_address: tuple[str, int],
        handler_class: type[BaseHTTPRequestHandler],
        *,
        store: GuardStore,
        auth_token: str,
        runtime_host: str,
        runtime_session_id: str,
        runtime_started_at: str,
        idle_timeout_seconds: float | None,
    ) -> None:
        super().__init__(server_address, handler_class)
        self.store = store
        self.runtime = GuardSurfaceRuntime(store)
        self.auth_token = auth_token
        self.runtime_host = runtime_host
        self.runtime_session_id = runtime_session_id
        self.runtime_started_at = runtime_started_at
        self.idle_timeout_seconds = idle_timeout_seconds
        self.last_activity_monotonic = time.monotonic()
        self.start_monotonic = time.monotonic()
        self.active_stream_clients = 0
        self.active_stream_clients_lock = threading.Lock()
        self.package_firewall_connect_state = None
        self.package_firewall_connect_state_lock = threading.Lock()
        self.guard_cloud_connect_state = None
        self.guard_cloud_connect_state_lock = threading.Lock()
        self.guard_cloud_browser_session_lock = threading.Lock()
        self.package_firewall_action_rate_limiter = PackageFirewallActionRateLimiter()
        self.package_firewall_session_nonces = {}
        self.package_firewall_session_nonces_lock = threading.Lock()
        self.daemon_discovery_challenges = {}
        self.daemon_discovery_challenges_lock = threading.Lock()
        from .hook_worker import HookWorker

        self.hook_worker = HookWorker(store=store)
        self.approval_attention = ApprovalAttentionCoordinator(
            store=store,
            runtime=self.runtime,
            opener=webbrowser.open,
        )

    def daemon_host(self) -> str:
        return str(self.server_address[0])

    def daemon_port(self) -> int:
        return int(self.server_address[1])


_STATIC_DIR = Path(__file__).with_name("static")
_INDEX_PATH = _STATIC_DIR / "index.html"
_ENTRY_PATH = _STATIC_DIR / "assets" / "guard-dashboard.js"
_DASHBOARD_CSP = "; ".join(
    (
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self' 'unsafe-inline'",
        "img-src 'self' data: https:",
        "font-src 'self' data:",
        "connect-src 'self'",
        "object-src 'none'",
        "base-uri 'none'",
        "frame-ancestors 'none'",
        "form-action 'self'",
    )
)
_ROOT_STATIC_FILES = {
    "/favicon.svg",
    "/favicon.ico",
    "/favicon-16x16.png",
    "/favicon-32x32.png",
}
_CLAUDE_HOOK_EXECUTION_LOCK = threading.Lock()
_RUNTIME_HOOK_ENV_ALLOWLIST = frozenset(
    {
        "HOL_GUARD_MANAGED_CURSOR_HOOK",
        "HOL_GUARD_CURSOR_APPROVAL_BINDING",
        "HOL_GUARD_CURSOR_AFTER_SHELL_PROOF",
        "CURSOR_PROJECT_DIR",
        "CURSOR_VERSION",
        "CURSOR_TRACE_ID",
        "CURSOR_SESSION_ID",
        "CURSOR_TRANSCRIPT_PATH",
    }
)


def _runtime_hook_env_overlay_from_payload(payload: Mapping[str, object]) -> dict[str, str]:
    raw_overlay = payload.get("hook_env")
    if not isinstance(raw_overlay, Mapping):
        return {}
    overlay: dict[str, str] = {}
    for key, value in raw_overlay.items():
        if not isinstance(key, str) or key not in _RUNTIME_HOOK_ENV_ALLOWLIST:
            continue
        if isinstance(value, str) and value:
            overlay[key] = value
    return overlay


_DEFAULT_GUARD_DAEMON_IDLE_TIMEOUT_SECONDS = 30 * 60
_DEFAULT_SUPPLY_CHAIN_REFRESH_BACKOFF_SECONDS = 60.0
_DEFAULT_SUPPLY_CHAIN_REFRESH_INTERVAL_SECONDS = 15 * 60.0
_EPHEMERAL_GUARD_DAEMON_IDLE_TIMEOUT_SECONDS = 5
_GUARD_DAEMON_IDLE_POLL_INTERVAL_SECONDS = 0.5
_HOSTED_GUARD_DASHBOARD_ORIGINS = frozenset({"https://hol.org", "https://www.hol.org"})
_HEADLESS_APP_ACTIONS = {
    "connect": ("install", "install"),
    "repair": ("repair", "repair"),
    "disconnect": ("remove", "uninstall"),
    "status": ("status", "verify"),
    "test": ("scan", "verify"),
}
_CLOUD_APP_DASHBOARD_SESSION_ACTIONS = {
    "connect": frozenset({"connect", "status", "test"}),
    "repair": frozenset({"repair", "status", "test"}),
    "status": frozenset({"status"}),
    "test": frozenset({"status", "test"}),
}
_HEADLESS_OPERATIONS = ("install", "repair", "remove", "status", "scan", "policy_sync")


def _headless_safe_failure_reasons() -> dict[str, str]:
    return {
        "offline": "Local Guard daemon is unavailable.",
        "timeout": "Local Guard daemon did not answer before the browser timeout.",
        "unauthorized": "Dashboard session is missing or stale.",
        "unsupported": "Harness is not supported by this daemon.",
        "confirmation_required": "Remove actions need the harness confirmation phrase.",
    }


def _supply_chain_package_action_error_response(
    *,
    operation: str,
    error: Exception,
) -> tuple[int, dict[str, object]]:
    if isinstance(error, GuardSyncAuthorizationExpiredError):
        return (
            403,
            {
                "error": "guard_cloud_reconnect_required",
                "message": str(error).strip() or "Guard Cloud authorization expired.",
                "operation": operation,
            },
        )
    if isinstance(error, GuardSyncNotConfiguredError):
        return (
            403,
            {
                "error": "guard_cloud_connect_required",
                "message": str(error).strip() or "Guard Cloud workspace is not connected.",
                "operation": operation,
            },
        )
    if isinstance(error, GuardSyncNotAvailableError):
        payload: dict[str, object] = {
            "error": "supply_chain_sync_unavailable",
            "message": str(error).strip() or "Supply-chain sync is not available on this device.",
            "operation": operation,
        }
        if error.retryable:
            payload["retryable"] = True
        return (503, payload)
    message = str(error).strip() or "Guard supply-chain bundle sync failed."
    return (
        502,
        {
            "error": "supply_chain_sync_failed",
            "message": message,
            "operation": operation,
        },
    )


def _cloud_app_dashboard_session_actions(action_path: str) -> frozenset[str]:
    return _CLOUD_APP_DASHBOARD_SESSION_ACTIONS.get(action_path, frozenset({action_path}))


def _headless_detection_status_to_app_status(value: object) -> str:
    status_map = {
        "protected": "protected",
        "found": "observed",
        "not_found": "inactive",
    }
    return status_map.get(str(value), "unknown")


def _headless_error_payload(
    *,
    code: str,
    message: str,
    retryable: bool,
    detail: str | None = None,
) -> dict[str, object]:
    error_payload: dict[str, object] = {
        "code": code,
        "message": message,
        "retryable": retryable,
    }
    if detail:
        error_payload["detail"] = detail
    payload: dict[str, object] = {
        "status": "failed",
        "error": error_payload,
    }
    return payload


def _headless_action_error_payload(
    *,
    operation: str,
    error_code: str,
) -> tuple[int, dict[str, object]]:
    error_details = {
        "missing_harness": (
            400,
            "Choose an app before retrying.",
            False,
        ),
        "unknown_harness": (
            404,
            "This app is not supported by local Guard.",
            False,
        ),
        "confirmation_required": (
            409,
            "Disconnect needs the local confirmation phrase before Guard removes protection.",
            False,
        ),
        "unsupported_operation": (
            400,
            "This version of local Guard cannot run the requested app action.",
            False,
        ),
    }
    known_error = error_details.get(error_code)
    if known_error is not None:
        status, message, retryable = known_error
        return status, _headless_error_payload(
            code=error_code,
            message=message,
            retryable=retryable,
        )
    operation_code = "proof_failed" if operation == "scan" else f"{operation}_failed"
    operation_label = "connection check" if operation == "scan" else operation
    return 400, _headless_error_payload(
        code=operation_code,
        message=f"Guard could not finish the {operation_label}.",
        retryable=True,
    )


def _headless_app_status_from_result(*, operation: str, result: dict[str, object]) -> str:
    if operation in {"install", "repair"}:
        managed_install = result.get("managed_install")
        if isinstance(managed_install, dict) and bool(managed_install.get("active")):
            return "protected"
        return "unknown"
    if operation == "remove":
        managed_install = result.get("managed_install")
        if isinstance(managed_install, dict) and managed_install.get("active") is False:
            return "inactive"
        return "unknown"
    verification = result.get("verification")
    if isinstance(verification, dict):
        if bool(verification.get("installed")):
            return "protected"
        if bool(verification.get("command_available")) or bool(verification.get("config_paths")):
            return "observed"
        return "inactive"
    return "unknown"


def _headless_action_state_payload(
    *,
    harness: str,
    operation: str,
    result: dict[str, object],
    receipt: dict[str, object],
) -> dict[str, object]:
    app_status = _headless_app_status_from_result(operation=operation, result=result)
    if operation == "install":
        outcome = "app_connected"
        message = f"{harness} is connected through local Guard."
        proof_status = "pending"
    elif operation == "repair":
        outcome = "app_repaired"
        message = f"{harness} protection was refreshed."
        proof_status = "pending"
    elif operation == "remove":
        outcome = "app_disconnected"
        message = f"{harness} protection was removed."
        proof_status = "not_applicable"
    elif operation == "scan":
        proof_passed = app_status == "protected"
        # Keep protocol values stable for Cloud clients; user-facing copy below avoids jargon.
        outcome = "proof_passed" if proof_passed else "proof_failed"
        message = (
            f"{harness} connection check passed. Guard sees local protection."
            if proof_passed
            else f"{harness} connection check finished, but Guard does not see active local protection yet."
        )
        proof_status = "passed" if proof_passed else "failed"
    else:
        outcome = "status_checked"
        message = f"{harness} status checked."
        proof_status = "not_applicable"
    return {
        "app_status": app_status,
        "message": message,
        "outcome": outcome,
        "proof_status": proof_status,
        "receipt_summary": {
            "id": receipt.get("id"),
            "operation": receipt.get("operation"),
            "status": receipt.get("status"),
            "timestamp": receipt.get("timestamp"),
        },
        "retryable": operation in {"install", "repair", "scan"},
    }


def _run_headless_cloud_sync(
    *,
    store: GuardStore,
) -> dict[str, object]:
    recorded_at = _now()
    summary: dict[str, object]

    def _perform_sync() -> dict[str, object]:
        auth_context = _resolve_guard_sync_auth_context(store)
        sync_payload = _sync_local_guard_cloud_proof_with_optional_auth_context(
            store,
            auth_context,
        )
        supply_chain_payload = _sync_supply_chain_cloud_state_with_optional_auth_context(
            store,
            auth_context,
        )
        latest_state = store.get_latest_guard_connect_state(now=recorded_at) or {}
        request_id = latest_state.get("request_id") if isinstance(latest_state, dict) else None
        store.record_latest_guard_connect_sync_success(
            sync_payload=sync_payload,
            now=recorded_at,
            request_id=request_id if isinstance(request_id, str) and request_id else None,
        )
        return {
            "status": "synced",
            "synced_at": sync_payload.get("synced_at"),
            "receipts_stored": sync_payload.get("receipts_stored", 0),
            "runtime_session_id": sync_payload.get("runtime_session_id"),
            "runtime_session_synced_at": sync_payload.get("runtime_session_synced_at"),
            "runtime_sessions_visible": sync_payload.get("runtime_sessions_visible"),
            "supply_chain": supply_chain_payload,
        }

    def _safe_storage_repair() -> dict[str, object]:
        try:
            return repair_guard_cloud_connect_storage(store)
        except Exception as repair_error:
            return {
                "cleared_stale_sign_in": False,
                "existing_sign_in_valid": False,
                "repaired_storage": False,
                "repair_error": str(repair_error),
            }

    try:
        summary = _perform_sync()
    except GuardSyncAuthorizationExpiredError as error:
        auth_error = error
        repair = _safe_storage_repair()
        if repair.get("existing_sign_in_valid"):
            try:
                summary = _perform_sync()
            except GuardSyncAuthorizationExpiredError as retry_error:
                auth_error = retry_error
            except GuardSyncNotConfiguredError as retry_error:
                store.record_latest_guard_connect_sync_result(
                    status="retry_required",
                    milestone="first_sync_failed",
                    now=recorded_at,
                    reason=str(retry_error),
                )
                summary = {
                    "status": "not_configured",
                    "message": str(retry_error),
                    "authorization_repair": repair,
                }
                store.set_sync_payload("headless_app_sync_summary", summary, recorded_at)
                return summary
            except GuardSyncNotAvailableError as retry_error:
                summary = {
                    "status": "not_available",
                    "message": str(retry_error),
                    "authorization_repair": repair,
                }
                store.set_sync_payload("headless_app_sync_summary", summary, recorded_at)
                return summary
            except Exception as retry_error:
                summary = {
                    "status": "pending",
                    "message": str(retry_error),
                    "authorization_repair": repair,
                }
                store.set_sync_payload("headless_app_sync_summary", summary, recorded_at)
                return summary
            else:
                store.set_sync_payload("headless_app_sync_summary", summary, recorded_at)
                return summary
        store.record_latest_guard_connect_sync_result(
            status="retry_required",
            milestone="first_sync_failed",
            now=recorded_at,
            reason=str(auth_error),
        )
        summary = {
            "status": "auth_expired",
            "message": str(auth_error),
            "authorization_repair": repair,
        }
    except GuardSyncNotConfiguredError as error:
        config_error = error
        repair = _safe_storage_repair()
        if repair.get("existing_sign_in_valid"):
            try:
                summary = _perform_sync()
            except GuardSyncAuthorizationExpiredError as retry_error:
                store.record_latest_guard_connect_sync_result(
                    status="retry_required",
                    milestone="first_sync_failed",
                    now=recorded_at,
                    reason=str(retry_error),
                )
                summary = {
                    "status": "auth_expired",
                    "message": str(retry_error),
                    "authorization_repair": repair,
                }
                store.set_sync_payload("headless_app_sync_summary", summary, recorded_at)
                return summary
            except GuardSyncNotConfiguredError as retry_error:
                config_error = retry_error
            except GuardSyncNotAvailableError as retry_error:
                summary = {
                    "status": "not_available",
                    "message": str(retry_error),
                    "authorization_repair": repair,
                }
                store.set_sync_payload("headless_app_sync_summary", summary, recorded_at)
                return summary
            except Exception as retry_error:
                summary = {
                    "status": "pending",
                    "message": str(retry_error),
                    "authorization_repair": repair,
                }
                store.set_sync_payload("headless_app_sync_summary", summary, recorded_at)
                return summary
            else:
                store.set_sync_payload("headless_app_sync_summary", summary, recorded_at)
                return summary
        store.record_latest_guard_connect_sync_result(
            status="retry_required",
            milestone="first_sync_failed",
            now=recorded_at,
            reason=str(config_error),
        )
        summary = {
            "status": "not_configured",
            "message": str(config_error),
            "authorization_repair": repair,
        }
    except GuardSyncNotAvailableError as error:
        summary = {
            "status": "not_available",
            "message": str(error),
        }
    except Exception as error:
        summary = {
            "status": "pending",
            "message": str(error),
        }
    store.set_sync_payload("headless_app_sync_summary", summary, recorded_at)
    return summary


def _queue_headless_cloud_sync(
    *,
    store: GuardStore,
) -> dict[str, object]:
    if store.get_cloud_sync_profile() is None:
        with suppress(Exception):
            repair_guard_cloud_connect_storage(store)
    if store.get_cloud_sync_profile() is None:
        return {
            "status": "not_configured",
            "message": "Cloud sync is not paired on this machine.",
        }
    store_key = _headless_cloud_sync_store_key(store)
    with _HEADLESS_CLOUD_SYNC_STATE_LOCK:
        if store_key in _HEADLESS_CLOUD_SYNC_IN_FLIGHT:
            return {
                "status": "in_progress",
                "message": "Cloud sync already running.",
            }
        # This probe only short-circuits obviously overlapping cross-process work.
        # sync_local_guard_cloud_proof() still acquires the real cloud sync lock.
        if store.cloud_sync_in_progress():
            return {
                "status": "in_progress",
                "message": "Cloud sync already running.",
            }
        _HEADLESS_CLOUD_SYNC_IN_FLIGHT.add(store_key)

    def _run_and_finalize() -> None:
        try:
            _run_headless_cloud_sync(store=store)
        finally:
            with _HEADLESS_CLOUD_SYNC_STATE_LOCK:
                _HEADLESS_CLOUD_SYNC_IN_FLIGHT.discard(store_key)

    threading.Thread(
        target=_run_and_finalize,
        daemon=True,
        name="guard-headless-app-cloud-sync",
    ).start()
    return {
        "status": "queued",
        "message": "Cloud sync started.",
    }


def _maybe_queue_first_cloud_sync(*, store: GuardStore) -> dict[str, object] | None:
    if store.get_cloud_sync_profile() is None:
        try:
            repair_guard_cloud_connect_storage(store)
        except Exception:
            return None
    if store.get_cloud_sync_profile() is None:
        return None
    oauth_health = store.get_oauth_local_credential_health()
    if bool(oauth_health.get("configured")) and str(oauth_health.get("state") or "") == "degraded":
        try:
            repair_guard_cloud_connect_storage(store)
        except Exception:
            return None
        oauth_health = store.get_oauth_local_credential_health()
        if bool(oauth_health.get("configured")) and str(oauth_health.get("state") or "") == "degraded":
            return None
    latest_state = store.get_effective_guard_connect_state(now=_now())
    if latest_state is None:
        return None
    if str(latest_state.get("status") or "") != "connected":
        return None
    if str(latest_state.get("milestone") or "") != "first_sync_pending":
        return None
    return _queue_headless_cloud_sync(store=store)


def _package_firewall_connect_url(store: GuardStore) -> str:
    profile = store.get_cloud_sync_profile()
    sync_url = profile.get("sync_url") if isinstance(profile, dict) else None
    if isinstance(sync_url, str) and sync_url.strip():
        parsed = urlparse(sync_url)
        if parsed.scheme and parsed.netloc:
            return f"{parsed.scheme}://{parsed.netloc}/guard/connect"
    return "https://hol.org/guard/connect"


def _package_firewall_connect_needs_repair(store: GuardStore, reason: str) -> bool:
    if reason == "guard_cloud_reconnect_required":
        return True
    oauth_health = store.get_oauth_local_credential_health()
    return bool(oauth_health.get("configured"))


def _package_firewall_connect_action_label(reason: str, *, repair_copy: bool = False) -> str:
    if reason == "guard_cloud_reconnect_required" or repair_copy:
        return "Repair Guard Cloud access"
    return "Connect HOL Guard Cloud"


def _copy_package_firewall_connect_state(server: _GuardDaemonHttpServer) -> dict[str, object] | None:
    with server.package_firewall_connect_state_lock:
        current = server.package_firewall_connect_state
        return dict(current) if isinstance(current, dict) else None


def _set_package_firewall_connect_state(server: _GuardDaemonHttpServer, state: dict[str, object] | None) -> None:
    with server.package_firewall_connect_state_lock:
        server.package_firewall_connect_state = dict(state) if isinstance(state, dict) else None


def _guard_cloud_connect_state_is_in_flight(state: dict[str, object] | None) -> TypeGuard[dict[str, object]]:
    return isinstance(state, dict) and str(state.get("state") or "") in {"starting", "running"}


def _begin_package_firewall_connect_state(
    server: _GuardDaemonHttpServer,
    starting_state: dict[str, object],
) -> tuple[bool, dict[str, object]]:
    with server.guard_cloud_browser_session_lock:
        current = _copy_package_firewall_connect_state(server)
        if _guard_cloud_connect_state_is_in_flight(current):
            return False, dict(current)
        current = _copy_guard_cloud_connect_state(server)
        if _guard_cloud_connect_state_is_in_flight(current):
            return False, dict(current)
        _set_package_firewall_connect_state(server, starting_state)
        return True, dict(starting_state)


def _default_package_firewall_connect_flow(
    *,
    store: GuardStore,
    reason: str,
) -> dict[str, object]:
    connect_url = _package_firewall_connect_url(store)
    repair_copy = _package_firewall_connect_needs_repair(store, reason)
    action_label = _package_firewall_connect_action_label(reason, repair_copy=repair_copy)
    if repair_copy:
        title = "Repair Guard Cloud access to restore package firewall"
        detail = (
            "Guard already has package-firewall coverage for this machine, but the local cloud authorization is not "
            "usable right now. Repair it here and Guard will unlock the firewall again."
        )
    else:
        title = "Connect HOL Guard Cloud to enable package firewall"
        detail = (
            "Guard keeps this machine protected locally. Connect HOL Guard Cloud here so the daemon can verify "
            "package-firewall access before it changes package-manager routing."
        )
    return {
        "state": "idle",
        "title": title,
        "detail": detail,
        "action_label": action_label,
        "connect_url": connect_url,
        "authorize_url": None,
        "browser_opened": None,
        "request_id": None,
        "poll_after_ms": None,
    }


def _activate_package_firewall_runtime(context: HarnessContext) -> tuple[int, dict[str, object]]:
    status = package_shim_status(context)
    installed_managers = status.get("installed_managers")
    if not isinstance(installed_managers, list) or not installed_managers:
        return (
            409,
            {
                "error": "activation_requires_installed_shims",
                "message": "Protect a package manager before activating this Guard session.",
            },
        )
    proof = probe_package_shim_intercepts(
        context,
        managers=tuple(str(manager) for manager in installed_managers),
        allow_inactive_path=True,
    )
    if not bool(proof.get("intercept_proved")):
        return (
            409,
            {
                "error": "shim_verification_failed",
                "message": ("Guard could not verify the installed package shim. Repair protection and try again."),
                "package_shims": package_shim_status(context),
                "proof": proof,
            },
        )
    return (
        200,
        {
            "status": "verified",
            "message": "Guard verified the installed package shim. Restart existing AI apps before using it.",
            "package_shims": package_shim_status(context),
            "proof": proof,
        },
    )


def _resolve_package_firewall_connect_flow(
    *,
    server: _GuardDaemonHttpServer,
    entitlement: dict[str, object],
) -> dict[str, object] | None:
    reason = str(entitlement.get("reason") or "").strip().lower()
    if reason not in {"guard_cloud_connect_required", "guard_cloud_reconnect_required"}:
        return None
    package_current = _copy_package_firewall_connect_state(server)
    cloud_current = _copy_guard_cloud_connect_state(server)
    if _guard_cloud_connect_state_is_in_flight(cloud_current):
        current = cloud_current
    elif package_current is not None:
        current = package_current
    else:
        current = cloud_current
    if current is None:
        return _default_package_firewall_connect_flow(store=server.store, reason=reason)
    state = str(current.get("state") or "idle")
    flow = {
        **_default_package_firewall_connect_flow(store=server.store, reason=reason),
        **current,
    }
    if state in {"starting", "running"}:
        flow["title"] = "Finish Guard Cloud sign-in in your browser"
        browser_opened = flow.get("browser_opened") is True
        flow["detail"] = (
            "HOL Guard opened the secure sign-in flow in your browser. Finish sign-in there and this page will "
            "unlock package-firewall controls automatically."
            if browser_opened
            else (
                "HOL Guard is opening the secure sign-in flow in your browser."
                if state == "starting"
                else (
                    "HOL Guard is waiting for browser approval. Open the sign-in page below if your browser did "
                    "not open automatically."
                )
            )
        )
        flow["poll_after_ms"] = _SUPPLY_CHAIN_CONNECT_POLL_AFTER_MS
        return flow
    if state == "failed":
        flow["title"] = "Guard Cloud sign-in needs attention"
        flow["poll_after_ms"] = None
        return flow
    return flow


def _copy_guard_cloud_connect_state(server: _GuardDaemonHttpServer) -> dict[str, object] | None:
    with server.guard_cloud_connect_state_lock:
        current = server.guard_cloud_connect_state
        return dict(current) if isinstance(current, dict) else None


def _set_guard_cloud_connect_state(server: _GuardDaemonHttpServer, state: dict[str, object] | None) -> None:
    with server.guard_cloud_connect_state_lock:
        server.guard_cloud_connect_state = dict(state) if isinstance(state, dict) else None


def _begin_guard_cloud_connect_state(
    server: _GuardDaemonHttpServer,
    starting_state: dict[str, object],
) -> tuple[bool, dict[str, object]]:
    with server.guard_cloud_browser_session_lock:
        current = _copy_guard_cloud_connect_state(server)
        if _guard_cloud_connect_state_is_in_flight(current):
            return False, dict(current)
        current = _copy_package_firewall_connect_state(server)
        if _guard_cloud_connect_state_is_in_flight(current):
            return False, dict(current)
        _set_guard_cloud_connect_state(server, starting_state)
        return True, dict(starting_state)


def _guard_cloud_connect_repair_mode_from_health(oauth_health: dict[str, object]) -> bool:
    return bool(oauth_health.get("configured")) and str(oauth_health.get("state") or "") == "degraded"


def _guard_cloud_connect_repair_mode(store: GuardStore) -> bool:
    return _guard_cloud_connect_repair_mode_from_health(store.get_oauth_local_credential_health())


def _guard_cloud_connect_required_for_insights(store: GuardStore) -> bool:
    oauth_health = store.get_oauth_local_credential_health()
    if _guard_cloud_connect_repair_mode_from_health(oauth_health):
        return True
    if bool(oauth_health.get("configured")) and str(oauth_health.get("state") or "") == "healthy":
        return store.get_cloud_sync_profile() is None
    return True


def _default_guard_cloud_connect_flow(*, store: GuardStore, repair_mode: bool) -> dict[str, object]:
    connect_url = _package_firewall_connect_url(store)
    action_label = "Repair Guard Cloud access" if repair_mode else "Connect Guard Cloud"
    if repair_mode:
        title = "Repair Guard Cloud access to publish insights"
        detail = (
            "Guard Cloud sign-in on this machine needs repair before it can publish a public share link. "
            "Start local connect here and finish approval in your browser."
        )
    else:
        title = "Connect Guard Cloud to publish insights"
        detail = (
            "Guard keeps protecting this machine locally. Connect Guard Cloud here so the daemon can publish "
            "a public share link with preview image support."
        )
    return {
        "state": "idle",
        "title": title,
        "detail": detail,
        "action_label": action_label,
        "connect_url": connect_url,
        "authorize_url": None,
        "browser_opened": None,
        "request_id": None,
        "poll_after_ms": None,
        "purpose": "insights_share",
    }


def _resolve_guard_cloud_connect_flow(*, server: _GuardDaemonHttpServer, store: GuardStore) -> dict[str, object] | None:
    if not _guard_cloud_connect_required_for_insights(store):
        return None
    repair_mode = _guard_cloud_connect_repair_mode(store)
    cloud_current = _copy_guard_cloud_connect_state(server)
    package_current = _copy_package_firewall_connect_state(server)
    current = package_current if _guard_cloud_connect_state_is_in_flight(package_current) else cloud_current
    if current is None:
        return _default_guard_cloud_connect_flow(store=store, repair_mode=repair_mode)
    state = str(current.get("state") or "idle")
    flow = {
        **_default_guard_cloud_connect_flow(store=store, repair_mode=repair_mode),
        **current,
    }
    if state in {"starting", "running"}:
        flow["title"] = "Finish Guard Cloud sign-in in your browser"
        browser_opened = flow.get("browser_opened") is True
        flow["detail"] = (
            "HOL Guard opened the secure sign-in flow in your browser. Finish sign-in there and this modal will "
            "unlock public sharing automatically."
            if browser_opened
            else (
                "HOL Guard is opening the secure sign-in flow in your browser."
                if state == "starting"
                else (
                    "HOL Guard is waiting for browser approval. Open the sign-in page below if your browser did "
                    "not open automatically."
                )
            )
        )
        flow["poll_after_ms"] = _SUPPLY_CHAIN_CONNECT_POLL_AFTER_MS
        return flow
    if state == "failed":
        flow["title"] = "Guard Cloud sign-in needs attention"
        flow["poll_after_ms"] = None
        return flow
    return flow


def _guard_cloud_connect_succeeded(store: GuardStore) -> bool:
    return not _guard_cloud_connect_required_for_insights(store)


def _sync_supply_chain_cloud_state_with_optional_auth_context(
    store: GuardStore,
    auth_context: dict[str, object] | None,
    *,
    workspace_dir: Path | None = None,
) -> dict[str, object]:
    try:
        parameters = inspect.signature(sync_supply_chain_cloud_state).parameters
    except (TypeError, ValueError):
        parameters = {}
    kwargs: dict[str, Any] = {}
    if auth_context is not None and "auth_context" in parameters:
        kwargs["auth_context"] = auth_context
    if workspace_dir is not None and "workspace_dir" in parameters:
        kwargs["workspace_dir"] = workspace_dir
    return sync_supply_chain_cloud_state(store, **kwargs)


def _sync_local_guard_cloud_proof_with_optional_auth_context(
    store: GuardStore,
    auth_context: dict[str, object] | None,
) -> dict[str, object]:
    try:
        parameters = inspect.signature(sync_local_guard_cloud_proof).parameters
    except (TypeError, ValueError):
        parameters = {}
    if auth_context is not None and "auth_context" in parameters:
        return sync_local_guard_cloud_proof(store, auth_context=auth_context)
    return sync_local_guard_cloud_proof(store)


def _finalize_daemon_guard_connect_payload(
    *,
    store: GuardStore,
    connect_url: str,
    payload: dict[str, object],
    now: str,
) -> dict[str, object]:
    sync_auth_context = payload.pop(CONNECT_SYNC_AUTH_CONTEXT_KEY, None)
    resolved_sync_auth_context = sync_auth_context if isinstance(sync_auth_context, dict) else None
    normalized_connect_url, allowed_origin = resolve_connect_url(connect_url)
    sync_url = f"{allowed_origin}/api/guard/receipts/sync"
    dashboard_url = f"{allowed_origin}/guard"
    payload.setdefault("connect_url", normalized_connect_url)
    payload.setdefault("sync_url", sync_url)
    payload.setdefault("dashboard_url", dashboard_url)
    payload.setdefault("inbox_url", f"{dashboard_url}/inbox")
    payload.setdefault("fleet_url", f"{dashboard_url}/protect")
    if str(payload.get("status") or "") != "connected":
        return payload
    store.clear_cloud_sync_state_for_reconnect()
    latest_state = store.record_guard_connect_pairing_completed(
        sync_url=sync_url,
        allowed_origin=allowed_origin,
        now=now,
    )
    payload.update(
        {
            "status": str(latest_state.get("status") or payload.get("status") or "connected"),
            "milestone": str(latest_state.get("milestone") or "first_sync_pending"),
            "completed_at": latest_state.get("completed_at") or now,
            "latest_connect_state": latest_state,
        }
    )
    oauth_health = store.get_oauth_local_credential_health()
    if store.get_cloud_sync_profile() is None and (
        oauth_health.get("state") == "degraded" or not oauth_health.get("configured")
    ):
        repair_message = (
            "Guard Cloud authorization did not persist locally. "
            "Start Guard Cloud connect again to repair local sign-in."
        )
        store.record_latest_guard_connect_sync_result(
            status="retry_required",
            milestone="first_sync_failed",
            now=now,
            reason=repair_message,
        )
        payload.update(
            {
                "status": "retry_required",
                "milestone": "first_sync_failed",
                "sync_succeeded": False,
                "sync_error": repair_message,
                "repair_message": repair_message,
                "latest_connect_state": store.get_effective_guard_connect_state(now=now),
            }
        )
        return payload
    if store.get_cloud_sync_profile() is None:
        payload["sync_attempted"] = False
        return payload
    payload["sync_attempted"] = True
    try:
        sync_payload = sync_local_guard_cloud_proof(
            store,
            auth_context=resolved_sync_auth_context,
        )
    except GuardSyncNotAvailableError as error:
        store.record_latest_guard_connect_sync_result(
            status="connected",
            milestone="sync_not_available",
            now=now,
            reason=str(error),
        )
        payload.update(
            {
                "milestone": "sync_not_available",
                "sync_succeeded": False,
                "sync_error": str(error),
                "repair_message": str(error),
                "latest_connect_state": store.get_latest_guard_connect_state(now=now),
            }
        )
        return payload
    except (GuardSyncAuthorizationExpiredError, GuardSyncNotConfiguredError) as error:
        store.record_latest_guard_connect_sync_result(
            status="retry_required",
            milestone="first_sync_failed",
            now=now,
            reason=str(error),
        )
        payload.update(
            {
                "status": "retry_required",
                "milestone": "first_sync_failed",
                "sync_succeeded": False,
                "sync_error": str(error),
                "repair_message": "Run Guard Cloud connect again to refresh local authorization.",
                "latest_connect_state": store.get_latest_guard_connect_state(now=now),
            }
        )
        return payload
    except (RuntimeError, TimeoutError) as error:
        repair_message = (
            "Guard Cloud pairing finished, but the first proof sync is still pending. Local Guard will retry while "
            "the daemon is running."
        )
        store.record_latest_guard_connect_sync_result(
            status="connected",
            milestone="first_sync_pending",
            now=now,
            reason=str(error),
        )
        payload.update(
            {
                "status": "connected",
                "milestone": "first_sync_pending",
                "sync_succeeded": False,
                "sync_error": str(error),
                "repair_message": repair_message,
                "latest_connect_state": store.get_latest_guard_connect_state(now=now),
            }
        )
        return payload
    latest_state = store.record_latest_guard_connect_sync_success(
        sync_payload=sync_payload,
        now=str(sync_payload.get("synced_at") or now),
        request_id=str(latest_state.get("request_id") or ""),
    )
    payload.update(
        {
            "status": "connected",
            "milestone": "first_sync_succeeded",
            "sync_succeeded": True,
            "sync": sync_payload,
            "last_sync_at": sync_payload.get("synced_at"),
            "latest_connect_state": latest_state or store.get_latest_guard_connect_state(now=now),
        }
    )
    try:
        payload["supply_chain"] = _sync_supply_chain_cloud_state_with_optional_auth_context(
            store,
            resolved_sync_auth_context,
        )
    except (GuardSyncNotConfiguredError, GuardSyncNotAvailableError, RuntimeError) as error:
        payload["supply_chain_error"] = str(error)
    return payload


class _GuardDaemonHandler(BaseHTTPRequestHandler):
    _MAX_BODY_BYTES = 1_000_000
    server: _GuardDaemonHttpServer  # pyright: ignore[reportIncompatibleVariableOverride]

    def do_OPTIONS(self) -> None:
        origin = self._normalize_origin(self.headers.get("Origin"))
        if origin is None:
            self._write_empty(status=400)
            return
        headers = self._cors_headers_for_request(
            allow_methods="GET, POST, DELETE, OPTIONS",
            allow_headers="Authorization, Content-Type, X-Guard-Dashboard-Session, X-Guard-Token",
        )
        if headers is None:
            self._write_empty(status=403)
            return
        self._write_empty(status=200, extra_headers=headers)

    def do_GET(self) -> None:
        store = self.server.store  # type: ignore[attr-defined]
        parsed = urlparse(self.path)
        self._touch_runtime_heartbeat(parsed.path)
        path_parts = [part for part in parsed.path.split("/") if part]
        if not self._origin_is_allowed_for_request(parsed.path, path_parts):
            self._write_json({"error": "forbidden_origin"}, status=403)
            return
        if parsed.path == "/healthz":
            self._write_json(self._public_healthz_payload())
            return
        if parsed.path == "/v1/healthz/details":
            if not self._header_token_is_valid():
                self._write_unauthorized(extra_headers=self._cors_headers_for_request())
                return
            self._write_json(self._detailed_healthz_payload())
            return
        if parsed.path == "/v1/events/stream":
            if self._query_has_guard_token(parsed.query):
                self._record_query_token_rejection()
                self._write_unauthorized(extra_headers=self._cors_headers_for_request())
                return
            if not self._header_token_is_valid():
                self._write_unauthorized(extra_headers=self._cors_headers_for_request())
                return
            self._stream_events(_int_query_value(parsed.query, "cursor"))
            return
        if parsed.path.startswith("/v1/") and not self._header_token_is_valid():
            self._write_unauthorized(extra_headers=self._cors_headers_for_request())
            return
        if parsed.path == "/v1/capabilities":
            self._handle_capabilities()
            return
        if parsed.path == "/v1/sessions":
            self._write_json({"items": store.list_guard_sessions(limit=200)})
            return
        if parsed.path == "/v1/runtime":
            _maybe_queue_first_cloud_sync(store=store)
            config = load_guard_config(store.guard_home)
            include_receipts = self._query_bool(parsed.query, "include_receipts", default=True)
            snapshot = build_runtime_snapshot(
                store=store,
                approval_center_url=(
                    f"http://{self._daemon_server().daemon_host()}:{self._daemon_server().daemon_port()}"
                ),
                active_request_id=self._query_string(parsed.query, "active_request_id"),
                include_items=self._query_bool(parsed.query, "include_items", default=True),
                receipt_limit=25 if include_receipts else 0,
            )
            self._write_json({**snapshot, "security_level": config.security_level})
            return
        if parsed.path == "/v1/harnesses":
            context = self._harness_context({})
            self._write_json({"items": list_harness_setup_items(context, self.server.store)})  # type: ignore[attr-defined]
            return
        if parsed.path == "/v1/supply-chain/package-shims":
            self._handle_supply_chain_package_firewall_status()
            return
        if parsed.path == "/v1/cloud/connect":
            self._handle_guard_cloud_connect_status()
            return
        if parsed.path == "/v1/supply-chain/entitlement":
            self._write_json(self._supply_chain_entitlement())
            return
        if parsed.path == "/v1/supply-chain/bundle":
            self._handle_get_supply_chain_bundle()
            return
        if len(path_parts) == 4 and path_parts[:2] == ["v1", "apps"] and path_parts[3] == "cloud":
            self._handle_cloud_app_handoff(path_parts[2], parsed.query)
            return
        if parsed.path == "/v1/inventory":
            from ..adapters.contracts import HARNESS_CONTRACTS

            inventory_items = store.list_inventory()
            installed_harnesses = {str(item.get("harness", "")) for item in inventory_items}
            contracts_index = {
                c.harness: {
                    "install_aliases": list(c.install_aliases),
                    "event_surfaces": list(c.event_surfaces),
                    "native_approval": c.native_approval,
                    "browser_fallback": c.browser_fallback,
                    "resume_support": c.resume_support,
                    "known_blind_spots": c.known_blind_spots,
                }
                for c in HARNESS_CONTRACTS
            }
            enriched: list[dict[str, object]] = []
            for item in inventory_items:
                harness_name = str(item.get("harness", ""))
                contract = contracts_index.get(harness_name, {})
                enriched.append({**item, "contract": contract})
            uninstalled = [
                {
                    "harness": c.harness,
                    "status": "unknown",
                    "contract": contracts_index[c.harness],
                }
                for c in HARNESS_CONTRACTS
                if c.harness not in installed_harnesses
            ]
            self._write_json({"items": enriched, "available": uninstalled})
            return
        if parsed.path == "/v1/settings/export":
            config = load_guard_config(store.guard_home)
            self._write_json(_settings_export_payload(config))
            return
        if parsed.path == "/v1/settings":
            config = load_guard_config(store.guard_home)
            self._write_json(_settings_response_payload(store.guard_home, editable_guard_settings(config)))
            return
        if parsed.path == "/v1/update/status":
            self._write_json(
                merge_dashboard_update_progress(
                    store.guard_home,
                    build_guard_update_status_payload(),
                )
            )
            return
        if len(path_parts) == 4 and path_parts[:2] == ["v1", "sessions"] and path_parts[3] == "resume":
            self._handle_session_resume(path_parts[2])
            return
        if len(path_parts) == 4 and path_parts[:2] == ["v1", "requests"] and path_parts[3] == "resume":
            if not self._header_token_is_valid():
                self._write_json(
                    {"error": "unauthorized"},
                    status=401,
                    extra_headers=self._cors_headers_for_request(),
                )
                return
            self._handle_request_resume_read(path_parts[2])
            return
        if len(path_parts) == 3 and path_parts[:2] == ["v1", "operations"]:
            operation = store.get_guard_operation(path_parts[2])
            if operation is None:
                self._write_json({"error": "not_found"}, status=404)
                return
            self._write_json(operation)
            return
        if parsed.path == "/v1/events":
            self._write_json({"items": store.list_events_after(_int_query_value(parsed.query, "cursor"), limit=200)})
            return
        if parsed.path == "/v1/requests":
            self._handle_requests_list(parsed.query)
            return
        if parsed.path == "/v1/connect/state":
            self._write_legacy_pairing_disabled()
            return
        if len(path_parts) == 3 and path_parts[:2] == ["v1", "requests"]:
            approval = store.get_approval_request(path_parts[2])
            if approval is None:
                self._write_json(
                    {
                        "error": "not_found",
                        "recovery": {
                            "code": "request_unknown",
                            "title": "This request is no longer waiting.",
                            "body": "The request was either already resolved or expired. You can close this tab.",
                            "queue_url": self._local_queue_url(),
                        },
                    },
                    status=404,
                )
                return
            self._write_json(approval)
            return
        if parsed.path == "/v1/receipts":
            query = parse_qs(parsed.query)
            harness_q = query.get("harness", [None])[-1]
            limit_q = query.get("limit", ["200"])[-1]
            try:
                limit_v = min(max(int(limit_q), 1), 500)
            except (ValueError, TypeError):
                limit_v = 200
            self._write_json(
                {
                    "items": store.list_receipts(
                        limit=limit_v,
                        harness=harness_q if isinstance(harness_q, str) and harness_q else None,
                    )
                }
            )
            return
        if parsed.path == "/v1/receipts/analytics":
            query = parse_qs(parsed.query)
            activity_days_q = query.get("activity_days", ["90"])[-1]
            trend_days_q = query.get("trend_days", ["7"])[-1]
            top_limit_q = query.get("top_limit", ["10"])[-1]
            try:
                activity_days = min(max(int(activity_days_q), 1), 366)
            except (ValueError, TypeError):
                activity_days = 90
            try:
                trend_days = min(max(int(trend_days_q), 1), activity_days)
            except (ValueError, TypeError):
                trend_days = 7
            try:
                top_limit = min(max(int(top_limit_q), 1), 50)
            except (ValueError, TypeError):
                top_limit = 10
            self._write_json(
                store.receipt_analytics(
                    activity_days=activity_days,
                    trend_days=trend_days,
                    top_limit=top_limit,
                )
            )
            return
        if parsed.path == "/v1/receipts/latest":
            query = parse_qs(parsed.query)
            harness = query.get("harness", [None])[-1]
            artifact_id = query.get("artifact_id", [None])[-1]
            if not isinstance(harness, str) or not harness or not isinstance(artifact_id, str) or not artifact_id:
                self._write_json({"error": "missing_receipt_query"}, status=400)
                return
            receipt = store.get_latest_receipt(harness, artifact_id)
            if receipt is None:
                self._write_json({"error": "not_found"}, status=404)
                return
            self._write_json(receipt)
            return
        if len(path_parts) == 3 and path_parts[:2] == ["v1", "receipts"]:
            receipt = store.get_receipt(path_parts[2])
            if receipt is None:
                self._write_json({"error": "not_found"}, status=404)
                return
            self._write_json(receipt)
            return
        if parsed.path == "/v1/policy":
            query = parse_qs(parsed.query)
            harness = query.get("harness", [None])[-1]
            harness_filter = harness if isinstance(harness, str) else None
            self._write_json(
                {
                    "items": store.list_policy_decisions(harness=harness_filter),
                    "cloud_exceptions": store.list_cloud_exceptions(harness=harness_filter),
                }
            )
            return
        if parsed.path == "/v1/policy/cloud-exceptions":
            query = parse_qs(parsed.query)
            harness = query.get("harness", [None])[-1]
            harness_filter = harness if isinstance(harness, str) else None
            self._write_json({"items": store.list_cloud_exceptions(harness=harness_filter)})
            return
        if parsed.path == "/v1/policy/cloud-exception-requests":
            self._handle_cloud_exception_request_list()
            return
        if parsed.path == "/v1/evidence":
            query = parse_qs(parsed.query)
            harness_q = query.get("harness", [None])[-1]
            category_q = query.get("category", [None])[-1]
            severity_q = query.get("severity", [None])[-1]
            before_q = query.get("before", [None])[-1]
            limit_q = query.get("limit", ["100"])[-1]
            try:
                limit_v = min(max(int(limit_q), 1), 500)
            except (ValueError, TypeError):
                limit_v = 100
            with store._connect() as conn:
                records = list_evidence(
                    conn,
                    harness=harness_q if isinstance(harness_q, str) else None,
                    category=category_q if isinstance(category_q, str) else None,
                    severity=severity_q if isinstance(severity_q, str) else None,
                    before_cursor=before_q if isinstance(before_q, str) else None,
                    limit=limit_v,
                    include_details=False,
                )
                total = count_evidence(
                    conn,
                    harness=harness_q if isinstance(harness_q, str) else None,
                    category=category_q if isinstance(category_q, str) else None,
                    severity=severity_q if isinstance(severity_q, str) else None,
                )
            self._write_json(
                {
                    "items": [evidence_record_to_dict(record) for record in records],
                    "total": total,
                }
            )
            return
        if parsed.path == "/v1/evidence/export":
            query = parse_qs(parsed.query)
            format_q = query.get("format", ["json"])[-1]
            with store._connect() as conn:
                if format_q == "json":
                    payload = export_evidence_json(conn, limit=10_000)
                    content_type = "application/json"
                elif format_q == "csv":
                    payload = export_evidence_csv(conn, limit=10_000)
                    content_type = "text/csv; charset=utf-8"
                else:
                    self._write_json({"error": "invalid_export_format"}, status=400)
                    return
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.end_headers()
            self.wfile.write(payload.encode("utf-8"))
            return
        if len(path_parts) == 4 and path_parts[:3] == ["v1", "artifacts", path_parts[2]] and path_parts[3] == "diff":
            query = parse_qs(parsed.query)
            harness = query.get("harness", [None])[-1]
            if not isinstance(harness, str) or not harness:
                self._write_json({"error": "missing_harness"}, status=400)
                return
            diff = store.get_latest_diff(harness, unquote(path_parts[2]))
            if diff is None:
                self._write_json({"error": "not_found"}, status=404)
                return
            self._write_json(diff)
            return
        if parsed.path == "/v1/read-state":
            self._write_json({"ids": store.get_read_state()})
            return
        if parsed.path in _ROOT_STATIC_FILES:
            self._write_static_asset(parsed.path.removeprefix("/"))
            return
        if parsed.path.startswith("/assets/") or parsed.path.startswith("/brand/"):
            self._write_static_asset(parsed.path.removeprefix("/"))
            return
        if self._is_dashboard_route(parsed.path):
            self._write_dashboard_shell()
            return
        self.send_response(404)
        self.end_headers()

    def do_DELETE(self) -> None:
        parsed = urlparse(self.path)
        self._touch_runtime_heartbeat(parsed.path)
        path_parts = [part for part in parsed.path.split("/") if part]
        if not self._origin_is_allowed_for_request(parsed.path, path_parts):
            self._write_json({"error": "forbidden_origin"}, status=403)
            return
        if not self._header_token_is_valid():
            self._write_json(
                {"error": "unauthorized"},
                status=401,
                extra_headers=self._cors_headers_for_request(),
            )
            return
        store = self.server.store  # type: ignore[attr-defined]
        if parsed.path == "/v1/evidence":
            with store._connect() as conn:
                deleted = clear_evidence(conn)
            self._write_json({"deleted": deleted})
            return
        if parsed.path == "/v1/read-state":
            body = self._read_delete_body()
            request_id = body.get("request_id") if body else None
            if isinstance(request_id, str):
                store.mark_request_unread(request_id)
            elif body and body.get("clear_all"):
                store.clear_read_state()
            self._write_json({"ok": True})
            return
        self._write_json({"error": "not_found"}, status=404)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        self._touch_runtime_heartbeat(parsed.path)
        path_parts = [part for part in parsed.path.split("/") if part]
        if parsed.path in {"/v1/connect/requests", "/v1/connect/complete", "/v1/connect/result"}:
            self._write_legacy_pairing_disabled()
            return
        if not self._origin_is_allowed_for_request(parsed.path, path_parts):
            self._write_json({"error": "forbidden_origin"}, status=403)
            return
        payload, body_error = self._load_request_body()
        if body_error is not None:
            self._write_json({"error": body_error}, status=400)
            return
        if parsed.path == "/v1/healthz/verify":
            nonce = self._optional_string(payload.get("nonce")) if payload else None
            if not nonce:
                self._write_json({"error": "missing_nonce"}, status=400)
                return
            auth_token = self.server.auth_token  # type: ignore[attr-defined]
            daemon_port = self.server.server_address[1]  # type: ignore[attr-defined]
            # Bind the proof to this daemon's listening port so a relay attacker
            # cannot proxy the nonce to the real daemon and reuse its proof from
            # a different port. The hook includes the same port in its local HMAC.
            proof_message = f"{daemon_port}:{nonce}"
            proof = hmac.new(
                auth_token.encode("utf-8"),
                proof_message.encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
            self._write_json({"proof": proof})
            return
        if parsed.path == "/v1/daemon/identity-challenge":
            self._handle_daemon_identity_challenge(payload)
            return
        if self._requires_header_token(parsed.path, path_parts) and not self._header_token_is_valid(payload=payload):
            if (
                len(path_parts) == 4
                and path_parts[:2] == ["v1", "requests"]
                and path_parts[3] in {"approve", "block", "resume"}
            ):
                host = self._daemon_server().daemon_host()
                port = self._daemon_server().daemon_port()
                reconnect_url = _build_local_url(host, port, "/#/reconnect")
                self._write_json(
                    {
                        "error": "unauthorized",
                        "recovery": {
                            "code": "session_stale",
                            "title": "Your session with the local Guard daemon has expired.",
                            "body": "Click the link below to reconnect, then retry your approval.",
                            "reconnect_url": reconnect_url,
                        },
                    },
                    status=401,
                    extra_headers=self._cors_headers_for_request(),
                )
            else:
                self._write_unauthorized(extra_headers=self._cors_headers_for_request())
            return
        if parsed.path == "/v1/hooks/codex" and not self._consume_codex_daemon_challenge(payload):
            self._write_json(
                {"error": "daemon_identity_required", "repair": "Run `hol-guard daemon repair`."},
                status=401,
            )
            return
        if parsed.path == "/v1/initialize":
            self._handle_initialize(payload)
            return
        if len(path_parts) == 3 and path_parts[:2] == ["v1", "hooks"]:
            self._handle_runtime_hook(payload, parsed.query, default_harness=path_parts[2])
            return
        if parsed.path == "/v1/clients/attach":
            self._handle_client_attach(payload)
            return
        if parsed.path == "/v1/clients/heartbeat":
            self._handle_client_heartbeat(payload)
            return
        if parsed.path == "/v1/sessions/start":
            self._handle_session_start(payload)
            return
        if parsed.path == "/v1/operations/start":
            self._handle_operation_start(payload)
            return
        if parsed.path == "/v1/operations/block":
            self._handle_operation_block(payload)
            return
        if len(path_parts) == 4 and path_parts[:2] == ["v1", "operations"] and path_parts[3] == "items":
            self._handle_operation_item(path_parts[2], payload)
            return
        if len(path_parts) == 4 and path_parts[:2] == ["v1", "operations"] and path_parts[3] == "status":
            self._handle_operation_status(path_parts[2], payload)
            return
        if parsed.path == "/v1/policy/decisions":
            self._handle_policy_upsert(payload)
            return
        if parsed.path == "/v1/policy/clear":
            self._handle_policy_clear(payload)
            return
        if parsed.path == "/v1/requests/clear":
            self._handle_requests_clear(payload)
            return
        if parsed.path == "/v1/requests/bulk-allow-once":
            self._handle_bulk_allow_read_once(payload)
            return
        if parsed.path == "/v1/policy/sync":
            self._handle_headless_policy_sync(payload)
            return
        if parsed.path == "/v1/policy/cloud-exception-requests":
            self._handle_cloud_exception_request_create(payload)
            return
        if parsed.path == "/v1/requests/remote-once":
            self._handle_headless_remote_once(payload)
            return
        if parsed.path == "/v1/read-state":
            self._handle_read_state_update(payload)
            return
        if parsed.path == "/v1/settings":
            self._handle_settings_update(payload)
            return
        if parsed.path == "/v1/settings/import":
            self._handle_settings_import(payload)
            return
        if parsed.path == "/v1/settings/reset":
            self._handle_settings_reset(payload)
            return
        if parsed.path == "/v1/approval-gate/cooldown/revoke":
            self._handle_approval_gate_cooldown_revoke(payload)
            return
        if parsed.path == "/v1/approval-gate/totp/enroll":
            self._handle_approval_gate_totp_enroll(payload)
            return
        if parsed.path == "/v1/approval-gate/totp/verify":
            self._handle_approval_gate_totp_verify(payload)
            return
        if parsed.path == "/v1/approval-gate/totp/disable":
            self._handle_approval_gate_totp_disable(payload)
            return
        if parsed.path == "/v1/daemon/repair":
            result = repair_approval_center_locator(self.server.store.guard_home)  # type: ignore[attr-defined]
            self._write_json(result)
            return
        if parsed.path == "/v1/insights/share":
            self._handle_insights_share_publish(payload)
            return
        if parsed.path == "/v1/cloud/connect":
            self._handle_guard_cloud_connect_start()
            return
        if parsed.path == "/v1/update":
            force_pypi_reinstall = bool(payload.get("force_pypi_reinstall"))
            status_payload = build_guard_update_status_payload()
            if status_payload.get("python_update_required") is True:
                self._write_json(
                    {
                        "error": "update_not_supported",
                        "message": status_payload.get("blocked_reason")
                        or "Update requires a different Python runtime.",
                    },
                    status=400,
                )
                return
            recovery_reinstall_available = bool(status_payload.get("recovery_reinstall_available"))
            if force_pypi_reinstall and not recovery_reinstall_available:
                self._write_json(
                    {
                        "error": "update_not_supported",
                        "message": status_payload.get("blocked_reason")
                        or "Reinstall is not available for this install.",
                    },
                    status=400,
                )
                return
            if status_payload.get("auto_updatable") is not True and not force_pypi_reinstall:
                self._write_json(
                    {
                        "error": "update_not_supported",
                        "message": status_payload.get("blocked_reason")
                        or "Automatic update is not available for this install.",
                    },
                    status=400,
                )
                return
            if status_payload.get("update_available") is not True and not force_pypi_reinstall:
                self._write_json(
                    {
                        "error": "update_not_available",
                        "message": "Guard is already on the latest version.",
                    },
                    status=400,
                )
                return
            guard_home = self.server.store.guard_home  # type: ignore[attr-defined]
            daemon_pid = os.getpid()
            daemon_port = self._daemon_server().daemon_port()
            self._write_json(
                schedule_guard_dashboard_update(
                    guard_home,
                    daemon_pid=daemon_pid,
                    daemon_port=daemon_port,
                    force_pypi_reinstall=force_pypi_reinstall,
                )
            )
            return
        if parsed.path == "/v1/notifications/setup":
            self._handle_notification_setup(payload)
            return
        if (
            len(path_parts) == 4
            and path_parts[:3] == ["v1", "audit", "remediations"]
            and path_parts[3] in _AUDIT_REMEDIATION_ACTIONS
        ):
            self._handle_audit_remediation(path_parts[3], payload)
            return
        if (
            len(path_parts) == 4
            and path_parts[:3] == ["v1", "supply-chain", "package-shims"]
            and path_parts[3] in _SUPPLY_CHAIN_PACKAGE_ACTIONS
        ):
            self._handle_supply_chain_package_firewall_action(path_parts[3], payload)
            return
        if len(path_parts) == 3 and path_parts[:2] == ["v1", "supply-chain"] and path_parts[2] in {"audit", "sync"}:
            self._handle_supply_chain_package_firewall_action(path_parts[2], payload)
            return
        if len(path_parts) == 4 and path_parts[:2] == ["v1", "harnesses"]:
            self._handle_harness_action(path_parts[2], path_parts[3], payload)
            return
        if len(path_parts) == 5 and path_parts[:2] == ["v1", "apps"] and path_parts[3] == "cloud":
            self._write_legacy_cloud_handoff_disabled()
            return
        if len(path_parts) == 3 and path_parts[:2] == ["v1", "apps"]:
            self._handle_headless_app_action(path_parts[2], payload)
            return
        if len(path_parts) == 4 and path_parts[:2] == ["v1", "requests"] and path_parts[3] == "resume":
            self._handle_request_resume_retry(path_parts[2])
            return
        request_id, action, matched = self._resolve_request_action(path_parts, payload)
        if not matched:
            self.send_response(404)
            self.end_headers()
            return
        if action is None:
            self._write_json({"resolved": False, "error": "missing_required_fields"}, status=400)
            return
        if request_id is None:
            self._write_json({"resolved": False, "error": "missing_required_fields"}, status=400)
            return
        scope = payload.get("scope")
        if not isinstance(scope, str) or not scope.strip():
            self._write_json({"resolved": False, "error": "missing_required_fields"}, status=400)
            return
        try:
            persist_policy = self._approval_persist_policy(payload)
            updated = apply_approval_resolution(
                store=self.server.store,  # type: ignore[attr-defined]
                request_id=request_id,
                action=action,
                scope=scope.strip(),
                workspace=self._optional_string(payload.get("workspace")),
                reason=self._optional_string(payload.get("reason")),
                return_queue_result=True,
                resolve_scope_matches=False,
                approval_gate_input=approval_gate_input_from_mapping(payload),
                persist_policy=persist_policy,
            )
        except ApprovalRequestNotFoundError:
            self._write_json(
                {
                    "resolved": False,
                    "error": "not_found",
                    "recovery": {
                        "code": "request_unknown",
                        "title": "This request is no longer waiting.",
                        "body": "The request was either already resolved or expired. You can close this tab.",
                        "queue_url": self._local_queue_url(),
                    },
                },
                status=404,
            )
            return
        except ApprovalRequestAlreadyResolvedError:
            self._write_json(
                {
                    "resolved": False,
                    "error": "already_resolved",
                    "recovery": {
                        "code": "request_resolved",
                        "title": "This request has already been resolved.",
                        "body": (
                            "If the action is blocked and you believe it should be allowed, "
                            "you can re-submit from your AI assistant."
                        ),
                        "queue_url": self._local_queue_url(),
                    },
                },
                status=409,
            )
            return
        except ApprovalGateError as error:
            self._write_approval_gate_error(error, resolved=False)
            return
        except ValueError as error:
            self._write_json({"resolved": False, "error": str(error)}, status=400)
            return
        normalized_scope = scope.strip()
        item = updated.get("item")
        harness_str = str(item.get("harness", "")) if isinstance(item, dict) else ""
        self.server.store.add_event(  # type: ignore[attr-defined]
            "approval_resolved",
            {"request_id": request_id, "action": action, "scope": normalized_scope, "harness": harness_str},
            _now(),
        )
        harness = str(updated.get("harness", ""))
        copy = _build_resolution_copy(action, harness_str or harness)
        codex_resume = None
        if harness_str == "codex" and action in {"allow", "block"}:
            codex_resume = defer_request_resume_to_live_hook(
                self.server.store,  # type: ignore[attr-defined]
                request_id=request_id,
                action=action,
                now=_now(),
            )
            if codex_resume is None:
                codex_resume = retry_request_resume(
                    self.server.store,  # type: ignore[attr-defined]
                    request_id=request_id,
                    now=_now(),
                )
        if codex_resume is not None:
            updated = self._apply_codex_resume_result(
                updated=updated,
                request_id=request_id,
                action=action,
                copy=copy,
                codex_resume=codex_resume,
            )
            updated_copy = updated.get("copy")
            if _is_string_object_dict(updated_copy):
                title = self._optional_string(updated_copy.get("title")) or copy["title"]
                body = self._optional_string(updated_copy.get("body")) or copy["body"]
                copy = {"title": title, "body": body}
        elif action in {"allow", "block"}:
            harness_resume = resume_harness_operation(
                self.server.store,  # type: ignore[attr-defined]
                request_id=request_id,
                action=action,
                now=_now(),
            )
            if harness_resume is not None:
                updated = self._apply_harness_resume_result(
                    updated=updated,
                    harness_resume=harness_resume,
                )
        updated["copy"] = copy
        updated["retry_hint"] = copy["body"]
        self._write_json(updated)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        return

    def _local_queue_url(self) -> str:
        host = self._daemon_server().daemon_host()
        port = self._daemon_server().daemon_port()
        return _build_local_url(host, port, "/#/inbox")

    def _load_request_body(self) -> tuple[dict[str, object], str | None]:
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0 or length > self._MAX_BODY_BYTES:
            return {}, None
        try:
            raw_body = self.rfile.read(length).decode("utf-8")
        except UnicodeDecodeError:
            return {}, "invalid_request_body"
        content_type = self.headers.get("Content-Type", "")
        if "application/json" in content_type:
            try:
                payload = json.loads(raw_body)
            except json.JSONDecodeError:
                return {}, "invalid_request_body"
            return (payload if isinstance(payload, dict) else {}), None
        form_payload = parse_qs(raw_body)
        return {key: values[-1] for key, values in form_payload.items() if values}, None

    def _handle_capabilities(self) -> None:
        context = self._harness_context({})
        items = list_harness_setup_items(context, self.server.store)  # type: ignore[attr-defined]
        supported = []
        failure_reasons = _headless_safe_failure_reasons()
        for item in items:
            harness = item.get("harness")
            if not isinstance(harness, str):
                continue
            supported.append(
                {
                    "display_name": item.get("display_name"),
                    "harness": harness,
                    "status": _headless_detection_status_to_app_status(item.get("status")),
                    "command_available": bool(item.get("command_available")),
                    "headless_actions": list(_HEADLESS_OPERATIONS[:-1]),
                    "safe_failure_reasons": failure_reasons,
                }
            )
        self._write_json(
            {
                "auth_state": "dashboard_session" if self._dashboard_session_token_is_valid() else "local_token",
                "command_available": any(bool(item.get("command_available")) for item in items),
                "daemon": {
                    "compatibility_version": GUARD_DAEMON_COMPATIBILITY_VERSION,
                    "package_version": __version__,
                    "platform": platform.system().lower() or "unknown",
                },
                "headless_api": {
                    "execution_mode": "guard_cloud_command_queue",
                    "operations": list(_HEADLESS_OPERATIONS),
                },
                "package_firewall_api": {
                    "execution_mode": "guard_cloud_command_queue",
                    "operations": ["status", "connect", "install", "repair", "test", "audit", "sync", "remove"],
                },
                "safe_failure_reasons": _headless_safe_failure_reasons(),
                "supported_harnesses": sorted(item["harness"] for item in supported),
                "items": supported,
            }
        )

    def _latest_cloud_sync_snapshot(self) -> dict[str, object]:
        latest_payload = self.server.store.get_sync_payload("headless_app_sync_summary")  # type: ignore[attr-defined]
        if not isinstance(latest_payload, dict):
            latest_payload = self.server.store.get_sync_payload("sync_summary")  # type: ignore[attr-defined]
        if isinstance(latest_payload, dict):
            return dict(latest_payload)
        return {}

    def _headless_reconnect_payload(
        self,
        *,
        cloud_sync: dict[str, object],
        location_id: str | None,
    ) -> dict[str, object]:
        runtime_summary = self.server.store.get_sync_payload("runtime_session_summary")  # type: ignore[attr-defined]
        runtime = runtime_summary if isinstance(runtime_summary, dict) else {}
        latest_cloud_sync = self._latest_cloud_sync_snapshot()
        cloud_sync_status = self._optional_string(cloud_sync.get("status")) or "unknown"
        if cloud_sync_status in {"queued", "in_progress"}:
            reconciliation_status = cloud_sync_status
        elif cloud_sync_status == "auth_expired":
            reconciliation_status = "auth_expired"
        elif cloud_sync_status == "not_configured":
            reconciliation_status = "not_configured"
        elif cloud_sync_status == "synced":
            reconciliation_status = "synced"
        else:
            reconciliation_status = "pending"
        return {
            "correlation_id": str(uuid.uuid4()),
            "freshness": {
                "last_receipt_sync_at": self._optional_string(latest_cloud_sync.get("synced_at")),
                "last_runtime_sync_at": (
                    self._optional_string(runtime.get("runtime_session_synced_at"))
                    or self._optional_string(runtime.get("synced_at"))
                ),
                "local_guard_online_at": self._optional_string(runtime.get("local_guard_online_at")),
            },
            "latest_cloud_sync": latest_cloud_sync,
            "local_identity": {
                "daemon_id": self._optional_string(runtime.get("runtime_device_id")),
                "daemon_version": __version__,
                "hostname": platform.node() or None,
                "ip_address": None,
                "private_ip_address": None,
                "public_ip_address": None,
            },
            "location_id": location_id,
            "reconciliation_status": reconciliation_status,
        }

    def _headless_app_action_payload(
        self,
        *,
        action_path: str,
        payload: dict[str, object],
    ) -> tuple[int, dict[str, object]]:
        try:
            mapping = _HEADLESS_APP_ACTIONS[action_path]
        except KeyError:
            return _headless_action_error_payload(
                operation=action_path,
                error_code="unsupported_operation",
            )
        operation, harness_action = mapping
        harness = self._optional_string(payload.get("harness"))
        if harness is None:
            return _headless_action_error_payload(
                operation=operation,
                error_code="missing_harness",
            )
        try:
            adapter = get_adapter(harness)
        except ValueError:
            return _headless_action_error_payload(
                operation=operation,
                error_code="unknown_harness",
            )
        try:
            surface = self._cursor_headless_surface(payload) if adapter.harness == "cursor" else None
        except ValueError:
            error_payload = _headless_error_payload(
                code="invalid_cursor_surface",
                message="Choose Cursor editor or CLI before retrying this local action.",
                retryable=False,
            )
            error = error_payload["error"]
            if isinstance(error, dict):
                error["app_id"] = "cursor"
                error["surface"] = self._optional_string(payload.get("surface")) or ""
            return 400, error_payload
        context = self._harness_context(payload)
        try:
            if harness_action == "verify":
                verification_action = "status" if action_path == "status" else "test"
                result = build_harness_verification(
                    adapter.harness,
                    context,
                    self.server.store,  # type: ignore[attr-defined]
                    surface=surface,
                    action=verification_action,
                )
            else:
                result = self._run_headless_managed_action(adapter.harness, harness_action, payload, context)
        except ValueError as error:
            return _headless_action_error_payload(
                operation=operation,
                error_code=str(error),
            )
        location_id = self._optional_string(payload.get("location_id")) or self._optional_string(
            payload.get("locationId")
        )
        receipt = self._record_headless_receipt(
            harness=adapter.harness,
            operation=operation,
            payload=payload,
            result=result,
            location_id=location_id,
            workspace_id=self._optional_string(payload.get("workspace_id")),
            cloud_sync={"status": "pending"},
        )
        cloud_sync = _queue_headless_cloud_sync(store=self.server.store)  # type: ignore[attr-defined]
        receipt["cloud_sync"] = cloud_sync
        return 200, {
            "cloud_sync": cloud_sync,
            "harness": adapter.harness,
            "operation": operation,
            "result": result,
            "receipt": receipt,
            "state": _headless_action_state_payload(
                harness=adapter.harness,
                operation=operation,
                result=result,
                receipt=receipt,
            ),
            "reconnect": self._headless_reconnect_payload(
                cloud_sync=cloud_sync,
                location_id=location_id,
            ),
            "status": "completed",
        }

    def _handle_cloud_app_handoff(self, harness: str, query_string: str) -> None:
        _ = (harness, query_string)
        self._write_legacy_cloud_handoff_disabled()

    def _handle_headless_app_action(self, action_path: str, payload: dict[str, object]) -> None:
        status, payload = self._headless_app_action_payload(action_path=action_path, payload=payload)
        self._write_json(payload, status=status)

    def _run_headless_managed_action(
        self,
        harness: str,
        action: str,
        payload: dict[str, object],
        context: HarnessContext,
    ) -> dict[str, object]:
        surface = self._cursor_headless_surface(payload) if harness == "cursor" else None
        if action == "uninstall":
            expected_confirmation = uninstall_confirmation_token(harness)
            confirmation = self._optional_string(payload.get("confirmation_phrase")) or self._optional_string(
                payload.get("confirmation_token")
            )
            if confirmation != expected_confirmation:
                raise ValueError("confirmation_required")
        install_command = "uninstall" if action == "uninstall" else "install"
        return apply_managed_install(
            install_command,
            harness,
            False,
            context,
            self.server.store,  # type: ignore[attr-defined]
            self._optional_string(payload.get("workspace_id")),
            _now(),
            surface=surface,
        )

    def _handle_headless_policy_sync(self, payload: dict[str, object]) -> None:
        harness = self._optional_string(payload.get("harness"))
        if harness is None:
            self._write_json({"error": "missing_harness"}, status=400)
            return
        try:
            adapter = get_adapter(harness)
        except ValueError:
            self._write_json({"error": "unknown_harness"}, status=404)
            return
        try:
            require_high_risk(
                self.server.store.guard_home,  # type: ignore[attr-defined]
                purpose="policy_write",
                approval_gate_input=approval_gate_input_from_mapping(payload),
            )
        except ApprovalGateError as error:
            self._write_approval_gate_error(error)
            return
        policy_memory = self._policy_memory_payload(payload.get("policy_memory"))
        policy_bundle = self._policy_memory_payload(payload.get("policy_bundle") or payload.get("policyBundle"))
        validated_policy_bundle: dict[str, object] | None = None
        applied_bundle_hash: str | None = None
        applied_bundle_version: str | None = None
        if not policy_memory and not policy_bundle:
            self._write_json({"error": "missing_policy_memory"}, status=400)
            return
        if policy_memory:
            self._write_json({"error": "unsupported_policy_memory_contract"}, status=400)
            return
        if policy_bundle:
            validated_policy_bundle, rejection_reason, trusted_policy_bundle_keys = validate_synced_policy_bundle(
                policy_bundle,
                stored_keyring=self.server.store.get_sync_payload("policy_bundle_keyring"),  # type: ignore[attr-defined]
                sync_payload=payload if isinstance(payload, dict) else None,
                supply_chain_keyring=self.server.store.get_sync_payload("supply_chain_bundle_keyring"),  # type: ignore[attr-defined]
            )
            existing_policy_bundle_payload = self.server.store.get_sync_payload("policy_bundle")  # type: ignore[attr-defined]
            existing_policy_bundle = (
                existing_policy_bundle_payload if isinstance(existing_policy_bundle_payload, dict) else None
            )
            if validated_policy_bundle is None:
                self._write_json({"error": rejection_reason or "invalid_policy_bundle"}, status=400)
                return
            if not _daemon_version_supported(validated_policy_bundle):
                self._write_json({"error": "unsupported_daemon_version"}, status=400)
                return
            if _policy_bundle_is_version_downgrade(existing_policy_bundle, validated_policy_bundle):
                self._write_json({"error": "bundle_version_downgrade"}, status=400)
                return
            applied_at = _now()
            self.server.store.set_sync_payload("policy_bundle", validated_policy_bundle, applied_at)  # type: ignore[attr-defined]
            self.server.store.set_sync_payload("policy_bundle_last_good", validated_policy_bundle, applied_at)  # type: ignore[attr-defined]
            self.server.store.set_sync_payload(  # type: ignore[attr-defined]
                "policy_bundle_keyring",
                policy_bundle_keyring_payload(
                    trusted_policy_bundle_keys,
                    workspace_id=self.server.store.get_cloud_workspace_id(),  # type: ignore[attr-defined]
                ),
                applied_at,
            )
            device_id, device_name = _guard_device_metadata(self.server.store)  # type: ignore[attr-defined]
            self.server.store.set_sync_payload(  # type: ignore[attr-defined]
                "policy_bundle_ack",
                _policy_bundle_acknowledgement_payload(
                    device_id=device_id,
                    device_name=device_name,
                    policy_bundle=validated_policy_bundle,
                    synced_at=applied_at,
                ),
                applied_at,
            )
            existing_remote_decisions = [
                PolicyDecision(
                    harness=str(item["harness"]),
                    scope=scope,
                    action=action,
                    artifact_id=self._optional_string(item.get("artifact_id")),
                    artifact_hash=self._optional_string(item.get("artifact_hash")),
                    workspace=self._optional_string(item.get("workspace")),
                    publisher=self._optional_string(item.get("publisher")),
                    reason=self._optional_string(item.get("reason")),
                    owner=self._optional_string(item.get("owner")),
                    source=str(item.get("source") or "cloud-sync"),
                    expires_at=self._optional_string(item.get("expires_at")),
                )
                for item in self.server.store.list_policy_decisions()  # type: ignore[attr-defined]
                if item.get("source") in {"cloud-sync", "team-policy"}
                if _is_decision_scope(scope := self._optional_string(item.get("scope")) or "")
                if _is_guard_action(action := self._optional_string(item.get("action")) or "")
            ]
            existing_remote_decisions.extend(
                _build_policy_bundle_decisions(
                    validated_policy_bundle,
                    device_id=device_id,
                    device_name=device_name,
                )
            )
            self.server.store.replace_remote_policies(  # type: ignore[attr-defined]
                existing_remote_decisions,
                applied_at,
                remote_write_authorized=True,
            )
            _persist_cloud_exceptions(
                self.server.store,  # type: ignore[attr-defined]
                policy_bundle=validated_policy_bundle,
                now=applied_at,
                device_id=device_id,
            )
            applied_bundle_hash = str(validated_policy_bundle["bundleHash"])
            applied_bundle_version = str(validated_policy_bundle["bundleVersion"])
        self._write_json(
            {
                "bundle_hash": applied_bundle_hash,
                "bundle_version": applied_bundle_version,
                "harness": adapter.harness,
                "operation": "policy_sync",
                "status": "completed",
            }
        )

    def _handle_headless_remote_once(self, payload: dict[str, object]) -> None:
        harness = self._optional_string(payload.get("harness"))
        if harness is None:
            self._write_json({"error": "missing_harness"}, status=400)
            return
        try:
            adapter = get_adapter(harness)
        except ValueError:
            self._write_json({"error": "unknown_harness"}, status=404)
            return
        remote_approval = self._policy_memory_payload(
            payload.get("remoteApproval")
            or payload.get("remote_approval")
            or payload.get("remote_once")
            or payload.get("remoteOnce")
        )
        if not remote_approval:
            self._write_json({"error": "missing_remote_approval"}, status=400)
            return
        try:
            envelope = validated_remote_approval_envelope(
                remote_approval,
                store=self.server.store,  # type: ignore[attr-defined]
            )
            oauth = guard_review_oauth_metadata(self.server.store)  # type: ignore[attr-defined]
        except GuardReviewContractError as error:
            self._write_json({"error": str(error)}, status=400)
            return
        request_id = self._coalesce_string(envelope, "localRequestId", "requestId")
        receipt_id = self._coalesce_string(envelope, "receiptId")
        if request_id is None or receipt_id is None:
            self._write_json({"error": "missing_remote_once_fields"}, status=400)
            return
        if self._remote_once_receipt_replayed(receipt_id):
            self._write_json({"error": "remote_once_replayed"}, status=409)
            return
        request_row = self.server.store.get_approval_request(request_id)  # type: ignore[attr-defined]
        if not isinstance(request_row, dict) or request_row.get("status") != "pending":
            self._write_json({"error": "remote_once_request_not_pending"}, status=409)
            return
        request_policy_action = self._optional_string(request_row.get("policy_action"))
        request_recommended_scope = self._optional_string(request_row.get("recommended_scope"))
        if (
            request_policy_action not in {"block", "pause", "review", "require-reapproval"}
            or request_recommended_scope not in DECISION_SCOPE_VALUES
        ):
            self._write_json({"error": "remote_once_not_permitted"}, status=409)
            return
        try:
            validate_remote_approval_request_binding(
                envelope=envelope,
                request_row=request_row,
                oauth=oauth,
                store=self.server.store,  # type: ignore[attr-defined]
            )
        except GuardReviewContractError as error:
            error_code = str(error)
            if error_code in {
                "remote_approval_request_id_mismatch",
                "remote_approval_approval_id_mismatch",
                "remote_approval_harness_mismatch",
                "remote_approval_action_hash_mismatch",
                "remote_approval_claim_hash_mismatch",
                "remote_approval_policy_version_mismatch",
            }:
                self._write_json({"error": "remote_once_request_stale"}, status=409)
                return
            if error_code in {
                "remote_approval_workspace_mismatch",
                "remote_approval_installation_mismatch",
                "remote_approval_machine_mismatch",
                "remote_approval_device_mismatch",
            }:
                self._write_json({"error": "remote_once_wrong_target"}, status=409)
                return
            self._write_json({"error": error_code}, status=400)
            return
        if not self.server.store.claim_remote_once_receipt(  # type: ignore[attr-defined]
            receipt_id,
            request_id=request_id,
            claimed_at=_now(),
        ):
            self._write_json({"error": "remote_once_replayed"}, status=409)
            return
        resolution_action = "block" if self._optional_string(envelope.get("decision")) == "block" else "allow"
        try:
            result = self.server.store.resolve_request_with_signed_remote_result(  # type: ignore[attr-defined]
                request_id,
                resolution_action=resolution_action,
                resolution_scope=request_recommended_scope or "artifact",
                reason="Guard Cloud signed remote approval",
                resolved_at=_now(),
            )
        except Exception:
            self.server.store.release_remote_once_receipt(receipt_id)  # type: ignore[attr-defined]
            raise
        if result.get("resolved") is not True:
            self.server.store.release_remote_once_receipt(receipt_id)  # type: ignore[attr-defined]
            self._write_json({"error": "remote_once_apply_failed"}, status=409)
            return
        resolved_request_value = result.get("resolved_request")
        resolved_request: dict[str, object] = (
            resolved_request_value if _is_string_object_dict(resolved_request_value) else {}
        )
        resolved_at = self._optional_string(resolved_request.get("resolved_at")) or _now()
        self.server.store.add_event(  # type: ignore[attr-defined]
            "approval.remote_once_applied",
            {
                "approval_url": self._optional_string(resolved_request.get("approval_url")),
                "receipt_id": receipt_id,
                "request_id": request_id,
                "review_command": self._optional_string(resolved_request.get("review_command")),
                "scope": request_recommended_scope or "artifact",
            },
            resolved_at,
        )
        artifact_name = self._optional_string(request_row.get("artifact_name")) or request_id
        receipt = self._record_headless_receipt(
            harness=adapter.harness,
            operation="remote_once",
            payload=payload,
            result=result,
            workspace_id=self._optional_string(request_row.get("workspace")),
            artifact_name=f"Remote once approval for {artifact_name}",
            scanner_evidence_extra={
                "receipt_id": receipt_id,
                "request_id": request_id,
            },
        )
        response_payload: dict[str, object] = {
            "harness": adapter.harness,
            "operation": "remote_once",
            "receipt": receipt,
            "request_id": request_id,
            "resolved_request": resolved_request,
            "status": "completed",
        }
        if adapter.harness == "codex":
            codex_resume = self._codex_resume_after_remote_once(
                request_id=request_id,
                action=resolution_action,
            )
            if codex_resume is not None:
                response_payload["codex_resume"] = codex_resume
                self.server.store.add_event(  # type: ignore[attr-defined]
                    "codex/thread_resume",
                    {"request_id": request_id, "action": resolution_action, **codex_resume},
                    _now(),
                )
        else:
            harness_resume = resume_harness_operation(
                self.server.store,  # type: ignore[attr-defined]
                request_id=request_id,
                action=resolution_action,
                now=_now(),
            )
            if harness_resume is not None:
                response_payload["harness_resume"] = harness_resume
                response_payload["harnessResume"] = harness_resume
        self._write_json(response_payload)

    def _handle_audit_remediation(self, action: str, payload: dict[str, object]) -> None:
        if action != "package_shim_path":
            self._write_json({"error": "unsupported_remediation", "operation": action}, status=404)
            return
        manager = self._optional_string(payload.get("manager"))
        if manager is None:
            self._write_json({"error": "missing_manager", "operation": action}, status=400)
            return
        managers, manager_error = self._supply_chain_managers({"managers": [manager]})
        if manager_error is not None:
            self._write_json({"error": manager_error, "operation": action}, status=400)
            return
        entitlement = self._supply_chain_entitlement()
        if not bool(entitlement["allowed"]):
            status, error_code, message = package_firewall_block_details(entitlement)
            current_status = package_shim_status(self._supply_chain_context(payload))
            self._write_json(
                {
                    "available_actions": package_firewall_available_actions(
                        entitlement,
                        has_installed_managers=bool(current_status.get("installed_managers")),
                    ),
                    "entitlement": entitlement,
                    "error": error_code,
                    "message": message,
                    "operation": action,
                },
                status=status,
            )
            return
        context = self._supply_chain_context(payload)
        try:
            require_high_risk(
                self.server.store.guard_home,  # type: ignore[attr-defined]
                purpose="supply_chain_firewall",
                approval_gate_input=approval_gate_input_from_mapping(payload),
            )
            activation_result = activate_package_shims(context, managers=managers)
        except ApprovalGateError as error:
            self._write_approval_gate_error(error)
            return
        except ValueError as error:
            self._write_json({"error": str(error), "operation": action}, status=400)
            return
        result = {
            "manager": manager,
            **activation_result,
        }
        receipt_overrides = package_firewall_receipt_metadata(
            operation=action,
            result=result,
            managers=(manager,),
            workspace_dir=context.workspace_dir,
        )
        scanner_evidence = receipt_overrides.get("scanner_evidence")
        receipt = self._record_headless_receipt(
            harness="package-firewall",
            operation=action,
            payload=payload,
            result=result,
            workspace_id=self._optional_string(payload.get("workspace_id"))
            or self.server.store.get_cloud_workspace_id(),  # type: ignore[attr-defined]
            policy_decision=self._optional_string(receipt_overrides.get("policy_decision")),
            capabilities_summary=self._optional_string(receipt_overrides.get("capabilities_summary")),
            artifact_name=self._optional_string(receipt_overrides.get("artifact_name")),
            scanner_evidence_extra=scanner_evidence if _is_string_object_dict(scanner_evidence) else None,
        )
        self._write_json(
            {
                "entitlement": entitlement,
                "operation": action,
                "receipt": receipt,
                "result": result,
                "status": "completed",
            }
        )

    def _handle_supply_chain_package_firewall_status(self) -> None:
        entitlement = self._supply_chain_entitlement()
        status = package_shim_status(self._harness_context({}))
        audit_workspace_dir = self._resolve_supply_chain_workspace_dir({})
        self._write_json(
            {
                "actions": package_firewall_action_states(
                    entitlement,
                    has_installed_managers=bool(status.get("installed_managers")),
                ),
                "audit_workspace_dir": (str(audit_workspace_dir) if audit_workspace_dir is not None else None),
                "cli_fallback": {
                    "connect": "hol-guard connect",
                    "install": "hol-guard package-shims install --json",
                    "status": "hol-guard package-shims status --json",
                    "remove": "hol-guard package-shims uninstall --json",
                },
                "connect_flow": self._supply_chain_connect_flow(entitlement),
                "entitlement": entitlement,
                "operation": "status",
                "status": "completed",
                "supported_managers": list(package_shim_supported_managers()),
                "package_shims": status,
            }
        )

    def _handle_supply_chain_package_firewall_action(self, action: str, payload: dict[str, object]) -> None:
        if action == "connect":
            self._handle_supply_chain_package_firewall_connect()
            return
        operation = "remove" if action == "uninstall" else action
        if operation == "open-shell":
            operation = "activate"
        if not self._enforce_package_firewall_rate_limit(operation, payload):
            return
        entitlement = self._supply_chain_entitlement()
        context = self._supply_chain_context(payload)
        current_status = package_shim_status(context)
        if not package_firewall_operation_allowed(
            entitlement,
            operation,
            has_installed_managers=bool(current_status.get("installed_managers")),
        ):
            status, error_code, message = package_firewall_block_details(entitlement)
            self._write_json(
                {
                    "available_actions": package_firewall_available_actions(
                        entitlement,
                        has_installed_managers=bool(current_status.get("installed_managers")),
                    ),
                    "entitlement": entitlement,
                    "error": error_code,
                    "message": message,
                    "operation": operation,
                },
                status=status,
            )
            return
        managers, manager_error = self._supply_chain_managers(payload)
        if manager_error is not None:
            self._write_json({"error": manager_error, "operation": operation}, status=400)
            return
        try:
            if operation in {"install", "repair", "remove", "test", "sync"}:
                require_high_risk(
                    self.server.store.guard_home,  # type: ignore[attr-defined]
                    purpose="supply_chain_firewall",
                    approval_gate_input=approval_gate_input_from_mapping(payload),
                )
            if operation == "activate":
                status, response = _activate_package_firewall_runtime(context)
                self._write_json(response, status=status)
                return
            result = self._run_supply_chain_package_action(operation, context, managers)
        except ApprovalGateError as error:
            self._write_approval_gate_error(error)
            return
        except ValueError as error:
            error_code = str(error)
            error_payload: dict[str, object] = {"error": error_code, "operation": operation}
            if error_code == "workspace_dir_required":
                error_payload["message"] = (
                    "Guard needs a project folder with package manifests before it can run "
                    "the workspace audit. Open Guard from a connected app workspace or pass "
                    "workspace_dir in the audit request."
                )
            self._write_json(error_payload, status=400)
            return
        except Exception as error:
            status, error_payload = _supply_chain_package_action_error_response(
                operation=operation,
                error=error,
            )
            self._write_json(error_payload, status=status)
            return
        receipt_overrides = package_firewall_receipt_metadata(
            operation=operation,
            result=result,
            managers=managers,
            workspace_dir=context.workspace_dir,
            store=self.server.store,  # type: ignore[attr-defined]
        )
        scanner_evidence = receipt_overrides.get("scanner_evidence")
        receipt = self._record_headless_receipt(
            harness="package-firewall",
            operation=operation,
            payload=payload,
            result=result,
            workspace_id=self._optional_string(payload.get("workspace_id"))
            or self.server.store.get_cloud_workspace_id(),  # type: ignore[attr-defined]
            policy_decision=self._optional_string(receipt_overrides.get("policy_decision")),
            capabilities_summary=self._optional_string(receipt_overrides.get("capabilities_summary")),
            artifact_name=self._optional_string(receipt_overrides.get("artifact_name")),
            scanner_evidence_extra=scanner_evidence if _is_string_object_dict(scanner_evidence) else None,
        )
        response_status = "completed"
        if operation == "audit":
            audit_status = result.get("audit_status")
            if audit_status == "incomplete":
                response_status = "incomplete"
        response_payload: dict[str, object] = {
            "entitlement": entitlement,
            "operation": operation,
            "receipt": receipt,
            "result": result,
            "status": response_status,
        }
        if operation == "audit":
            cloud_sync = _queue_headless_cloud_sync(store=self.server.store)  # type: ignore[attr-defined]
            receipt["cloud_sync"] = cloud_sync
            response_payload["cloud_sync"] = cloud_sync
        self._write_json(response_payload)

    def _run_supply_chain_package_action(
        self,
        operation: str,
        context: HarnessContext,
        managers: tuple[str, ...] | None,
    ) -> dict[str, object]:
        store = self.server.store  # type: ignore[attr-defined]
        if operation == "install":
            return activate_package_shims(context, managers=managers)
        if operation == "repair":
            return activate_package_shims(context, managers=managers, repair=True)
        if operation == "remove":
            return uninstall_package_shims(context, managers=managers)
        if operation == "test":
            return probe_package_shim_intercepts(
                context,
                managers=managers,
                workspace_dir=context.workspace_dir,
            )
        if operation == "audit":
            if context.workspace_dir is None:
                raise ValueError("workspace_dir_required")
            config = load_guard_config(store.guard_home)
            now = datetime.now(timezone.utc).isoformat()
            audit_payload, exit_code = build_workspace_audit_payload(
                command_name="audit",
                config=config,
                now=now,
                sbom_paths=(),
                store=store,
                workspace_dir=context.workspace_dir,
            )
            audit_payload["exit_code"] = exit_code
            if exit_code == 0:
                record_package_shim_audit_result(context, audited_at=now)
            return audit_payload
        if operation == "sync":
            return _sync_supply_chain_cloud_state_with_optional_auth_context(
                self.server.store,  # type: ignore[attr-defined]
                None,
                workspace_dir=context.workspace_dir,
            )
        raise ValueError("unsupported_supply_chain_operation")

    def _resolve_supply_chain_workspace_dir(self, payload: dict[str, object]) -> Path | None:
        allowed_roots = (
            Path.home().resolve(),
            Path.cwd().resolve(),
            Path(tempfile.gettempdir()).resolve(),
        )
        managed_workspace_dirs = managed_install_audit_workspace_dirs(self.server.store)  # type: ignore[attr-defined]
        return resolve_supply_chain_audit_workspace_dir(
            workspace_dir_value=payload.get("workspace_dir"),
            workspace_value=payload.get("workspace"),
            allowed_roots=allowed_roots,
            managed_workspace_dirs=managed_workspace_dirs,
        )

    def _supply_chain_context(self, payload: dict[str, object]) -> HarnessContext:
        workspace_dir = self._resolve_supply_chain_workspace_dir(payload)
        return HarnessContext(
            home_dir=Path.home().resolve(),
            workspace_dir=workspace_dir,
            guard_home=self.server.store.guard_home,  # type: ignore[attr-defined]
        )

    @staticmethod
    def _supply_chain_managers(payload: dict[str, object]) -> tuple[tuple[str, ...] | None, str | None]:
        managers_value = payload.get("managers")
        if managers_value is None:
            return None, None
        if not isinstance(managers_value, list) or not all(isinstance(manager, str) for manager in managers_value):
            return None, "invalid_managers"
        supported = set(package_shim_supported_managers())
        normalized = [manager.strip().lower() for manager in managers_value if manager.strip()]
        if len(normalized) != len(set(normalized)):
            return None, "duplicate_manager"
        managers = tuple(normalized)
        if not managers:
            return None, "invalid_managers"
        if not set(managers).issubset(supported):
            return None, "unsupported_manager"
        return managers, None

    def _supply_chain_entitlement(self) -> dict[str, object]:
        return resolve_package_firewall_entitlement_with_refresh(self.server.store)  # type: ignore[attr-defined]

    def _handle_get_supply_chain_bundle(self) -> None:
        store = self.server.store  # type: ignore[attr-defined]
        workspace_id = store.get_cloud_workspace_id()
        wrapper = store.get_cached_supply_chain_bundle(workspace_id) if workspace_id is not None else None
        bundle = wrapper.get("bundle") if isinstance(wrapper, dict) else None
        self._write_json({"bundle": bundle})

    def _supply_chain_connect_flow(self, entitlement: dict[str, object]) -> dict[str, object] | None:
        return _resolve_package_firewall_connect_flow(server=self.server, entitlement=entitlement)  # type: ignore[arg-type]

    def _handle_supply_chain_package_firewall_connect(self) -> None:
        entitlement = self._supply_chain_entitlement()
        reason = str(entitlement.get("reason") or "").strip().lower()
        if reason not in {"guard_cloud_connect_required", "guard_cloud_reconnect_required"}:
            self._write_json(
                {
                    "error": "guard_cloud_connect_not_required",
                    "entitlement": entitlement,
                    "message": "Guard Cloud connect is not required for package firewall on this machine.",
                },
                status=409,
            )
            return
        store = self.server.store  # type: ignore[attr-defined]
        connect_url = _package_firewall_connect_url(store)
        action_label = _package_firewall_connect_action_label(
            reason,
            repair_copy=_package_firewall_connect_needs_repair(store, reason),
        )
        request_id = f"guard-connect-{uuid.uuid4().hex}"
        starting_state = {
            **_default_package_firewall_connect_flow(store=store, reason=reason),
            "state": "starting",
            "title": "Opening Guard Cloud sign-in",
            "detail": "HOL Guard is opening the secure sign-in flow in your browser.",
            "action_label": action_label,
            "authorize_url": None,
            "browser_opened": None,
            "request_id": request_id,
            "poll_after_ms": _SUPPLY_CHAIN_CONNECT_POLL_AFTER_MS,
        }
        started, current = _begin_package_firewall_connect_state(  # type: ignore[arg-type]
            self.server,
            starting_state,
        )
        if not started:
            self._write_json(current, status=202)
            return
        try:
            prepare_guard_cloud_connect_authorization(store)
            device = store.get_device_metadata()
            session = start_guard_browser_session(
                connect_url=connect_url,
                machine_id=str(device["installation_id"]),
                machine_label=str(device["device_label"]),
            )
            browser_opened = bool(webbrowser.open(session.authorize_url))
        except Exception as error:
            failure = {
                **_default_package_firewall_connect_flow(store=store, reason=reason),
                "state": "failed",
                "detail": str(error),
                "browser_opened": False,
                "poll_after_ms": None,
            }
            _set_package_firewall_connect_state(self.server, failure)  # type: ignore[arg-type]
            self._write_json(failure, status=500)
            return

        running_state = {
            **_default_package_firewall_connect_flow(store=store, reason=reason),
            "state": "running",
            "title": "Finish Guard Cloud sign-in in your browser",
            "detail": (
                "HOL Guard opened the secure sign-in flow in your browser. Finish sign-in there and this page will "
                "unlock package-firewall controls automatically."
                if browser_opened
                else (
                    "HOL Guard is waiting for browser approval. Open the sign-in page below if your browser did "
                    "not open automatically."
                )
            ),
            "action_label": action_label,
            "authorize_url": session.authorize_url,
            "browser_opened": browser_opened,
            "request_id": request_id,
            "poll_after_ms": _SUPPLY_CHAIN_CONNECT_POLL_AFTER_MS,
        }
        _set_package_firewall_connect_state(self.server, running_state)  # type: ignore[arg-type]

        def _complete_connect() -> None:
            try:
                _, allowed_origin = resolve_connect_url(connect_url)
                oauth_client = resolve_guard_oauth_client_config(allowed_origin)
                callback = session.wait_for_callback(_SUPPLY_CHAIN_CONNECT_WAIT_TIMEOUT_SECONDS)
                if callback is None or callback.code is None:
                    raise RuntimeError("Guard OAuth callback missing authorization code.")
                token_result = exchange_guard_authorization_code(
                    token_endpoint=oauth_client.token_endpoint,
                    client_id=oauth_client.client_id,
                    code=callback.code,
                    redirect_uri=session.redirect_uri,
                    code_verifier=session.pkce_verifier,
                    dpop_key_material=session.dpop_key_material,
                )
                if token_result.refresh_token is None:
                    raise RuntimeError("Guard OAuth token exchange failed: missing refresh token.")
                timestamp = _now()
                _persist_oauth_local_credentials(
                    store=store,
                    issuer=oauth_client.issuer,
                    client_id=oauth_client.client_id,
                    refresh_token=token_result.refresh_token,
                    dpop_key_material=session.dpop_key_material,
                    grant_id=token_result.grant_id,
                    machine_id=token_result.machine_id,
                    supply_chain_entitlement=token_result.supply_chain_entitlement,
                    workspace_id=token_result.workspace_id,
                    runtime_id="hol-guard",
                    runtime_label="HOL Guard CLI",
                    access_token=token_result.access_token,
                    access_token_expires_at=token_result.access_token_expires_at,
                    now=timestamp,
                )
                payload = _finalize_daemon_guard_connect_payload(
                    store=store,
                    connect_url=connect_url,
                    payload={
                        "status": "connected",
                        "connect_mode": "browser_oauth",
                        "browser_opened": browser_opened,
                        "authorize_url": session.authorize_url,
                        "redirect_uri": session.redirect_uri,
                        "grant_id": token_result.grant_id,
                        "machine_id": token_result.machine_id,
                        "workspace_id": token_result.workspace_id,
                        "connect_url": connect_url,
                        "sync_url": f"{allowed_origin}/api/guard/receipts/sync",
                        "_guard_sync_auth_context": _build_sync_auth_context(
                            access_token=token_result.access_token,
                            dpop_key_material=session.dpop_key_material,
                            sync_url=f"{allowed_origin}/api/guard/receipts/sync",
                        ),
                    },
                    now=timestamp,
                )
                resolved_entitlement = resolve_package_firewall_entitlement(store)
                resolved_reason = str(resolved_entitlement.get("reason") or "")
                if bool(resolved_entitlement.get("allowed")) or resolved_reason == "paid_guard_cloud_required":
                    _set_package_firewall_connect_state(self.server, None)  # type: ignore[arg-type]
                    return
                repair_message = str(
                    payload.get("repair_message") or payload.get("sync_error") or "Guard Cloud connect did not finish."
                )
                _set_package_firewall_connect_state(  # type: ignore[arg-type]
                    self.server,
                    {
                        **running_state,
                        "state": "failed",
                        "title": "Guard Cloud sign-in needs attention",
                        "detail": repair_message,
                        "poll_after_ms": None,
                    },
                )
            except Exception as error:
                _set_package_firewall_connect_state(  # type: ignore[arg-type]
                    self.server,
                    {
                        **running_state,
                        "state": "failed",
                        "title": "Guard Cloud sign-in needs attention",
                        "detail": str(error),
                        "poll_after_ms": None,
                    },
                )
            finally:
                session.close()

        threading.Thread(
            target=_complete_connect,
            daemon=True,
            name="guard-package-firewall-connect",
        ).start()
        self._write_json(running_state, status=202)

    def _handle_guard_cloud_connect_status(self) -> None:
        store = self.server.store  # type: ignore[attr-defined]
        connect_flow = _resolve_guard_cloud_connect_flow(server=self.server, store=store)  # type: ignore[arg-type]
        self._write_json(
            {
                "connect_required": connect_flow is not None,
                "connect_flow": connect_flow,
            }
        )

    def _handle_guard_cloud_connect_start(self) -> None:
        store = self.server.store  # type: ignore[attr-defined]
        if not _guard_cloud_connect_required_for_insights(store):
            self._write_json(
                {
                    "error": "guard_cloud_connect_not_required",
                    "connect_required": False,
                    "connect_flow": None,
                    "message": "Guard Cloud connect is not required to publish insights from this machine.",
                },
                status=409,
            )
            return
        repair_mode = _guard_cloud_connect_repair_mode(store)
        connect_url = _package_firewall_connect_url(store)
        action_label = "Repair Guard Cloud access" if repair_mode else "Connect Guard Cloud"
        request_id = f"guard-connect-{uuid.uuid4().hex}"
        starting_state = {
            **_default_guard_cloud_connect_flow(store=store, repair_mode=repair_mode),
            "state": "starting",
            "title": "Opening Guard Cloud sign-in",
            "detail": "HOL Guard is opening the secure sign-in flow in your browser.",
            "action_label": action_label,
            "authorize_url": None,
            "browser_opened": None,
            "request_id": request_id,
            "poll_after_ms": _SUPPLY_CHAIN_CONNECT_POLL_AFTER_MS,
        }
        started, current = _begin_guard_cloud_connect_state(  # type: ignore[arg-type]
            self.server,
            starting_state,
        )
        if not started:
            self._write_json({"connect_required": True, "connect_flow": current}, status=202)
            return
        try:
            prepare_guard_cloud_connect_authorization(store)
            device = store.get_device_metadata()
            session = start_guard_browser_session(
                connect_url=connect_url,
                machine_id=str(device["installation_id"]),
                machine_label=str(device["device_label"]),
            )
            browser_opened = bool(webbrowser.open(session.authorize_url))
        except Exception as error:
            failure = {
                **_default_guard_cloud_connect_flow(store=store, repair_mode=repair_mode),
                "state": "failed",
                "detail": str(error),
                "browser_opened": False,
                "poll_after_ms": None,
            }
            _set_guard_cloud_connect_state(self.server, failure)  # type: ignore[arg-type]
            self._write_json(
                {"connect_required": True, "connect_flow": failure, "message": str(error)},
                status=500,
            )
            return

        running_state = {
            **_default_guard_cloud_connect_flow(store=store, repair_mode=repair_mode),
            "state": "running",
            "title": "Finish Guard Cloud sign-in in your browser",
            "detail": (
                "HOL Guard opened the secure sign-in flow in your browser. Finish sign-in there and this modal will "
                "unlock public sharing automatically."
                if browser_opened
                else (
                    "HOL Guard is waiting for browser approval. Open the sign-in page below if your browser did "
                    "not open automatically."
                )
            ),
            "action_label": action_label,
            "authorize_url": session.authorize_url,
            "browser_opened": browser_opened,
            "request_id": request_id,
            "poll_after_ms": _SUPPLY_CHAIN_CONNECT_POLL_AFTER_MS,
        }
        _set_guard_cloud_connect_state(self.server, running_state)  # type: ignore[arg-type]

        def _complete_connect() -> None:
            try:
                _, allowed_origin = resolve_connect_url(connect_url)
                oauth_client = resolve_guard_oauth_client_config(allowed_origin)
                callback = session.wait_for_callback(_SUPPLY_CHAIN_CONNECT_WAIT_TIMEOUT_SECONDS)
                if callback is None or callback.code is None:
                    raise RuntimeError("Guard OAuth callback missing authorization code.")
                token_result = exchange_guard_authorization_code(
                    token_endpoint=oauth_client.token_endpoint,
                    client_id=oauth_client.client_id,
                    code=callback.code,
                    redirect_uri=session.redirect_uri,
                    code_verifier=session.pkce_verifier,
                    dpop_key_material=session.dpop_key_material,
                )
                if token_result.refresh_token is None:
                    raise RuntimeError("Guard OAuth token exchange failed: missing refresh token.")
                timestamp = _now()
                _persist_oauth_local_credentials(
                    store=store,
                    issuer=oauth_client.issuer,
                    client_id=oauth_client.client_id,
                    refresh_token=token_result.refresh_token,
                    dpop_key_material=session.dpop_key_material,
                    grant_id=token_result.grant_id,
                    machine_id=token_result.machine_id,
                    supply_chain_entitlement=token_result.supply_chain_entitlement,
                    workspace_id=token_result.workspace_id,
                    runtime_id="hol-guard",
                    runtime_label="HOL Guard CLI",
                    access_token=token_result.access_token,
                    access_token_expires_at=token_result.access_token_expires_at,
                    now=timestamp,
                )
                payload = _finalize_daemon_guard_connect_payload(
                    store=store,
                    connect_url=connect_url,
                    payload={
                        "status": "connected",
                        "connect_mode": "browser_oauth",
                        "browser_opened": browser_opened,
                        "authorize_url": session.authorize_url,
                        "redirect_uri": session.redirect_uri,
                        "grant_id": token_result.grant_id,
                        "machine_id": token_result.machine_id,
                        "workspace_id": token_result.workspace_id,
                        "connect_url": connect_url,
                        "sync_url": f"{allowed_origin}/api/guard/receipts/sync",
                        "_guard_sync_auth_context": _build_sync_auth_context(
                            access_token=token_result.access_token,
                            dpop_key_material=session.dpop_key_material,
                            sync_url=f"{allowed_origin}/api/guard/receipts/sync",
                        ),
                    },
                    now=timestamp,
                )
                if _guard_cloud_connect_succeeded(store):
                    _set_guard_cloud_connect_state(self.server, None)  # type: ignore[arg-type]
                    return
                repair_message = str(
                    payload.get("repair_message") or payload.get("sync_error") or "Guard Cloud connect did not finish."
                )
                _set_guard_cloud_connect_state(  # type: ignore[arg-type]
                    self.server,
                    {
                        **running_state,
                        "state": "failed",
                        "title": "Guard Cloud sign-in needs attention",
                        "detail": repair_message,
                        "poll_after_ms": None,
                    },
                )
            except Exception as error:
                _set_guard_cloud_connect_state(  # type: ignore[arg-type]
                    self.server,
                    {
                        **running_state,
                        "state": "failed",
                        "title": "Guard Cloud sign-in needs attention",
                        "detail": str(error),
                        "poll_after_ms": None,
                    },
                )
            finally:
                session.close()

        threading.Thread(
            target=_complete_connect,
            daemon=True,
            name="guard-cloud-connect",
        ).start()
        self._write_json({"connect_required": True, "connect_flow": running_state}, status=202)

    @staticmethod
    def _policy_memory_payload(value: object) -> dict[str, object]:
        if isinstance(value, dict):
            return dict(value)
        if isinstance(value, str) and value.strip():
            try:
                parsed = json.loads(value)
            except json.JSONDecodeError:
                return {}
            return parsed if isinstance(parsed, dict) else {}
        return {}

    def _remote_once_receipt_replayed(self, receipt_id: str) -> bool:
        return self.server.store.has_remote_once_receipt(receipt_id)  # type: ignore[attr-defined]

    def _record_headless_receipt(
        self,
        *,
        harness: str,
        location_id: str | None = None,
        operation: str,
        payload: dict[str, object],
        result: dict[str, object],
        workspace_id: str | None,
        cloud_sync: dict[str, object] | None = None,
        policy_decision: str | None = None,
        capabilities_summary: str | None = None,
        artifact_name: str | None = None,
        scanner_evidence_extra: dict[str, object] | None = None,
    ) -> dict[str, object]:
        cursor_receipt_context = self._cursor_receipt_context(
            harness=harness,
            operation=operation,
            payload=payload,
            result=result,
            cloud_sync=cloud_sync,
        )
        material = json.dumps(
            {
                "harness": harness,
                "location_id": location_id,
                "operation": operation,
                "result_keys": sorted(result.keys()),
                "cursor": cursor_receipt_context,
                "workspace_id": workspace_id,
            },
            sort_keys=True,
        )
        artifact_hash = stable_digest_hex(material.encode("utf-8"))
        changed_capabilities = [] if operation in {"status", "scan"} else [operation]
        artifact_id = f"headless:{harness}:{operation}"
        resolved_artifact_name = artifact_name or f"Headless {operation}"
        resolved_capabilities_summary = capabilities_summary or f"Guard local daemon completed headless {operation}."
        source_scope = "local-daemon"
        resolved_policy_decision = policy_decision or "allow"
        scanner_evidence: dict[str, object] = {
            "operation": operation,
            "location_id": location_id,
            "workspace_id": workspace_id,
            "status": "completed",
        }
        if scanner_evidence_extra is not None:
            scanner_evidence.update(scanner_evidence_extra)
        if cursor_receipt_context is not None:
            artifact_id = str(cursor_receipt_context["action_scope"])
            resolved_artifact_name = str(cursor_receipt_context["artifact_name"])
            resolved_capabilities_summary = str(cursor_receipt_context["capabilities_summary"])
            source_scope = str(cursor_receipt_context["source_scope"])
            changed_capabilities = [str(cursor_receipt_context["changed_capability"])]
            scanner_evidence.update(cursor_receipt_context["scanner_evidence"])
        receipt = build_receipt(
            harness=harness,
            artifact_id=artifact_id,
            artifact_hash=artifact_hash,
            policy_decision=resolved_policy_decision,
            capabilities_summary=resolved_capabilities_summary,
            changed_capabilities=changed_capabilities,
            provenance_summary="Guard Cloud local daemon API",
            artifact_name=resolved_artifact_name,
            source_scope=source_scope,
            scanner_evidence=(scanner_evidence,),
            approval_source="guard-cloud-headless",
        )
        self.server.store.add_receipt(receipt)  # type: ignore[attr-defined]
        summary: dict[str, object] = {
            "id": receipt.receipt_id,
            "operation": operation,
            "status": "completed",
            "timestamp": receipt.timestamp,
        }
        if cursor_receipt_context is not None:
            summary.update(cursor_receipt_context["summary"])
        return summary

    def _cursor_headless_surface(self, payload: dict[str, object]) -> str | None:
        surface = self._optional_string(payload.get("surface")) or self._optional_string(payload.get("editor_or_cli"))
        if surface is None:
            return None
        if surface not in {"editor", "cli"}:
            raise ValueError("invalid_cursor_surface")
        return surface

    def _cursor_receipt_context(
        self,
        *,
        harness: str,
        operation: str,
        payload: dict[str, object],
        result: dict[str, object],
        cloud_sync: dict[str, object] | None,
    ) -> _CursorReceiptContext | None:
        if harness != "cursor":
            return None
        action_payload = result.get("cursor_action")
        action_dict = action_payload if isinstance(action_payload, dict) else {}
        surface = (
            self._optional_string(action_dict.get("surface"))
            or self._optional_string(payload.get("surface"))
            or self._optional_string(payload.get("editor_or_cli"))
            or "editor"
        )
        action = self._optional_string(action_dict.get("action")) or operation
        evidence = action_dict.get("evidence")
        evidence_dict = evidence if isinstance(evidence, dict) else {}
        action_scope = self._optional_string(evidence_dict.get("actionScope")) or f"cursor:{surface}:{action}"
        cloud_sync_status = "pending"
        if isinstance(cloud_sync, dict):
            cloud_sync_status = self._optional_string(cloud_sync.get("status")) or cloud_sync_status
        surface_label = "CLI" if surface == "cli" else "editor"
        scanner_evidence: dict[str, object] = {
            "action_scope": action_scope,
            "cloud_sync_status": cloud_sync_status,
            "cursor_status": self._optional_string(action_dict.get("status")) or "unknown",
            "editor_or_cli": surface,
            "error_reason": self._optional_string(payload.get("error_reason")),
        }
        summary: dict[str, object] = {
            "action_scope": action_scope,
            "cloud_sync": dict(cloud_sync) if isinstance(cloud_sync, dict) else {"status": cloud_sync_status},
            "editor_or_cli": surface,
        }
        return {
            "action_scope": action_scope,
            "artifact_name": f"Cursor {surface_label} {action}",
            "capabilities_summary": f"Guard local daemon completed Cursor {surface_label} {action}.",
            "changed_capability": f"{surface}:{action}",
            "scanner_evidence": scanner_evidence,
            "source_scope": f"cursor:{surface}",
            "summary": summary,
        }

    def _handle_policy_clear(self, payload: dict[str, object]) -> None:
        harness = self._optional_string(payload.get("harness"))
        source = self._optional_string(payload.get("source"))
        scope = self._optional_string(payload.get("scope"))
        artifact_id = self._optional_string(payload.get("artifact_id"))
        artifact_hash = self._optional_string(payload.get("artifact_hash"))
        workspace = self._optional_string(payload.get("workspace"))
        publisher = self._optional_string(payload.get("publisher"))
        try:
            clear_all = self._optional_bool(payload.get("all"), default=False)
            artifact_id_is_null = self._optional_bool(payload.get("artifact_id_is_null"), default=False)
            artifact_hash_is_null = self._optional_bool(payload.get("artifact_hash_is_null"), default=False)
        except ValueError:
            self._write_json({"error": "invalid_clear_payload", "cleared": 0}, status=400)
            return
        if scope is not None and scope not in {"artifact", "workspace", "publisher", "harness", "global"}:
            self._write_json({"error": "invalid_scope", "cleared": 0, "scope": scope}, status=400)
            return
        if clear_all and harness is not None:
            self._write_json(
                {
                    "error": "choose_all_or_harness",
                    "cleared": 0,
                    "harness": harness,
                    "source": source,
                },
                status=400,
            )
            return
        if not clear_all and harness is None:
            self._write_json({"error": "missing_harness_or_all", "cleared": 0}, status=400)
            return
        try:
            approval_gate_grant = require_high_risk(
                self.server.store.guard_home,  # type: ignore[attr-defined]
                purpose="policy_clear",
                approval_gate_input=approval_gate_input_from_mapping(payload),
            )
            cleared = self.server.store.clear_policy_decisions(  # type: ignore[attr-defined]
                None if clear_all else harness,
                source,
                scope=scope,
                artifact_id=artifact_id,
                artifact_hash=artifact_hash,
                artifact_id_is_null=artifact_id_is_null,
                artifact_hash_is_null=artifact_hash_is_null,
                workspace=workspace,
                publisher=publisher,
                approval_gate_grant=approval_gate_grant,
            )
        except ApprovalGateError as error:
            payload = error.to_payload()
            payload["cleared"] = 0
            self._write_json(payload, status=error.status)
            return
        self._write_json(
            {
                "cleared": cleared,
                "harness": None if clear_all else harness,
                "source": source,
                "scope": scope,
                "artifact_id": artifact_id,
                "artifact_hash": artifact_hash,
                "artifact_id_is_null": artifact_id_is_null,
                "artifact_hash_is_null": artifact_hash_is_null,
                "workspace": workspace,
                "publisher": publisher,
            }
        )

    def _handle_requests_clear(self, payload: dict[str, object]) -> None:
        status = self._optional_string(payload.get("status")) or "pending"
        harness = self._optional_string(payload.get("harness"))
        if status not in {"pending", "resolved"}:
            self._write_json({"error": "invalid_status", "cleared": 0, "status": status}, status=400)
            return
        try:
            require_high_risk(
                self.server.store.guard_home,  # type: ignore[attr-defined]
                purpose="queue_clear",
                approval_gate_input=approval_gate_input_from_mapping(payload),
            )
            cleared = self.server.store.clear_approval_requests(  # type: ignore[attr-defined]
                harness=harness,
                status=status,
            )
        except ApprovalGateError as error:
            payload = error.to_payload()
            payload["cleared"] = 0
            payload["status"] = status
            self._write_json(payload, status=error.status)
            return
        self._write_json({"cleared": cleared, "status": status, "harness": harness})

    def _handle_bulk_allow_read_once(self, payload: dict[str, object]) -> None:
        request_ids = payload.get("request_ids")
        if not isinstance(request_ids, list) or len(request_ids) == 0:
            self._write_json({"error": "missing_request_ids", "resolved_count": 0, "failed": []}, status=400)
            return
        normalized_ids = [str(item).strip() for item in request_ids if isinstance(item, str) and str(item).strip()]
        if len(normalized_ids) == 0:
            self._write_json({"error": "missing_request_ids", "resolved_count": 0, "failed": []}, status=400)
            return
        try:
            result = bulk_allow_read_only_once(
                store=self.server.store,  # type: ignore[attr-defined]
                request_ids=normalized_ids,
                approval_gate_input=approval_gate_input_from_mapping(payload),
            )
        except ValueError as error:
            if str(error) == "bulk_approve_gate_required":
                self._write_json(
                    {"error": str(error), "resolved_count": 0, "failed": []},
                    status=403,
                )
                return
            self._write_json(
                {"error": str(error), "resolved_count": 0, "failed": []},
                status=400,
            )
            return
        except ApprovalGateError as error:
            error_payload = error.to_payload()
            error_payload.setdefault("resolved_count", 0)
            error_payload.setdefault("failed", [])
            self._write_json(error_payload, status=error.status)
            return
        self._write_json(result)

    def _harness_context(self, payload: dict[str, object]) -> HarnessContext:
        del payload
        return HarnessContext(
            home_dir=Path.home().resolve(),
            workspace_dir=None,
            guard_home=self.server.store.guard_home,  # type: ignore[attr-defined]
        )

    def _handle_harness_action(self, harness: str, action: str, payload: dict[str, object]) -> None:
        if action not in {"install", "verify", "repair", "uninstall"}:
            self._write_json({"error": "not_found"}, status=404)
            return
        context = self._harness_context(payload)
        if action == "verify":
            try:
                self._write_json(build_harness_verification(harness, context, self.server.store))  # type: ignore[attr-defined]
            except ValueError as error:
                self._write_json({"error": str(error)}, status=404)
            return
        try:
            dry_run = self._optional_bool(payload.get("dry_run"), default=True)
        except ValueError:
            self._write_json({"error": "invalid_dry_run"}, status=400)
            return
        try:
            adapter = get_adapter(harness)
        except ValueError as error:
            self._write_json({"error": str(error)}, status=404)
            return
        if action == "uninstall":
            expected_confirmation = uninstall_confirmation_token(adapter.harness)
            confirmation = self._optional_string(payload.get("confirmation_phrase")) or self._optional_string(
                payload.get("confirmation_token")
            )
            if confirmation != expected_confirmation:
                self._write_json(
                    {
                        "error": "confirmation_required",
                        "harness": adapter.harness,
                        "confirmation_phrase": expected_confirmation,
                        "confirm_command": (
                            f"hol-guard apps disconnect {adapter.harness} --confirm {expected_confirmation}"
                        ),
                    },
                    status=400,
                )
                return
        if dry_run:
            self._write_json(build_harness_setup_plan(action, adapter.harness, context, dry_run=True))
            return
        install_command = "uninstall" if action == "uninstall" else "install"
        try:
            result = apply_managed_install(
                install_command,
                adapter.harness,
                False,
                context,
                self.server.store,  # type: ignore[attr-defined]
                str(context.workspace_dir) if context.workspace_dir is not None else None,
                _now(),
            )
        except ValueError as error:
            self._write_json({"error": str(error)}, status=400)
            return
        self._write_json({"harness": adapter.harness, "action": action, "dry_run": False, **result})

    def _handle_notification_setup(self, payload: dict[str, object]) -> None:
        del payload
        host = self._daemon_server().daemon_host()
        port = self._daemon_server().daemon_port()
        approval_url = _build_local_url(host, port, "/approvals/notification-preview")
        try:
            result = ensure_desktop_notification_setup(
                self.server.store.guard_home,  # type: ignore[attr-defined]
                approval_url=approval_url,
                force=True,
            )
        except Exception as error:
            self._write_json({"error": str(error)}, status=500)
            return
        guidance = macos_notification_guidance(result.notifier_path) if result.platform == "Darwin" else None
        self._write_json(desktop_notification_setup_payload(result, guidance=guidance))

    def _handle_requests_list(self, query_string: str) -> None:
        limit = self._query_limit(query_string, default=200, maximum=200)
        if limit is None:
            self._write_json({"error": "invalid_limit"}, status=400)
            return
        status = self._query_string(query_string, "status") or "pending"
        if status == "all":
            status_filter = None
        elif status in {"pending", "resolved"}:
            status_filter = status
        else:
            self._write_json({"error": "invalid_status"}, status=400)
            return
        include_totals = self._query_bool(query_string, "include_totals", default=True)
        try:
            page = self.server.store.list_approval_request_page(  # type: ignore[attr-defined]
                status=status_filter,
                limit=limit,
                cursor=self._query_string(query_string, "cursor"),
                harness=self._query_string(query_string, "harness"),
                search=self._query_string(query_string, "search"),
                include_totals=include_totals,
            )
        except InvalidApprovalCursorError:
            self._write_json(
                {
                    "error": "invalid_cursor",
                    "recovery": {
                        "code": "refresh_queue",
                        "title": "Refresh the blocked action list.",
                        "body": "The queue position expired. Refresh the Review Queue to continue.",
                    },
                },
                status=400,
            )
            return
        self._write_json(page)

    @staticmethod
    def _optional_bool(value: object, *, default: bool) -> bool:
        if value is None:
            return default
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            normalized = value.strip().lower()
            if normalized in {"true", "1", "yes", "on"}:
                return True
            if normalized in {"false", "0", "no", "off", ""}:
                return False
        raise ValueError("invalid boolean value")

    def _approval_persist_policy(self, payload: dict[str, object]) -> bool | None:
        if "persist_policy" in payload:
            return True if self._optional_bool(payload.get("persist_policy"), default=False) else None
        if "remember" in payload:
            return True if self._optional_bool(payload.get("remember"), default=False) else None
        return None

    def _write_approval_gate_error(self, error: ApprovalGateError, *, resolved: bool | None = None) -> None:
        payload = error.to_payload()
        if resolved is not None:
            payload["resolved"] = resolved
        self._write_json(payload, status=error.status)

    def _handle_insights_share_publish(self, payload: dict[str, object]) -> None:
        include_top_artifacts = self._optional_bool(payload.get("includeTopArtifacts"), default=False)
        show_display_name = self._optional_bool(payload.get("showDisplayName"), default=False)
        display_name_value = payload.get("displayName")
        display_name = display_name_value.strip()[:120] if isinstance(display_name_value, str) else None
        store = self.server.store  # type: ignore[attr-defined]
        try:
            result = publish_insights_share(
                store,
                include_top_artifacts=include_top_artifacts,
                show_display_name=show_display_name,
                display_name=display_name,
            )
        except Exception as error:
            message = str(error).strip() or "Unable to publish Guard insights share."
            self._write_json({"error": "insights_share_failed", "message": message}, status=502)
            return
        self._write_json(result)

    def _handle_cloud_exception_request_list(self) -> None:
        store = self.server.store  # type: ignore[attr-defined]
        try:
            result = fetch_cloud_exception_requests(store)
        except CloudExceptionRequestError as error:
            message = str(error).strip() or "Unable to load Guard Cloud exception requests."
            self._write_json({"error": "cloud_exception_request_list_failed", "message": message}, status=error.status)
            return
        except Exception as error:
            message = str(error).strip() or "Unable to load Guard Cloud exception requests."
            self._write_json({"error": "cloud_exception_request_list_failed", "message": message}, status=502)
            return
        self._write_json(result)

    def _handle_cloud_exception_request_create(self, payload: dict[str, object]) -> None:
        store = self.server.store  # type: ignore[attr-defined]
        try:
            result = submit_cloud_exception_request(store, payload)
        except ValueError as error:
            message = str(error).strip() or "Invalid Guard exception request payload."
            self._write_json({"error": "invalid_payload", "message": message}, status=400)
            return
        except CloudExceptionRequestError as error:
            message = str(error).strip() or "Unable to create Guard Cloud exception request."
            self._write_json({"error": "cloud_exception_request_failed", "message": message}, status=error.status)
            return
        except Exception as error:
            message = str(error).strip() or "Unable to create Guard Cloud exception request."
            self._write_json({"error": "cloud_exception_request_failed", "message": message}, status=502)
            return
        self._write_json(result)

    def _handle_read_state_update(self, payload: dict[str, object]) -> None:
        store = self.server.store  # type: ignore[attr-defined]
        action = str(payload.get("action") or "mark_read")
        if action == "mark_all_read":
            request_ids = payload.get("request_ids")
            if not isinstance(request_ids, list):
                self._write_json({"error": "invalid_request_ids"}, status=400)
                return
            store.mark_requests_read([str(rid) for rid in request_ids if isinstance(rid, str)])
            self._write_json({"ok": True, "ids": store.get_read_state()})
            return
        if action == "mark_unread":
            request_id = payload.get("request_id")
            if not isinstance(request_id, str):
                self._write_json({"error": "invalid_request_id"}, status=400)
                return
            store.mark_request_unread(request_id)
            self._write_json({"ok": True, "ids": store.get_read_state()})
            return
        request_id = payload.get("request_id")
        if isinstance(request_id, str):
            store.mark_requests_read([request_id])
            self._write_json({"ok": True, "ids": store.get_read_state()})
            return
        self._write_json({"error": "invalid_action"}, status=400)

    def _read_delete_body(self) -> dict[str, object] | None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return None
        if length <= 0 or length > self._MAX_BODY_BYTES:
            return None
        raw = self.rfile.read(length)
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None
        return parsed if isinstance(parsed, dict) else None

    def _handle_settings_update(self, payload: dict[str, object]) -> None:
        settings = payload.get("settings")
        if not isinstance(settings, dict):
            self._write_json({"error": "invalid_settings"}, status=400)
            return
        guard_home = self.server.store.guard_home  # type: ignore[attr-defined]
        gate_payload = settings.get("approval_gate")
        gate_input = (
            approval_gate_input_from_mapping({"approval_gate": gate_payload})
            if isinstance(gate_payload, dict)
            else None
        )
        if payload.get("approval_password") or payload.get("approval_totp_code"):
            proof_input = approval_gate_input_from_mapping(payload)
            if proof_input is not None:
                gate_input = proof_input
        try:
            approval_gate_grant = require_high_risk(
                guard_home,
                purpose="settings_write",
                approval_gate_input=gate_input,
            )
            if isinstance(gate_payload, dict):
                validate_approval_gate_settings(
                    guard_home,
                    gate_payload,
                    approval_gate_grant=approval_gate_grant,
                )
            config_settings = {key: value for key, value in settings.items() if key != "approval_gate"}
            config = update_guard_settings(guard_home, config_settings, approval_gate_grant=approval_gate_grant)
            if isinstance(gate_payload, dict):
                update_approval_gate_settings(
                    guard_home,
                    gate_payload,
                    approval_gate_grant=approval_gate_grant,
                )
                config = load_guard_config(guard_home)
        except ApprovalGateError as error:
            self._write_approval_gate_error(error)
            return
        except ValueError as error:
            self._write_json({"error": "invalid_settings", "message": str(error)}, status=400)
            return
        self._write_json(_settings_response_payload(guard_home, editable_guard_settings(config)))

    def _handle_settings_import(self, payload: dict[str, object]) -> None:
        settings = payload.get("settings")
        if not isinstance(settings, dict):
            self._write_json({"error": "invalid_settings_import"}, status=400)
            return
        guard_home = self.server.store.guard_home  # type: ignore[attr-defined]
        gate_payload = settings.get("approval_gate")
        gate_input = (
            approval_gate_input_from_mapping({"approval_gate": gate_payload})
            if isinstance(gate_payload, dict)
            else None
        )
        if payload.get("approval_password") or payload.get("approval_totp_code"):
            proof_input = approval_gate_input_from_mapping(payload)
            if proof_input is not None:
                gate_input = proof_input
        try:
            approval_gate_grant = require_high_risk(
                guard_home,
                purpose="settings_write",
                approval_gate_input=gate_input,
            )
            if isinstance(gate_payload, dict):
                validate_approval_gate_settings(
                    guard_home,
                    gate_payload,
                    approval_gate_grant=approval_gate_grant,
                )
            config_settings = {key: value for key, value in settings.items() if key != "approval_gate"}
            config = update_guard_settings(guard_home, config_settings, approval_gate_grant=approval_gate_grant)
            if isinstance(gate_payload, dict):
                update_approval_gate_settings(
                    guard_home,
                    gate_payload,
                    approval_gate_grant=approval_gate_grant,
                )
                config = load_guard_config(guard_home)
        except ApprovalGateError as error:
            self._write_approval_gate_error(error)
            return
        except ValueError as error:
            self._write_json({"error": "invalid_settings", "message": str(error)}, status=400)
            return
        self._write_json(_settings_response_payload(guard_home, editable_guard_settings(config)))

    def _handle_settings_reset(self, payload: dict[str, object]) -> None:
        confirm = payload.get("confirm")
        if confirm != "reset-local-settings":
            self._write_json({"error": "confirmation_required", "confirm": "reset-local-settings"}, status=400)
            return
        guard_home = self.server.store.guard_home  # type: ignore[attr-defined]
        try:
            approval_gate_grant = require_high_risk(
                guard_home,
                purpose="settings_write",
                approval_gate_input=approval_gate_input_from_mapping(payload),
            )
            config = reset_guard_settings(guard_home, approval_gate_grant=approval_gate_grant)
        except ApprovalGateError as error:
            self._write_approval_gate_error(error)
            return
        self._write_json(_settings_response_payload(guard_home, editable_guard_settings(config)))

    def _handle_approval_gate_cooldown_revoke(self, payload: dict[str, object]) -> None:
        guard_home = self.server.store.guard_home  # type: ignore[attr-defined]
        try:
            require_high_risk(
                guard_home,
                purpose="settings_write",
                approval_gate_input=approval_gate_input_from_mapping(payload),
            )
        except ApprovalGateError as error:
            self._write_approval_gate_error(error)
            return
        gate = revoke_approval_gate_cooldown(guard_home).to_dict()
        config = load_guard_config(guard_home)
        settings = editable_guard_settings(config)
        settings["approval_gate"] = gate
        self._write_json(_settings_response_payload(guard_home, settings))

    def _handle_approval_gate_totp_enroll(self, payload: dict[str, object]) -> None:
        guard_home = self.server.store.guard_home  # type: ignore[attr-defined]
        device_label = self._optional_string(payload.get("device_label")) or "local-device"
        try:
            enrollment = begin_totp_enrollment(
                guard_home,
                approval_gate_input=approval_gate_input_from_mapping(payload),
                device_label=device_label,
            )
        except ApprovalGateError as error:
            self._write_approval_gate_error(error)
            return
        config = load_guard_config(guard_home)
        settings = editable_guard_settings(config)
        settings["approval_gate"] = approval_gate_public_config(guard_home).to_dict()
        response = _settings_response_payload(guard_home, settings)
        response["enrollment"] = enrollment
        self._write_json(response)

    def _handle_approval_gate_totp_verify(self, payload: dict[str, object]) -> None:
        guard_home = self.server.store.guard_home  # type: ignore[attr-defined]
        try:
            gate = confirm_totp_enrollment(
                guard_home,
                approval_gate_input=approval_gate_input_from_mapping(payload),
            )
        except ApprovalGateError as error:
            self._write_approval_gate_error(error)
            return
        config = load_guard_config(guard_home)
        settings = editable_guard_settings(config)
        settings["approval_gate"] = gate.to_dict()
        self._write_json(_settings_response_payload(guard_home, settings))

    def _handle_approval_gate_totp_disable(self, payload: dict[str, object]) -> None:
        guard_home = self.server.store.guard_home  # type: ignore[attr-defined]
        try:
            gate = disable_totp(
                guard_home,
                approval_gate_input=approval_gate_input_from_mapping(payload),
            )
        except ApprovalGateError as error:
            self._write_approval_gate_error(error)
            return
        config = load_guard_config(guard_home)
        settings = editable_guard_settings(config)
        settings["approval_gate"] = gate.to_dict()
        self._write_json(_settings_response_payload(guard_home, settings))

    def _handle_initialize(self, payload: dict[str, object]) -> None:
        client_name = self._optional_string(payload.get("client_name")) or "guard-client"
        surface = self._optional_string(payload.get("surface")) or "cli"
        capabilities = payload.get("capabilities")
        capability_items = (
            tuple(str(item) for item in capabilities if isinstance(item, str)) if isinstance(capabilities, list) else ()
        )
        supported_versions = payload.get("supported_protocol_versions")
        try:
            response = self.server.runtime.initialize_client(  # type: ignore[attr-defined]
                client_name=client_name,
                client_title=self._optional_string(payload.get("client_title")),
                version=self._optional_string(payload.get("version")),
                surface=surface,
                capabilities=capability_items,
                supported_protocol_versions=tuple(str(item) for item in supported_versions if isinstance(item, str))
                if isinstance(supported_versions, list)
                else (),
            )
        except ValueError as error:
            self._write_json({"error": str(error)}, status=400)
            return
        refreshed_session_token = self._refresh_dashboard_session_token(surface=surface)
        if refreshed_session_token is not None:
            response["dashboard_session_token"] = refreshed_session_token
        self._write_json(response)

    def _handle_client_attach(self, payload: dict[str, object]) -> None:
        client_id = self._optional_string(payload.get("client_id"))
        surface = self._optional_string(payload.get("surface"))
        if client_id is None or surface is None:
            self._write_json({"attached": False, "error": "missing_required_fields"}, status=400)
            return
        try:
            attachment = self.server.runtime.attach_client(  # type: ignore[attr-defined]
                client_id=client_id,
                surface=surface,
                session_id=self._optional_string(payload.get("session_id")),
                metadata={"title": self._optional_string(payload.get("client_title")) or surface},
                lease_seconds=self._optional_int(payload.get("lease_seconds")) or 60,
            )
        except ValueError as error:
            self._write_json({"attached": False, "error": str(error)}, status=400)
            return
        self._write_json({"attached": True, "item": attachment})

    def _handle_client_heartbeat(self, payload: dict[str, object]) -> None:
        client_id = self._optional_string(payload.get("client_id"))
        lease_id = self._optional_string(payload.get("lease_id"))
        if client_id is None or lease_id is None:
            self._write_json({"renewed": False, "error": "missing_required_fields"}, status=400)
            return
        try:
            attachment = self.server.runtime.renew_client(  # type: ignore[attr-defined]
                client_id=client_id,
                lease_id=lease_id,
                lease_seconds=self._optional_int(payload.get("lease_seconds")) or 60,
            )
        except ValueError as error:
            self._write_json({"renewed": False, "error": str(error)}, status=404)
            return
        self._write_json({"renewed": True, "item": attachment})

    def _handle_session_start(self, payload: dict[str, object]) -> None:
        harness = self._optional_string(payload.get("harness"))
        surface = self._optional_string(payload.get("surface"))
        client_name = self._optional_string(payload.get("client_name"))
        if harness is None or surface is None or client_name is None:
            self._write_json({"error": "missing_required_fields"}, status=400)
            return
        capabilities = payload.get("capabilities")
        session = self.server.runtime.start_session(  # type: ignore[attr-defined]
            harness=harness,
            surface=surface,
            workspace=self._optional_string(payload.get("workspace")),
            client_name=client_name,
            client_title=self._optional_string(payload.get("client_title")),
            client_version=self._optional_string(payload.get("client_version")),
            capabilities=tuple(str(item) for item in capabilities if isinstance(item, str))
            if isinstance(capabilities, list)
            else (),
        )
        self._write_json(session)

    def _handle_operation_start(self, payload: dict[str, object]) -> None:
        session_id = self._optional_string(payload.get("session_id"))
        operation_type = self._optional_string(payload.get("operation_type"))
        harness = self._optional_string(payload.get("harness"))
        if session_id is None or operation_type is None or harness is None:
            self._write_json({"error": "missing_required_fields"}, status=400)
            return
        metadata = payload.get("metadata")
        try:
            operation = self.server.runtime.start_operation(  # type: ignore[attr-defined]
                session_id=session_id,
                operation_type=operation_type,
                harness=harness,
                metadata=metadata if isinstance(metadata, dict) else {},
            )
        except ValueError as error:
            self._write_json({"error": str(error)}, status=400)
            return
        self._write_json(operation)

    def _handle_operation_block(self, payload: dict[str, object]) -> None:
        session_id = self._optional_string(payload.get("session_id"))
        operation_type = self._optional_string(payload.get("operation_type"))
        harness = self._optional_string(payload.get("harness"))
        approval_center_url = self._optional_string(payload.get("approval_center_url"))
        approval_surface_policy = self._optional_string(payload.get("approval_surface_policy"))
        detection = payload.get("detection")
        evaluation = payload.get("evaluation")
        if (
            session_id is None
            or operation_type is None
            or harness is None
            or approval_center_url is None
            or approval_surface_policy is None
            or not _is_string_object_dict(detection)
            or not _is_string_object_dict(evaluation)
        ):
            self._write_json({"error": "missing_required_fields"}, status=400)
            return
        metadata = payload.get("metadata")
        try:
            redaction_level = self._optional_string(payload.get("redaction_level")) or "full"
            response = self.server.runtime.queue_blocked_operation(  # type: ignore[attr-defined]
                session_id=session_id,
                operation_type=operation_type,
                harness=harness,
                metadata=metadata if _is_string_object_dict(metadata) else {},
                detection=detection,
                evaluation=evaluation,
                approval_center_url=approval_center_url,
                browser_url=_approval_center_browser_url(approval_center_url, self.server.auth_token),  # type: ignore[attr-defined]
                approval_surface_policy=approval_surface_policy,
                open_key=self._optional_string(payload.get("open_key")),
                opener=webbrowser.open,
                redaction_level=redaction_level,
            )
        except ValueError as error:
            self._write_json({"error": str(error)}, status=400)
            return
        surface = response.get("surface")
        operation = response.get("operation")
        requests = response.get("approval_requests")
        if (
            isinstance(surface, dict)
            and surface.get("reason") == "attention-deferred"
            and isinstance(operation, dict)
            and isinstance(operation.get("operation_id"), str)
            and isinstance(requests, list)
        ):
            typed_requests = [request for request in requests if _is_string_object_dict(request)]
            first_url: str | None = None
            for request in typed_requests:
                candidate_url = request.get("approval_url")
                if isinstance(candidate_url, str):
                    first_url = candidate_url
                    break
            browser_url = build_approval_browser_url(first_url, auth_token=self.server.auth_token)  # type: ignore[attr-defined]
            if browser_url is not None:
                self.server.approval_attention.schedule(  # type: ignore[attr-defined]
                    operation_id=str(operation["operation_id"]),
                    requests=typed_requests,
                    browser_url=browser_url,
                )
        self._write_json(response)

    def _handle_operation_item(self, operation_id: str, payload: dict[str, object]) -> None:
        item_type = self._optional_string(payload.get("item_type"))
        item_payload = payload.get("payload")
        if item_type is None or not isinstance(item_payload, dict):
            self._write_json({"error": "missing_required_fields"}, status=400)
            return
        try:
            item = self.server.runtime.add_item(  # type: ignore[attr-defined]
                operation_id=operation_id,
                item_type=item_type,
                payload=item_payload,
            )
        except ValueError as error:
            self._write_json({"error": str(error)}, status=400)
            return
        self._write_json({"item": item})

    def _handle_operation_status(self, operation_id: str, payload: dict[str, object]) -> None:
        status = self._optional_string(payload.get("status"))
        if status is None:
            self._write_json({"error": "missing_required_fields"}, status=400)
            return
        request_ids = payload.get("approval_request_ids")
        try:
            operation = self.server.runtime.update_operation_status(  # type: ignore[attr-defined]
                operation_id=operation_id,
                status=status,
                approval_request_ids=[str(item) for item in request_ids if isinstance(item, str)]
                if isinstance(request_ids, list)
                else [],
            )
        except ValueError as error:
            self._write_json({"error": str(error)}, status=400)
            return
        self._write_json({"operation": operation})

    def _handle_session_resume(self, session_id: str) -> None:
        try:
            payload = self.server.runtime.resume_session(session_id)  # type: ignore[attr-defined]
        except ValueError:
            self._write_json({"error": "not_found"}, status=404)
            return
        self._write_json(payload)

    def _handle_request_resume_read(self, request_id: str) -> None:
        if self.server.store.get_approval_request(request_id) is None:  # type: ignore[attr-defined]
            self._write_json({"error": "not_found"}, status=404)
            return
        payload = get_request_resume_status(self.server.store, request_id=request_id, now=_now())  # type: ignore[attr-defined]
        if payload is None:
            self._write_json({"error": "not_found"}, status=404)
            return
        self._write_json(payload)

    def _handle_request_resume_retry(self, request_id: str) -> None:
        try:
            payload = retry_request_resume(self.server.store, request_id=request_id, now=_now(), force=False)  # type: ignore[attr-defined]
        except ValueError as error:
            error_code = str(error)
            if error_code == "not_found":
                self._write_json({"error": "not_found"}, status=404)
                return
            if error_code == "not_resolved":
                self._write_json({"error": "not_resolved"}, status=409)
                return
            self._write_json({"error": "resume_not_supported"}, status=400)
            return
        self.server.store.add_event(  # type: ignore[attr-defined]
            "codex/thread_resume",
            {"request_id": request_id, "action": payload.get("resolution_action"), **payload},
            _now(),
        )
        self._write_json(payload)

    def _apply_codex_resume_result(
        self,
        *,
        updated: dict[str, object],
        request_id: str,
        action: str,
        copy: dict[str, str],
        codex_resume: dict[str, object],
    ) -> dict[str, object]:
        updated["codex_resume"] = codex_resume
        self.server.store.add_event(  # type: ignore[attr-defined]
            "codex/thread_resume",
            {"request_id": request_id, "action": action, **codex_resume},
            _now(),
        )
        status = str(codex_resume.get("status") or "")
        message = str(codex_resume.get("message") or "")
        if status == "sent":
            updated["resolution_summary"] = (
                "Decision saved. HOL Guard sent Codex a continue prompt in the original thread."
            )
            copy = {
                "title": "Decision saved. Codex chat was notified.",
                "body": message,
            }
        elif status in {"pending", "in_progress"}:
            updated["resolution_summary"] = message or "Decision saved. Codex is still waiting for HOL Guard."
            copy = {
                "title": "Decision saved. Codex is continuing.",
                "body": message or "Return to Codex; the original action should continue automatically.",
            }
        elif status == "already_sent":
            updated["resolution_summary"] = "Decision saved. Codex was already notified for this request."
            copy = {
                "title": "Decision saved. Codex already notified.",
                "body": message,
            }
        else:
            updated["resolution_summary"] = message or str(updated.get("resolution_summary") or "Decision saved.")
            copy = {
                "title": (
                    "Decision saved. Return to Codex."
                    if status == "skipped"
                    else "Decision saved. Codex chat could not be notified."
                ),
                "body": message or copy["body"],
            }
        updated["copy"] = copy
        updated["retry_hint"] = copy["body"]
        return updated

    def _apply_harness_resume_result(
        self,
        *,
        updated: dict[str, object],
        harness_resume: dict[str, object],
    ) -> dict[str, object]:
        updated["harness_resume"] = harness_resume
        updated["harnessResume"] = harness_resume
        return updated

    def _codex_resume_after_remote_once(
        self,
        *,
        request_id: str,
        action: str,
    ) -> dict[str, object] | None:
        try:
            codex_resume = defer_request_resume_to_live_hook(
                self.server.store,  # type: ignore[attr-defined]
                request_id=request_id,
                action=action,
                now=_now(),
            )
            if codex_resume is None:
                codex_resume = retry_request_resume(
                    self.server.store,  # type: ignore[attr-defined]
                    request_id=request_id,
                    now=_now(),
                )
            return safe_resume_metadata(codex_resume)
        except ResumeNotSupportedError:
            return {
                "status": "skipped",
                "reason": "resume_not_supported",
                "message": "This Codex request does not expose a supported resume target.",
            }
        except ValueError as error:
            return {
                "status": "failed",
                "reason": str(error) or "resume_failed",
                "message": "HOL Guard could not resume the Codex request after applying the remote decision.",
            }

    def _write_legacy_pairing_disabled(self) -> None:
        self._write_json(
            {
                "error": "legacy_pairing_disabled",
                "message": "Use hol-guard connect for browser OAuth.",
            },
            status=410,
        )

    def _write_legacy_cloud_handoff_disabled(self) -> None:
        self._write_json(
            {
                "error": "legacy_cloud_handoff_disabled",
                "message": "Use hol-guard connect for browser OAuth.",
            },
            status=410,
        )

    def _handle_runtime_hook(self, payload: dict[str, object], query: str, *, default_harness: str) -> None:
        params = parse_qs(query)
        hook_env = _runtime_hook_env_overlay_from_payload(payload)
        payload = {key: value for key, value in payload.items() if key != "hook_env"}
        try:
            home_dir = self._validated_hook_directory_string(
                "home",
                self._optional_string(params.get("home", [None])[-1]),
                roots=self._hook_safe_roots(),
            )
            guard_home = self._validated_hook_guard_home(self._optional_string(params.get("guard-home", [None])[-1]))
            workspace = self._validated_hook_directory_string(
                "workspace",
                self._normalized_hook_workspace_string(params.get("workspace", [None])[-1]),
                roots=self._hook_safe_roots(),
            )
        except _HookPathValidationError as error:
            self._record_hook_path_rejection(parameter=error.parameter, reason=error.reason)
            self._write_json({"error": error.code}, status=400)
            return

        # Fast path: use the resident hook worker for supported hooks.
        if self._hook_fast_path_enabled():
            result = self._handle_runtime_hook_fast(
                payload,
                params,
                default_harness=default_harness,
                home_dir=home_dir,
                guard_home=guard_home,
                workspace=workspace,
            )
            if result is not None:
                self._write_json(result)
                return

        # Legacy CLI path.
        self._handle_runtime_hook_legacy_cli(
            payload,
            params,
            hook_env=hook_env,
            default_harness=default_harness,
            home_dir=home_dir,
            guard_home=guard_home,
            workspace=workspace,
        )

    def _hook_fast_path_enabled(self) -> bool:
        from ..config import hook_fast_path_enabled

        return hook_fast_path_enabled()

    def _handle_runtime_hook_fast(
        self,
        payload: dict[str, object],
        params: Mapping[str, list[str]],
        *,
        default_harness: str,
        home_dir: str | None,
        guard_home: str | None,
        workspace: str | None,
    ) -> dict[str, object] | None:
        """Try the resident hook worker. Return None to fall back to legacy.

        The worker only handles ``PostToolUse`` with ``guard_source_ref``.
        ``HookWorkerUnsupported`` means the event is not eligible for the
        fast path — return ``None`` so the caller falls through to the
        legacy CLI path, preserving existing policy/permission checks.

        Any other exception is a real failure — deny/block rather than
        fall back, because the request may have omitted full output and
        supplied only ``guard_source_ref``.
        """
        from .hook_worker import HookWorkerUnsupported, post_tool_fail_safe_response

        if home_dir is None or guard_home is None:
            return None

        try:
            worker = self._daemon_server().hook_worker
            return worker.review_http_payload(
                payload=payload,
                params=params,
                default_harness=default_harness,
                home_dir=Path(home_dir),
                guard_home=Path(guard_home),
                workspace=Path(workspace) if workspace else None,
            )
        except HookWorkerUnsupported:
            # Not eligible for fast path — fall back to legacy CLI so
            # PreToolUse/PermissionRequest/PostToolUse-without-source-ref
            # still get full policy/permission/approval checks.
            return None
        except Exception:
            # Fail safe: deny/block. Do not fall back to legacy CLI for
            # requests that omitted full output and supplied only guard_source_ref.
            rt_values = params.get("runtime-harness", [])
            actual_harness = (
                rt_values[-1].strip()
                if rt_values and isinstance(rt_values[-1], str) and rt_values[-1].strip()
                else default_harness
            )
            return post_tool_fail_safe_response(
                actual_harness,
                reason="HOL Guard could not complete local hook review safely.",
                reason_code="daemon_worker_exception",
            )

    def _handle_runtime_hook_legacy_cli(
        self,
        payload: dict[str, object],
        params: Mapping[str, list[str]],
        *,
        hook_env: dict[str, str],
        default_harness: str,
        home_dir: str | None,
        guard_home: str | None,
        workspace: str | None,
    ) -> None:
        runtime_harness = self._optional_string(params.get("runtime-harness", [None])[-1])
        harness = runtime_harness or default_harness
        args = argparse.Namespace(
            guard_command="hook",
            home=home_dir,
            guard_home=guard_home,
            workspace=workspace,
            runtime_harness=runtime_harness,
            harness=harness,
            artifact_id=None,
            artifact_name=None,
            policy_action=None,
            event_file=None,
            json=True,
        )
        buffer = io.StringIO()
        with _CLAUDE_HOOK_EXECUTION_LOCK:
            from ..cli.commands import run_guard_command

            original_env: dict[str, str | None] = {key: os.environ.get(key) for key in hook_env}
            try:
                os.environ.update(hook_env)
                exit_code = run_guard_command(args, input_text=json.dumps(payload), output_stream=buffer)
            finally:
                for key, original in original_env.items():
                    if original is None:
                        os.environ.pop(key, None)
                    else:
                        os.environ[key] = original
        raw_response = buffer.getvalue().strip()
        if not raw_response:
            if exit_code == 0:
                self._write_json({})
                return
            self._write_json({"error": "empty_hook_response", "exit_code": exit_code}, status=502)
            return
        try:
            hook_payload = json.loads(raw_response)
        except json.JSONDecodeError:
            self._write_json(
                {"error": "invalid_hook_response", "raw": raw_response, "exit_code": exit_code},
                status=502,
            )
            return
        self._write_json(hook_payload)

    def _query_has_guard_token(self, query: str) -> bool:
        return any(key == "token" for key, _value in parse_qsl(query, keep_blank_values=True))

    def _handle_daemon_identity_challenge(self, payload: dict[str, object]) -> None:
        nonce = self._optional_string(payload.get("nonce"))
        hook_event = self._optional_string(payload.get("hook_event"))
        state_id = self._optional_string(payload.get("state_id"))
        protocol_version = payload.get("protocol_version")
        if (
            nonce is None
            or len(nonce) != 64
            or any(character not in "0123456789abcdef" for character in nonce.lower())
            or hook_event is None
            or len(hook_event) > 128
            or state_id is None
            or protocol_version != DAEMON_DISCOVERY_PROTOCOL_VERSION
        ):
            self._write_json({"error": "invalid_daemon_identity_challenge"}, status=400)
            return
        daemon_server = self._daemon_server()
        guard_home = daemon_server.store.guard_home
        state = load_authenticated_daemon_state(guard_home)
        discovery_key = load_daemon_discovery_key(guard_home)
        if state is None or discovery_key is None:
            self._write_json({"error": "daemon_identity_unavailable"}, status=503)
            return
        expected_guard_home = str(guard_home.resolve())
        if (
            state.get("state_id") != state_id
            or state.get("guard_home") != expected_guard_home
            or state.get("host") != daemon_server.daemon_host()
            or state.get("port") != daemon_server.daemon_port()
            or state.get("pid") != os.getpid()
        ):
            self._write_json({"error": "daemon_identity_state_mismatch"}, status=409)
            return
        issued_at_ms = int(time.time() * 1000)
        expires_at_ms = issued_at_ms + DAEMON_DISCOVERY_CHALLENGE_TTL_SECONDS * 1000
        response = authenticated_challenge_payload(
            discovery_key=discovery_key,
            state=state,
            nonce=nonce,
            hook_event=hook_event,
            issued_at_ms=issued_at_ms,
            expires_at_ms=expires_at_ms,
        )
        with daemon_server.daemon_discovery_challenges_lock:
            expired: list[str] = []
            for candidate, item in daemon_server.daemon_discovery_challenges.items():
                candidate_expiry = item.get("expires_at_ms")
                if not isinstance(candidate_expiry, int) or candidate_expiry < issued_at_ms:
                    expired.append(candidate)
            for candidate in expired:
                daemon_server.daemon_discovery_challenges.pop(candidate, None)
            if len(daemon_server.daemon_discovery_challenges) >= 256:
                oldest = next(iter(daemon_server.daemon_discovery_challenges))
                daemon_server.daemon_discovery_challenges.pop(oldest, None)
            daemon_server.daemon_discovery_challenges[nonce] = {
                "proof": response["proof"],
                "hook_event": hook_event,
                "expires_at_ms": expires_at_ms,
                "connection_id": id(self.connection),
                "state_id": state_id,
            }
        self.close_connection = False
        # The handler intentionally remains HTTP/1.0 for the rest of the daemon,
        # but this two-step proof must stay on one TCP connection.  Advertise an
        # HTTP/1.1 response for this request only; the response has an explicit
        # Content-Length, so http.client can safely reuse the socket for the
        # authenticated hook request.  ``close_connection = False`` also tells
        # BaseHTTPRequestHandler to read that next request on this handler.
        self.connection.settimeout(DAEMON_DISCOVERY_CHALLENGE_TTL_SECONDS)
        previous_protocol_version = self.protocol_version
        self.protocol_version = "HTTP/1.1"
        try:
            self._write_json(response, extra_headers={"Cache-Control": "no-store"})
        finally:
            self.protocol_version = previous_protocol_version

    def _consume_codex_daemon_challenge(self, payload: dict[str, object]) -> bool:
        nonce = self.headers.get("X-Guard-Daemon-Nonce")
        proof = self.headers.get("X-Guard-Daemon-Proof")
        if not isinstance(nonce, str) or not isinstance(proof, str):
            return False
        daemon_server = self._daemon_server()
        with daemon_server.daemon_discovery_challenges_lock:
            challenge = daemon_server.daemon_discovery_challenges.pop(nonce, None)
        if challenge is None:
            return False
        expires_at_ms = challenge.get("expires_at_ms")
        expected_proof = challenge.get("proof")
        if (
            not isinstance(expires_at_ms, int)
            or expires_at_ms < int(time.time() * 1000)
            or challenge.get("connection_id") != id(self.connection)
            or not isinstance(expected_proof, str)
            or not secrets.compare_digest(proof, expected_proof)
        ):
            return False
        event = payload.get("hook_event_name", payload.get("event"))
        return isinstance(event, str) and event.strip() == challenge.get("hook_event")

    def _write_unauthorized(self, *, extra_headers: dict[str, str] | None = None) -> None:
        self._record_auth_audit_event()
        self._write_json({"error": "unauthorized"}, status=401, extra_headers=extra_headers)

    def _daemon_server(self) -> _GuardDaemonHttpServer:
        return cast(_GuardDaemonHttpServer, self.server)

    def _record_auth_audit_event(self) -> None:
        origin = self.headers.get("Origin")
        self._daemon_server().store.add_event(
            "daemon.auth.unauthorized",
            {
                "method": self.command,
                "path": urlparse(self.path).path,
                "origin": self._normalize_origin(origin),
                "origin_header": origin if isinstance(origin, str) and origin.strip() else None,
                "has_authorization": isinstance(self.headers.get("Authorization"), str),
                "has_dashboard_session": isinstance(self.headers.get("X-Guard-Dashboard-Session"), str),
                "has_guard_token": isinstance(self.headers.get("X-Guard-Token"), str),
            },
            _now(),
        )

    def _record_query_token_rejection(self) -> None:
        self._daemon_server().store.add_event(
            "daemon.auth.query_token_rejected",
            {
                "method": self.command,
                "path": urlparse(self.path).path,
                "has_query_token": True,
            },
            _now(),
        )

    def _record_hook_path_rejection(self, *, parameter: str, reason: str) -> None:
        self._daemon_server().store.add_event(
            "daemon.hook.path_rejected",
            {
                "method": self.command,
                "path": urlparse(self.path).path,
                "parameter": parameter,
                "reason": reason,
            },
            _now(),
        )

    def _header_token_is_valid(self, *, payload: dict[str, object] | None = None) -> bool:
        token = self.headers.get("X-Guard-Token")
        path = urlparse(self.path).path
        path_parts = [part for part in path.split("/") if part]
        return self._tokens_match(token) or (
            self._path_supports_dashboard_session(path, path_parts)
            and self._dashboard_session_token_is_valid(payload=payload)
        )

    def _dashboard_session_token_is_valid(self, *, payload: dict[str, object] | None = None) -> bool:
        session_token = self.headers.get("X-Guard-Dashboard-Session")
        authorization = self.headers.get("Authorization")
        bearer_token = None
        if isinstance(authorization, str) and authorization.lower().startswith("bearer "):
            bearer_token = authorization[7:].strip()
        candidates = [
            candidate for candidate in (session_token, bearer_token) if isinstance(candidate, str) and candidate.strip()
        ]
        return any(self._dashboard_session_token_matches(candidate, payload=payload) for candidate in candidates)

    def _dashboard_session_token_matches(self, token: str, *, payload: dict[str, object] | None = None) -> bool:
        claims = self._dashboard_session_token_claims(token)
        if claims is None:
            return False
        return self._dashboard_session_claims_authorize_request(claims, payload=payload)

    def _dashboard_session_token_claims(
        self,
        token: str,
        *,
        allow_expired_within_seconds: float = 0.0,
    ) -> dict[str, object] | None:
        if not token.startswith("gld1."):
            return None
        parts = token.split(".")
        if len(parts) != 3:
            return None
        prefix, encoded_payload, signature = parts
        if prefix != "gld1" or not encoded_payload or not signature:
            return None
        expected = _dashboard_session_signature(encoded_payload, self.server.auth_token)  # type: ignore[attr-defined]
        if not secrets.compare_digest(signature, expected):
            return None
        claims = _decode_dashboard_session_payload(encoded_payload)
        if self._optional_string(claims.get("aud")) != LOCAL_DASHBOARD_SESSION_AUDIENCE:
            return None
        expires_at = claims.get("expires_at")
        if not isinstance(expires_at, str):
            return None
        try:
            expires_at_timestamp = _parse_iso_timestamp(expires_at)
        except ValueError:
            return None
        if expires_at_timestamp + max(0.0, allow_expired_within_seconds) <= time.time():
            return None
        return claims

    def _refresh_dashboard_session_token(self, *, surface: str) -> str | None:
        if self._refreshable_dashboard_session_claims() is None:
            return None
        refreshed_surface = surface if surface in {"approval-center", "dashboard", "cloud-dashboard"} else "dashboard"
        return build_local_dashboard_session_token(
            auth_token=self.server.auth_token,  # type: ignore[attr-defined]
            surface=refreshed_surface,
        )

    def _refreshable_dashboard_session_claims(self) -> dict[str, object] | None:
        session_token = self.headers.get("X-Guard-Dashboard-Session")
        authorization = self.headers.get("Authorization")
        bearer_token = None
        if isinstance(authorization, str) and authorization.lower().startswith("bearer "):
            bearer_token = authorization[7:].strip()
        candidates = [
            candidate for candidate in (session_token, bearer_token) if isinstance(candidate, str) and candidate.strip()
        ]
        for candidate in candidates:
            claims = self._dashboard_session_token_claims(
                candidate,
                allow_expired_within_seconds=_LOCAL_DASHBOARD_SESSION_REFRESH_GRACE_SECONDS,
            )
            if claims is None:
                continue
            surface = self._optional_string(claims.get("surface"))
            if surface in {"approval-center", "dashboard", "cloud-dashboard"}:
                return claims
        return None

    def _dashboard_session_claims_authorize_request(
        self,
        claims: dict[str, object],
        *,
        payload: dict[str, object] | None,
    ) -> bool:
        surface = self._optional_string(claims.get("surface"))
        path = urlparse(self.path).path
        path_parts = [part for part in path.split("/") if part]
        if surface in {"approval-center", "dashboard", "cloud-dashboard"}:
            return self._path_supports_dashboard_session(path, path_parts)
        action_path = self._optional_string(claims.get("action_path"))
        if action_path is None:
            return False
        if self.command == "GET" and self._dashboard_session_scoped_read_path_is_allowed(claims, path):
            return self._dashboard_session_scoped_nonce_matches_request(claims=claims, payload=payload)
        if (
            len(path_parts) == 3
            and path_parts[:2] == ["v1", "apps"]
            and path_parts[2] in _cloud_app_dashboard_session_actions(action_path)
        ):
            if payload is None:
                return False
            harness = self._optional_string(claims.get("harness"))
            location_id = self._optional_string(claims.get("location_id"))
            workspace_id = self._optional_string(claims.get("workspace_id")) or ""
            payload_harness = self._optional_string(payload.get("harness"))
            payload_location_id = self._optional_string(payload.get("location_id")) or self._optional_string(
                payload.get("locationId")
            )
            payload_workspace_id = self._optional_string(payload.get("workspace_id")) or ""
            return (
                harness is not None
                and payload_harness == harness
                and (not location_id or payload_location_id == location_id)
                and (not workspace_id or payload_workspace_id == workspace_id)
            )
        supply_chain_action = self._supply_chain_claim_action_for_request(path, path_parts)
        if supply_chain_action is not None:
            return self._supply_chain_dashboard_claims_authorize(
                claims,
                payload=payload,
                supply_chain_action=supply_chain_action,
            )
        return False

    def _dashboard_session_scoped_read_path_is_allowed(self, claims: dict[str, object], path: str) -> bool:
        allowed_read_paths = claims.get("allowed_read_paths")
        if not isinstance(allowed_read_paths, list):
            return False
        return path in {item for item in allowed_read_paths if isinstance(item, str)}

    def _dashboard_session_scoped_nonce_matches_request(
        self,
        *,
        claims: dict[str, object],
        payload: dict[str, object] | None,
    ) -> bool:
        claim_nonce = self._optional_string(claims.get("nonce"))
        if claim_nonce is None:
            return True
        request_nonce = self._optional_string(self.headers.get("X-Guard-Dashboard-Nonce"))
        if request_nonce is None and payload is not None:
            request_nonce = self._optional_string(payload.get("dashboard_session_nonce"))
        return request_nonce == claim_nonce

    def _local_surface_session_request_is_allowed(self, path: str, path_parts: list[str]) -> bool:
        if path in {
            "/v1/capabilities",
            "/v1/sessions",
            "/v1/runtime",
            "/v1/harnesses",
            "/v1/inventory",
            "/v1/settings",
            "/v1/settings/export",
            "/v1/events",
            "/v1/events/stream",
            "/v1/requests",
            "/v1/receipts",
            "/v1/receipts/analytics",
            "/v1/insights/share",
            "/v1/cloud/connect",
            "/v1/receipts/latest",
            "/v1/policy",
            "/v1/policy/cloud-exceptions",
            "/v1/evidence",
            "/v1/evidence/export",
            "/v1/clients/attach",
            "/v1/clients/heartbeat",
            "/v1/sessions/start",
            "/v1/operations/start",
            "/v1/operations/block",
            "/v1/policy/sync",
            "/v1/requests/clear",
            "/v1/requests/bulk-allow-once",
            "/v1/requests/remote-once",
            "/v1/settings/import",
            "/v1/settings/reset",
            "/v1/read-state",
            "/v1/policy/clear",
            "/v1/approval-gate/cooldown/revoke",
            "/v1/approval-gate/totp/enroll",
            "/v1/approval-gate/totp/verify",
            "/v1/approval-gate/totp/disable",
            "/v1/daemon/repair",
            "/v1/notifications/setup",
            "/v1/update/status",
        }:
            return True
        # Hosted dashboard access is blocked for these routes, but local
        # loopback/dashboard sessions still use them until the route deletion
        # slice lands.
        if len(path_parts) == 3 and path_parts[:2] == ["v1", "apps"] and path_parts[2] in _HEADLESS_APP_ACTIONS:
            return True
        if len(path_parts) >= 2 and path_parts[:2] == ["v1", "supply-chain"]:
            return True
        if self.command == "GET":
            if len(path_parts) == 3 and path_parts[:2] in (
                ["v1", "requests"],
                ["v1", "receipts"],
                ["v1", "operations"],
            ):
                return True
            if len(path_parts) == 4 and path_parts[:2] == ["v1", "sessions"] and path_parts[3] == "resume":
                return True
        if self.command == "POST":
            if path == "/v1/update":
                return True
            if (
                len(path_parts) == 4
                and path_parts[:2] == ["v1", "requests"]
                and path_parts[3]
                in {
                    "approve",
                    "block",
                    "resume",
                }
            ):
                return True
            if (
                len(path_parts) == 4
                and path_parts[:2] == ["v1", "operations"]
                and path_parts[3]
                in {
                    "items",
                    "status",
                }
            ):
                return True
        return False

    def _path_supports_dashboard_session(self, path: str, path_parts: list[str]) -> bool:
        return self._is_hosted_dashboard_api_path(path, path_parts) or self._local_surface_session_request_is_allowed(
            path,
            path_parts,
        )

    def _claim_string(self, claims: dict[str, object], *keys: str) -> str | None:
        for key in keys:
            value = self._optional_string(claims.get(key))
            if value is not None:
                return value
        return None

    def _enforce_package_firewall_rate_limit(
        self,
        operation: str,
        payload: dict[str, object],
    ) -> bool:
        workspace_id = (
            self._optional_string(payload.get("workspace_id"))
            or self._optional_string(payload.get("workspaceId"))
            or self.server.store.get_cloud_workspace_id()  # type: ignore[attr-defined]
            or "local"
        )
        rate_key = f"{workspace_id}:{operation}"
        allowed, retry_after = self.server.package_firewall_action_rate_limiter.allow(rate_key)  # type: ignore[attr-defined]
        if allowed:
            return True
        self._write_json(
            {
                "error": "rate_limited",
                "message": "Package firewall actions are temporarily rate limited.",
                "operation": operation,
                "retry_after_seconds": retry_after,
            },
            status=429,
        )
        return False

    def _consume_dashboard_session_nonce(self, nonce: str) -> bool:
        now = time.monotonic()
        ttl_seconds = 600.0
        with self.server.package_firewall_session_nonces_lock:  # type: ignore[attr-defined]
            stale_before = now - ttl_seconds
            stale_keys = [
                key for key, seen_at in self.server.package_firewall_session_nonces.items() if seen_at <= stale_before
            ]
            for key in stale_keys:
                del self.server.package_firewall_session_nonces[key]
            if nonce in self.server.package_firewall_session_nonces:
                return False
            self.server.package_firewall_session_nonces[nonce] = now
            return True

    def _supply_chain_dashboard_claims_authorize(
        self,
        claims: dict[str, object],
        *,
        payload: dict[str, object] | None,
        supply_chain_action: str,
    ) -> bool:
        action_path = self._optional_string(claims.get("action_path"))
        allowed_claim = claims.get("allowed_action_paths")
        allowed_actions = (
            {item for item in allowed_claim if isinstance(item, str)} if isinstance(allowed_claim, list) else set()
        )
        if supply_chain_action != action_path and supply_chain_action not in allowed_actions:
            return False
        claim_nonce = self._claim_string(claims, "nonce")
        if claim_nonce is not None and not self._consume_dashboard_session_nonce(claim_nonce):
            return False
        if payload is None:
            return supply_chain_action in {"package_shims_status", "supply_chain_bundle"}
        workspace_id = self._claim_string(claims, "workspace_id", "workspaceId") or ""
        payload_workspace_id = (
            self._optional_string(payload.get("workspace_id"))
            or self._optional_string(payload.get("workspaceId"))
            or ""
        )
        if workspace_id and payload_workspace_id != workspace_id:
            return False
        location_id = self._claim_string(claims, "location_id", "locationId")
        payload_location_id = (
            self._optional_string(payload.get("location_id")) or self._optional_string(payload.get("locationId")) or ""
        )
        if location_id and payload_location_id != location_id:
            return False
        daemon_origin = self._claim_string(claims, "daemon_origin", "daemonOrigin")
        if daemon_origin is not None:
            request_origin = self._normalize_origin(self.headers.get("Origin"))
            payload_origin = (
                self._optional_string(payload.get("daemon_origin"))
                or self._optional_string(payload.get("daemonOrigin"))
                or request_origin
            )
            if payload_origin != daemon_origin:
                return False
        managers_claim = claims.get("managers")
        if not isinstance(managers_claim, list):
            return True
        allowed_managers = {item for item in managers_claim if isinstance(item, str)}
        managers_value = payload.get("managers")
        if managers_value is None:
            return True
        if not isinstance(managers_value, list) or not all(isinstance(manager, str) for manager in managers_value):
            return False
        return set(managers_value).issubset(allowed_managers)

    @staticmethod
    def _supply_chain_claim_action_for_request(path: str, path_parts: list[str]) -> str | None:
        if path == "/v1/supply-chain/package-shims":
            return "package_shims_status"
        if path == "/v1/supply-chain/entitlement":
            return "supply_chain_entitlement"
        if path == "/v1/supply-chain/bundle":
            return "supply_chain_bundle"
        if len(path_parts) == 4 and path_parts[:3] == ["v1", "supply-chain", "package-shims"]:
            action = "remove" if path_parts[3] == "uninstall" else path_parts[3]
            if action in {"activate", "install", "repair", "test", "remove", "open-shell"}:
                return f"package_shims_{action}"
        if len(path_parts) == 3 and path_parts[:2] == ["v1", "supply-chain"] and path_parts[2] in {"audit", "sync"}:
            return f"package_shims_{path_parts[2]}"
        return None

    def _tokens_match(self, token: object) -> bool:
        if not isinstance(token, str):
            return False
        try:
            provided = token.encode("ascii")
            expected = self.server.auth_token.encode("ascii")  # type: ignore[attr-defined]
        except UnicodeEncodeError:
            return False
        return secrets.compare_digest(provided, expected)

    def _touch_runtime_heartbeat(self, path: str) -> None:
        if path != "/healthz" and not path.startswith("/v1/"):
            return
        self.server.last_activity_monotonic = time.monotonic()  # type: ignore[attr-defined]
        self.server.store.touch_runtime_state(  # type: ignore[attr-defined]
            session_id=self.server.runtime_session_id,  # type: ignore[attr-defined]
            last_heartbeat_at=_now(),
        )

    def _increment_active_stream_clients(self) -> None:
        with self.server.active_stream_clients_lock:  # type: ignore[attr-defined]
            self.server.active_stream_clients += 1  # type: ignore[attr-defined]

    def _decrement_active_stream_clients(self) -> None:
        with self.server.active_stream_clients_lock:  # type: ignore[attr-defined]
            self.server.active_stream_clients = max(0, self.server.active_stream_clients - 1)  # type: ignore[attr-defined]

    @staticmethod
    def _optional_int(value: object) -> int | None:
        if isinstance(value, int):
            return value
        if isinstance(value, str) and value.strip():
            try:
                return int(value.strip())
            except ValueError:
                return None
        return None

    def _stream_events(self, cursor: int) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        next_cursor = cursor
        self._increment_active_stream_clients()
        try:
            while True:
                self._touch_runtime_heartbeat("/v1/events/stream")
                items = self.server.store.list_events_after(next_cursor, limit=100)  # type: ignore[attr-defined]
                for item in items:
                    event_id = item.get("event_id")
                    if not isinstance(event_id, int):
                        continue
                    next_cursor = event_id
                    body = json.dumps(item)
                    try:
                        self.wfile.write(f"data: {body}\n\n".encode())
                        self.wfile.flush()
                    except BrokenPipeError:
                        return
                time.sleep(0.5)
        finally:
            self._decrement_active_stream_clients()

    def _origin_is_allowed_for_request(self, path: str, path_parts: list[str]) -> bool:
        origin = self.headers.get("Origin")
        if origin is None:
            return True
        normalized_origin = self._normalize_origin(origin)
        if normalized_origin is None:
            return False
        parsed = urlparse(normalized_origin)
        local_origin = parsed.hostname in {"127.0.0.1", "localhost", "::1"}
        if local_origin:
            return True
        return normalized_origin in _HOSTED_GUARD_DASHBOARD_ORIGINS and self._is_hosted_dashboard_api_path(
            path, path_parts
        )

    @staticmethod
    def _is_hosted_dashboard_api_path(path: str, path_parts: list[str]) -> bool:
        if path in {
            "/v1/capabilities",
            "/v1/connect/complete",
            "/v1/inventory",
            "/v1/connect/state",
            "/v1/daemon/repair",
            "/v1/evidence",
            "/v1/evidence/export",
            "/v1/harnesses",
            "/v1/notifications/setup",
            "/v1/policy",
            "/v1/policy/cloud-exceptions",
            "/v1/policy/cloud-exception-requests",
            "/v1/policy/clear",
            "/v1/receipts",
            "/v1/receipts/analytics",
            "/v1/insights/share",
            "/v1/cloud/connect",
            "/v1/supply-chain/package-shims/connect",
            "/v1/supply-chain/package-shims/activate",
            "/v1/receipts/latest",
            "/v1/runtime",
            "/v1/settings",
            "/v1/settings/export",
            "/v1/settings/import",
            "/v1/settings/reset",
            "/v1/read-state",
            "/v1/update",
            "/v1/update/status",
        }:
            return True
        if len(path_parts) == 3 and path_parts[:2] == ["v1", "receipts"]:
            return True
        if len(path_parts) == 4 and path_parts[:3] == ["v1", "audit", "remediations"]:
            return True
        if len(path_parts) == 4 and path_parts[:2] == ["v1", "approvals"] and path_parts[3] == "decision":
            return True
        if (
            len(path_parts) == 5
            and path_parts[:2] == ["v1", "apps"]
            and path_parts[3] == "cloud"
            and path_parts[4] == "start"
        ):
            return True
        if (
            len(path_parts) == 4
            and path_parts[:2] == ["v1", "harnesses"]
            and path_parts[3]
            in {
                "install",
                "verify",
                "repair",
                "uninstall",
            }
        ):
            return True
        return len(path_parts) == 4 and path_parts[:2] == ["v1", "artifacts"] and path_parts[3] == "diff"

    def _is_hosted_dashboard_origin(self) -> bool:
        origin = self._normalize_origin(self.headers.get("Origin"))
        return origin in _HOSTED_GUARD_DASHBOARD_ORIGINS

    def _public_healthz_payload(self) -> dict[str, object]:
        return {
            "ok": True,
            "compatibility_version": GUARD_DAEMON_COMPATIBILITY_VERSION,
        }

    def _detailed_healthz_payload(self) -> dict[str, object]:
        uptime = round(time.monotonic() - self.server.start_monotonic, 1)  # type: ignore[attr-defined]
        store = self.server.store  # type: ignore[attr-defined]
        pending_approvals = store.count_approval_requests()
        return {
            "ok": True,
            "receipts": len(store.list_receipts(limit=500)),
            "approvals": pending_approvals,
            "pending_approvals": pending_approvals,
            "uptime_seconds": uptime,
            "pid": os.getpid(),
            "tables": store.list_table_names(),
            "compatibility_version": GUARD_DAEMON_COMPATIBILITY_VERSION,
            "package_version": __version__,
            "guard_home": str(store.guard_home.resolve()),
        }

    @staticmethod
    def _normalize_origin(origin: str | None) -> str | None:
        if not isinstance(origin, str) or not origin.strip():
            return None
        parsed = urlparse(origin.strip())
        if (
            parsed.scheme not in {"http", "https"}
            or parsed.hostname is None
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.params
            or parsed.query
            or parsed.fragment
        ):
            return None
        host = parsed.hostname
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        default_port = 80 if parsed.scheme == "http" else 443
        try:
            port = parsed.port
        except ValueError:
            return None
        port_suffix = f":{port}" if port not in {None, default_port} else ""
        return f"{parsed.scheme}://{host}{port_suffix}"

    @staticmethod
    def _cors_headers(
        origin: str,
        *,
        allow_methods: str = "POST, OPTIONS",
        allow_headers: str = "Authorization, Content-Type, X-Guard-Dashboard-Session, X-Guard-Token",
    ) -> dict[str, str]:
        return {
            "Access-Control-Allow-Origin": origin,
            "Access-Control-Allow-Methods": allow_methods,
            "Access-Control-Allow-Headers": allow_headers,
            "Access-Control-Allow-Private-Network": "true",
            "Vary": "Origin",
        }

    def _cors_headers_for_request(
        self,
        *,
        allow_methods: str = "POST, OPTIONS",
        allow_headers: str = "Authorization, Content-Type, X-Guard-Dashboard-Session, X-Guard-Token",
    ) -> dict[str, str] | None:
        parsed = urlparse(self.path)
        path_parts = [part for part in parsed.path.split("/") if part]
        origin = self._normalize_origin(self.headers.get("Origin"))
        if origin is None or not self._origin_is_allowed_for_request(parsed.path, path_parts):
            return None
        return self._cors_headers(origin, allow_methods=allow_methods, allow_headers=allow_headers)

    def _handle_policy_upsert(self, payload: dict[str, object]) -> None:
        harness = payload.get("harness")
        scope = payload.get("scope")
        action = payload.get("action")
        if (
            not isinstance(harness, str)
            or not harness.strip()
            or not isinstance(scope, str)
            or not scope.strip()
            or not isinstance(action, str)
            or not action.strip()
        ):
            self._write_json({"saved": False, "error": "missing_required_fields"}, status=400)
            return
        normalized_harness = harness.strip()
        normalized_scope = scope.strip()
        normalized_action = action.strip()
        if not _is_decision_scope(normalized_scope) or not _is_guard_action(normalized_action):
            self._write_json({"saved": False, "error": "unsupported_policy_value"}, status=400)
            return
        if normalized_scope == "global" and normalized_action == "allow":
            self._write_json({"saved": False, "error": "broad_allow_requires_narrow_scope"}, status=400)
            return
        record = {
            "harness": normalized_harness,
            "scope": normalized_scope,
            "action": normalized_action,
            "artifact_id": self._optional_string(payload.get("artifact_id")),
            "workspace": self._optional_string(payload.get("workspace")),
            "publisher": self._optional_string(payload.get("publisher")),
            "reason": self._optional_string(payload.get("reason")),
        }
        if not self._scope_target_is_valid(
            normalized_scope,
            artifact_id=record["artifact_id"],
            workspace=record["workspace"],
            publisher=record["publisher"],
        ):
            self._write_json({"saved": False, "error": "missing_scope_target"}, status=400)
            return
        store = self.server.store  # type: ignore[attr-defined]
        decision = PolicyDecision(
            harness=normalized_harness,
            scope=normalized_scope,
            action=normalized_action,
            artifact_id=record["artifact_id"],
            workspace=record["workspace"],
            publisher=record["publisher"],
            reason=record["reason"],
        )
        try:
            approval_gate_grant = require_high_risk(
                store.guard_home,
                purpose="policy_write",
                approval_gate_input=approval_gate_input_from_mapping(payload),
            )
            store.upsert_policy(
                decision,
                _now(),
                approval_gate_grant=approval_gate_grant,
            )
        except ApprovalGateError as error:
            payload = error.to_payload()
            payload["saved"] = False
            self._write_json(payload, status=error.status)
            return
        except ValueError as error:
            self._write_json({"saved": False, "error": str(error)}, status=400)
            return
        self._write_json({"saved": True, "decision": record})

    @staticmethod
    def _optional_string(value: object) -> str | None:
        if isinstance(value, str) and value.strip():
            return value.strip()
        return None

    def _coalesce_string(self, mapping: dict[str, object], *keys: str) -> str | None:
        for key in keys:
            value = self._optional_string(mapping.get(key))
            if value is not None:
                return value
        return None

    @staticmethod
    def _query_string(query_string: str, key: str) -> str | None:
        value = parse_qs(query_string).get(key, [None])[-1]
        if isinstance(value, str) and value.strip():
            return value.strip()
        return None

    @staticmethod
    def _query_bool(query_string: str, key: str, *, default: bool) -> bool:
        value = parse_qs(query_string).get(key, [None])[-1]
        if not isinstance(value, str):
            return default
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "on"}:
            return True
        if normalized in {"0", "false", "no", "off"}:
            return False
        return default

    @staticmethod
    def _query_limit(query_string: str, *, default: int, maximum: int) -> int | None:
        raw_value = parse_qs(query_string).get("limit", [None])[-1]
        if raw_value is None:
            return default
        try:
            value = int(raw_value)
        except (TypeError, ValueError):
            return None
        if value < 1:
            return None
        return min(value, maximum)

    def _validated_hook_directory_string(
        self,
        parameter: str,
        value: str | None,
        *,
        roots: tuple[Path, ...] | None = None,
    ) -> str | None:
        if value is None:
            return None
        return os.fspath(self._validate_hook_directory_path(parameter, value, roots=roots))

    @staticmethod
    def _normalized_hook_workspace_string(value: object) -> str | None:
        if not isinstance(value, str):
            return None
        stripped = value.strip()
        if not stripped or stripped.lower() in {"none", "null"}:
            return None
        # Mirror the CLI hook contract until runtime callers stop emitting `/None`
        # as the explicit "no workspace" sentinel.
        candidate = os.path.expanduser(stripped)
        if os.path.basename(candidate) == "None":
            candidate = os.path.dirname(candidate)
            if not candidate.strip():
                return None
        return os.path.normpath(candidate)

    def _validate_hook_directory_path(
        self,
        parameter: str,
        value: str,
        *,
        roots: tuple[Path, ...] | None = None,
    ) -> Path:
        expanded = os.path.expanduser(value)
        if not os.path.isabs(expanded):
            raise _HookPathValidationError(parameter, "relative_path")
        try:
            candidate = os.path.realpath(expanded)
        except OSError:
            raise _HookPathValidationError(parameter, "path_resolve_failed") from None
        effective_roots = roots
        if parameter in {"home", "workspace"} and effective_roots is None:
            effective_roots = self._hook_safe_roots()
        if effective_roots is not None:
            root_match = False
            for root in effective_roots:
                root_path = os.path.realpath(os.fspath(root))
                try:
                    if os.path.commonpath([candidate, root_path]) == root_path:
                        root_match = True
                        break
                except ValueError:
                    continue
            if not root_match:
                raise _HookPathValidationError(parameter, "unexpected_root")
        return Path(candidate)

    def _validated_hook_guard_home(self, value: str | None) -> str | None:
        if value is None:
            return None
        expanded = os.path.expanduser(value)
        if not os.path.isabs(expanded):
            raise _HookPathValidationError("guard-home", "relative_path")
        try:
            candidate = os.path.realpath(expanded)
        except OSError:
            raise _HookPathValidationError("guard-home", "path_resolve_failed") from None
        expected = os.path.realpath(os.fspath(self._daemon_server().store.guard_home.expanduser()))
        if candidate != expected:
            raise _HookPathValidationError("guard-home", "unexpected_guard_home")
        return expected

    def _hook_safe_roots(self) -> tuple[Path, ...]:
        current_home = Path.home().resolve()
        roots: list[Path] = [current_home]
        guard_home_root = self._daemon_server().store.guard_home.expanduser().resolve().parent
        if not self._path_is_within_root(guard_home_root, current_home):
            roots.append(guard_home_root)
        return tuple(roots)

    @staticmethod
    def _path_is_within_root(candidate: Path | str, root: Path | str) -> bool:
        candidate_path = os.fspath(candidate)
        root_path = os.fspath(root)
        try:
            return os.path.commonpath([candidate_path, root_path]) == root_path
        except ValueError:
            return False

    @staticmethod
    def _scope_target_is_valid(
        scope: str,
        *,
        artifact_id: str | None,
        workspace: str | None,
        publisher: str | None,
    ) -> bool:
        if scope in {"global", "harness"}:
            return True
        if scope == "artifact":
            return artifact_id is not None
        if scope == "workspace":
            return workspace is not None
        if scope == "publisher":
            return publisher is not None
        return False

    @staticmethod
    def _resolve_request_action(
        path_parts: list[str], payload: dict[str, object]
    ) -> tuple[str | None, str | None, bool]:
        if len(path_parts) == 4 and path_parts[:2] == ["v1", "requests"] and path_parts[3] in {"approve", "block"}:
            return path_parts[2], "allow" if path_parts[3] == "approve" else "block", True
        if len(path_parts) == 3 and path_parts[0] == "approvals" and path_parts[2] == "decision":
            action = payload.get("action")
            if not isinstance(action, str) or not action.strip():
                return path_parts[1], None, True
            return path_parts[1], action.strip(), True
        if len(path_parts) == 4 and path_parts[:2] == ["v1", "approvals"] and path_parts[3] == "decision":
            action = payload.get("action")
            if not isinstance(action, str) or not action.strip():
                return path_parts[2], None, True
            return path_parts[2], action.strip(), True
        return None, None, False

    @staticmethod
    def _requires_header_token(path: str, path_parts: list[str]) -> bool:
        if path in {
            "/v1/clients/attach",
            "/v1/clients/heartbeat",
            "/v1/sessions/start",
            "/v1/operations/start",
            "/v1/connect/requests",
            "/v1/connect/result",
            "/v1/operations/block",
            "/v1/policy/decisions",
            "/v1/policy/cloud-exceptions",
            "/v1/policy/cloud-exception-requests",
            "/v1/policy/clear",
            "/v1/policy/sync",
            "/v1/requests/clear",
            "/v1/requests/bulk-allow-once",
            "/v1/requests/remote-once",
            "/v1/settings",
            "/v1/settings/import",
            "/v1/settings/reset",
            "/v1/approval-gate/cooldown/revoke",
            "/v1/approval-gate/totp/enroll",
            "/v1/approval-gate/totp/verify",
            "/v1/approval-gate/totp/disable",
            "/v1/daemon/repair",
            "/v1/insights/share",
            "/v1/cloud/connect",
            "/v1/notifications/setup",
            "/v1/update",
        }:
            return True
        if len(path_parts) >= 3 and path_parts[:2] == ["v1", "hooks"]:
            return True
        if len(path_parts) == 3 and path_parts[:2] == ["v1", "apps"] and path_parts[2] in _HEADLESS_APP_ACTIONS:
            return True
        if len(path_parts) >= 2 and path_parts[:2] == ["v1", "supply-chain"]:
            return True
        if len(path_parts) == 4 and path_parts[:3] == ["v1", "audit", "remediations"]:
            return True
        if len(path_parts) == 4 and path_parts[:2] == ["v1", "operations"] and path_parts[3] in {"items", "status"}:
            return True
        if (
            len(path_parts) == 4
            and path_parts[:2] == ["v1", "requests"]
            and path_parts[3] in {"approve", "block", "resume"}
        ):
            return True
        if (
            len(path_parts) == 4
            and path_parts[:2] == ["v1", "harnesses"]
            and path_parts[3]
            in {
                "install",
                "verify",
                "repair",
                "uninstall",
            }
        ):
            return True
        if len(path_parts) == 5 and path_parts[:2] == ["v1", "apps"] and path_parts[3:] == ["cloud", "start"]:
            return True
        if len(path_parts) == 3 and path_parts[0] == "approvals" and path_parts[2] == "decision":
            return True
        return len(path_parts) == 4 and path_parts[:2] == ["v1", "approvals"] and path_parts[3] == "decision"

    def _write_json(
        self,
        payload: dict[str, Any],
        *,
        status: int = 200,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        body = json.dumps(payload).encode("utf-8")
        headers = dict(extra_headers or {})
        cors_headers = self._cors_headers_for_request(allow_methods="GET, POST, OPTIONS")
        if cors_headers is not None:
            headers = {**cors_headers, **headers}
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for key, value in self._validated_headers(headers).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _write_empty(
        self,
        *,
        status: int,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        self.send_response(status)
        for key, value in self._validated_headers(extra_headers).items():
            self.send_header(key, value)
        self.end_headers()

    @staticmethod
    def _validated_headers(extra_headers: dict[str, str] | None) -> dict[str, str]:
        allowed_headers = {
            "Access-Control-Allow-Origin",
            "Access-Control-Allow-Methods",
            "Access-Control-Allow-Headers",
            "Access-Control-Allow-Private-Network",
            "Cache-Control",
            "Expires",
            "Location",
            "Pragma",
            "Vary",
        }
        validated: dict[str, str] = {}
        for key, value in (extra_headers or {}).items():
            if key not in allowed_headers or not isinstance(value, str):
                continue
            if "\r" in value or "\n" in value:
                continue
            validated[key] = value
        return validated

    def _write_static_asset(self, relative_path: str) -> None:
        target = (_STATIC_DIR / relative_path).resolve()
        if not target.is_file() or _STATIC_DIR.resolve() not in target.parents:
            self.send_response(404)
            self.end_headers()
            return
        body = target.read_bytes()
        content_type, _ = mimetypes.guess_type(str(target))
        self.send_response(200)
        self.send_header("Content-Type", content_type or "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _write_dashboard_shell(self) -> None:
        if _INDEX_PATH.is_file() and _ENTRY_PATH.is_file():
            encoded = _INDEX_PATH.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(encoded)))
            self.send_header("Cache-Control", "no-store, max-age=0")
            self.send_header("Pragma", "no-cache")
            self.send_header("Expires", "0")
            self.send_header("Content-Security-Policy", _DASHBOARD_CSP)
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(encoded)
            return
        self._write_json({"error": "dashboard_bundle_missing"}, status=503)

    @staticmethod
    def _is_dashboard_route(path: str) -> bool:
        if path in {
            "/",
            "/home",
            "/dashboard",
            "/inbox",
            "/protect",
            "/evidence",
            "/supply-chain",
            "/audit",
            "/policy",
            "/feed-health",
            "/settings",
            "/about",
            "/requests",
            "/approvals",
        }:
            return True
        if path.startswith("/requests/"):
            return True
        if path.startswith("/apps/"):
            return True
        return path.startswith("/approvals/") and not path.endswith("/decision")


class GuardDaemonServer:
    """Small local daemon for health, receipts, and approval-center introspection."""

    def __init__(
        self,
        store: GuardStore,
        host: str = "127.0.0.1",
        port: int = 0,
        *,
        bundle_refresh_backoff_seconds: float = _DEFAULT_SUPPLY_CHAIN_REFRESH_BACKOFF_SECONDS,
        bundle_refresh_interval_seconds: float | None = _DEFAULT_SUPPLY_CHAIN_REFRESH_INTERVAL_SECONDS,
        aibom_refresh_backoff_seconds: float = _DEFAULT_SUPPLY_CHAIN_REFRESH_BACKOFF_SECONDS,
        aibom_refresh_interval_seconds: float | None = float(_AIBOM_AUTO_SYNC_INTERVAL_SECONDS),
        idle_timeout_seconds: float | None = None,
        home_dir: Path | None = None,
        workspace_dir: Path | None = None,
    ) -> None:
        _validate_dashboard_bundle()
        self._server = _GuardDaemonHttpServer(
            (host, port),
            _GuardDaemonHandler,
            store=store,
            auth_token=load_guard_daemon_auth_token(store.guard_home) or uuid.uuid4().hex,
            runtime_host=host,
            runtime_session_id=uuid.uuid4().hex,
            runtime_started_at=_now(),
            idle_timeout_seconds=_guard_daemon_idle_timeout_seconds(
                store.guard_home,
                idle_timeout_seconds=idle_timeout_seconds,
            ),
        )
        self.port = self._server.daemon_port()
        self._bundle_refresh_backoff_seconds = bundle_refresh_backoff_seconds
        self._bundle_refresh_interval_seconds = bundle_refresh_interval_seconds
        self._aibom_refresh_backoff_seconds = aibom_refresh_backoff_seconds
        self._aibom_refresh_interval_seconds = aibom_refresh_interval_seconds
        self._headless_cloud_sync_backoff_seconds = _DEFAULT_HEADLESS_CLOUD_SYNC_BACKOFF_SECONDS
        self._headless_cloud_sync_interval_seconds = _DEFAULT_HEADLESS_CLOUD_SYNC_INTERVAL_SECONDS
        self._aibom_home_dir = home_dir.expanduser() if home_dir is not None else None
        self._aibom_workspace_dir = workspace_dir.expanduser() if workspace_dir is not None else None
        self._aibom_context_workspace_id = (
            store.get_cloud_workspace_id() if self._aibom_workspace_dir is not None else None
        )
        self._aibom_refresh_thread: threading.Thread | None = None
        self._bundle_refresh_thread: threading.Thread | None = None
        self._command_queue_worker: CommandQueueWorker | None = None
        self._headless_cloud_sync_thread: threading.Thread | None = None
        self._live_request_sync_worker: LiveRequestSyncWorker | None = None
        self._thread: threading.Thread | None = None
        self._watchdog_thread: threading.Thread | None = None
        self._shutdown_started = threading.Event()

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._thread = None
        self._begin_service()
        self._thread = threading.Thread(target=self._serve_forever, daemon=True)
        self._thread.start()

    def serve(self) -> None:
        self._begin_service()
        self._serve_forever()

    def stop(self) -> None:
        self._shutdown_started.set()
        self._server.shutdown()
        self._server.server_close()
        self._finish_service()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None
        if self._watchdog_thread is not None:
            self._watchdog_thread.join(timeout=5)
            self._watchdog_thread = None
        if self._bundle_refresh_thread is not None:
            self._bundle_refresh_thread.join(timeout=5)
            self._bundle_refresh_thread = None
        if self._aibom_refresh_thread is not None:
            self._aibom_refresh_thread.join(timeout=_AIBOM_REFRESH_STOP_JOIN_TIMEOUT_SECONDS)
            if not self._aibom_refresh_thread.is_alive():
                self._aibom_refresh_thread = None
        if self._headless_cloud_sync_thread is not None:
            self._headless_cloud_sync_thread.join(timeout=5)
            self._headless_cloud_sync_thread = None
        self._command_queue_worker = stop_command_queue_worker(self._command_queue_worker)
        self._live_request_sync_worker = stop_cloud_sync_sync_worker(self._live_request_sync_worker)

    def _begin_service(self) -> None:
        if self._aibom_refresh_thread is not None:
            if self._aibom_refresh_thread.is_alive():
                raise RuntimeError("AIBOM inventory refresh is still stopping")
            self._aibom_refresh_thread = None
        self._shutdown_started.clear()
        self._persist_aibom_inventory_context()
        self._server.last_activity_monotonic = time.monotonic()
        write_guard_daemon_state(
            self._server.store.guard_home,
            self.port,
            self._server.auth_token,
            host=self._server.daemon_host(),
            state_id=self._server.runtime_session_id,
            started_at=self._server.runtime_started_at,
        )
        self._server.store.upsert_runtime_state(
            session_id=self._server.runtime_session_id,
            daemon_host=self._server.runtime_host,
            daemon_port=self.port,
            started_at=self._server.runtime_started_at,
            last_heartbeat_at=_now(),
        )
        approval_attention = getattr(self._server, "approval_attention", None)
        if approval_attention is not None:
            approval_attention.start()
        self._start_watchdog()
        self._start_headless_cloud_sync()
        self._start_supply_chain_bundle_refresh()
        self._start_aibom_inventory_refresh()
        self._command_queue_worker = start_command_queue_worker(self._server.store, self._command_queue_worker)
        self._live_request_sync_worker = start_cloud_sync_sync_worker(
            self._server.store,
            self._live_request_sync_worker,
        )

    def _persist_aibom_inventory_context(self) -> None:
        workspace_id = self._server.store.get_cloud_workspace_id()
        if (
            workspace_id is None
            or workspace_id != self._aibom_context_workspace_id
            or self._aibom_workspace_dir is None
        ):
            return
        payload: dict[str, object] = {
            "workspace_dir": str(self._aibom_workspace_dir),
            "workspace_id": workspace_id,
        }
        if self._aibom_home_dir is not None:
            payload["home_dir"] = str(self._aibom_home_dir)
        now = _now()
        self._server.store.set_sync_payload("aibom_inventory_context", payload, now)

    def _serve_forever(self) -> None:
        try:
            self._server.serve_forever()
        finally:
            self._server.server_close()
            self._finish_service()

    def _finish_service(self) -> None:
        self._shutdown_started.set()
        approval_attention = getattr(self._server, "approval_attention", None)
        if approval_attention is not None:
            approval_attention.stop()
        self._command_queue_worker = stop_command_queue_worker(self._command_queue_worker)
        self._live_request_sync_worker = stop_cloud_sync_sync_worker(self._live_request_sync_worker)
        clear_guard_daemon_state_if_current(self._server.store.guard_home, pid=os.getpid(), port=self.port)
        self._server.store.clear_runtime_state(session_id=self._server.runtime_session_id)

    def _start_watchdog(self) -> None:
        if self._watchdog_thread is not None and self._watchdog_thread.is_alive():
            return
        idle_timeout_seconds = self._server.idle_timeout_seconds
        if idle_timeout_seconds is None or idle_timeout_seconds <= 0:
            return
        self._watchdog_thread = threading.Thread(target=self._watch_for_idle_shutdown, daemon=True)
        self._watchdog_thread.start()

    def _start_headless_cloud_sync(self) -> None:
        if self._headless_cloud_sync_interval_seconds <= 0:
            return
        if self._headless_cloud_sync_thread is not None and self._headless_cloud_sync_thread.is_alive():
            return
        self._headless_cloud_sync_thread = threading.Thread(
            target=self._refresh_headless_cloud_sync_loop,
            daemon=True,
            name="guard-headless-cloud-sync-loop",
        )
        self._headless_cloud_sync_thread.start()

    def _refresh_headless_cloud_sync_loop(self) -> None:
        interval_seconds = self._headless_cloud_sync_interval_seconds
        backoff_seconds = (
            self._headless_cloud_sync_backoff_seconds
            if self._headless_cloud_sync_backoff_seconds > 0
            else interval_seconds
        )
        while not self._shutdown_started.is_set():
            summary = _run_headless_cloud_sync(store=self._server.store)
            status = str(summary.get("status") or "")
            wait_seconds = interval_seconds if status == "synced" else backoff_seconds
            if self._shutdown_started.wait(wait_seconds):
                return

    def _watch_for_idle_shutdown(self) -> None:
        idle_timeout_seconds = self._server.idle_timeout_seconds
        if idle_timeout_seconds is None or idle_timeout_seconds <= 0:
            return
        while not self._shutdown_started.is_set():
            with self._server.active_stream_clients_lock:
                active_stream_clients = self._server.active_stream_clients
            pending_live_requests = self._server.store.list_approval_requests(
                status="pending",
                limit=1,
            )
            cloud_profile = self._server.store.get_cloud_sync_profile()
            workspace_id = cloud_profile.get("workspace_id") if isinstance(cloud_profile, dict) else None
            outbox_status = self._server.store.live_request_outbox_status(
                now=_now(),
                workspace_id=workspace_id,
            )
            outbox_depth = outbox_status["depth"]
            if (
                active_stream_clients > 0
                or pending_live_requests
                or (workspace_id is not None and isinstance(outbox_depth, int) and outbox_depth > 0)
            ):
                time.sleep(_GUARD_DAEMON_IDLE_POLL_INTERVAL_SECONDS)
                continue
            if time.monotonic() - self._server.last_activity_monotonic >= idle_timeout_seconds:
                self._shutdown_started.set()
                self._server.shutdown()
                return
            time.sleep(_GUARD_DAEMON_IDLE_POLL_INTERVAL_SECONDS)

    def _start_supply_chain_bundle_refresh(self) -> None:
        if self._bundle_refresh_interval_seconds is None or self._bundle_refresh_interval_seconds <= 0:
            return
        if self._bundle_refresh_thread is not None and self._bundle_refresh_thread.is_alive():
            return
        self._bundle_refresh_thread = threading.Thread(
            target=self._refresh_supply_chain_bundle_loop,
            daemon=True,
        )
        self._bundle_refresh_thread.start()

    def _refresh_supply_chain_bundle_loop(self) -> None:
        interval_seconds = self._bundle_refresh_interval_seconds
        if interval_seconds is None or interval_seconds <= 0:
            return
        backoff_seconds = (
            self._bundle_refresh_backoff_seconds if self._bundle_refresh_backoff_seconds > 0 else interval_seconds
        )
        while not self._shutdown_started.is_set():
            refreshed_at = _now()
            try:
                summary = sync_supply_chain_bundle(self._server.store)
                self._server.store.set_sync_payload(
                    "supply_chain_bundle_daemon",
                    {**summary, "status": "synced"},
                    refreshed_at,
                )
                wait_seconds = interval_seconds
            except GuardSyncAuthorizationExpiredError as error:
                self._server.store.set_sync_payload(
                    "supply_chain_bundle_daemon",
                    {
                        "status": "auth_expired",
                        "refreshed_at": refreshed_at,
                        "message": str(error),
                    },
                    refreshed_at,
                )
                wait_seconds = backoff_seconds
            except GuardSyncNotConfiguredError:
                self._server.store.set_sync_payload(
                    "supply_chain_bundle_daemon",
                    {"status": "not_configured", "refreshed_at": refreshed_at},
                    refreshed_at,
                )
                wait_seconds = backoff_seconds
            except Exception as error:
                self._server.store.set_sync_payload(
                    "supply_chain_bundle_daemon",
                    {
                        "error": str(error),
                        "refreshed_at": refreshed_at,
                        "status": "error",
                    },
                    refreshed_at,
                )
                wait_seconds = backoff_seconds
            if self._shutdown_started.wait(wait_seconds):
                return

    def _start_aibom_inventory_refresh(self) -> None:
        if self._aibom_refresh_interval_seconds is None or self._aibom_refresh_interval_seconds <= 0:
            return
        if self._aibom_refresh_thread is not None and self._aibom_refresh_thread.is_alive():
            return
        self._aibom_refresh_thread = threading.Thread(
            target=self._refresh_aibom_inventory_loop,
            daemon=True,
        )
        self._aibom_refresh_thread.start()

    def _aibom_inventory_context_dirs(self) -> tuple[Path | None, Path | None, str | None]:
        payload = self._server.store.get_sync_payload("aibom_inventory_context")
        current_workspace_id = self._server.store.get_cloud_workspace_id()
        bound_payload: dict[str, object] | None = None
        if (
            current_workspace_id is not None
            and isinstance(payload, dict)
            and payload.get("workspace_id") == current_workspace_id
        ):
            bound_payload = payload
        if bound_payload is not None:
            home_value = bound_payload.get("home_dir")
            workspace_value = bound_payload.get("workspace_dir")
        else:
            home_value = None
            workspace_value = None
        explicit_context_is_bound = (
            self._aibom_workspace_dir is not None and self._aibom_context_workspace_id == current_workspace_id
        )
        home_dir = self._aibom_home_dir if explicit_context_is_bound else None
        if home_dir is None and isinstance(home_value, str) and home_value.strip():
            home_dir = Path(home_value).expanduser()
        workspace_dir = self._aibom_workspace_dir if explicit_context_is_bound else None
        if workspace_dir is None and isinstance(workspace_value, str) and workspace_value.strip():
            workspace_dir = Path(workspace_value).expanduser()
        bound_workspace_id = current_workspace_id if workspace_dir is not None else None
        return home_dir, workspace_dir, bound_workspace_id

    def _refresh_aibom_inventory_loop(self) -> None:
        interval_seconds = self._aibom_refresh_interval_seconds
        if interval_seconds is None or interval_seconds <= 0:
            return
        backoff_seconds = (
            self._aibom_refresh_backoff_seconds if self._aibom_refresh_backoff_seconds > 0 else interval_seconds
        )
        while not self._shutdown_started.is_set():
            refreshed_at = _now()
            try:
                home_dir, workspace_dir, bound_workspace_id = self._aibom_inventory_context_dirs()
                if workspace_dir is None:
                    self._server.store.set_sync_payload(
                        "aibom_inventory_daemon",
                        {
                            "status": "missing_workspace_context",
                            "reason": "missing_workspace_context",
                            "skipped": True,
                            "refreshed_at": refreshed_at,
                        },
                        refreshed_at,
                    )
                    if self._shutdown_started.wait(backoff_seconds):
                        return
                    continue
                auth_context = _resolve_guard_sync_auth_context(self._server.store)
                with self._server.store.hold_cloud_sync_lock():
                    summary = sync_aibom_snapshots_if_due(
                        self._server.store,
                        generated_at=refreshed_at,
                        min_interval_seconds=max(int(interval_seconds), 1),
                        auth_context=auth_context,
                        expected_workspace_id=bound_workspace_id,
                        home_dir=home_dir,
                        workspace_dir=workspace_dir,
                    )
                has_error = bool(summary.get("error"))
                if has_error:
                    status = "error"
                elif summary.get("synced") is True:
                    status = "synced"
                else:
                    status = str(summary.get("reason") or "skipped")
                self._server.store.set_sync_payload(
                    "aibom_inventory_daemon",
                    {**summary, "status": status, "refreshed_at": refreshed_at},
                    refreshed_at,
                )
                wait_seconds = backoff_seconds if has_error or status == "not_configured" else interval_seconds
            except GuardSyncAuthorizationExpiredError as error:
                self._server.store.set_sync_payload(
                    "aibom_inventory_daemon",
                    {
                        "status": "auth_expired",
                        "refreshed_at": refreshed_at,
                        "message": str(error),
                    },
                    refreshed_at,
                )
                wait_seconds = backoff_seconds
            except GuardSyncNotConfiguredError:
                self._server.store.set_sync_payload(
                    "aibom_inventory_daemon",
                    {"status": "not_configured", "refreshed_at": refreshed_at},
                    refreshed_at,
                )
                wait_seconds = backoff_seconds
            except Exception as error:
                self._server.store.set_sync_payload(
                    "aibom_inventory_daemon",
                    {
                        "error": str(error),
                        "refreshed_at": refreshed_at,
                        "status": "error",
                    },
                    refreshed_at,
                )
                wait_seconds = backoff_seconds
            if self._shutdown_started.wait(wait_seconds):
                return


def _approval_center_browser_url(approval_center_url: str, auth_token: str) -> str:
    parsed = urlparse(approval_center_url)
    fragment_pairs = [
        (key, value) for key, value in parse_qsl(parsed.fragment, keep_blank_values=True) if key != "guard-token"
    ]
    fragment_pairs.append(
        (
            "guard-token",
            build_local_dashboard_session_token(auth_token=auth_token, surface="approval-center"),
        )
    )
    return urlunparse(parsed._replace(fragment=urlencode(fragment_pairs)))


def _build_local_url(host: str, port: int, path: str) -> str:
    host_part = f"[{host}]" if ":" in host else host
    return f"http://{host_part}:{port}{path}"


_HARNESS_RETRY_COPY: dict[str, str] = {
    "codex": "Return to Codex and retry",
    "claude-code": "Return to Claude and retry",
    "opencode": "Return to OpenCode and retry",
    "copilot": "Return to Copilot and retry",
    "pi": "Return to Pi and retry",
}
_DEFAULT_RETRY_COPY = "Return to your AI assistant and retry"


def _build_resolution_copy(action: str, harness: str) -> dict[str, str]:
    title = "Approved. Retry in chat." if action == "allow" else "Blocked. Decision saved."
    return {"title": title, "body": _HARNESS_RETRY_COPY.get(harness, _DEFAULT_RETRY_COPY)}


def _settings_response_payload(guard_home: Path, settings: dict[str, object]) -> dict[str, object]:
    return {
        "guard_home": str(guard_home),
        "config_path": str(guard_home / "config.toml"),
        "settings": settings,
    }


def _settings_export_payload(config: GuardConfig) -> dict[str, object]:
    return {
        "schema_version": 1,
        "privacy_warning": "Exports include local Guard preferences but not secrets or receipt evidence.",
        "settings": editable_guard_settings(config),
    }


def _dashboard_session_signature(payload: str, auth_token: str) -> str:
    digest = hmac.new(auth_token.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def _decode_dashboard_session_payload(payload: str) -> dict[str, object]:
    padding = "=" * (-len(payload) % 4)
    try:
        decoded = base64.urlsafe_b64decode(f"{payload}{padding}".encode("ascii")).decode("utf-8")
        parsed = json.loads(decoded)
    except (UnicodeDecodeError, ValueError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _parse_iso_timestamp(value: str) -> float:
    normalized = value.replace("Z", "+00:00")
    return datetime.fromisoformat(normalized).timestamp()


def _normalized_iso_timestamp_string(value: object) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None

    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _validate_dashboard_bundle() -> None:
    if not _INDEX_PATH.is_file() or not _ENTRY_PATH.is_file():
        raise RuntimeError(
            "Guard dashboard bundle is missing. Run `pnpm install && pnpm run build` in the dashboard directory."
        )


def _guard_daemon_idle_timeout_seconds(
    guard_home: Path,
    *,
    idle_timeout_seconds: float | None = None,
) -> float | None:
    if idle_timeout_seconds is not None:
        return idle_timeout_seconds if idle_timeout_seconds > 0 else None
    configured_timeout = os.environ.get("GUARD_DAEMON_IDLE_TIMEOUT_SECONDS")
    if isinstance(configured_timeout, str) and configured_timeout.strip():
        try:
            parsed_timeout = float(configured_timeout.strip())
        except ValueError:
            parsed_timeout = None
        if isinstance(parsed_timeout, float) and parsed_timeout > 0:
            return parsed_timeout
        if parsed_timeout == 0:
            return None
    if _guard_home_is_ephemeral(guard_home):
        return _EPHEMERAL_GUARD_DAEMON_IDLE_TIMEOUT_SECONDS
    return _DEFAULT_GUARD_DAEMON_IDLE_TIMEOUT_SECONDS


def _guard_home_is_ephemeral(guard_home: Path) -> bool:
    resolved_parts = guard_home.resolve().parts
    return any(part.startswith("pytest-") or "pytest-of-" in part for part in resolved_parts)


def _int_query_value(query: str, key: str) -> int:
    values = parse_qs(query).get(key, ["0"])
    raw_value = values[-1]
    try:
        return int(str(raw_value))
    except ValueError:
        return 0
