"""Services dependencies reexported by the daemon namespace."""

from __future__ import annotations

from .command_queue_worker import (
    CommandQueueWorker,
    refresh_command_queue_worker,
    start_command_queue_worker,
    stop_command_queue_worker,
)
from .dashboard_reconnect import (
    DASHBOARD_RECONNECT_PROTOCOL_VERSION,
    consume_dashboard_reconnect_challenge,
    dashboard_reconnect_challenge_identity,
    issue_dashboard_reconnect_challenge,
    prepare_dashboard_reconnect_authorization,
)
from .dashboard_update import merge_dashboard_update_progress, schedule_guard_dashboard_update
from .diagnostics import DaemonDiagnostics
from .discovery import (
    DAEMON_DISCOVERY_CHALLENGE_TTL_SECONDS,
    DAEMON_DISCOVERY_PROTOCOL_VERSION,
    authenticated_challenge_payload,
    load_authenticated_daemon_state,
    load_daemon_discovery_key,
)
from .extension_control_api import ExtensionControlApiError, ExtensionControlApiService
from .first_cloud_sync import maybe_queue_first_cloud_sync, queue_sync_with_optional_publish
from .hook_process_runner import HookProcessRunner
from .hook_request_auth import CHALLENGE_HOOK_PATHS, challenge_auth, request_auth
from .hook_worker_responses import prepare_native_hook_policy
from .lifecycle_journal import record_daemon_lifecycle_event
from .local_approval_continuation import apply_local_approval_continuation
from .local_cli_api import LocalCliApiService
from .local_cli_http import handle_local_cli_list, handle_local_cli_post
from .managed_controls_api import managed_policy_rows
from .managed_policy_delivery import daemon_managed_controls_candidate
from .manager import (
    GUARD_DAEMON_COMPATIBILITY_VERSION,
    clear_guard_daemon_state_if_current,
    current_guard_daemon_runtime_fingerprint,
    load_guard_daemon_auth_token,
    release_guard_daemon_owner_lock,
    repair_approval_center_locator,
    write_guard_daemon_state,
)
from .protection_repair_retry import confirmed_containment_repair_signals, incomplete_protection_repair_payload
from .request_executor import BoundedRequestExecutor as _BoundedRequestExecutor
from .runtime_heartbeat import RuntimeHeartbeatWriter
from .runtime_hook_deadline import RuntimeHookDeadline
from .runtime_hook_evidence_writer import RuntimeHookEvidenceWriter
from .runtime_hook_scheduler import RuntimeHookAdmissionReason, RuntimeHookLane, RuntimeHookScheduler
from .service_lifecycle import (
    begin_service,
    contain_failed_service_start,
    enable_full_capacity_for_generation,
    start_serve_thread,
    startup_generation_is_current,
)

__all__ = [
    "CHALLENGE_HOOK_PATHS",
    "DAEMON_DISCOVERY_CHALLENGE_TTL_SECONDS",
    "DAEMON_DISCOVERY_PROTOCOL_VERSION",
    "DASHBOARD_RECONNECT_PROTOCOL_VERSION",
    "GUARD_DAEMON_COMPATIBILITY_VERSION",
    "CommandQueueWorker",
    "DaemonDiagnostics",
    "ExtensionControlApiError",
    "ExtensionControlApiService",
    "HookProcessRunner",
    "LocalCliApiService",
    "RuntimeHeartbeatWriter",
    "RuntimeHookAdmissionReason",
    "RuntimeHookDeadline",
    "RuntimeHookEvidenceWriter",
    "RuntimeHookLane",
    "RuntimeHookScheduler",
    "_BoundedRequestExecutor",
    "apply_local_approval_continuation",
    "authenticated_challenge_payload",
    "begin_service",
    "challenge_auth",
    "clear_guard_daemon_state_if_current",
    "confirmed_containment_repair_signals",
    "consume_dashboard_reconnect_challenge",
    "contain_failed_service_start",
    "current_guard_daemon_runtime_fingerprint",
    "daemon_managed_controls_candidate",
    "dashboard_reconnect_challenge_identity",
    "enable_full_capacity_for_generation",
    "handle_local_cli_list",
    "handle_local_cli_post",
    "incomplete_protection_repair_payload",
    "issue_dashboard_reconnect_challenge",
    "load_authenticated_daemon_state",
    "load_daemon_discovery_key",
    "load_guard_daemon_auth_token",
    "managed_policy_rows",
    "maybe_queue_first_cloud_sync",
    "merge_dashboard_update_progress",
    "prepare_dashboard_reconnect_authorization",
    "prepare_native_hook_policy",
    "queue_sync_with_optional_publish",
    "record_daemon_lifecycle_event",
    "refresh_command_queue_worker",
    "release_guard_daemon_owner_lock",
    "repair_approval_center_locator",
    "request_auth",
    "schedule_guard_dashboard_update",
    "start_command_queue_worker",
    "start_serve_thread",
    "startup_generation_is_current",
    "stop_command_queue_worker",
    "write_guard_daemon_state",
]
