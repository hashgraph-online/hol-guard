"""Local Guard daemon helpers."""

from __future__ import annotations

import base64
import errno
import hashlib
import hmac
import json
import os
import secrets
import select
import socket
import sqlite3
import sys
import tempfile
import threading
import time
import uuid
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import Any, BinaryIO, ClassVar, TypeAlias, TypedDict, cast
from urllib.parse import parse_qs, parse_qsl, urlparse

from ...version import __version__
from ..adapters import get_adapter
from ..aibom_cli import _AIBOM_AUTO_SYNC_INTERVAL_SECONDS, sync_aibom_snapshots_if_due
from ..approval_gate import (
    ApprovalGateError,
    require_high_risk,
)
from ..approval_gate import input_from_mapping as approval_gate_input_from_mapping
from ..browser_opener import open_browser_url
from ..catalog_delivery import lifecycle
from ..codex_live_decision import complete_codex_live_decision, resolve_codex_live_allow_authority
from ..codex_live_decision_revalidation import revalidate_codex_live_allow
from ..config import (
    load_guard_config,
)
from ..fork_safety import forget_in_child
from ..json_transport import escape_json_for_html
from ..local_dashboard_session import (
    DEFAULT_LOCAL_DASHBOARD_SESSION_TTL_SECONDS,
    LOCAL_DASHBOARD_SESSION_AUDIENCE,
    LOCAL_DASHBOARD_SESSION_STARTED_AT_CLAIM,
    MAX_LOCAL_DASHBOARD_SESSION_AGE_SECONDS,
    PROTECTION_REPAIR_DASHBOARD_SURFACE,
    build_local_dashboard_session_token,
)
from ..models import (
    GuardRuntimeRegistration,
)
from ..native_codex_binding_capture import start_codex_binding_capture_writer
from ..native_daemon_handler import (
    HandlerDecision,
    NativeDaemonHandlerError,
    native_events_cursor,
)
from ..native_daemon_route import (
    NativeDaemonRouteError,
    native_origin_decision,
    native_route_facts,
    native_session_authorize,
    native_strict_loopback_origin,
)
from ..native_directory_trust import (
    UNAVAILABLE_REASON as _DIRECTORY_TRUST_UNAVAILABLE,
)
from ..native_directory_trust import (
    DirectoryTrustCandidate,
    DirectoryTrustVerdict,
    NativeDirectoryTrustError,
    native_directory_trust,
)
from ..native_guard_store import NativeGuardStoreUnavailable
from ..native_hook_evidence_writer import NativeHookEvidenceWriter, unreachable_writer_stats
from ..native_policy_snapshot_constants import NativePolicySnapshotError
from ..native_resident_revival import native_route_unavailable_body
from ..native_resident_watchdog import start_native_resident_watchdog
from ..native_runtime_request_scope import scoped_hook_post
from ..package_firewall_action_rate_limit import PackageFirewallActionRateLimiter
from ..runtime.approval_attention import ApprovalAttentionCoordinator
from ..runtime.cloud_review_sync import CloudReviewSyncWorker, start_cloud_sync_sync_worker, stop_cloud_sync_sync_worker
from ..runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY, CommandSafetyExtensionRegistry
from ..runtime.extension_control_authority import ExtensionControlAuthorityView
from ..runtime.extension_control_runtime import (
    ExtensionControlRuntime,
    ExtensionControlRuntimeSnapshot,
)
from ..runtime.isolation_provider import load_managed_provider_registry
from ..runtime.network_status import project_network_supervisor_health
from ..runtime.network_supervisor import NetworkSupervisor
from ..runtime.runner import (
    GuardSyncAuthorizationExpiredError,
    GuardSyncNotConfiguredError,
    _resolve_guard_sync_auth_context,
    sync_supply_chain_bundle,
)
from ..runtime.surface_server import GuardSurfaceRuntime
from ..runtime_artifact_reconciliation import (
    reconcile_runtime_artifacts,
)
from ..sqlite_recovery import quarantined_store_summary
from ..store import GuardStore
from ..store_evidence import (
    clear_evidence,
)
from ..store_storage_maintenance import DEFAULT_GUARD_EVENT_LIMIT, DEFAULT_RECEIPT_DETAIL_LIMIT
from . import repair_self_check
from .aibom_inventory_persist import persist_aibom_inventory_context
from .audit_persistence import NOT_PERSISTED as AUDIT_NOT_PERSISTED
from .audit_persistence import WRITTEN as AUDIT_WRITTEN
from .audit_persistence import AuditPersistence
from .bounded_http import BoundedThreadingHTTPServer
from .catalog_read_v2 import CATALOG_V2_PREFIX, serve_catalog_read_v2
from .command_activity_api import (
    parse_command_activity_event_cursor,
    stream_command_activity_events,
)
from .command_queue_worker import (
    CommandQueueWorker,
    refresh_command_queue_worker,
    start_command_queue_worker,
    stop_command_queue_worker,
)
from .dashboard_bundle import DASHBOARD_BUILD_HEADER, dashboard_build_id, pin_dashboard_bundle
from .diagnostics import DaemonDiagnostics
from .discovery import (
    DAEMON_DISCOVERY_CHALLENGE_TTL_SECONDS,
    DAEMON_DISCOVERY_PROTOCOL_VERSION,
    authenticated_challenge_payload,
    load_authenticated_daemon_state,
    load_daemon_discovery_key,
)
from .extension_control_api import ExtensionControlApiService
from .extension_discovery_read import (
    DISCOVERY_EVENTS_PATH,
    DISCOVERY_OPTED_OUT,
    DISCOVERY_RENDERS_PATH,
    DISCOVERY_UNAVAILABLE,
    DiscoveryReadError,
    discovery_placement_projection,
    discovery_rollout_enabled,
    relay_discovery_measurement,
)
from .hook_evidence_dispatch import HookEvidenceDispatch
from .hook_managed_install_state import _hook_harness_is_unmanaged
from .hook_policy_admission import prepare_native_hook_policy
from .hook_request_auth import CHALLENGE_HOOK_PATHS, challenge_auth, request_auth
from .hook_worker import WORKSPACE_POLICY_READINESS_TIMEOUT_SECONDS
from .lifecycle_journal import record_daemon_lifecycle_event
from .local_cli_api import LocalCliApiService
from .manager import (
    GUARD_DAEMON_COMPATIBILITY_VERSION,
    clear_guard_daemon_state_if_current,
    current_guard_daemon_runtime_fingerprint,
    current_guard_daemon_source_root,
    ensure_guard_daemon_auth_token,
    release_guard_daemon_owner_lock,
    write_guard_daemon_state,
)
from .request_executor import BoundedRequestExecutor as _BoundedRequestExecutor
from .runtime_heartbeat import RuntimeHeartbeatWriter
from .runtime_hook_deadline import PROMPT_ADMISSION_SECONDS, RuntimeHookDeadline, remaining_hint_from_payload
from .runtime_hook_scheduler import RuntimeHookAdmissionReason, RuntimeHookLane, RuntimeHookScheduler
from .server_common import (
    _LOGGER,
    _build_local_url,
    _now,
)
from .server_control_cloud_connect import _CloudConnectRoutes
from .server_control_cloud_sync import (
    _managed_controls_publish_for,
    _run_headless_cloud_sync_with_optional_publish,
)
from .server_control_headless import (
    _HeadlessRoutes,
)
from .server_control_health import _ControlHealthRoutes
from .server_control_misc import _ControlMiscRoutes
from .server_control_operations import _ControlOperationRoutes
from .server_control_policy import _ControlPolicyRoutes
from .server_control_repair import _RepairSettingsRoutes
from .server_control_routes_post import _ControlPostRoutes
from .server_control_supply_chain import _SupplyChainRoutes
from .server_control_sync import _ControlSyncRoutes
from .server_dashboard_records_read import _DashboardRecordsReadRoutes
from .server_dashboard_runtime_read import _DashboardRuntimeReadRoutes
from .server_dashboard_support import _DashboardSupportRoutes
from .service_lifecycle import (
    begin_service,
    contain_failed_service_start,
    start_serve_thread,
    startup_generation_is_current,
)
from .sponsored_discovery_settings import (
    sponsored_discovery_allowed,
    sponsored_discovery_measurement_allowed,
    sponsored_discovery_settings,
    update_sponsored_discovery_settings,
)
from .startup_phase import flush_pending_phases, record_phase_since, timed_phase

# Local daemon routes. The Cloud paths stay in the read module and are the
# only paths relayed upstream.
_LOCAL_DISCOVERY_PREFIX = "/v1/discovery/extensions/"
_LOCAL_DISCOVERY_PLACEMENTS = "/v1/discovery/extensions/placements"
_LOCAL_DISCOVERY_SETTINGS = "/v1/discovery/extensions/settings"
_LOCAL_DISCOVERY_MEASUREMENT = {
    "/v1/discovery/extensions/renders": DISCOVERY_RENDERS_PATH,
    "/v1/discovery/extensions/events": DISCOVERY_EVENTS_PATH,
}

_LOCAL_DASHBOARD_SESSION_REFRESH_GRACE_SECONDS = 7 * 24 * 60 * 60
_DEFAULT_HEADLESS_CLOUD_SYNC_INTERVAL_SECONDS = 30.0
_DEFAULT_HEADLESS_CLOUD_SYNC_BACKOFF_SECONDS = 10.0


class _InstalledAuthorityMigrationError(Exception):
    """The installed release's command-pack authority is not migrated yet."""


class _HookPathValidationError(ValueError):
    def __init__(self, parameter: str, reason: str) -> None:
        self.parameter = parameter
        self.reason = reason
        parameter_slug = parameter.replace("-", "_")
        super().__init__(f"invalid_hook_{parameter_slug}_path")
        self.code = f"invalid_hook_{parameter_slug}_path"


# One request spells the same directory several ways -- the query string, the
# payload, the exec command's own working directory -- and each spelling is
# labelled apart so their verdicts cannot collide. A caller still sees the
# parameter the route has always reported, whichever spelling was refused.
_REPORTED_HOOK_PARAMETER = {
    "exec-workdir": "workspace",
    "workspace-payload": "workspace",
    "workspace-query": "workspace",
}


def _reported_hook_parameter(parameter: str) -> str:
    """The name a rejection of this candidate is reported under."""

    return _REPORTED_HOOK_PARAMETER.get(parameter, parameter)


class _HookDirectories:
    """The directories one hook request named, as the native owner settled them.

    Every candidate is asked for in a single call, so the handler reads its
    verdicts back in whatever order the route needs without paying for a
    round trip per path. A parameter the request did not carry has no verdict
    and reads as `None`, which is what an absent directory meant before.
    """

    def __init__(self, verdicts: Sequence[DirectoryTrustVerdict]) -> None:
        self._verdicts = {verdict.parameter: verdict for verdict in verdicts}

    def require(self, parameter: str) -> str | None:
        """The settled path for one candidate, or `None` where it named none."""

        verdict = self._verdicts.get(parameter)
        if verdict is None:
            return None
        if verdict.reason is not None:
            raise _HookPathValidationError(_reported_hook_parameter(parameter), verdict.reason)
        return verdict.path


# A fail-safe hook answer stands in for a runtime that has just failed, so it
# waits only this long for the directories it reports.
_FAIL_SAFE_DIRECTORY_TRUST_SECONDS = 0.5

_MAX_CONCURRENT_DAEMON_REQUESTS = 32
_MAX_CONCURRENT_DAEMON_CONTROL_REQUESTS = 8
_MAX_CONCURRENT_DAEMON_CRITICAL_REQUESTS = 8
_MAX_CONCURRENT_DAEMON_CONNECTIONS = 128
_AUTH_AUDIT_COALESCE_SECONDS = 60.0
_AUTH_AUDIT_KEY_LIMIT = 64
_AUTH_AUDIT_SQLITE_TIMEOUT_SECONDS = 0.25
_AuthAuditKey: TypeAlias = tuple[str, str, str | None, str | None, bool, bool, bool]


class _AuthAuditWindow(TypedDict):
    started_at: float
    suppressed_count: int
    pending: bool
    persisted: bool


_MAX_CONCURRENT_RUNTIME_HOOKS = 32
_MAX_CONCURRENT_RUNTIME_HOOKS_PER_HARNESS = 24
_RUNTIME_HOOK_ADMISSION_TIMEOUT_SECONDS = 3.0
_RUNTIME_HOOK_PROCESS_TIMEOUT_SECONDS = 1.45
_RUNTIME_WORKSPACE_READINESS_TIMEOUT_SECONDS = WORKSPACE_POLICY_READINESS_TIMEOUT_SECONDS
_DAEMON_REQUEST_READ_TIMEOUT_SECONDS = 0.4
_DAEMON_SERVE_THREAD_START_TIMEOUT_SECONDS = 5.0
_DAEMON_CONNECTION_ADMISSION_WAIT_SECONDS = 0.05
_DAEMON_CONTROL_ADMISSION_WAIT_SECONDS = 1.0
_DAEMON_UNCLASSIFIED_WATCHDOG_POLL_SECONDS = 0.025
_AIBOM_REFRESH_STOP_JOIN_TIMEOUT_SECONDS = 5.0
# A watchdog tick may be inside a cold-start resident request (5s plus a 10s spawn allowance).
_NATIVE_RESIDENT_WATCHDOG_STOP_JOIN_TIMEOUT_SECONDS = 16.0
_DAEMON_CONTROL_PATHS = frozenset(
    {
        "/v1/healthz/details",
        "/v1/healthz/verify",
    }
)
_DAEMON_CRITICAL_PATHS = frozenset(
    {
        "/healthz",
        "/v1/daemon/identity-challenge",
        "/v1/desktop/bootstrap",
    }
)


def _runtime_hook_remaining_hint(payload: dict[str, object]) -> float:
    hint = remaining_hint_from_payload(payload, pop=True)
    return _RUNTIME_HOOK_ADMISSION_TIMEOUT_SECONDS if hint is None else hint


def _codex_live_replay_authority(
    request: object,
    previous: object,
) -> tuple[str | None, str | None]:
    """Return already-claimed exact context only for a terminal allow replay."""

    if not isinstance(request, Mapping) or not isinstance(previous, Mapping):
        return None, None
    if request.get("resolution_action") != "allow" or previous.get("resolution_action") != "allow":
        return None, None
    if previous.get("status") not in {"resumed", "sent"}:
        return None, None
    artifact_hash = request.get("artifact_hash")
    request_id = request.get("request_id")
    if not isinstance(artifact_hash, str) or not artifact_hash:
        return None, None
    if not isinstance(request_id, str) or not request_id:
        return None, None
    return artifact_hash, request_id


_PEER_DISCONNECT_ERRORS = (BrokenPipeError, ConnectionResetError, ConnectionAbortedError)


class _GuardDaemonHTTPServer(BoundedThreadingHTTPServer):
    request_queue_size = _MAX_CONCURRENT_DAEMON_CONNECTIONS
    # Set while the installed release's authority still awaits migration.
    _installed_authority_pending: bool = False
    # Set while the control API serves the core registry because startup could
    # not read the installed authority.
    _extension_control_on_core_registry: bool = False
    store: GuardStore
    runtime: GuardSurfaceRuntime
    auth_token: str
    runtime_host: str
    runtime_session_id: str
    runtime_started_at: str
    idle_timeout_seconds: float | None
    last_activity_monotonic: float
    idle_shutdown_claimed: bool
    start_monotonic: float
    active_stream_clients: int
    active_stream_clients_lock: threading.Lock
    shutdown_started: threading.Event
    package_firewall_connect_state: dict[str, object] | None
    package_firewall_connect_state_lock: threading.Lock
    onefile_extraction_status: dict[str, object] | None
    repair_self_check_status: dict[str, object] | None
    guard_cloud_connect_state: dict[str, object] | None
    guard_cloud_connect_state_lock: threading.Lock
    guard_cloud_browser_session_lock: threading.Lock
    package_firewall_action_rate_limiter: PackageFirewallActionRateLimiter
    package_firewall_mutation_lock: threading.Lock
    package_firewall_session_nonces: dict[str, float]
    package_firewall_session_nonces_lock: threading.Lock
    approval_attention: ApprovalAttentionCoordinator
    daemon_discovery_challenges: dict[str, dict[str, object]]
    daemon_discovery_challenges_lock: threading.Lock
    dashboard_reconnect_lock: threading.Lock
    dashboard_reconnect_consumed_challenges: dict[str, int]
    containment_health_cache: dict[str, object] | None
    containment_health_cache_monotonic: float
    containment_health_cache_lock: threading.Lock
    containment_health_refreshing: bool
    containment_health_refresh_event: threading.Event
    containment_health_generation: int
    containment_health_completed_generation: int
    network_supervisor: NetworkSupervisor
    active_hook_requests: int
    rejected_hook_requests: int
    hook_harness_active: dict[str, int]
    hook_harness_rejected: dict[str, int]
    hook_capacity_lock: threading.Lock
    runtime_hook_scheduler: RuntimeHookScheduler
    runtime_hook_evidence_writer: NativeHookEvidenceWriter
    runtime_hook_evidence_dispatch: HookEvidenceDispatch
    request_capacity: threading.BoundedSemaphore
    request_capacity_limit: int
    connection_capacity: threading.BoundedSemaphore
    connection_capacity_limit: int
    control_request_capacity: threading.BoundedSemaphore
    control_request_capacity_limit: int
    critical_request_capacity: threading.BoundedSemaphore
    critical_request_capacity_limit: int
    active_requests: int
    normal_connections: set[int]
    rejected_requests: int
    request_capacity_kinds: dict[int, str]
    request_accepted_at: dict[int, float]
    active_connections: dict[int, socket.socket]
    request_capacity_lock: threading.Lock
    unclassified_connections: dict[int, tuple[socket.socket, float]]
    pending_classifications: dict[int, tuple[tuple[str, int], float]]
    saturation_probes: dict[int, tuple[socket.socket, tuple[str, int], float]]
    unclassified_connections_lock: threading.Lock
    unclassified_watchdog_stop: threading.Event
    unclassified_watchdog_thread: threading.Thread | None
    runtime_heartbeat: RuntimeHeartbeatWriter
    general_request_executor: _BoundedRequestExecutor
    control_request_executor: _BoundedRequestExecutor
    request_executors_stopped: bool
    diagnostics: DaemonDiagnostics
    auth_audit_lock: threading.Lock
    denial_audit_lock: threading.Lock
    audit_persistence: AuditPersistence
    auth_audit_windows: dict[_AuthAuditKey, _AuthAuditWindow]
    command_queue_lifecycle: GuardDaemonServer | None
    home_dir: Path
    workspace_dir: Path | None

    def handle_error(self, request: Any, client_address: Any) -> None:
        """Suppress expected peer disconnects without hiding server defects."""

        import sys

        error = sys.exc_info()[1]
        if isinstance(error, _PEER_DISCONNECT_ERRORS) or (
            isinstance(error, OSError)
            and error.errno in {errno.EBADF, errno.ECONNABORTED, errno.ECONNRESET, errno.EPIPE}
        ):
            return
        self.diagnostics.record_exception("http_request_failed")

    def server_close(self) -> None:
        _ = self._stop_request_executors()
        audit_persistence = getattr(self, "audit_persistence", None)
        if audit_persistence is not None:
            audit_persistence.close()
        hook_worker = getattr(self, "hook_worker", None)
        if hook_worker is not None:
            with suppress(Exception):
                hook_worker.close()
        dispatch = getattr(self, "runtime_hook_evidence_dispatch", None)
        if dispatch is not None:
            # What a finished hook left behind is submitted before the writer
            # it submits to is dropped.
            with suppress(Exception):
                _ = dispatch.stop(1.0)
        writer = getattr(self, "runtime_hook_evidence_writer", None)
        if writer is not None:
            # The writer now lives in the resident, which can refuse the call.
            # Shutdown drops it either way; what it had queued is on its own
            # journal, and the next writer for this home recovers that.
            with suppress(Exception):
                _ = writer.stop(timeout_seconds=1.0)
        capture_writer = getattr(self, "codex_binding_capture_writer", None)
        if capture_writer is not None:
            capture_writer.stop_capture()
        super().server_close()

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
        home_dir: Path,
        workspace_dir: Path | None,
        idle_timeout_seconds: float | None,
        shutdown_started: threading.Event,
        diagnostics: DaemonDiagnostics,
    ) -> None:
        # TCPServer calls server_close() when bind/activation fails. Treat the
        # request executors as already stopped until their construction finishes.
        self.request_executors_stopped = True
        self.store = store
        self.runtime = GuardSurfaceRuntime(store)
        self.auth_token = auth_token
        self.runtime_host = runtime_host
        self.runtime_session_id = runtime_session_id
        self.runtime_started_at = runtime_started_at
        self.home_dir = home_dir.resolve(strict=False)
        self.workspace_dir = workspace_dir.resolve(strict=False) if workspace_dir is not None else None
        self.idle_timeout_seconds = idle_timeout_seconds
        self.last_activity_monotonic = time.monotonic()
        self.idle_shutdown_claimed = False
        self.start_monotonic = time.monotonic()
        self.active_stream_clients = 0
        self.active_stream_clients_lock = threading.Lock()
        self.shutdown_started = shutdown_started
        self.diagnostics = diagnostics
        self.auth_audit_lock, self.denial_audit_lock = threading.Lock(), threading.Lock()
        self.auth_audit_windows = {}
        self.audit_persistence = AuditPersistence(
            store, diagnostics, attempt_timeout_seconds=_AUTH_AUDIT_SQLITE_TIMEOUT_SECONDS
        )
        self.command_queue_lifecycle = None
        self.package_firewall_connect_state = None
        self.package_firewall_connect_state_lock = threading.Lock()
        self.onefile_extraction_status = None
        self.repair_self_check_status = None
        self.guard_cloud_connect_state = None
        self.guard_cloud_connect_state_lock = threading.Lock()
        self.guard_cloud_browser_session_lock = threading.Lock()
        self.package_firewall_action_rate_limiter = PackageFirewallActionRateLimiter()
        self.package_firewall_mutation_lock = threading.Lock()
        self.package_firewall_session_nonces = {}
        self.package_firewall_session_nonces_lock = threading.Lock()
        self.daemon_discovery_challenges = {}
        self.daemon_discovery_challenges_lock = threading.Lock()
        self.dashboard_reconnect_lock = threading.Lock()
        self.dashboard_reconnect_consumed_challenges = {}
        self.containment_health_cache = None
        self.containment_health_cache_monotonic = 0.0
        self.containment_health_cache_lock = threading.Lock()
        self.containment_health_refreshing = False
        self.containment_health_refresh_event = threading.Event()
        self.containment_health_generation = 0
        self.containment_health_completed_generation = 0
        self.network_supervisor = NetworkSupervisor()
        self.active_hook_requests = 0
        self.rejected_hook_requests = 0
        self.hook_harness_active = {}
        self.hook_harness_rejected = {}
        self.hook_capacity_lock = threading.Lock()
        self.runtime_hook_scheduler = RuntimeHookScheduler(
            active_limit=_MAX_CONCURRENT_RUNTIME_HOOKS,
            per_harness_active_limit=_MAX_CONCURRENT_RUNTIME_HOOKS_PER_HARNESS,
        )
        self.request_capacity_limit = _MAX_CONCURRENT_DAEMON_REQUESTS
        self.request_capacity = threading.BoundedSemaphore(self.request_capacity_limit)
        self.connection_capacity_limit = _MAX_CONCURRENT_DAEMON_CONNECTIONS
        self.connection_capacity = threading.BoundedSemaphore(self.connection_capacity_limit)
        self.control_request_capacity_limit = _MAX_CONCURRENT_DAEMON_CONTROL_REQUESTS
        self.control_request_capacity = threading.BoundedSemaphore(self.control_request_capacity_limit)
        self.critical_request_capacity_limit = _MAX_CONCURRENT_DAEMON_CRITICAL_REQUESTS
        self.critical_request_capacity = threading.BoundedSemaphore(self.critical_request_capacity_limit)
        self.active_requests = 0
        self.normal_connections = set()
        self.rejected_requests = 0
        self.request_capacity_kinds = {}
        self.request_accepted_at = {}
        self.active_connections = {}
        self.request_capacity_lock = threading.Lock()
        self.unclassified_connections = {}
        self.pending_classifications = {}
        self.saturation_probes = {}
        self.unclassified_connections_lock = threading.Lock()
        self.unclassified_watchdog_stop = threading.Event()
        self.unclassified_watchdog_thread = None
        self.runtime_heartbeat = RuntimeHeartbeatWriter(
            store=store,
            session_id=runtime_session_id,
            write_timeout_seconds=0.05,
            retry_interval_seconds=0.05,
        )
        self.store.set_policy_integrity_state_listener(self.publish_trust_state)
        self.runtime_hook_evidence_writer = NativeHookEvidenceWriter(store=store)
        # Evidence for a hook that has already answered is submitted here
        # rather than on the thread the harness is waiting on.
        self.runtime_hook_evidence_dispatch = HookEvidenceDispatch()
        self.codex_binding_capture_writer = start_codex_binding_capture_writer()
        self._initialize_request_services()
        self.request_executors_stopped = False
        super().__init__(server_address, handler_class)

    def _initialize_request_services(self) -> None:
        from .hook_direct_counters import bind_hook_counter_sink
        from .hook_worker import HookWorker

        try:
            self.hook_worker = HookWorker(
                store=self.store,
                workspace=self.workspace_dir,
                home_dir=self.home_dir,
                activity_writer=self.runtime_hook_evidence_writer,
                evidence_dispatch=self.runtime_hook_evidence_dispatch,
                capture_writer=self.codex_binding_capture_writer,
            )
            bind_hook_counter_sink(self.hook_worker, getattr(self, "diagnostics", None))
            from ..catalog_delivery.projection import capture

            try:
                self._migrate_installed_authority()
                _, control_registry, _ = capture(self.store)
                startup_view = self._startup_extension_control_view(control_registry)
            except (_InstalledAuthorityMigrationError, NativePolicySnapshotError):
                # An activation record this build cannot authenticate, such as
                # one written under a newer schema, or an installed release whose
                # authority could not be migrated, activates nothing. Start on
                # the core registry with a tampered authority so every hook
                # fails closed, rather than taking hook protection down with
                # the daemon. The refresh loop keeps this snapshot until the
                # record reads again.
                control_registry = BUILT_IN_COMMAND_EXTENSION_REGISTRY
                startup_view = self.store._tampered_view(control_registry.catalog_digest)
                self._extension_control_on_core_registry = True
            self.extension_control_runtime = ExtensionControlRuntime(startup_view)
            self.extension_control_api = ExtensionControlApiService(
                store=self.store,
                registry=control_registry,
                runtime=self.extension_control_runtime,
            )
            self.local_cli_api = LocalCliApiService(store=self.store)
            self.approval_attention = ApprovalAttentionCoordinator(
                store=self.store,
                runtime=self.runtime,
                opener=open_browser_url,
                home_dir=self.home_dir,
            )
            self.general_request_executor = _BoundedRequestExecutor(
                name="general",
                workers=_MAX_CONCURRENT_DAEMON_REQUESTS,
                queue_limit=_MAX_CONCURRENT_DAEMON_CONNECTIONS,
                run=self._process_request_worker,
                discard=self._discard_request,
            )
            self.control_request_executor = _BoundedRequestExecutor(
                name="control",
                workers=_MAX_CONCURRENT_DAEMON_CONTROL_REQUESTS,
                queue_limit=_MAX_CONCURRENT_DAEMON_CONNECTIONS,
                run=self._process_request_worker,
                discard=self._discard_request,
            )
        except BaseException:
            for executor_name in ("control_request_executor", "general_request_executor"):
                executor = getattr(self, executor_name, None)
                if executor is not None:
                    _ = executor.shutdown(timeout_seconds=1.0)
            with suppress(Exception):
                _ = self.runtime_hook_evidence_dispatch.stop(1.0)
            with suppress(Exception):
                _ = self.runtime_hook_evidence_writer.stop(timeout_seconds=1.0)
            if self.codex_binding_capture_writer is not None:
                self.codex_binding_capture_writer.stop_capture()
            raise

    def _migrate_installed_authority(self) -> None:
        """Admit the installed release, or report why it cannot be admitted yet.

        A failure leaves the migration pending. The daemon then starts on a
        tampered authority, so every hook fails closed instead of the daemon
        exiting, and each refresh retries it before reading anything newer.
        """

        try:
            self.store.migrate_installed_command_pack_authority()
        except Exception as error:
            self._installed_authority_pending = True
            _LOGGER.warning("Installed command-pack authority could not be migrated: %s", error, exc_info=True)
            raise _InstalledAuthorityMigrationError from error
        self._installed_authority_pending = False

    def _startup_extension_control_view(
        self, registry: CommandSafetyExtensionRegistry
    ) -> ExtensionControlAuthorityView:
        """Read the authority for startup without letting a busy lease stop the daemon.

        A lease timeout reports that the authority was not read, never that it
        is unhealthy, so this falls back to the shared lease that a reader can
        always join. Only if that is unobtainable too does the daemon start on
        a view with no layers, which the next refresh replaces. Refusing to
        start would take the hook worker down with it, and a daemon that is not
        there protects nothing.

        Both attempts take the same exclusive entry gate, so they share one
        acquisition budget rather than waiting it twice in sequence. The
        exclusive attempt gets half of it, which leaves the shared fallback a
        span to run in instead of arriving after the budget is already spent.
        """

        from ..native_command_control_authority_io import (
            AUTHORITY_LOCK_TIMEOUT_SECONDS,
            NativeCommandControlAuthorityUnavailableError,
            NativeCommandControlMutationRequiredError,
        )

        deadline = time.monotonic() + AUTHORITY_LOCK_TIMEOUT_SECONDS
        with suppress(NativeCommandControlAuthorityUnavailableError):
            return self.store.read_extension_control_authority_for_registry(
                registry, lock_timeout_seconds=AUTHORITY_LOCK_TIMEOUT_SECONDS / 2
            )
        remaining = deadline - time.monotonic()
        if remaining > 0.0:
            with suppress(NativeCommandControlAuthorityUnavailableError, NativeCommandControlMutationRequiredError):
                return self.store.read_extension_control_authority_for_registry(
                    registry, read_only=True, lock_timeout_seconds=remaining
                )
        return self.store.extension_control_authority_unreadable_view(registry.catalog_digest)

    def refresh_extension_control_runtime(self) -> ExtensionControlRuntimeSnapshot:
        from ..catalog_delivery.projection import capture, require_current
        from ..native_command_control_authority_io import (
            NativeCommandControlAuthorityUnavailableError,
            NativeCommandControlMutationRequiredError,
            hold_command_control_authority_lock,
        )
        from ..native_command_control_authority_store import _key

        def read(*, shared: bool) -> ExtensionControlRuntimeSnapshot:
            _, registry, activation_digest = capture(self.store)
            with hold_command_control_authority_lock(self.store.guard_home, shared=shared):
                require_current(self.store, _key(self.store), activation_digest)
                view = self.store.read_extension_control_authority_for_registry(registry, read_only=shared)
                snapshot = self.extension_control_runtime.refresh(view)
            if self._extension_control_on_core_registry:
                # Startup bound the control API to the core registry. Once the
                # authority reads again, serve the registry it was read for so
                # previews and mutations stop failing against the core one.
                self.extension_control_api.rebind_registry(registry)
                self._extension_control_on_core_registry = False
            return snapshot

        if self._installed_authority_pending:
            try:
                self._migrate_installed_authority()
            except _InstalledAuthorityMigrationError:
                # Nothing newer is admitted until the release is migrated.
                return self.extension_control_runtime.current()
        try:
            try:
                return read(shared=True)
            except NativeCommandControlMutationRequiredError:
                # Release the shared lease before migration and recapture the
                # active projection under the exclusive mutation fence.
                return read(shared=False)
        except NativeCommandControlAuthorityUnavailableError:
            # Nothing was read, so there is nothing to refresh from. Keeping the
            # snapshot already installed beats replacing a known authority with
            # the absence of a reading.
            return self.extension_control_runtime.current()

    def process_request(self, request: Any, client_address: Any) -> None:
        request_socket = cast(socket.socket, request)
        accepted_at = time.monotonic()
        admission_deadline = accepted_at + _DAEMON_CONNECTION_ADMISSION_WAIT_SECONDS
        # Do not wait for bytes on the accept thread. A saturated burst of
        # idle peers would otherwise hold the next connection, including
        # health, until each of those peers had been polled.
        path = self._peek_request_path(request_socket)
        control = path in _DAEMON_CONTROL_PATHS or path in _DAEMON_CRITICAL_PATHS
        if path is not None and not control and self._normal_admission_full():
            with self.request_capacity_lock:
                self.rejected_requests += 1
            self._guard_reject_overload(request_socket)
            return
        reserved_normal = False
        if not control:
            reserved_normal = self._reserve_normal_connection(request_socket)
            # Park only while a connection permit remains. That permit is
            # reserved for control, so an in-flight line must not take it.
            # A full pool still goes through admission and can evict.
            if (
                path is None
                and not reserved_normal
                and self._normal_admission_full()
                and self.connection_capacity.acquire(blocking=False)
            ):
                self.connection_capacity.release()
                self._park_saturation_probe(request_socket, client_address, accepted_at)
                return
        pending = not control and not reserved_normal
        self._accept_classified_request(
            request_socket,
            client_address,
            control=control,
            pending=pending,
            accepted_at=accepted_at,
            admission_deadline=admission_deadline,
        )

    def _accept_classified_request(
        self,
        request_socket: socket.socket,
        client_address: Any,
        *,
        control: bool,
        pending: bool,
        accepted_at: float,
        admission_deadline: float,
    ) -> None:
        # A live holder keeps its slot until it finishes or the watchdog
        # expires it. Evicting it here would admit the newcomer and hide overload.
        try:
            guard_admitted = self._guard_admit_request(request_socket)
        except BaseException:
            with self.request_capacity_lock:
                self.normal_connections.discard(id(request_socket))
            raise
        if not guard_admitted:
            with self.request_capacity_lock:
                self.normal_connections.discard(id(request_socket))
                self.rejected_requests += 1
            return
        admitted = self.connection_capacity.acquire(blocking=False)
        if not admitted:
            self._evict_oldest_unclassified_connection()
            admitted = self.connection_capacity.acquire(
                blocking=True,
                timeout=max(0.0, admission_deadline - time.monotonic()),
            )
        if not admitted:
            with self.request_capacity_lock:
                self.rejected_requests += 1
            try:
                self.shutdown_request(request_socket)
            finally:
                self._guard_release_request()
                with self.request_capacity_lock:
                    self.normal_connections.discard(id(request_socket))
            return
        # Admission and the idle watchdog's shutdown claim share this lock, so a
        # request is either counted before the claim or refused here, never
        # admitted into a server that is closing.
        with self.request_capacity_lock:
            closing = self.idle_shutdown_claimed
            if closing:
                self.rejected_requests += 1
            else:
                self.active_requests += 1
                self.last_activity_monotonic = time.monotonic()
        if closing:
            try:
                self.shutdown_request(request_socket)
            finally:
                self.connection_capacity.release()
                self._guard_release_request()
                with self.request_capacity_lock:
                    self.normal_connections.discard(id(request_socket))
            return
        with suppress(OSError):
            request_socket.settimeout(_DAEMON_REQUEST_READ_TIMEOUT_SECONDS)
        self._register_unclassified_connection(request_socket, accepted_at=accepted_at)
        if pending:
            # Do not serialize partial-header waits on the accept thread.
            # These sockets still own both outer permits; the existing bounded
            # watchdog classifies them within this admission's original budget.
            with self.unclassified_connections_lock:
                if id(request_socket) in self.unclassified_connections:
                    self.pending_classifications[id(request_socket)] = (
                        cast(tuple[str, int], client_address),
                        min(admission_deadline, accepted_at + _DAEMON_REQUEST_READ_TIMEOUT_SECONDS),
                    )
            return
        self._submit_transport_request(request_socket, client_address, control=control)

    def _park_saturation_probe(self, request: socket.socket, client_address: Any, accepted_at: float) -> None:
        deadline = accepted_at + 0.15
        limit = max(1, self.connection_capacity_limit)
        displaced: tuple[socket.socket, tuple[str, int], float] | None = None
        with self.unclassified_connections_lock:
            # A full probe table is older unread clients. Closing the newcomer
            # drops a health check that has not sent its request line yet.
            if len(self.saturation_probes) >= limit:
                displaced = self.saturation_probes.pop(next(iter(self.saturation_probes)))
            self.saturation_probes[id(request)] = (request, cast(tuple[str, int], client_address), deadline)
        if displaced is None:
            return
        with self.request_capacity_lock:
            self.rejected_requests += 1
        self._close_unclassified_socket(displaced[0])

    def _submit_transport_request(self, request_socket: socket.socket, client_address: Any, *, control: bool) -> None:
        # An unread socket stays on the evictable set. Starting a worker
        # classifies it and holds its connection permit until the read times
        # out, which closes a later health check without a response.
        # Classification advancement removes the socket before submit, so a
        # completed header does not return here.
        if not self._buffered_request_headers_complete(request_socket, pending=True):
            with self.unclassified_connections_lock:
                current = self.unclassified_connections.get(id(request_socket))
                if current is not None and current[0] is request_socket:
                    self.pending_classifications[id(request_socket)] = (
                        cast(tuple[str, int], client_address),
                        current[1],
                    )
                    return
        executor = (
            self.control_request_executor
            if control or self._transport_request_is_control(request_socket)
            else self.general_request_executor
        )
        try:
            submitted = executor.submit(request_socket, client_address)
        except BaseException:
            self._discard_request(request_socket)
            raise
        if not submitted:
            with self.request_capacity_lock:
                self.rejected_requests += 1
            self._discard_request(request_socket)

    def _normal_admission_limit(self) -> int:
        capacity = min(self.connection_capacity_limit, self._guard_capacity_limit)
        reserved = min(self.control_request_capacity_limit + self.critical_request_capacity_limit, capacity // 4)
        return capacity - reserved

    def _normal_admission_full(self) -> bool:
        with self.request_capacity_lock:
            return len(self.normal_connections) >= self._normal_admission_limit()

    def _reserve_normal_connection(self, request: socket.socket) -> bool:
        # Reserve within both admission bounds, including a smaller configured
        # outer HTTP limit. No new sockets, workers or priority authorization.
        with self.request_capacity_lock:
            if len(self.normal_connections) >= self._normal_admission_limit():
                return False
            self.normal_connections.add(id(request))
        return True

    def _process_request_worker(self, request_socket: socket.socket, client_address: tuple[str, int]) -> None:
        try:
            self.finish_request(request_socket, client_address)
            self.shutdown_request(request_socket)
        except BaseException:
            self.handle_error(request_socket, client_address)
            self.shutdown_request(request_socket)
        finally:
            self._release_request_capacity(request_socket)

    def _discard_request(self, request_socket: socket.socket) -> None:
        try:
            self.shutdown_request(request_socket)
        finally:
            self._release_request_capacity(request_socket)

    def _release_request_capacity(self, request: socket.socket) -> None:
        self.classify_connection(request)
        with self.request_capacity_lock:
            was_active = self.request_accepted_at.pop(id(request), None) is not None
            self.active_connections.pop(id(request), None)
            self.normal_connections.discard(id(request))
            if was_active:
                self.active_requests -= 1
                # The idle clock starts when the last request finishes, not when it started.
                self.last_activity_monotonic = time.monotonic()
            capacity_kind = self.request_capacity_kinds.pop(id(request), None)
        if capacity_kind is not None:
            self._request_capacity_for_kind(capacity_kind).release()
        if was_active:
            self.connection_capacity.release()
            self._guard_release_request()

    def _register_unclassified_connection(self, request: socket.socket, *, accepted_at: float | None = None) -> None:
        if accepted_at is None:
            accepted_at = time.monotonic()
        deadline = accepted_at + _DAEMON_REQUEST_READ_TIMEOUT_SECONDS
        with self.request_capacity_lock:
            self.request_accepted_at[id(request)] = accepted_at
            self.active_connections[id(request)] = request
        with self.unclassified_connections_lock:
            self.unclassified_connections[id(request)] = (request, deadline)

    def request_deadline(self, request: socket.socket, timeout_seconds: float) -> float:
        with self.request_capacity_lock:
            accepted_at = self.request_accepted_at.get(id(request), time.monotonic())
        return accepted_at + timeout_seconds

    @staticmethod
    def _peek_request_path(request: socket.socket, *, deadline: float | None = None) -> str | None:
        try:
            request.setblocking(False)
            while True:
                try:
                    buffered = request.recv(4_096, socket.MSG_PEEK)
                except (BlockingIOError, InterruptedError):
                    buffered = b""
                if b"\n" in buffered:
                    break
                if deadline is None or time.monotonic() >= deadline or len(buffered) >= 4_096:
                    return None
                remaining = max(0.0, deadline - time.monotonic())
                if buffered:
                    # MSG_PEEK keeps a partial line readable, so select would
                    # spin on the same prefix. Keep this wait on the one budget.
                    time.sleep(min(0.001, remaining))
                else:
                    select.select([request], [], [], remaining)
        except (BlockingIOError, InterruptedError, OSError, ValueError):
            return None
        finally:
            with suppress(OSError):
                request.settimeout(_DAEMON_REQUEST_READ_TIMEOUT_SECONDS)
        request_line = buffered.splitlines()[0] if buffered else b""
        parts = request_line.split()
        if len(parts) != 3 or not parts[2].startswith(b"HTTP/"):
            return None
        try:
            return parts[1].decode("ascii").split("?", 1)[0]
        except UnicodeDecodeError:
            return None

    @staticmethod
    def _transport_request_is_control(request: socket.socket, *, deadline: float | None = None) -> bool:
        path = _GuardDaemonHTTPServer._peek_request_path(request, deadline=deadline)
        return path in _DAEMON_CONTROL_PATHS or path in _DAEMON_CRITICAL_PATHS

    def _stop_request_executors(self) -> bool:
        if self.request_executors_stopped:
            return True
        with self.request_capacity_lock:
            requests = list(self.active_connections.values())
        with self.unclassified_connections_lock:
            pending = set(self.pending_classifications)
            self.pending_classifications.clear()
            probes = [probe[0] for probe in self.saturation_probes.values()]
            self.saturation_probes.clear()
        for request in probes:
            self._close_unclassified_socket(request)
        for request in requests:
            if id(request) in pending:
                self._discard_request(request)
            else:
                self._close_unclassified_socket(request)
        general_stopped = self.general_request_executor.shutdown(timeout_seconds=5.0)
        control_stopped = self.control_request_executor.shutdown(timeout_seconds=5.0)
        self.request_executors_stopped = general_stopped and control_stopped
        return self.request_executors_stopped

    def classify_connection(self, request: socket.socket) -> None:
        with self.unclassified_connections_lock:
            self.unclassified_connections.pop(id(request), None)
            self.pending_classifications.pop(id(request), None)
            self.saturation_probes.pop(id(request), None)

    def _evict_oldest_unclassified_connection(self) -> None:
        with self.unclassified_connections_lock:
            oldest = next(iter(self.unclassified_connections.values()), None)
        if oldest is not None:
            self._discard_request(oldest[0])
            with self.request_capacity_lock:
                self.rejected_requests += 1

    @staticmethod
    def _close_unclassified_socket(request: socket.socket) -> None:
        with suppress(OSError):
            request.shutdown(socket.SHUT_RDWR)
        with suppress(OSError):
            request.close()

    def start_unclassified_watchdog(self) -> None:
        if self.unclassified_watchdog_thread is not None and self.unclassified_watchdog_thread.is_alive():
            return
        self.unclassified_watchdog_stop.clear()
        self.unclassified_watchdog_thread = threading.Thread(
            target=self._watch_unclassified_connections,
            daemon=True,
            name="guard-unclassified-connection-watchdog",
        )
        self.unclassified_watchdog_thread.start()

    def stop_unclassified_watchdog(self) -> bool:
        self.unclassified_watchdog_stop.set()
        thread = self.unclassified_watchdog_thread
        if thread is not None:
            thread.join(timeout=1.0)
        if thread is None or not thread.is_alive():
            self.unclassified_watchdog_thread = None
        return self.unclassified_watchdog_thread is None

    def _watch_unclassified_connections(self) -> None:
        while not self.unclassified_watchdog_stop.wait(_DAEMON_UNCLASSIFIED_WATCHDOG_POLL_SECONDS):
            self._advance_pending_classifications()
            self._advance_saturation_probes()
            now = time.monotonic()
            with self.unclassified_connections_lock:
                expired = [request for request, deadline in self.unclassified_connections.values() if deadline <= now]
            for request in expired:
                headers_complete = self._buffered_request_headers_complete(request)
                with self.unclassified_connections_lock:
                    current = self.unclassified_connections.get(id(request))
                    if current is None or current[0] is not request or current[1] > now:
                        continue
                    owned_by_pending = id(request) in self.pending_classifications
                    if not owned_by_pending:
                        self.unclassified_connections.pop(id(request))
                        if not headers_complete:
                            self._close_unclassified_socket(request)
                if owned_by_pending:
                    self._discard_request(request)

    def _advance_pending_classifications(self) -> None:
        with self.unclassified_connections_lock:
            pending = [
                (self.unclassified_connections[key][0], address, deadline)
                for key, (address, deadline) in self.pending_classifications.items()
                if key in self.unclassified_connections
            ]
        for request, address, deadline in pending:
            with self.unclassified_connections_lock:
                if id(request) not in self.pending_classifications:
                    continue
            if time.monotonic() >= deadline or self._unread_peer_closed(request):
                self._discard_request(request)
                continue
            if not self._buffered_request_headers_complete(request, pending=True):
                continue
            control = self._transport_request_is_control(request)
            with self.unclassified_connections_lock:
                if self.pending_classifications.pop(id(request), None) is None:
                    continue
                self.unclassified_connections.pop(id(request), None)
            if not control and not self._reserve_normal_connection(request):
                # The socket reserved its seat before its headers were ready.
                # A full pool makes a second reserve fail even though this
                # request already counts toward the limit.
                with self.request_capacity_lock:
                    already_reserved = id(request) in self.normal_connections
                    if not already_reserved:
                        self.rejected_requests += 1
                if not already_reserved:
                    self._discard_request(request)
                    continue
            try:
                self._submit_transport_request(request, address, control=control)
            except BaseException:
                # Submission already discarded this socket and its permits.
                self.handle_error(request, address)

    def _advance_saturation_probes(self) -> None:
        with self.unclassified_connections_lock:
            probes = list(self.saturation_probes.values())
        for request, address, deadline in probes:
            path = self._peek_request_path(request)
            if path is None and time.monotonic() < deadline:
                continue
            with self.unclassified_connections_lock:
                current = self.saturation_probes.pop(id(request), None)
            if current is None or current[0] is not request:
                continue
            control = path in _DAEMON_CONTROL_PATHS or path in _DAEMON_CRITICAL_PATHS
            if path is None or not control:
                with self.request_capacity_lock:
                    self.rejected_requests += 1
                if path is None:
                    self._close_unclassified_socket(request)
                else:
                    self._guard_reject_overload(request)
                continue
            accepted_at = time.monotonic()
            try:
                self._accept_classified_request(
                    request,
                    address,
                    control=True,
                    pending=False,
                    accepted_at=accepted_at,
                    admission_deadline=accepted_at + _DAEMON_CONNECTION_ADMISSION_WAIT_SECONDS,
                )
            except BaseException:
                self.handle_error(request, address)

    @staticmethod
    def _unread_peer_closed(request: socket.socket) -> bool:
        """Return whether the peer closed before sending a request line."""
        timeout = request.gettimeout()
        try:
            if not select.select([request], [], [], 0)[0]:
                return False
            request.setblocking(False)
            peeked = request.recv(1, socket.MSG_PEEK | (getattr(socket, "MSG_DONTWAIT", 0) or 0))
        except (BlockingIOError, InterruptedError):
            return False
        except OSError:
            return True
        finally:
            with suppress(OSError):
                request.settimeout(timeout)
        return peeked == b""

    @staticmethod
    def _buffered_request_headers_complete(request: socket.socket, *, pending: bool = False) -> bool:
        nonblocking_flag = getattr(socket, "MSG_DONTWAIT", None)
        if nonblocking_flag is None and not pending:
            return False
        timeout = request.gettimeout()
        try:
            if not select.select([request], [], [], 0)[0]:
                return False
            if pending:
                # This socket has not been handed to any request worker. Do
                # not let Python's timeout-mode select wrap a kernel peek.
                request.setblocking(False)
            buffered = request.recv(65_536, socket.MSG_PEEK | (nonblocking_flag or 0))
        except (BlockingIOError, InterruptedError, OSError, ValueError):
            return False
        finally:
            if pending:
                with suppress(OSError):
                    request.settimeout(timeout)
        return b"\r\n\r\n" in buffered or b"\n\n" in buffered

    def claim_request_capacity(self, request: socket.socket, path: str) -> bool:
        capacity_kind = self._request_capacity_kind(path)
        capacity = self._request_capacity_for_kind(capacity_kind)
        with self.request_capacity_lock:
            previous_kind = self.request_capacity_kinds.pop(id(request), None)
            if previous_kind is not None and id(request) in self.request_accepted_at:
                # A follow-up request on a kept-alive connection (the hook POST
                # after its identity challenge) starts its own admission clock.
                # Charging it the challenge round trip left loaded hosts with
                # too little of the hook budget to finish the review.
                self.request_accepted_at[id(request)] = time.monotonic()
        if previous_kind is not None:
            self._request_capacity_for_kind(previous_kind).release()
        admitted = (
            capacity.acquire(timeout=_DAEMON_CONTROL_ADMISSION_WAIT_SECONDS)
            if capacity_kind in {"critical", "control"}
            else capacity.acquire(blocking=False)
        )
        if not admitted:
            with self.request_capacity_lock:
                self.rejected_requests += 1
            return False
        with self.request_capacity_lock:
            self.request_capacity_kinds[id(request)] = capacity_kind
        return True

    def _request_capacity_for_kind(self, capacity_kind: str) -> threading.BoundedSemaphore:
        if capacity_kind == "critical":
            return self.critical_request_capacity
        if capacity_kind == "control":
            return self.control_request_capacity
        return self.request_capacity

    @staticmethod
    def _request_capacity_kind(path: str) -> str:
        path = path.split("?", 1)[0]
        if path in _DAEMON_CRITICAL_PATHS:
            return "critical"
        if path in _DAEMON_CONTROL_PATHS:
            return "control"
        return "general"

    @staticmethod
    def canonical_hook_capacity_harness(harness: str) -> str:
        try:
            return get_adapter(harness).harness
        except ValueError:
            return "other"

    def daemon_host(self) -> str:
        return str(self.server_address[0])

    def daemon_port(self) -> int:
        return int(self.server_address[1])

    def publish_trust_state(self, trust_status: dict[str, object] | None = None) -> None:
        write_guard_daemon_state(
            self.store.guard_home,
            self.daemon_port(),
            self.auth_token,
            write_auth_token=False,
            host=self.daemon_host(),
            state_id=self.runtime_session_id,
            started_at=self.runtime_started_at,
            trust_status=trust_status or self.store.get_cached_policy_integrity_state(),
        )


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


_DEFAULT_SUPPLY_CHAIN_REFRESH_BACKOFF_SECONDS = 60.0
_DEFAULT_SUPPLY_CHAIN_REFRESH_INTERVAL_SECONDS = 15 * 60.0
_EPHEMERAL_GUARD_DAEMON_IDLE_TIMEOUT_SECONDS = 5
_GUARD_DAEMON_IDLE_POLL_INTERVAL_SECONDS = 0.5


_GuardDaemonHttpServer = _GuardDaemonHTTPServer


class _GuardDaemonHandler(
    _DashboardRuntimeReadRoutes,
    _DashboardRecordsReadRoutes,
    _DashboardSupportRoutes,
    _ControlPostRoutes,
    _SupplyChainRoutes,
    _CloudConnectRoutes,
    _HeadlessRoutes,
    _ControlMiscRoutes,
    _RepairSettingsRoutes,
    _ControlPolicyRoutes,
    _ControlSyncRoutes,
    _ControlOperationRoutes,
    _ControlHealthRoutes,
    BaseHTTPRequestHandler,
):
    _MAX_BODY_BYTES = 1_000_000
    server: _GuardDaemonHttpServer  # pyright: ignore[reportIncompatibleVariableOverride]

    def end_headers(self) -> None:
        # Every response names the dashboard bundle this daemon serves, so a tab
        # still running an older bundle notices the restart and reloads.
        build_id = dashboard_build_id(_STATIC_DIR)
        if build_id is not None:
            self.send_header(DASHBOARD_BUILD_HEADER, build_id)
        super().end_headers()

    def parse_request(self) -> bool:
        parsed = super().parse_request()
        self._daemon_server().classify_connection(self.request)
        if not parsed:
            return False
        if self._daemon_server().claim_request_capacity(self.request, self.path):
            return True
        self.send_error(503, "Guard daemon request capacity reached")
        return False

    def do_OPTIONS(self) -> None:
        origin = self._normalize_origin(self.headers.get("Origin"))
        if origin is None:
            self._write_empty(status=400)
            return
        headers = self._cors_headers_for_request(
            allow_methods="GET, POST, DELETE, OPTIONS",
            allow_headers=(
                "Authorization, Content-Type, If-None-Match, Last-Event-ID, X-Guard-Dashboard-Session, X-Guard-Token"
            ),
        )
        if headers is None:
            self._write_empty(status=403)
            return
        self._write_empty(status=200, extra_headers=headers)

    def _serve_desktop_bootstrap(self, store: GuardStore) -> None:
        """Return the desktop bootstrap document without queueing behind hook traffic.

        The token is accepted only as a header. A query-string token is rejected
        the same way as the other v1 routes. Failure is a 503 so the CLI falls
        through to the full bootstrap command.
        """

        parsed = urlparse(self.path)
        if self._query_has_guard_token(parsed.query):
            self._record_query_token_rejection()
            self._write_unauthorized(extra_headers=self._cors_headers_for_request())
            return
        if not self._header_token_is_valid():
            self._write_unauthorized(extra_headers=self._cors_headers_for_request())
            return
        try:
            from ..cli.commands_dispatch_desktop import desktop_bootstrap_document_for_running_daemon

            document = desktop_bootstrap_document_for_running_daemon(
                store=store,
                home_dir=self.server.home_dir,
                daemon_url=f"http://127.0.0.1:{self.server.daemon_port()}",
                auth_token=self.server.auth_token,
            )
        except Exception:
            diagnostics = getattr(self.server, "diagnostics", None)
            if diagnostics is not None:
                diagnostics.record_exception("desktop_bootstrap_unavailable")
            self._write_json({"error": "desktop_bootstrap_unavailable"}, status=503)
            return
        self._write_json(document)

    def do_GET(self) -> None:
        store = self.server.store  # type: ignore[attr-defined]
        parsed = urlparse(self.path)
        self._touch_runtime_heartbeat(parsed.path)
        path_parts = [part for part in parsed.path.split("/") if part]
        if not self._origin_is_allowed_for_request(parsed.path):
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
        if parsed.path == "/v1/desktop/bootstrap":
            self._serve_desktop_bootstrap(store)
            return
        if parsed.path == "/v1/events/stream":
            if self._query_has_guard_token(parsed.query):
                self._record_query_token_rejection()
                self._write_unauthorized(extra_headers=self._cors_headers_for_request())
                return
            if not self._header_token_is_valid():
                self._write_unauthorized(extra_headers=self._cors_headers_for_request())
                return
            cursor_decision = self._native_handler_decision(
                lambda: native_events_cursor(parsed.query, guard_home=store.guard_home)
            )
            if cursor_decision is None:
                return
            self._stream_events(cursor_decision.fields["cursor"])
            return
        if parsed.path == "/v1/command-activity/events":
            if self._query_has_guard_token(parsed.query):
                self._record_query_token_rejection()
                self._write_unauthorized(extra_headers=self._cors_headers_for_request())
                return
            if not self._header_token_is_valid():
                self._write_unauthorized(extra_headers=self._cors_headers_for_request())
                return
            try:
                cursor = parse_command_activity_event_cursor(
                    parsed.query,
                    last_event_id=self.headers.get("Last-Event-ID"),
                )
            except ValueError as error:
                self._write_json({"error": str(error)}, status=400)
                return
            stream_command_activity_events(self, cursor)
            return
        if parsed.path.startswith("/v2/"):
            # /v2/ is outside the /v1/ prefix check below; authenticate it
            # explicitly before any metadata or ETag comparison.
            if self._query_has_guard_token(parsed.query):
                self._record_query_token_rejection()
                self._write_unauthorized(extra_headers=self._cors_headers_for_request())
                return
            if not self._header_token_is_valid():
                self._write_unauthorized(extra_headers=self._cors_headers_for_request())
                return
            if parsed.path.startswith(CATALOG_V2_PREFIX):
                daemon = self._daemon_server()
                serve_catalog_read_v2(
                    self,
                    path=parsed.path,
                    query=parsed.query,
                    if_none_match=self.headers.get("If-None-Match"),
                    guard_home=self.server.store.guard_home,  # type: ignore[attr-defined]
                    catalog_digest=daemon.extension_control_api.catalog_digest,
                )
                return
            self._write_json({"error": "not_found"}, status=404)
            return
        if parsed.path.startswith(_LOCAL_DISCOVERY_PREFIX):
            if self._query_has_guard_token(parsed.query):
                self._record_query_token_rejection()
                self._write_unauthorized(extra_headers=self._cors_headers_for_request())
                return
            if not self._header_token_is_valid():
                self._write_unauthorized(extra_headers=self._cors_headers_for_request())
                return
            # A device whose user or administrator turned sponsored discovery
            # off answers that before anything that can fail. The rollout gate,
            # the native capability and the upstream read all have failure
            # modes, and a failure must never read as "no preference stated" on
            # a device that already stated one.
            if parsed.path == _LOCAL_DISCOVERY_PLACEMENTS and not sponsored_discovery_allowed(
                self.server.store  # type: ignore[attr-defined]
            ):
                self._write_json({"error": DISCOVERY_OPTED_OUT}, status=403)
                return
            if not discovery_rollout_enabled():
                self._write_json({"error": DISCOVERY_UNAVAILABLE}, status=503)
                return
            if parsed.path == _LOCAL_DISCOVERY_SETTINGS:
                store = self.server.store  # type: ignore[attr-defined]
                self._write_json(sponsored_discovery_settings(store))
                return
            if parsed.path != _LOCAL_DISCOVERY_PLACEMENTS:
                self._write_json({"error": "not_found"}, status=404)
                return
            # Sponsored discovery is user/managed gated; a disabled preference
            # still answers a valid policy-blocked projection rather than an
            # error, so the dashboard can distinguish opt-out from failure.
            store = self.server.store  # type: ignore[attr-defined]
            allowed = sponsored_discovery_allowed(store)
            result = discovery_placement_projection(
                guard_home=store.guard_home,
                policy_allowed=allowed,
            )
            if result is None:
                self._write_json({"error": DISCOVERY_UNAVAILABLE}, status=501)
                return
            if result.error_code is not None:
                self._write_json({"error": result.error_code}, status=result.status)
                return
            if result.body is None:
                self._write_json({"error": DISCOVERY_UNAVAILABLE}, status=503)
                return
            self._write_discovery_body(result.body)
            return
        if parsed.path.startswith("/v1/") and not self._header_token_is_valid():
            self._write_unauthorized(extra_headers=self._cors_headers_for_request())
            return
        if self._serve_dashboard_runtime_read(parsed, path_parts, store):
            return
        if self._serve_dashboard_records_read(parsed, path_parts, store):
            return
        self.send_response(404)
        self.end_headers()

    def do_DELETE(self) -> None:
        parsed = urlparse(self.path)
        self._touch_runtime_heartbeat(parsed.path)
        if not self._origin_is_allowed_for_request(parsed.path):
            self._write_json({"error": "forbidden_origin"}, status=403)
            return
        if not self._header_token_is_valid():
            self._write_json(
                {"error": "unauthorized"},
                status=401,
                extra_headers=self._cors_headers_for_request(),
            )
            return
        body = self._read_delete_body() if parsed.path == "/v1/command-activity" else None
        store = self.server.store  # type: ignore[attr-defined]
        if parsed.path == "/v1/command-activity":
            if body is None:
                self._write_json({"error": "invalid_request"}, status=400)
                return
            if body.get("confirm") != "clear-command-activity":
                self._write_json(
                    {"error": "confirmation_required", "confirm": "clear-command-activity"},
                    status=400,
                )
                return
            try:
                require_high_risk(
                    store.guard_home,
                    purpose="evidence_clear",
                    approval_gate_input=approval_gate_input_from_mapping(body),
                )
            except ApprovalGateError as error:
                self._write_approval_gate_error(error)
                return
            self._write_json(store.clear_command_activity_evidence())
            return
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

    @scoped_hook_post
    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        self._touch_runtime_heartbeat(parsed.path)
        path_parts = [part for part in parsed.path.split("/") if part]
        if parsed.path in {"/v1/connect/requests", "/v1/connect/complete", "/v1/connect/result"}:
            self._write_legacy_pairing_disabled()
            return
        if not self._origin_is_allowed_for_request(parsed.path):
            self._write_json({"error": "forbidden_origin"}, status=403)
            return
        try:
            route = native_route_facts("POST", parsed.path, guard_home=self._route_home())
        except NativeDaemonRouteError:
            self._write_json(native_route_unavailable_body(), status=503)
            return
        discovery_post = parsed.path.startswith(_LOCAL_DISCOVERY_PREFIX)
        if discovery_post and self._query_has_guard_token(parsed.query):
            self._record_query_token_rejection()
            self._write_unauthorized(extra_headers=self._cors_headers_for_request())
            return
        if (route.route_class != "none" or discovery_post) and not self._header_token_is_valid():
            self._write_unauthorized(extra_headers=self._cors_headers_for_request())
            return
        if route.route_class != "none" or discovery_post:
            try:
                content_length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                self._write_json({"error": "invalid_content_length"}, status=400)
                return
            if content_length < 0 or content_length > self._MAX_BODY_BYTES:
                self._write_json({"error": "body_too_large"}, status=413)
                return
        payload, body_error = self._load_request_body()
        if body_error is not None:
            status = {
                "request_body_timeout": 408,
                "request_body_too_large": 413,
            }.get(body_error, 400)
            self._write_json({"error": body_error}, status=status)
            return
        if parsed.path.startswith(_LOCAL_DISCOVERY_PREFIX):
            if not discovery_rollout_enabled():
                self._write_json({"error": DISCOVERY_UNAVAILABLE}, status=503)
                return
            store = self.server.store  # type: ignore[attr-defined]
            upstream = _LOCAL_DISCOVERY_MEASUREMENT.get(parsed.path)
            if upstream is not None:
                # Consent-gated relay: measurement off still allows discovery
                # but emits no render/event POSTs and no persistent identity.
                if not sponsored_discovery_measurement_allowed(store):
                    self._write_json({"error": "measurement_disabled"}, status=403)
                    return
                if not isinstance(payload, dict):
                    self._write_json({"error": "invalid_request"}, status=400)
                    return
                # Only the strictly parsed, bounded JSON moves upstream: no
                # local credential, identifier, or inventory is attached.
                raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
                try:
                    status, body = relay_discovery_measurement(path=upstream, payload=raw)
                except DiscoveryReadError as error:
                    self._write_json({"error": error.code}, status=error.status)
                    return
                self._write_json_bytes(
                    escape_json_for_html(body),
                    status=status,
                    extra_headers={"Cache-Control": "no-store"},
                )
                return
            if parsed.path == _LOCAL_DISCOVERY_SETTINGS:
                update = payload if isinstance(payload, dict) else {}
                enabled = update.get("sponsored_discovery_enabled")
                measurement = update.get("sponsored_discovery_measurement_enabled")
                if enabled is not None and not isinstance(enabled, bool):
                    self._write_json({"error": "invalid_request"}, status=400)
                    return
                if measurement is not None and not isinstance(measurement, bool):
                    self._write_json({"error": "invalid_request"}, status=400)
                    return
                settings = update_sponsored_discovery_settings(
                    store,
                    sponsored_discovery_enabled=enabled if isinstance(enabled, bool) else None,
                    sponsored_discovery_measurement_enabled=measurement if isinstance(measurement, bool) else None,
                    now=datetime.now(timezone.utc).isoformat(),
                )
                self._write_json(settings)
                return
            self._write_json({"error": "not_found"}, status=404)
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
        if parsed.path == "/v1/update/reconnect/challenge":
            self._handle_dashboard_reconnect_challenge(payload)
            return
        if parsed.path == "/v1/update/reconnect/verify":
            self._handle_dashboard_reconnect_verify(payload)
            return
        proof_authorized = challenge_auth(parsed.path, payload, self._consume_codex_daemon_challenge)
        if not request_auth(route.requires_header_token, proof_authorized, payload, self._header_token_is_valid):
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
        if parsed.path in CHALLENGE_HOOK_PATHS and not proof_authorized:
            self._write_json(
                {"error": "daemon_identity_required", "repair": "Run `hol-guard daemon repair`."},
                status=401,
            )
            return
        if len(path_parts) == 3 and path_parts[:2] == ["v1", "hooks"]:
            self._handle_runtime_hook(payload, parsed.query, default_harness=path_parts[2])
            return
        if len(path_parts) == 4 and path_parts[:2] == ["v1", "hooks"] and path_parts[3] == "readiness":
            self._handle_hook_readiness(payload, parsed.query, default_harness=path_parts[2])
            return
        self._dispatch_control_post(parsed, path_parts, payload, route)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        return

    def _load_request_body(self) -> tuple[dict[str, object], str | None]:
        if self.headers.get("Transfer-Encoding") is not None:
            return {}, "unsupported_transfer_encoding"
        content_lengths = self.headers.get_all("Content-Length", [])
        if len(content_lengths) > 1:
            return {}, "invalid_content_length"
        try:
            length = int(content_lengths[0]) if content_lengths else 0
        except ValueError:
            return {}, "invalid_content_length"
        if length < 0:
            return {}, "invalid_content_length"
        if length == 0:
            return {}, None
        if length > self._MAX_BODY_BYTES:
            return {}, "request_body_too_large"
        raw_body, body_error = self._read_request_body(length)
        if body_error is not None:
            return {}, body_error
        try:
            decoded_body = raw_body.decode("utf-8")
        except UnicodeDecodeError:
            return {}, "invalid_request_body"
        content_type = self.headers.get("Content-Type", "")
        if "application/json" in content_type:
            try:
                payload = json.loads(decoded_body)
            except json.JSONDecodeError:
                return {}, "invalid_request_body"
            return (payload if isinstance(payload, dict) else {}), None
        form_payload = parse_qs(decoded_body)
        return {key: values[-1] for key, values in form_payload.items() if values}, None

    def _read_request_body(self, length: int) -> tuple[bytes, str | None]:
        deadline = time.monotonic() + _DAEMON_REQUEST_READ_TIMEOUT_SECONDS
        chunks: list[bytes] = []
        remaining = length
        while remaining > 0:
            timeout = deadline - time.monotonic()
            if timeout <= 0:
                return b"", "request_body_timeout"
            with suppress(OSError):
                self.connection.settimeout(timeout)
            try:
                chunk = self.rfile.read1(min(remaining, 64 * 1024))
            except TimeoutError:
                return b"", "request_body_timeout"
            except OSError:
                return b"", "incomplete_request_body"
            if not chunk:
                return b"", "incomplete_request_body"
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks), None

    def _write_approval_gate_error(self, error: ApprovalGateError, *, resolved: bool | None = None) -> None:
        payload = error.to_payload()
        if resolved is not None:
            payload["resolved"] = resolved
        self._write_json(payload, status=error.status)

    def _handle_codex_live_decision(self, request_id: str, payload: Mapping[str, object]) -> None:
        request = self.server.store.get_approval_request(request_id)  # type: ignore[attr-defined]
        previous = self.server.store.get_request_resume(request_id)  # type: ignore[attr-defined]
        claimed_hash, claimed_request_id = _codex_live_replay_authority(request, previous)
        if isinstance(request, Mapping) and request.get("resolution_action") == "allow":
            authority = resolve_codex_live_allow_authority(
                self.server.store,  # type: ignore[attr-defined]
                request=request,
                request_id=request_id,
                now=_now(),
            )
            artifact_hash = request.get("artifact_hash")
            if authority is not None and isinstance(artifact_hash, str) and artifact_hash:
                claimed_hash = artifact_hash
                claimed_request_id = request_id
        fresh_allow_authorized = self._revalidate_codex_live_allow(
            request,
            payload,
            claimed_saved_allow_hash=claimed_hash,
            claimed_approval_request_id=claimed_request_id,
        )
        result = complete_codex_live_decision(
            self.server.store,  # type: ignore[attr-defined]
            request_id=request_id,
            now=_now(),
            fresh_allow_authorized=fresh_allow_authorized,
        )
        self._write_json(result, status=200 if result.get("completed") is True else 409)

    def _revalidate_codex_live_allow(
        self,
        request: object,
        payload: Mapping[str, object],
        *,
        claimed_saved_allow_hash: str | None = None,
        claimed_approval_request_id: str | None = None,
    ) -> bool:
        daemon_server = self._daemon_server()
        home_dir = daemon_server.home_dir
        return revalidate_codex_live_allow(
            request,
            payload,
            home_dir=home_dir,
            guard_home=daemon_server.store.guard_home,
            claimed_saved_allow_hash=claimed_saved_allow_hash,
            claimed_approval_request_id=claimed_approval_request_id,
            reviewer=lambda hook_payload, workspace, claimed_hash, claimed_request_id: (
                daemon_server.hook_worker.review_http_payload(
                    payload=dict(hook_payload),
                    params={},
                    default_harness="codex",
                    home_dir=home_dir,
                    guard_home=daemon_server.store.guard_home,
                    workspace=workspace,
                    deadline=time.monotonic() + _RUNTIME_HOOK_PROCESS_TIMEOUT_SECONDS,
                    claim_saved_approval=False,
                    claimed_saved_allow_hash=claimed_hash,
                    claimed_approval_request_id=claimed_request_id,
                )
            ),
        )

    def _write_legacy_pairing_disabled(self) -> None:
        self._write_json(
            {
                "error": "legacy_pairing_disabled",
                "message": "Use hol-guard connect for browser OAuth.",
            },
            status=410,
        )

    def _handle_hook_readiness(
        self,
        payload: dict[str, object],
        query: str,
        *,
        default_harness: str,
    ) -> None:
        """Prepare the active workspace before a host's timed hook starts.

        This route is deliberately separate from semantic hook review. It gives
        the native publisher and isolated worker the existing setup budget so a
        first tool call does not spend its short host deadline on cold startup.
        """

        params = parse_qs(query)
        workspace_candidate = self._hook_workspace_spelling(
            params.get("workspace", [None])[-1] or payload.get("workspace") or payload.get("cwd")
        )
        try:
            guard_home_candidate = self._optional_string(params.get("guard-home", [None])[-1])
            _ = self._settled_hook_directories(("guard-home", guard_home_candidate)).require("guard-home")
            # An unmanaged harness is ready without a workspace, so it is not
            # held behind settling one it will never use.
            if _hook_harness_is_unmanaged(self._daemon_server(), default_harness):
                self._write_json(
                    {"ready": True, "native_required": False, "workspace_acknowledged": False, "worker_ready": True},
                    extra_headers={"Cache-Control": "no-store"},
                )
                return
            workspace = self._settled_hook_directories(("workspace", workspace_candidate, "hook-workspace")).require(
                "workspace"
            )
        except _HookPathValidationError as error:
            self._record_hook_path_rejection(parameter=error.parameter, reason=error.reason)
            self._write_json(
                {"ready": False, "reason_code": f"invalid_{error.parameter.replace('-', '_')}"},
                status=400,
                extra_headers={"Cache-Control": "no-store"},
            )
            return
        if workspace is None:
            self._write_json(
                {"ready": False, "reason_code": "workspace_required"},
                status=400,
                extra_headers={"Cache-Control": "no-store"},
            )
            return

        daemon_server = self._daemon_server()
        readiness_deadline = time.monotonic() + _RUNTIME_WORKSPACE_READINESS_TIMEOUT_SECONDS
        try:
            prepared_policy = daemon_server.hook_worker.prepare_workspace_policy(
                Path(workspace),
                deadline=readiness_deadline,
            )
        except Exception:
            daemon_server.diagnostics.record_exception("native_workspace_readiness_failed")
            prepared_policy = None
        if not isinstance(prepared_policy, dict):
            self._write_json(
                {"ready": False, "reason_code": "native_policy_not_ready"},
                status=503,
                extra_headers={"Cache-Control": "no-store"},
            )
            return

        self._write_json(
            {
                "ready": True,
                "native_required": True,
                "native_route": "native_resident",
                "workspace_acknowledged": True,
                "worker_ready": True,
            },
            extra_headers={"Cache-Control": "no-store"},
        )

    def _handle_runtime_hook(self, payload: dict[str, object], query: str, *, default_harness: str) -> None:
        from .hook_direct_counters import note_hook_received
        from .hook_direct_pi_transport import pi_direct_answer
        from .hook_request_parsing import (
            HookPayloadReferenceError,
            hook_payload_reference_size,
            runtime_hook_event_name,
        )

        prompt_event = runtime_hook_event_name(payload) == "UserPromptSubmit"
        admission_seconds = PROMPT_ADMISSION_SECONDS if prompt_event else _RUNTIME_HOOK_ADMISSION_TIMEOUT_SECONDS
        transport_deadline = self._daemon_server().request_deadline(self.request, admission_seconds)
        params = parse_qs(query)
        # Diagnostics only: a count by the harness the worker reviews (the
        # `runtime-harness` override first), before anything is judged.
        note_hook_received(
            getattr(self._daemon_server(), "hook_worker", None),
            self._optional_string(params.get("runtime-harness", [None])[-1]) or default_harness,
        )
        hint_missing = "guard_remaining_seconds" not in payload and "guard_remaining_ms" not in payload
        hook_deadline = RuntimeHookDeadline.for_admission(
            _runtime_hook_remaining_hint(payload),
            hint_missing=hint_missing,
            prompt_event=prompt_event,
            admission_seconds=admission_seconds,
            transport_deadline=transport_deadline,
        )
        payload = {key: value for key, value in payload.items() if key != "hook_env"}
        daemon_server = self._daemon_server()
        # Oh My Pi has no bridge to ask the resident first, so ask it here.
        # The raw `home` query goes with the raw workspace: the resident
        # settles both against the lane it bound, and a home it cannot settle
        # defers to the daemon path below, which refuses and audits it. Asking
        # the runtime to settle directories first would spend a round trip per
        # hook on the answer path, where nothing here reads the result.
        #
        # A `guard-home` query is the exception, because the lane never sends
        # it: it answers out of the home it bound, so a request naming another
        # Guard home would be answered without that claim being refused or
        # audited. Spelling it the same way as this daemon's own home is the
        # only claim the lane may answer, and this comparison costs no round
        # trip. A spelling that merely looks different -- a link, a relative
        # path -- is not refused here; it goes down the daemon path, which
        # settles it properly and refuses or admits it there.
        if self._hook_guard_home_query_is_this_home(params, daemon_server):
            direct_response = pi_direct_answer(
                getattr(daemon_server, "hook_worker", None),
                default_harness=default_harness,
                params=params,
                payload=payload,
                home_dir=self._optional_string(params.get("home", [None])[-1]),
                deadline=hook_deadline.expires_at,
            )
            if direct_response is not None:
                self._write_json(direct_response)
                return

        try:
            action_workdir_provided, action_workdir_spelling = self._runtime_hook_exec_command_workdir(payload)
            # One call settles every directory this request named, including
            # each spelling of the workspace; the verdicts are still read in
            # the order the route rejects in, and a spelling the route never
            # reaches is never held against it.
            directories = self._settled_hook_directories(
                ("home", self._optional_string(params.get("home", [None])[-1])),
                ("guard-home", self._optional_string(params.get("guard-home", [None])[-1])),
                ("exec-workdir", action_workdir_spelling, "exec-workdir"),
                ("workspace-payload", self._hook_workspace_spelling(payload.get("cwd")), "hook-workspace"),
                (
                    "workspace-query",
                    self._hook_workspace_spelling(params.get("workspace", [None])[-1]),
                    "hook-workspace",
                ),
                deadline_monotonic=hook_deadline.expires_at,
            )
            home_dir = directories.require("home")
            guard_home = directories.require("guard-home")
            action_workdir = directories.require("exec-workdir")
            if action_workdir_provided and action_workdir is None:
                raise _HookPathValidationError("workspace", "invalid_action_workdir")
            workspace = (
                action_workdir or directories.require("workspace-payload") or directories.require("workspace-query")
            )
        except _HookPathValidationError as error:
            # The Rust edge still receives the complete raw payload. Use
            # daemon-owned metadata when an optional caller context is
            # missing or invalid; never turn metadata rejection into a
            # Python semantic/source-ref fallback.
            self._record_hook_path_rejection(parameter=error.parameter, reason=error.reason)
            home_dir = str(daemon_server.home_dir)
            guard_home = str(daemon_server.store.guard_home)
            workspace = None

        if not prepare_native_hook_policy(
            self, daemon_server, payload, params, default_harness, workspace, hook_deadline.expires_at
        ):
            return

        runtime_harness = self._optional_string(params.get("runtime-harness", [None])[-1])
        capacity_harness = daemon_server.canonical_hook_capacity_harness(
            (runtime_harness or default_harness).strip().lower().replace("_", "-")
        )
        try:
            referenced_payload_bytes = hook_payload_reference_size(
                payload,
                guard_home=daemon_server.store.guard_home,
                deadline_monotonic=hook_deadline.expires_at,
            )
            payload_bytes = (
                referenced_payload_bytes
                if referenced_payload_bytes is not None
                else self._runtime_hook_payload_size(payload)
            )
        except HookPayloadReferenceError as error:
            daemon_server.hook_worker.metrics.record_failure(
                stage="server",
                exception_type=type(error).__name__,
            )
            self._write_json(
                self._runtime_hook_fail_safe_response(
                    payload,
                    params,
                    default_harness=default_harness,
                    reason="HOL Guard could not authenticate the local hook payload.",
                    reason_code="invalid_hook_payload_reference",
                    hook_deadline=hook_deadline.expires_at,
                )
            )
            return

        byte_reservation, reservation_reason = daemon_server.runtime_hook_scheduler.reserve_bytes(
            payload_bytes=payload_bytes,
            deadline=hook_deadline.expires_at,
        )
        if byte_reservation is None:
            self._record_hook_capacity_rejection(daemon_server, capacity_harness)
            self._write_json(
                self._runtime_hook_capacity_response(
                    payload,
                    params,
                    default_harness=default_harness,
                    reason_code=reservation_reason,
                    hook_deadline=hook_deadline.expires_at,
                )
            )
            return
        with byte_reservation:
            # A referenced payload reserves its bounded maximum, but remains
            # an opaque envelope until the native edge owns its file I/O.
            # Do not hydrate or re-encode it here: duplicate keys in the
            # referenced bytes must not be collapsed by Python before Rust.
            normalized_payload = None
            if referenced_payload_bytes is None:
                normalized_payload = json.dumps(
                    payload,
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("utf-8")
            admission = daemon_server.runtime_hook_scheduler.acquire(
                harness=capacity_harness,
                client_key=self._runtime_hook_client_key(payload, workspace),
                lane=self._runtime_hook_lane(payload),
                payload_bytes=payload_bytes,
                deadline=hook_deadline,
                byte_reservation=byte_reservation,
                normalized_payload=normalized_payload,
            )
            if admission.permit is None:
                self._record_hook_capacity_rejection(daemon_server, capacity_harness)
                self._write_json(
                    self._runtime_hook_capacity_response(
                        payload,
                        params,
                        default_harness=default_harness,
                        reason_code=admission.reason_code,
                    )
                )
                return
        with daemon_server.hook_capacity_lock:
            daemon_server.active_hook_requests += 1
            daemon_server.hook_harness_active[capacity_harness] = (
                daemon_server.hook_harness_active.get(capacity_harness, 0) + 1
            )
        try:
            with admission.permit:
                self._execute_runtime_hook(
                    payload,
                    params,
                    default_harness=default_harness,
                    home_dir=home_dir,
                    guard_home=guard_home,
                    workspace=workspace,
                    deadline=hook_deadline.expires_at,
                    release_capacity=admission.permit.release,
                )
        finally:
            with daemon_server.hook_capacity_lock:
                daemon_server.active_hook_requests -= 1
                daemon_server.hook_harness_active[capacity_harness] -= 1

    @staticmethod
    def _runtime_hook_lane(payload: Mapping[str, object]) -> RuntimeHookLane:
        from .hook_worker import runtime_hook_event_name

        event = runtime_hook_event_name(payload).lower().replace("_", "").replace("-", "")
        if event in {"pretooluse", "permissionrequest", "userpromptsubmit", "userpromptsubmitted"}:
            return "decision"
        return "content-security"

    @staticmethod
    def _runtime_hook_client_key(payload: Mapping[str, object], workspace: str | None) -> str:
        session = next(
            (
                payload.get(key)
                for key in ("session_id", "conversation_id", "thread_id")
                if isinstance(payload.get(key), str) and payload.get(key)
            ),
            "",
        )
        material = f"{workspace or ''}\0{session}"
        return hashlib.sha256(material.encode("utf-8", errors="replace")).hexdigest()[:32]

    @staticmethod
    def _runtime_hook_payload_size(payload: Mapping[str, object]) -> int:
        return len(
            json.dumps(
                payload,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        )

    @staticmethod
    def _record_hook_capacity_rejection(
        daemon_server: _GuardDaemonHttpServer,
        capacity_harness: str,
    ) -> None:
        with daemon_server.hook_capacity_lock:
            daemon_server.rejected_hook_requests += 1
            daemon_server.hook_harness_rejected[capacity_harness] = (
                daemon_server.hook_harness_rejected.get(capacity_harness, 0) + 1
            )

    def _runtime_hook_capacity_response(
        self,
        payload: Mapping[str, object],
        params: Mapping[str, list[str]],
        *,
        default_harness: str,
        reason_code: RuntimeHookAdmissionReason | None = None,
        hook_deadline: float | None = None,
    ) -> dict[str, object]:
        resolved_reason_code = reason_code or "daemon_hook_queue_capacity"
        if resolved_reason_code == "daemon_hook_deadline_exhausted":
            reason = "HOL Guard could not complete local review within the hook deadline. Retry this action."
        else:
            reason = "HOL Guard is safely queueing the maximum local review workload. Retry this action."
        return self._runtime_hook_fail_safe_response(
            payload,
            params,
            default_harness=default_harness,
            reason=reason,
            reason_code=resolved_reason_code,
            hook_deadline=hook_deadline,
        )

    def _runtime_hook_fail_safe_response(
        self,
        payload: Mapping[str, object],
        params: Mapping[str, list[str]],
        *,
        default_harness: str,
        reason: str,
        reason_code: str,
        hook_deadline: float | None = None,
    ) -> dict[str, object]:
        runtime_harness = self._optional_string(params.get("runtime-harness", [None])[-1])
        harness = (runtime_harness or default_harness).strip().lower().replace("_", "-")
        event = self._optional_string(payload.get("hook_event_name", payload.get("event"))) or "PreToolUse"
        daemon_server = getattr(self, "server", None)
        workspace_path, home_path = self._validated_fail_safe_hook_paths(params, hook_deadline=hook_deadline)
        guard_home = None if daemon_server is None else cast(_GuardDaemonHttpServer, daemon_server).store.guard_home
        from ..native_policy_snapshot_acked import recording_only_from_acked_snapshot
        from .hook_availability_policy import availability_harness_response

        payload_dict = dict(payload) if isinstance(payload, Mapping) else {}
        return availability_harness_response(
            payload_dict,
            harness=harness,
            event_name=event,
            reason_code=reason_code,
            reason=reason,
            workspace=workspace_path,
            home_dir=home_path,
            guard_home=guard_home,
            recording_only=recording_only_from_acked_snapshot(getattr(daemon_server, "store", None), harness),
        )

    def _validated_fail_safe_hook_paths(
        self,
        params: Mapping[str, list[str]],
        *,
        hook_deadline: float | None = None,
    ) -> tuple[Path | None, Path | None]:
        """Return workspace and home directories that passed hook path validation.

        This answer is built when the runtime has just failed or is overloaded,
        so both directories are settled in one call against a short deadline:
        a fail-safe response must not wait on the runtime it is standing in for.
        """

        deadline = time.monotonic() + _FAIL_SAFE_DIRECTORY_TRUST_SECONDS
        if hook_deadline is not None:
            deadline = min(deadline, hook_deadline)
        if time.monotonic() >= deadline:
            # A fail-safe answer must not start another RPC after the hook
            # budget expires; omitting unverified paths remains fail closed.
            return (None, None)
        try:
            directories = self._settled_hook_directories(
                ("workspace", self._optional_string(params.get("workspace", [None])[-1])),
                ("home", self._optional_string(params.get("home", [None])[-1])),
                deadline_monotonic=deadline,
            )
        except _HookPathValidationError:
            return (None, None)
        return (
            self._fail_safe_directory(directories, "workspace"),
            self._fail_safe_directory(directories, "home"),
        )

    @staticmethod
    def _fail_safe_directory(directories: _HookDirectories, parameter: str) -> Path | None:
        try:
            settled = directories.require(parameter)
        except _HookPathValidationError:
            return None
        return Path(settled) if settled else None

    def _execute_runtime_hook(
        self,
        payload: dict[str, object],
        params: Mapping[str, list[str]],
        *,
        default_harness: str,
        home_dir: str | None,
        guard_home: str | None,
        workspace: str | None,
        deadline: float | None = None,
        release_capacity: Callable[[], None] | None = None,
    ) -> None:
        from contextlib import nullcontext

        from ..sqlite_tuning import sqlite_operation_deadline

        with sqlite_operation_deadline(deadline) if deadline is not None else nullcontext():
            result = self._handle_runtime_hook_fast(
                payload,
                params,
                default_harness=default_harness,
                home_dir=home_dir,
                guard_home=guard_home,
                workspace=workspace,
                deadline=deadline,
            )
            if result is None:
                result = self._runtime_hook_fail_safe_response(
                    payload,
                    params,
                    default_harness=default_harness,
                    reason="HOL Guard could not complete the native hook decision safely.",
                    reason_code="native_hook_worker_unavailable",
                    hook_deadline=deadline,
                )
            # A review that finished late still finished: the answer carries the
            # same decision the native edge would have sent on time, so send it
            # rather than a block. The client owns the real timeout -- it stops
            # waiting on its own clock and ignores whatever arrives after -- and
            # discarding a completed decision here only turns a slow host into a
            # blocked one, which is how a cold or contended machine ends up
            # refusing `grep`. The deadline still bounds the work itself: it
            # caps storage waits and the native edge's own evaluation, and a
            # review that produces nothing fails safe above.
        # The decision is final. Free its review slot before the answer is
        # sent: a client holding its answer must never see the slot still
        # busy, and a slow reader must not occupy review capacity.
        if release_capacity is not None:
            release_capacity()
        self._write_json(result)

    def _handle_runtime_hook_fast(
        self,
        payload: dict[str, object],
        params: Mapping[str, list[str]],
        *,
        default_harness: str,
        home_dir: str | None,
        guard_home: str | None,
        workspace: str | None,
        deadline: float | None,
    ) -> dict[str, object] | None:
        """Review through the resident hook worker; failures deny and never reach Python semantics."""
        from contextlib import nullcontext

        from ..sqlite_tuning import sqlite_operation_deadline

        daemon_server = self._daemon_server()
        effective_home_dir = Path(home_dir) if home_dir is not None else daemon_server.home_dir
        effective_guard_home = Path(guard_home) if guard_home is not None else daemon_server.store.guard_home

        # Keep failure rendering on the same storage clock as direct review.
        with sqlite_operation_deadline(deadline) if deadline is not None else nullcontext():
            try:
                worker = daemon_server.hook_worker
                return worker.review_http_payload(
                    payload=payload,
                    params=params,
                    default_harness=default_harness,
                    home_dir=effective_home_dir,
                    guard_home=effective_guard_home,
                    workspace=Path(workspace) if workspace else None,
                    deadline=deadline,
                )
            except Exception as error:
                # Fail safe: deny/block; there is no Python semantic fallback.
                self._daemon_server().hook_worker.metrics.record_failure(
                    stage="server",
                    exception_type=type(error).__name__,
                )
                return self._runtime_hook_fail_safe_response(
                    payload,
                    params,
                    default_harness=default_harness,
                    reason="HOL Guard could not complete local hook review safely.",
                    reason_code="daemon_worker_exception",
                )

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
        payload: dict[str, object] = {
            "method": self.command,
            "path": urlparse(self.path).path,
            "origin": self._normalize_origin(origin),
            "origin_header": origin if isinstance(origin, str) and origin.strip() else None,
            "has_authorization": isinstance(self.headers.get("Authorization"), str),
            "has_dashboard_session": isinstance(self.headers.get("X-Guard-Dashboard-Session"), str),
            "has_guard_token": isinstance(self.headers.get("X-Guard-Token"), str),
        }
        key: _AuthAuditKey = (
            self.command,
            cast(str, payload["path"]),
            cast(str | None, payload["origin"]),
            cast(str | None, payload["origin_header"]),
            cast(bool, payload["has_authorization"]),
            cast(bool, payload["has_dashboard_session"]),
            cast(bool, payload["has_guard_token"]),
        )
        daemon_server = self._daemon_server()
        now = time.monotonic()
        with daemon_server.auth_audit_lock:
            previous = daemon_server.auth_audit_windows.get(key)
            reported_suppressed_count = 0
            if previous is not None and now - previous["started_at"] < _AUTH_AUDIT_COALESCE_SECONDS:
                if previous["pending"] or previous["persisted"]:
                    previous["suppressed_count"] += 1
                    return
                reported_suppressed_count = previous["suppressed_count"]
            elif previous is not None:
                reported_suppressed_count = previous["suppressed_count"]
            if reported_suppressed_count:
                payload["suppressed_count"] = reported_suppressed_count
            if (
                key not in daemon_server.auth_audit_windows
                and len(daemon_server.auth_audit_windows) >= _AUTH_AUDIT_KEY_LIMIT
            ):
                oldest = min(
                    daemon_server.auth_audit_windows,
                    key=lambda item: daemon_server.auth_audit_windows[item]["started_at"],
                )
                _ = daemon_server.auth_audit_windows.pop(oldest)
            window: _AuthAuditWindow = {
                "started_at": now,
                "suppressed_count": reported_suppressed_count,
                "pending": True,
                "persisted": False,
            }
            daemon_server.auth_audit_windows[key] = window
        outcome = daemon_server.audit_persistence.persist("daemon.auth.unauthorized", payload, _now())
        with daemon_server.auth_audit_lock:
            if daemon_server.auth_audit_windows.get(key) is not window:
                return
            window["pending"] = False
            if outcome == AUDIT_NOT_PERSISTED:
                window["suppressed_count"] += 1
                return
            # A queued row carries the suppressed count, but its retry can still
            # fail, so only a confirmed write lets the window coalesce later events.
            window["suppressed_count"] -= reported_suppressed_count
            window["persisted"] = outcome == AUDIT_WRITTEN

    def _record_query_token_rejection(self) -> None:
        self._record_bounded_denial_event(
            "daemon.auth.query_token_rejected",
            {"method": self.command, "path": urlparse(self.path).path, "has_query_token": True},
        )

    def _hook_guard_home_query_is_this_home(
        self,
        params: Mapping[str, list[str]],
        daemon_server: object,
    ) -> bool:
        """Whether a `guard-home` query, if one was sent, names this daemon's home.

        Answering from the direct lane skips settling directories, so a claim
        about which Guard home a request belongs to has nothing to check it.
        Naming no home at all claims nothing and is fine; naming this one is
        the claim the lane is allowed to answer. Everything else keeps the
        daemon path, which settles the spelling and records the rejection.
        """
        query = self._optional_string(params.get("guard-home", [None])[-1])
        if query is None:
            return True
        try:
            claimed = os.path.normpath(os.path.expanduser(query))
            own = os.path.normpath(str(daemon_server.store.guard_home))  # pyright: ignore[reportAttributeAccessIssue]
        except (AttributeError, TypeError, ValueError):
            return False
        return claimed == own

    def _record_hook_path_rejection(self, *, parameter: str, reason: str) -> None:
        self._record_bounded_denial_event(
            "daemon.hook.path_rejected",
            {
                "method": self.command,
                "path": urlparse(self.path).path,
                "parameter": parameter,
                "reason": reason,
            },
        )

    def _record_bounded_denial_event(self, event_name: str, payload: dict[str, object]) -> None:
        daemon_server = self._daemon_server()
        with daemon_server.denial_audit_lock:
            _ = daemon_server.audit_persistence.persist(event_name, payload, _now())

    def _route_home(self) -> Path | None:
        return getattr(getattr(self.server, "store", None), "guard_home", None)

    def _path_supports_dashboard_session(self, path: str) -> bool:
        try:
            return native_route_facts(self.command, path, guard_home=self._route_home()).session_path
        except NativeDaemonRouteError:
            return False

    def _header_token_is_valid(self, *, payload: dict[str, object] | None = None) -> bool:
        token = self.headers.get("X-Guard-Token")
        path = urlparse(self.path).path
        return self._tokens_match(token) or (
            self._path_supports_dashboard_session(path) and self._dashboard_session_token_is_valid(payload=payload)
        )

    def _origin_is_allowed_for_request(self, path: str) -> bool:
        origin = self.headers.get("Origin")
        if origin is None:
            return True
        normalized_origin = self._normalize_origin(origin)
        if normalized_origin is None:
            return False
        try:
            return native_origin_decision(normalized_origin, path, guard_home=self._route_home()).allowed
        except NativeDaemonRouteError:
            return False

    def _is_hosted_dashboard_origin(self) -> bool:
        origin = self._normalize_origin(self.headers.get("Origin"))
        if origin is None:
            return False
        try:
            return native_origin_decision(origin, "/", guard_home=self._route_home()).hosted_origin
        except NativeDaemonRouteError:
            return True

    def _strict_loopback_origin(self, value: object) -> str | None:
        if not isinstance(value, str):
            return None
        try:
            return native_strict_loopback_origin(
                value.strip(), self._normalize_origin(value), guard_home=self._route_home()
            )
        except NativeDaemonRouteError:
            return None

    def _dashboard_session_claims_authorize_request(
        self,
        claims: dict[str, object],
        *,
        payload: dict[str, object] | None,
    ) -> bool:
        try:
            verdict = native_session_authorize(
                method=self.command,
                path=urlparse(self.path).path,
                claims=claims,
                payload=payload,
                header_nonce=self.headers.get("X-Guard-Dashboard-Nonce"),
                request_origin=self._normalize_origin(self.headers.get("Origin")),
                guard_home=self._route_home(),
            )
        except NativeDaemonRouteError:
            return False
        if verdict.consume_nonce is not None and not self._consume_dashboard_session_nonce(verdict.consume_nonce):
            return False
        return verdict.allowed

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
        claims = self._refreshable_dashboard_session_claims()
        if claims is None:
            return None
        started_at = self._optional_string(claims.get(LOCAL_DASHBOARD_SESSION_STARTED_AT_CLAIM))
        if started_at is None:
            expires_at = self._optional_string(claims.get("expires_at"))
            if expires_at is None:
                return None
            try:
                started_at_timestamp = _parse_iso_timestamp(expires_at) - DEFAULT_LOCAL_DASHBOARD_SESSION_TTL_SECONDS
            except ValueError:
                return None
            started_at = datetime.fromtimestamp(started_at_timestamp, tz=timezone.utc).isoformat()
        try:
            absolute_expires_at = _parse_iso_timestamp(started_at) + MAX_LOCAL_DASHBOARD_SESSION_AGE_SECONDS
        except ValueError:
            return None
        remaining_seconds = absolute_expires_at - time.time()
        if remaining_seconds < 1:
            return None
        claim_surface = self._optional_string(claims.get("surface"))
        if claim_surface == PROTECTION_REPAIR_DASHBOARD_SURFACE:
            refreshed_surface = PROTECTION_REPAIR_DASHBOARD_SURFACE
        elif surface in {"approval-center", "dashboard", "cloud-dashboard"}:
            refreshed_surface = surface
        else:
            refreshed_surface = "dashboard"
        return build_local_dashboard_session_token(
            auth_token=self.server.auth_token,  # type: ignore[attr-defined]
            surface=refreshed_surface,
            expires_in_seconds=min(DEFAULT_LOCAL_DASHBOARD_SESSION_TTL_SECONDS, int(remaining_seconds)),
            session_started_at=started_at,
        )

    def _request_uses_protection_repair_session(self) -> bool:
        session_token = self.headers.get("X-Guard-Dashboard-Session")
        authorization = self.headers.get("Authorization")
        bearer_token = None
        if isinstance(authorization, str) and authorization.lower().startswith("bearer "):
            bearer_token = authorization[7:].strip()
        candidates = [
            candidate for candidate in (session_token, bearer_token) if isinstance(candidate, str) and candidate.strip()
        ]
        for candidate in candidates:
            claims = self._dashboard_session_token_claims(candidate)
            if claims is not None and claims.get("surface") == PROTECTION_REPAIR_DASHBOARD_SURFACE:
                return True
        return False

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
            if surface in {
                "approval-center",
                "dashboard",
                "cloud-dashboard",
                PROTECTION_REPAIR_DASHBOARD_SURFACE,
            }:
                return claims
        return None

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
        if path != "/healthz" and not path.startswith(("/v1/", "/v2/")):
            return
        self.server.last_activity_monotonic = time.monotonic()  # type: ignore[attr-defined]
        self._daemon_server().runtime_heartbeat.touch(_now())

    def _increment_active_stream_clients(self) -> None:
        with self.server.active_stream_clients_lock:  # type: ignore[attr-defined]
            self.server.active_stream_clients += 1  # type: ignore[attr-defined]

    def _try_increment_active_stream_clients(self, maximum: int) -> bool:
        with self.server.active_stream_clients_lock:  # type: ignore[attr-defined]
            if self.server.active_stream_clients >= maximum:  # type: ignore[attr-defined]
                return False
            self.server.active_stream_clients += 1  # type: ignore[attr-defined]
            return True

    def _decrement_active_stream_clients(self) -> None:
        with self.server.active_stream_clients_lock:  # type: ignore[attr-defined]
            self.server.active_stream_clients = max(0, self.server.active_stream_clients - 1)  # type: ignore[attr-defined]

    def _public_healthz_payload(self) -> dict[str, object]:
        return {
            "ok": True,
            "compatibility_version": GUARD_DAEMON_COMPATIBILITY_VERSION,
        }

    def _detailed_healthz_payload(self) -> dict[str, object]:
        uptime = round(time.monotonic() - self.server.start_monotonic, 1)  # type: ignore[attr-defined]
        daemon_server = self._daemon_server()
        store = daemon_server.store
        pending_approvals = store.count_approval_requests()
        activity_health = store.get_command_activity_persistence_health()
        scheduler_stats = daemon_server.runtime_hook_scheduler.stats()
        try:
            evidence_writer_stats = daemon_server.runtime_hook_evidence_writer.stats()
        except Exception:
            evidence_writer_stats = unreachable_writer_stats()
        sqlite_profile = store.sqlite_profile()
        sqlite_migration_gate = store.sqlite_migration_gate_report()
        with daemon_server.hook_capacity_lock:
            hook_capacity = {
                "active": scheduler_stats["active"],
                "limit": scheduler_stats["active_limit"],
                "queued": scheduler_stats["queued"],
                "queued_limit": scheduler_stats["queued_limit"],
                "retained_bytes": scheduler_stats["retained_bytes"],
                "retained_bytes_limit": scheduler_stats["retained_bytes_limit"],
                "per_harness_active": scheduler_stats["per_harness_active"],
                "per_harness_queued": scheduler_stats["per_harness_queued"],
                "per_harness_rejected": dict(daemon_server.hook_harness_rejected),
                "rejected": daemon_server.rejected_hook_requests,
                "expired": scheduler_stats["expired"],
                "cancelled": scheduler_stats["cancelled"],
                "retries": scheduler_stats["retries"],
                "completed": scheduler_stats["completed"],
                "oldest_queued_ms": scheduler_stats["oldest_queued_ms"],
                "queue_wait_by_lane_p95_ms": scheduler_stats["queue_wait_by_lane_p95_ms"],
                "service_time_by_lane_p95_ms": scheduler_stats["service_time_by_lane_p95_ms"],
                "queue_wait_by_lane_p99_ms": scheduler_stats["queue_wait_by_lane_p99_ms"],
                "service_time_by_lane_p99_ms": scheduler_stats["service_time_by_lane_p99_ms"],
                "rejection_reasons": scheduler_stats["rejected"],
            }
        with daemon_server.request_capacity_lock:
            request_capacity = {
                "active": daemon_server.active_requests,
                "connection_limit": daemon_server.connection_capacity_limit,
                "control_limit": daemon_server.control_request_capacity_limit,
                "critical_limit": daemon_server.critical_request_capacity_limit,
                "limit": daemon_server.request_capacity_limit,
                "rejected": daemon_server.rejected_requests,
            }
        if evidence_writer_stats["failures"] and evidence_writer_stats["queued"]:
            load_state = "store-contended"
            load_detail = "Evidence persistence is retrying outside the security decision path."
        elif scheduler_stats["expired"] or daemon_server.rejected_hook_requests:
            load_state = "saturated"
            load_detail = "Secure review capacity was exhausted; recovery is automatic as load falls."
        elif scheduler_stats["queued"]:
            load_state = "backlogged"
            load_detail = "Queued reviews are draining automatically."
        else:
            load_state = "healthy"
            load_detail = "Review capacity is available."
        return {
            "ok": True,
            "receipts": len(store.list_receipts(limit=500)),
            "approvals": pending_approvals,
            "pending_approvals": pending_approvals,
            "hook_evidence_writer": evidence_writer_stats,
            "sqlite_profile": sqlite_profile,
            "sqlite_migration_gate": sqlite_migration_gate,
            "quarantined_store": quarantined_store_summary(store.guard_home),
            "onefile_extraction": daemon_server.onefile_extraction_status,
            "repair_self_check": daemon_server.repair_self_check_status,
            "uptime_seconds": uptime,
            "pid": os.getpid(),
            "tables": store.list_table_names(),
            "compatibility_version": GUARD_DAEMON_COMPATIBILITY_VERSION,
            "package_version": __version__,
            "runtime_fingerprint": current_guard_daemon_runtime_fingerprint(),
            # Adoption needs the install root to reject a previous generation
            # still running from the same, now upgraded, install.
            "source_root": current_guard_daemon_source_root(),
            "guard_home": str(store.guard_home.resolve()),
            "command_activity_evidence": {
                "state": "degraded" if activity_health.persistence_error_count else "healthy",
                "dropped_event_count": activity_health.dropped_event_count,
                "persistence_error_count": activity_health.persistence_error_count,
                "last_error_code": activity_health.last_error_code,
                "last_error_at": (
                    activity_health.last_error_at.isoformat() if activity_health.last_error_at is not None else None
                ),
                "schema_version": activity_health.schema_version,
            },
            "network_protection": project_network_supervisor_health(
                daemon_server.network_supervisor.health(now_epoch_ms=int(time.time() * 1000))
            ),
            "hook_capacity": hook_capacity,
            "hook_load": {
                "state": load_state,
                "detail": load_detail,
            },
            "request_capacity": request_capacity,
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
        origin = self._normalize_origin(self.headers.get("Origin"))
        if origin is None or not self._origin_is_allowed_for_request(parsed.path):
            return None
        return self._cors_headers(origin, allow_methods=allow_methods, allow_headers=allow_headers)

    def _native_handler_decision(self, ask: Callable[[], HandlerDecision]) -> HandlerDecision | None:
        """Ask the resident to validate a request.

        A rejection is written as the resident shaped it; so is the fail-closed
        reply when the resident cannot answer. Both return ``None``.
        """

        try:
            decision = ask()
        except NativeDaemonHandlerError:
            self._write_json({"error": "native_handler_policy_unavailable"}, status=503)
            return None
        if decision.rejected:
            self._write_json(decision.body, status=decision.status)
            return None
        return decision

    @staticmethod
    def _optional_string(value: object) -> str | None:
        if isinstance(value, str) and value.strip():
            return value.strip()
        return None

    @staticmethod
    def _hook_workspace_spelling(value: object) -> str | None:
        """The workspace spelling a hook sent, read out of the request as-is.

        What the spelling means -- a sentinel standing for "no workspace", a
        `~` to expand, the shared temporary root a workspaceless process runs
        in -- is the runtime's to settle, under the `hook-workspace` rule.
        """

        return value if isinstance(value, str) else None

    @staticmethod
    def _runtime_hook_exec_command_workdir(payload: dict[str, object]) -> tuple[bool, str | None]:
        """Whether this call named a working directory, and how it spelled it.

        The flag and the spelling are separate answers: a call that carries a
        `workdir` Guard cannot use is rejected, while a call that carries none
        falls through to the workspace the request named elsewhere.
        """

        tool_name = payload.get("tool_name")
        if not isinstance(tool_name, str) or tool_name.strip().casefold() != "exec_command":
            return False, None
        tool_input = payload.get("tool_input")
        if not isinstance(tool_input, dict) or "workdir" not in tool_input:
            return False, None
        value = tool_input.get("workdir")
        return True, value if isinstance(value, str) else None

    def _settled_hook_directories(
        self,
        *candidates: tuple[str, str | None] | tuple[str, str | None, str],
        deadline_monotonic: float | None = None,
    ) -> _HookDirectories:
        """Ask the native owner about every directory this request named.

        The runtime decides which directories a hook may name; this handler
        only frames the question and reads the answer. A runtime that cannot
        answer refuses the request rather than letting the daemon work the
        verdict out for itself, so an unreachable resident never widens what
        a hook reaches.

        A candidate may carry a third element naming the rule to hold it to,
        which is how one request asks about several spellings of the same
        workspace -- the query string, the payload, the call's own working
        directory -- without their labels colliding.

        A route holding a deadline passes it, so settling paths cannot spend
        a budget the hook still needs for its own answer.
        """

        asked: list[DirectoryTrustCandidate] = [
            (candidate[0], candidate[1], candidate[2]) if len(candidate) == 3 else (candidate[0], candidate[1])
            for candidate in candidates
            if candidate[1] is not None
        ]
        if not asked:
            return _HookDirectories(())
        try:
            daemon_server = self._daemon_server()
            verdicts = native_directory_trust(
                asked,
                guard_home=daemon_server.store.guard_home,
                # The home this daemon was configured with, not whichever home
                # the process happens to be running as: the runtime expands `~`
                # against it and treats it as a trusted root, so letting it
                # fall back to `Path.home()` would settle these paths against a
                # different home than the one the rest of the route uses.
                home_dir=daemon_server.home_dir,
                deadline_monotonic=deadline_monotonic,
            )
        except NativeDirectoryTrustError as error:
            # Nothing was settled, so the request is refused under the first
            # candidate it named -- reported the same way a verdict against
            # that candidate would be, not under the label the spellings are
            # held apart by.
            raise _HookPathValidationError(
                _reported_hook_parameter(asked[0][0]), _DIRECTORY_TRUST_UNAVAILABLE
            ) from error
        return _HookDirectories(verdicts)

    def _write_json(
        self,
        payload: dict[str, Any],
        *,
        status: int = 200,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        body = escape_json_for_html(json.dumps(payload).encode("utf-8"))
        self._write_json_bytes(body, status=status, extra_headers=extra_headers)

    def _write_discovery_body(self, body: bytes) -> None:
        """Write the native discovery projection verbatim, uncached.

        The bytes are exactly what the native validator produced: this server
        never interprets, filters, or reorders placements.
        """

        self._write_json_bytes(
            escape_json_for_html(body),
            status=200,
            extra_headers={"Cache-Control": "no-store"},
        )

    def _write_json_bytes(
        self,
        body: bytes,
        *,
        status: int,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        """Write already HTML-safe JSON bytes with the standard response headers."""

        headers = {**dict(extra_headers or {}), "X-Content-Type-Options": "nosniff"}
        cors_headers = self._cors_headers_for_request(allow_methods="GET, POST, OPTIONS")
        if cors_headers is not None:
            headers = {**cors_headers, **headers}
        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            for key, value in self._validated_headers(headers).items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(body)
        except _PEER_DISCONNECT_ERRORS:
            self.close_connection = True

    def _write_empty(
        self,
        *,
        status: int,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        try:
            self.send_response(status)
            for key, value in self._validated_headers(extra_headers).items():
                self.send_header(key, value)
            self.end_headers()
        except _PEER_DISCONNECT_ERRORS:
            self.close_connection = True

    @staticmethod
    def _validated_headers(extra_headers: dict[str, str] | None) -> dict[str, str]:
        allowed_headers = {
            "Access-Control-Allow-Origin",
            "Access-Control-Expose-Headers",
            "ETag",
            "Access-Control-Allow-Methods",
            "Access-Control-Allow-Headers",
            "Access-Control-Allow-Private-Network",
            "Cache-Control",
            "Expires",
            "Location",
            "Pragma",
            "Vary",
            "X-Content-Type-Options",
        }
        validated: dict[str, str] = {}
        for key, value in (extra_headers or {}).items():
            if key not in allowed_headers or not isinstance(value, str):
                continue
            if "\r" in value or "\n" in value:
                continue
            validated[key] = value
        return validated


class GuardDaemonServer:
    """Small local daemon for health, receipts, and approval-center introspection."""

    _quarantine_lock: ClassVar[threading.Lock] = threading.Lock()
    _quarantined_services: ClassVar[dict[str, GuardDaemonServer]] = {}

    @staticmethod
    def _quarantine_key(guard_home: Path) -> str:
        try:
            return str(guard_home.resolve())
        except OSError:
            return str(guard_home)

    @classmethod
    def _retry_quarantined_service(cls, guard_home: Path) -> bool:
        key = cls._quarantine_key(guard_home)
        with cls._quarantine_lock:
            service = cls._quarantined_services.get(key)
        if service is None:
            return True
        return service._finish_service()

    def _is_quarantined(self) -> bool:
        key = self._quarantine_key(self._server.store.guard_home)
        with type(self)._quarantine_lock:
            return type(self)._quarantined_services.get(key) is self

    def _record_quarantine_state(self, *, contained: bool) -> bool:
        key = self._quarantine_key(self._server.store.guard_home)
        with type(self)._quarantine_lock:
            current = type(self)._quarantined_services.get(key)
            if contained:
                if current is self:
                    _ = type(self)._quarantined_services.pop(key, None)
            else:
                type(self)._quarantined_services[key] = self
        return contained

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
        extension_control_refresh_interval_seconds: float = 5.0,
        idle_timeout_seconds: float | None = None,
        home_dir: Path | None = None,
        workspace_dir: Path | None = None,
    ) -> None:
        if not type(self)._retry_quarantined_service(store.guard_home):
            raise RuntimeError("A previous Guard daemon remains quarantined after unconfirmed containment.")
        self._diagnostics = DaemonDiagnostics(store.guard_home)
        flush_pending_phases(self._diagnostics.record_phase)
        try:
            with timed_phase("init_provider_registry"):
                self._isolation_provider_registry = load_managed_provider_registry()
            with timed_phase("init_dashboard_bundle"):
                _validate_dashboard_bundle()
            # Pin this process's identity before serving. Computing it lazily
            # after an in-place upgrade would advertise the replacement
            # install's fingerprint for code that is still the old generation.
            with timed_phase("init_runtime_fingerprint"):
                current_guard_daemon_runtime_fingerprint()
        except BaseException:
            self._diagnostics.record_exception("daemon_initialization_failed")
            self._diagnostics.close(timeout_seconds=0.5)
            raise
        self._shutdown_started = threading.Event()
        self._lifecycle_lock = threading.Lock()
        self._lifecycle_generation = 0
        self._active_start_generation: int | None = None
        self._finish_service_lock = threading.Lock()
        self._finish_service_completed = False
        self._owned_service_ready = False
        self._serve_thread_error: BaseException | None = None
        self._owner_lock: BinaryIO | None = None
        try:
            http_server_started = time.monotonic()
            self._server = _GuardDaemonHttpServer(
                (host, port),
                _GuardDaemonHandler,
                store=store,
                auth_token=ensure_guard_daemon_auth_token(store.guard_home),
                runtime_host=host,
                runtime_session_id=uuid.uuid4().hex,
                runtime_started_at=_now(),
                home_dir=(home_dir or Path.home()).expanduser().resolve(strict=False),
                workspace_dir=workspace_dir.expanduser().resolve(strict=False) if workspace_dir is not None else None,
                idle_timeout_seconds=_guard_daemon_idle_timeout_seconds(
                    store.guard_home,
                    idle_timeout_seconds=idle_timeout_seconds,
                ),
                shutdown_started=self._shutdown_started,
                diagnostics=self._diagnostics,
            )
            self._server.command_queue_lifecycle = self
            record_phase_since("init_http_server", http_server_started)
        except BaseException:
            self._diagnostics.record_exception("daemon_initialization_failed")
            self._diagnostics.close(timeout_seconds=0.5)
            raise
        self.port = self._server.daemon_port()
        self._bundle_refresh_backoff_seconds = bundle_refresh_backoff_seconds
        self._bundle_refresh_interval_seconds = bundle_refresh_interval_seconds
        self._aibom_refresh_backoff_seconds = aibom_refresh_backoff_seconds
        self._aibom_refresh_interval_seconds = aibom_refresh_interval_seconds
        self._headless_cloud_sync_backoff_seconds = _DEFAULT_HEADLESS_CLOUD_SYNC_BACKOFF_SECONDS
        self._headless_cloud_sync_interval_seconds = _DEFAULT_HEADLESS_CLOUD_SYNC_INTERVAL_SECONDS
        self._aibom_home_dir = home_dir.expanduser() if home_dir is not None else None
        self._aibom_workspace_dir = workspace_dir.expanduser() if workspace_dir is not None else None
        self._aibom_context_workspace_id = store.get_cloud_workspace_id() if self._aibom_workspace_dir else None
        self._aibom_refresh_thread: threading.Thread | None = None
        self._bundle_refresh_thread: threading.Thread | None = None
        self._command_queue_worker: CommandQueueWorker | None = None
        self._headless_cloud_sync_thread: threading.Thread | None = None
        self._command_activity_maintenance_thread: threading.Thread | None = None
        self._onefile_extraction_reclaim_thread: threading.Thread | None = None
        self._extension_control_refresh_thread: threading.Thread | None = None
        self._extension_control_refresh_interval_seconds = extension_control_refresh_interval_seconds
        self._cloud_review_sync_worker: CloudReviewSyncWorker | None = None
        self._thread: threading.Thread | None = None
        self._serve_loop_started = threading.Event()
        self._watchdog_thread: threading.Thread | None = None
        self._native_resident_watchdog_thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            if self._shutdown_started.is_set():
                if self._aibom_refresh_thread is not None and self._aibom_refresh_thread.is_alive():
                    raise RuntimeError("AIBOM inventory refresh is still stopping")
                raise RuntimeError("Guard daemon is still stopping")
            return
        self._thread = None
        self._begin_service()
        generation = self._active_start_generation
        serve_thread_started = False
        try:
            start_serve_thread(self)
            serve_thread_started = True
            if not self._serve_loop_started.wait(timeout=_DAEMON_SERVE_THREAD_START_TIMEOUT_SECONDS):
                raise RuntimeError("Guard daemon serve thread did not become ready")
            if not startup_generation_is_current(self, generation):
                raise RuntimeError("Guard daemon stopped during startup")
        except BaseException as error:
            contain_failed_service_start(
                self,
                error,
                serve_thread_started=serve_thread_started,
            )
            raise

    def serve(self) -> None:
        self._serve_thread_error = None
        try:
            self._begin_service(publish_before_workers=True)
        except RuntimeError as error:
            if str(error) == "Guard daemon stopped during startup":
                return
            raise
        generation = self._active_start_generation
        serve_thread = self._thread
        try:
            if not startup_generation_is_current(self, generation):
                raise RuntimeError("Guard daemon stopped during startup")
            if serve_thread is None:
                self._serve_forever()
                return
            serve_thread.join()
            serve_error = self._serve_thread_error
            if serve_error is not None:
                raise serve_error
        except RuntimeError as error:
            if str(error) == "Guard daemon stopped during startup":
                return
            contain_failed_service_start(
                self,
                error,
                serve_thread_started=serve_thread is not None,
            )
            raise
        except BaseException as error:
            contain_failed_service_start(
                self,
                error,
                serve_thread_started=serve_thread is not None,
            )
            raise

    def stop(self) -> None:
        self._record_lifecycle("shutdown_requested", reason="explicit_stop")
        self._diagnostics.record("daemon_shutdown_requested")
        with self._lifecycle_lock:
            self._lifecycle_generation += 1
            self._shutdown_started.set()
        with self._finish_service_lock:
            serve_thread = self._thread
            self._server.request_serve_stop()
            if serve_thread is None:
                self._server.server_close()
        _ = self._finish_service()
        if (
            self._join_service_thread(serve_thread, deadline=time.monotonic() + 5) is None
            and self._thread is serve_thread
        ):
            self._thread = None

    def _begin_service(self, *, publish_before_workers: bool = False) -> None:
        begin_service(self, publish_before_workers=publish_before_workers)

    def _publish_listen_state(self) -> None:
        self._server.last_activity_monotonic = time.monotonic()
        self._server.publish_trust_state()
        self._server.runtime_heartbeat.register(
            GuardRuntimeRegistration(
                daemon_host=self._server.runtime_host,
                daemon_port=self.port,
                started_at=self._server.runtime_started_at,
            )
        )
        self._server.store.upsert_runtime_state(
            session_id=self._server.runtime_session_id,
            daemon_host=self._server.runtime_host,
            daemon_port=self.port,
            started_at=self._server.runtime_started_at,
            last_heartbeat_at=_now(),
        )

    def _begin_owned_service(
        self,
        generation: int | None = None,
        *,
        publish_before_workers: bool = False,
        continue_after_listen: bool = True,
    ) -> None:
        generation = generation if generation is not None else self._active_start_generation
        with self._lifecycle_lock:
            if generation != self._lifecycle_generation or self._shutdown_started.is_set():
                raise RuntimeError("Guard daemon stopped during startup")
        if self._aibom_refresh_thread is not None:
            if self._aibom_refresh_thread.is_alive():
                raise RuntimeError("AIBOM inventory refresh is still stopping")
            self._aibom_refresh_thread = None
        self._require_command_activity_maintenance_stopped()
        if publish_before_workers:
            # Desktop `desktop bootstrap --json` waits for the daemon state
            # file, not for hook workers or artifact reconciliation. Accept
            # HTTP and publish that file before the 60s+ cold-home work.
            with timed_phase("serve_thread_start", self._diagnostics.record_phase):
                start_serve_thread(self, already_locked=True)
                if not self._serve_loop_started.wait(timeout=_DAEMON_SERVE_THREAD_START_TIMEOUT_SECONDS):
                    raise RuntimeError("Guard daemon serve thread did not become ready")
            # Re-check under _finish_service_lock: shutdown may have been
            # requested while the serve loop was coming up. Publishing or
            # registering after shutdown would resurrect a stopped daemon.
            if self._shutdown_started.is_set() or not startup_generation_is_current(self, generation):
                raise RuntimeError("Guard daemon stopped during startup")
            self._publish_listen_state()
            self._diagnostics.record("daemon_listen_ready")
            self._warm_desktop_bootstrap_cache()
            if not continue_after_listen:
                return
        self._complete_owned_service_after_listen(generation, already_locked=True)

    def _complete_owned_service_after_listen(
        self,
        generation: int | None,
        *,
        already_locked: bool = False,
    ) -> None:
        if not startup_generation_is_current(self, generation):
            raise RuntimeError("Guard daemon stopped during startup")
        phase = self._diagnostics.record_phase
        with timed_phase("reconcile_runtime_artifacts", phase):
            self._reconcile_runtime_artifacts_best_effort()
        if not startup_generation_is_current(self, generation):
            raise RuntimeError("Guard daemon stopped during startup")
        with timed_phase("maintain_command_activity", phase):
            self._maintain_command_activity_best_effort()
        if not startup_generation_is_current(self, generation):
            raise RuntimeError("Guard daemon stopped during startup")
        with timed_phase("persist_aibom_context", phase):
            self._persist_aibom_inventory_context()

        def start_post_listen_workers() -> None:
            # The shutdown/generation re-check and the registration publish
            # must stay atomic under _finish_service_lock: _finish_service
            # takes the same lock, so a completed shutdown can never be
            # followed by a late register()/heartbeat start resurrecting the
            # runtime row.
            if self._shutdown_started.is_set() or not startup_generation_is_current(self, generation):
                raise RuntimeError("Guard daemon stopped during startup")
            with timed_phase("publish_listen_state", phase):
                self._publish_listen_state()
            with timed_phase("start_watchdog_and_heartbeat", phase):
                self._server.start_unclassified_watchdog()
                self._server.runtime_heartbeat.start()
                approval_attention = getattr(self._server, "approval_attention", None)
                if approval_attention is not None:
                    approval_attention.start()
                self._start_watchdog()
            with timed_phase("start_sync_and_refresh_threads", phase):
                self._start_headless_cloud_sync()
                self._start_supply_chain_bundle_refresh()
                self._start_aibom_inventory_refresh()
                self._start_extension_control_refresh()
            with timed_phase("start_queue_and_cloud_workers", phase):
                self._command_queue_worker = start_command_queue_worker(self._server.store, self._command_queue_worker)
                self._cloud_review_sync_worker = start_cloud_sync_sync_worker(
                    self._server.store,
                    self._cloud_review_sync_worker,
                    on_authority_changed=self._start_command_queue_after_authority,
                )
            with timed_phase("start_maintenance_threads", phase):
                self._start_command_activity_maintenance()
                self._start_onefile_extraction_reclaim()
                self._start_repair_self_check()
                self._start_native_resident_watchdog()
            self._record_lifecycle("ready")
            self._owned_service_ready = True
            self._diagnostics.record("daemon_ready")

        if already_locked:
            start_post_listen_workers()
            return
        with self._finish_service_lock:
            start_post_listen_workers()

    def _warm_desktop_bootstrap_cache(self) -> None:
        """Fill the bootstrap document before Desktop's first open poll.

        This runs beside artifact reconciliation. A failure leaves the cache
        empty; the request path builds the document or returns 503.
        """

        server = self._server

        def warm() -> None:
            try:
                from ..cli.commands_dispatch_desktop import desktop_bootstrap_document_for_running_daemon

                with timed_phase("warm_desktop_bootstrap_cache", self._diagnostics.record_phase):
                    desktop_bootstrap_document_for_running_daemon(
                        store=server.store,
                        home_dir=server.home_dir,
                        daemon_url=f"http://127.0.0.1:{server.daemon_port()}",
                        auth_token=server.auth_token,
                    )
            except Exception:
                self._diagnostics.record_exception("desktop_bootstrap_warmup_failed")
                return

        threading.Thread(target=warm, name="desktop-bootstrap-warm", daemon=True).start()

    def refresh_command_queue_worker(self) -> dict[str, object]:
        """Apply changed Cloud connectivity and consent without a daemon restart."""

        if not self._finish_service_lock.acquire(blocking=False):
            return {
                "operation": "guard.review.resolveExact",
                "running": False,
                "sync_running": False,
            }
        try:
            if not self._owned_service_ready or self._shutdown_started.is_set():
                return {
                    "operation": "guard.review.resolveExact",
                    "running": False,
                    "sync_running": False,
                }
            self._command_queue_worker, running = refresh_command_queue_worker(
                self._server.store,
                self._command_queue_worker,
                shutting_down=self._shutdown_started.is_set(),
            )
            from ..runtime.cloud_review_sync_worker import refresh_cloud_review_sync_worker

            self._cloud_review_sync_worker, sync_running = refresh_cloud_review_sync_worker(
                self._server.store,
                self._cloud_review_sync_worker,
                shutting_down=self._shutdown_started.is_set(),
                on_authority_changed=self._start_command_queue_after_authority,
            )
        finally:
            self._finish_service_lock.release()
        return {
            "operation": "guard.review.resolveExact",
            "running": running,
            "sync_running": sync_running,
        }

    def _start_command_queue_after_authority(self) -> bool:
        if self._shutdown_started.is_set() or not self._finish_service_lock.acquire(blocking=False):
            return False
        try:
            if not self._owned_service_ready or self._shutdown_started.is_set():
                return False
            self._command_queue_worker = start_command_queue_worker(self._server.store, self._command_queue_worker)
            return True
        finally:
            self._finish_service_lock.release()

    def _reconcile_runtime_artifacts_best_effort(self) -> None:
        """Align existing Guard-owned artifacts before reporting daemon_ready."""
        try:
            result = reconcile_runtime_artifacts(
                self._server.store,
                home_dir=self._aibom_home_dir,
            )
        except Exception as error:
            self._diagnostics.record("runtime_artifact_reconciliation_failed", detail=str(error))
            return
        detail = (
            f"launchers={','.join(result.refreshed_launchers) or 'none'} "
            f"harnesses={','.join(result.repaired_harnesses) or 'none'} "
            f"packages={','.join(result.repaired_package_managers) or 'none'} "
            f"failed={','.join((*result.failed_harnesses, *result.errors)) or 'none'}"
        )
        event = (
            "runtime_artifact_reconciliation_completed"
            if result.healthy
            else "runtime_artifact_reconciliation_degraded"
        )
        self._diagnostics.record(event, detail=detail)

    def _maintain_command_activity_best_effort(self) -> None:
        now = datetime.now(timezone.utc)
        try:
            config = load_guard_config(self._server.store.guard_home)
            self._server.store.maintain_command_activity(
                now=now,
                detail_retain_days=config.evidence_retain_days,
            )
        except Exception:
            with suppress(Exception):
                self._server.store.record_command_activity_persistence_failure(
                    error_code="maintenance_failed",
                    occurred_at=now,
                )

    def _maintain_storage_best_effort(self) -> bool:
        try:
            config = load_guard_config(
                self._server.store.guard_home,
            )
            receipt_detail_limit = (
                config.receipt_detail_limit if config.receipt_detail_limit is not None else DEFAULT_RECEIPT_DETAIL_LIMIT
            )
            guard_event_limit = (
                config.guard_event_limit if config.guard_event_limit is not None else DEFAULT_GUARD_EVENT_LIMIT
            )
            result = self._server.store.maintain_storage(
                now=datetime.now(timezone.utc),
                detail_retain_days=config.evidence_retain_days,
                receipt_detail_limit=receipt_detail_limit,
                guard_event_limit=guard_event_limit,
            )
        except Exception:
            return False
        return result.completed

    def _start_command_activity_maintenance(self) -> None:
        if (
            self._command_activity_maintenance_thread is not None
            and self._command_activity_maintenance_thread.is_alive()
        ):
            return
        self._command_activity_maintenance_thread = threading.Thread(
            target=self._command_activity_maintenance_loop,
            daemon=True,
        )
        self._command_activity_maintenance_thread.start()

    def _require_command_activity_maintenance_stopped(self) -> None:
        if self._command_activity_maintenance_thread is None:
            return
        if self._command_activity_maintenance_thread.is_alive():
            raise RuntimeError("command activity maintenance is still stopping")
        self._command_activity_maintenance_thread = None

    def _command_activity_maintenance_loop(self) -> None:
        if self._shutdown_started.is_set():
            return
        self._maintain_command_activity_best_effort()
        storage_complete = self._maintain_storage_best_effort()
        while not self._shutdown_started.wait(3_600 if storage_complete else 5):
            self._maintain_command_activity_best_effort()
            storage_complete = self._maintain_storage_best_effort()

    def _start_onefile_extraction_reclaim(self) -> None:
        if not getattr(sys, "frozen", False):
            return
        if self._onefile_extraction_reclaim_thread is not None and self._onefile_extraction_reclaim_thread.is_alive():
            return
        self._onefile_extraction_reclaim_thread = threading.Thread(
            target=self._onefile_extraction_reclaim_loop,
            daemon=True,
        )
        self._onefile_extraction_reclaim_thread.start()

    def _start_repair_self_check(self) -> None:
        def publish(status: dict[str, object]) -> None:
            self._server.repair_self_check_status = status

        repair_self_check.start_self_check(
            self._server.store,
            publish=publish,
            stop=self._shutdown_started,
            on_error=self._diagnostics.record_exception,
        )

    def _start_native_resident_watchdog(self) -> None:
        self._native_resident_watchdog_thread = start_native_resident_watchdog(
            self._server.store.guard_home,
            stop=self._shutdown_started,
            on_error=self._diagnostics.record_exception,
        )

    def _onefile_extraction_reclaim_loop(self) -> None:
        while not self._shutdown_started.is_set():
            self._reclaim_onefile_extraction_dirs_once()
            if self._shutdown_started.wait(3_600):
                return

    def _reclaim_onefile_extraction_dirs_once(self) -> None:
        try:
            from ..onefile_extraction import reclaim_orphaned_extraction_dirs
            from ..onefile_open_paths import scan_open_extraction_dirs

            result = reclaim_orphaned_extraction_dirs(
                temp_root=Path(tempfile.gettempdir()),
                current_meipass=getattr(sys, "_MEIPASS", None),
                now=datetime.now(timezone.utc),
                should_stop=self._shutdown_started.is_set,
                open_path_scanner=scan_open_extraction_dirs,
            )
        except Exception:
            self._diagnostics.record_exception("onefile_extraction_reclaim_failed")
            self._server.onefile_extraction_status = {
                "last_run_at": datetime.now(timezone.utc).isoformat(),
                "error": "reclaim_failed",
            }
            return
        self._server.onefile_extraction_status = {
            "last_run_at": datetime.now(timezone.utc).isoformat(),
            "reclaimed_count": result.reclaimed_count,
            "reclaimed_bytes": result.reclaimed_bytes,
            "killed_launches_last_run": result.killed_launches,
            "unmarked_legacy_count": result.unmarked_count,
            "unmarked_legacy_bytes_estimate": result.unmarked_bytes_estimate,
            "unmarked_reclaimed_count": result.unmarked_reclaimed_count,
            "unmarked_reclaimed_bytes": result.unmarked_reclaimed_bytes,
            "unmarked_scan": result.unmarked_scan,
            "error_count": len(result.errors),
        }
        self._diagnostics.record(
            "onefile_extraction_reclaimed",
            detail=(
                f"reclaimed={result.reclaimed_count} bytes={result.reclaimed_bytes} "
                f"killed={result.killed_launches} unmarked={result.unmarked_count} "
                f"unmarked_bytes_estimate={result.unmarked_bytes_estimate} errors={len(result.errors)}"
            ),
        )

    def _persist_aibom_inventory_context(self) -> None:
        persist_aibom_inventory_context(
            store=self._server.store,
            cached_workspace_id=self._aibom_context_workspace_id,
            workspace_dir=self._aibom_workspace_dir,
            home_dir=self._aibom_home_dir,
            now=_now(),
            record_diagnostic=self._diagnostics.record,
        )

    def _serve_forever(self) -> None:
        stop_reason = "serve_loop_returned"
        try:
            self._serve_loop_started.set()
            self._server.serve_forever()
            if self._shutdown_started.is_set():
                stop_reason = "requested_shutdown"
        except KeyboardInterrupt:
            self._record_lifecycle("shutdown_requested", reason="keyboard_interrupt")
            self._shutdown_started.set()
            stop_reason = "requested_shutdown"
        except BaseException as error:
            stop_reason = "serve_loop_failed"
            self._serve_thread_error = error
            self._record_lifecycle("serve_failed", reason="unexpected_exception")
            self._diagnostics.record_exception("daemon_serve_failed")
            raise
        finally:
            self._diagnostics.record("daemon_stopped", detail=stop_reason)
            self._server.server_close()
            _ = self._finish_service()
            self._record_lifecycle("stopped", reason=stop_reason)
            if self._thread is threading.current_thread():
                self._thread = None

    def _record_lifecycle(self, event: str, *, reason: str | None = None) -> None:
        with suppress(Exception):
            record_daemon_lifecycle_event(
                self._server.store.guard_home,
                event=event,
                session_id=self._server.runtime_session_id,
                reason=reason,
                port=self.port,
            )

    def _finish_service(self) -> bool:
        finish_lock = getattr(self, "_finish_service_lock", None)
        if finish_lock is None:
            with type(self)._quarantine_lock:
                finish_lock = getattr(self, "_finish_service_lock", None)
                if finish_lock is None:
                    finish_lock = threading.Lock()
                    self._finish_service_lock = finish_lock
        with finish_lock:
            if getattr(self, "_finish_service_completed", False):
                return True
            contained = self._finish_service_locked()
            if contained:
                self._finish_service_completed = True
            return contained

    def _finish_service_locked(self) -> bool:
        self._owned_service_ready = False
        self._shutdown_started.set()
        contained = True
        close_discovery = getattr(getattr(self._server, "local_cli_api", None), "close_discovery", None)
        if callable(close_discovery):
            try:
                contained = close_discovery() is not False and contained
            except Exception:
                contained = False
        stop_request_executors = getattr(self._server, "_stop_request_executors", None)
        if callable(stop_request_executors):
            try:
                contained = stop_request_executors() is not False and contained
            except Exception:
                contained = False
        stop_unclassified_watchdog = getattr(self._server, "stop_unclassified_watchdog", None)
        if callable(stop_unclassified_watchdog):
            try:
                contained = stop_unclassified_watchdog() is not False and contained
            except Exception:
                contained = False
        approval_attention = getattr(self._server, "approval_attention", None)
        if approval_attention is not None:
            try:
                contained = approval_attention.stop() is not False and contained
            except Exception:
                contained = False
        try:
            self._command_queue_worker = stop_command_queue_worker(self._command_queue_worker)
            contained = self._command_queue_worker is None and contained
        except Exception:
            contained = False
        try:
            self._cloud_review_sync_worker = stop_cloud_sync_sync_worker(self._cloud_review_sync_worker)
            contained = self._cloud_review_sync_worker is None and contained
        except Exception:
            contained = False
        runtime_heartbeat = getattr(self._server, "runtime_heartbeat", None)
        if runtime_heartbeat is not None:
            try:
                runtime_heartbeat.clear_registration()
            except Exception:
                contained = False
            try:
                contained = runtime_heartbeat.stop(timeout_seconds=1.0) is not False and contained
            except Exception:
                contained = False
        runtime_hook_evidence_dispatch = getattr(self._server, "runtime_hook_evidence_dispatch", None)
        if runtime_hook_evidence_dispatch is not None:
            with suppress(Exception):
                contained = runtime_hook_evidence_dispatch.stop(1.0) and contained
        runtime_hook_evidence_writer = getattr(self._server, "runtime_hook_evidence_writer", None)
        if runtime_hook_evidence_writer is not None:
            try:
                contained = runtime_hook_evidence_writer.stop(timeout_seconds=1.0) is not False and contained
            except Exception:
                contained = False
        hook_worker = getattr(self._server, "hook_worker", None)
        if hook_worker is not None:
            try:
                close_contained = getattr(hook_worker, "close_contained", None)
                if callable(close_contained):
                    contained = close_contained() is not False and contained
                else:
                    contained = hook_worker.close() is not False and contained
            except Exception:
                contained = False
        contained = self._join_service_background_threads() and contained
        extension_control_api = getattr(self._server, "extension_control_api", None)
        if extension_control_api is not None:
            # Best effort: process exit releases the leases anyway.
            with suppress(Exception):
                _ = extension_control_api.release_prepared_cache_leases()
        with suppress(Exception):
            clear_guard_daemon_state_if_current(
                self._server.store.guard_home,
                pid=os.getpid(),
                port=self.port,
            )
        with suppress(Exception):
            self._server.store.clear_runtime_state(session_id=self._server.runtime_session_id)
        if contained and (self._thread is None or self._is_quarantined()):
            try:
                self._server.server_close()
            except Exception:
                contained = False
        if contained:
            try:
                release_guard_daemon_owner_lock(getattr(self, "_owner_lock", None))
            except Exception:
                contained = False
            else:
                self._owner_lock = None
        with suppress(Exception):
            self._diagnostics.close(timeout_seconds=1.0)
        return self._record_quarantine_state(contained=contained)

    @staticmethod
    def _join_service_thread(
        thread: threading.Thread | None,
        *,
        deadline: float,
    ) -> threading.Thread | None:
        if thread is None:
            return None
        if thread is not threading.current_thread():
            thread.join(timeout=max(0.0, deadline - time.monotonic()))
        return thread if thread.is_alive() else None

    def _join_service_background_threads(self) -> bool:
        started = time.monotonic()
        deadline = started + _AIBOM_REFRESH_STOP_JOIN_TIMEOUT_SECONDS
        self._watchdog_thread = self._join_service_thread(
            getattr(self, "_watchdog_thread", None),
            deadline=deadline,
        )
        self._bundle_refresh_thread = self._join_service_thread(
            getattr(self, "_bundle_refresh_thread", None),
            deadline=deadline,
        )
        self._aibom_refresh_thread = self._join_service_thread(
            getattr(self, "_aibom_refresh_thread", None),
            deadline=deadline,
        )
        self._extension_control_refresh_thread = self._join_service_thread(
            getattr(self, "_extension_control_refresh_thread", None),
            deadline=deadline,
        )
        self._headless_cloud_sync_thread = self._join_service_thread(
            getattr(self, "_headless_cloud_sync_thread", None),
            deadline=deadline,
        )
        self._command_activity_maintenance_thread = self._join_service_thread(
            getattr(self, "_command_activity_maintenance_thread", None),
            deadline=deadline,
        )
        self._onefile_extraction_reclaim_thread = self._join_service_thread(
            getattr(self, "_onefile_extraction_reclaim_thread", None),
            deadline=deadline,
        )
        self._native_resident_watchdog_thread = self._join_service_thread(
            getattr(self, "_native_resident_watchdog_thread", None),
            deadline=started + _NATIVE_RESIDENT_WATCHDOG_STOP_JOIN_TIMEOUT_SECONDS,
        )
        return all(
            thread is None
            for thread in (
                self._watchdog_thread,
                self._bundle_refresh_thread,
                self._aibom_refresh_thread,
                self._extension_control_refresh_thread,
                self._headless_cloud_sync_thread,
                self._command_activity_maintenance_thread,
                self._onefile_extraction_reclaim_thread,
                self._native_resident_watchdog_thread,
            )
        )

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
        reported_failure: str | None = None
        while not self._shutdown_started.is_set():
            try:
                summary = _run_headless_cloud_sync_with_optional_publish(
                    store=self._server.store,
                    managed_controls_publish=_managed_controls_publish_for(self._server),
                )
            except Exception as error:
                # Cloud sync carries receipts and bookkeeping, never admission
                # authority, so a store that cannot record the attempt must not
                # end the loop. An unconnected install reaches this through the
                # not-logged-in path, where recording the outcome needs the same
                # native store; letting that escape left the daemon printing a
                # traceback and never syncing again, not even after a sign-in.
                reason = f"{type(error).__name__}: {error}"
                if reason != reported_failure:
                    reported_failure = reason
                    if isinstance(error, NativeGuardStoreUnavailable):
                        _LOGGER.warning("Headless cloud sync could not complete: %s", reason)
                    else:
                        _LOGGER.exception("Headless cloud sync could not complete: %s", reason)
                status = ""
            else:
                reported_failure = None
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
            from ..native_approval_scope import ApprovalScopeUnavailableError

            try:
                try:
                    pending_review_requests = self._server.store.list_approval_requests(
                        status="pending",
                        limit=1,
                    )
                except ApprovalScopeUnavailableError as error:
                    if not isinstance(error.__cause__, NativeGuardStoreUnavailable):
                        raise
                    # The native resident cannot read the queue, so whether a review
                    # is pending is unknown. Pending rows stay durable in guard.db;
                    # do not let this pin the daemon alive.
                    pending_review_requests = []
                cloud_profile = self._server.store.get_cloud_sync_profile()
                workspace_id = cloud_profile.get("workspace_id") if isinstance(cloud_profile, dict) else None
                try:
                    outbox_status = self._server.store.review_event_outbox_status(
                        now=_now(),
                        workspace_id=workspace_id,
                    )
                    outbox_depth = outbox_status["depth"]
                except NativeGuardStoreUnavailable:
                    # The native resident cannot answer, so no delivery can run and
                    # the depth is unknown rather than transient-locked. Queued events
                    # stay durable in guard.db; do not let this pin the daemon alive.
                    outbox_depth = None
            except (sqlite3.OperationalError, ApprovalScopeUnavailableError):
                time.sleep(_GUARD_DAEMON_IDLE_POLL_INTERVAL_SECONDS)
                continue
            if (
                active_stream_clients > 0
                or pending_review_requests
                or (workspace_id is not None and isinstance(outbox_depth, int) and outbox_depth > 0)
            ):
                time.sleep(_GUARD_DAEMON_IDLE_POLL_INTERVAL_SECONDS)
                continue
            with self._server.request_capacity_lock:
                # A request that outlives the idle window is activity, not idleness.
                idle = (
                    self._server.active_requests == 0
                    and time.monotonic() - self._server.last_activity_monotonic >= idle_timeout_seconds
                )
                if idle:
                    self._server.idle_shutdown_claimed = True
            if idle:
                self._record_lifecycle("shutdown_requested", reason="idle_timeout")
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

    def _start_extension_control_refresh(self) -> None:
        if self._extension_control_refresh_thread is not None:
            return
        self._extension_control_refresh_thread = threading.Thread(
            target=self._refresh_extension_control_loop,
            daemon=True,
            name="guard-extension-control-refresh",
        )
        self._extension_control_refresh_thread.start()

    def _refresh_extension_control_loop(self) -> None:
        next_security_refresh = 0.0
        while not self._shutdown_started.wait(self._extension_control_refresh_interval_seconds):
            periodic = time.monotonic() >= next_security_refresh
            try:
                with lifecycle.session():
                    if periodic:
                        from ..catalog_delivery.active_security import observe
                        from ..catalog_delivery.discovery import request_refresh

                        next_security_refresh = time.monotonic() + 300.0
                        # Security observation must not wait for complete discovery
                        # traversal. The latter has its own bounded background slot.
                        try:
                            observe(self._server.store)
                        finally:
                            request_refresh(self._server.store.guard_home, store=self._server.store)
                    _ = self._server.refresh_extension_control_runtime()
            except Exception:
                _LOGGER.exception("Failed to refresh resident extension-control authority")
            if periodic:
                try:
                    from ..catalog_delivery.cache_io import cleanup

                    with lifecycle.session():
                        self._server.extension_control_api.expire_prepared_cache_leases()
                        cleanup(self._server.store)
                except Exception:
                    _LOGGER.exception("Failed to clean the command-pack cache")

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


def _validate_dashboard_bundle() -> None:
    if not _INDEX_PATH.is_file() or not _ENTRY_PATH.is_file():
        raise RuntimeError(
            "Guard dashboard bundle is missing. Run `pnpm install && pnpm run build` in the dashboard directory."
        )
    # Serve the dashboard that matches this process's code, even after an
    # in-place upgrade replaces the files on disk.
    pin_dashboard_bundle(_STATIC_DIR)


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
    return None


def _guard_home_is_ephemeral(guard_home: Path) -> bool:
    resolved_parts = guard_home.resolve().parts
    return any(part.startswith("pytest-") or "pytest-of-" in part for part in resolved_parts)


forget_in_child(GuardDaemonServer._quarantined_services)
