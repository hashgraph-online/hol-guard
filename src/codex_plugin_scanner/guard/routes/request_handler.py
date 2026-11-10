"""Local Guard daemon helpers."""

# pyright: reportUninitializedInstanceVariable=false

from __future__ import annotations

import base64
import errno
import hashlib
import hmac
import json
import os
import socket
import sys
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, TypeAlias, TypedDict

from ..daemon.audit_persistence import AuditPersistence
from ..daemon.diagnostics import DaemonDiagnostics
from ..daemon.hook_evidence_dispatch import HookEvidenceDispatch
from ..daemon.manager import (
    write_guard_daemon_state,
)
from ..daemon.runtime_heartbeat import RuntimeHeartbeatWriter
from ..native_hook_evidence_writer import NativeHookEvidenceWriter
from ..runtime.approval_attention import ApprovalAttentionCoordinator
from ..runtime.network_supervisor import NetworkSupervisor
from ..runtime.surface_server import GuardSurfaceRuntime
from ..store import GuardStore

_LOCAL_DASHBOARD_SESSION_REFRESH_GRACE_SECONDS = 7 * 24 * 60 * 60
_DEFAULT_HEADLESS_CLOUD_SYNC_INTERVAL_SECONDS = 30.0
_PLUGIN_TELEMETRY_FIRST_CHECK_SECONDS = 300.0
_PLUGIN_TELEMETRY_CHECK_INTERVAL_SECONDS = 6 * 60 * 60.0
_DEFAULT_HEADLESS_CLOUD_SYNC_BACKOFF_SECONDS = 10.0


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


_RUNTIME_HOOK_PROCESS_TIMEOUT_SECONDS = 1.45
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


_PEER_DISCONNECT_ERRORS = (BrokenPipeError, ConnectionResetError, ConnectionAbortedError)


class _GuardDaemonHTTPServer:
    request_queue_size = _MAX_CONCURRENT_DAEMON_CONNECTIONS
    # Set once the HTTP superclass has bound the listening socket.
    _socket_bound: bool = False
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
    runtime_heartbeat: RuntimeHeartbeatWriter
    diagnostics: DaemonDiagnostics
    auth_audit_lock: threading.Lock
    denial_audit_lock: threading.Lock
    audit_persistence: AuditPersistence
    auth_audit_windows: dict[_AuthAuditKey, _AuthAuditWindow]
    command_queue_lifecycle: Any
    server_address: Any
    extension_control_runtime: Any
    extension_control_api: Any
    hook_worker: Any

    def classify_connection(self, request: Any) -> None:
        raise NotImplementedError

    def claim_request_capacity(self, request: Any, path: str) -> bool:
        raise NotImplementedError

    def request_deadline(self, request: Any, timeout_seconds: float) -> float:
        raise NotImplementedError

    home_dir: Path
    workspace_dir: Path | None

    def handle_error(self, request: Any, client_address: Any) -> None:
        """Suppress expected peer disconnects without hiding server defects."""

        error = sys.exc_info()[1]
        if isinstance(error, _PEER_DISCONNECT_ERRORS) or (
            isinstance(error, OSError)
            and error.errno in {errno.EBADF, errno.ECONNABORTED, errno.ECONNRESET, errno.EPIPE}
        ):
            return
        self.diagnostics.record_exception("http_request_failed")

    @staticmethod
    def _request_capacity_kind(path: str) -> str:
        path = path.split("?", 1)[0]
        if path in _DAEMON_CRITICAL_PATHS:
            return "critical"
        if path in _DAEMON_CONTROL_PATHS:
            return "control"
        return "general"

    def daemon_host(self) -> str:
        return str(self.server_address[0])

    def daemon_port(self) -> int:
        return int(self.server_address[1])

    def daemon_pid(self) -> int:
        """The process the published daemon state names."""

        return os.getpid()

    def publish_trust_state(self, trust_status: dict[str, object] | None = None) -> None:
        # The store can report an integrity change while the hook worker starts,
        # before the listening socket is bound. `server_address` is assigned
        # before the bind, so with port 0 it would still name no port; the
        # daemon publishes its trust state once it listens.
        if not self._socket_bound:
            return
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


_STATIC_DIR = Path(__file__).parent.parent / "daemon" / "static"
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


def _is_public_static_path(path: str) -> bool:
    """Whether ``path`` names a dashboard file bundled with the package.

    These files are the same for every caller, and a page on any site can load
    them with a plain script or image tag, which sends no ``Origin``. Asking the
    native runtime about the caller's origin protects nothing here. The
    dashboard requests a few dozen of them at once when it opens, and on a slow
    machine that burst outlasted the origin check's budget and the page broke.
    """
    return path in _ROOT_STATIC_FILES or path.startswith(("/assets/", "/brand/"))


_DEFAULT_SUPPLY_CHAIN_REFRESH_BACKOFF_SECONDS = 60.0
_DEFAULT_SUPPLY_CHAIN_REFRESH_INTERVAL_SECONDS = 15 * 60.0
_EPHEMERAL_GUARD_DAEMON_IDLE_TIMEOUT_SECONDS = 5
_GUARD_DAEMON_IDLE_POLL_INTERVAL_SECONDS = 0.5


_GuardDaemonHttpServer = _GuardDaemonHTTPServer


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
