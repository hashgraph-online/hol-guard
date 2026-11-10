"""Local Guard daemon helpers."""

# pyright: reportUninitializedInstanceVariable=false

from __future__ import annotations

import base64
import errno
import hashlib
import hmac
import json
import os
import secrets
import socket
import sys
import threading
import time
from collections.abc import Callable, Mapping
from contextlib import suppress
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import Any, TypeAlias, TypedDict, cast
from urllib.parse import parse_qs, parse_qsl, urlparse

from ...version import __version__
from ..adapters import get_adapter
from ..approval_gate import (
    ApprovalGateError,
)
from ..codex_live_decision import complete_codex_live_decision, resolve_codex_live_allow_authority
from ..codex_live_decision_revalidation import revalidate_codex_live_allow
from ..daemon.audit_persistence import NOT_PERSISTED as AUDIT_NOT_PERSISTED
from ..daemon.audit_persistence import WRITTEN as AUDIT_WRITTEN
from ..daemon.audit_persistence import AuditPersistence
from ..daemon.command_activity_api import (
    parse_command_activity_event_cursor,
    stream_command_activity_events,
)
from ..daemon.dashboard_bundle import DASHBOARD_BUILD_HEADER, dashboard_build_id
from ..daemon.diagnostics import DaemonDiagnostics
from ..daemon.hook_evidence_dispatch import HookEvidenceDispatch
from ..daemon.hook_request_auth import CHALLENGE_HOOK_PATHS, challenge_auth, request_auth
from ..daemon.manager import (
    GUARD_DAEMON_COMPATIBILITY_VERSION,
    current_guard_daemon_runtime_fingerprint,
    current_guard_daemon_source_root,
    write_guard_daemon_state,
)
from ..daemon.runtime_heartbeat import RuntimeHeartbeatWriter
from ..daemon.runtime_hook_scheduler import RuntimeHookScheduler
from ..daemon.server_common import (
    _build_local_url,
    _now,
)
from ..daemon.server_control_cloud_connect import _CloudConnectRoutes
from ..daemon.server_control_headless import (
    _HeadlessRoutes,
)
from ..daemon.server_control_health import _ControlHealthRoutes
from ..daemon.server_control_misc import _ControlMiscRoutes
from ..daemon.server_control_policy import _ControlPolicyRoutes
from ..daemon.server_control_repair import _RepairSettingsRoutes
from ..daemon.server_control_routes_post import _ControlPostRoutes
from ..daemon.server_control_supply_chain import _SupplyChainRoutes
from ..daemon.server_dashboard_records_read import _DashboardRecordsReadRoutes
from ..daemon.server_dashboard_runtime_read import _DashboardRuntimeReadRoutes
from ..daemon.server_dashboard_support import _DashboardSupportRoutes
from ..daemon.server_runtime_hook import _RuntimeHookRoutes
from ..json_transport import escape_json_for_html
from ..local_dashboard_session import (
    DEFAULT_LOCAL_DASHBOARD_SESSION_TTL_SECONDS,
    LOCAL_DASHBOARD_SESSION_AUDIENCE,
    LOCAL_DASHBOARD_SESSION_STARTED_AT_CLAIM,
    MAX_LOCAL_DASHBOARD_SESSION_AGE_SECONDS,
    PROTECTION_REPAIR_DASHBOARD_SURFACE,
    build_local_dashboard_session_token,
)
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
from ..native_hook_evidence_writer import NativeHookEvidenceWriter, unreachable_writer_stats
from ..native_resident_client import record_native_resident_client_failure_code
from ..native_resident_revival import native_route_unavailable_body
from ..native_runtime_request_scope import scoped_hook_post
from ..package_firewall_action_rate_limit import PackageFirewallActionRateLimiter
from ..routes.context_assistance_versions_http import request_body_limit as context_request_body_limit
from ..runtime.approval_attention import ApprovalAttentionCoordinator
from ..runtime.network_status import project_network_supervisor_health
from ..runtime.network_supervisor import NetworkSupervisor
from ..runtime.surface_server import GuardSurfaceRuntime
from ..storage_retention import quarantined_store_summary
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


_MAX_CONCURRENT_RUNTIME_HOOKS = 32
_MAX_CONCURRENT_RUNTIME_HOOKS_PER_HARNESS = 24
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
    _ControlHealthRoutes,
    _RuntimeHookRoutes,
    BaseHTTPRequestHandler,
):
    _MAX_BODY_BYTES = 1_000_000
    _native_gate_unavailable = False
    server: _GuardDaemonHttpServer  # pyright: ignore[reportIncompatibleVariableOverride]

    def end_headers(self) -> None:
        # Every response names the dashboard bundle this daemon serves, so a tab
        # still running an older bundle notices the restart and reloads.
        build_id = dashboard_build_id(_STATIC_DIR)
        if build_id is not None:
            self.send_header(DASHBOARD_BUILD_HEADER, build_id)
        super().end_headers()

    def parse_request(self) -> bool:
        # A kept-alive connection reuses this thread, so each request starts
        # without the previous request's gate or resident failure.
        self._native_gate_unavailable = False
        record_native_resident_client_failure_code(None)
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
        if not _is_public_static_path(parsed.path) and not self._origin_is_allowed_for_request(parsed.path):
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
            self._write_json({"error": "not_found"}, status=404)
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
        if route.route_class != "none" and not self._header_token_is_valid():
            self._write_unauthorized(extra_headers=self._cors_headers_for_request())
            return
        if route.route_class != "none":
            try:
                content_length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                self._write_json({"error": "invalid_content_length"}, status=400)
                return
            if content_length < 0 or content_length > context_request_body_limit(parsed.path, self._MAX_BODY_BYTES):
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
        if length > context_request_body_limit(urlparse(getattr(self, "path", "")).path, self._MAX_BODY_BYTES):
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
        authority_resolved = False
        if isinstance(request, Mapping) and request.get("resolution_action") == "allow":
            authority_resolved = (
                resolve_codex_live_allow_authority(
                    self.server.store,  # type: ignore[attr-defined]
                    request=request,
                    request_id=request_id,
                    now=_now(),
                )
                is not None
            )
        fresh_allow_authorized = self._revalidate_codex_live_allow(
            request,
            payload,
            previous=previous,
            request_id=request_id,
            authority_resolved=authority_resolved,
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
        previous: object = None,
        request_id: str | None = None,
        authority_resolved: bool = False,
    ) -> bool:
        daemon_server = self._daemon_server()
        home_dir = daemon_server.home_dir
        return revalidate_codex_live_allow(
            request,
            payload,
            home_dir=home_dir,
            guard_home=daemon_server.store.guard_home,
            previous=previous,
            request_id=request_id,
            authority_resolved=authority_resolved,
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

    def _query_has_guard_token(self, query: str) -> bool:
        return any(key == "token" for key, _value in parse_qsl(query, keep_blank_values=True))

    def _consume_codex_daemon_challenge(self, payload: dict[str, object]) -> bool:
        # The native daemon issues the identity challenge and checks the proof
        # on the connection the hook arrives on; it tells this replay whether
        # the hook presented that proof for its own event.
        del payload
        return bool(getattr(self._daemon_server(), "daemon_proof_verified", False))

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
            self._native_gate_unavailable = True
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
            self._native_gate_unavailable = True
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
            self._native_gate_unavailable = True
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
            self._native_gate_unavailable = True
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
        if claims is None or claims.get("request_id") is not None:
            # A session bound to one request ends with the link that opened it.
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

    def _request_holds_link_bound_session(self) -> bool:
        """Whether the caller presents a session opened from an approval link."""

        session_token = self.headers.get("X-Guard-Dashboard-Session")
        authorization = self.headers.get("Authorization")
        bearer_token = None
        if isinstance(authorization, str) and authorization.lower().startswith("bearer "):
            bearer_token = authorization[7:].strip()
        for candidate in (session_token, bearer_token):
            if not isinstance(candidate, str) or not candidate.strip():
                continue
            claims = self._dashboard_session_token_claims(
                candidate,
                allow_expired_within_seconds=_LOCAL_DASHBOARD_SESSION_REFRESH_GRACE_SECONDS,
            )
            if claims is not None and claims.get("request_id") is not None:
                return True
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
            "receipts": store.count_receipts(),
            "approvals": pending_approvals,
            "pending_approvals": pending_approvals,
            "hook_evidence_writer": evidence_writer_stats,
            "sqlite_profile": sqlite_profile,
            "sqlite_migration_gate": sqlite_migration_gate,
            "quarantined_store": quarantined_store_summary(store.guard_home),
            "onefile_extraction": daemon_server.onefile_extraction_status,
            "repair_self_check": daemon_server.repair_self_check_status,
            "uptime_seconds": uptime,
            "pid": self._daemon_server().daemon_pid(),
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
        # Choosing response headers is not the gate that refused the request,
        # so a busy resident here must not turn a real denial into a retry.
        gate_unavailable = self._native_gate_unavailable
        try:
            if origin is None or not self._origin_is_allowed_for_request(parsed.path):
                return None
        finally:
            self._native_gate_unavailable = gate_unavailable
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

    def _write_json(
        self,
        payload: dict[str, Any],
        *,
        status: int = 200,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        # A denial written after an origin or session check could not reach the
        # resident is not a verdict on the caller: the request stays refused, but
        # as the retryable 503 a busy resident gets everywhere else, so the
        # dashboard retries instead of dropping its session.
        if status in (401, 403) and self._native_gate_unavailable:
            payload, status = native_route_unavailable_body(), 503
        body = escape_json_for_html(json.dumps(payload).encode("utf-8"))
        self._write_json_bytes(body, status=status, extra_headers=extra_headers)

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
