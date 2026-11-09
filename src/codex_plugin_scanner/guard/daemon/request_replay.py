"""One daemon request answered in a short-lived CLI process.

The native daemon owns the listening socket. A route it does not answer
itself arrives here as the raw request bytes on standard input; this module
runs the daemon's own handler over them and prints the raw response. The
handler keeps every check it applies today (origin, auth, body limits), so a
route answered this way behaves as it did in the long-running daemon.

State the long-running daemon kept in memory between requests (connect
flows, discovery challenges, reconnect challenges, session nonces) lives in
``daemon-replay-state.json`` under the Guard home instead, written atomically
with owner-only permissions.
"""

from __future__ import annotations

import io
import json
import os
import threading
import time
from contextlib import suppress
from functools import cached_property
from pathlib import Path
from typing import Any

from ..store import GuardStore

_STATE_FILENAME = "daemon-replay-state.json"
_STATE_LIMIT_BYTES = 1024 * 1024
# How long work a handler started after answering (a connect flow waiting on
# the browser) may keep this process alive.
_BACKGROUND_LIMIT_SECONDS = 15 * 60.0
_PERSISTED_FIELDS = (
    "guard_cloud_connect_state",
    "package_firewall_connect_state",
    "daemon_discovery_challenges",
    "dashboard_reconnect_consumed_challenges",
    "package_firewall_session_nonces",
)


class _ReplayState:
    """The cross-request fields, read from and written back to one file."""

    def __init__(self, guard_home: Path) -> None:
        self._path = guard_home / _STATE_FILENAME
        self._lock = threading.Lock()

    def read(self) -> dict[str, Any]:
        try:
            if self._path.is_symlink():
                return {}
            with self._path.open("rb") as handle:
                raw = handle.read(_STATE_LIMIT_BYTES + 1)
        except OSError:
            return {}
        if len(raw) > _STATE_LIMIT_BYTES:
            return {}
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return {}
        return payload if isinstance(payload, dict) else {}

    def get(self, field: str) -> Any:
        with self._lock:
            return self.read().get(field)

    def set(self, field: str, value: Any) -> None:
        with self._lock:
            state = self.read()
            if value is None:
                state.pop(field, None)
            else:
                state[field] = value
            encoded = json.dumps(state, separators=(",", ":"), default=str).encode("utf-8")
            if len(encoded) > _STATE_LIMIT_BYTES:
                return
            temporary = self._path.with_name(f".{_STATE_FILENAME}.{os.getpid()}.{threading.get_ident()}")
            try:
                descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(descriptor, "wb") as handle:
                    handle.write(encoded)
                os.replace(temporary, self._path)
            except OSError:
                with suppress(OSError):
                    temporary.unlink()


class _PersistedMapping(dict[str, Any]):
    """A dict whose every change is written back to the replay state."""

    def __init__(self, state: _ReplayState, field: str) -> None:
        stored = state.get(field)
        super().__init__(stored if isinstance(stored, dict) else {})
        self._state = state
        self._field = field

    def _save(self) -> None:
        self._state.set(self._field, dict(self))

    def __setitem__(self, key: Any, value: Any) -> None:
        super().__setitem__(key, value)
        self._save()

    def __delitem__(self, key: Any) -> None:
        super().__delitem__(key)
        self._save()

    def pop(self, key: Any, *default: Any) -> Any:
        value = super().pop(key, *default)
        self._save()
        return value

    def clear(self) -> None:
        super().clear()
        self._save()

    def update(self, *args: Any, **kwargs: Any) -> None:
        super().update(*args, **kwargs)
        self._save()


class _ReplaySocket:
    """The connection the handler sees: the request bytes in, the answer out."""

    def __init__(self, request: bytes, response: io.BytesIO) -> None:
        self._request = request
        self._response = response

    def makefile(self, mode: str, *args: object, **kwargs: object) -> io.BufferedIOBase:
        del args, kwargs
        if "r" in mode:
            return io.BufferedReader(io.BytesIO(self._request))  # type: ignore[arg-type]
        return _Unclosable(self._response)

    def sendall(self, data: bytes) -> None:
        self._response.write(data)

    def settimeout(self, timeout: float | None) -> None:
        del timeout

    def setsockopt(self, *args: object) -> None:
        del args

    def getpeername(self) -> tuple[str, int]:
        return ("127.0.0.1", 0)

    def shutdown(self, how: int) -> None:
        del how

    def close(self) -> None:
        return None


class _Unclosable(io.BufferedIOBase):
    def __init__(self, target: io.BytesIO) -> None:
        self._target = target

    def writable(self) -> bool:
        return True

    def write(self, data: Any) -> int:
        return self._target.write(bytes(data))

    def flush(self) -> None:
        return None


def _replay_server_class() -> type:
    from ..runtime.surface_server import GuardSurfaceRuntime
    from . import server as daemon_server
    from .diagnostics import DaemonDiagnostics

    base = daemon_server._GuardDaemonHTTPServer

    class ReplayServer(base):  # type: ignore[misc, valid-type]
        def __init__(  # pyright: ignore[reportMissingSuperCall]
            self, store: GuardStore, port: int, host: str, home_dir: Path, auth_key: str
        ) -> None:
            # The listening socket, executors and workers belong to the native
            # daemon; only the fields handlers read are set here.
            self._replay_state = _ReplayState(store.guard_home)
            self.store = store
            self.runtime = GuardSurfaceRuntime(store)
            self.native_edge = None
            self.server_address = (host, port)
            self._socket_bound = True
            self.request_executors_stopped = True
            self.auth_token = auth_key
            self.runtime_host = host
            state = load_runtime_identity(store.guard_home)
            self.runtime_session_id = state.get("session_id") or ""
            self.runtime_started_at = state.get("started_at") or ""
            self.home_dir = home_dir.resolve(strict=False)
            self.workspace_dir = None
            self.idle_timeout_seconds = None
            self.last_activity_monotonic = time.monotonic()
            self.idle_shutdown_claimed = False
            self.start_monotonic = time.monotonic()
            self.active_stream_clients = 0
            self.active_stream_clients_lock = threading.Lock()
            self.shutdown_started = threading.Event()
            self.diagnostics = DaemonDiagnostics(store.guard_home, start_worker=False, rotate=False)
            self.auth_audit_lock, self.denial_audit_lock = threading.Lock(), threading.Lock()
            self.auth_audit_windows = {}
            self.audit_persistence = daemon_server.AuditPersistence(
                store,
                self.diagnostics,
                attempt_timeout_seconds=daemon_server._AUTH_AUDIT_SQLITE_TIMEOUT_SECONDS,
            )
            self.command_queue_lifecycle = None
            self.package_firewall_connect_state_lock = threading.Lock()
            self.onefile_extraction_status = None
            self.repair_self_check_status = None
            self.guard_cloud_connect_state_lock = threading.Lock()
            self.guard_cloud_browser_session_lock = threading.Lock()
            self.package_firewall_mutation_lock = threading.Lock()
            self.package_firewall_session_nonces = _PersistedMapping(
                self._replay_state, "package_firewall_session_nonces"
            )
            self.package_firewall_session_nonces_lock = threading.Lock()
            self.daemon_discovery_challenges = _PersistedMapping(self._replay_state, "daemon_discovery_challenges")
            self.daemon_discovery_challenges_lock = threading.Lock()
            self.dashboard_reconnect_lock = threading.Lock()
            self.dashboard_reconnect_consumed_challenges = _PersistedMapping(
                self._replay_state, "dashboard_reconnect_consumed_challenges"
            )
            self.containment_health_cache = None
            self.containment_health_cache_monotonic = 0.0
            self.containment_health_cache_lock = threading.Lock()
            self.containment_health_refreshing = False
            self.containment_health_refresh_event = threading.Event()
            self.containment_health_generation = 0
            self.containment_health_completed_generation = 0
            self.active_hook_requests = 0
            self.rejected_hook_requests = 0
            self.hook_harness_active = {}
            self.hook_harness_rejected = {}
            self.hook_capacity_lock = threading.Lock()
            self.request_capacity_limit = daemon_server._MAX_CONCURRENT_DAEMON_REQUESTS
            self.request_capacity = threading.BoundedSemaphore(self.request_capacity_limit)
            self.connection_capacity_limit = daemon_server._MAX_CONCURRENT_DAEMON_CONNECTIONS
            self.connection_capacity = threading.BoundedSemaphore(self.connection_capacity_limit)
            self.control_request_capacity_limit = daemon_server._MAX_CONCURRENT_DAEMON_CONTROL_REQUESTS
            self.control_request_capacity = threading.BoundedSemaphore(self.control_request_capacity_limit)
            self.critical_request_capacity_limit = daemon_server._MAX_CONCURRENT_DAEMON_CRITICAL_REQUESTS
            self.critical_request_capacity = threading.BoundedSemaphore(self.critical_request_capacity_limit)
            self._guard_capacity_limit = self.request_capacity_limit
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
            self.unclassified_watchdog_thread = None

        @property
        def guard_cloud_connect_state(self) -> dict[str, object] | None:  # pyright: ignore[reportIncompatibleVariableOverride]
            value = self._replay_state.get("guard_cloud_connect_state")
            return value if isinstance(value, dict) else None

        @guard_cloud_connect_state.setter
        def guard_cloud_connect_state(self, value: dict[str, object] | None) -> None:  # pyright: ignore[reportIncompatibleVariableOverride]
            self._replay_state.set("guard_cloud_connect_state", value)

        @property
        def package_firewall_connect_state(self) -> dict[str, object] | None:  # pyright: ignore[reportIncompatibleVariableOverride]
            value = self._replay_state.get("package_firewall_connect_state")
            return value if isinstance(value, dict) else None

        @package_firewall_connect_state.setter
        def package_firewall_connect_state(self, value: dict[str, object] | None) -> None:  # pyright: ignore[reportIncompatibleVariableOverride]
            self._replay_state.set("package_firewall_connect_state", value)

        @cached_property
        def package_firewall_action_rate_limiter(self) -> Any:  # pyright: ignore[reportIncompatibleVariableOverride]
            from ..package_firewall_action_rate_limit import PackageFirewallActionRateLimiter

            return PackageFirewallActionRateLimiter()

        @cached_property
        def network_supervisor(self) -> Any:  # pyright: ignore[reportIncompatibleVariableOverride]
            from ..runtime.network_supervisor import NetworkSupervisor

            return NetworkSupervisor()

        @cached_property
        def runtime_hook_scheduler(self) -> Any:  # pyright: ignore[reportIncompatibleVariableOverride]
            from .runtime_hook_scheduler import RuntimeHookScheduler

            return RuntimeHookScheduler(
                active_limit=daemon_server._MAX_CONCURRENT_RUNTIME_HOOKS,
                per_harness_active_limit=daemon_server._MAX_CONCURRENT_RUNTIME_HOOKS_PER_HARNESS,
            )

        @cached_property
        def runtime_heartbeat(self) -> Any:  # pyright: ignore[reportIncompatibleVariableOverride]
            from .runtime_heartbeat import RuntimeHeartbeatWriter

            return RuntimeHeartbeatWriter(
                store=self.store,
                session_id=self.runtime_session_id,
                write_timeout_seconds=0.05,
                retry_interval_seconds=0.05,
            )

        @cached_property
        def extension_control_api(self) -> Any:
            from ..catalog_delivery.projection import capture
            from ..runtime.extension_control_runtime import ExtensionControlRuntime
            from .extension_control_api import ExtensionControlApiService

            try:
                self._migrate_installed_authority()
                self._enroll_authority_by_default()
                _, registry, _ = capture(self.store)
                view = self._startup_extension_control_view(registry)
            except (daemon_server._InstalledAuthorityMigrationError, daemon_server.NativePolicySnapshotError):
                registry = daemon_server.BUILT_IN_COMMAND_EXTENSION_REGISTRY
                view = self.store._tampered_view(registry.catalog_digest)
                self._extension_control_on_core_registry = True
            self.__dict__["extension_control_runtime"] = ExtensionControlRuntime(view)
            return ExtensionControlApiService(
                store=self.store,
                registry=registry,
                runtime=self.__dict__["extension_control_runtime"],
            )

        @cached_property
        def extension_control_runtime(self) -> Any:
            _ = self.extension_control_api
            return self.__dict__["extension_control_runtime"]

        @cached_property
        def local_cli_api(self) -> Any:
            from .local_cli_api import LocalCliApiService

            return LocalCliApiService(store=self.store, record_exception=self.diagnostics.record_exception)

        @cached_property
        def approval_attention(self) -> Any:  # pyright: ignore[reportIncompatibleVariableOverride]
            from ..browser_opener import open_browser_url
            from ..runtime.approval_attention import ApprovalAttentionCoordinator

            return ApprovalAttentionCoordinator(
                store=self.store,
                runtime=self.runtime,
                opener=open_browser_url,
                home_dir=self.home_dir,
            )

        @cached_property
        def hook_worker(self) -> Any:
            from ..native_hook_evidence_writer import NativeHookEvidenceWriter
            from .hook_direct_counters import bind_hook_counter_sink
            from .hook_evidence_dispatch import HookEvidenceDispatch
            from .hook_worker import HookWorker

            self.runtime_hook_evidence_writer = NativeHookEvidenceWriter(store=self.store)
            self.runtime_hook_evidence_dispatch = HookEvidenceDispatch()
            worker = HookWorker(
                store=self.store,
                workspace=self.workspace_dir,
                home_dir=self.home_dir,
                activity_writer=self.runtime_hook_evidence_writer,
                evidence_dispatch=self.runtime_hook_evidence_dispatch,
                capture_writer=None,
            )
            bind_hook_counter_sink(worker, self.diagnostics)
            return worker

        def classify_connection(self, request: Any) -> None:
            del request

        def claim_request_capacity(self, request: Any, path: str) -> bool:
            del request, path
            return True

        def _release_request_capacity(self, request: Any) -> None:
            del request

        def request_deadline(self, request: Any, timeout_seconds: float) -> float:
            del request
            return time.monotonic() + timeout_seconds

        def publish_trust_state(self, trust_status: dict[str, object] | None = None) -> None:
            del trust_status

        def server_close(self) -> None:
            self.diagnostics.close(timeout_seconds=0.5)

    return ReplayServer


def load_runtime_identity(guard_home: Path) -> dict[str, str]:
    """The state id and start time the native daemon published, if any."""

    from .manager import _state_path

    try:
        with _state_path(guard_home).open("rb") as handle:
            state = json.loads(handle.read(_STATE_LIMIT_BYTES).decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return {}
    if not isinstance(state, dict):
        return {}
    identity = {"session_id": state.get("state_id"), "started_at": state.get("started_at")}
    return {key: value for key, value in identity.items() if isinstance(value, str)}


def replay_request(
    guard_home: Path,
    request: bytes,
    *,
    port: int,
    host: str = "127.0.0.1",
    home_dir: Path | None = None,
) -> bytes:
    """The raw response the daemon's handler writes for ``request``."""

    from .auth_token import load_guard_daemon_auth_token
    from .server import _GuardDaemonHandler

    auth_key = load_guard_daemon_auth_token(guard_home) or ""
    store = GuardStore(guard_home)
    server = _replay_server_class()(store, port, host, home_dir or Path.home(), auth_key)
    response = io.BytesIO()
    try:
        _GuardDaemonHandler(_ReplaySocket(request, response), ("127.0.0.1", 0), server)  # pyright: ignore[reportArgumentType]
    finally:
        server.server_close()
    return response.getvalue()


def wait_for_background_work() -> None:
    """Let work a handler started after answering finish, within a bound."""

    deadline = time.monotonic() + _BACKGROUND_LIMIT_SECONDS
    current = threading.current_thread()
    for thread in threading.enumerate():
        if thread is current or thread.daemon or not thread.is_alive():
            continue
        thread.join(max(0.0, deadline - time.monotonic()))


__all__ = ["replay_request", "wait_for_background_work"]
