"""One daemon request answered in a short-lived CLI process.

The native daemon owns the listening socket. A route it does not answer
itself arrives here as the raw request bytes on standard input; this module
runs the daemon's own handler over them and prints the raw response. The
handler keeps every check it applies today (origin, auth, body limits), so a
route answered this way behaves as it did in the long-running daemon.

State the long-running daemon kept in memory between requests (connect
flows, discovery challenges, reconnect challenges, session nonces, discovery
job status) lives in ``daemon-replay-state.json`` under the Guard home
instead, written atomically with owner-only permissions. Replay processes run
side by side, so every read-check-write of that state holds an exclusive lock
on ``daemon-replay-state.lock`` and rereads the file first: a nonce or
challenge one process consumes is gone for the next.
"""

from __future__ import annotations

import io
import json
import os
import threading
import time
from collections.abc import Callable
from functools import cached_property
from pathlib import Path
from typing import Any

from ..store import GuardStore
from .request_replay_state import (
    _STATE_LIMIT_BYTES,
    _PersistedMapping,
    _ReplayDiscoveryJobs,
    _ReplayState,
    _SyncedLock,
)

# How long work a handler started after answering (a connect flow waiting on
# the browser) may keep this process alive.
_BACKGROUND_LIMIT_SECONDS = 15 * 60.0
# Threads a handler starts that finish its work after the answer is written.
# They are daemon threads in the long-running daemon, where the process
# outlives them; here the process waits for them.
_BACKGROUND_THREAD_NAMES = frozenset(
    {
        "guard-cloud-connect",
        "guard-package-firewall-connect",
        "guard-headless-app-cloud-sync",
        "hol-guard-mcp-discovery",
    }
)


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


def _republish_trust_status(guard_home: Path) -> Callable[[dict[str, object]], None]:
    """Carries an integrity transition this replay commits into the daemon's state."""

    def republish(trust_status: dict[str, object]) -> None:
        from .manager import republish_guard_daemon_trust_status

        republish_guard_daemon_trust_status(guard_home, trust_status)

    return republish


def _replay_server_class() -> type:
    from ..runtime.surface_server import GuardSurfaceRuntime
    from . import server as daemon_server
    from .diagnostics import DaemonDiagnostics

    base = daemon_server._GuardDaemonHTTPServer

    class ReplayServer(base):  # type: ignore[misc, valid-type]
        def __init__(  # pyright: ignore[reportMissingSuperCall]
            self,
            store: GuardStore,
            port: int,
            host: str,
            home_dir: Path,
            auth_key: str,
            daemon_pid: int | None = None,
            daemon_proof_verified: bool = False,
        ) -> None:
            # The listening socket, executors and workers belong to the native
            # daemon; only the fields handlers read are set here.
            self._replay_state = state_file = _ReplayState(store.guard_home)
            self._replay_daemon_pid = daemon_pid
            self.daemon_proof_verified = daemon_proof_verified
            self.store = store
            store.set_policy_integrity_state_listener(_republish_trust_status(store.guard_home))
            self.runtime = GuardSurfaceRuntime(store)
            self.server_address = (host, port)
            self._socket_bound = True
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
            from ..workers.host import DurableWorkerRefresh

            self.command_queue_lifecycle = DurableWorkerRefresh(store)
            self.package_firewall_connect_state_lock = _SyncedLock(state_file)  # pyright: ignore[reportAttributeAccessIssue]
            self.onefile_extraction_status = None
            from ..workers.host import REPAIR_SELF_CHECK_KEY

            repair_status = store.get_sync_payload(REPAIR_SELF_CHECK_KEY)
            self.repair_self_check_status = repair_status if isinstance(repair_status, dict) else None
            self.guard_cloud_connect_state_lock = _SyncedLock(state_file)  # pyright: ignore[reportAttributeAccessIssue]
            self.guard_cloud_browser_session_lock = _SyncedLock(state_file)  # pyright: ignore[reportAttributeAccessIssue]
            self.package_firewall_mutation_lock = threading.Lock()
            self.package_firewall_session_nonces = _PersistedMapping(
                self._replay_state, "package_firewall_session_nonces"
            )
            self.package_firewall_session_nonces_lock = _SyncedLock(state_file, self.package_firewall_session_nonces)  # pyright: ignore[reportAttributeAccessIssue]
            self.daemon_discovery_challenges = _PersistedMapping(self._replay_state, "daemon_discovery_challenges")
            self.daemon_discovery_challenges_lock = _SyncedLock(state_file, self.daemon_discovery_challenges)  # pyright: ignore[reportAttributeAccessIssue]
            self.dashboard_reconnect_consumed_challenges = _PersistedMapping(
                self._replay_state, "dashboard_reconnect_consumed_challenges"
            )
            self.dashboard_reconnect_lock = _SyncedLock(state_file, self.dashboard_reconnect_consumed_challenges)  # pyright: ignore[reportAttributeAccessIssue]
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

        def daemon_pid(self) -> int:
            # The edge names the daemon it serves; this process is short-lived.
            return self._replay_daemon_pid or os.getpid()

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

            service = LocalCliApiService(store=self.store, record_exception=self.diagnostics.record_exception)
            service._discovery_jobs = _ReplayDiscoveryJobs(self._replay_state)
            return service

        @cached_property
        def approval_attention(self) -> Any:  # pyright: ignore[reportIncompatibleVariableOverride]
            from ..workers.host import DurableApprovalAttention

            # This process ends with its request; the daemon's worker host
            # opens the browser when the operation still waits.
            return DurableApprovalAttention(self.store)

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
            _republish_trust_status(self.store.guard_home)(
                trust_status or self.store.get_cached_policy_integrity_state()
            )

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
    daemon_pid: int | None = None,
    proof_verified: bool = False,
) -> bytes:
    """The raw response the daemon's handler writes for ``request``.

    ``proof_verified`` is the native daemon's word that this hook presented
    the identity proof it issued on the same connection.
    """

    from .auth_token import load_guard_daemon_auth_token
    from .server import _GuardDaemonHandler

    auth_key = load_guard_daemon_auth_token(guard_home) or ""
    store = GuardStore(guard_home)
    server = _replay_server_class()(store, port, host, home_dir or Path.home(), auth_key, daemon_pid, proof_verified)
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
        if thread is current or not thread.is_alive():
            continue
        if thread.daemon and thread.name not in _BACKGROUND_THREAD_NAMES:
            continue
        thread.join(max(0.0, deadline - time.monotonic()))


__all__ = ["replay_request", "wait_for_background_work"]
