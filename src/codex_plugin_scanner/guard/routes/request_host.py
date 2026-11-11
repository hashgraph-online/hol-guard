"""One daemon request answered by the route handler in a library call.

The native daemon owns the listening socket. A request it does not answer
itself arrives here (``route.request``) as its raw bytes; this module runs
the route handler over them and returns the raw response. The handler keeps
every check it applies (origin, auth, body limits).

State the long-running daemon kept in memory between requests (connect
flows, discovery challenges, reconnect challenges, session nonces, discovery
job status) lives in ``daemon-replay-state.json`` under the Guard home
instead, written atomically with owner-only permissions. Library-call processes
run side by side, so every read-check-write of that state holds an exclusive lock
on ``daemon-replay-state.lock`` and rereads the file first: a nonce or
challenge one process consumes is gone for the next.
"""

from __future__ import annotations

import json
import os
import threading
import time
from collections.abc import Callable
from functools import cached_property
from pathlib import Path
from typing import Any

from ..store import GuardStore
from .request_state import (
    _STATE_LIMIT_BYTES,
    _PersistedMapping,
    _ReplayDiscoveryJobs,
    _ReplayState,
    _SyncedLock,
)

# The largest request the native daemon hands over (head and body).
_REQUEST_LIMIT_BYTES = 1_100_000
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


# Package firewall mutations and their rate limit span requests, and each
# request builds its own server, so both live for the serving process.
_PROCESS_SHARED_LOCK = threading.Lock()
_PROCESS_SHARED: dict[tuple[str, str], Any] = {}


def _process_shared(guard_home: Path, name: str, build: Callable[[], Any]) -> Any:
    key = (str(guard_home), name)
    with _PROCESS_SHARED_LOCK:
        value = _PROCESS_SHARED.get(key)
        if value is None:
            value = _PROCESS_SHARED[key] = build()
        return value


def _republish_trust_status(guard_home: Path) -> Callable[[dict[str, object]], None]:
    """Carries an integrity transition this replay commits into the daemon's state."""

    def republish(trust_status: dict[str, object]) -> None:
        from ..native_daemon_manage import republish_guard_daemon_trust_status

        republish_guard_daemon_trust_status(guard_home, trust_status)

    return republish


def _replay_server_class() -> type:
    from ..daemon.diagnostics import DaemonDiagnostics
    from ..runtime.surface_server import GuardSurfaceRuntime
    from . import request_handler as daemon_server

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
        def network_supervisor(self) -> Any:  # pyright: ignore[reportIncompatibleVariableOverride]
            from ..runtime.network_supervisor import NetworkSupervisor

            return NetworkSupervisor()

        # The extension-control service is the resident's, one per Guard home.
        @property
        def extension_control_api(self) -> Any:  # pyright: ignore[reportIncompatibleVariableOverride]
            from ..extension_control_host import host_for

            return host_for(self.store).api

        @property
        def extension_control_runtime(self) -> Any:  # pyright: ignore[reportIncompatibleVariableOverride]
            from ..extension_control_host import host_for

            return host_for(self.store).runtime

        def refresh_extension_control_runtime(self) -> Any:
            from ..extension_control_host import host_for

            return host_for(self.store).refresh()

        @cached_property
        def local_cli_api(self) -> Any:
            from ..daemon.local_cli_api import LocalCliApiService

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
            from ..daemon.hook_direct_counters import bind_hook_counter_sink
            from ..daemon.hook_evidence_dispatch import HookEvidenceDispatch
            from ..daemon.hook_worker import HookWorker
            from ..native_hook_evidence_writer import NativeHookEvidenceWriter

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

    from ..native_daemon_manage import _state_path

    try:
        with _state_path(guard_home).open("rb") as handle:
            state = json.loads(handle.read(_STATE_LIMIT_BYTES).decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return {}
    if not isinstance(state, dict):
        return {}
    identity = {"session_id": state.get("state_id"), "started_at": state.get("started_at")}
    return {key: value for key, value in identity.items() if isinstance(value, str)}


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


__all__ = ["load_runtime_identity", "wait_for_background_work"]
