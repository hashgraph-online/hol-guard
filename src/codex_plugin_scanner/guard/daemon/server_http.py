"""_GuardDaemonHTTPServer ownership and method bindings."""

from __future__ import annotations

from . import server as _server
from . import server_http_requests as _http_requests
from .server_constants import _MAX_CONCURRENT_DAEMON_CONNECTIONS
from .server_dependencies_runtime import BoundedThreadingHTTPServer


class _GuardDaemonHTTPServer(BoundedThreadingHTTPServer):
    request_queue_size = _MAX_CONCURRENT_DAEMON_CONNECTIONS
    store: _server.GuardStore
    runtime: _server.GuardSurfaceRuntime
    auth_token: str
    runtime_host: str
    runtime_session_id: str
    runtime_started_at: str
    idle_timeout_seconds: float | None
    last_activity_monotonic: float
    start_monotonic: float
    active_stream_clients: int
    active_stream_clients_lock: _server.threading.Lock
    shutdown_started: _server.threading.Event
    package_firewall_connect_state: dict[str, object] | None
    package_firewall_connect_state_lock: _server.threading.Lock
    guard_cloud_connect_state: dict[str, object] | None
    guard_cloud_connect_state_lock: _server.threading.Lock
    guard_cloud_browser_session_lock: _server.threading.Lock
    package_firewall_action_rate_limiter: _server.PackageFirewallActionRateLimiter
    package_firewall_session_nonces: dict[str, float]
    package_firewall_session_nonces_lock: _server.threading.Lock
    approval_attention: _server.ApprovalAttentionCoordinator
    daemon_discovery_challenges: dict[str, dict[str, object]]
    daemon_discovery_challenges_lock: _server.threading.Lock
    dashboard_reconnect_lock: _server.threading.Lock
    dashboard_reconnect_consumed_challenges: dict[str, int]
    containment_health_cache: dict[str, object] | None
    containment_health_cache_monotonic: float
    containment_health_cache_lock: _server.threading.Lock
    network_supervisor: _server.NetworkSupervisor
    active_hook_requests: int
    rejected_hook_requests: int
    hook_harness_active: dict[str, int]
    hook_harness_rejected: dict[str, int]
    hook_capacity_lock: _server.threading.Lock
    runtime_hook_scheduler: _server.RuntimeHookScheduler
    runtime_hook_process_scheduler: _server.RuntimeHookScheduler
    runtime_hook_evidence_writer: _server.RuntimeHookEvidenceWriter
    request_capacity: _server.threading.BoundedSemaphore
    request_capacity_limit: int
    connection_capacity: _server.threading.BoundedSemaphore
    connection_capacity_limit: int
    control_request_capacity: _server.threading.BoundedSemaphore
    control_request_capacity_limit: int
    critical_request_capacity: _server.threading.BoundedSemaphore
    critical_request_capacity_limit: int
    active_requests: int
    rejected_requests: int
    request_capacity_kinds: dict[int, str]
    request_accepted_at: dict[int, float]
    active_connections: dict[int, _server.socket.socket]
    request_capacity_lock: _server.threading.Lock
    unclassified_connections: dict[int, tuple[_server.socket.socket, float]]
    unclassified_connections_lock: _server.threading.Lock
    unclassified_watchdog_stop: _server.threading.Event
    unclassified_watchdog_thread: _server.threading.Thread | None
    hook_process_runner: _server.HookProcessRunner
    runtime_heartbeat: _server.RuntimeHeartbeatWriter
    general_request_executor: _server._BoundedRequestExecutor
    control_request_executor: _server._BoundedRequestExecutor
    request_executors_stopped: bool
    diagnostics: _server.DaemonDiagnostics
    auth_audit_lock: _server.threading.Lock
    denial_audit_lock: _server.threading.Lock
    auth_audit_windows: dict[_server._AuthAuditKey, _server._AuthAuditWindow]
    command_queue_lifecycle: _server.GuardDaemonServer | None
    home_dir: _server.Path
    handle_error = _http_requests.handle_error

    def server_close(self) -> None:
        _ = self._stop_request_executors()
        hook_worker = getattr(self, "hook_worker", None)
        if hook_worker is not None:
            with _server.suppress(Exception):
                hook_worker.close()
        writer = getattr(self, "runtime_hook_evidence_writer", None)
        if writer is not None:
            _ = writer.stop(timeout_seconds=1.0)
        super().server_close()

    def __init__(
        self,
        server_address: tuple[str, int],
        handler_class: type[_server.BaseHTTPRequestHandler],
        *,
        store: _server.GuardStore,
        auth_token: str,
        runtime_host: str,
        runtime_session_id: str,
        runtime_started_at: str,
        home_dir: _server.Path,
        idle_timeout_seconds: float | None,
        shutdown_started: _server.threading.Event,
        diagnostics: _server.DaemonDiagnostics,
    ) -> None:
        # TCPServer calls server_close() when bind/activation fails. Treat the
        # request executors as already stopped until their construction finishes.
        self.request_executors_stopped = True
        self.store = store
        self.runtime = _server.GuardSurfaceRuntime(store)
        self.auth_token = auth_token
        self.runtime_host = runtime_host
        self.runtime_session_id = runtime_session_id
        self.runtime_started_at = runtime_started_at
        self.home_dir = home_dir.resolve(strict=False)
        self.idle_timeout_seconds = idle_timeout_seconds
        self.last_activity_monotonic = _server.time.monotonic()
        self.start_monotonic = _server.time.monotonic()
        self.active_stream_clients = 0
        self.active_stream_clients_lock = _server.threading.Lock()
        self.shutdown_started = shutdown_started
        self.diagnostics = diagnostics
        self.auth_audit_lock, self.denial_audit_lock = _server.threading.Lock(), _server.threading.Lock()
        self.auth_audit_windows = {}
        self.command_queue_lifecycle = None
        self.package_firewall_connect_state = None
        self.package_firewall_connect_state_lock = _server.threading.Lock()
        self.guard_cloud_connect_state = None
        self.guard_cloud_connect_state_lock = _server.threading.Lock()
        self.guard_cloud_browser_session_lock = _server.threading.Lock()
        self.package_firewall_action_rate_limiter = _server.PackageFirewallActionRateLimiter()
        self.package_firewall_session_nonces = {}
        self.package_firewall_session_nonces_lock = _server.threading.Lock()
        self.daemon_discovery_challenges = {}
        self.daemon_discovery_challenges_lock = _server.threading.Lock()
        self.dashboard_reconnect_lock = _server.threading.Lock()
        self.dashboard_reconnect_consumed_challenges = {}
        self.containment_health_cache = None
        self.containment_health_cache_monotonic = 0.0
        self.containment_health_cache_lock = _server.threading.Lock()
        self.network_supervisor = _server.NetworkSupervisor()
        self.active_hook_requests = 0
        self.rejected_hook_requests = 0
        self.hook_harness_active = {}
        self.hook_harness_rejected = {}
        self.hook_capacity_lock = _server.threading.Lock()
        self.runtime_hook_scheduler = _server.RuntimeHookScheduler(
            active_limit=_server._MAX_CONCURRENT_RUNTIME_HOOKS,
            per_harness_active_limit=_server._MAX_CONCURRENT_RUNTIME_HOOKS_PER_HARNESS,
        )
        self.runtime_hook_process_scheduler = _server.RuntimeHookScheduler(
            active_limit=0,
            per_harness_active_limit=_server._MAX_CONCURRENT_RUNTIME_HOOKS_PER_HARNESS,
            retained_bytes_limit=1,
        )
        self.request_capacity_limit = _server._MAX_CONCURRENT_DAEMON_REQUESTS
        self.request_capacity = _server.threading.BoundedSemaphore(self.request_capacity_limit)
        self.connection_capacity_limit = _server._MAX_CONCURRENT_DAEMON_CONNECTIONS
        self.connection_capacity = _server.threading.BoundedSemaphore(self.connection_capacity_limit)
        self.control_request_capacity_limit = _server._MAX_CONCURRENT_DAEMON_CONTROL_REQUESTS
        self.control_request_capacity = _server.threading.BoundedSemaphore(self.control_request_capacity_limit)
        self.critical_request_capacity_limit = _server._MAX_CONCURRENT_DAEMON_CRITICAL_REQUESTS
        self.critical_request_capacity = _server.threading.BoundedSemaphore(self.critical_request_capacity_limit)
        self.active_requests = 0
        self.rejected_requests = 0
        self.request_capacity_kinds = {}
        self.request_accepted_at = {}
        self.active_connections = {}
        self.request_capacity_lock = _server.threading.Lock()
        self.unclassified_connections = {}
        self.unclassified_connections_lock = _server.threading.Lock()
        self.unclassified_watchdog_stop = _server.threading.Event()
        self.unclassified_watchdog_thread = None
        from .config_read_scope import HookConfigReadScope

        self.hook_config_scope = HookConfigReadScope.for_guard_home(store.guard_home)
        self.hook_config_reader = self.hook_config_scope.read_toml
        self.hook_process_runner = _server.HookProcessRunner(guard_home=self.hook_config_scope.canonical_home)
        self.hook_process_runner.set_capacity_listener(self.runtime_hook_process_scheduler.set_active_limit)
        self.runtime_hook_process_scheduler.set_queue_listener(self.hook_process_runner.notify_queued_work)
        self.runtime_heartbeat = _server.RuntimeHeartbeatWriter(
            store=store,
            session_id=runtime_session_id,
            write_timeout_seconds=0.05,
            retry_interval_seconds=0.05,
        )
        self.store.set_policy_integrity_state_listener(self.publish_trust_state)
        self.runtime_hook_evidence_writer = _server.RuntimeHookEvidenceWriter(store=store)
        self._initialize_request_services()
        self.request_executors_stopped = False
        super().__init__(server_address, handler_class)

    def _initialize_request_services(self) -> None:
        from .hook_worker import HookWorker

        try:
            self.hook_worker = HookWorker(
                store=self.store,
                activity_writer=self.runtime_hook_evidence_writer,
                config_reader=self.hook_config_reader,
                config_capture=self.hook_config_scope,
            )
            self.extension_control_runtime = _server.ExtensionControlRuntime(
                self.store.read_extension_control_authority_for_registry(_server.BUILT_IN_COMMAND_EXTENSION_REGISTRY)
            )
            self.extension_control_api = _server.ExtensionControlApiService(
                store=self.store,
                registry=_server.BUILT_IN_COMMAND_EXTENSION_REGISTRY,
                runtime=self.extension_control_runtime,
            )
            self.local_cli_api = _server.LocalCliApiService(store=self.store)
            self.approval_attention = _server.ApprovalAttentionCoordinator(
                store=self.store,
                runtime=self.runtime,
                opener=_server.open_browser_url,
                config_reader=self.hook_config_reader,
            )
            self.general_request_executor = _server._BoundedRequestExecutor(
                name="general",
                workers=_server._MAX_CONCURRENT_DAEMON_REQUESTS,
                queue_limit=_server._MAX_CONCURRENT_DAEMON_CONNECTIONS,
                run=self._process_request_worker,
                discard=self._discard_request,
            )
            self.control_request_executor = _server._BoundedRequestExecutor(
                name="control",
                workers=_server._MAX_CONCURRENT_DAEMON_CONTROL_REQUESTS,
                queue_limit=_server._MAX_CONCURRENT_DAEMON_CONNECTIONS,
                run=self._process_request_worker,
                discard=self._discard_request,
            )
        except BaseException:
            for executor_name in ("control_request_executor", "general_request_executor"):
                executor = getattr(self, executor_name, None)
                if executor is not None:
                    _ = executor.shutdown(timeout_seconds=1.0)
            _ = self.runtime_hook_evidence_writer.stop(timeout_seconds=1.0)
            _ = self.hook_process_runner.close_contained()
            raise

    refresh_extension_control_runtime = _http_requests.refresh_extension_control_runtime
    process_request = _http_requests.process_request
    _process_request_worker = _http_requests._process_request_worker
    _discard_request = _http_requests._discard_request
    _release_request_capacity = _http_requests._release_request_capacity
    _register_unclassified_connection = _http_requests._register_unclassified_connection
    request_deadline = _http_requests.request_deadline
    _transport_request_is_control = staticmethod(_http_requests._transport_request_is_control)
    _stop_request_executors = _http_requests._stop_request_executors
    classify_connection = _http_requests.classify_connection
    _evict_oldest_unclassified_connection = _http_requests._evict_oldest_unclassified_connection
    _close_unclassified_socket = staticmethod(_http_requests._close_unclassified_socket)
    start_unclassified_watchdog = _http_requests.start_unclassified_watchdog
    stop_unclassified_watchdog = _http_requests.stop_unclassified_watchdog
    _watch_unclassified_connections = _http_requests._watch_unclassified_connections
    _buffered_request_headers_complete = staticmethod(_http_requests._buffered_request_headers_complete)
    claim_request_capacity = _http_requests.claim_request_capacity
    _request_capacity_for_kind = _http_requests._request_capacity_for_kind
    _request_capacity_kind = staticmethod(_http_requests._request_capacity_kind)
    canonical_hook_capacity_harness = staticmethod(_http_requests.canonical_hook_capacity_harness)
    daemon_host = _http_requests.daemon_host
    daemon_port = _http_requests.daemon_port
    publish_trust_state = _http_requests.publish_trust_state
