"""GuardDaemonServer ownership and method bindings."""

from __future__ import annotations

from typing import ClassVar

from . import server as _server
from . import server_service_lifecycle as _service_lifecycle
from . import server_service_maintenance as _service_maintenance
from . import server_service_refresh as _service_refresh
from . import server_service_shutdown as _service_shutdown
from .server_constants import (
    _DEFAULT_SUPPLY_CHAIN_REFRESH_BACKOFF_SECONDS,
    _DEFAULT_SUPPLY_CHAIN_REFRESH_INTERVAL_SECONDS,
)
from .server_dependencies_base import threading
from .server_dependencies_guard import _AIBOM_AUTO_SYNC_INTERVAL_SECONDS


class GuardDaemonServer:
    """Small local daemon for health, receipts, and approval-center introspection."""

    _quarantine_lock: ClassVar[_server.threading.Lock] = threading.Lock()
    _quarantined_services: ClassVar[dict[str, _server.GuardDaemonServer]] = {}
    _quarantine_key = staticmethod(_service_lifecycle._quarantine_key)
    _retry_quarantined_service = classmethod(_service_lifecycle._retry_quarantined_service)
    _is_quarantined = _service_lifecycle._is_quarantined
    _record_quarantine_state = _service_lifecycle._record_quarantine_state

    def __init__(
        self,
        store: _server.GuardStore,
        host: str = "127.0.0.1",
        port: int = 0,
        *,
        bundle_refresh_backoff_seconds: float = _DEFAULT_SUPPLY_CHAIN_REFRESH_BACKOFF_SECONDS,
        bundle_refresh_interval_seconds: float | None = _DEFAULT_SUPPLY_CHAIN_REFRESH_INTERVAL_SECONDS,
        aibom_refresh_backoff_seconds: float = _DEFAULT_SUPPLY_CHAIN_REFRESH_BACKOFF_SECONDS,
        aibom_refresh_interval_seconds: float | None = float(_AIBOM_AUTO_SYNC_INTERVAL_SECONDS),
        extension_control_refresh_interval_seconds: float = 5.0,
        idle_timeout_seconds: float | None = None,
        home_dir: _server.Path | None = None,
        workspace_dir: _server.Path | None = None,
    ) -> None:
        if not type(self)._retry_quarantined_service(store.guard_home):
            raise RuntimeError("A previous Guard daemon remains quarantined after unconfirmed containment.")
        self._diagnostics = _server.DaemonDiagnostics(store.guard_home)
        try:
            self._isolation_provider_registry = _server.load_managed_provider_registry()
            _server._validate_dashboard_bundle()
        except BaseException:
            self._diagnostics.record_exception("daemon_initialization_failed")
            self._diagnostics.close(timeout_seconds=0.5)
            raise
        self._shutdown_started = _server.threading.Event()
        self._lifecycle_lock = _server.threading.Lock()
        self._lifecycle_generation = 0
        self._active_start_generation: int | None = None
        self._finish_service_lock = _server.threading.Lock()
        self._finish_service_completed = False
        self._owned_service_ready = False
        self._serve_thread_error: BaseException | None = None
        self._owner_lock: _server.BinaryIO | None = None
        try:
            self._server = _server._GuardDaemonHttpServer(
                (host, port),
                _server._GuardDaemonHandler,
                store=store,
                auth_token=_server.load_guard_daemon_auth_token(store.guard_home) or _server.uuid.uuid4().hex,
                runtime_host=host,
                runtime_session_id=_server.uuid.uuid4().hex,
                runtime_started_at=_server._now(),
                home_dir=(home_dir or _server.Path.home()).expanduser().resolve(strict=False),
                idle_timeout_seconds=_server._guard_daemon_idle_timeout_seconds(
                    store.guard_home,
                    idle_timeout_seconds=idle_timeout_seconds,
                ),
                shutdown_started=self._shutdown_started,
                diagnostics=self._diagnostics,
            )
            self._server.command_queue_lifecycle = self
        except BaseException:
            self._diagnostics.record_exception("daemon_initialization_failed")
            self._diagnostics.close(timeout_seconds=0.5)
            raise
        self.port = self._server.daemon_port()
        self._bundle_refresh_backoff_seconds = bundle_refresh_backoff_seconds
        self._bundle_refresh_interval_seconds = bundle_refresh_interval_seconds
        self._aibom_refresh_backoff_seconds = aibom_refresh_backoff_seconds
        self._aibom_refresh_interval_seconds = aibom_refresh_interval_seconds
        self._headless_cloud_sync_backoff_seconds = _server._DEFAULT_HEADLESS_CLOUD_SYNC_BACKOFF_SECONDS
        self._headless_cloud_sync_interval_seconds = _server._DEFAULT_HEADLESS_CLOUD_SYNC_INTERVAL_SECONDS
        self._aibom_home_dir = home_dir.expanduser() if home_dir is not None else None
        self._aibom_workspace_dir = workspace_dir.expanduser() if workspace_dir is not None else None
        self._aibom_context_workspace_id = store.get_cloud_workspace_id() if self._aibom_workspace_dir else None
        self._aibom_refresh_thread: _server.threading.Thread | None = None
        self._bundle_refresh_thread: _server.threading.Thread | None = None
        self._command_queue_worker: _server.CommandQueueWorker | None = None
        self._headless_cloud_sync_thread: _server.threading.Thread | None = None
        self._command_activity_maintenance_thread: _server.threading.Thread | None = None
        self._extension_control_refresh_thread: _server.threading.Thread | None = None
        self._extension_control_refresh_interval_seconds = extension_control_refresh_interval_seconds
        self._cloud_review_sync_worker: _server.CloudReviewSyncWorker | None = None
        self._thread: _server.threading.Thread | None = None
        self._serve_loop_started = _server.threading.Event()
        self._watchdog_thread: _server.threading.Thread | None = None

    start = _service_lifecycle.start
    serve = _service_lifecycle.serve
    stop = _service_lifecycle.stop
    _begin_service = _service_lifecycle._begin_service
    _publish_listen_state = _service_lifecycle._publish_listen_state
    _begin_owned_service = _service_lifecycle._begin_owned_service
    _complete_owned_service_after_listen = _service_lifecycle._complete_owned_service_after_listen
    refresh_command_queue_worker = _service_maintenance.refresh_command_queue_worker
    _reconcile_runtime_artifacts_best_effort = _service_maintenance._reconcile_runtime_artifacts_best_effort
    _maintain_command_activity_best_effort = _service_maintenance._maintain_command_activity_best_effort
    _maintain_storage_best_effort = _service_maintenance._maintain_storage_best_effort
    _start_command_activity_maintenance = _service_maintenance._start_command_activity_maintenance
    _require_command_activity_maintenance_stopped = _service_maintenance._require_command_activity_maintenance_stopped
    _join_command_activity_maintenance = _service_maintenance._join_command_activity_maintenance
    _command_activity_maintenance_loop = _service_maintenance._command_activity_maintenance_loop
    _persist_aibom_inventory_context = _service_maintenance._persist_aibom_inventory_context
    _serve_forever = _service_lifecycle._serve_forever
    _record_lifecycle = _service_lifecycle._record_lifecycle
    _finish_service = _service_shutdown._finish_service
    _finish_service_locked = _service_shutdown._finish_service_locked
    _join_service_thread = staticmethod(_service_shutdown._join_service_thread)
    _join_service_background_threads = _service_shutdown._join_service_background_threads
    _start_watchdog = _service_shutdown._start_watchdog
    _start_headless_cloud_sync = _service_refresh._start_headless_cloud_sync
    _refresh_headless_cloud_sync_loop = _service_refresh._refresh_headless_cloud_sync_loop
    _watch_for_idle_shutdown = _service_refresh._watch_for_idle_shutdown
    _start_supply_chain_bundle_refresh = _service_refresh._start_supply_chain_bundle_refresh
    _refresh_supply_chain_bundle_loop = _service_refresh._refresh_supply_chain_bundle_loop
    _start_extension_control_refresh = _service_refresh._start_extension_control_refresh
    _refresh_extension_control_loop = _service_refresh._refresh_extension_control_loop
    _start_aibom_inventory_refresh = _service_refresh._start_aibom_inventory_refresh
    _aibom_inventory_context_dirs = _service_refresh._aibom_inventory_context_dirs
    _refresh_aibom_inventory_loop = _service_refresh._refresh_aibom_inventory_loop
