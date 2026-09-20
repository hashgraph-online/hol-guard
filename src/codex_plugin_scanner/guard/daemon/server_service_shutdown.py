"""Daemon service shutdown and quarantine."""

from __future__ import annotations

from . import server as _server


def _finish_service(self: _server.GuardDaemonServer) -> bool:
    finish_lock = getattr(self, "_finish_service_lock", None)
    if finish_lock is None:
        with type(self)._quarantine_lock:
            finish_lock = getattr(self, "_finish_service_lock", None)
            if finish_lock is None:
                finish_lock = _server.threading.Lock()
                self._finish_service_lock = finish_lock
    with finish_lock:
        if getattr(self, "_finish_service_completed", False):
            return True
        contained = self._finish_service_locked()
        if contained:
            self._finish_service_completed = True
        return contained


def _finish_service_locked(self: _server.GuardDaemonServer) -> bool:
    self._owned_service_ready = False
    self._shutdown_started.set()
    contained = True
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
        self._command_queue_worker = _server.stop_command_queue_worker(self._command_queue_worker)
        contained = self._command_queue_worker is None and contained
    except Exception:
        contained = False
    try:
        self._cloud_review_sync_worker = _server.stop_cloud_sync_sync_worker(self._cloud_review_sync_worker)
        contained = self._cloud_review_sync_worker is None and contained
    except Exception:
        contained = False
    runtime_heartbeat = getattr(self._server, "runtime_heartbeat", None)
    if runtime_heartbeat is not None:
        try:
            contained = runtime_heartbeat.stop(timeout_seconds=1.0) is not False and contained
        except Exception:
            contained = False
    runtime_hook_evidence_writer = getattr(self._server, "runtime_hook_evidence_writer", None)
    if runtime_hook_evidence_writer is not None:
        try:
            contained = runtime_hook_evidence_writer.stop(timeout_seconds=1.0) is not False and contained
        except Exception:
            contained = False
    hook_process_runner = getattr(self._server, "hook_process_runner", None)
    if hook_process_runner is not None:
        try:
            close_contained = getattr(hook_process_runner, "close_contained", None)
            if callable(close_contained):
                contained = close_contained() is not False and contained
            else:
                contained = hook_process_runner.close() is not False and contained
        except Exception:
            contained = False
    contained = self._join_service_background_threads() and contained
    with _server.suppress(Exception):
        _server.clear_guard_daemon_state_if_current(
            self._server.store.guard_home,
            pid=_server.os.getpid(),
            port=self.port,
        )
    with _server.suppress(Exception):
        self._server.store.clear_runtime_state(session_id=self._server.runtime_session_id)
    if contained and self._is_quarantined():
        try:
            self._server.server_close()
        except Exception:
            contained = False
    if contained:
        try:
            _server.release_guard_daemon_owner_lock(getattr(self, "_owner_lock", None))
        except Exception:
            contained = False
        else:
            self._owner_lock = None
    with _server.suppress(Exception):
        self._diagnostics.close(timeout_seconds=1.0)
    return self._record_quarantine_state(contained=contained)


def _join_service_thread(
    thread: _server.threading.Thread | None,
    *,
    deadline: float,
) -> _server.threading.Thread | None:
    if thread is None:
        return None
    if thread is not _server.threading.current_thread():
        thread.join(timeout=max(0.0, deadline - _server.time.monotonic()))
    return thread if thread.is_alive() else None


def _join_service_background_threads(self: _server.GuardDaemonServer) -> bool:
    deadline = _server.time.monotonic() + _server._AIBOM_REFRESH_STOP_JOIN_TIMEOUT_SECONDS
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
    return all(
        thread is None
        for thread in (
            self._watchdog_thread,
            self._bundle_refresh_thread,
            self._aibom_refresh_thread,
            self._extension_control_refresh_thread,
            self._headless_cloud_sync_thread,
            self._command_activity_maintenance_thread,
        )
    )


def _start_watchdog(self: _server.GuardDaemonServer) -> None:
    if self._watchdog_thread is not None and self._watchdog_thread.is_alive():
        return
    idle_timeout_seconds = self._server.idle_timeout_seconds
    if idle_timeout_seconds is None or idle_timeout_seconds <= 0:
        return
    self._watchdog_thread = _server.threading.Thread(target=self._watch_for_idle_shutdown, daemon=True)
    self._watchdog_thread.start()
