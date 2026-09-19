"""Daemon service startup and ownership."""

from __future__ import annotations

from . import server as _server


def _quarantine_key(guard_home: _server.Path) -> str:
    try:
        return str(guard_home.resolve())
    except OSError:
        return str(guard_home)


def _retry_quarantined_service(cls: type[_server.GuardDaemonServer], guard_home: _server.Path) -> bool:
    key = cls._quarantine_key(guard_home)
    with cls._quarantine_lock:
        service = cls._quarantined_services.get(key)
    if service is None:
        return True
    return service._finish_service()


def _is_quarantined(self: _server.GuardDaemonServer) -> bool:
    key = self._quarantine_key(self._server.store.guard_home)
    with type(self)._quarantine_lock:
        return type(self)._quarantined_services.get(key) is self


def _record_quarantine_state(self: _server.GuardDaemonServer, *, contained: bool) -> bool:
    key = self._quarantine_key(self._server.store.guard_home)
    with type(self)._quarantine_lock:
        current = type(self)._quarantined_services.get(key)
        if contained:
            if current is self:
                _ = type(self)._quarantined_services.pop(key, None)
        else:
            type(self)._quarantined_services[key] = self
    return contained


def start(self: _server.GuardDaemonServer) -> None:
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
        _server.start_serve_thread(self)
        serve_thread_started = True
        if not self._serve_loop_started.wait(timeout=_server._DAEMON_SERVE_THREAD_START_TIMEOUT_SECONDS):
            raise RuntimeError("Guard daemon serve thread did not become ready")
        _server.enable_full_capacity_for_generation(self, generation)
    except BaseException as error:
        _server.contain_failed_service_start(
            self,
            error,
            serve_thread_started=serve_thread_started,
        )
        raise


def serve(self: _server.GuardDaemonServer) -> None:
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
        _server.enable_full_capacity_for_generation(self, generation)
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
        _server.contain_failed_service_start(
            self,
            error,
            serve_thread_started=serve_thread is not None,
        )
        raise
    except BaseException as error:
        _server.contain_failed_service_start(
            self,
            error,
            serve_thread_started=serve_thread is not None,
        )
        raise


def stop(self: _server.GuardDaemonServer) -> None:
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
        self._join_service_thread(serve_thread, deadline=_server.time.monotonic() + 5) is None
        and self._thread is serve_thread
    ):
        self._thread = None


def _begin_service(self: _server.GuardDaemonServer, *, publish_before_workers: bool = False) -> None:
    _server.begin_service(self, publish_before_workers=publish_before_workers)


def _publish_listen_state(self: _server.GuardDaemonServer) -> None:
    self._server.last_activity_monotonic = _server.time.monotonic()
    self._server.publish_trust_state()
    self._server.store.upsert_runtime_state(
        session_id=self._server.runtime_session_id,
        daemon_host=self._server.runtime_host,
        daemon_port=self.port,
        started_at=self._server.runtime_started_at,
        last_heartbeat_at=_server._now(),
    )


def _begin_owned_service(
    self: _server.GuardDaemonServer,
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
    self._server.hook_process_runner.start(defer_backfill=publish_before_workers)
    if publish_before_workers:
        # Desktop `desktop bootstrap --json` waits for the daemon state
        # file, not for hook workers or artifact reconciliation. Accept
        # HTTP and publish that file before the 60s+ cold-home work.
        _server.start_serve_thread(self, already_locked=True)
        if not self._serve_loop_started.wait(timeout=_server._DAEMON_SERVE_THREAD_START_TIMEOUT_SECONDS):
            raise RuntimeError("Guard daemon serve thread did not become ready")
        self._publish_listen_state()
        self._diagnostics.record("daemon_listen_ready")
        if not continue_after_listen:
            return
    self._complete_owned_service_after_listen(generation, already_locked=True)


def _complete_owned_service_after_listen(
    self: _server.GuardDaemonServer,
    generation: int | None,
    *,
    already_locked: bool = False,
) -> None:
    if not _server.startup_generation_is_current(self, generation):
        raise RuntimeError("Guard daemon stopped during startup")
    self._server.hook_process_runner.require_initial_capacity()
    self._reconcile_runtime_artifacts_best_effort()
    if not _server.startup_generation_is_current(self, generation):
        raise RuntimeError("Guard daemon stopped during startup")
    self._maintain_command_activity_best_effort()
    if not _server.startup_generation_is_current(self, generation):
        raise RuntimeError("Guard daemon stopped during startup")
    self._persist_aibom_inventory_context()

    def start_post_listen_workers() -> None:
        if generation is not None and not _server.startup_generation_is_current(self, generation):
            raise RuntimeError("Guard daemon stopped during startup")
        self._publish_listen_state()
        self._server.start_unclassified_watchdog()
        self._server.runtime_heartbeat.start()
        approval_attention = getattr(self._server, "approval_attention", None)
        if approval_attention is not None:
            approval_attention.start()
        self._start_watchdog()
        self._start_headless_cloud_sync()
        self._start_supply_chain_bundle_refresh()
        self._start_aibom_inventory_refresh()
        self._start_extension_control_refresh()
        self._command_queue_worker = _server.start_command_queue_worker(
            self._server.store, self._command_queue_worker, config_reader=self._server.hook_config_reader
        )
        self._cloud_review_sync_worker = _server.start_cloud_sync_sync_worker(
            self._server.store,
            self._cloud_review_sync_worker,
        )
        self._start_command_activity_maintenance()
        self._record_lifecycle("ready")
        self._owned_service_ready = True
        self._diagnostics.record("daemon_ready")

    if already_locked:
        start_post_listen_workers()
        return
    with self._finish_service_lock:
        start_post_listen_workers()


def _serve_forever(self: _server.GuardDaemonServer) -> None:
    stop_reason = "serve_loop_returned"
    try:
        self._serve_loop_started.set()
        self._server.serve_forever()
        if self._shutdown_started.is_set():
            stop_reason = "requested_shutdown"
    except KeyboardInterrupt:
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
        if self._thread is _server.threading.current_thread():
            self._thread = None


def _record_lifecycle(self: _server.GuardDaemonServer, event: str, *, reason: str | None = None) -> None:
    with _server.suppress(Exception):
        _server.record_daemon_lifecycle_event(
            self._server.store.guard_home,
            event=event,
            session_id=self._server.runtime_session_id,
            reason=reason,
            port=self.port,
        )
