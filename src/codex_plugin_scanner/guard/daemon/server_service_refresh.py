"""Background synchronization and idle shutdown."""

from __future__ import annotations

from . import server as _server


def _start_headless_cloud_sync(self: _server.GuardDaemonServer) -> None:
    if self._headless_cloud_sync_interval_seconds <= 0:
        return
    if self._headless_cloud_sync_thread is not None and self._headless_cloud_sync_thread.is_alive():
        return
    self._headless_cloud_sync_thread = _server.threading.Thread(
        target=self._refresh_headless_cloud_sync_loop,
        daemon=True,
        name="guard-headless-cloud-sync-loop",
    )
    self._headless_cloud_sync_thread.start()


def _refresh_headless_cloud_sync_loop(self: _server.GuardDaemonServer) -> None:
    interval_seconds = self._headless_cloud_sync_interval_seconds
    backoff_seconds = (
        self._headless_cloud_sync_backoff_seconds if self._headless_cloud_sync_backoff_seconds > 0 else interval_seconds
    )
    while not self._shutdown_started.is_set():
        summary = _server._run_headless_cloud_sync_with_optional_publish(
            store=self._server.store,
            managed_controls_publish=_server._managed_controls_publish_for(self._server),
        )
        status = str(summary.get("status") or "")
        wait_seconds = interval_seconds if status == "synced" else backoff_seconds
        if self._shutdown_started.wait(wait_seconds):
            return


def _watch_for_idle_shutdown(self: _server.GuardDaemonServer) -> None:
    idle_timeout_seconds = self._server.idle_timeout_seconds
    if idle_timeout_seconds is None or idle_timeout_seconds <= 0:
        return
    while not self._shutdown_started.is_set():
        with self._server.active_stream_clients_lock:
            active_stream_clients = self._server.active_stream_clients
        try:
            pending_review_requests = self._server.store.list_approval_requests(
                status="pending",
                limit=1,
            )
            cloud_profile = self._server.store.get_cloud_sync_profile()
            workspace_id = cloud_profile.get("workspace_id") if isinstance(cloud_profile, dict) else None
            outbox_status = self._server.store.review_event_outbox_status(
                now=_server._now(),
                workspace_id=workspace_id,
            )
            outbox_depth = outbox_status["depth"]
        except _server.sqlite3.OperationalError:
            _server.time.sleep(_server._GUARD_DAEMON_IDLE_POLL_INTERVAL_SECONDS)
            continue
        if (
            active_stream_clients > 0
            or pending_review_requests
            or (workspace_id is not None and isinstance(outbox_depth, int) and outbox_depth > 0)
        ):
            _server.time.sleep(_server._GUARD_DAEMON_IDLE_POLL_INTERVAL_SECONDS)
            continue
        if _server.time.monotonic() - self._server.last_activity_monotonic >= idle_timeout_seconds:
            self._shutdown_started.set()
            self._server.shutdown()
            return
        _server.time.sleep(_server._GUARD_DAEMON_IDLE_POLL_INTERVAL_SECONDS)


def _start_supply_chain_bundle_refresh(self: _server.GuardDaemonServer) -> None:
    if self._bundle_refresh_interval_seconds is None or self._bundle_refresh_interval_seconds <= 0:
        return
    if self._bundle_refresh_thread is not None and self._bundle_refresh_thread.is_alive():
        return
    self._bundle_refresh_thread = _server.threading.Thread(
        target=self._refresh_supply_chain_bundle_loop,
        daemon=True,
    )
    self._bundle_refresh_thread.start()


def _refresh_supply_chain_bundle_loop(self: _server.GuardDaemonServer) -> None:
    interval_seconds = self._bundle_refresh_interval_seconds
    if interval_seconds is None or interval_seconds <= 0:
        return
    backoff_seconds = (
        self._bundle_refresh_backoff_seconds if self._bundle_refresh_backoff_seconds > 0 else interval_seconds
    )
    while not self._shutdown_started.is_set():
        refreshed_at = _server._now()
        try:
            summary = _server.sync_supply_chain_bundle(self._server.store)
            self._server.store.set_sync_payload(
                "supply_chain_bundle_daemon",
                {**summary, "status": "synced"},
                refreshed_at,
            )
            wait_seconds = interval_seconds
        except _server.GuardSyncAuthorizationExpiredError as error:
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
        except _server.GuardSyncNotConfiguredError:
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


def _start_extension_control_refresh(self: _server.GuardDaemonServer) -> None:
    if self._extension_control_refresh_thread is not None:
        return
    self._extension_control_refresh_thread = _server.threading.Thread(
        target=self._refresh_extension_control_loop,
        daemon=True,
        name="guard-extension-control-refresh",
    )
    self._extension_control_refresh_thread.start()


def _refresh_extension_control_loop(self: _server.GuardDaemonServer) -> None:
    while not self._shutdown_started.wait(self._extension_control_refresh_interval_seconds):
        try:
            _ = self._server.refresh_extension_control_runtime()
        except Exception:
            _server._LOGGER.exception("Failed to refresh resident extension-control authority")


def _start_aibom_inventory_refresh(self: _server.GuardDaemonServer) -> None:
    if self._aibom_refresh_interval_seconds is None or self._aibom_refresh_interval_seconds <= 0:
        return
    if self._aibom_refresh_thread is not None and self._aibom_refresh_thread.is_alive():
        return
    self._aibom_refresh_thread = _server.threading.Thread(
        target=self._refresh_aibom_inventory_loop,
        daemon=True,
    )
    self._aibom_refresh_thread.start()


def _aibom_inventory_context_dirs(
    self: _server.GuardDaemonServer,
) -> tuple[_server.Path | None, _server.Path | None, str | None]:
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
        home_dir = _server.Path(home_value).expanduser()
    workspace_dir = self._aibom_workspace_dir if explicit_context_is_bound else None
    if workspace_dir is None and isinstance(workspace_value, str) and workspace_value.strip():
        workspace_dir = _server.Path(workspace_value).expanduser()
    bound_workspace_id = current_workspace_id if workspace_dir is not None else None
    return home_dir, workspace_dir, bound_workspace_id


def _refresh_aibom_inventory_loop(self: _server.GuardDaemonServer) -> None:
    interval_seconds = self._aibom_refresh_interval_seconds
    if interval_seconds is None or interval_seconds <= 0:
        return
    backoff_seconds = (
        self._aibom_refresh_backoff_seconds if self._aibom_refresh_backoff_seconds > 0 else interval_seconds
    )
    while not self._shutdown_started.is_set():
        refreshed_at = _server._now()
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
            auth_context = _server._resolve_guard_sync_auth_context(self._server.store)
            with self._server.store.hold_cloud_sync_lock():
                summary = _server.sync_aibom_snapshots_if_due(
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
        except _server.GuardSyncAuthorizationExpiredError as error:
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
        except _server.GuardSyncNotConfiguredError:
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
