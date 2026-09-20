"""Daemon command and inventory maintenance."""

from __future__ import annotations

from . import server as _server


def refresh_command_queue_worker(self: _server.GuardDaemonServer) -> dict[str, object]:
    """Apply changed Cloud connectivity and consent without a daemon restart."""

    if not self._finish_service_lock.acquire(blocking=False):
        return {
            "operation": "guard.review.resolveExact",
            "running": False,
            "sync_running": False,
        }
    try:
        if not self._owned_service_ready or self._shutdown_started.is_set():
            return {
                "operation": "guard.review.resolveExact",
                "running": False,
                "sync_running": False,
            }
        self._command_queue_worker, running = _server.refresh_command_queue_worker(
            self._server.store,
            self._command_queue_worker,
            shutting_down=self._shutdown_started.is_set(),
            config_reader=self._server.hook_config_reader,
        )
        from ..runtime.cloud_review_sync_worker import refresh_cloud_review_sync_worker

        self._cloud_review_sync_worker, sync_running = refresh_cloud_review_sync_worker(
            self._server.store, self._cloud_review_sync_worker, shutting_down=self._shutdown_started.is_set()
        )
    finally:
        self._finish_service_lock.release()
    return {
        "operation": "guard.review.resolveExact",
        "running": running,
        "sync_running": sync_running,
    }


def _reconcile_runtime_artifacts_best_effort(self: _server.GuardDaemonServer) -> None:
    """Align existing Guard-owned artifacts before reporting daemon_ready."""
    try:
        result = _server.reconcile_runtime_artifacts(
            self._server.store,
            home_dir=self._aibom_home_dir,
        )
    except Exception as error:
        self._diagnostics.record("runtime_artifact_reconciliation_failed", detail=str(error))
        return
    detail = (
        f"launchers={','.join(result.refreshed_launchers) or 'none'} "
        f"harnesses={','.join(result.repaired_harnesses) or 'none'} "
        f"packages={','.join(result.repaired_package_managers) or 'none'} "
        f"failed={','.join((*result.failed_harnesses, *result.errors)) or 'none'}"
    )
    event = (
        "runtime_artifact_reconciliation_completed" if result.healthy else "runtime_artifact_reconciliation_degraded"
    )
    self._diagnostics.record(event, detail=detail)


def _maintain_command_activity_best_effort(self: _server.GuardDaemonServer) -> None:
    now = _server.datetime.now(_server.timezone.utc)
    try:
        config = _server.load_guard_config(self._server.store.guard_home, config_reader=self._server.hook_config_reader)
        self._server.store.maintain_command_activity(
            now=now,
            detail_retain_days=config.evidence_retain_days,
        )
    except Exception:
        with _server.suppress(Exception):
            self._server.store.record_command_activity_persistence_failure(
                error_code="maintenance_failed",
                occurred_at=now,
            )


def _maintain_storage_best_effort(self: _server.GuardDaemonServer) -> bool:
    try:
        config = _server.load_guard_config(
            self._server.store.guard_home,
            config_reader=self._server.hook_config_reader,
        )
        receipt_detail_limit = (
            config.receipt_detail_limit
            if config.receipt_detail_limit is not None
            else _server.DEFAULT_RECEIPT_DETAIL_LIMIT
        )
        guard_event_limit = (
            config.guard_event_limit if config.guard_event_limit is not None else _server.DEFAULT_GUARD_EVENT_LIMIT
        )
        result = self._server.store.maintain_storage(
            now=_server.datetime.now(_server.timezone.utc),
            detail_retain_days=config.evidence_retain_days,
            receipt_detail_limit=receipt_detail_limit,
            guard_event_limit=guard_event_limit,
        )
    except Exception:
        return False
    return result.completed


def _start_command_activity_maintenance(self: _server.GuardDaemonServer) -> None:
    if self._command_activity_maintenance_thread is not None and self._command_activity_maintenance_thread.is_alive():
        return
    self._command_activity_maintenance_thread = _server.threading.Thread(
        target=self._command_activity_maintenance_loop,
        daemon=True,
    )
    self._command_activity_maintenance_thread.start()


def _require_command_activity_maintenance_stopped(self: _server.GuardDaemonServer) -> None:
    if self._command_activity_maintenance_thread is None:
        return
    if self._command_activity_maintenance_thread.is_alive():
        raise RuntimeError("command activity maintenance is still stopping")
    self._command_activity_maintenance_thread = None


def _join_command_activity_maintenance(self: _server.GuardDaemonServer) -> None:
    if self._command_activity_maintenance_thread is None:
        return
    self._command_activity_maintenance_thread.join(timeout=5)
    if not self._command_activity_maintenance_thread.is_alive():
        self._command_activity_maintenance_thread = None


def _command_activity_maintenance_loop(self: _server.GuardDaemonServer) -> None:
    if self._shutdown_started.is_set():
        return
    self._maintain_command_activity_best_effort()
    storage_complete = self._maintain_storage_best_effort()
    while not self._shutdown_started.wait(3_600 if storage_complete else 5):
        self._maintain_command_activity_best_effort()
        storage_complete = self._maintain_storage_best_effort()


def _persist_aibom_inventory_context(self: _server.GuardDaemonServer) -> None:
    workspace_id = self._server.store.get_cloud_workspace_id()
    if workspace_id is None or workspace_id != self._aibom_context_workspace_id or self._aibom_workspace_dir is None:
        return
    payload: dict[str, object] = {
        "workspace_dir": str(self._aibom_workspace_dir),
        "workspace_id": workspace_id,
    }
    if self._aibom_home_dir is not None:
        payload["home_dir"] = str(self._aibom_home_dir)
    now = _server._now()
    self._server.store.set_sync_payload("aibom_inventory_context", payload, now)
