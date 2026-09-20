"""Headless cloud synchronization lifecycle."""

from __future__ import annotations

from . import server as _server


def _run_headless_cloud_sync(
    *,
    store: _server.GuardStore,
    managed_controls_publish: (
        _server.Callable[[_server.ExtensionControlAuthorityView, _server.Callable[[], None]], object] | None
    ) = None,
) -> dict[str, object]:
    recorded_at = _server._now()
    summary: dict[str, object]

    def _perform_sync() -> dict[str, object]:
        auth_context = _server._resolve_guard_sync_auth_context(store)
        if managed_controls_publish is None:
            sync_payload = _server._sync_local_guard_cloud_proof_with_optional_auth_context(
                store,
                auth_context,
            )
        else:
            sync_payload = _server._sync_local_guard_cloud_proof_with_optional_auth_context(
                store,
                auth_context,
                managed_controls_publish,
            )
        supply_chain_payload = _server._sync_supply_chain_cloud_state_with_optional_auth_context(
            store,
            auth_context,
        )
        latest_state = store.get_latest_guard_connect_state(now=recorded_at) or {}
        request_id = latest_state.get("request_id") if isinstance(latest_state, dict) else None
        store.record_latest_guard_connect_sync_success(
            sync_payload=sync_payload,
            now=recorded_at,
            request_id=request_id if isinstance(request_id, str) and request_id else None,
        )
        return {
            "status": "synced",
            "synced_at": sync_payload.get("synced_at"),
            "receipts_stored": sync_payload.get("receipts_stored", 0),
            "runtime_session_id": sync_payload.get("runtime_session_id"),
            "runtime_session_synced_at": sync_payload.get("runtime_session_synced_at"),
            "runtime_sessions_visible": sync_payload.get("runtime_sessions_visible"),
            "supply_chain": supply_chain_payload,
        }

    def _safe_storage_repair() -> dict[str, object]:
        try:
            return _server.repair_guard_cloud_connect_storage(store)
        except Exception as repair_error:
            return {
                "cleared_stale_sign_in": False,
                "existing_sign_in_valid": False,
                "repaired_storage": False,
                "repair_error": str(repair_error),
            }

    try:
        summary = _perform_sync()
    except _server.GuardSyncAuthorizationExpiredError as error:
        auth_error = error
        repair = _safe_storage_repair()
        if repair.get("existing_sign_in_valid"):
            try:
                summary = _perform_sync()
            except _server.GuardSyncAuthorizationExpiredError as retry_error:
                auth_error = retry_error
            except _server.GuardSyncNotConfiguredError as retry_error:
                return _server.headless_sync_retry_summary(
                    store,
                    status="not_configured",
                    error=retry_error,
                    repair=repair,
                    recorded_at=recorded_at,
                    record_retry=True,
                )
            except _server.GuardSyncNotAvailableError as retry_error:
                return _server.headless_sync_retry_summary(
                    store,
                    status="not_available",
                    error=retry_error,
                    repair=repair,
                    recorded_at=recorded_at,
                )
            except Exception as retry_error:
                return _server.headless_sync_retry_summary(
                    store,
                    status="pending",
                    error=retry_error,
                    repair=repair,
                    recorded_at=recorded_at,
                )
            else:
                store.set_sync_payload("headless_app_sync_summary", summary, recorded_at)
                return summary
        store.record_latest_guard_connect_sync_result(
            status="retry_required",
            milestone="first_sync_failed",
            now=recorded_at,
            reason=str(auth_error),
        )
        summary = {
            "status": "auth_expired",
            "message": str(auth_error),
            "authorization_repair": repair,
        }
    except _server.GuardSyncNotConfiguredError as error:
        config_error = error
        repair = _safe_storage_repair()
        if repair.get("existing_sign_in_valid"):
            try:
                summary = _perform_sync()
            except _server.GuardSyncAuthorizationExpiredError as retry_error:
                return _server.headless_sync_retry_summary(
                    store,
                    status="auth_expired",
                    error=retry_error,
                    repair=repair,
                    recorded_at=recorded_at,
                    record_retry=True,
                )
            except _server.GuardSyncNotConfiguredError as retry_error:
                config_error = retry_error
            except _server.GuardSyncNotAvailableError as retry_error:
                return _server.headless_sync_retry_summary(
                    store,
                    status="not_available",
                    error=retry_error,
                    repair=repair,
                    recorded_at=recorded_at,
                )
            except Exception as retry_error:
                return _server.headless_sync_retry_summary(
                    store,
                    status="pending",
                    error=retry_error,
                    repair=repair,
                    recorded_at=recorded_at,
                )
            else:
                store.set_sync_payload("headless_app_sync_summary", summary, recorded_at)
                return summary
        store.record_latest_guard_connect_sync_result(
            status="retry_required",
            milestone="first_sync_failed",
            now=recorded_at,
            reason=str(config_error),
        )
        summary = {
            "status": "not_configured",
            "message": str(config_error),
            "authorization_repair": repair,
        }
    except _server.GuardSyncNotAvailableError as error:
        summary = {
            "status": "not_available",
            "message": str(error),
        }
    except Exception as error:
        summary = {
            "status": "pending",
            "message": str(error),
        }
    store.set_sync_payload("headless_app_sync_summary", summary, recorded_at)
    return summary


def _run_headless_cloud_sync_with_optional_publish(
    *,
    store: _server.GuardStore,
    managed_controls_publish: _server.Callable[
        [_server.ExtensionControlAuthorityView, _server.Callable[[], None]], object
    ]
    | None,
) -> dict[str, object]:
    try:
        sync_parameters = _server.inspect.signature(_server._run_headless_cloud_sync).parameters
    except (TypeError, ValueError):
        sync_parameters = {}
    if managed_controls_publish is not None and "managed_controls_publish" in sync_parameters:
        return _server._run_headless_cloud_sync(
            store=store,
            managed_controls_publish=managed_controls_publish,
        )
    return _server._run_headless_cloud_sync(store=store)


def _managed_controls_publish_for(
    server: object,
) -> _server.Callable[[_server.ExtensionControlAuthorityView, _server.Callable[[], None]], object] | None:
    runtime = getattr(server, "extension_control_runtime", None)
    publish = getattr(runtime, "publish_after_commit", None)
    if not callable(publish):
        return None
    return _server.cast(
        _server.Callable[[_server.ExtensionControlAuthorityView, _server.Callable[[], None]], object], publish
    )


def _queue_headless_cloud_sync(
    *,
    store: _server.GuardStore,
    managed_controls_publish: (
        _server.Callable[[_server.ExtensionControlAuthorityView, _server.Callable[[], None]], object] | None
    ) = None,
) -> dict[str, object]:
    if store.get_cloud_sync_profile() is None:
        with _server.suppress(Exception):
            _server.repair_guard_cloud_connect_storage(store)
    if store.get_cloud_sync_profile() is None:
        return {
            "status": "not_configured",
            "message": "Cloud sync is not paired on this machine.",
        }
    store_key = _server._headless_cloud_sync_store_key(store)
    with _server._HEADLESS_CLOUD_SYNC_STATE_LOCK:
        if store_key in _server._HEADLESS_CLOUD_SYNC_IN_FLIGHT:
            return {
                "status": "in_progress",
                "message": "Cloud sync already running.",
            }
        # Short-circuit obvious overlap; sync_local_guard_cloud_proof() still owns the real lock.
        if store.cloud_sync_in_progress():
            return {
                "status": "in_progress",
                "message": "Cloud sync already running.",
            }
        _server._HEADLESS_CLOUD_SYNC_IN_FLIGHT.add(store_key)

    def _run_and_finalize() -> None:
        try:
            _server._run_headless_cloud_sync_with_optional_publish(
                store=store,
                managed_controls_publish=managed_controls_publish,
            )
        finally:
            with _server._HEADLESS_CLOUD_SYNC_STATE_LOCK:
                _server._HEADLESS_CLOUD_SYNC_IN_FLIGHT.discard(store_key)

    _server.threading.Thread(
        target=_run_and_finalize,
        daemon=True,
        name="guard-headless-app-cloud-sync",
    ).start()
    return {
        "status": "queued",
        "message": "Cloud sync started.",
    }


def _queue_headless_cloud_sync_with_optional_publish(
    *, store: _server.GuardStore, managed_controls_publish: _server.Callable[..., object] | None
) -> dict[str, object]:
    return _server.queue_sync_with_optional_publish(
        store=store, queue_sync=_server._queue_headless_cloud_sync, managed_controls_publish=managed_controls_publish
    )


def _maybe_queue_first_cloud_sync(
    *,
    store: _server.GuardStore,
    managed_controls_publish: (
        _server.Callable[[_server.ExtensionControlAuthorityView, _server.Callable[[], None]], object] | None
    ) = None,
) -> dict[str, object] | None:
    return _server.maybe_queue_first_cloud_sync(
        store=store,
        queue_sync=_server._queue_headless_cloud_sync,
        repair_connect=_server.repair_guard_cloud_connect_storage,
        now=_server._now,
        managed_controls_publish=managed_controls_publish,
    )
