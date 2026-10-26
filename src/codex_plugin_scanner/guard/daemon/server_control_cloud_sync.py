"""Headless cloud-sync queueing and publishing for the daemon control plane."""

# pyright: reportAttributeAccessIssue=false, reportUnknownMemberType=false

from __future__ import annotations

import inspect
import threading
from collections.abc import Callable
from contextlib import suppress
from pathlib import Path
from typing import Any, cast

from ..cli.connect_sync_result import (
    headless_sync_retry_summary,
)
from ..local_supply_chain import (
    sync_supply_chain_cloud_state,
)
from ..native_daemon_handler import (
    NativeDaemonHandlerError,
)
from ..runtime.extension_control_authority import ExtensionControlAuthorityView
from ..runtime.runner import (
    GuardSyncAuthorizationExpiredError,
    GuardSyncNotAvailableError,
    GuardSyncNotConfiguredError,
    _resolve_guard_sync_auth_context,
    repair_guard_cloud_connect_storage,
    sync_local_guard_cloud_proof,
)
from ..store import GuardStore
from .first_cloud_sync import maybe_queue_first_cloud_sync, queue_sync_with_optional_publish
from .server_common import (
    _NATIVE_HANDLER_UNAVAILABLE,
    _now,
)

_HEADLESS_CLOUD_SYNC_STATE_LOCK = threading.Lock()


_HEADLESS_CLOUD_SYNC_IN_FLIGHT: set[str] = set()


def _headless_cloud_sync_store_key(store: GuardStore) -> str:
    return str(store.guard_home.expanduser().resolve())


def _receipt_summary(receipt: dict[str, object]) -> dict[str, object]:
    return {
        "id": receipt.get("id"),
        "operation": receipt.get("operation"),
        "status": receipt.get("status"),
        "timestamp": receipt.get("timestamp"),
    }


def _headless_failure(
    ask: Callable[[], tuple[int, dict[str, Any]]],
) -> tuple[int, dict[str, object]]:
    """A failed headless action as the resident shaped it; fail closed when it cannot answer."""

    try:
        return ask()
    except NativeDaemonHandlerError:
        return _NATIVE_HANDLER_UNAVAILABLE


def _run_headless_cloud_sync(
    *,
    store: GuardStore,
    managed_controls_publish: (Callable[[ExtensionControlAuthorityView, Callable[[], None]], object] | None) = None,
) -> dict[str, object]:
    recorded_at = _now()
    summary: dict[str, object]

    def _perform_sync() -> dict[str, object]:
        auth_context = _resolve_guard_sync_auth_context(store)
        if managed_controls_publish is None:
            sync_payload = _sync_local_guard_cloud_proof_with_optional_auth_context(
                store,
                auth_context,
            )
        else:
            sync_payload = _sync_local_guard_cloud_proof_with_optional_auth_context(
                store,
                auth_context,
                managed_controls_publish,
            )
        supply_chain_payload = _sync_supply_chain_cloud_state_with_optional_auth_context(
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
            return repair_guard_cloud_connect_storage(store)
        except Exception as repair_error:
            return {
                "cleared_stale_sign_in": False,
                "existing_sign_in_valid": False,
                "repaired_storage": False,
                "repair_error": str(repair_error),
            }

    try:
        summary = _perform_sync()
    except GuardSyncAuthorizationExpiredError as error:
        auth_error = error
        repair = _safe_storage_repair()
        if repair.get("existing_sign_in_valid"):
            try:
                summary = _perform_sync()
            except GuardSyncAuthorizationExpiredError as retry_error:
                auth_error = retry_error
            except GuardSyncNotConfiguredError as retry_error:
                return headless_sync_retry_summary(
                    store,
                    status="not_configured",
                    error=retry_error,
                    repair=repair,
                    recorded_at=recorded_at,
                    record_retry=True,
                )
            except GuardSyncNotAvailableError as retry_error:
                return headless_sync_retry_summary(
                    store,
                    status="not_available",
                    error=retry_error,
                    repair=repair,
                    recorded_at=recorded_at,
                )
            except Exception as retry_error:
                return headless_sync_retry_summary(
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
    except GuardSyncNotConfiguredError as error:
        config_error = error
        repair = _safe_storage_repair()
        if repair.get("existing_sign_in_valid"):
            try:
                summary = _perform_sync()
            except GuardSyncAuthorizationExpiredError as retry_error:
                return headless_sync_retry_summary(
                    store,
                    status="auth_expired",
                    error=retry_error,
                    repair=repair,
                    recorded_at=recorded_at,
                    record_retry=True,
                )
            except GuardSyncNotConfiguredError as retry_error:
                config_error = retry_error
            except GuardSyncNotAvailableError as retry_error:
                return headless_sync_retry_summary(
                    store,
                    status="not_available",
                    error=retry_error,
                    repair=repair,
                    recorded_at=recorded_at,
                )
            except Exception as retry_error:
                return headless_sync_retry_summary(
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
    except GuardSyncNotAvailableError as error:
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
    store: GuardStore,
    managed_controls_publish: Callable[[ExtensionControlAuthorityView, Callable[[], None]], object] | None,
) -> dict[str, object]:
    try:
        sync_parameters = inspect.signature(_run_headless_cloud_sync).parameters
    except (TypeError, ValueError):
        sync_parameters = {}
    if managed_controls_publish is not None and "managed_controls_publish" in sync_parameters:
        return _run_headless_cloud_sync(
            store=store,
            managed_controls_publish=managed_controls_publish,
        )
    return _run_headless_cloud_sync(store=store)


def _managed_controls_publish_for(
    server: object,
) -> Callable[[ExtensionControlAuthorityView, Callable[[], None]], object] | None:
    runtime = getattr(server, "extension_control_runtime", None)
    publish = getattr(runtime, "publish_after_commit", None)
    if not callable(publish):
        return None
    return cast(Callable[[ExtensionControlAuthorityView, Callable[[], None]], object], publish)


def _queue_headless_cloud_sync(
    *,
    store: GuardStore,
    managed_controls_publish: (Callable[[ExtensionControlAuthorityView, Callable[[], None]], object] | None) = None,
) -> dict[str, object]:
    if store.get_cloud_sync_profile() is None:
        with suppress(Exception):
            repair_guard_cloud_connect_storage(store)
    if store.get_cloud_sync_profile() is None:
        return {
            "status": "not_configured",
            "message": "Cloud sync is not paired on this machine.",
        }
    store_key = _headless_cloud_sync_store_key(store)
    with _HEADLESS_CLOUD_SYNC_STATE_LOCK:
        if store_key in _HEADLESS_CLOUD_SYNC_IN_FLIGHT:
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
        _HEADLESS_CLOUD_SYNC_IN_FLIGHT.add(store_key)

    def _run_and_finalize() -> None:
        try:
            _run_headless_cloud_sync_with_optional_publish(
                store=store,
                managed_controls_publish=managed_controls_publish,
            )
        finally:
            with _HEADLESS_CLOUD_SYNC_STATE_LOCK:
                _HEADLESS_CLOUD_SYNC_IN_FLIGHT.discard(store_key)

    threading.Thread(
        target=_run_and_finalize,
        daemon=True,
        name="guard-headless-app-cloud-sync",
    ).start()
    return {
        "status": "queued",
        "message": "Cloud sync started.",
    }


def _queue_headless_cloud_sync_with_optional_publish(
    *, store: GuardStore, managed_controls_publish: Callable[..., object] | None
) -> dict[str, object]:
    return queue_sync_with_optional_publish(
        store=store, queue_sync=_queue_headless_cloud_sync, managed_controls_publish=managed_controls_publish
    )


def _maybe_queue_first_cloud_sync(
    *,
    store: GuardStore,
    managed_controls_publish: (Callable[[ExtensionControlAuthorityView, Callable[[], None]], object] | None) = None,
) -> dict[str, object] | None:
    return maybe_queue_first_cloud_sync(
        store=store,
        queue_sync=_queue_headless_cloud_sync,
        repair_connect=repair_guard_cloud_connect_storage,
        now=_now,
        managed_controls_publish=managed_controls_publish,
    )


def _sync_supply_chain_cloud_state_with_optional_auth_context(
    store: GuardStore,
    auth_context: dict[str, object] | None,
    *,
    workspace_dir: Path | None = None,
) -> dict[str, object]:
    try:
        parameters = inspect.signature(sync_supply_chain_cloud_state).parameters
    except (TypeError, ValueError):
        parameters = {}
    kwargs: dict[str, Any] = {}
    if auth_context is not None and "auth_context" in parameters:
        kwargs["auth_context"] = auth_context
    if workspace_dir is not None and "workspace_dir" in parameters:
        kwargs["workspace_dir"] = workspace_dir
    return sync_supply_chain_cloud_state(store, **kwargs)


def _sync_local_guard_cloud_proof_with_optional_auth_context(
    store: GuardStore,
    auth_context: dict[str, object] | None,
    managed_controls_publish: (Callable[[ExtensionControlAuthorityView, Callable[[], None]], object] | None) = None,
) -> dict[str, object]:
    try:
        parameters = inspect.signature(sync_local_guard_cloud_proof).parameters
    except (TypeError, ValueError):
        parameters = {}
    if (
        auth_context is not None
        and "auth_context" in parameters
        and managed_controls_publish is not None
        and "managed_controls_publish" in parameters
    ):
        return sync_local_guard_cloud_proof(
            store,
            auth_context=auth_context,
            managed_controls_publish=managed_controls_publish,
        )
    if auth_context is not None and "auth_context" in parameters:
        return sync_local_guard_cloud_proof(store, auth_context=auth_context)
    if managed_controls_publish is not None and "managed_controls_publish" in parameters:
        return sync_local_guard_cloud_proof(
            store,
            managed_controls_publish=managed_controls_publish,
        )
    return sync_local_guard_cloud_proof(store)
