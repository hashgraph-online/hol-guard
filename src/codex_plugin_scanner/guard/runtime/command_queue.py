"""Guard Cloud command queue client for local daemon workers."""

from __future__ import annotations

import json
import logging
import urllib.error
from collections.abc import Callable
from datetime import datetime, timezone
from functools import partial
from pathlib import Path
from typing import Any

from ...version import __version__
from ..adapters.base import HarnessContext
from ..store import GuardStore
from . import exact_cloud_review_lifecycle
from .auto_update import maybe_auto_update
from .command_capability import (
    CommandCapabilityError,
    audit_command_decision,
    command_capability_operations,
    command_capability_status,
    command_environment_allows_queue,
    consume_local_command_approval,
    mark_command_job_consumed,
    register_pending_command,
)
from .command_executors import (
    COMMAND_OPERATION_SCHEMA_VERSIONS,
    SUPPORTED_COMMAND_OPERATIONS,
    _local_request_snapshot_payload,
    command_job_operation,
    execute_guard_command_job,
)
from .command_queue_activation import (
    COMMAND_QUEUE_LEASE_WAIT_MS_ENV as _COMMAND_QUEUE_LEASE_WAIT_MS_ENV,
)
from .command_queue_activation import (
    command_queue_is_enabled,
)
from .command_queue_activation import (
    command_queue_lease_wait_ms as _command_queue_lease_wait_ms,
)
from .command_queue_activation import (
    command_queue_long_poll_enabled as _command_queue_long_poll_enabled,
)
from .command_queue_activation import (
    nonnegative_env_float as _env_float,
)
from .command_queue_authority import authorize_transport_command_queue_job as authorize_command_queue_job
from .command_queue_authority import command_queue_oauth_target
from .command_queue_protocol import command_api_url as _command_api_url
from .command_queue_protocol import job_id as _job_id
from .command_queue_protocol import lease_id as _lease_id
from .command_queue_protocol import pending_result_is_stale as _pending_result_is_stale
from .command_queue_protocol import redacted_error as _format_redacted_error
from .command_queue_protocol import result_payload as _result_payload
from .command_queue_protocol import retry_wait_seconds as _retry_wait_seconds
from .exact_cloud_review import (
    EXACT_CLOUD_REVIEW_OPERATION,
    exact_cloud_review_operations,
    exact_cloud_review_status,
)
from .exact_cloud_review_lifecycle import ExactReviewLifecycleObserver as LifecycleObserver
from .exact_cloud_review_transport import (
    EXACT_CLOUD_REVIEW_COMMAND_API_BASE,
    lease_next_job,
    uses_exact_transport,
)
from .live_request_repair import live_request_sync_repair_status
from .runner import (
    GuardSyncAuthorizationExpiredError,
    GuardSyncNotConfiguredError,
    _guard_sync_request,
    _resolve_guard_sync_auth_context,
    _sync_http_error_message,
    _sync_url_error_message,
    _urlopen_json_with_timeout_retry,
    repair_guard_cloud_connect_storage,
)

COMMAND_QUEUE_STATE_KEY = "guard_command_queue_state"
COMMAND_QUEUE_ENABLED_ENV = "GUARD_CLOUD_COMMAND_QUEUE_ENABLED"
COMMAND_QUEUE_LEASE_WAIT_MS_ENV = _COMMAND_QUEUE_LEASE_WAIT_MS_ENV
COMMAND_QUEUE_POLL_INTERVAL_ENV = "GUARD_CLOUD_COMMAND_QUEUE_POLL_INTERVAL_SECONDS"
COMMAND_QUEUE_ERROR_BACKOFF_ENV = "GUARD_CLOUD_COMMAND_QUEUE_ERROR_BACKOFF_SECONDS"

_DEFAULT_POLL_INTERVAL_SECONDS = 2.0
_DEFAULT_ERROR_BACKOFF_SECONDS = 30.0
_LONG_POLL_EMPTY_MIN_WAIT_SECONDS = 0.05
_REQUEST_TIMEOUT_SECONDS = 35
_RETRY_TIMEOUT_SECONDS = 60
_LOGGER = logging.getLogger(__name__)
_LEASE_LOCAL_REQUEST_SNAPSHOT_KEYS = (
    "requests",
    "pendingComplete",
    "resolvedComplete",
    "pendingLimit",
    "resolvedLimit",
    "pendingCount",
    "resolvedCount",
)
Observer = LifecycleObserver | None
observe_execution = exact_cloud_review_lifecycle.observe_exact_review_execution


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def command_queue_enabled(
    store: GuardStore | None = None,
    environ: dict[str, str] | None = None,
) -> bool:
    """Return whether a valid local capability permits Cloud command polling.

    The environment variable is an emergency opt-out only. It cannot grant a
    capability or restore an expired/revoked capability.
    """

    return command_queue_is_enabled(
        store,
        environ,
        enabled_env=COMMAND_QUEUE_ENABLED_ENV,
        environment_allows_queue=command_environment_allows_queue,
        operations=command_queue_operations,
        logger=_LOGGER,
    )


def command_queue_operations(store: GuardStore) -> tuple[str, ...]:
    generic = tuple(
        operation for operation in command_capability_operations(store) if operation != EXACT_CLOUD_REVIEW_OPERATION
    )
    return generic + tuple(operation for operation in exact_cloud_review_operations(store) if operation not in generic)


def _redacted_error(error: BaseException) -> str:
    return _format_redacted_error(
        error,
        http_formatter=_sync_http_error_message,
        os_formatter=_sync_url_error_message,
    )


def _json_request(
    auth_context: dict[str, object],
    *,
    method: str,
    path: str,
    payload: dict[str, object],
) -> dict[str, object]:
    return _json_request_base(auth_context, method=method, path=path, payload=payload)


def _exact_json_request(
    auth_context: dict[str, object],
    *,
    method: str,
    path: str,
    payload: dict[str, object],
) -> dict[str, object]:
    return _json_request_base(
        auth_context,
        method=method,
        path=path,
        payload=payload,
        base_path=EXACT_CLOUD_REVIEW_COMMAND_API_BASE,
    )


def _json_request_base(
    auth_context: dict[str, object],
    *,
    method: str,
    path: str,
    payload: dict[str, object],
    base_path: str = "/api/guard/commands",
) -> dict[str, object]:
    request_url = _command_api_url(auth_context["sync_url"], path, base_path=base_path)
    request = _guard_sync_request(
        auth_context,
        request_url=request_url,
        method=method,
        data=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
    )
    return _urlopen_json_with_timeout_retry(
        request=request,
        timeout_seconds=_REQUEST_TIMEOUT_SECONDS,
        retry_timeout_seconds=_RETRY_TIMEOUT_SECONDS,
    )


def _load_state(store: GuardStore) -> dict[str, object]:
    payload = store.get_sync_payload(COMMAND_QUEUE_STATE_KEY)
    return dict(payload) if isinstance(payload, dict) else {}


def _save_state(store: GuardStore, payload: dict[str, object]) -> None:
    store.set_sync_payload(COMMAND_QUEUE_STATE_KEY, payload, _now())


def command_queue_status(store: GuardStore) -> dict[str, object]:
    state = _load_state(store)
    profile = store.get_cloud_sync_profile()
    capability = command_capability_status(store)
    cloud_review = exact_cloud_review_status(store)
    return {
        "enabled": command_queue_enabled(store),
        "configured": profile is not None,
        "state": state.get("state", "idle"),
        "last_poll_at": state.get("last_poll_at"),
        "last_lease_at": state.get("last_lease_at"),
        "last_empty_poll_at": state.get("last_empty_poll_at"),
        "last_result_at": state.get("last_result_at"),
        "last_error": state.get("last_error"),
        "exact_review_route_error": state.get("exact_review_route_error"),
        "exact_review_route_error_at": state.get("exact_review_route_error_at"),
        "last_poll_was_empty": bool(state.get("last_poll_was_empty")),
        "active_job": state.get("active_job"),
        "pending_result": state.get("pending_result"),
        "capability": capability,
        "cloud_review": cloud_review,
        "granted_operations": list(command_queue_operations(store)),
        "supported_operations": list(SUPPORTED_COMMAND_OPERATIONS),
    }


def repair_command_queue_state(store: GuardStore) -> dict[str, object]:
    state = _load_state(store)
    repaired: list[str] = []
    active_job = state.get("active_job")
    if active_job is not None and not isinstance(active_job, dict):
        state.pop("active_job", None)
        repaired.append("active_job")
    pending_result = state.get("pending_result")
    if pending_result is not None:
        pending_valid = (
            isinstance(pending_result, dict)
            and isinstance(pending_result.get("job"), dict)
            and isinstance(pending_result.get("payload"), dict)
        )
        if not pending_valid:
            state.pop("pending_result", None)
            repaired.append("pending_result")
    if repaired:
        state.update({"state": "idle", "last_error": None})
        _save_state(store, state)
    return {
        "repaired": repaired,
        "repaired_count": len(repaired),
        "status": command_queue_status(store),
    }


def _lease_payload(
    store: GuardStore,
    *,
    operations: tuple[str, ...] | None = None,
    wait_ms: int | None = None,
) -> dict[str, object]:
    machine_id, workspace_id = command_queue_oauth_target(store)
    operations = command_queue_operations(store) if operations is None else operations
    if not operations:
        raise CommandCapabilityError("command_capability_required")
    capabilities: dict[str, object] = {
        "operations": list(operations),
        # Schema negotiation is a compatibility registry, not an authority
        # grant. `operations` remains the complete locally authorized set.
        "schemaVersions": {
            operation: COMMAND_OPERATION_SCHEMA_VERSIONS[operation]
            for operation in operations
            if operation in COMMAND_OPERATION_SCHEMA_VERSIONS
        },
    }
    repair_status = _live_request_sync_repair_status(store)
    if repair_status is not None:
        capabilities["liveRequestSync"] = repair_status
    return {
        "workspaceId": workspace_id,
        "deviceId": machine_id,
        "daemonVersion": __version__,
        "capabilities": capabilities,
        "localRequestsSnapshot": _local_requests_snapshot(store),
        "maxJobs": 1,
        "waitMs": _command_queue_lease_wait_ms() if wait_ms is None else wait_ms,
    }


def _live_request_sync_repair_status(store: GuardStore) -> dict[str, object] | None:
    try:
        return live_request_sync_repair_status(store)
    except Exception as exc:
        _LOGGER.warning("Guard live request repair status failed: %s", _redacted_error(exc))
        return None


def _local_requests_snapshot(store: GuardStore) -> dict[str, object]:
    try:
        payload = _local_request_snapshot_payload(store)
    except Exception as exc:
        _LOGGER.warning("Guard command local request snapshot failed: %s", _redacted_error(exc))
        return {"requests": []}
    if not isinstance(payload, dict):
        return {"requests": []}
    return {key: payload[key] for key in _LEASE_LOCAL_REQUEST_SNAPSHOT_KEYS if key in payload}


def _repair_guard_cloud_authorization(store: GuardStore) -> dict[str, bool]:
    try:
        result = repair_guard_cloud_connect_storage(store)
    except Exception as exc:
        _LOGGER.warning("Guard command authorization repair failed: %s", _redacted_error(exc))
        return {
            "cleared_stale_sign_in": False,
            "existing_sign_in_valid": False,
            "repaired_storage": False,
        }
    return {
        "cleared_stale_sign_in": bool(result.get("cleared_stale_sign_in")),
        "existing_sign_in_valid": bool(result.get("existing_sign_in_valid")),
        "repaired_storage": bool(result.get("repaired_storage")),
    }


def _resolve_guard_sync_auth_context_with_repair(store: GuardStore) -> dict[str, object]:
    try:
        return _resolve_guard_sync_auth_context(store)
    except (GuardSyncAuthorizationExpiredError, GuardSyncNotConfiguredError):
        repair = _repair_guard_cloud_authorization(store)
        if repair["existing_sign_in_valid"]:
            return _resolve_guard_sync_auth_context(store)
        raise


def _execute_job(job: dict[str, object], context: HarnessContext, store: GuardStore) -> dict[str, object]:
    return execute_guard_command_job(job, context=context, store=store, now=_now)


def _heartbeat(auth_context: dict[str, object], job: dict[str, object]) -> None:
    request = _exact_json_request if uses_exact_transport(job) else _json_request
    path = f"/{_job_id(job)}/ack" if uses_exact_transport(job) else f"/{_job_id(job)}/heartbeat"
    request(
        auth_context,
        method="POST",
        path=path,
        payload={"leaseId": _lease_id(job)},
    )


def _post_result(auth_context: dict[str, object], job: dict[str, object], payload: dict[str, object]) -> None:
    request = _exact_json_request if uses_exact_transport(job) else _json_request
    request(
        auth_context,
        method="POST",
        path=f"/{_job_id(job)}/result",
        payload=payload,
    )


def _lease_next_job(
    store: GuardStore,
    auth_context: dict[str, object],
    *,
    state: dict[str, object] | None = None,
) -> dict[str, object] | None:
    operations = command_queue_operations(store)
    exact_route_failure: Callable[[urllib.error.HTTPError], None] | None = None
    exact_route_success: Callable[[], None] | None = None
    if state is not None:
        exact_route_failure = partial(_record_exact_route_failure, state)
        exact_route_success = partial(_clear_exact_route_failure, state)
    return lease_next_job(
        operations=operations,
        wait_ms=_command_queue_lease_wait_ms(),
        exact_request=lambda options: _exact_json_request(
            auth_context,
            method="POST",
            path="/lease",
            payload=_lease_payload(
                store,
                operations=options["operations"],  # type: ignore[arg-type]
                wait_ms=options["wait_ms"],  # type: ignore[arg-type]
            ),
        ),
        queue_request=lambda options: _json_request(
            auth_context,
            method="POST",
            path="/lease",
            payload=_lease_payload(
                store,
                operations=options["operations"],  # type: ignore[arg-type]
                wait_ms=options["wait_ms"],  # type: ignore[arg-type]
            ),
        ),
        exact_route_failure=exact_route_failure,
        exact_route_success=exact_route_success,
    )


def _retry_pending_result(
    store: GuardStore,
    auth_context: dict[str, object],
    state: dict[str, object],
) -> bool:
    pending = state.get("pending_result")
    if not isinstance(pending, dict):
        return False
    job = pending.get("job")
    payload = pending.get("payload")
    if not isinstance(job, dict) or not isinstance(payload, dict):
        state.pop("pending_result", None)
        state.pop("active_job", None)
        _save_state(store, state)
        return False
    if _pending_result_is_stale(job):
        _LOGGER.warning("Guard command dropped stale pending result.")
        state.pop("pending_result", None)
        state.pop("active_job", None)
        state["state"] = "idle"
        state["last_error"] = None
        _save_state(store, state)
        return False
    try:
        _post_result(auth_context, job, payload)
    except urllib.error.HTTPError as error:
        if error.code != 401:
            raise
        _LOGGER.warning("Pending Guard result 401, attempting OAuth refresh retry.")
        refreshed_auth_context = _resolve_command_queue_auth_context(store, force_refresh=True)
        _post_result(refreshed_auth_context, job, payload)
    state.pop("pending_result", None)
    state.pop("active_job", None)
    state.update(
        {
            "state": "idle",
            "last_result_at": _now(),
            "last_error": None,
            "last_poll_was_empty": False,
        }
    )
    _save_state(store, state)
    return True


def _resolve_command_queue_auth_context(
    store: GuardStore,
    *,
    force_refresh: bool = False,
) -> dict[str, object]:
    try:
        if force_refresh:
            return _resolve_guard_sync_auth_context(store, force_refresh=True)
        return _resolve_guard_sync_auth_context(store)
    except (GuardSyncAuthorizationExpiredError, GuardSyncNotConfiguredError):
        repair = _repair_guard_cloud_authorization(store)
        if not repair["existing_sign_in_valid"] and not repair["repaired_storage"]:
            raise
        if force_refresh:
            return _resolve_guard_sync_auth_context(store, force_refresh=True)
        return _resolve_guard_sync_auth_context(store)


def _record_exact_route_failure(state: dict[str, object], error: urllib.error.HTTPError) -> None:
    state["exact_review_route_error"] = _redacted_error(error)
    state["exact_review_route_error_at"] = _now()
    _LOGGER.warning("Guard Cloud Review exact command route is unavailable; generic queue polling continues.")


def _clear_exact_route_failure(state: dict[str, object]) -> None:
    state.pop("exact_review_route_error", None)
    state.pop("exact_review_route_error_at", None)


def _record_leased_job(
    store: GuardStore, state: dict[str, object], item: dict[str, object], observer: Observer
) -> None:
    state.update(
        {
            "state": "leased",
            "last_lease_at": _now(),
            "active_job": item,
            "last_poll_was_empty": False,
        }
    )
    _save_state(store, state)
    if uses_exact_transport(item):
        exact_cloud_review_lifecycle.observe_exact_review_lease(observer, item, occurred_at=str(state["last_lease_at"]))


def poll_command_queue_once(
    store: GuardStore, context: HarnessContext, *, observer: Observer = None
) -> dict[str, object]:
    if not command_queue_enabled(store):
        state = _load_state(store)
        state.update(
            {
                "state": "disabled",
                "last_error": None,
                "active_job": None,
            }
        )
        _save_state(store, state)
        return command_queue_status(store)
    auth_context = _resolve_command_queue_auth_context(store)
    state = _load_state(store)
    state.update(
        {
            "state": "polling",
            "last_poll_at": _now(),
            "last_error": None,
            "last_poll_was_empty": False,
        }
    )
    _save_state(store, state)
    if _retry_pending_result(store, auth_context, state):
        return command_queue_status(store)
    item = _lease_next_job(store, auth_context, state=state)
    if item is None:
        empty_at = _now()
        state.update(
            {
                "state": "idle",
                "last_empty_poll_at": empty_at,
                "last_poll_at": empty_at,
                "last_poll_was_empty": True,
            }
        )
        _save_state(store, state)
        maybe_auto_update(store, context)
        return command_queue_status(store)
    _record_leased_job(store, state, item, observer)
    try:
        _heartbeat(auth_context, item)
    except urllib.error.HTTPError as error:
        if error.code != 401:
            raise
        _LOGGER.warning("Guard heartbeat 401, attempting OAuth refresh retry.")
        auth_context = _resolve_command_queue_auth_context(store, force_refresh=True)
        state["state"] = "auth_expired"
        _save_state(store, state)
        try:
            _heartbeat(auth_context, item)
        except Exception:
            state.pop("active_job", None)
            state.update({"state": "error", "last_error": "Guard command heartbeat failed."})
            _save_state(store, state)
            raise
    except Exception:
        state.pop("active_job", None)
        state.update({"state": "error", "last_error": "Guard command heartbeat failed."})
        _save_state(store, state)
        raise
    try:
        authorized = authorize_command_queue_job(
            store,
            item,
            schema_versions=COMMAND_OPERATION_SCHEMA_VERSIONS,
        )
    except CommandCapabilityError as error:
        audit_command_decision(
            store,
            "cloud_command.rejected",
            job=item,
            reason=error.code,
        )
        execution: dict[str, object] = {
            "failureCode": error.code,
            "failureMessage": "The local Guard command capability rejected this job.",
        }
    else:
        if not consume_local_command_approval(store, authorized):
            pending = register_pending_command(store, authorized, item)
            execution = {
                "waitingLocalConfirm": True,
                "operation": authorized.operation,
                "jobId": authorized.identity["id"],
                "approveCommand": pending["approveCommand"],
            }
            audit_command_decision(
                store,
                "cloud_command.waiting_local_approval",
                job=item,
                reason="local_approval_required",
            )
        else:
            mark_command_job_consumed(store, authorized)
            audit_command_decision(
                store,
                "cloud_command.accepted",
                job=item,
                reason="capability_and_job_valid",
            )
            try:
                _LOGGER.info(
                    "Guard command leased: job_id=%s operation=%s",
                    _job_id(item),
                    command_job_operation(item),
                )
                execution = _execute_job(item, context, store)
                observe_execution(observer, item, execution, occurred_at=_now())
            except Exception as error:
                _LOGGER.warning(
                    "Guard command execution failed: job_id=%s error=%s",
                    _job_id(item),
                    _redacted_error(error),
                )
                execution = {
                    "failureCode": "execution_error",
                    "failureMessage": _redacted_error(error),
                }
    payload = _result_payload(item, execution)
    try:
        _heartbeat(auth_context, item)
        _post_result(auth_context, item, payload)
    except urllib.error.HTTPError as error:
        if error.code != 401:
            _LOGGER.warning("Guard command result upload failed: job_id=%s", _job_id(item))
            state.update(
                {
                    "state": "result_pending",
                    "pending_result": {"job": item, "payload": payload, "recorded_at": _now()},
                }
            )
            _save_state(store, state)
            raise
        _LOGGER.warning("Guard result 401, attempting OAuth refresh retry.")
        auth_context = _resolve_command_queue_auth_context(store, force_refresh=True)
        state["state"] = "auth_expired"
        _save_state(store, state)
        try:
            _heartbeat(auth_context, item)
            _post_result(auth_context, item, payload)
        except Exception:
            _LOGGER.warning("Guard command result upload failed: job_id=%s", _job_id(item))
            state.update(
                {
                    "state": "result_pending",
                    "pending_result": {"job": item, "payload": payload, "recorded_at": _now()},
                }
            )
            _save_state(store, state)
            raise
    except Exception:
        _LOGGER.warning("Guard command result upload failed: job_id=%s", _job_id(item))
        state.update(
            {
                "state": "result_pending",
                "pending_result": {"job": item, "payload": payload, "recorded_at": _now()},
            }
        )
        _save_state(store, state)
        raise
    state.pop("active_job", None)
    state.pop("pending_result", None)
    state.update({"state": "idle", "last_result_at": _now(), "last_poll_was_empty": False})
    _save_state(store, state)
    audit_command_decision(
        store,
        "cloud_command.result",
        job=item,
        reason=str(payload.get("status") or "unknown"),
    )
    _LOGGER.info("Guard command completed: job_id=%s status=%s", _job_id(item), payload.get("status"))
    if uses_exact_transport(item):
        exact_cloud_review_lifecycle.observe_exact_review_result(
            observer, item, occurred_at=str(state["last_result_at"]), status=payload.get("status")
        )
    return command_queue_status(store)


def command_queue_loop(
    store: GuardStore,
    context: HarnessContext,
    *,
    stop_event: Any,
) -> None:
    if not command_queue_enabled(store):
        return
    poll_interval = _env_float(COMMAND_QUEUE_POLL_INTERVAL_ENV, _DEFAULT_POLL_INTERVAL_SECONDS)
    error_backoff = _env_float(COMMAND_QUEUE_ERROR_BACKOFF_ENV, _DEFAULT_ERROR_BACKOFF_SECONDS)
    empty_streak = 0
    error_streak = 0
    while not stop_event.is_set():
        wait_seconds = poll_interval
        try:
            status = poll_command_queue_once(store, context)
            error_streak = 0
            if status.get("last_poll_was_empty") is True:
                empty_streak += 1
                if _command_queue_long_poll_enabled():
                    wait_seconds = min(
                        poll_interval,
                        _LONG_POLL_EMPTY_MIN_WAIT_SECONDS * (2 ** min(empty_streak - 1, 8)),
                    )
                else:
                    wait_seconds = _retry_wait_seconds(poll_interval, error_backoff, empty_streak)
            else:
                empty_streak = 0
        except GuardSyncAuthorizationExpiredError as error:
            empty_streak = 0
            error_streak += 1
            _save_state(
                store,
                {
                    **_load_state(store),
                    "state": "auth_expired",
                    "last_error": _redacted_error(error),
                    "last_poll_at": _now(),
                },
            )
            wait_seconds = _retry_wait_seconds(poll_interval, error_backoff, error_streak)
        except GuardSyncNotConfiguredError as error:
            empty_streak = 0
            error_streak += 1
            _save_state(
                store,
                {
                    **_load_state(store),
                    "state": "not_configured",
                    "last_error": _redacted_error(error),
                    "last_poll_at": _now(),
                },
            )
            wait_seconds = _retry_wait_seconds(poll_interval, error_backoff, error_streak)
        except Exception as error:
            empty_streak = 0
            error_streak += 1
            _save_state(
                store,
                {
                    **_load_state(store),
                    "state": "error",
                    "last_error": _redacted_error(error),
                    "last_poll_at": _now(),
                },
            )
            wait_seconds = _retry_wait_seconds(poll_interval, error_backoff, error_streak)
        if stop_event.wait(wait_seconds):
            return


def default_command_context(store: GuardStore) -> HarnessContext:
    return HarnessContext(
        home_dir=Path.home().resolve(),
        workspace_dir=None,
        guard_home=store.guard_home,
    )
