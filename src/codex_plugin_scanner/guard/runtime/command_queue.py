from __future__ import annotations

import logging
import urllib.error
from collections.abc import Callable
from functools import partial
from typing import Any

from ...version import __version__  # noqa: F401 - public compatibility export
from ..adapters.base import HarnessContext
from ..review_verification_keyring import review_verification_keyring_ready
from ..store import GuardStore
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
    execute_guard_command_job,
)
from .command_queue_activation import (
    command_queue_is_enabled,
)
from .command_queue_activation import (
    command_queue_lease_wait_ms as _command_queue_lease_wait_ms,
)
from .command_queue_auth import resolve_command_queue_auth_context
from .command_queue_authority import authorize_transport_command_queue_job as authorize_command_queue_job
from .command_queue_http import format_redacted_error as _redacted_error
from .command_queue_http import request_json
from .command_queue_http import request_json as _json_request
from .command_queue_loop import (
    COMMAND_QUEUE_ERROR_BACKOFF_ENV,  # noqa: F401 - public compatibility export
    COMMAND_QUEUE_POLL_INTERVAL_ENV,  # noqa: F401 - public compatibility export
    run_command_queue_loop,
)
from .command_queue_protocol import command_api_url as _command_api_url  # noqa: F401
from .command_queue_protocol import job_id as _job_id
from .command_queue_protocol import lease_id as _lease_id
from .command_queue_protocol import pending_result_is_stale as _pending_result_is_stale
from .command_queue_protocol import result_payload as _result_payload
from .command_queue_protocol import retry_wait_seconds as _retry_wait_seconds  # noqa: F401
from .command_queue_state import (
    COMMAND_QUEUE_ENABLED_ENV,
    COMMAND_QUEUE_LEASE_WAIT_MS_ENV,  # noqa: F401 - public compatibility export
    COMMAND_QUEUE_STATE_KEY,  # noqa: F401 - public compatibility export
    command_queue_lease_payload,
    default_command_context,  # noqa: F401 - public compatibility export
    repair_command_queue_state,  # noqa: F401 - public compatibility export
)
from .command_queue_state import (
    clear_exact_route_failure as _clear_exact_route_failure,
)
from .command_queue_state import (
    command_queue_now as _now,
)
from .command_queue_state import (
    command_queue_status as _state_command_queue_status,
)
from .command_queue_state import (
    load_command_queue_state as _load_state,
)
from .command_queue_state import (
    record_exact_route_failure as _record_exact_route_failure,
)
from .command_queue_state import (
    save_command_queue_state as _save_state,
)
from .exact_cloud_review import (
    EXACT_CLOUD_REVIEW_OPERATION,
    EXACT_CLOUD_REVIEW_PROTOCOL_VERSION,
    exact_cloud_review_operations,
)
from .exact_cloud_review_transport import (
    EXACT_CLOUD_REVIEW_COMMAND_API_BASE,
    lease_next_job,
    uses_exact_transport,
)
from .runner import _resolve_guard_sync_auth_context, repair_guard_cloud_connect_storage

_LOGGER = logging.getLogger(__name__)


def command_queue_operations(store: GuardStore) -> tuple[str, ...]:
    generic = tuple(
        operation for operation in command_capability_operations(store) if operation != EXACT_CLOUD_REVIEW_OPERATION
    )
    return generic + tuple(operation for operation in exact_cloud_review_operations(store) if operation not in generic)


def lease_ready_operations(store: GuardStore) -> tuple[str, ...]:
    operations = command_queue_operations(store)
    if review_verification_keyring_ready(store):
        return operations
    return tuple(operation for operation in operations if operation != EXACT_CLOUD_REVIEW_OPERATION)


def command_queue_enabled(store: GuardStore | None = None, environ: dict[str, str] | None = None) -> bool:
    return command_queue_is_enabled(
        store,
        environ,
        enabled_env=COMMAND_QUEUE_ENABLED_ENV,
        environment_allows_queue=command_environment_allows_queue,
        operations=command_queue_operations,
        logger=_LOGGER,
    )


def command_queue_status(store: GuardStore) -> dict[str, object]:
    return _state_command_queue_status(
        store,
        enabled=command_queue_enabled,
        operation_resolver=command_queue_operations,
        capability_status=command_capability_status,
    )


def _lease_payload(
    store: GuardStore,
    *,
    operations: tuple[str, ...] | None = None,
    wait_ms: int | None = None,
) -> dict[str, object]:
    return command_queue_lease_payload(
        store,
        operations=operations,
        wait_ms=wait_ms,
        operation_resolver=command_queue_operations,
    )


def _exact_json_request(
    auth_context: dict[str, object],
    *,
    method: str,
    path: str,
    payload: dict[str, object],
) -> dict[str, object]:
    return request_json(
        auth_context,
        method=method,
        path=path,
        payload=payload,
        base_path=EXACT_CLOUD_REVIEW_COMMAND_API_BASE,
    )


def _resolve_command_queue_auth_context(
    store: GuardStore,
    *,
    force_refresh: bool = False,
) -> dict[str, object]:
    return resolve_command_queue_auth_context(
        store,
        force_refresh=force_refresh,
        resolve_auth_context=_resolve_guard_sync_auth_context,
        repair_authorization=repair_guard_cloud_connect_storage,
    )


def _execute_job(job: dict[str, object], context: HarnessContext, store: GuardStore) -> dict[str, object]:
    return execute_guard_command_job(job, context=context, store=store, now=_now)


def _heartbeat(auth_context: dict[str, object], job: dict[str, object]) -> None:
    request = _exact_json_request if uses_exact_transport(job) else _json_request
    path = f"/{_job_id(job)}/ack" if uses_exact_transport(job) else f"/{_job_id(job)}/heartbeat"
    payload: dict[str, object] = {"leaseId": _lease_id(job)}
    if uses_exact_transport(job):
        payload["protocolVersion"] = EXACT_CLOUD_REVIEW_PROTOCOL_VERSION
    request(
        auth_context,
        method="POST",
        path=path,
        payload=payload,
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
    operations = lease_ready_operations(store)
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


def _record_leased_job(store: GuardStore, state: dict[str, object], item: dict[str, object]) -> None:
    state.update(
        {
            "state": "leased",
            "last_lease_at": _now(),
            "active_job": item,
            "last_poll_was_empty": False,
        }
    )
    _save_state(store, state)


def _lease_job_with_401_retry(
    store: GuardStore,
    state: dict[str, object],
    auth_context: dict[str, object],
) -> dict[str, object] | None:
    try:
        return _lease_next_job(store, auth_context, state=state)
    except urllib.error.HTTPError as error:
        if error.code != 401:
            raise
    _LOGGER.warning("Guard command lease 401, attempting OAuth refresh retry.")
    refreshed_auth_context = _resolve_command_queue_auth_context(store, force_refresh=True)
    return _lease_next_job(store, refreshed_auth_context, state=state)


def poll_command_queue_once(store: GuardStore, context: HarnessContext) -> dict[str, object]:
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
    item = _lease_job_with_401_retry(store, state, auth_context)
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
    auth_context = _resolve_command_queue_auth_context(store)
    _record_leased_job(store, state, item)
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
                _LOGGER.info("Guard command leased.")
                execution = _execute_job(item, context, store)
            except Exception as error:
                _LOGGER.warning(
                    "Guard command execution failed: error=%s",
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
            _LOGGER.warning("Guard command result upload failed.")
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
            _LOGGER.warning("Guard command result upload failed.")
            state.update(
                {
                    "state": "result_pending",
                    "pending_result": {"job": item, "payload": payload, "recorded_at": _now()},
                }
            )
            _save_state(store, state)
            raise
    except Exception:
        _LOGGER.warning("Guard command result upload failed.")
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
    _LOGGER.info("Guard command completed.")
    return command_queue_status(store)


def command_queue_loop(
    store: GuardStore,
    context: HarnessContext,
    *,
    stop_event: Any,
) -> None:
    run_command_queue_loop(
        store,
        context,
        stop_event=stop_event,
        enabled=command_queue_enabled,
        poll_once=poll_command_queue_once,
        load_state=_load_state,
        save_state=_save_state,
        format_error=_redacted_error,
        now=_now,
    )
