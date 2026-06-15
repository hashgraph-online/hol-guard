"""Guard Cloud command queue client for local daemon workers."""

from __future__ import annotations

import json
import logging
import os
import urllib.error
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlunparse

from ...version import __version__
from ..adapters.base import HarnessContext
from ..store import GuardStore
from .command_executors import (
    COMMAND_OPERATION_SCHEMA_VERSIONS,
    SUPPORTED_COMMAND_OPERATIONS,
    _local_request_snapshot_items,
    command_job_operation,
    execute_guard_command_job,
)
from .runner import (
    GuardSyncAuthorizationExpiredError,
    GuardSyncNotConfiguredError,
    _guard_sync_request,
    _resolve_guard_sync_auth_context,
    _sync_http_error_message,
    _sync_url_error_message,
    _urlopen_json_with_timeout_retry,
)

COMMAND_QUEUE_STATE_KEY = "guard_command_queue_state"
COMMAND_QUEUE_ENABLED_ENV = "GUARD_CLOUD_COMMAND_QUEUE_ENABLED"
COMMAND_QUEUE_LEASE_WAIT_MS_ENV = "GUARD_CLOUD_COMMAND_QUEUE_LEASE_WAIT_MS"
COMMAND_QUEUE_POLL_INTERVAL_ENV = "GUARD_CLOUD_COMMAND_QUEUE_POLL_INTERVAL_SECONDS"
COMMAND_QUEUE_ERROR_BACKOFF_ENV = "GUARD_CLOUD_COMMAND_QUEUE_ERROR_BACKOFF_SECONDS"

_DEFAULT_LEASE_WAIT_MS = 25_000
_DEFAULT_POLL_INTERVAL_SECONDS = 2.0
_DEFAULT_ERROR_BACKOFF_SECONDS = 30.0
_REQUEST_TIMEOUT_SECONDS = 35
_RETRY_TIMEOUT_SECONDS = 60
_LOGGER = logging.getLogger(__name__)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def command_queue_enabled(environ: dict[str, str] | None = None) -> bool:
    source = os.environ if environ is None else environ
    value = source.get(COMMAND_QUEUE_ENABLED_ENV)
    if value is None:
        return True
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"", "0", "false", "no", "off", "disabled"}:
        return False
    _LOGGER.warning("Ignoring unrecognized %s value; command queue disabled.", COMMAND_QUEUE_ENABLED_ENV)
    return False


def _env_float(name: str, default: float) -> float:
    value = os.environ.get(name, "").strip()
    if not value:
        return default
    try:
        parsed = float(value)
    except ValueError:
        return default
    return parsed if parsed >= 0 else default


def _env_int(name: str, default: int) -> int:
    value = os.environ.get(name, "").strip()
    if not value:
        return default
    try:
        parsed = int(value)
    except ValueError:
        return default
    return parsed if parsed >= 0 else default


def _command_api_url(sync_url: object, path: str) -> str:
    parsed = urlparse(str(sync_url))
    base_path = "/api/guard/commands"
    normalized_path = path if path.startswith("/") else f"/{path}"
    return urlunparse((parsed.scheme, parsed.netloc, f"{base_path}{normalized_path}", "", "", ""))


def _redacted_error(error: BaseException) -> str:
    if isinstance(error, urllib.error.HTTPError):
        try:
            return _sync_http_error_message(error)
        except Exception:
            return f"HTTP Error {error.code}: {error.reason}"
    if isinstance(error, OSError):
        return _sync_url_error_message(error)
    return str(error)


def _json_request(
    auth_context: dict[str, object],
    *,
    method: str,
    path: str,
    payload: dict[str, object],
) -> dict[str, object]:
    request_url = _command_api_url(auth_context["sync_url"], path)
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
    return {
        "enabled": command_queue_enabled(),
        "configured": profile is not None,
        "state": state.get("state", "idle"),
        "last_poll_at": state.get("last_poll_at"),
        "last_lease_at": state.get("last_lease_at"),
        "last_empty_poll_at": state.get("last_empty_poll_at"),
        "last_result_at": state.get("last_result_at"),
        "last_error": state.get("last_error"),
        "last_poll_was_empty": bool(state.get("last_poll_was_empty")),
        "active_job": state.get("active_job"),
        "pending_result": state.get("pending_result"),
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


def _oauth_metadata(store: GuardStore) -> tuple[str, str]:
    credentials = store.get_oauth_local_credentials(allow_primary=False)
    if not isinstance(credentials, dict):
        raise GuardSyncNotConfiguredError("Guard command queue requires OAuth credentials.")
    machine_id = credentials.get("machine_id")
    workspace_id = credentials.get("workspace_id")
    if not isinstance(machine_id, str) or not machine_id:
        raise GuardSyncNotConfiguredError("Guard command queue requires a machine-bound OAuth grant.")
    if not isinstance(workspace_id, str) or not workspace_id:
        raise GuardSyncNotConfiguredError("Guard command queue requires a workspace-bound OAuth grant.")
    return machine_id, workspace_id


def _lease_payload(store: GuardStore) -> dict[str, object]:
    machine_id, workspace_id = _oauth_metadata(store)
    return {
        "workspaceId": workspace_id,
        "deviceId": machine_id,
        "daemonVersion": __version__,
        "capabilities": {
            "operations": list(SUPPORTED_COMMAND_OPERATIONS),
            "schemaVersions": dict(COMMAND_OPERATION_SCHEMA_VERSIONS),
        },
        "localRequestsSnapshot": _local_requests_snapshot(store),
        "maxJobs": 1,
        "waitMs": _env_int(COMMAND_QUEUE_LEASE_WAIT_MS_ENV, _DEFAULT_LEASE_WAIT_MS),
    }


def _local_requests_snapshot(store: GuardStore) -> dict[str, object]:
    try:
        return {"requests": _local_request_snapshot_items(store)}
    except Exception as exc:
        _LOGGER.warning("Guard command local request snapshot failed: %s", _redacted_error(exc))
        return {"requests": []}


def _job_id(job: dict[str, object]) -> str:
    job_id = job.get("id")
    if not isinstance(job_id, str) or not job_id:
        raise RuntimeError("Guard command job is missing an id.")
    return job_id


def _lease_id(job: dict[str, object]) -> str:
    lease_id = job.get("leaseId")
    if not isinstance(lease_id, str) or not lease_id:
        raise RuntimeError("Guard command job is missing a lease id.")
    return lease_id


def _execute_job(job: dict[str, object], context: HarnessContext, store: GuardStore) -> dict[str, object]:
    return execute_guard_command_job(job, context=context, store=store, now=_now)


def _heartbeat(auth_context: dict[str, object], job: dict[str, object]) -> None:
    _json_request(
        auth_context,
        method="POST",
        path=f"/{_job_id(job)}/heartbeat",
        payload={"leaseId": _lease_id(job)},
    )


def _result_payload(job: dict[str, object], execution: dict[str, object]) -> dict[str, object]:
    if execution.get("waitingLocalConfirm") is True:
        sanitized_execution = dict(execution)
        sanitized_execution.pop("waitingLocalConfirm", None)
        return {
            "leaseId": _lease_id(job),
            "idempotencyKey": f"{_job_id(job)}:{_lease_id(job)}:waiting_local_confirm",
            "status": "waiting_local_confirm",
            "result": sanitized_execution,
        }
    failure_code = execution.get("failureCode")
    if isinstance(failure_code, str) and failure_code:
        payload: dict[str, object] = {
            "leaseId": _lease_id(job),
            "idempotencyKey": f"{_job_id(job)}:{_lease_id(job)}:failed",
            "status": "failed",
            "failureCode": failure_code,
            "failureMessage": str(execution.get("failureMessage") or failure_code),
        }
        return payload
    return {
        "leaseId": _lease_id(job),
        "idempotencyKey": f"{_job_id(job)}:{_lease_id(job)}:succeeded",
        "status": "succeeded",
        "result": execution,
    }


def _post_result(auth_context: dict[str, object], job: dict[str, object], payload: dict[str, object]) -> None:
    _json_request(
        auth_context,
        method="POST",
        path=f"/{_job_id(job)}/result",
        payload=payload,
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
    _post_result(auth_context, job, payload)
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


def poll_command_queue_once(store: GuardStore, context: HarnessContext) -> dict[str, object]:
    auth_context = _resolve_guard_sync_auth_context(store)
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

    lease_response = _json_request(
        auth_context,
        method="POST",
        path="/lease",
        payload=_lease_payload(store),
    )
    item = lease_response.get("item")
    if not isinstance(item, dict):
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
        return command_queue_status(store)

    state.update(
        {
            "state": "leased",
            "last_lease_at": _now(),
            "active_job": item,
            "last_poll_was_empty": False,
        }
    )
    _save_state(store, state)
    try:
        _heartbeat(auth_context, item)
    except Exception:
        state.pop("active_job", None)
        state.update({"state": "error", "last_error": "Guard command heartbeat failed."})
        _save_state(store, state)
        raise
    try:
        _LOGGER.info("Guard command leased: job_id=%s operation=%s", _job_id(item), command_job_operation(item))
        execution = _execute_job(item, context, store)
    except Exception as error:
        _LOGGER.warning("Guard command execution failed: job_id=%s error=%s", _job_id(item), _redacted_error(error))
        execution = {
            "failureCode": "execution_error",
            "failureMessage": _redacted_error(error),
        }
    payload = _result_payload(item, execution)
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
    state.pop("active_job", None)
    state.pop("pending_result", None)
    state.update({"state": "idle", "last_result_at": _now(), "last_poll_was_empty": False})
    _save_state(store, state)
    _LOGGER.info("Guard command completed: job_id=%s status=%s", _job_id(item), payload.get("status"))
    return command_queue_status(store)


def command_queue_loop(
    store: GuardStore,
    context: HarnessContext,
    *,
    stop_event: Any,
) -> None:
    if not command_queue_enabled():
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
                wait_seconds = min(error_backoff, poll_interval * (2 ** max(0, empty_streak - 1)))
            else:
                empty_streak = 0
        except GuardSyncAuthorizationExpiredError as error:
            _save_state(
                store,
                {
                    **_load_state(store),
                    "state": "auth_expired",
                    "last_error": _redacted_error(error),
                    "last_poll_at": _now(),
                },
            )
            return
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
            wait_seconds = min(error_backoff, poll_interval * (2 ** max(0, error_streak - 1)))
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
            wait_seconds = min(error_backoff, poll_interval * (2 ** max(0, error_streak - 1)))
        if stop_event.wait(wait_seconds):
            return


def default_command_context(store: GuardStore) -> HarnessContext:
    return HarnessContext(
        home_dir=Path.home().resolve(),
        workspace_dir=None,
        guard_home=store.guard_home,
    )
