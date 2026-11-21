from __future__ import annotations

import json
import logging
import sqlite3
import urllib.error
from collections.abc import Callable
from contextlib import AbstractContextManager, nullcontext
from functools import partial
from typing import Any

from ...version import __version__
from ..harness_context import HarnessContext
from ..review_verification_keyring import review_verification_keyring_ready
from ..store import GuardStore
from . import cloud_command_lease
from .auto_update import maybe_auto_update
from .cloud_policy_revision import cloud_policy_store_key, observe_cloud_policy_revision
from .command_capability import (
    AuthorizedCommandJob,
    CommandCapabilityError,
    CommandCapabilityUnavailableError,
    audit_command_decision,
    command_capability_operations,
    command_capability_status,
    command_environment_allows_queue,
    command_identity_digest,
    consume_local_command_approval,
    register_pending_command,
)
from .command_executors import COMMAND_OPERATION_SCHEMA_VERSIONS, execute_guard_command_job
from .command_queue_activation import command_queue_is_enabled
from .command_queue_activation import command_queue_lease_wait_ms as _command_queue_lease_wait_ms
from .command_queue_auth import reuse_command_queue_auth_context
from .command_queue_authority import authorize_transport_command_queue_job as authorize_command_queue_job
from .command_queue_authority import command_queue_oauth_target
from .command_queue_authorization import start_command_authorization, start_overlapped_acknowledgement
from .command_queue_drain import REVIEW_LEASE_BATCH_SIZE, ReviewLeaseBatch, start_review_drains, with_review_drains
from .command_queue_http import format_redacted_error as _redacted_error
from .command_queue_http import request_json
from .command_queue_http import request_json as _json_request  # noqa: F401 - test doubles replay over it
from .command_queue_lease_ready import lane_lease_ready_operations
from .command_queue_loop import (
    COMMAND_QUEUE_ERROR_BACKOFF_ENV,  # noqa: F401 - public compatibility export
    COMMAND_QUEUE_POLL_INTERVAL_ENV,  # noqa: F401 - public compatibility export
    run_command_queue_loop,
)
from .command_queue_pending import hold_pending_result as _hold_pending_result
from .command_queue_pending import retry_pending_result
from .command_queue_protocol import command_api_url as _command_api_url
from .command_queue_protocol import job_id as _job_id
from .command_queue_protocol import lease_id as _lease_id
from .command_queue_protocol import result_payload as _result_payload
from .command_queue_protocol import retry_wait_seconds as _retry_wait_seconds  # noqa: F401
from .command_queue_results import drop_refused_result, post_result_unless_refused
from .command_queue_settle import SettleCalls, settle_authorized_job
from .command_queue_settle_slots import settle_slots
from .command_queue_state import (
    COMMAND_QUEUE_ENABLED_ENV,
    COMMAND_QUEUE_LEASE_WAIT_MS_ENV,  # noqa: F401 - public compatibility export
    COMMAND_QUEUE_STATE_KEY,  # noqa: F401 - public compatibility export
    command_queue_brief_status,
    default_command_context,  # noqa: F401 - public compatibility export
    lane_exact_lease_batch_limit,
    record_exact_lease_batch_limit,
    repair_command_queue_state,  # noqa: F401 - public compatibility export
)
from .command_queue_state import clear_exact_route_failure as _clear_exact_route_failure
from .command_queue_state import command_queue_now as _now
from .command_queue_state import command_queue_status as _state_command_queue_status
from .command_queue_state import current_command_queue_lane as _current_lane
from .command_queue_state import load_command_queue_state as _load_state
from .command_queue_state import record_exact_route_failure as _record_exact_route_failure
from .command_queue_state import save_command_queue_state as _save_state
from .command_queue_state import transition_command_queue_state as _transition
from .exact_cloud_review import (
    EXACT_CLOUD_REVIEW_OPERATION,
    exact_cloud_review_operations,
)
from .exact_cloud_review_transport import (
    EXACT_CLOUD_REVIEW_COMMAND_API_BASE,
    LeaseCall,
    lease_next_job,
    uses_exact_transport,
)
from .native_workspace_review_queue import is_native_workspace_review_job, native_workspace_review_transport_candidate
from .runner import _resolve_guard_sync_auth_context, repair_guard_cloud_connect_storage

_LOGGER = logging.getLogger(__name__)


def command_queue_operations(store: GuardStore) -> tuple[str, ...]:
    generic = _generic_command_queue_operations(store)
    return generic + tuple(operation for operation in exact_cloud_review_operations(store) if operation not in generic)


def lease_ready_operations(store: GuardStore) -> tuple[str, ...]:
    operations = command_queue_operations(store)
    if review_verification_keyring_ready(store) or native_workspace_review_transport_candidate(store):
        return operations
    return tuple(operation for operation in operations if operation != EXACT_CLOUD_REVIEW_OPERATION)


def _generic_command_queue_operations(store: GuardStore) -> tuple[str, ...]:
    return tuple(
        operation for operation in command_capability_operations(store) if operation != EXACT_CLOUD_REVIEW_OPERATION
    )


def command_queue_enabled(store: GuardStore | None = None, environ: dict[str, str] | None = None) -> bool:
    return command_queue_is_enabled(
        store,
        environ,
        enabled_env=COMMAND_QUEUE_ENABLED_ENV,
        environment_allows_queue=command_environment_allows_queue,
        operations=_generic_command_queue_operations,
        logger=_LOGGER,
    )


def command_queue_should_poll(store: GuardStore | None = None, environ: dict[str, str] | None = None) -> bool:
    """Poll when generic commands or Cloud Review receive jobs are available."""

    if store is None or not command_environment_allows_queue(environ):
        return False
    return command_queue_enabled(store) or bool(lease_ready_operations(store))


def command_queue_status(store: GuardStore) -> dict[str, object]:
    return _state_command_queue_status(
        store,
        enabled=command_queue_enabled,
        operation_resolver=command_queue_operations,
        capability_status=command_capability_status,
    )


def _exact_json_request(
    auth_context: dict[str, object],
    *,
    method: str,
    path: str,
    payload: dict[str, object],
) -> dict[str, object]:
    """Exact-route request the test doubles replay native leases and reports over."""
    return request_json(
        auth_context, method=method, path=path, payload=payload, base_path=EXACT_CLOUD_REVIEW_COMMAND_API_BASE
    )


def _resolve_command_queue_auth_context(
    store: GuardStore,
    *,
    force_refresh: bool = False,
) -> dict[str, object]:
    return reuse_command_queue_auth_context(
        store,
        force_refresh=force_refresh,
        resolve_auth_context=_resolve_guard_sync_auth_context,
        repair_authorization=repair_guard_cloud_connect_storage,
    )


def _execute_job(job: dict[str, object], context: HarnessContext, store: GuardStore) -> dict[str, object]:
    with _review_connection_scope(store, job):
        return execute_guard_command_job(job, context=context, store=store, now=_now)


def _review_connection_scope(store: GuardStore, job: dict[str, object]) -> AbstractContextManager[None]:
    # A Review decision makes dozens of store calls; opening a connection for
    # each one (and paying its schema load) cost more than the work under
    # concurrent drains. Each call still commits on its own. The shared scope
    # holds the storage gate, so jobs that can wait on outside work, such as
    # an update, keep opening a connection per call.
    return store.connection_scope() if uses_exact_transport(job) else nullcontext()


def _heartbeat(auth_context: dict[str, object], job: dict[str, object]) -> None:
    cloud_command_lease.cloud_command_report(
        auth_context, job_id=_job_id(job), exact=uses_exact_transport(job), kind="ack", lease_id=_lease_id(job)
    )


def _post_result(auth_context: dict[str, object], job: dict[str, object], payload: dict[str, object]) -> None:
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    cloud_command_lease.cloud_command_report(
        auth_context, job_id=_job_id(job), exact=uses_exact_transport(job), kind="result", body=body
    )


def _lease_next_job(
    store: GuardStore,
    auth_context: dict[str, object],
    *,
    state: dict[str, object] | None = None,
    max_jobs: int = 1,
    on_extra_jobs: Callable[[list[dict[str, object]]], object] | None = None,
) -> dict[str, object] | None:
    lane = _current_lane()
    ready = lane_lease_ready_operations(store, drain=lane.is_drain, check=lease_ready_operations)
    scope = lane.lease_scope(ready, _command_queue_lease_wait_ms())
    if scope is None:
        return None
    operations, wait_ms = scope
    exact_route_failure: Callable[[urllib.error.HTTPError], None] | None = None
    exact_route_success: Callable[[], None] | None = None
    observe_lease_batch_limit: Callable[[int], None] | None = None
    if state is not None:
        exact_route_failure = partial(_record_exact_route_failure, state)
        exact_route_success = partial(_clear_exact_route_failure, state)
        observe_lease_batch_limit = partial(record_exact_lease_batch_limit, store, state)
    return lease_next_job(
        operations=operations,
        wait_ms=wait_ms,
        lease=partial(_native_lease, store, auth_context),
        lease_url=lambda route: _command_api_url(auth_context.get("sync_url"), "/lease", base_path=route),
        exact_route_failure=exact_route_failure,
        exact_route_success=exact_route_success,
        observe_response=partial(observe_cloud_policy_revision, cloud_policy_store_key(store)),
        max_jobs=max_jobs,
        on_extra_jobs=on_extra_jobs,
        observe_lease_batch_limit=observe_lease_batch_limit,
    )


def _native_lease(store: GuardStore, auth_context: dict[str, object], call: LeaseCall) -> dict[str, object]:
    """Lease through the native runtime, for this device and workspace."""

    device_id, workspace_id = command_queue_oauth_target(store)
    return cloud_command_lease.cloud_command_lease(
        auth_context,
        {
            **call,
            "workspaceId": workspace_id,
            "deviceId": device_id,
            "daemonVersion": __version__,
            "schemaVersions": dict(COMMAND_OPERATION_SCHEMA_VERSIONS),
        },
    )


def _retry_pending_result(store: GuardStore, auth_context: dict[str, object], state: dict[str, object]) -> bool:
    return retry_pending_result(
        store, auth_context, state, post_result=_post_result, resolve_auth=_resolve_command_queue_auth_context
    )


def _record_leased_job(store: GuardStore, state: dict[str, object], item: dict[str, object]) -> None:
    state.update({"state": "leased", "last_lease_at": _now(), "active_job": item, "last_poll_was_empty": False})
    _save_state(store, state)


def _lease_job_with_401_retry(
    store: GuardStore,
    state: dict[str, object],
    auth_context: dict[str, object],
    **batch: Any,
) -> dict[str, object] | None:
    try:
        return _lease_next_job(store, auth_context, state=state, **batch)
    except urllib.error.HTTPError as error:
        if error.code != 401:
            raise
    _LOGGER.warning("Guard command lease 401, attempting OAuth refresh retry.")
    refreshed_auth_context = _resolve_command_queue_auth_context(store, force_refresh=True)
    return _lease_next_job(store, refreshed_auth_context, state=state, **batch)


def _authorize_in_connection_scope(store: GuardStore, job: dict[str, object]) -> AuthorizedCommandJob:
    # Every SQLite connection pays for a schema load on its first statement,
    # and authorizing a job reads the store many times over. One connection
    # for the whole check keeps that cost to a single load per job.
    with _review_connection_scope(store, job):
        return authorize_command_queue_job(store, job, schema_versions=COMMAND_OPERATION_SCHEMA_VERSIONS)


def _settle_authorized_job(
    store: GuardStore,
    context: HarnessContext,
    item: dict[str, object],
    authorized: AuthorizedCommandJob,
) -> dict[str, object]:
    calls = SettleCalls(
        identity_digest=command_identity_digest,
        consume=consume_local_command_approval,
        register=register_pending_command,
        audit=audit_command_decision,
        native_review=is_native_workspace_review_job,
        execute=_execute_job,
    )
    return settle_authorized_job(store, context, item, authorized, calls)


def poll_command_queue_once(
    store: GuardStore,
    context: HarnessContext,
    *,
    on_exact_review_lease: Callable[[ReviewLeaseBatch], object] | None = None,
    leased_item: dict[str, object] | None = None,
    brief_status: bool = False,
) -> dict[str, object]:
    """Settle one command job: lease it, or take ``leased_item`` already leased.

    With ``on_exact_review_lease``, an exact Review lease may return further
    jobs leased in the same response; they go to the callback to settle on
    drain workers. ``leased_item`` is how a drain worker settles one of them.
    ``brief_status`` returns only the lane's queue state, for the daemon loops.
    """

    status = command_queue_brief_status if brief_status else command_queue_status

    # A drain lane only starts beside a main poll that passed the full check,
    # and its lease scope already requires a ready Review keyring.
    ready = command_environment_allows_queue() if _current_lane().is_drain else command_queue_should_poll(store)
    if not ready:
        _transition(store, {}, "disabled")
        return status(store)
    extras: list[dict[str, object]] = []
    batch_size = 1
    if leased_item is not None:
        # A handed-over job is already leased. Its few setup reads and writes
        # share one connection, so they pay one schema load instead of one
        # per call while the other drain workers contend for the store.
        # Auth can refresh over the network, so it resolves before the shared
        # connection, which holds the storage gate, is opened.
        auth_context = _resolve_command_queue_auth_context(store)
        with _review_connection_scope(store, leased_item):
            state = _load_state(store)
            state.update({"last_poll_at": _now(), "last_error": None})
            _record_leased_job(store, state, leased_item)
        item = leased_item
    else:
        auth_context = _resolve_command_queue_auth_context(store)
        state = dict[str, object]()
        _transition(store, state, "polling", at=_now())
        if _retry_pending_result(store, auth_context, state):
            return status(store)
        batch_size = (
            min(lane_exact_lease_batch_limit(store, state), REVIEW_LEASE_BATCH_SIZE) if on_exact_review_lease else 1
        )
        item = _lease_job_with_401_retry(
            store,
            state,
            auth_context,
            max_jobs=batch_size,
            on_extra_jobs=extras.extend if batch_size > 1 else None,
        )
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
            if not _current_lane().is_drain:
                maybe_auto_update(store, context)
            return status(store)
        hand_over = on_exact_review_lease if uses_exact_transport(item) else None
        more_may_be_ready = batch_size == 1 or len(extras) + 1 >= batch_size
        if hand_over is not None:
            # Hand bulk siblings over before anything below can fail and strand them.
            start_review_drains(hand_over, extras, more_may_be_ready=more_may_be_ready)
        try:
            auth_context = _resolve_command_queue_auth_context(store)
            _record_leased_job(store, state, item)
        except Exception:  # nothing has run for this job yet; a drain worker can settle it
            if hand_over is not None:
                start_review_drains(hand_over, [item], more_may_be_ready=more_may_be_ready)
            raise
    authorization = start_command_authorization(
        store,
        item,
        authorize=_authorize_in_connection_scope,
    )
    # A job that checks its authority again as it applies settles while its
    # acknowledgement is in flight; waiting for that round trip first added it
    # to every approval the person was waiting on.
    acknowledgement = start_overlapped_acknowledgement(item, partial(_heartbeat, auth_context, item))
    try:
        if acknowledgement is None:
            _heartbeat(auth_context, item)
    except urllib.error.HTTPError as error:
        if error.code != 401:
            raise
        _LOGGER.warning("Guard heartbeat 401, attempting OAuth refresh retry.")
        auth_context = _resolve_command_queue_auth_context(store, force_refresh=True)
        _transition(store, state, "auth_expired")
        try:
            _heartbeat(auth_context, item)
        except Exception:
            _transition(store, state, "heartbeat_failed")
            raise
    except Exception:
        _transition(store, state, "heartbeat_failed")
        raise
    try:
        authorized = authorization()
    except (CommandCapabilityError, CommandCapabilityUnavailableError) as error:
        reason = error.code if isinstance(error, CommandCapabilityError) else error.reason
        audit_command_decision(
            store,
            "cloud_command.rejected",
            job=item,
            reason=reason,
        )
        execution: dict[str, object] = {
            "failureCode": reason,
            "failureMessage": "The local Guard command capability rejected this job.",
        }
    else:
        # A storage failure recorded inside the shared scope is raised when it
        # closes, after the job ran and its grant was spent. It still reached
        # recovery there; here it becomes the posted result so the lease closes.
        try:
            # Only Review jobs queue for a settle slot: a bulk approval leases
            # them together. A generic command settles straight after its
            # capability check, as it always has, so no wait can separate the
            # two.
            slot = settle_slots.hold() if item.get("operation") == EXACT_CLOUD_REVIEW_OPERATION else nullcontext()
            with slot, _review_connection_scope(store, item):
                execution = _settle_authorized_job(store, context, item, authorized)
        except sqlite3.DatabaseError as error:
            _LOGGER.warning("Guard command settle storage failure: error=%s", _redacted_error(error))
            execution = {
                "failureCode": "execution_error",
                "failureMessage": _redacted_error(error),
            }
    if acknowledgement is not None:
        acknowledgement()
    payload = _result_payload(item, execution)
    refused: urllib.error.HTTPError | None = None
    # Posting the result refreshes the job's heartbeat on the server, so a
    # separate heartbeat here only adds a round trip to every approval.
    try:
        refused = post_result_unless_refused(partial(_post_result, auth_context, item, payload))
    except urllib.error.HTTPError as error:
        if error.code != 401:
            _hold_pending_result(store, state, item, payload)
            raise
        _LOGGER.warning("Guard result 401, attempting OAuth refresh retry.")
        auth_context = _resolve_command_queue_auth_context(store, force_refresh=True)
        _transition(store, state, "auth_expired")
        try:
            refused = post_result_unless_refused(partial(_post_result, auth_context, item, payload))
        except Exception:
            _hold_pending_result(store, state, item, payload)
            raise
    except Exception:
        _hold_pending_result(store, state, item, payload)
        raise
    if refused is not None:
        drop_refused_result(store, state, item, refused)
        return status(store)
    _transition(store, state, "settled", at=_now())
    audit_command_decision(
        store,
        "cloud_command.result",
        job=item,
        reason=str(payload.get("status") or "unknown"),
    )
    _LOGGER.info("Guard command completed.")
    return status(store)


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
        enabled=command_queue_should_poll,
        poll_once=with_review_drains(
            store,
            context,
            stop_event=stop_event,
            poll_once=partial(poll_command_queue_once, brief_status=True),
            format_error=_redacted_error,
        ),
        load_state=_load_state,
        save_state=_save_state,
        format_error=_redacted_error,
        now=_now,
    )
