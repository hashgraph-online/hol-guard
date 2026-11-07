"""Capability, persistence, and status projection for the command queue."""

from __future__ import annotations

import logging
import urllib.error
from collections.abc import Callable
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from ...version import __version__
from ..adapters.base import HarnessContext
from ..store import GuardStore
from .command_capability import (
    CommandCapabilityError,
    command_capability_operations,
    command_capability_status,
    command_environment_allows_queue,
)
from .command_executors import COMMAND_OPERATION_SCHEMA_VERSIONS, SUPPORTED_COMMAND_OPERATIONS
from .command_queue_activation import (
    COMMAND_QUEUE_LEASE_WAIT_MS_ENV,
    command_queue_is_enabled,
    command_queue_lease_wait_ms,
)
from .command_queue_authority import command_queue_oauth_target
from .command_queue_protocol import redacted_error
from .exact_cloud_review import (
    EXACT_CLOUD_REVIEW_OPERATION,
    EXACT_CLOUD_REVIEW_PROTOCOL_VERSION,
    exact_cloud_review_operations,
    exact_cloud_review_status,
)
from .runner import _sync_http_error_message, _sync_url_error_message

COMMAND_QUEUE_STATE_KEY = "guard_command_queue_state"
COMMAND_QUEUE_ENABLED_ENV = "GUARD_CLOUD_COMMAND_QUEUE_ENABLED"

_LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class CommandQueueLane:
    """Which queue state a worker owns and which jobs it may lease.

    The daemon's main worker uses the defaults: the shared state key, every
    ready operation and the configured long-poll wait. A Review drain worker
    keeps its own state key, so a result it could not upload is retried by
    that worker instead of being overwritten by another, and leases exact
    Review jobs without waiting.
    """

    state_key: str = COMMAND_QUEUE_STATE_KEY
    operations: tuple[str, ...] | None = None
    wait_ms: int | None = None

    @property
    def is_drain(self) -> bool:
        """Whether this lane is a Review drain worker rather than the main worker."""

        return self.state_key != COMMAND_QUEUE_STATE_KEY

    def lease_scope(self, operations: tuple[str, ...], wait_ms: int) -> tuple[tuple[str, ...], int] | None:
        """Narrow a lease of ``operations`` to this lane, or None when it may lease none."""

        if self.operations is not None:
            operations = tuple(operation for operation in self.operations if operation in operations)
            if not operations:
                return None
        return operations, wait_ms if self.wait_ms is None else self.wait_ms


_MAIN_LANE = CommandQueueLane()
_CURRENT_LANE: ContextVar[CommandQueueLane] = ContextVar("guard_command_queue_lane", default=_MAIN_LANE)


def current_command_queue_lane() -> CommandQueueLane:
    """The lane bound to the calling thread's context; the main lane by default."""

    return _CURRENT_LANE.get()


def enter_command_queue_lane(lane: CommandQueueLane) -> None:
    """Bind ``lane`` to the calling thread's context for the rest of its run."""

    _CURRENT_LANE.set(lane)


def command_queue_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def command_queue_operations(store: GuardStore) -> tuple[str, ...]:
    generic = tuple(
        operation for operation in command_capability_operations(store) if operation != EXACT_CLOUD_REVIEW_OPERATION
    )
    return generic + tuple(operation for operation in exact_cloud_review_operations(store) if operation not in generic)


def command_queue_enabled(
    store: GuardStore | None = None,
    environ: dict[str, str] | None = None,
    *,
    operation_resolver: Callable[[GuardStore], tuple[str, ...]] = command_queue_operations,
) -> bool:
    """Return whether a valid local capability permits Cloud command polling."""

    return command_queue_is_enabled(
        store,
        environ,
        enabled_env=COMMAND_QUEUE_ENABLED_ENV,
        environment_allows_queue=command_environment_allows_queue,
        operations=operation_resolver,
        logger=_LOGGER,
    )


def load_command_queue_state(store: GuardStore) -> dict[str, object]:
    payload = store.get_sync_payload(current_command_queue_lane().state_key)
    return dict(payload) if isinstance(payload, dict) else {}


def save_command_queue_state(store: GuardStore, payload: dict[str, object]) -> None:
    store.set_sync_payload(current_command_queue_lane().state_key, payload, command_queue_now())


def record_exact_route_failure(state: dict[str, object], error: urllib.error.HTTPError) -> None:
    state["exact_review_route_error"] = redacted_error(
        error,
        http_formatter=_sync_http_error_message,
        os_formatter=_sync_url_error_message,
    )
    state["exact_review_route_error_at"] = command_queue_now()
    _LOGGER.warning("Guard Cloud Review exact command route is unavailable; generic queue polling continues.")


def clear_exact_route_failure(state: dict[str, object]) -> None:
    state.pop("exact_review_route_error", None)
    state.pop("exact_review_route_error_at", None)


EXACT_LEASE_BATCH_LIMIT_KEY = "exact_lease_batch_limit"


def exact_lease_batch_limit(state: dict[str, object]) -> int:
    """How many exact Review jobs Guard Cloud last said one lease may return."""

    value = state.get(EXACT_LEASE_BATCH_LIMIT_KEY)
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        return 1
    return value


def lane_exact_lease_batch_limit(store: GuardStore, state: dict[str, object]) -> int:
    """The lease batch limit for this lane's state.

    A drain lane that has not leased a batch of its own yet uses the limit the
    main worker recorded, so its first batch is not cut to one job.
    """

    if EXACT_LEASE_BATCH_LIMIT_KEY in state or not current_command_queue_lane().is_drain:
        return exact_lease_batch_limit(state)
    main = store.get_sync_payload(COMMAND_QUEUE_STATE_KEY)
    return exact_lease_batch_limit(main if isinstance(main, dict) else {})


def record_exact_lease_batch_limit(store: GuardStore, state: dict[str, object], limit: int) -> None:
    """Remember Guard Cloud's lease batch limit, saving at once when it changes.

    A limit that drops back to one is saved even when the poll then fails, so a
    Guard Cloud that stopped accepting batches is never asked for one again.
    """

    if exact_lease_batch_limit(state) == limit and EXACT_LEASE_BATCH_LIMIT_KEY in state:
        return
    state[EXACT_LEASE_BATCH_LIMIT_KEY] = limit
    save_command_queue_state(store, state)


def command_queue_status(
    store: GuardStore,
    *,
    enabled: Callable[[GuardStore], bool] = command_queue_enabled,
    operation_resolver: Callable[[GuardStore], tuple[str, ...]] = command_queue_operations,
    capability_status: Callable[[GuardStore], dict[str, object]] = command_capability_status,
) -> dict[str, object]:
    state = load_command_queue_state(store)
    return {
        "enabled": enabled(store),
        "configured": store.get_cloud_sync_profile() is not None,
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
        "capability": capability_status(store),
        "cloud_review": exact_cloud_review_status(store),
        "granted_operations": list(operation_resolver(store)),
        "supported_operations": list(SUPPORTED_COMMAND_OPERATIONS),
    }


def repair_command_queue_state(store: GuardStore) -> dict[str, object]:
    state = load_command_queue_state(store)
    repaired: list[str] = []
    if state.get("active_job") is not None and not isinstance(state.get("active_job"), dict):
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
        save_command_queue_state(store, state)
    return {"repaired": repaired, "repaired_count": len(repaired), "status": command_queue_status(store)}


def command_queue_lease_payload(
    store: GuardStore,
    *,
    operations: tuple[str, ...] | None = None,
    wait_ms: int | None = None,
    max_jobs: int = 1,
    operation_resolver: Callable[[GuardStore], tuple[str, ...]] = command_queue_operations,
) -> dict[str, object]:
    machine_id, workspace_id = command_queue_oauth_target(store)
    operations = operation_resolver(store) if operations is None else operations
    if not operations:
        raise CommandCapabilityError("command_capability_required")
    capabilities: dict[str, object] = {"operations": list(operations)}
    schema_versions = {
        operation: COMMAND_OPERATION_SCHEMA_VERSIONS[operation]
        for operation in operations
        if operation != EXACT_CLOUD_REVIEW_OPERATION and operation in COMMAND_OPERATION_SCHEMA_VERSIONS
    }
    if schema_versions:
        capabilities["schemaVersions"] = schema_versions
    exact_only = operations == (EXACT_CLOUD_REVIEW_OPERATION,)
    payload: dict[str, object] = {
        "workspaceId": workspace_id,
        "deviceId": machine_id,
        "daemonVersion": __version__,
        "capabilities": capabilities,
        # Only the exact Review route leases more than one job at a time.
        "maxJobs": max_jobs if exact_only else 1,
        "waitMs": command_queue_lease_wait_ms() if wait_ms is None else wait_ms,
    }
    if exact_only:
        payload["protocolVersion"] = EXACT_CLOUD_REVIEW_PROTOCOL_VERSION
    return payload


def default_command_context(store: GuardStore) -> HarnessContext:
    return HarnessContext(home_dir=Path.home().resolve(), workspace_dir=None, guard_home=store.guard_home)


__all__ = [
    "COMMAND_QUEUE_ENABLED_ENV",
    "COMMAND_QUEUE_LEASE_WAIT_MS_ENV",
    "COMMAND_QUEUE_STATE_KEY",
    "CommandQueueLane",
    "clear_exact_route_failure",
    "command_queue_enabled",
    "command_queue_lease_payload",
    "command_queue_now",
    "command_queue_operations",
    "command_queue_status",
    "current_command_queue_lane",
    "default_command_context",
    "enter_command_queue_lane",
    "load_command_queue_state",
    "record_exact_route_failure",
    "repair_command_queue_state",
    "save_command_queue_state",
]
