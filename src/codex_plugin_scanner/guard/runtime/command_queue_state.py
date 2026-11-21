"""Capability, persistence, and status projection for the command queue."""

from __future__ import annotations

import logging
import urllib.error
from collections.abc import Callable
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from ..harness_context import HarnessContext
from ..native_command_state import CommandStateUnavailableError, native_command_state
from ..store import GuardStore
from .command_capability import (
    command_capability_operations,
    command_capability_status,
    command_environment_allows_queue,
)
from .command_executors import SUPPORTED_COMMAND_OPERATIONS
from .command_queue_activation import (
    COMMAND_QUEUE_LEASE_WAIT_MS_ENV,
    command_queue_is_enabled,
)
from .command_queue_protocol import redacted_error
from .exact_cloud_review import (
    EXACT_CLOUD_REVIEW_OPERATION,
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


def transition_command_queue_state(
    store: GuardStore,
    state: dict[str, object],
    transition: str,
    *,
    at: str | None = None,
    pending: dict[str, object] | None = None,
) -> None:
    """Apply one named job step to this lane's stored row and adopt the result.

    The native store decides the step's fields and merges them into the stored
    row. ``state`` becomes that merged row, so a caller must have saved every
    in-memory change it means to keep before taking a step.
    """

    merged = store.transition_command_queue_state(
        current_command_queue_lane().state_key,
        transition,
        now=command_queue_now(),
        at=at,
        pending=pending,
    )
    state.clear()
    state.update(merged)


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
    The runtime merges the limit alone into the lane's stored row, so a write
    made to that row since ``state`` was loaded is kept.
    """

    if exact_lease_batch_limit(state) == limit and EXACT_LEASE_BATCH_LIMIT_KEY in state:
        return
    state[EXACT_LEASE_BATCH_LIMIT_KEY] = limit
    store.record_command_queue_lease_limit(current_command_queue_lane().state_key, limit, now=command_queue_now())


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


def command_queue_brief_status(store: GuardStore) -> dict[str, object]:
    """The lane's queue state alone, for the daemon's own loops between jobs.

    The full status also reports capability, Cloud Review and grant details.
    Building it costs a native round trip per job, and the loops read none of it.
    """

    state = load_command_queue_state(store)
    return {
        "state": state.get("state", "idle"),
        "last_error": state.get("last_error"),
        "last_poll_was_empty": bool(state.get("last_poll_was_empty")),
        "pending_result": state.get("pending_result"),
    }


def repair_command_queue_state(store: GuardStore) -> dict[str, object]:
    """Drop the lane's damaged queue fields and report which ones went.

    The runtime reads the lane's state row, drops an ``active_job`` that is not
    an object and a ``pending_result`` without an object job and payload, and
    writes the row back idle, all in one transaction, so a queue worker saving
    the same row cannot lose its write. Raises ``CommandStateUnavailableError``
    when no capable runtime answers and ``CommandStateRefusedError`` when the
    row cannot be read.
    """

    guard_home = getattr(store, "guard_home", None)
    if not isinstance(guard_home, Path):
        raise CommandStateUnavailableError
    answer = native_command_state(
        guard_home,
        "queue_repair",
        now=command_queue_now(),
        state_key=current_command_queue_lane().state_key,
    )
    listed = answer.get("repaired") if isinstance(answer, dict) else None
    repaired = [field for field in listed if isinstance(field, str)] if isinstance(listed, list) else []
    return {"repaired": repaired, "repaired_count": len(repaired), "status": command_queue_status(store)}


def default_command_context(store: GuardStore) -> HarnessContext:
    return HarnessContext(home_dir=Path.home().resolve(), workspace_dir=None, guard_home=store.guard_home)


__all__ = [
    "COMMAND_QUEUE_ENABLED_ENV",
    "COMMAND_QUEUE_LEASE_WAIT_MS_ENV",
    "COMMAND_QUEUE_STATE_KEY",
    "CommandQueueLane",
    "clear_exact_route_failure",
    "command_queue_brief_status",
    "command_queue_enabled",
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
    "transition_command_queue_state",
]
