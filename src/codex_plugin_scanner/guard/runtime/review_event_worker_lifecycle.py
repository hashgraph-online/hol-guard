"""Lifecycle supervision for the independent Review event delivery worker."""

from __future__ import annotations

import logging
import os
import threading
import time
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from ..mdm.user_health import run_user_health_cadence, user_health_report_due
from ..review_contracts import GuardReviewContractError, guard_review_oauth_metadata
from ..review_event_wake import (
    consume_review_event_outbox_signal,
    register_review_event_outbox_wake_callback,
    review_event_outbox_signal_token,
)
from ..store_live_request_outbox import live_request_oauth_subject_hash
from .review_event_batch_worker import classify_review_event_sync_error, next_review_event_backoff_seconds
from .time_support import parse_utc_timestamp

if TYPE_CHECKING:
    from ..store import GuardStore


@dataclass
class LiveRequestSyncWorker:
    """Background worker for durable Review event delivery."""

    thread: threading.Thread
    stop_event: threading.Event
    wake_event: threading.Event
    unregister_wake: Callable[[], None] | None = None
    watchdog_thread: threading.Thread | None = None
    poll_interval: float = 30.0
    error_backoff: float = 1.0


_WATCHDOG_INTERVAL_SECONDS = 5.0
_MINIMUM_STALLED_HEARTBEAT_SECONDS = 90.0
_LOGGER = logging.getLogger(__name__)


def _sync_module() -> Any:
    from . import live_request_sync

    return live_request_sync


def _monotonic() -> float:
    return time.monotonic()


def _retry_deadline(result: object, *, now: str, monotonic_now: float) -> float | None:
    if not isinstance(result, Mapping):
        return None
    outbox = result.get("outbox")
    if not isinstance(outbox, Mapping):
        return None
    next_attempt = parse_utc_timestamp(outbox.get("next_attempt_at"))
    observed = parse_utc_timestamp(now)
    if next_attempt is None or observed is None:
        return None
    return monotonic_now + max(0.0, (next_attempt - observed).total_seconds())


def _worker_wait_seconds(
    poll_interval: float,
    *,
    monotonic_now: float,
    health_deadline: float,
    retry_deadline: float | None,
) -> float:
    deadlines = tuple(deadline for deadline in (health_deadline, retry_deadline) if deadline is not None)
    if not deadlines:
        return poll_interval
    return min(poll_interval, max(0.0, min(deadlines) - monotonic_now))


def _wait_for_worker_signal(
    stop_event: threading.Event,
    wake_event: threading.Event | None,
    seconds: float,
) -> bool:
    if stop_event.is_set():
        return True
    if wake_event is None:
        return stop_event.wait(seconds)
    _ = wake_event.wait(seconds)
    return stop_event.is_set()


def start_cloud_sync_sync_worker(
    store: GuardStore,
    existing: LiveRequestSyncWorker | None = None,
    *,
    poll_interval: float | None = None,
    error_backoff: float | None = None,
) -> LiveRequestSyncWorker | None:
    """Start or supervise the independent Review delivery worker."""

    sync = _sync_module()
    thread_runtime = sync.threading
    existing_watchdog = getattr(existing, "watchdog_thread", None) if existing is not None else None
    if existing is not None and not existing.stop_event.is_set() and existing.thread.is_alive():
        if isinstance(existing, LiveRequestSyncWorker) and (
            existing_watchdog is None or not existing_watchdog.is_alive()
        ):
            _start_review_event_watchdog(store, existing)
        return existing
    if (
        existing is not None
        and not existing.stop_event.is_set()
        and existing_watchdog is not None
        and existing_watchdog.is_alive()
    ):
        return existing
    if existing is not None and existing.thread.is_alive():
        existing.thread.join(timeout=1.0)
        if existing.thread.is_alive():
            raise RuntimeError("Previous live-request sync worker did not stop.")
    if existing is not None:
        state = sync._load_sync_state(store)
        state["watchdog_restart_count"] = sync._state_int(state, "watchdog_restart_count") + 1
        state["watchdog_restarted_at"] = sync._now()
        sync._save_sync_state(store, state)
    if os.environ.get("GUARD_LIVE_REQUEST_ENABLED", "1").strip().lower() in {"0", "false", "no", "off"}:
        return None
    stop_event = thread_runtime.Event()
    wake_event = thread_runtime.Event()
    poll_interval = poll_interval or _configured_seconds(
        "GUARD_LIVE_REQUEST_POLL_INTERVAL",
        sync.DEFAULT_POLL_INTERVAL_SECONDS,
    )
    error_backoff = error_backoff or _configured_seconds(
        "GUARD_LIVE_REQUEST_ERROR_BACKOFF",
        sync.DEFAULT_ERROR_BACKOFF_SECONDS,
    )
    thread = thread_runtime.Thread(
        target=_cloud_sync_sync_loop,
        kwargs={
            "store": store,
            "stop_event": stop_event,
            "wake_event": wake_event,
            "poll_interval": poll_interval,
            "error_backoff": error_backoff,
        },
        daemon=True,
        name="hol-guard-live-request-sync",
    )
    worker = LiveRequestSyncWorker(
        thread=thread,
        stop_event=stop_event,
        wake_event=wake_event,
        poll_interval=poll_interval,
        error_backoff=error_backoff,
    )
    worker.unregister_wake = register_review_event_outbox_wake_callback(store, wake_event.set)
    thread.start()
    _start_review_event_watchdog(store, worker)
    return worker


def _start_review_event_watchdog(store: GuardStore, worker: LiveRequestSyncWorker) -> None:
    watchdog_thread = threading.Thread(
        target=_watch_review_event_worker,
        kwargs={"store": store, "worker": worker},
        daemon=True,
        name="hol-guard-review-event-watchdog",
    )
    worker.watchdog_thread = watchdog_thread
    watchdog_thread.start()


def stop_cloud_sync_sync_worker(worker: LiveRequestSyncWorker | None) -> LiveRequestSyncWorker | None:
    """Signal a worker and leave a visible survivor for watchdog handling."""

    if worker is None:
        return None
    worker.stop_event.set()
    worker.wake_event.set()
    worker.thread.join(timeout=1.0)
    if worker.watchdog_thread is not None:
        worker.watchdog_thread.join(timeout=1.0)
    if worker.thread.is_alive() or (worker.watchdog_thread is not None and worker.watchdog_thread.is_alive()):
        return worker
    if worker.unregister_wake is not None:
        worker.unregister_wake()
    return None


def _watch_review_event_worker(store: GuardStore, worker: LiveRequestSyncWorker) -> None:
    """Restart confirmed-dead workers and report live threads with stale heartbeats."""

    while not worker.stop_event.wait(
        _configured_seconds("GUARD_REVIEW_EVENT_WATCHDOG_INTERVAL", _WATCHDOG_INTERVAL_SECONDS)
    ):
        if worker.stop_event.is_set():
            return
        try:
            if not worker.thread.is_alive():
                _ = _restart_dead_review_event_worker(store, worker)
                continue
            _record_stalled_heartbeat_if_needed(store, worker)
        except Exception as error:
            _LOGGER.warning(
                "Guard Review event watchdog check failed: %s",
                type(error).__name__,
            )


def _restart_dead_review_event_worker(store: GuardStore, worker: LiveRequestSyncWorker) -> bool:
    """Replace one confirmed-dead delivery thread without changing worker ownership."""

    if worker.stop_event.is_set() or worker.thread.is_alive():
        return False
    sync = _sync_module()
    state = sync._load_sync_state(store)
    state.update(
        {
            "watchdog_restart_count": sync._state_int(state, "watchdog_restart_count") + 1,
            "watchdog_restarted_at": sync._now(),
            "worker_state": "restarting",
        }
    )
    sync._save_sync_state(store, state)
    replacement = sync.threading.Thread(
        target=_cloud_sync_sync_loop,
        kwargs={
            "store": store,
            "stop_event": worker.stop_event,
            "wake_event": worker.wake_event,
            "poll_interval": worker.poll_interval,
            "error_backoff": worker.error_backoff,
        },
        daemon=True,
        name="hol-guard-live-request-sync",
    )
    worker.thread = replacement
    replacement.start()
    return True


def _record_stalled_heartbeat_if_needed(store: GuardStore, worker: LiveRequestSyncWorker) -> None:
    sync = _sync_module()
    state = sync._load_sync_state(store)
    heartbeat = state.get("worker_heartbeat_at")
    age = _heartbeat_age_seconds(heartbeat, now=sync._now())
    threshold = max(_MINIMUM_STALLED_HEARTBEAT_SECONDS, worker.poll_interval * 3)
    if age is None or age <= threshold or state.get("worker_state") == "stalled":
        return
    state.update({"worker_state": "stalled", "worker_stalled_at": sync._now()})
    sync._save_sync_state(store, state)


def _heartbeat_age_seconds(value: object, *, now: str) -> float | None:
    if not isinstance(value, str):
        return None
    try:
        heartbeat = datetime.fromisoformat(value.replace("Z", "+00:00"))
        observed = datetime.fromisoformat(now.replace("Z", "+00:00"))
    except ValueError:
        return None
    if heartbeat.tzinfo is None or observed.tzinfo is None:
        return None
    return max(0.0, (observed.astimezone(timezone.utc) - heartbeat.astimezone(timezone.utc)).total_seconds())


def _with_live_request_sync_identity(
    store: GuardStore,
    auth_context: dict[str, object],
) -> dict[str, object]:
    oauth = guard_review_oauth_metadata(store)
    subject_hash = live_request_oauth_subject_hash(oauth.grant_id)
    if subject_hash is None:
        raise GuardReviewContractError("missing_oauth_subject")
    expected_binding = {
        "oauth_source": store.guard_source,
        "oauth_subject_hash": subject_hash,
        "workspace_id": oauth.workspace_id,
        "machine_id": oauth.machine_id,
        "machine_installation_id": oauth.installation_id,
    }
    if store.get_live_request_oauth_binding() != expected_binding:
        raise GuardReviewContractError("oauth_binding_mismatch")
    return {**auth_context, **expected_binding}


def _resolve_live_request_sync_auth_context(
    store: GuardStore,
    *,
    force_refresh: bool = False,
) -> dict[str, Any]:
    """Resolve or repair paired cloud credentials once before a retry."""

    from .runner import (
        GuardSyncAuthorizationExpiredError,
        GuardSyncNotConfiguredError,
        _resolve_guard_sync_auth_context,
        repair_guard_cloud_connect_storage,
    )

    try:
        return _with_live_request_sync_identity(
            store,
            _resolve_guard_sync_auth_context(store, force_refresh=force_refresh),
        )
    except (GuardSyncAuthorizationExpiredError, GuardSyncNotConfiguredError):
        repair = repair_guard_cloud_connect_storage(store)
        if repair["existing_sign_in_valid"] or repair["repaired_storage"]:
            return _with_live_request_sync_identity(
                store,
                _resolve_guard_sync_auth_context(store, force_refresh=True),
            )
        raise


def _cloud_sync_sync_loop(
    store: GuardStore,
    stop_event: threading.Event,
    *,
    wake_event: threading.Event | None = None,
    poll_interval: float,
    error_backoff: float,
) -> None:
    """Run wake-driven sync, fallback polling, and persisted health reporting."""

    from .runner import GuardSyncAuthorizationExpiredError, GuardSyncNotConfiguredError

    sync = _sync_module()
    error_streak = 0
    next_health_sync_at = 0.0
    next_retry_sync_at: float | None = None
    while not stop_event.is_set():
        wake_requested = wake_event is not None and wake_event.is_set()
        if wake_event is not None:
            wake_event.clear()
        signal = review_event_outbox_signal_token(store)
        signal_pending = signal is not None
        now_monotonic = _monotonic()
        health_due = now_monotonic >= next_health_sync_at
        retry_due = next_retry_sync_at is not None and now_monotonic >= next_retry_sync_at
        if not health_due and not retry_due and not signal_pending and not wake_requested:
            wait = _worker_wait_seconds(
                _configured_seconds("GUARD_LIVE_REQUEST_POLL_INTERVAL", poll_interval),
                monotonic_now=now_monotonic,
                health_deadline=next_health_sync_at,
                retry_deadline=next_retry_sync_at,
            )
            if _wait_for_worker_signal(stop_event, wake_event, wait):
                return
            continue
        if signal_pending:
            _ = consume_review_event_outbox_signal(store)
        try:
            state = sync._load_sync_state(store)
            state.update({"worker_heartbeat_at": sync._now(), "worker_state": "running"})
            sync._save_sync_state(store, state)
            if not _cloud_connection_is_ready(store):
                state.update({"state": "waiting_for_cloud_connection", "last_error": None})
                sync._save_sync_state(store, state)
                next_retry_sync_at = None
                error_streak = 0
            else:
                resolver = getattr(
                    sync,
                    "_resolve_live_request_sync_auth_context",
                    _resolve_live_request_sync_auth_context,
                )
                result = sync.sync_live_requests_once(store, resolver(store))
                completed_monotonic = _monotonic()
                next_retry_sync_at = _retry_deadline(
                    result,
                    now=sync._now(),
                    monotonic_now=completed_monotonic,
                )
                with suppress(OSError, PermissionError, RuntimeError, ValueError):
                    if user_health_report_due(store.guard_home):
                        run_user_health_cadence(store.guard_home)
                error_streak = 0
            if health_due:
                health_interval = getattr(sync, "DEFAULT_HEALTH_INTERVAL_SECONDS", 30.0)
                next_health_sync_at = _monotonic() + float(health_interval)
        except (GuardSyncAuthorizationExpiredError, GuardSyncNotConfiguredError) as error:
            error_streak = _record_loop_failure(store, error, "authorization", error_streak, sync)
        except Exception as error:
            sync._LOGGER.exception("Unexpected error in live-request sync loop")
            error_streak = _record_loop_failure(
                store,
                error,
                classify_review_event_sync_error(error),
                error_streak,
                sync,
            )
        wait = (
            next_review_event_backoff_seconds(
                error_streak,
                base_seconds=_configured_seconds("GUARD_LIVE_REQUEST_ERROR_BACKOFF", error_backoff),
            )
            if error_streak
            else _configured_seconds("GUARD_LIVE_REQUEST_POLL_INTERVAL", poll_interval)
        )
        if not error_streak:
            wait = _worker_wait_seconds(
                wait,
                monotonic_now=_monotonic(),
                health_deadline=next_health_sync_at,
                retry_deadline=next_retry_sync_at,
            )
        if _wait_for_worker_signal(stop_event, wake_event, wait):
            return


def _record_loop_failure(store: GuardStore, error: BaseException, category: str, streak: int, sync: Any) -> int:
    streak += 1
    state = sync._load_sync_state(store)
    state.update(
        {
            "state": "error",
            "last_error": sync._redacted_error(error),
            "last_error_at": sync._now(),
            "last_error_category": category,
            "error_streak": streak,
        }
    )
    sync._save_sync_state(store, state)
    return streak


def _cloud_connection_is_ready(store: GuardStore) -> bool:
    profile = store.get_cloud_sync_profile()
    return isinstance(profile, dict) and bool(profile.get("workspace_id")) and bool(profile.get("sync_url"))


def _configured_seconds(name: str, fallback: float) -> float:
    try:
        configured = float(os.environ.get(name, str(fallback)))
    except ValueError:
        return fallback
    return configured if configured > 0 else fallback
