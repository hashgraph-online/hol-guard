"""Wake-driven background worker for durable Cloud Review event delivery."""

from __future__ import annotations

import logging
import os
import random
import threading
from contextlib import suppress
from dataclasses import dataclass

from ..mdm.user_health import run_user_health_cadence, user_health_report_due
from ..review_event_wake import ReviewEventWake, ReviewEventWakeSignal, review_event_wake_signal
from ..store import GuardStore

_LOGGER = logging.getLogger(__name__)

DEFAULT_SAFETY_POLL_SECONDS = 30.0
DEFAULT_ERROR_BACKOFF_SECONDS = 30.0


@dataclass
class CloudReviewSyncWorker:
    """Background worker for the Cloud Review event outbox."""

    thread: threading.Thread
    stop_event: threading.Event
    wake_signal: ReviewEventWakeSignal


def start_cloud_sync_sync_worker(
    store: GuardStore,
    existing: CloudReviewSyncWorker | None = None,
    *,
    poll_interval: float | None = None,
    error_backoff: float | None = None,
) -> CloudReviewSyncWorker | None:
    """Start a wake-driven worker with a low-frequency durable safety poll."""
    if existing is not None and existing.thread.is_alive() and not existing.stop_event.is_set():
        return existing
    if existing is not None and existing.thread.is_alive():
        existing.wake_signal.notify()
        existing.thread.join(timeout=1.0)
        if existing.thread.is_alive():
            raise RuntimeError("Previous Cloud Review sync worker did not stop.")

    profile = store.get_cloud_sync_profile()
    if not isinstance(profile, dict) or not profile.get("workspace_id") or not profile.get("sync_url"):
        return None
    stop_event = threading.Event()
    wake_signal = review_event_wake_signal(store.path)
    safety_poll = poll_interval or float(
        os.environ.get("GUARD_CLOUD_REVIEW_POLL_INTERVAL", str(DEFAULT_SAFETY_POLL_SECONDS))
    )
    maximum_backoff = error_backoff or float(
        os.environ.get("GUARD_CLOUD_REVIEW_ERROR_BACKOFF", str(DEFAULT_ERROR_BACKOFF_SECONDS))
    )
    thread = threading.Thread(
        target=_cloud_sync_sync_loop,
        kwargs={
            "store": store,
            "stop_event": stop_event,
            "wake_signal": wake_signal,
            "poll_interval": safety_poll,
            "error_backoff": maximum_backoff,
        },
        daemon=True,
        name="hol-guard-cloud-review-sync",
    )
    thread.start()
    return CloudReviewSyncWorker(thread=thread, stop_event=stop_event, wake_signal=wake_signal)


def stop_cloud_sync_sync_worker(
    worker: CloudReviewSyncWorker | None,
) -> CloudReviewSyncWorker | None:
    """Signal a Cloud Review sync worker and wait briefly for shutdown."""
    if worker is None:
        return None
    worker.stop_event.set()
    worker.wake_signal.notify()
    worker.thread.join(timeout=1.0)
    return worker if worker.thread.is_alive() else None


def _bounded_error_wait(poll_interval: float, maximum: float, streak: int) -> float:
    exponential = min(maximum, poll_interval * (2 ** min(streak, 10)))
    return exponential * random.uniform(0.5, 1.0)


def _cloud_sync_sync_loop(
    store: GuardStore,
    stop_event: threading.Event,
    wake_signal: ReviewEventWake,
    *,
    poll_interval: float,
    error_backoff: float,
) -> None:
    """Drain immediately after commits and poll durably if a hint is lost."""
    from . import cloud_review_sync as sync
    from .runner import GuardSyncAuthorizationExpiredError, GuardSyncNotConfiguredError

    error_streak = 0
    while not stop_event.is_set():
        observed_generation = wake_signal.generation()
        try:
            auth_context = sync._resolve_cloud_review_sync_auth_context(store)
            result = sync.sync_cloud_review_events_once(store, auth_context)
            error_streak = 0
            with suppress(OSError, PermissionError, RuntimeError, ValueError):
                if user_health_report_due(store.guard_home):
                    run_user_health_cadence(store.guard_home)
            synced = result.get("synced", 0)
            if isinstance(synced, int) and synced > 0:
                continue
        except (GuardSyncAuthorizationExpiredError, GuardSyncNotConfiguredError) as error:
            error_streak += 1
            state = sync._load_sync_state(store)
            state.update(
                {
                    "state": "error",
                    "last_error": sync._redacted_error(error),
                    "last_error_at": sync._now(),
                }
            )
            sync._save_sync_state(store, state)
        except Exception as error:
            error_streak += 1
            _LOGGER.exception("Unexpected error in Cloud Review sync loop")
            state = sync._load_sync_state(store)
            state.update(
                {
                    "state": "error",
                    "last_error": sync._redacted_error(error),
                    "last_error_at": sync._now(),
                }
            )
            sync._save_sync_state(store, state)

        wait = _bounded_error_wait(poll_interval, error_backoff, error_streak) if error_streak else poll_interval
        wake_signal.wait(observed_generation, wait)


__all__ = [
    "CloudReviewSyncWorker",
    "start_cloud_sync_sync_worker",
    "stop_cloud_sync_sync_worker",
]
