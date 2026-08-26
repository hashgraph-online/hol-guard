"""Daemon lifecycle helpers for the Guard Cloud command queue poller."""

from __future__ import annotations

import threading
from dataclasses import dataclass

from ..runtime.command_queue import command_queue_enabled, command_queue_loop, default_command_context
from ..store import GuardStore

_COMMAND_QUEUE_THREAD_JOIN_TIMEOUT_SECONDS = 1.0


@dataclass
class CommandQueueWorker:
    thread: threading.Thread
    stop_event: threading.Event


def start_command_queue_worker(
    store: GuardStore,
    existing: CommandQueueWorker | None = None,
) -> CommandQueueWorker | None:
    if not command_queue_enabled(store):
        return stop_command_queue_worker(existing)
    if existing is not None:
        if existing.thread.is_alive() and not existing.stop_event.is_set():
            return existing
        existing = stop_command_queue_worker(existing)
        if existing is not None:
            return existing
    stop_event = threading.Event()
    thread = threading.Thread(
        target=command_queue_loop,
        kwargs={
            "store": store,
            "context": default_command_context(store),
            "stop_event": stop_event,
        },
        daemon=True,
    )
    thread.start()
    return CommandQueueWorker(thread=thread, stop_event=stop_event)


def stop_command_queue_worker(worker: CommandQueueWorker | None) -> CommandQueueWorker | None:
    if worker is None:
        return None
    worker.stop_event.set()
    worker.thread.join(timeout=_COMMAND_QUEUE_THREAD_JOIN_TIMEOUT_SECONDS)
    return worker if worker.thread.is_alive() else None


def refresh_command_queue_worker(
    store: GuardStore,
    worker: CommandQueueWorker | None,
    *,
    shutting_down: bool,
) -> tuple[CommandQueueWorker | None, bool]:
    refreshed = stop_command_queue_worker(worker) if shutting_down else start_command_queue_worker(store, worker)
    running = refreshed is not None and refreshed.thread.is_alive() and not refreshed.stop_event.is_set()
    return refreshed, running
