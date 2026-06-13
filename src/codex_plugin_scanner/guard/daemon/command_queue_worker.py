"""Daemon lifecycle helpers for the Guard Cloud command queue poller."""

from __future__ import annotations

import threading
from dataclasses import dataclass

from ..runtime.command_queue import command_queue_enabled, command_queue_loop, default_command_context
from ..store import GuardStore

_COMMAND_QUEUE_THREAD_JOIN_TIMEOUT_SECONDS = 100


@dataclass
class CommandQueueWorker:
    thread: threading.Thread
    stop_event: threading.Event


def start_command_queue_worker(
    store: GuardStore,
    existing: CommandQueueWorker | None = None,
) -> CommandQueueWorker | None:
    if not command_queue_enabled():
        return existing if existing is not None and existing.thread.is_alive() else None
    if existing is not None and existing.thread.is_alive() and not existing.stop_event.is_set():
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
