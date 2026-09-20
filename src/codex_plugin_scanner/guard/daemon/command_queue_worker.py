"""Daemon lifecycle helpers for the Guard Cloud command queue poller."""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from ..runtime.command_queue import (
    command_queue_enabled,
    command_queue_loop,
    command_queue_should_poll,
    default_command_context,
)
from ..store import GuardStore

_COMMAND_QUEUE_THREAD_JOIN_TIMEOUT_SECONDS = 1.0


@dataclass
class CommandQueueWorker:
    thread: threading.Thread
    stop_event: threading.Event
    config_reader: Callable[[Path], dict[str, object]] | None = None


def start_command_queue_worker(
    store: GuardStore,
    existing: CommandQueueWorker | None = None,
    *,
    config_reader: Callable[[Path], dict[str, object]] | None = None,
) -> CommandQueueWorker | None:
    if not command_queue_should_poll(store) and not command_queue_enabled(store):
        return stop_command_queue_worker(existing)
    if existing is not None:
        if existing.config_reader is not config_reader:
            raise ValueError("command_queue_config_scope_changed")
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
            **({"config_reader": config_reader} if config_reader is not None else {}),
        },
        daemon=True,
    )
    thread.start()
    return CommandQueueWorker(thread=thread, stop_event=stop_event, config_reader=config_reader)


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
    config_reader: Callable[[Path], dict[str, object]] | None = None,
) -> tuple[CommandQueueWorker | None, bool]:
    refreshed = (
        stop_command_queue_worker(worker)
        if shutting_down
        else start_command_queue_worker(store, worker, config_reader=config_reader)
    )
    running = refreshed is not None and refreshed.thread.is_alive() and not refreshed.stop_event.is_set()
    return refreshed, running
