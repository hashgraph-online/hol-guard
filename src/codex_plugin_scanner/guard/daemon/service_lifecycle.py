"""Shared containment helpers for Guard daemon startup failures."""

from __future__ import annotations

import logging
import sqlite3
import threading
import time
from typing import TYPE_CHECKING

_LOGGER = logging.getLogger(__name__)

if TYPE_CHECKING:
    from .server import GuardDaemonServer


def startup_generation_is_current(server: GuardDaemonServer, generation: int | None) -> bool:
    """Check that startup still owns the service lifecycle generation."""

    with server._lifecycle_lock:
        return generation == server._lifecycle_generation and not server._shutdown_started.is_set()


def _failed_sqlite_identity(error: BaseException) -> tuple[int, int] | None:
    identity = getattr(error, "guard_failed_sqlite_identity", None)
    if isinstance(identity, tuple) and len(identity) == 2 and all(isinstance(part, int) for part in identity):
        return identity[0], identity[1]
    return None


def _begin_owned_service_with_store_recovery(
    server: GuardDaemonServer,
    generation: int,
    *,
    publish_before_workers: bool = False,
    continue_after_listen: bool = True,
) -> None:
    """Retry owned startup once after a fatal SQLite store is quarantined."""

    try:
        server._begin_owned_service(
            generation,
            publish_before_workers=publish_before_workers,
            continue_after_listen=continue_after_listen,
        )
    except sqlite3.DatabaseError as error:
        store = server._server.store
        if not store._recover_fatal_sqlite_store(
            error,
            failed_identity=_failed_sqlite_identity(error),
        ):
            raise
        server._begin_owned_service(
            generation,
            publish_before_workers=publish_before_workers,
            continue_after_listen=continue_after_listen,
        )


def _complete_owned_service_after_listen_with_store_recovery(
    server: GuardDaemonServer,
    generation: int,
) -> None:
    """Retry post-listen startup once after a fatal SQLite store is quarantined."""

    try:
        server._complete_owned_service_after_listen(generation)
    except sqlite3.DatabaseError as error:
        store = server._server.store
        if not store._recover_fatal_sqlite_store(
            error,
            failed_identity=_failed_sqlite_identity(error),
        ):
            raise
        server._complete_owned_service_after_listen(generation)


def _preflight_existing_service_workers(server: GuardDaemonServer) -> None:
    """Reject a restart while retained workers still need shutdown containment."""

    if server._aibom_refresh_thread is not None:
        if server._aibom_refresh_thread.is_alive():
            raise RuntimeError("AIBOM inventory refresh is still stopping")
        server._aibom_refresh_thread = None
    server._require_command_activity_maintenance_stopped()


def begin_service(server: GuardDaemonServer, *, publish_before_workers: bool = False) -> None:
    """Claim ownership and initialize background services for one generation."""

    from .manager import acquire_guard_daemon_owner_lock

    with server._finish_service_lock:
        with server._lifecycle_lock:
            server._lifecycle_generation += 1
            generation = server._lifecycle_generation
            server._active_start_generation = generation
        server._finish_service_completed = False
    server._record_lifecycle("start_requested")
    if server._is_quarantined():
        _preflight_existing_service_workers(server)
        raise RuntimeError("This Guard daemon is quarantined after unconfirmed containment.")
    try:
        with server._finish_service_lock:
            _preflight_existing_service_workers(server)
            with server._lifecycle_lock:
                if generation != server._lifecycle_generation:
                    raise RuntimeError("Guard daemon stopped during startup")
                server._shutdown_started.clear()
            if not startup_generation_is_current(server, generation):
                raise RuntimeError("Guard daemon stopped during startup")
            server._owner_lock = acquire_guard_daemon_owner_lock(server._server.store.guard_home)
            _begin_owned_service_with_store_recovery(
                server,
                generation,
                publish_before_workers=publish_before_workers,
                continue_after_listen=not publish_before_workers,
            )
        if publish_before_workers:
            _complete_owned_service_after_listen_with_store_recovery(server, generation)
    except BaseException as error:
        server._diagnostics.record_exception("daemon_start_failed")
        server._record_lifecycle("start_failed", reason="initialization_failed")
        serve_thread = server._thread
        leftover_serve_thread = None
        if serve_thread is not None:
            server._server.request_serve_stop()
            leftover_serve_thread = server._join_service_thread(
                serve_thread,
                deadline=time.monotonic() + 5,
            )
        if leftover_serve_thread is not None:
            add_note = getattr(error, "add_note", None)
            if callable(add_note):
                add_note("Guard retained daemon ownership because the serve thread did not exit.")
            raise
        if not server._finish_service():
            add_note = getattr(error, "add_note", None)
            if callable(add_note):
                add_note("Guard retained daemon ownership because partial-start containment was unconfirmed.")
        raise


def start_serve_thread(server: GuardDaemonServer, *, already_locked: bool = False) -> None:
    """Start the HTTP serve loop while holding the service ownership lock."""

    def start_locked() -> None:
        def run_serve() -> None:
            try:
                server._serve_forever()
            except BaseException as error:
                if server._serve_thread_error is None:
                    server._serve_thread_error = error
                if not isinstance(error, (KeyboardInterrupt, SystemExit)):
                    _LOGGER.exception("Guard daemon serve thread failed")

        if server._shutdown_started.is_set():
            raise RuntimeError("Guard daemon stopped during startup")
        if server._thread is not None and server._thread.is_alive():
            return
        server._serve_loop_started.clear()
        server._thread = threading.Thread(target=run_serve, daemon=True)
        server._thread.start()

    if already_locked:
        start_locked()
        return
    with server._finish_service_lock:
        start_locked()


def enable_full_capacity_for_generation(server: GuardDaemonServer, generation: int | None) -> None:
    """Enable workers only while the startup generation still owns the service."""

    with server._finish_service_lock:
        if not startup_generation_is_current(server, generation):
            raise RuntimeError("Guard daemon stopped during startup")
        server._server.hook_process_runner.enable_full_capacity()
        if not startup_generation_is_current(server, generation):
            raise RuntimeError("Guard daemon stopped during startup")


def contain_failed_service_start(
    server: GuardDaemonServer,
    error: BaseException,
    *,
    serve_thread_started: bool,
) -> None:
    """Contain partial startup state before propagating the original failure."""

    server._diagnostics.record_exception("daemon_start_thread_failed")
    serve_thread = server._thread
    serve_thread_contained = True
    if serve_thread_started and serve_thread is not None:
        server._server.request_serve_stop()
    else:
        try:
            server._server.server_close()
        except Exception:
            serve_thread_contained = False
    service_finished = server._finish_service()
    if serve_thread_started and serve_thread is not None:
        serve_thread_contained = (
            server._join_service_thread(
                serve_thread,
                deadline=time.monotonic() + 5,
            )
            is None
        )
    if serve_thread_contained and server._thread is serve_thread:
        server._thread = None
    if not service_finished or not serve_thread_contained:
        add_note = getattr(error, "add_note", None)
        if callable(add_note):
            add_note("Guard retained daemon ownership because startup containment was unconfirmed.")


__all__ = [
    "begin_service",
    "contain_failed_service_start",
    "enable_full_capacity_for_generation",
    "start_serve_thread",
    "startup_generation_is_current",
]
