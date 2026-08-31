"""Shared containment helpers for Guard daemon startup failures."""

from __future__ import annotations

import threading
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .server import GuardDaemonServer


def startup_generation_is_current(server: GuardDaemonServer, generation: int | None) -> bool:
    """Check that startup still owns the service lifecycle generation."""

    with server._lifecycle_lock:
        return generation == server._lifecycle_generation and not server._shutdown_started.is_set()


def _preflight_existing_service_workers(server: GuardDaemonServer) -> None:
    """Reject a restart while retained workers still need shutdown containment."""

    if server._aibom_refresh_thread is not None:
        if server._aibom_refresh_thread.is_alive():
            raise RuntimeError("AIBOM inventory refresh is still stopping")
        server._aibom_refresh_thread = None
    server._require_command_activity_maintenance_stopped()


def begin_service(server: GuardDaemonServer) -> None:
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
            server._begin_owned_service(generation)
    except BaseException as error:
        server._diagnostics.record_exception("daemon_start_failed")
        server._record_lifecycle("start_failed", reason="initialization_failed")
        if not server._finish_service():
            add_note = getattr(error, "add_note", None)
            if callable(add_note):
                add_note("Guard retained daemon ownership because partial-start containment was unconfirmed.")
        raise


def start_serve_thread(server: GuardDaemonServer) -> None:
    """Start the HTTP serve loop while holding the service ownership lock."""

    with server._finish_service_lock:
        if server._shutdown_started.is_set():
            raise RuntimeError("Guard daemon stopped during startup")
        server._serve_loop_started.clear()
        server._thread = threading.Thread(target=server._serve_forever, daemon=True)
        server._thread.start()


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
