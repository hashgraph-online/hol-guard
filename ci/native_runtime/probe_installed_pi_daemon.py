"""Installed Pi probe daemon helpers; dependencies remain bound to its public entry point."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .probe_installed_pi_api import probe_api


def _close_startup_resource(resource: Any | None) -> BaseException | None:
    """Close a public startup resource when daemon construction aborts."""
    _api = probe_api()
    if resource is None:
        return None
    for method_name in ("close", "shutdown"):
        method = getattr(resource, method_name, None)
        if not callable(method):
            continue
        try:
            if method() is False:
                return _api.ProbeCleanupUnsafeError(f"startup resource {method_name} did not complete")
        except BaseException as exc:
            return exc
        return None
    return None


def _start_installed_daemon(*, guard_home: Path, home: Path, workspace: Path, identity: Any) -> Any:
    """Start the installed Guard daemon that the generated extension will use."""
    _api = probe_api()
    from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
    from codex_plugin_scanner.guard.store import GuardStore

    store: Any | None = None
    daemon: Any | None = None
    try:
        store = GuardStore(
            guard_home,
            source="default",
            prime_policy_integrity=False,
            allow_system_keyring=False,
        )
        daemon = GuardDaemonServer(
            store,
            host="127.0.0.1",
            port=0,
            home_dir=home,
            workspace_dir=workspace,
        )
        # Match the native default probe: publish the policy overlay before the
        # first generated-extension request pays the workspace registration cost.
        register_workspace = getattr(
            daemon._server.hook_worker.policy_snapshot_publisher,
            "register_workspace",
            None,
        )
        if callable(register_workspace):
            _ = register_workspace(workspace)
        daemon.start()
    except BaseException as startup_error:
        cleanup_failure: BaseException | None = None
        cleanup_unsafe = False
        if daemon is not None:
            try:
                _api._cleanup_installed_daemon(daemon)
            except BaseException as exc:
                cleanup_failure = exc
                cleanup_unsafe = isinstance(exc, _api.ProbeCleanupUnsafeError)
        else:
            # GuardDaemonServer owns rollback for any partially constructed
            # HTTP/publisher resources. Keep the root unsafe because no daemon
            # containment signal exists when construction never completed.
            resource_failure = _api._close_startup_resource(store)
            publisher = getattr(store, "policy_snapshot_publisher", None)
            if publisher is not None and publisher is not store:
                resource_failure = resource_failure or _api._close_startup_resource(publisher)
            cleanup_failure = resource_failure or _api.ProbeCleanupUnsafeError(
                "installed Guard daemon construction did not complete"
            )
            cleanup_unsafe = True
        if not cleanup_unsafe:
            try:
                _api._cleanup_native(identity, guard_home)
            except BaseException as exc:
                cleanup_failure = cleanup_failure or exc
        if cleanup_failure is not None:
            cleanup_error_type = _api.ProbeCleanupUnsafeError if cleanup_unsafe else _api.ProbeCleanupError
            raise cleanup_error_type(
                f"installed Guard daemon startup cleanup failed: {type(cleanup_failure).__name__}"
            ) from startup_error
        raise
    return daemon


def _prepare_installed_daemon_workspace(daemon: Any, workspace: Path) -> Any:
    """Synchronously publish the workspace policy before exercising Node."""
    _api = probe_api()
    hook_worker = getattr(getattr(daemon, "_server", None), "hook_worker", None)
    prepare = getattr(hook_worker, "prepare_workspace_policy", None)
    if not callable(prepare):
        raise _api.ProbeError("installed Guard daemon did not expose workspace readiness")
    deadline = _api.time.monotonic() + _api._DAEMON_READINESS_TIMEOUT
    try:
        prepared = prepare(workspace, deadline=deadline)
    except BaseException as exc:
        raise _api.ProbeError(f"installed Guard daemon workspace readiness failed: {type(exc).__name__}") from exc
    if prepared is None:
        raise _api.ProbeError("installed Guard daemon workspace policy was not ready")
    return prepared


def _restore_alarm_state(
    *,
    prior_handler: Any,
    prior_timer: tuple[float, float],
    elapsed: float,
) -> None:
    """Restore SIGALRM even when setup or the bounded call failed."""
    _api = probe_api()
    restoration_error: BaseException | None = None
    try:
        _api.signal.setitimer(_api.signal.ITIMER_REAL, 0)
    except BaseException as exc:
        restoration_error = exc

    handler_restored = False
    try:
        _api.signal.signal(_api.signal.SIGALRM, prior_handler)
        handler_restored = True
    except BaseException as exc:
        restoration_error = restoration_error or exc

    if handler_restored:
        prior_remaining, prior_interval = prior_timer
        if prior_remaining > 0:
            remaining = prior_remaining - elapsed
            if remaining <= 0:
                # The prior timer may have expired while this bounded call ran.
                # Deliver it shortly instead of silently discarding it.
                remaining = 0.001
            try:
                _api.signal.setitimer(_api.signal.ITIMER_REAL, remaining, prior_interval)
            except BaseException as exc:
                restoration_error = restoration_error or exc

    if restoration_error is not None:
        raise _api.ProbeCleanupUnsafeError("Guard daemon alarm state restoration failed") from restoration_error


def _bounded_daemon_call(daemon: Any, method_name: str) -> object | None:
    _api = probe_api()
    if _api.threading.current_thread() is not _api.threading.main_thread():
        raise _api.ProbeError("bounded Guard daemon cleanup must run on the main thread")
    method = getattr(daemon, method_name, None)
    if not callable(method):
        raise _api.ProbeError(f"installed Guard daemon {method_name} signal is unavailable")

    try:
        prior_handler = _api.signal.getsignal(_api.signal.SIGALRM)
        prior_timer = _api.signal.getitimer(_api.signal.ITIMER_REAL)
    except BaseException as exc:
        raise _api.ProbeCleanupUnsafeError("Guard daemon alarm state could not be inspected") from exc
    started = _api.time.monotonic()

    def timeout_handler(_signum: int, _frame: Any) -> None:
        raise _api._DaemonCallTimeoutError(f"authenticated Guard daemon {method_name} timed out")

    try:
        _api.signal.signal(_api.signal.SIGALRM, timeout_handler)
        _api.signal.setitimer(_api.signal.ITIMER_REAL, _api._DAEMON_CLEANUP_TIMEOUT)
        return method()
    except _api._DaemonCallTimeoutError:
        raise
    except BaseException as exc:
        if method_name == "stop":
            raise _api.ProbeError(f"authenticated Guard daemon cleanup failed: {type(exc).__name__}") from exc
        raise _api.ProbeError(f"authenticated Guard daemon {method_name} failed: {type(exc).__name__}") from exc
    finally:
        elapsed = _api.time.monotonic() - started
        _api._restore_alarm_state(prior_handler=prior_handler, prior_timer=prior_timer, elapsed=elapsed)


def _bounded_daemon_finish(daemon: Any) -> bool:
    # GuardDaemonServer has no public containment status; use its bounded
    # lifecycle completion and quarantine signals rather than trusting stop().
    _api = probe_api()
    return _api._bounded_daemon_call(daemon, "_finish_service") is True


def _cleanup_installed_daemon(daemon: Any) -> None:
    _api = probe_api()
    try:
        _api._bounded_daemon_call(daemon, "stop")
        if not _api._bounded_daemon_finish(daemon):
            raise _api.ProbeCleanupUnsafeError("authenticated Guard daemon containment was not confirmed")
        is_quarantined = getattr(daemon, "_is_quarantined", None)
        if callable(is_quarantined) and is_quarantined() is not False:
            raise _api.ProbeCleanupUnsafeError("authenticated Guard daemon remained quarantined")
        serve_thread = getattr(daemon, "_thread", None)
        is_alive = getattr(serve_thread, "is_alive", None)
        if callable(is_alive) and is_alive():
            raise _api.ProbeCleanupUnsafeError("authenticated Guard daemon serve thread remained alive")
    except BaseException as exc:
        if isinstance(exc, _api.ProbeCleanupUnsafeError):
            raise exc
        if isinstance(exc, _api.ProbeError):
            raise _api.ProbeCleanupUnsafeError(str(exc)) from exc
        raise _api.ProbeCleanupUnsafeError(f"authenticated Guard daemon cleanup failed: {type(exc).__name__}") from exc
