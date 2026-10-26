"""Bounded lifecycle calls into the installed Guard daemon used by the probes."""

from __future__ import annotations

import signal
import threading
import time
from typing import Any


class ProbeError(RuntimeError):
    """Raised when the installed Pi/native boundary cannot be proven."""


class ProbeCleanupError(ProbeError):
    """Raised when startup cleanup must be retained for a bounded retry."""


class ProbeCleanupUnsafeError(ProbeCleanupError):
    """Raised when daemon containment is unproven and the scratch root may be mutable."""


class _DaemonCallTimeoutError(ProbeCleanupUnsafeError):
    """Internal signal interruption for a bounded daemon lifecycle call."""


def _restore_alarm_state(
    *,
    prior_handler: Any,
    prior_timer: tuple[float, float],
    elapsed: float,
) -> None:
    """Restore SIGALRM even when setup or the bounded call failed."""
    restoration_error: BaseException | None = None
    try:
        signal.setitimer(signal.ITIMER_REAL, 0)
    except BaseException as exc:
        restoration_error = exc

    handler_restored = False
    try:
        signal.signal(signal.SIGALRM, prior_handler)
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
                signal.setitimer(signal.ITIMER_REAL, remaining, prior_interval)
            except BaseException as exc:
                restoration_error = restoration_error or exc

    if restoration_error is not None:
        raise ProbeCleanupUnsafeError("Guard daemon alarm state restoration failed") from restoration_error


def bounded_daemon_call(daemon: Any, method_name: str, timeout: float) -> object | None:
    if threading.current_thread() is not threading.main_thread():
        raise ProbeError("bounded Guard daemon cleanup must run on the main thread")
    method = getattr(daemon, method_name, None)
    if not callable(method):
        raise ProbeError(f"installed Guard daemon {method_name} signal is unavailable")
    if not hasattr(signal, "SIGALRM"):
        return _bounded_daemon_call_without_alarm(method, method_name, timeout)

    try:
        prior_handler = signal.getsignal(signal.SIGALRM)
        prior_timer = signal.getitimer(signal.ITIMER_REAL)
    except BaseException as exc:
        raise ProbeCleanupUnsafeError("Guard daemon alarm state could not be inspected") from exc
    started = time.monotonic()

    def timeout_handler(_signum: int, _frame: Any) -> None:
        raise _DaemonCallTimeoutError(f"authenticated Guard daemon {method_name} timed out")

    try:
        signal.signal(signal.SIGALRM, timeout_handler)
        signal.setitimer(signal.ITIMER_REAL, timeout)
        return method()
    except _DaemonCallTimeoutError:
        raise
    except BaseException as exc:
        if method_name == "stop":
            raise ProbeError(f"authenticated Guard daemon cleanup failed: {type(exc).__name__}") from exc
        raise ProbeError(f"authenticated Guard daemon {method_name} failed: {type(exc).__name__}") from exc
    finally:
        elapsed = time.monotonic() - started
        _restore_alarm_state(prior_handler=prior_handler, prior_timer=prior_timer, elapsed=elapsed)


def _bounded_daemon_call_without_alarm(method: Any, method_name: str, timeout: float) -> object | None:
    """Bound the call by joining a worker thread where SIGALRM does not exist (Windows)."""
    outcome: dict[str, Any] = {}

    def call() -> None:
        try:
            outcome["value"] = method()
        except BaseException as exc:
            outcome["error"] = exc

    worker = threading.Thread(target=call, name=f"guard-daemon-{method_name}", daemon=True)
    worker.start()
    worker.join(timeout)
    if worker.is_alive():
        raise _DaemonCallTimeoutError(f"authenticated Guard daemon {method_name} timed out")
    error = outcome.get("error")
    if error is not None:
        if method_name == "stop":
            raise ProbeError(f"authenticated Guard daemon cleanup failed: {type(error).__name__}") from error
        raise ProbeError(f"authenticated Guard daemon {method_name} failed: {type(error).__name__}") from error
    return outcome.get("value")
