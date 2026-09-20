"""Finite observations of an existing publisher during an installed probe."""

from __future__ import annotations

import sys
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from math import isfinite
from time import perf_counter as _phase_clock
from typing import Any, Literal

from codex_plugin_scanner.guard.native_approval_errors import FINITE_FAILURE_CODES
from codex_plugin_scanner.guard.native_policy_test_support import (
    PublicationLifecycleObservation,
    _finite_publisher_failure,
)
from codex_plugin_scanner.guard.native_resident_client import (
    native_resident_client_failure_code,
    native_resident_client_request,
)
from scripts.native_publication_capture_diagnostic import CaptureMetadataObservation
from scripts.native_publication_worker_diagnostic import describe_publication_worker

_CODES = FINITE_FAILURE_CODES | frozenset(
    {
        "native_client_containment_failed",
        "native_client_timed_out",
        "native_client_output_limit_exceeded",
        "native_client_status_missing",
        "native_client_exit_nonzero",
        "native_client_output_missing",
        "native_client_process_failed",
        "native_client_pool_exhausted",
        "native_client_start_failed",
        "native_client_stream_failed",
        "native_client_stdin_unavailable",
        "native_client_frame_write_failed",
        "native_client_request_invalid",
        "native_client_launcher_failed",
    }
)


def _finite_code(value: object) -> str:
    if value is None:
        return "missing"
    return value if type(value) is str and value in _CODES else "other"


_READINESS_METHODS = (
    ("_publish_once", "publication"),
    ("_confirm_resident_fingerprint", "confirmation"),
    ("wait_until_ready", "wait"),
    ("current_snapshot_binding", "binding"),
    ("current_snapshot", "fallback"),
    ("_publication_context", "context"),
    ("_status_provider", "runtime"),
    ("_compiled_command_extensions", "command"),
    ("_compiled_effective_policy", "config"),
)
_PREPARATION_PHASES = ("context", "runtime", "command", "config")
_MAX_ELAPSED_MS = 999_999


def _clock_sample() -> float | None:
    with suppress(BaseException):
        value = _phase_clock()
        if type(value) in {int, float} and isfinite(value):
            return float(value)
    return None


def _default_runtime_status() -> object:
    # Resolve the same current provider as the production context on each call.
    from codex_plugin_scanner.guard.native_runtime import native_runtime_status

    return native_runtime_status()


def _retry_facts(publisher: Any) -> str:
    with suppress(BaseException):
        namespace = vars(publisher)
        used = namespace.get("_initial_database_capture_retry_used")
        failures = namespace.get("_failure_count")
        used_value = "yes" if used is True else "no" if used is False else "unknown"
        failure_value = min(999, max(0, failures)) if type(failures) is int else "unknown"
        return f"; initial_capture_retry_used={used_value}; publication_failure_count={failure_value}"
    return ""


class _ReadinessObservation:
    """Observe existing calls without reading or retaining their private material."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._values = {label: "unobserved" for _, label in _READINESS_METHODS}
        self._observed = False
        self._publication_started = 0
        self._publication_completed = 0
        self._publication_state = ("unknown", "unknown", "unknown", "unknown")
        self._publication_last_outcome = "unobserved"
        # Only finite labels, capped counters, and elapsed milliseconds survive a call.
        self._phase_counts = {label: [0, 0] for label in _PREPARATION_PHASES}
        self._phase_elapsed = {label: [0, 0, 0] for label in _PREPARATION_PHASES}

    @staticmethod
    def _epoch(publisher: Any) -> int | None:
        with suppress(BaseException):
            value = vars(publisher).get("_epoch")
            return value if type(value) is int else None
        return None

    def _begin(self, label: str) -> None:
        with self._lock:
            self._observed = True
            self._values[label] = "running"
            if label == "publication":
                self._publication_started = min(999, self._publication_started + 1)
            elif label in self._phase_counts:
                self._phase_counts[label][0] = min(999, self._phase_counts[label][0] + 1)

    def _finish(self, label: str, result: object, publisher: Any, before_epoch: int | None) -> None:
        state = ("unknown", "unknown", "unknown", "unknown")
        if label == "publication":
            namespace = vars(publisher)
            acked, snapshot, closed = (
                namespace.get("_acked"),
                namespace.get("_snapshot", self),
                namespace.get("_closed"),
            )
            after_epoch = self._epoch(publisher)
            state = (
                "yes" if acked is True else "no" if acked is False else "unknown",
                "missing" if snapshot is None else "unknown" if snapshot is self else "present",
                "yes" if closed is True else "no" if closed is False else "unknown",
                "unknown"
                if before_epoch is None or after_epoch is None
                else "yes"
                if before_epoch == after_epoch
                else "no",
            )
            value = "returned"
        elif label in _PREPARATION_PHASES:
            value = "returned"
        elif label == "confirmation":
            value = "missing" if result is None else "present"
        elif label == "wait":
            value = "ready" if result is True else "not_ready" if result is False else "other"
        else:
            value = "present" if isinstance(result, dict) else "missing" if result is None else "other"
        with self._lock:
            self._values[label] = value
            if label == "publication":
                self._publication_completed = min(999, self._publication_completed + 1)
                self._publication_state = state
                self._publication_last_outcome = "returned"

    def _raised(self, label: str) -> None:
        with self._lock:
            self._values[label] = "raised"
            if label == "publication":
                self._publication_completed = min(999, self._publication_completed + 1)
                self._publication_state = ("unknown", "unknown", "unknown", "unknown")
                self._publication_last_outcome = "raised"

    def _record_elapsed(self, label: str, started: float | None) -> None:
        ended = _clock_sample()
        elapsed = ended - started if started is not None and ended is not None else None
        valid = elapsed is not None and isfinite(elapsed) and elapsed >= 0
        elapsed_ms = int(min(_MAX_ELAPSED_MS, elapsed * 1_000)) if valid and elapsed is not None else 0
        with self._lock:
            counts, timings = self._phase_counts[label], self._phase_elapsed[label]
            counts[1] = min(999, counts[1] + 1)
            timings[0] = min(_MAX_ELAPSED_MS, timings[0] + elapsed_ms)
            timings[1] = max(timings[1], elapsed_ms)
            timings[2] = min(999, timings[2] + (not valid))

    def _wrapper(self, label: str, original: Callable[..., Any], publisher: Any) -> Callable[..., Any]:
        def observed(*args: Any, **kwargs: Any) -> Any:
            __tracebackhide__ = True
            before_epoch = self._epoch(publisher) if label == "publication" else None
            with suppress(BaseException):
                self._begin(label)
            started = _clock_sample() if label in _PREPARATION_PHASES else None
            try:
                result = original(*args, **kwargs)
            except BaseException:
                with suppress(BaseException):
                    self._raised(label)
                raise
            finally:
                if label in _PREPARATION_PHASES:
                    with suppress(BaseException):
                        self._record_elapsed(label, started)
            with suppress(BaseException):
                self._finish(label, result, publisher, before_epoch)
            return result

        return observed

    @contextmanager
    def attach(self, publisher: Any) -> Iterator[None]:
        """Restore exact instance overrides without replacing concurrent changes."""
        try:
            namespace = vars(publisher)
        except (TypeError, AttributeError):
            yield
            return
        missing = object()
        installed = []
        try:
            for name, label in _READINESS_METHODS:
                original = getattr(publisher, name, None)
                if name == "_status_provider" and name in namespace and original is None:
                    original = _default_runtime_status
                if not callable(original):
                    continue
                previous = namespace.get(name, missing)
                wrapped = self._wrapper(label, original, publisher)
                namespace[name] = wrapped
                installed.append((name, previous, wrapped))
            yield
        finally:
            for name, previous, wrapped in reversed(installed):
                if namespace.get(name) is wrapped:
                    if previous is missing:
                        del namespace[name]
                    else:
                        namespace[name] = previous

    def describe(self, publisher: Any = None) -> str:
        with self._lock:
            if not self._observed:
                return ""
            acked, snapshot, closed, epoch_current = self._publication_state
            phases = "".join(
                f"; preparation_{label}={self._values[label]}"
                f"; preparation_{label}_calls={self._phase_counts[label][0]}/{self._phase_counts[label][1]}"
                f"; preparation_{label}_elapsed_ms={self._phase_elapsed[label][0]}"
                f"; preparation_{label}_max_ms={self._phase_elapsed[label][1]}"
                f"; preparation_{label}_invalid_clock={self._phase_elapsed[label][2]}"
                for label in _PREPARATION_PHASES
            )
            return (
                "; readiness_observed=True; "
                f"publication={self._values['publication']}; "
                f"publication_calls={self._publication_started}/{self._publication_completed}; "
                f"publication_acked={acked}; publication_snapshot={snapshot}; "
                f"publication_closed={closed}; publication_entry_epoch_unchanged={epoch_current}; "
                f"readiness_wait={self._values['wait']}; "
                f"current_binding={self._values['binding']}; fallback_snapshot={self._values['fallback']}; "
                f"resident_confirmation={self._values['confirmation']}; "
                f"publication_last_completed={self._publication_last_outcome}"
                + phases
                + (_retry_facts(publisher) if publisher is not None else "")
            )


class PublicationObservation:
    """No waits, starts, snapshots, or retained request/response material."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._started = 0
        self._completed = 0
        self._failure = "missing"
        self.attached = False
        self.lifecycle = PublicationLifecycleObservation()
        self.readiness = _ReadinessObservation()
        self.capture = CaptureMetadataObservation()

    def call(self, client: Callable[..., bytes | None], **kwargs: Any) -> bytes | None:
        __tracebackhide__ = True
        with self._lock:
            self._started = min(999, self._started + 1)
        try:
            return client(**kwargs)
        finally:
            # Failure state belongs to the calling worker, not the observer thread.
            code = _finite_code(native_resident_client_failure_code())
            with self._lock:
                self._completed = min(999, self._completed + 1)
                if code != "missing":
                    self._failure = code

    def describe(
        self,
        publisher_error: object,
        *,
        window: Literal["after_daemon_construction", "before_publisher_start"] = "after_daemon_construction",
    ) -> str:
        label = (
            "before_publisher_start"
            if type(window) is str and window == "before_publisher_start"
            else "after_daemon_construction"
        )
        with self._lock:
            return (
                f"window={label}; "
                f"attached={self.attached}; publisher={_finite_publisher_failure(publisher_error)}; "
                f"transport={self._failure}; started={self._started}; completed={self._completed}"
            )


@contextmanager
def observe_publication(publisher: Any) -> Iterator[PublicationObservation]:
    """Attach to future calls only; an already captured client stays untouched."""
    observation = PublicationObservation()
    missing = object()
    previous = getattr(publisher, "_client_request", missing)
    if previous is None:

        def client(**kwargs: Any) -> bytes | None:
            __tracebackhide__ = True
            return observation.call(native_resident_client_request, **kwargs)

        publisher._client_request = client
        observation.attached = True
    try:
        with (
            observation.lifecycle.attach(publisher),
            observation.readiness.attach(publisher),
            observation.capture.attach(publisher),
        ):
            yield observation
    finally:
        if observation.attached:
            publisher._client_request = previous


def report_publication_failure(
    observation: PublicationObservation,
    publisher: Any,
    *,
    window: Literal["after_daemon_construction", "before_publisher_start"] = "after_daemon_construction",
) -> None:
    """Best-effort finite evidence must never replace the original failure."""
    with suppress(BaseException):
        print(
            "native_publication_observation: "
            + observation.describe(getattr(publisher, "last_error", None), window=window)
            + "; "
            + observation.lifecycle.describe(publisher)
            + observation.readiness.describe(publisher)
            + "; "
            + describe_publication_worker(publisher)
            + observation.capture.describe(),
            file=sys.stderr,
        )


def cleanup_after_failure(cleanup: Callable[[], object]) -> None:
    """Call the original cleanup once while preserving the active exception."""
    __tracebackhide__ = True
    try:
        cleanup()
    except BaseException:
        with suppress(BaseException):
            print("native_probe_cleanup=failed", file=sys.stderr)


@contextmanager
def cleanup_preserving_failure(cleanup: Callable[[], object]) -> Iterator[None]:
    __tracebackhide__ = True
    try:
        yield
    except BaseException:
        cleanup_after_failure(cleanup)
        raise
    else:
        cleanup()
