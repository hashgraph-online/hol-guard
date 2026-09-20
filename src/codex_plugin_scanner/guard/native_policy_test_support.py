"""Helpers for exercising the native resident with an authenticated policy."""

from __future__ import annotations

import sys
import threading
import time
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from .native_approval_errors import FINITE_FAILURE_CODES
from .native_policy_snapshot import get_native_policy_snapshot_publisher
from .native_resident_client import native_resident_client_failure_code, native_resident_client_request
from .store import GuardStore

_DIAGNOSTIC_FAILURE_CODES = FINITE_FAILURE_CODES | frozenset(
    {
        "native_client_containment_failed",
        "native_client_timed_out",
        "native_client_output_limit_exceeded",
        "native_client_status_missing",
        "native_client_exit_nonzero",
        "native_client_output_missing",
        "native_client_process_failed",
        "native_client_pool_exhausted",
        "native_resident_invalid_response",
        "native_resident_unavailable",
    }
)


def _finite_failure(value: object) -> str:
    if value is None:
        return "missing"
    return value if type(value) is str and value in _DIAGNOSTIC_FAILURE_CODES else "other"


def native_review_diagnostic(guard_home: Path) -> str:
    """Describe a completed failed review using only finite diagnostic codes."""
    from .native_runtime import native_runtime_health

    health = _finite_failure(native_runtime_health(guard_home).reason)
    transport = _finite_failure(native_resident_client_failure_code())
    return f"health={health}; transport={transport}"


# Exact source-defined publisher/startup outcomes only. Unknown values never
# enter the retained observation, even when they resemble one of these codes.
_PUBLISHER_FAILURE_CODES = _DIAGNOSTIC_FAILURE_CODES | frozenset(
    {
        "native_policy_authority_bundle_semantics_unsupported",
        "native_policy_authority_bundle_unavailable",
        "native_policy_authority_capture_changed",
        "native_policy_authority_catalog_mismatch",
        "native_policy_authority_changed_during_publish",
        "native_policy_authority_changed_during_read",
        "native_policy_authority_config_changed",
        "native_policy_authority_device_unavailable",
        "native_policy_authority_input_invalid",
        "native_policy_authority_local_unavailable",
        "native_policy_authority_managed_consumer_required",
        "native_policy_authority_managed_unavailable",
        "native_policy_authority_materialization_unavailable",
        "native_policy_authority_memory_binding_unavailable",
        "native_policy_authority_memory_unavailable",
        "native_policy_authority_scoped_consumer_required",
        "native_policy_authority_source_changed",
        "native_policy_authority_state_invalid",
        "native_policy_snapshot_ack_invalid",
        "native_policy_snapshot_ack_mismatch",
        "native_policy_snapshot_cache_integrity_invalid",
        "native_policy_snapshot_expired",
        "native_policy_snapshot_generation_state_invalid",
        "native_policy_snapshot_generation_state_missing",
        "native_policy_snapshot_integrity_key_unavailable",
        "native_policy_snapshot_native_disabled",
        "native_policy_snapshot_protocol_unsupported",
        "native_policy_snapshot_publish_failed",
        "native_policy_snapshot_requires_new_generation",
        "native_policy_snapshot_resident_changed",
        "native_policy_snapshot_runtime_unavailable",
        "native_resident_owner_busy",
        "native_resident_runtime_identity_mismatch",
        "native_resident_runtime_path_failed",
        "native_resident_spawn_auth_failed",
        "native_resident_spawn_containment_failed",
        "native_resident_spawn_failed",
        "native_resident_spawn_stdin_failed",
        "native_resident_start_in_progress",
        "native_resident_start_timeout",
    }
)


def _finite_publisher_failure(value: object) -> str:
    if value is None:
        return "missing"
    return value if type(value) is str and value in _PUBLISHER_FAILURE_CODES else "other"


def _bounded_epoch(publisher: Any) -> int | str:
    value = getattr(publisher, "_epoch", None)
    return min(value, 999) if type(value) is int and value >= 0 else "missing"


class PublicationLifecycleObservation:
    """Retain finite error events across resets without polling or new work."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._error = "missing"
        self._error_epoch: int | str = "missing"
        self._events = 0
        self._initial = "missing"
        self._attached = False

    @contextmanager
    def attach(self, publisher: Any) -> Iterator[None]:
        __tracebackhide__ = True
        previous = getattr(publisher, "_record_error", None)
        if not callable(previous):
            yield
            return
        missing = object()
        instance_previous = vars(publisher).get("_record_error", missing)
        self._initial = _finite_publisher_failure(getattr(publisher, "last_error", None))

        def record(error: str) -> object:
            __tracebackhide__ = True
            code, epoch = _finite_publisher_failure(error), _bounded_epoch(publisher)
            try:
                return previous(error)
            finally:
                with self._lock:
                    self._error, self._error_epoch = code, epoch
                    self._events = min(self._events + 1, 999)

        publisher._record_error = record
        self._attached = True
        try:
            yield
        finally:
            if getattr(publisher, "_record_error", None) is record:
                if instance_previous is missing:
                    del publisher._record_error
                else:
                    publisher._record_error = instance_previous

    def describe(self, publisher: Any) -> str:
        epoch = _bounded_epoch(publisher)
        with self._lock:
            return (
                f"lifecycle_attached={self._attached}; initial_publisher={self._initial}; "
                f"last_publisher={self._error}; error_epoch={self._error_epoch}; "
                f"epoch={epoch}; error_events={self._events}"
            )


class _PublicationDiagnostics:
    """Keep finite completed-call observations even if a retry clears its error."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._started = 0
        self._completed = 0
        self._failure = "missing"

    def call(self, client: Callable[..., bytes | None], **kwargs: Any) -> bytes | None:
        with self._lock:
            self._started = min(self._started + 1, 999)
        try:
            return client(**kwargs)
        finally:
            # The failure code is context-local, so read it in the same worker
            # immediately after the unchanged native transport invocation.
            code = _finite_failure(native_resident_client_failure_code())
            with self._lock:
                self._completed = min(self._completed + 1, 999)
                if code != "missing":
                    self._failure = code

    def describe(self, publisher_error: object) -> str:
        with self._lock:
            return (
                f"publisher={_finite_failure(publisher_error)}; transport={self._failure}; "
                f"started={self._started}; completed={self._completed}"
            )


@contextmanager
def native_policy_snapshot(guard_home: Path) -> Iterator[Mapping[str, object]]:
    """Publish and yield the current ACKed snapshot for a test Guard home."""

    publisher = get_native_policy_snapshot_publisher(GuardStore(guard_home))
    diagnostics = _PublicationDiagnostics()
    lifecycle = PublicationLifecycleObservation()
    previous_client = publisher._client_request
    if previous_client is None:
        publisher._client_request = lambda **kwargs: diagnostics.call(native_resident_client_request, **kwargs)
    try:
        with lifecycle.attach(publisher):
            publisher.start()
            ready_wait_seconds = 25.0 if sys.platform == "win32" else 3.0
            if not publisher.wait_until_ready(time.monotonic() + ready_wait_seconds):
                raise AssertionError(
                    f"native policy publisher was not ready: {diagnostics.describe(publisher.last_error)}; "
                    + lifecycle.describe(publisher)
                )
            snapshot = publisher.current_snapshot()
            if snapshot is None:
                raise AssertionError("native policy publisher returned no ACKed snapshot")
            yield snapshot
    finally:
        try:
            publisher.close()
        finally:
            publisher._client_request = previous_client
