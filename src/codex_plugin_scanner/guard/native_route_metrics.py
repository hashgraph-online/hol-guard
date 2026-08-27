"""Privacy-safe aggregate evidence for Rust decision-route ownership.

The hook path performs only bounded in-memory counter updates and a non-blocking
report enqueue. A daemon thread writes owner-private aggregate reports outside
the request path. Persisted reports are partitioned by Guard home so one local
security boundary can never observe another home's routing metadata.

Reports never contain commands, prompts, output, paths, secrets, users, hosts,
or workspace identifiers.
"""

from __future__ import annotations

import json
import os
import queue
import stat
import threading
import time
from collections import Counter
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Final, Literal
from uuid import uuid4

from .runtime.hook_review_types import HookReviewResponse

NativeDecisionBackend = Literal["rust_native", "native_fail_safe", "python_compat"]
NativeTransport = Literal["resident_or_oneshot", "unavailable"]

_ALLOWED_BACKENDS: Final[frozenset[str]] = frozenset(
    {"rust_native", "native_fail_safe", "python_compat"}
)
_ALLOWED_TRANSPORTS: Final[frozenset[str]] = frozenset({"resident_or_oneshot", "unavailable"})
_MAX_CODE_LENGTH: Final = 96
_REPORT_DIRECTORY: Final = "logs"
_REPORT_FILENAME: Final = "native-route-metrics.json"
_REPORT_QUEUE_CAPACITY: Final = 16
_REPORT_COALESCE_SECONDS: Final = 0.05
_LOCK = threading.Lock()
_REPORT_QUEUE: queue.Queue[Path] = queue.Queue(maxsize=_REPORT_QUEUE_CAPACITY)
_REPORT_STATE_LOCK = threading.Lock()
_REPORT_PENDING: set[Path] = set()
_REPORT_WRITTEN_REVISION: dict[Path, int] = {}
_REPORT_THREAD: threading.Thread | None = None


@dataclass(slots=True)
class _RouteMetricsBucket:
    counters: Counter[tuple[str, str, str]] = field(default_factory=Counter)
    total: int = 0
    rust: int = 0
    fail_safe: int = 0
    python: int = 0
    revision: int = 0


_AGGREGATE = _RouteMetricsBucket()
_HOME_BUCKETS: dict[Path, _RouteMetricsBucket] = {}


@dataclass(frozen=True, slots=True)
class NativeDecisionReceipt:
    schema: str
    decision_backend: NativeDecisionBackend
    decision_core: str
    native_transport: NativeTransport
    reason_code: str

    def as_metrics(self) -> dict[str, object]:
        return {
            "backend_receipt_schema": self.schema,
            "decision_backend": self.decision_backend,
            "decision_core": self.decision_core,
            "native_transport": self.native_transport,
            "fallback_reason_code": self.reason_code,
        }


def _bounded_code(value: str, *, fallback: str) -> str:
    candidate = value.strip().lower().replace(" ", "_")
    if not candidate or len(candidate) > _MAX_CODE_LENGTH:
        return fallback
    if not all(character.isalnum() or character in {"_", "-", "."} for character in candidate):
        return fallback
    return candidate


def native_decision_receipt(
    *,
    backend: NativeDecisionBackend,
    transport: NativeTransport,
    decision_core: str,
    reason_code: str,
) -> NativeDecisionReceipt:
    if backend not in _ALLOWED_BACKENDS:
        raise ValueError("unsupported decision backend")
    if transport not in _ALLOWED_TRANSPORTS:
        raise ValueError("unsupported native transport")
    return NativeDecisionReceipt(
        schema="hol-guard-native-backend-receipt.v1",
        decision_backend=backend,
        decision_core=_bounded_code(decision_core, fallback="unknown_core"),
        native_transport=transport,
        reason_code=_bounded_code(reason_code, fallback="unknown_reason"),
    )


def attach_native_decision_receipt(
    response: HookReviewResponse,
    receipt: NativeDecisionReceipt,
) -> HookReviewResponse:
    metrics = dict(response.metrics)
    metrics.update(receipt.as_metrics())
    return replace(response, metrics=metrics)


def native_route_metrics_report_path(guard_home: Path) -> Path:
    return guard_home.expanduser() / _REPORT_DIRECTORY / _REPORT_FILENAME


def _record_bucket(
    bucket: _RouteMetricsBucket,
    key: tuple[str, str, str],
    backend: NativeDecisionBackend,
) -> None:
    bucket.counters[key] += 1
    bucket.total += 1
    bucket.revision += 1
    if backend == "rust_native":
        bucket.rust += 1
    elif backend == "native_fail_safe":
        bucket.fail_safe += 1
    else:
        bucket.python += 1


def record_native_decision(
    event_name: str,
    harness: str,
    receipt: NativeDecisionReceipt,
    *,
    guard_home: Path | None = None,
) -> None:
    del harness  # Harness identity is intentionally not retained in aggregate route counters.
    event = _bounded_code(event_name, fallback="unknown_event")
    key = (event, receipt.decision_backend, receipt.reason_code)
    report_path = native_route_metrics_report_path(guard_home) if guard_home is not None else None
    with _LOCK:
        _record_bucket(_AGGREGATE, key, receipt.decision_backend)
        if report_path is not None:
            bucket = _HOME_BUCKETS.setdefault(report_path, _RouteMetricsBucket())
            _record_bucket(bucket, key, receipt.decision_backend)
    if report_path is not None:
        _schedule_report(report_path)


def _snapshot_from_bucket(bucket: _RouteMetricsBucket | None) -> dict[str, object]:
    if bucket is None:
        total = rust = fail_safe = python = revision = 0
        counters: dict[tuple[str, str, str], int] = {}
    else:
        total = bucket.total
        rust = bucket.rust
        fail_safe = bucket.fail_safe
        python = bucket.python
        revision = bucket.revision
        counters = dict(bucket.counters)
    return {
        "schema": "hol-guard-native-route-metrics.v1",
        "revision": revision,
        "total_outcomes": total,
        "rust_decisions": rust,
        "native_fail_safe_outcomes": fail_safe,
        "python_decisions": python,
        "rust_decision_share": 1.0 if total == 0 else rust / total,
        "native_fail_safe_share": 0.0 if total == 0 else fail_safe / total,
        "python_decision_fallback_share": 0.0 if total == 0 else python / total,
        "routes": [
            {
                "event": event,
                "backend": backend,
                "reason_code": reason,
                "count": count,
            }
            for (event, backend, reason), count in sorted(counters.items())
        ],
    }


def native_route_metrics_snapshot(*, guard_home: Path | None = None) -> dict[str, object]:
    with _LOCK:
        if guard_home is None:
            bucket = _RouteMetricsBucket(
                counters=Counter(_AGGREGATE.counters),
                total=_AGGREGATE.total,
                rust=_AGGREGATE.rust,
                fail_safe=_AGGREGATE.fail_safe,
                python=_AGGREGATE.python,
                revision=_AGGREGATE.revision,
            )
        else:
            source = _HOME_BUCKETS.get(native_route_metrics_report_path(guard_home))
            bucket = (
                None
                if source is None
                else _RouteMetricsBucket(
                    counters=Counter(source.counters),
                    total=source.total,
                    rust=source.rust,
                    fail_safe=source.fail_safe,
                    python=source.python,
                    revision=source.revision,
                )
            )
    return _snapshot_from_bucket(bucket)


def _snapshot_for_report(path: Path) -> dict[str, object]:
    with _LOCK:
        source = _HOME_BUCKETS.get(path)
        bucket = (
            None
            if source is None
            else _RouteMetricsBucket(
                counters=Counter(source.counters),
                total=source.total,
                rust=source.rust,
                fail_safe=source.fail_safe,
                python=source.python,
                revision=source.revision,
            )
        )
    return _snapshot_from_bucket(bucket)


def _metrics_revision(path: Path) -> int:
    with _LOCK:
        bucket = _HOME_BUCKETS.get(path)
        return 0 if bucket is None else bucket.revision


def _schedule_report(path: Path) -> None:
    try:
        lexical = path.expanduser()
    except (OSError, RuntimeError, ValueError):
        return
    with _REPORT_STATE_LOCK:
        if lexical in _REPORT_PENDING:
            return
        _REPORT_PENDING.add(lexical)
        _ensure_report_thread_locked()
    try:
        _REPORT_QUEUE.put_nowait(lexical)
    except queue.Full:
        with _REPORT_STATE_LOCK:
            _REPORT_PENDING.discard(lexical)


def _ensure_report_thread_locked() -> None:
    global _REPORT_THREAD
    if _REPORT_THREAD is not None and _REPORT_THREAD.is_alive():
        return
    _REPORT_THREAD = threading.Thread(
        target=_report_worker,
        name="hol-guard-native-route-report",
        daemon=True,
    )
    _REPORT_THREAD.start()


def _report_worker() -> None:
    while True:
        path = _REPORT_QUEUE.get()
        written_revision = -1
        requeue_after_task_done = False
        try:
            time.sleep(_REPORT_COALESCE_SECONDS)
            snapshot = _snapshot_for_report(path)
            written_revision = int(snapshot["revision"])
            _write_report(path, snapshot)
        except (OSError, RuntimeError, TypeError, ValueError):
            pass
        finally:
            current_revision = _metrics_revision(path)
            with _REPORT_STATE_LOCK:
                if written_revision >= 0:
                    _REPORT_WRITTEN_REVISION[path] = max(
                        written_revision,
                        _REPORT_WRITTEN_REVISION.get(path, -1),
                    )
                if written_revision >= 0 and current_revision > written_revision:
                    # Enqueue the follow-up before task_done so unfinished_tasks
                    # cannot transiently reach zero while a newer revision is
                    # waiting to be persisted.
                    try:
                        _REPORT_QUEUE.put_nowait(path)
                    except queue.Full:
                        _REPORT_PENDING.discard(path)
                        requeue_after_task_done = True
                else:
                    _REPORT_PENDING.discard(path)
            _REPORT_QUEUE.task_done()
            if requeue_after_task_done:
                # A full queue already has unfinished tasks, so scheduling here
                # cannot create the stale-idle race that the common path avoids.
                _schedule_report(path)


def _write_report(path: Path, snapshot: dict[str, object]) -> None:
    directory = path.parent
    guard_home = directory.parent
    guard_metadata = guard_home.lstat()
    if stat.S_ISLNK(guard_metadata.st_mode) or not stat.S_ISDIR(guard_metadata.st_mode):
        raise OSError("native route report guard home is not a regular directory")
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    directory_metadata = directory.lstat()
    if stat.S_ISLNK(directory_metadata.st_mode) or not stat.S_ISDIR(directory_metadata.st_mode):
        raise OSError("native route report directory is not a regular directory")
    if os.name != "nt":
        current_uid = os.getuid() if hasattr(os, "getuid") else None
        if current_uid is not None and directory_metadata.st_uid != current_uid:
            raise OSError("native route report directory has an unexpected owner")
        if stat.S_IMODE(directory_metadata.st_mode) & 0o077:
            os.chmod(  # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
                directory,
                0o700,
            )
    temporary = directory / f".{_REPORT_FILENAME}.{uuid4().hex}.tmp"
    payload = json.dumps(
        snapshot,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    descriptor = os.open(
        temporary,
        os.O_CREAT
        | os.O_EXCL
        | os.O_WRONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written < 1:
                raise OSError("native route report write made no progress")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        os.replace(temporary, path)
        if os.name != "nt":
            os.chmod(path, 0o600)
    finally:
        temporary.unlink(missing_ok=True)


def _report_is_current(path: Path) -> bool:
    current_revision = _metrics_revision(path)
    with _REPORT_STATE_LOCK:
        written_revision = _REPORT_WRITTEN_REVISION.get(path, 0)
        pending = path in _REPORT_PENDING
    return not pending and written_revision >= current_revision


def flush_native_route_metrics_report_for_tests(
    timeout_seconds: float = 2.0,
    *,
    guard_home: Path | None = None,
) -> bool:
    deadline = time.monotonic() + max(0.0, timeout_seconds)
    report_path = native_route_metrics_report_path(guard_home) if guard_home is not None else None
    while time.monotonic() < deadline:
        if report_path is not None:
            if _report_is_current(report_path):
                return True
        else:
            with _LOCK:
                paths = tuple(_HOME_BUCKETS)
            if _REPORT_QUEUE.unfinished_tasks == 0 and all(_report_is_current(path) for path in paths):
                return True
        time.sleep(0.01)
    if report_path is not None:
        return _report_is_current(report_path)
    with _LOCK:
        paths = tuple(_HOME_BUCKETS)
    return _REPORT_QUEUE.unfinished_tasks == 0 and all(_report_is_current(path) for path in paths)


def reset_native_route_metrics_for_tests() -> None:
    with _LOCK:
        _AGGREGATE.counters.clear()
        _AGGREGATE.total = 0
        _AGGREGATE.rust = 0
        _AGGREGATE.fail_safe = 0
        _AGGREGATE.python = 0
        _AGGREGATE.revision = 0
        _HOME_BUCKETS.clear()
    with _REPORT_STATE_LOCK:
        _REPORT_WRITTEN_REVISION.clear()


__all__ = [
    "NativeDecisionBackend",
    "NativeDecisionReceipt",
    "NativeTransport",
    "attach_native_decision_receipt",
    "flush_native_route_metrics_report_for_tests",
    "native_decision_receipt",
    "native_route_metrics_report_path",
    "native_route_metrics_snapshot",
    "record_native_decision",
    "reset_native_route_metrics_for_tests",
]
