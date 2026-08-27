"""Privacy-safe aggregate evidence for Rust decision-route ownership.

The hook path performs only bounded in-memory counter updates and a non-blocking
report enqueue. A daemon thread writes an owner-private aggregate report outside
the request path. Reports never contain commands, prompts, output, paths,
secrets, users, hosts, or workspace identifiers.
"""

from __future__ import annotations

import json
import os
import queue
import stat
import threading
import time
from collections import Counter
from dataclasses import dataclass, replace
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
_COUNTERS: Counter[tuple[str, str, str]] = Counter()
_TOTAL = 0
_RUST = 0
_FAIL_SAFE = 0
_PYTHON = 0
_REVISION = 0
_REPORT_QUEUE: queue.Queue[Path] = queue.Queue(maxsize=_REPORT_QUEUE_CAPACITY)
_REPORT_STATE_LOCK = threading.Lock()
_REPORT_PENDING: set[Path] = set()
_REPORT_THREAD: threading.Thread | None = None


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
    return guard_home / _REPORT_DIRECTORY / _REPORT_FILENAME


def record_native_decision(
    event_name: str,
    harness: str,
    receipt: NativeDecisionReceipt,
    *,
    guard_home: Path | None = None,
) -> None:
    del harness  # Harness identity is intentionally not retained in aggregate route counters.
    global _TOTAL, _RUST, _FAIL_SAFE, _PYTHON, _REVISION
    event = _bounded_code(event_name, fallback="unknown_event")
    key = (event, receipt.decision_backend, receipt.reason_code)
    with _LOCK:
        _COUNTERS[key] += 1
        _TOTAL += 1
        _REVISION += 1
        if receipt.decision_backend == "rust_native":
            _RUST += 1
        elif receipt.decision_backend == "native_fail_safe":
            _FAIL_SAFE += 1
        else:
            _PYTHON += 1
    if guard_home is not None:
        _schedule_report(native_route_metrics_report_path(guard_home))


def native_route_metrics_snapshot() -> dict[str, object]:
    with _LOCK:
        total = _TOTAL
        rust = _RUST
        fail_safe = _FAIL_SAFE
        python = _PYTHON
        revision = _REVISION
        counters = dict(_COUNTERS)
    payload: dict[str, object] = {
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
    return payload


def _metrics_revision() -> int:
    with _LOCK:
        return _REVISION


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
        try:
            time.sleep(_REPORT_COALESCE_SECONDS)
            snapshot = native_route_metrics_snapshot()
            written_revision = int(snapshot["revision"])
            _write_report(path, snapshot)
        except (OSError, RuntimeError, TypeError, ValueError):
            pass
        finally:
            with _REPORT_STATE_LOCK:
                _REPORT_PENDING.discard(path)
            _REPORT_QUEUE.task_done()
            if written_revision >= 0 and _metrics_revision() > written_revision:
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
            # Owner-only directory access is intentional for local security evidence.
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


def flush_native_route_metrics_report_for_tests(timeout_seconds: float = 2.0) -> bool:
    deadline = time.monotonic() + max(0.0, timeout_seconds)
    while time.monotonic() < deadline:
        if _REPORT_QUEUE.unfinished_tasks == 0:
            return True
        time.sleep(0.01)
    return _REPORT_QUEUE.unfinished_tasks == 0


def reset_native_route_metrics_for_tests() -> None:
    global _TOTAL, _RUST, _FAIL_SAFE, _PYTHON, _REVISION
    with _LOCK:
        _COUNTERS.clear()
        _TOTAL = 0
        _RUST = 0
        _FAIL_SAFE = 0
        _PYTHON = 0
        _REVISION = 0


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
