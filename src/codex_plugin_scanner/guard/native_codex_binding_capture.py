"""Opt-in Codex binding capture, served by the native runtime.

The capture is private evidence that binds Codex hook ingress to a Rust
native-edge receipt. It never authenticates ingress and never takes part in a
hook decision. The runtime owns the marker, the per-run key, every keyed
fingerprint, the sealed receipt and the output file; this module only forwards
JSON text and reports whether the runtime recorded it.

The capture is off unless a private marker exists, so each call first checks
for that one file and returns without any runtime traffic when it is absent.
Capture fails closed everywhere else, including Windows, where the runtime has
no descriptor-relative private-file support.
"""

from __future__ import annotations

import json
import os
import threading
from collections import deque
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Final
from uuid import uuid4

if TYPE_CHECKING:
    from .native_runtime_values import NativeRuntimeStatus

BINDING_CAPTURE_FEATURE: Final = "codex-binding-capture-v1"
_REQUEST_SCHEMA: Final = "guard-codex-binding-capture-request.v1"
_RESULT_SCHEMA: Final = "guard-codex-binding-capture-result.v1"
_MARKER_PARTS: Final = ("diagnostics", "codex-binding-capture.v2.json")
_MAX_TEXT_BYTES: Final = 65536
_TIMEOUT_SECONDS: Final = 2.0
_BRIDGE_TIMEOUT_SECONDS: Final = 0.2
_JOIN_PROBE_RECORDS: Final = 129
# One join row may exceed the 64 KiB capture ceiling so the runtime can return
# record_size. The row still has to fit inside the 256 KiB request cap.
_JOIN_RECORD_BYTES: Final = 256 * 1024 - 8192
_QUEUE_LIMIT: Final = 8
_canonical_request_sha256: Callable[[dict[str, object]], str] | None = None
ensure_resident_prerequisite: Callable[[Path], bool] | None = None
_resident_request: Callable[..., dict[str, object] | None] | None = None


def _bind_runtime_imports() -> tuple[
    Callable[[dict[str, object]], str],
    Callable[[Path], bool],
    Callable[..., dict[str, object] | None],
]:
    """Import the resident client only after a caller has decided to exchange."""

    global _canonical_request_sha256, ensure_resident_prerequisite, _resident_request
    if _canonical_request_sha256 is None:
        from .native_context import _canonical_request_sha256 as digest

        _canonical_request_sha256 = digest
    if ensure_resident_prerequisite is None:
        from .native_context import ensure_resident_prerequisite as prepare

        ensure_resident_prerequisite = prepare
    if _resident_request is None:
        from .native_execution import _resident_request as request

        _resident_request = request
    digest_fn = _canonical_request_sha256
    prepare_fn = ensure_resident_prerequisite
    request_fn = _resident_request
    if digest_fn is None or prepare_fn is None or request_fn is None:
        raise RuntimeError("binding capture runtime imports were not bound")
    return digest_fn, prepare_fn, request_fn


def _marker_present(guard_home: Path) -> bool:
    if os.name == "nt" or not guard_home.is_absolute():
        return False
    try:
        return os.path.lexists(guard_home.joinpath(*_MARKER_PARTS))
    except (OSError, ValueError):
        return False


def _exchange(
    guard_home: Path,
    command: dict[str, object],
    *,
    timeout_seconds: float = _TIMEOUT_SECONDS,
    prepare: bool = True,
    status: NativeRuntimeStatus | None = None,
) -> object | None:
    digest_fn, prepare_fn, request_fn = _bind_runtime_imports()
    request: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": f"codex-binding-capture-{uuid4().hex}",
        "guard_home": str(guard_home),
        "command": command,
    }
    try:
        digest = "sha256:" + digest_fn(request)
    except (TypeError, ValueError):
        return None
    if prepare and not prepare_fn(guard_home):
        return None
    response = request_fn(
        operation="codex_binding_capture",
        request=request,
        guard_home=guard_home,
        timeout_seconds=timeout_seconds,
        required_feature=BINDING_CAPTURE_FEATURE,
        response_schema=_RESULT_SCHEMA,
        record_resilience=False,
        status=status,
    )
    if (
        response is None
        or response.get("schema") != _RESULT_SCHEMA
        or response.get("request_id") != request["request_id"]
        or response.get("request_sha256") != digest
        or response.get("status") != "ok"
        or response.get("code") != "ok"
    ):
        return None
    return response.get("payload")


def _bounded_text(value: object) -> str | None:
    """UTF-8 text within the runtime's payload ceiling, or ``None``."""

    try:
        if type(value) is bytes:
            text = value.decode("utf-8")
        elif type(value) is str:
            text = value
            _ = text.encode("utf-8")
        else:
            return None
    except UnicodeError:
        return None
    return text if len(text) <= _MAX_TEXT_BYTES and len(text.encode("utf-8")) <= _MAX_TEXT_BYTES else None


def _recorded(payload: object) -> bool:
    return isinstance(payload, Mapping) and payload.get("recorded") is True


def _contains_oversized_text(value: object, limit: int) -> bool:
    if isinstance(value, str):
        return len(value.encode("utf-8")) > limit
    if isinstance(value, Mapping):
        return any(
            _contains_oversized_text(key, limit) or _contains_oversized_text(item, limit) for key, item in value.items()
        )
    if isinstance(value, (list, tuple)):
        return any(_contains_oversized_text(item, limit) for item in value)
    return False


def _bounded_json(value: object, limit: int = _MAX_TEXT_BYTES) -> str | None:
    """Compact UTF-8 JSON, or ``None`` once the byte ceiling is crossed."""

    if _contains_oversized_text(value, limit):
        return None
    encoder = json.JSONEncoder(sort_keys=True, separators=(",", ":"), allow_nan=False, ensure_ascii=False)
    try:
        parts: list[str] = []
        size = 0
        for chunk in encoder.iterencode(value):
            size += len(chunk.encode("utf-8"))
            if size > limit:
                return None
            parts.append(chunk)
    except (TypeError, ValueError, RecursionError):
        return None
    return "".join(parts)


def _bridge_resident_status(guard_home: Path) -> NativeRuntimeStatus | None:
    """Status of an already-idle resident, with no store provisioning and no spawn."""

    from .native_resident_client import native_resident_client_ready
    from .native_runtime import native_runtime_status

    status = native_runtime_status()
    identity = getattr(status, "identity", None)
    path = getattr(identity, "path", None)
    if not isinstance(path, Path) or not native_resident_client_ready(path, guard_home):
        return None
    return status


def record_bridge_ingress(
    *,
    guard_home: Path,
    raw_payload: str | bytes,
    event_name: str,
    forwarded_payload: str | bytes | None = None,
    harness: str = "codex",
) -> bool:
    """Record raw and forwarded ingress fingerprints when a marker enables it."""

    if harness != "codex" or not _marker_present(guard_home):
        return False
    raw = _bounded_text(raw_payload)
    forwarded = raw if forwarded_payload is None else _bounded_text(forwarded_payload)
    if raw is None or forwarded is None or not isinstance(event_name, str):
        return False
    status = _bridge_resident_status(guard_home)
    if status is None:
        return False
    return _recorded(
        _exchange(
            guard_home,
            {
                "kind": "bridge",
                "raw_payload": raw,
                "forwarded_payload": forwarded,
                "event_name": event_name,
                "harness": harness,
            },
            timeout_seconds=_BRIDGE_TIMEOUT_SECONDS,
            prepare=False,
            status=status,
        )
    )


def record_native_worker(
    *,
    guard_home: Path,
    payload: Mapping[str, object],
    harness: str,
    event_name: str,
    receipt: object,
) -> bool:
    """Record the forwarded payload and a validated native-edge receipt."""

    if harness != "codex" or not isinstance(event_name, str) or not _marker_present(guard_home):
        return False
    payload_text = _bounded_json(payload)
    receipt_text = _bounded_json(receipt)
    if payload_text is None or receipt_text is None:
        return False
    return _recorded(
        _exchange(
            guard_home,
            {
                "kind": "native",
                "payload": payload_text,
                "receipt": receipt_text,
                "event_name": event_name,
                "harness": harness,
            },
        )
    )


def initialize_capture_marker(
    guard_home: Path,
    *,
    run_id: str,
    expires_at: int,
    max_records: int | None = None,
    max_bytes: int | None = None,
) -> dict[str, object] | None:
    """Explicitly create one private v2 marker; the key stays in the runtime.

    Returns the session metadata (run id, key id, expiry and limits), never the
    key itself, or ``None`` when the runtime refused or is unavailable.
    """

    if os.name == "nt" or not guard_home.is_absolute():
        return None
    command: dict[str, object] = {"kind": "init_marker", "run_id": run_id, "expires_at": expires_at}
    command["max_records"] = max_records
    command["max_bytes"] = max_bytes
    payload = _exchange(guard_home, command)
    session = payload.get("session") if isinstance(payload, Mapping) else None
    return dict(session) if isinstance(session, Mapping) else None


def join_binding_records(guard_home: Path, records: list[object]) -> dict[str, object] | None:
    """Join capture rows with the marker's key, returning the runtime verdict."""

    if os.name == "nt" or not guard_home.is_absolute():
        return None
    encoded: list[str] = []
    encoded_bytes = 0
    for record in records:
        if len(encoded) >= _JOIN_PROBE_RECORDS:
            break
        text = _bounded_json(record, _JOIN_RECORD_BYTES)
        if text is None:
            return None
        encoded.append(text)
        encoded_bytes += len(text.encode("utf-8"))
        if encoded_bytes > _MAX_TEXT_BYTES:
            break
    payload = _exchange(guard_home, {"kind": "join", "records": encoded})
    result = payload.get("result") if isinstance(payload, Mapping) else None
    return dict(result) if isinstance(result, Mapping) else None


@dataclass(frozen=True, slots=True)
class _CaptureTask:
    guard_home: Path
    payload: str
    receipt: str
    event_name: str


class CodexBindingCaptureWriter:
    """Keep capture traffic out of native review and response delivery.

    Submission snapshots bounded JSON after the authority fence, never waits
    for the queue lock, and drops diagnostics when busy or full. The daemon
    owns the worker; shutdown does not wait for an in-flight capture request.
    """

    def __init__(self) -> None:
        self._pending: deque[_CaptureTask] = deque()
        self._lock = threading.Lock()
        self._stopped = threading.Event()
        self._thread = threading.Thread(target=self._run, name="codex-binding-capture", daemon=True)
        self._thread.start()

    def submit_native_capture(
        self,
        *,
        guard_home: Path,
        payload: Mapping[str, object],
        receipt: Mapping[str, object],
    ) -> bool:
        event_name = receipt.get("event_name")
        if self._stopped.is_set() or receipt.get("harness") != "codex" or not isinstance(event_name, str):
            return False
        if not self._lock.acquire(blocking=False):
            return False
        try:
            if self._stopped.is_set() or len(self._pending) >= _QUEUE_LIMIT or not _marker_present(guard_home):
                return False
            payload_text = _bounded_json(payload)
            receipt_text = _bounded_json(receipt)
            if payload_text is None or receipt_text is None:
                return False
            self._pending.append(_CaptureTask(guard_home, payload_text, receipt_text, event_name))
            return True
        finally:
            self._lock.release()

    def stop_capture(self) -> None:
        # Never wait for an in-flight request. The event prevents queued work
        # from running even if a submission temporarily owns the queue lock.
        self._stopped.set()
        if self._lock.acquire(blocking=False):
            try:
                self._pending.clear()
            finally:
                self._lock.release()

    def _run(self) -> None:
        while not self._stopped.wait(0.01):
            with self._lock:
                task = self._pending.popleft() if self._pending else None
            if task is None or self._stopped.is_set():
                continue
            with suppress(OSError, json.JSONDecodeError):
                _ = _exchange(
                    task.guard_home,
                    {
                        "kind": "native",
                        "payload": task.payload,
                        "receipt": task.receipt,
                        "event_name": task.event_name,
                        "harness": "codex",
                    },
                )


def start_codex_binding_capture_writer() -> CodexBindingCaptureWriter | None:
    try:
        return CodexBindingCaptureWriter()
    except Exception:
        return None
