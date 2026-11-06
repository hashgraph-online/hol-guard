"""Codex browser approval resume orchestration and diagnostics.

The native resident owns the resume record: it seeds it from the queued Codex
operation, decides each retry, sends the continuation to the original thread
and records the outcome (``codex_request_resume`` op). Python keeps the
storage gate around the call, the live-hook checks a deferral needs and the
capability report. A resident that cannot answer resumes nothing.
"""

from __future__ import annotations

import os
import tempfile
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from .codex_app_server import default_codex_app_server_socket_available
from .native_context import ensure_resident_prerequisite
from .native_execution import _resident_request
from .native_store_policy import _payload
from .store import GuardStore
from .store_base import sqlite_connect_timeout_seconds


class ResumeNotSupportedError(ValueError):
    """Raised when an approval request cannot be resumed automatically."""

    def __init__(self) -> None:
        super().__init__("resume_not_supported")


class ResumeUnavailableError(ValueError):
    """Raised when the native resident gave no answer for a status read or retry."""

    def __init__(self) -> None:
        super().__init__("resume_unavailable")


_FEATURE = "codex-request-resume-v1"
_REQUEST_SCHEMA = "guard-codex-request-resume-request.v1"
_RESULT_SCHEMA = "guard-codex-request-resume-result.v1"
_MAX_REQUEST_BYTES = 64 * 1024
_MAX_TIMEOUT_MS = 60_000
_MAX_BUSY_TIMEOUT_MS = 10_000
_DEFAULT_CONTINUE_TIMEOUT_SECONDS = 5.0
_TRANSPORT_GRACE_SECONDS = 5.0
_REFUSALS = {"not_found", "not_resolved", "resume_not_supported"}


def seed_request_resume_record(store: GuardStore, *, request_id: str, now: str) -> dict[str, object] | None:
    payload = _resume_call(store, call="seed", request_id=request_id, now=now)
    return _resume(payload)


def get_request_resume_status(store: GuardStore, *, request_id: str, now: str) -> dict[str, object] | None:
    payload = _resume_call(store, call="status", request_id=request_id, now=now)
    if payload is None:
        raise ResumeUnavailableError()
    return _resume(payload)


def retry_request_resume(
    store: GuardStore,
    *,
    request_id: str,
    now: str,
    force: bool = False,
    timeout_seconds: float | None = None,
) -> dict[str, object]:
    payload = _resume_call(
        store,
        call="retry",
        request_id=request_id,
        now=now,
        force=force,
        timeout_seconds=timeout_seconds,
    )
    if payload is None:
        raise ResumeUnavailableError()
    error = payload.get("error")
    if error in _REFUSALS:
        if error == "resume_not_supported":
            raise ResumeNotSupportedError()
        raise ValueError(error)
    resume = _resume(payload)
    if resume is None:
        raise ResumeNotSupportedError()
    return resume


def defer_request_resume_to_live_hook(
    store: GuardStore,
    *,
    request_id: str,
    action: str,
    now: str,
) -> dict[str, object] | None:
    """Let an active Codex hook consume the saved browser decision itself."""

    operation = store.get_guard_operation_for_approval_request(request_id)
    if operation is None or str(operation.get("harness")) != "codex":
        return None
    if str(operation.get("status")) != "waiting_on_approval":
        return None
    metadata = operation.get("metadata")
    if not isinstance(metadata, Mapping):
        return None
    event_name = str(metadata.get("hook_event_name") or metadata.get("event") or "")
    if not _live_hook_wait_is_active(metadata=metadata, now=now) and not (
        event_name == "PreToolUse" and _pretool_bridge_wait_is_active(store, operation, now=now)
    ):
        return None
    payload = _resume_call(store, call="defer", request_id=request_id, now=now, action=action)
    if payload is None:
        raise ResumeUnavailableError()
    return _resume(payload)


def inspect_codex_resume_capabilities(store: GuardStore) -> dict[str, object]:
    socket_available = default_codex_app_server_socket_available()
    latest_attempt = store.get_latest_request_resume(harness="codex")
    return {
        "codex_binary_found": False,
        "app_server_support": socket_available,
        "app_server_support_reason": (
            "Same-chat continuation requires the Codex app-server remote-control socket. "
            "When the socket is missing, HOL Guard cannot visibly continue the open Codex App chat."
        ),
        "app_server_socket_available": socket_available,
        "headless_resume_support": False,
        "headless_resume_support_reason": (
            "Disabled by design. `codex exec resume` starts a separate background run and does not continue "
            "the visible Codex App chat. HOL Guard only auto-continues Codex through the app-server socket."
        ),
        "latest_attempt": latest_attempt,
    }


def _live_hook_wait_is_active(*, metadata: Mapping[str, object], now: str) -> bool:
    if metadata.get("codex_hook_waits_for_browser_approval") is not True:
        return False
    from .live_process_identity import process_identity_matches

    if not process_identity_matches(metadata.get("codex_browser_wait_process")):
        return False
    deadline = _first_string(metadata, ("codex_browser_wait_deadline_at", "browser_wait_deadline_at"))
    if deadline is None:
        return False
    deadline_at = _parse_timestamp(deadline)
    now_at = _parse_timestamp(now)
    if deadline_at is None or now_at is None:
        return False
    return now_at <= deadline_at


def _pretool_bridge_wait_is_active(
    store: GuardStore,
    operation: Mapping[str, object],
    *,
    now: str,
) -> bool:
    metadata = operation.get("metadata")
    if not isinstance(metadata, Mapping):
        return False
    from .codex_live_hook_target import codex_live_hook_wait_deadline

    deadline = codex_live_hook_wait_deadline(
        store,
        operation={**operation, "status": operation.get("status") or "waiting_on_approval"},
        metadata={**metadata, "hook_event_name": metadata.get("hook_event_name") or "PreToolUse"},
    )
    now_at = _parse_timestamp(now)
    return deadline is not None and now_at is not None and now_at <= deadline


def _parse_timestamp(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _resume_call(
    store: GuardStore,
    *,
    call: str,
    request_id: str,
    now: str,
    action: str | None = None,
    force: bool = False,
    timeout_seconds: float | None = None,
) -> dict[str, object] | None:
    """Run one call in the resident under the shared storage gate.

    Returns the bound payload, or ``None`` when the resident gave no answer.
    """

    seconds = _DEFAULT_CONTINUE_TIMEOUT_SECONDS if timeout_seconds is None else timeout_seconds
    timeout_ms = max(1, min(_MAX_TIMEOUT_MS, int(seconds * 1000)))
    busy_timeout_ms = max(1, min(_MAX_BUSY_TIMEOUT_MS, int(sqlite_connect_timeout_seconds() * 1000)))
    home = Path(store.guard_home)
    wire: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": f"codex-request-resume-{uuid4().hex}",
        "approval_request_id": request_id,
        "call": call,
        "action": action,
        "force": force,
        "now": now,
        "store_path": str(store.path),
        "guard_home": str(home),
        "busy_timeout_ms": busy_timeout_ms,
        "home_dir": str(Path.home()),
        "temp_dir": tempfile.gettempdir(),
        "cwd": os.getcwd(),
        "timeout_ms": timeout_ms,
    }
    if not ensure_resident_prerequisite(home):
        return None
    try:
        with store._hold_storage_gate(exclusive=False):  # pyright: ignore[reportPrivateUsage]
            try:
                response = _resident_request(
                    operation="codex_request_resume",
                    request=wire,
                    guard_home=home,
                    timeout_seconds=(timeout_ms + busy_timeout_ms) / 1000 + _TRANSPORT_GRACE_SECONDS,
                    required_feature=_FEATURE,
                    response_schema=_RESULT_SCHEMA,
                    max_request_bytes=_MAX_REQUEST_BYTES,
                    record_success=False,
                )
            except (TypeError, ValueError, OSError, RuntimeError):
                response = None
    except (OSError, TimeoutError):
        return None
    store._repair_store_permissions()  # pyright: ignore[reportPrivateUsage]
    return _payload(response, wire, home)


def _resume(payload: Mapping[str, object] | None) -> dict[str, object] | None:
    resume = payload.get("resume") if payload is not None else None
    return dict(resume) if isinstance(resume, dict) else None


def _first_string(mapping: Mapping[str, object], keys: tuple[str, ...]) -> str | None:
    for key in keys:
        value = mapping.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return None
