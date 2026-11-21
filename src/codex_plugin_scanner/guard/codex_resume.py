"""Codex browser approval resume orchestration and diagnostics.

The native resident owns the resume record: it seeds it from the queued Codex
operation, decides each retry, proves a waiting hook is still live, sends the
continuation to the original thread, reads the capability report and records
the outcome (``codex_request_resume`` op). Python keeps the storage gate around
the call and renders the answer. A resident that cannot answer resumes nothing.
"""

from __future__ import annotations

import os
import tempfile
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

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
    """Let an active Codex hook consume the saved browser decision itself.

    The resident proves the hook is still waiting; ``None`` means it is not.
    """

    payload = _resume_call(store, call="defer_live", request_id=request_id, now=now, action=action)
    if payload is None:
        raise ResumeUnavailableError()
    return _resume(payload)


def inspect_codex_resume_capabilities(store: GuardStore) -> dict[str, object]:
    # Without a native answer nothing is proven: no socket, no recorded attempt.
    payload = _resume_call(store, call="capabilities", request_id="codex-capabilities", now=_now())
    socket_available = payload is not None and payload.get("app_server_socket_available") is True
    latest = payload.get("latest_attempt") if payload is not None else None
    latest_attempt = dict(latest) if isinstance(latest, dict) else None
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


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


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
        "codex_home": os.environ.get("CODEX_HOME", "").strip() or None,
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
