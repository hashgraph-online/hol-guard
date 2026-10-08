"""Freeze a proven Codex PreToolUse hook wait for exact Cloud resumption."""

from __future__ import annotations

import logging
import sqlite3
import uuid
from collections.abc import Mapping
from datetime import datetime, timedelta
from pathlib import Path

from ..config import MAX_APPROVAL_WAIT_TIMEOUT_SECONDS
from ..continuation_snapshot import validated_continuation_snapshot
from ..live_process_identity import (
    CODEX_BROWSER_WAIT_PROCESS_KEY,
    bound_wait_timeout_seconds,
    process_identity_matches,
)
from ..review_correlation import cloud_review_correlation_id

_LOGGER = logging.getLogger(__name__)


def _live_codex_wait(
    *,
    harness: str,
    payload: Mapping[str, object],
    request_id: str,
    now: datetime,
) -> tuple[dict[str, object], datetime, int, dict[str, object]] | None:
    """Freeze the attached hook before the approval insert copies its snapshot."""

    if harness.strip().lower() != "codex":
        return None
    from .hook_request_parsing import runtime_hook_event_name

    if runtime_hook_event_name(payload) != "PreToolUse":
        return None
    identity = _proven_codex_wait_process(payload)
    timeout_seconds = bound_wait_timeout_seconds(payload, maximum=MAX_APPROVAL_WAIT_TIMEOUT_SECONDS)
    if identity is None or timeout_seconds is None:
        return None
    deadline = now + timedelta(seconds=timeout_seconds)
    snapshot = validated_continuation_snapshot(
        {
            "capability": "suspended-response",
            "correlationId": cloud_review_correlation_id(request_id),
            "hookAttached": True,
            "opaqueTargetId": None,
            "waitDeadline": deadline.isoformat(),
        }
    )
    if snapshot is None:
        return None
    return snapshot, deadline, timeout_seconds, identity


def _bind_live_codex_hook_wait(
    store: object,
    *,
    request_id: str,
    workspace: Path | None,
    now: datetime,
    live_wait: tuple[dict[str, object], datetime, int, dict[str, object]] | None,
) -> None:
    """Record a proven waiting Codex hook so exact Cloud apply can resume it.

    A native pause previously stored only the approval row. Continuation then
    treated the still-running hook as retry-only and the original action stayed
    denied. A process that is not this live bridge does not become authority.
    The deadline is the same instant frozen on the approval snapshot.
    """

    if live_wait is None:
        return
    _snapshot, deadline, timeout_seconds, identity = live_wait
    upsert_session = getattr(store, "upsert_guard_session", None)
    upsert_operation = getattr(store, "upsert_guard_operation", None)
    if not callable(upsert_session) or not callable(upsert_operation):
        return
    now_text = now.isoformat()
    try:
        session = upsert_session(
            session_id=uuid.uuid4().hex,
            harness="codex",
            surface="harness-adapter",
            status="active",
            client_name="codex-hook",
            client_title="codex hook",
            client_version="1.0.0",
            workspace=str(workspace) if workspace is not None else None,
            capabilities=["approval-resolution"],
            now=now_text,
        )
        session_id = session.get("session_id") if isinstance(session, dict) else None
        if not isinstance(session_id, str) or not session_id:
            return
        upsert_operation(
            operation_id=uuid.uuid4().hex,
            session_id=session_id,
            harness="codex",
            operation_type="tool_call",
            status="waiting_on_approval",
            approval_request_ids=[request_id],
            resume_token=None,
            metadata={
                "codex_hook_waits_for_browser_approval": True,
                "codex_browser_wait_deadline_at": deadline.isoformat(),
                "codex_browser_wait_process": identity,
                "codex_browser_wait_timeout_seconds": timeout_seconds,
                "hook_event_name": "PreToolUse",
                "event": "PreToolUse",
                "workspace": str(workspace) if workspace is not None else None,
            },
            now=now_text,
        )
        from ..codex_resume import seed_request_resume_record
        from ..store import GuardStore

        if isinstance(store, GuardStore):
            seed_request_resume_record(store, request_id=request_id, now=now_text)
    except (OSError, RuntimeError, TypeError, ValueError, sqlite3.Error):
        _LOGGER.warning("Native Codex wait binding failed for %s", request_id)


def _proven_codex_wait_process(payload: Mapping[str, object]) -> dict[str, object] | None:
    raw = payload.get(CODEX_BROWSER_WAIT_PROCESS_KEY)
    if not isinstance(raw, dict) or set(raw) != {"pid", "startToken"}:
        return None
    pid = raw.get("pid")
    start_token = raw.get("startToken")
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        return None
    if not isinstance(start_token, str) or not start_token:
        return None
    # A live start token can match this process.
    if not process_identity_matches(raw):  # NOSONAR
        return None
    return {"pid": pid, "startToken": start_token}
