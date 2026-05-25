"""Codex browser approval resume orchestration and diagnostics."""

from __future__ import annotations

import shutil
from collections.abc import Mapping

from .codex_app_server import default_codex_app_server_socket_available, resume_codex_thread_for_request
from .store import GuardStore

_THREAD_ID_KEYS = (
    "codex_thread_id",
    "thread_id",
    "threadId",
    "conversation_id",
    "conversationId",
    "session_id",
    "sessionId",
)


def seed_request_resume_record(store: GuardStore, *, request_id: str, now: str) -> dict[str, object] | None:
    request = store.get_approval_request(request_id)
    if request is None or str(request.get("harness")) != "codex":
        return None
    operation = store.get_guard_operation_for_approval_request(request_id)
    metadata = operation.get("metadata") if isinstance(operation, dict) else None
    thread_id = _first_string(metadata, _THREAD_ID_KEYS) if isinstance(metadata, Mapping) else None
    strategy = "manual-only"
    if thread_id is not None:
        strategy = "codex-app-server-thread"
    store.seed_request_resume(
        request_id=request_id,
        operation_id=str(operation["operation_id"]) if isinstance(operation, dict) else None,
        harness="codex",
        strategy=strategy,
        supported=thread_id is not None,
        thread_id=thread_id,
        now=now,
    )
    return store.get_request_resume(request_id)


def get_request_resume_status(store: GuardStore, *, request_id: str, now: str) -> dict[str, object] | None:
    resume = store.get_request_resume(request_id)
    if resume is not None:
        return resume
    return seed_request_resume_record(store, request_id=request_id, now=now)


def retry_request_resume(
    store: GuardStore,
    *,
    request_id: str,
    now: str,
    force: bool = False,
) -> dict[str, object]:
    request = store.get_approval_request(request_id)
    if request is None:
        raise ValueError("not_found")
    if str(request.get("harness")) != "codex":
        raise ValueError("resume_not_supported")
    action = request.get("resolution_action")
    if not isinstance(action, str) or not action:
        raise ValueError("not_resolved")
    resume = get_request_resume_status(store, request_id=request_id, now=now)
    if resume is None:
        raise ValueError("resume_not_supported")
    if str(resume.get("status")) == "sent" and not force:
        return {
            **resume,
            "status": "already_sent",
            "message": "HOL Guard already sent Codex a continuation message for this request.",
        }
    if str(resume.get("status")) == "in_progress":
        return resume
    attempt_count = int(resume.get("attempt_count") or 0) + 1
    store.update_request_resume(
        request_id=request_id,
        resolution_action=action,
        strategy=str(resume.get("strategy")) if isinstance(resume.get("strategy"), str) else None,
        supported=bool(resume.get("supported")) if resume.get("supported") is not None else None,
        status="in_progress",
        reason="attempting_resume",
        message="Sending Codex a continuation message...",
        last_error=None,
        attempt_count=attempt_count,
        last_attempt_at=now,
        sent_at=str(resume.get("sent_at")) if isinstance(resume.get("sent_at"), str) else None,
        now=now,
    )
    refreshed = store.get_request_resume(request_id)
    if refreshed is None:
        raise ValueError("resume_not_supported")
    final = _finalize_resume_attempt(
        store=store,
        request_id=request_id,
        action=action,
        resume=refreshed,
        now=now,
    )
    return final


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
    if not isinstance(metadata, Mapping) or metadata.get("codex_hook_waits_for_browser_approval") is not True:
        return None
    resume = get_request_resume_status(store, request_id=request_id, now=now)
    if resume is None:
        return None
    attempt_count = int(resume.get("attempt_count") or 0)
    message = (
        "Decision saved. Codex is still waiting for this browser decision, "
        "so HOL Guard will let the original Codex action continue without starting a second headless run."
    )
    store.update_request_resume(
        request_id=request_id,
        resolution_action=action,
        strategy=str(resume.get("strategy")) if isinstance(resume.get("strategy"), str) else None,
        supported=bool(resume.get("supported")) if resume.get("supported") is not None else None,
        status="pending",
        reason="live_hook_waiting",
        message=message,
        last_error=None,
        attempt_count=attempt_count,
        last_attempt_at=now,
        sent_at=str(resume.get("sent_at")) if isinstance(resume.get("sent_at"), str) else None,
        now=now,
    )
    return store.get_request_resume(request_id)


def inspect_codex_resume_capabilities(store: GuardStore) -> dict[str, object]:
    binary_path = shutil.which("codex")
    socket_available = default_codex_app_server_socket_available()
    latest_attempt = store.get_latest_request_resume(harness="codex")
    return {
        "codex_binary_found": binary_path is not None,
        "app_server_support": None,
        "app_server_support_reason": (
            "Codex does not expose a stable public app-server capability probe; "
            "same-thread continuation uses the local app-server socket when it is active."
        ),
        "app_server_socket_available": socket_available,
        "headless_resume_support": binary_path is not None,
        "headless_resume_support_reason": (
            "When the live app-server socket is gone, HOL Guard resumes saved Codex exec threads with "
            "`codex exec resume` from the original workspace."
            if binary_path is not None
            else "`codex` was not found on PATH, so HOL Guard can only save the approval for manual retry."
        ),
        "latest_attempt": latest_attempt,
    }


def _finalize_resume_attempt(
    *,
    store: GuardStore,
    request_id: str,
    action: str,
    resume: dict[str, object],
    now: str,
) -> dict[str, object]:
    strategy = str(resume["strategy"])
    supported = bool(resume["supported"])
    thread_id = str(resume["thread_id"]) if resume.get("thread_id") is not None else None
    attempt_count = int(resume["attempt_count"])
    if strategy == "manual-only" or not supported:
        message = _manual_resume_message(action)
        store.update_request_resume(
            request_id=request_id,
            resolution_action=action,
            strategy=str(resume.get("strategy")) if isinstance(resume.get("strategy"), str) else None,
            supported=bool(resume.get("supported")) if resume.get("supported") is not None else None,
            status="skipped",
            reason="session_not_found",
            message=message,
            last_error=None,
            attempt_count=attempt_count,
            last_attempt_at=now,
            sent_at=None,
            now=now,
        )
        result = store.get_request_resume(request_id)
        if result is None:
            raise ValueError("resume_not_supported")
        return result

    raw_result = _dispatch_resume_attempt(
        store=store,
        request_id=request_id,
        action=action,
        strategy=strategy,
        thread_id=thread_id,
    )
    normalized = _normalize_dispatch_result(
        action=action,
        strategy=strategy,
        thread_id=thread_id,
        raw_result=raw_result,
    )
    sent_at = now if normalized["status"] == "sent" else str(resume.get("sent_at")) if resume.get("sent_at") else None
    store.update_request_resume(
        request_id=request_id,
        resolution_action=action,
        strategy=str(normalized["strategy"]),
        supported=bool(normalized["supported"]),
        status=str(normalized["status"]),
        reason=str(normalized["reason"]) if normalized.get("reason") is not None else None,
        message=str(normalized["message"]) if normalized.get("message") is not None else None,
        last_error=str(normalized["last_error"]) if normalized.get("last_error") is not None else None,
        attempt_count=attempt_count,
        last_attempt_at=now,
        sent_at=sent_at,
        now=now,
    )
    result = store.get_request_resume(request_id)
    if result is None:
        raise ValueError("resume_not_supported")
    return result


def _dispatch_resume_attempt(
    *,
    store: GuardStore,
    request_id: str,
    action: str,
    strategy: str,
    thread_id: str | None,
) -> dict[str, object] | None:
    if thread_id is None:
        return None

    app_server_result = resume_codex_thread_for_request(store=store, request_id=request_id, action=action)
    if app_server_result is None:
        return {
            "status": "skipped",
            "reason": "session_not_found",
            "thread_id": thread_id,
            "strategy": strategy,
            "supported": False,
        }
    return app_server_result


def _normalize_dispatch_result(
    *,
    action: str,
    strategy: str,
    thread_id: str | None,
    raw_result: dict[str, object] | None,
) -> dict[str, object]:
    if raw_result is None:
        return {
            "status": "skipped",
            "reason": "session_not_found",
            "message": _manual_resume_message(action),
            "last_error": None,
            "thread_id": thread_id,
            "strategy": strategy,
            "supported": False,
        }
    effective_strategy = str(raw_result.get("strategy") or strategy)
    raw_status = str(raw_result.get("status") or "")
    raw_reason = str(raw_result.get("reason") or "unknown")
    raw_thread_id = str(raw_result.get("thread_id")) if raw_result.get("thread_id") is not None else thread_id
    raw_last_error = str(raw_result.get("last_error")) if raw_result.get("last_error") is not None else None
    raw_supported = raw_result.get("supported")
    supported = raw_supported if isinstance(raw_supported, bool) else raw_status != "skipped"
    if raw_status == "sent":
        return {
            "status": "sent",
            "reason": raw_reason,
            "message": "HOL Guard sent Codex a continuation message in the original chat.",
            "last_error": None,
            "thread_id": raw_thread_id,
            "strategy": effective_strategy,
            "supported": True,
        }
    if raw_reason in {"socket_not_available", "unsafe_socket_path", "turn_start_timeout", "turn_start_error"}:
        return {
            "status": "failed",
            "reason": raw_reason,
            "message": _failed_resume_message(action),
            "last_error": raw_last_error or str(raw_result.get("message") or raw_reason),
            "thread_id": raw_thread_id,
            "strategy": effective_strategy,
            "supported": True,
        }
    return {
        "status": "failed" if raw_status == "failed" else "skipped",
        "reason": raw_reason,
        "message": _failed_resume_message(action) if raw_status == "failed" else _manual_resume_message(action),
        "last_error": raw_last_error or str(raw_result.get("message") or raw_reason)
        if raw_status == "failed"
        else None,
        "thread_id": raw_thread_id,
        "strategy": effective_strategy,
        "supported": supported,
    }


def _manual_resume_message(action: str) -> str:
    if action == "block":
        return (
            "Decision saved. HOL Guard could not find the original Codex chat to message. "
            "Do not retry that action in Codex. Ask for a safe alternative instead."
        )
    return (
        "Decision saved. HOL Guard could not find the original Codex chat to message. "
        "Return to Codex and retry the same request; this approval is now saved."
    )


def _failed_resume_message(action: str) -> str:
    if action == "block":
        return (
            "Decision saved. HOL Guard could not send Codex a continuation message in the original chat. "
            "Do not retry that action in Codex. Ask for a safe alternative instead."
        )
    return (
        "Decision saved. HOL Guard could not send Codex a continuation message in the original chat. "
        "Return to Codex and retry the same request; this approval is now saved."
    )


def _first_string(mapping: Mapping[str, object], keys: tuple[str, ...]) -> str | None:
    for key in keys:
        value = mapping.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return None
