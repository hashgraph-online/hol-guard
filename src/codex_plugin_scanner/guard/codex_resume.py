"""Codex browser approval resume orchestration and diagnostics."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from collections.abc import Mapping
from pathlib import Path

from .codex_app_server import build_codex_continuation_prompt, resume_codex_thread_for_request
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
_SOCKET_KEYS = ("codex_app_server_socket", "app_server_socket", "appServerSocket")
_CODEX_HOME_KEYS = ("codex_home", "codexHome")
_COMMAND_TEXT_KEYS = ("command_text", "commandText")
_APP_SERVER_FALLBACK_REASONS = {
    "invalid_turn_start_response",
    "missing_turn_start_response",
    "socket_not_available",
    "turn_start_error",
    "turn_start_timeout",
    "unsafe_socket_path",
}
_CODEX_EXEC_RESUME_TIMEOUT_SECONDS = 120.0
_SAFE_CODEX_SESSION_ID_PATTERN = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


def seed_request_resume_record(store: GuardStore, *, request_id: str, now: str) -> dict[str, object] | None:
    request = store.get_approval_request(request_id)
    if request is None or str(request.get("harness")) != "codex":
        return None
    operation = store.get_guard_operation_for_approval_request(request_id)
    metadata = operation.get("metadata") if isinstance(operation, dict) else None
    thread_id = _first_string(metadata, _THREAD_ID_KEYS) if isinstance(metadata, Mapping) else None
    socket_path = _first_string(metadata, _SOCKET_KEYS) if isinstance(metadata, Mapping) else None
    strategy = "manual-only"
    if thread_id is not None:
        strategy = "codex-app-server-thread" if socket_path is not None else "codex-exec-resume"
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
            "message": "Codex was already resumed for this request.",
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
        message="Resuming Codex...",
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


def inspect_codex_resume_capabilities(store: GuardStore) -> dict[str, object]:
    binary_path = shutil.which("codex")
    app_server_support = _command_available(["codex", "app-server", "--help"]) if binary_path else False
    remote_control_support = _command_available(["codex", "remote-control", "--help"]) if binary_path else False
    headless_resume_support = _command_available(["codex", "exec", "resume", "--help"]) if binary_path else False
    latest_attempt = store.get_latest_request_resume(harness="codex")
    return {
        "codex_binary_found": binary_path is not None,
        "app_server_support": app_server_support,
        "remote_control_support": remote_control_support,
        "headless_resume_support": headless_resume_support,
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
    if strategy == "codex-exec-resume":
        return _resume_codex_exec_session(store=store, request_id=request_id, action=action, thread_id=thread_id)

    app_server_result = resume_codex_thread_for_request(store=store, request_id=request_id, action=action)
    if app_server_result is None:
        return _resume_codex_exec_session(store=store, request_id=request_id, action=action, thread_id=thread_id)
    if str(app_server_result.get("status") or "") == "sent":
        return app_server_result
    if str(app_server_result.get("reason") or "") not in _APP_SERVER_FALLBACK_REASONS:
        return app_server_result

    exec_result = _resume_codex_exec_session(store=store, request_id=request_id, action=action, thread_id=thread_id)
    if exec_result is not None and str(exec_result.get("status") or "") == "sent":
        return exec_result
    return exec_result or app_server_result


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
            "message": "Codex resumed. Watch the chat for the next HOL Guard message.",
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


def _resume_codex_exec_session(
    *,
    store: GuardStore,
    request_id: str,
    action: str,
    thread_id: str,
) -> dict[str, object]:
    operation = store.get_guard_operation_for_approval_request(request_id)
    metadata = operation.get("metadata") if isinstance(operation, dict) else None
    session_id = (
        str(operation["session_id"])
        if isinstance(operation, dict) and operation.get("session_id") is not None
        else None
    )
    session = store.get_guard_session(session_id) if session_id is not None else None
    workspace = (
        str(session["workspace"]) if isinstance(session, dict) and session.get("workspace") is not None else None
    )
    if not _is_safe_codex_session_id(thread_id):
        return {
            "status": "failed",
            "reason": "unsafe_thread_id",
            "message": "Codex session metadata was not safe to resume automatically.",
            "last_error": "unsafe Codex session id",
            "thread_id": thread_id,
            "strategy": "codex-exec-resume",
            "supported": True,
        }
    if shutil.which("codex") is None:
        return {
            "status": "failed",
            "reason": "codex_not_found",
            "message": "The codex binary is not available for automatic resume.",
            "last_error": "codex binary not found",
            "thread_id": thread_id,
            "strategy": "codex-exec-resume",
            "supported": True,
        }
    command_text = _first_string(metadata, _COMMAND_TEXT_KEYS) if isinstance(metadata, Mapping) else None
    if command_text is not None and not _is_safe_resume_prompt_text(command_text):
        command_text = None
    prompt = build_codex_continuation_prompt(
        action,
        request_id=request_id,
        command_text=command_text,
    )
    command = [
        "codex",
        "exec",
        "resume",
        "--json",
        "--dangerously-bypass-approvals-and-sandbox",
        "--dangerously-bypass-hook-trust",
        "--ignore-user-config",
        "--skip-git-repo-check",
        thread_id,
        "-",
    ]
    env = os.environ.copy()
    codex_home = _first_string(metadata, _CODEX_HOME_KEYS) if isinstance(metadata, Mapping) else None
    if codex_home is not None and _is_safe_local_directory(codex_home):
        env["CODEX_HOME"] = codex_home
    cwd = workspace if workspace is not None and _is_safe_local_directory(workspace) else None
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            check=False,
            cwd=cwd,
            env=env,
            input=prompt,
            text=True,
            timeout=_CODEX_EXEC_RESUME_TIMEOUT_SECONDS,
        )
    except FileNotFoundError:
        return {
            "status": "failed",
            "reason": "codex_not_found",
            "message": "The codex binary is not available for automatic resume.",
            "last_error": "codex binary not found",
            "thread_id": thread_id,
            "strategy": "codex-exec-resume",
            "supported": True,
        }
    except OSError as error:
        return {
            "status": "failed",
            "reason": "exec_resume_launch_failed",
            "message": "Guard could not start Codex for automatic resume.",
            "last_error": str(error),
            "thread_id": thread_id,
            "strategy": "codex-exec-resume",
            "supported": True,
        }
    except subprocess.TimeoutExpired:
        return {
            "status": "failed",
            "reason": "exec_resume_timeout",
            "message": "Codex did not finish the automatic resume prompt in time.",
            "last_error": "timed out waiting for codex exec resume",
            "thread_id": thread_id,
            "strategy": "codex-exec-resume",
            "supported": True,
        }
    if result.returncode == 0:
        return {
            "status": "sent",
            "reason": "exec_resume_sent",
            "thread_id": thread_id,
            "strategy": "codex-exec-resume",
            "supported": True,
        }
    failure_output = (result.stderr or result.stdout or "").strip()
    return {
        "status": "failed",
        "reason": "exec_resume_failed",
        "message": "Codex rejected the automatic resume prompt.",
        "last_error": failure_output or "codex exec resume exited with a non-zero status",
        "thread_id": thread_id,
        "strategy": "codex-exec-resume",
        "supported": True,
    }


def _is_safe_codex_session_id(value: str) -> bool:
    return bool(_SAFE_CODEX_SESSION_ID_PATTERN.fullmatch(value))


def _is_safe_resume_prompt_text(value: str) -> bool:
    if "\x00" in value or len(value) > 4000:
        return False
    return all(character in "\n\r\t" or 32 <= ord(character) <= 126 for character in value)


def _is_safe_local_directory(raw_path: str) -> bool:
    if "\x00" in raw_path or not raw_path.strip():
        return False
    try:
        path = Path(raw_path).expanduser().resolve(strict=False)
    except (OSError, RuntimeError, ValueError):
        return False
    return path.is_dir()


def _manual_resume_message(action: str) -> str:
    if action == "block":
        return (
            "Decision saved. HOL Guard could not find the Codex session to resume. "
            "Do not retry that action in Codex. Ask for a safe alternative instead."
        )
    return (
        "Decision saved. HOL Guard could not find the Codex session to resume. "
        "Retry the same request in Codex; it should pass because this approval is now saved."
    )


def _failed_resume_message(action: str) -> str:
    if action == "block":
        return (
            "Decision saved. HOL Guard could not resume Codex automatically. "
            "Do not retry that action in Codex. Ask for a safe alternative instead."
        )
    return (
        "Decision saved. HOL Guard could not resume Codex automatically. "
        "Retry the same request in Codex; it should pass because this approval is now saved."
    )


def _first_string(mapping: Mapping[str, object], keys: tuple[str, ...]) -> str | None:
    for key in keys:
        value = mapping.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return None


def _command_available(command: list[str]) -> bool:
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            check=False,
            text=True,
            timeout=5,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0
