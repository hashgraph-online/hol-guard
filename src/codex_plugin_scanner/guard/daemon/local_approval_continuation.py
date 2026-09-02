"""Local approval continuation projection for daemon HTTP decisions."""

from __future__ import annotations

from collections.abc import Callable, Mapping

from ..codex_live_hook_target import codex_live_hook_process_is_unavailable
from ..codex_resume import defer_request_resume_to_live_hook, retry_request_resume
from ..codex_resume_response import project_codex_resume_response
from ..continuation_runtime import continue_request_after_application
from ..store import GuardStore


def apply_local_approval_continuation(
    *,
    store: GuardStore,
    updated: dict[str, object],
    request_id: str,
    action: str,
    harness: str,
    copy: dict[str, str],
    now: Callable[[], str],
) -> tuple[dict[str, object], dict[str, str]]:
    resolved_request = store.get_approval_request(request_id)
    if not isinstance(resolved_request, dict) or action not in {"allow", "block"}:
        return updated, copy
    if harness != "codex":
        continuation = continue_request_after_application(
            store,
            request_row=resolved_request,
            action=action,
            now=now(),
            headless=False,
        )
        harness_resume = continuation.get("harnessResume")
        if isinstance(harness_resume, dict):
            updated["harnessResume"] = harness_resume
        return updated, copy

    codex_resume = _codex_continuation(
        store=store,
        request_id=request_id,
        action=action,
        request=resolved_request,
        now=now,
    )
    if codex_resume is None:
        return updated, copy
    updated["codexResume"] = codex_resume
    store.add_event(
        "codex/thread_resume",
        {"request_id": request_id, "action": action, **codex_resume},
        now(),
    )
    updated = project_codex_resume_response(updated=updated, copy=copy, codex_resume=codex_resume)
    updated_copy = updated.get("copy")
    if isinstance(updated_copy, dict):
        title = _optional_string(updated_copy.get("title")) or copy["title"]
        body = _optional_string(updated_copy.get("body")) or copy["body"]
        copy = {"title": title, "body": body}
    return updated, copy


def _codex_continuation(
    *,
    store: GuardStore,
    request_id: str,
    action: str,
    request: dict[str, object],
    now: Callable[[], str],
) -> dict[str, object] | None:
    timestamp = now()
    codex_resume = defer_request_resume_to_live_hook(
        store,
        request_id=request_id,
        action=action,
        now=timestamp,
    )
    if codex_resume is not None:
        return codex_resume
    operation = store.get_guard_operation_for_approval_request(request_id)
    metadata = operation.get("metadata") if isinstance(operation, dict) else None
    if isinstance(metadata, Mapping) and codex_live_hook_process_is_unavailable(metadata):
        continuation = continue_request_after_application(
            store,
            request_row=request,
            action=action,
            now=timestamp,
            headless=False,
        )
        retry_payload = continuation.get("codexResume")
        if isinstance(retry_payload, dict):
            return retry_payload
        return None
    return retry_request_resume(
        store,
        request_id=request_id,
        now=timestamp,
    )


def _optional_string(value: object) -> str | None:
    return value if isinstance(value, str) and value.strip() else None


__all__ = ["apply_local_approval_continuation"]
