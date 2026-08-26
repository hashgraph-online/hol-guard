"""Persist proof that the original Codex hook consumed a browser decision."""

from __future__ import annotations

from collections.abc import Mapping

from ..continuation_runtime import record_live_hook_completion
from ..store import GuardStore


def record_codex_live_hook_continuation(
    *,
    response_payload: dict[str, object],
    store: GuardStore,
    request_ids: list[str],
    action: str,
    now: str,
) -> None:
    status = "resumed" if action == "allow" else "blocked"
    sandbox_required = action == "sandbox-required"
    continuation: dict[str, object] = {
        "status": status,
        "resolution_action": action,
        "strategy": "live-hook",
    }
    response_payload["continuation"] = continuation
    response_payload["codex_resume"] = dict(continuation)
    for request_id in request_ids:
        completion = (
            record_live_hook_completion(store, request_id=request_id, action=action, now=now)
            if action in {"allow", "block"}
            else None
        )
        if completion is not None:
            continue
        resume = store.get_request_resume(request_id)
        if not isinstance(resume, Mapping):
            continue
        attempt_count = resume.get("attempt_count")
        store.update_request_resume(
            request_id=request_id,
            resolution_action=action,
            strategy=str(resume.get("strategy")) if isinstance(resume.get("strategy"), str) else "live-hook",
            supported=bool(resume.get("supported")) if resume.get("supported") is not None else action == "allow",
            status=status,
            reason=(
                "live_hook_completed"
                if action == "allow"
                else "sandbox_required_not_resumed"
                if sandbox_required
                else "blocked_not_resumed"
            ),
            message=(
                "The original Codex hook consumed the exact browser approval and resumed the action."
                if action == "allow"
                else "Current HOL Guard policy requires a sandbox; the original Codex action was not resumed."
                if sandbox_required
                else "HOL Guard kept the original Codex action blocked."
            ),
            last_error=None,
            attempt_count=int(attempt_count) if isinstance(attempt_count, int) else 0,
            last_attempt_at=now,
            sent_at=str(resume.get("sent_at")) if isinstance(resume.get("sent_at"), str) else None,
            now=now,
        )
