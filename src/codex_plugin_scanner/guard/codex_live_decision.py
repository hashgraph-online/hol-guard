"""Authorize and record the original Codex hook's browser decision."""

from __future__ import annotations

from collections.abc import Mapping

from .continuation_runtime import record_live_hook_completion
from .store import GuardStore

_REVIEW_ACTIONS = frozenset({"review", "require-reapproval"})


def complete_codex_live_decision(
    store: GuardStore,
    *,
    request_id: str,
    now: str,
) -> dict[str, object]:
    """Consume exact authority and persist terminal continuation evidence."""

    request = store.get_approval_request(request_id)
    if not isinstance(request, Mapping):
        return _failure("request_not_found")
    if request.get("harness") != "codex" or request.get("status") != "resolved":
        return _failure("request_not_resolved")
    raw_action = request.get("resolution_action")
    if not isinstance(raw_action, str) or raw_action not in {"allow", "block"}:
        return _failure("decision_not_terminal")
    action = raw_action
    if request.get("policy_action") not in _REVIEW_ACTIONS:
        return _failure("policy_no_longer_reviewable")

    previous = store.get_request_resume(request_id)
    if isinstance(previous, dict) and _terminal_resume_matches(previous, action=action):
        return {"action": action, "completed": True, "continuation": previous, "replayed": True}

    approval_decision: Mapping[str, object] | None = None
    if action == "allow":
        lookup = store.resolve_policy_decision_lookup(
            str(request["harness"]),
            _optional_text(request.get("artifact_id")),
            artifact_hash=_optional_text(request.get("artifact_hash")),
            workspace=_optional_text(request.get("workspace")),
            publisher=_optional_text(request.get("publisher")),
            now=now,
            consume_one_shot=False,
        )
        decision = lookup.get("decision")
        if not isinstance(decision, Mapping) or not _exact_request_authority(decision, request_id=request_id):
            return _failure("exact_approval_unavailable")
        approval_decision = {str(key): value for key, value in decision.items()}

    completion = record_live_hook_completion(
        store,
        request_id=request_id,
        action=action,
        now=now,
        approval_decision=approval_decision,
    )
    expected_status = "resumed" if action == "allow" else "blocked_not_resumed"
    if not isinstance(completion, Mapping) or completion.get("continuationStatus") != expected_status:
        return _failure("continuation_not_recorded")
    return {"action": action, "completed": True, "continuation": dict(completion), "replayed": False}


def _exact_request_authority(value: object, *, request_id: str) -> bool:
    return (
        isinstance(value, Mapping)
        and value.get("action") == "allow"
        and value.get("source") == "approval-gate-once"
        and value.get("request_id") == request_id
        and value.get("integrity_status") == "valid"
        and isinstance(value.get("approval_id"), str)
    )


def _terminal_resume_matches(value: object, *, action: object) -> bool:
    if not isinstance(value, Mapping) or value.get("resolution_action") != action:
        return False
    status = value.get("status")
    return status in {"resumed", "sent"} if action == "allow" else status in {"blocked", "skipped"}


def _optional_text(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _failure(code: str) -> dict[str, object]:
    return {"completed": False, "error": code}


__all__ = ["complete_codex_live_decision"]
