"""Small browser-wait projections shared by Guard hook flows."""

from __future__ import annotations

from collections.abc import Mapping

from ..live_process_identity import MAX_CODEX_BROWSER_INLINE_WAIT_SECONDS


def bounded_inline_wait_seconds(value: int | None, *, bound: bool) -> int | None:
    """Keep an authenticated inline wait within the daemon worker budget."""

    if not bound:
        return None
    if not isinstance(value, int) or isinstance(value, bool):
        return MAX_CODEX_BROWSER_INLINE_WAIT_SECONDS
    return min(MAX_CODEX_BROWSER_INLINE_WAIT_SECONDS, max(1, value))


def browser_wait_request_ids(
    response_payload: Mapping[str, object],
    *,
    browser_wait_bound: bool | None,
) -> list[str]:
    if browser_wait_bound is False:
        return []
    operation = response_payload.get("operation")
    operation_metadata = operation.get("metadata") if isinstance(operation, Mapping) else None
    if (
        isinstance(operation_metadata, Mapping)
        and operation_metadata.get("codex_hook_waits_for_browser_approval") is not True
    ):
        return []
    approval_requests = response_payload.get("approval_requests")
    if not isinstance(approval_requests, list):
        return []
    return [
        item["request_id"]
        for item in approval_requests
        if isinstance(item, dict) and isinstance(item.get("request_id"), str)
    ]
