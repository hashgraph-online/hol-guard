"""Authorize and record the original Codex hook's browser decision."""

from __future__ import annotations

from collections.abc import Mapping

from .store import GuardStore


def complete_codex_live_decision(
    store: GuardStore,
    *,
    request_id: str,
    now: str,
    fresh_allow_authorized: bool = False,
) -> dict[str, object]:
    """Consume exact authority and persist terminal continuation evidence."""

    request = store.get_approval_request(request_id)
    if not isinstance(request, Mapping):
        return _failure("request_not_found")
    return store.complete_codex_live_decision(
        request,
        now=now,
        fresh_allow_authorized=fresh_allow_authorized,
    )


def resolve_codex_live_allow_authority(
    store: GuardStore,
    *,
    request: Mapping[str, object],
    request_id: str,
    now: str,
) -> dict[str, object] | None:
    """Return the exact unconsumed one-shot authority for this request."""

    if _optional_text(request.get("request_id")) != request_id:
        return None
    return store.codex_live_allow_authority(request, now=now)


def _optional_text(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _failure(code: str) -> dict[str, object]:
    return {"completed": False, "error": code}


__all__ = ["complete_codex_live_decision", "resolve_codex_live_allow_authority"]
