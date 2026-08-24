"""Spawn-safe execution plan for harness continuation adapters."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import cast
from uuid import uuid4

from .codex_resume import defer_request_resume_to_live_hook, retry_request_resume
from .continuation_contract import ContinuationAction, ContinuationOffer, ContinuationResult, ContinuationStatus
from .store import GuardStore


@dataclass(frozen=True, slots=True)
class StoreContinuationPlan:
    guard_home: str
    request_id: str
    observed_at: str


def run_store_continuation_plan(
    plan: StoreContinuationPlan,
    offer: ContinuationOffer,
    action: ContinuationAction,
    timeout_seconds: float,
) -> ContinuationResult:
    """Reconstruct the minimum store facade inside an isolated spawned process."""

    child_store = GuardStore(Path(plan.guard_home), prime_policy_integrity=False, daemon_managed_schema=True)
    return StoreContinuationAdapter(
        store=child_store,
        request_id=plan.request_id,
        observed_at=plan.observed_at,
    ).continue_after_application(
        offer,
        action=action,
        timeout_seconds=timeout_seconds,
        cancelled=lambda: False,
    )


class StoreContinuationAdapter:
    def __init__(self, *, store: GuardStore, request_id: str, observed_at: str) -> None:
        self._store: GuardStore = store
        self._request_id: str = request_id
        self._observed_at: str = observed_at

    def continue_after_application(
        self,
        offer: ContinuationOffer,
        *,
        action: ContinuationAction,
        timeout_seconds: float,
        cancelled: Callable[[], bool],
    ) -> ContinuationResult:
        if cancelled():
            return _result(offer, "failed", "continuation_cancelled", self._observed_at)
        if offer.capability == "suspended-response":
            deferred = defer_request_resume_to_live_hook(
                self._store,
                request_id=self._request_id,
                action="allow" if action == "allow_once" else "block",
                now=self._observed_at,
            )
            if deferred is not None:
                return _result(offer, "waiting", "original_hook_waiting", self._observed_at)
            return _result(offer, "manual_retry_required", "original_hook_not_available", self._observed_at)
        if offer.capability != "session-resume":
            return _result(offer, "manual_retry_required", "manual_retry_required", self._observed_at)
        try:
            raw = retry_request_resume(
                self._store,
                request_id=self._request_id,
                now=self._observed_at,
                force=False,
                timeout_seconds=timeout_seconds,
            )
        except ValueError:
            return _result(offer, "failed", "codex_app_server_failed", self._observed_at)
        if cancelled():
            return _result(offer, "failed", "continuation_cancelled", self._observed_at)
        status = _text(raw.get("status"))
        reason = _bounded_reason(_text(raw.get("reason")) or "codex_app_server_unconfirmed")
        if status == "sent":
            return _result(offer, "resumed", reason, self._observed_at)
        if status == "already_sent":
            return _result(offer, "already_resumed", reason, self._observed_at)
        if status == "skipped":
            return _result(offer, "manual_retry_required", reason, self._observed_at)
        return _result(offer, "failed", reason, self._observed_at)


def _result(
    offer: ContinuationOffer,
    status: ContinuationStatus,
    reason: str,
    completed_at: str,
) -> ContinuationResult:
    return ContinuationResult(
        correlation_id=offer.correlation_id,
        capability=offer.capability,
        status=status,
        reason=_bounded_reason(reason),
        completed_at=datetime.fromisoformat(completed_at),
        evidence_id=f"evidence-{uuid4().hex}",
    )


def _bounded_reason(value: str) -> str:
    return value[:128] or "continuation_unknown"


def _text(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    return cast(str | None, normalized or None)
