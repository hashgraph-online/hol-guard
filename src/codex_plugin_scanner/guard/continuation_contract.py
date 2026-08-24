"""Versioned, transport-free harness continuation coordination for Cloud Review v2."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Literal, Protocol

ContinuationCapability = Literal["suspended-response", "session-resume", "retry-only", "unsupported"]
ContinuationStatus = Literal[
    "resumed",
    "already_resumed",
    "manual_retry_required",
    "blocked_not_resumed",
    "unsupported",
    "failed",
]
ContinuationAction = Literal["allow_once", "block"]
CAPABILITY_CONTRACT_VERSION = "guard.harness-continuation.v1"
_OPAQUE_IDENTIFIER_CHARACTERS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_")


def _require_opaque_identifier(value: str | None, label: str) -> None:
    if value is None:
        return
    if not 8 <= len(value) <= 128 or any(character not in _OPAQUE_IDENTIFIER_CHARACTERS for character in value):
        raise ValueError(f"{label} must be a safe opaque identifier")


@dataclass(frozen=True, slots=True)
class ContinuationOffer:
    """Runtime-reported capability; it never derives continuation from display copy."""

    correlation_id: str
    harness: str
    capability: ContinuationCapability
    original_hook_attached: bool
    wait_deadline: datetime | None = None
    opaque_target_id: str | None = None
    contract_version: str = CAPABILITY_CONTRACT_VERSION

    def __post_init__(self) -> None:
        _require_opaque_identifier(self.opaque_target_id, "opaque_target_id")
        if self.contract_version != CAPABILITY_CONTRACT_VERSION:
            raise ValueError("unsupported continuation capability contract")
        if self.capability == "suspended-response":
            if not self.original_hook_attached or self.wait_deadline is None:
                raise ValueError("suspended-response requires an attached hook and wait deadline")
        elif self.original_hook_attached:
            raise ValueError("only suspended-response may report an attached original hook")
        if self.capability == "session-resume" and self.opaque_target_id is None:
            raise ValueError("session-resume requires an opaque target identifier")
        if self.capability in {"retry-only", "unsupported"} and self.opaque_target_id is not None:
            raise ValueError("non-resumable capabilities cannot report a continuation target")


@dataclass(frozen=True, slots=True)
class ContinuationResult:
    correlation_id: str
    capability: ContinuationCapability
    status: ContinuationStatus
    reason: str
    completed_at: datetime
    evidence_id: str

    def __post_init__(self) -> None:
        _require_opaque_identifier(self.evidence_id, "evidence_id")
        if not self.reason or len(self.reason) > 128:
            raise ValueError("continuation result requires a bounded reason")


class HarnessContinuationAdapter(Protocol):
    """Applies a post-application continuation and proves the original target accepted it."""

    def continue_after_application(
        self,
        offer: ContinuationOffer,
        *,
        action: ContinuationAction,
        timeout_seconds: float,
        cancelled: Callable[[], bool],
    ) -> ContinuationResult: ...


AttemptSink = Callable[[ContinuationOffer, ContinuationAction, ContinuationResult], None]
FallbackNotifier = Callable[[ContinuationOffer, ContinuationResult], None]


class ContinuationCoordinator:
    """Idempotently records terminal continuation evidence outside a delivery lease."""

    def __init__(
        self,
        adapter: HarnessContinuationAdapter,
        *,
        record_attempt: AttemptSink,
        notify_manual_retry: FallbackNotifier,
        now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ) -> None:
        self._adapter: HarnessContinuationAdapter = adapter
        self._record_attempt: AttemptSink = record_attempt
        self._notify_manual_retry: FallbackNotifier = notify_manual_retry
        self._now: Callable[[], datetime] = now
        self._completed: dict[tuple[str, ContinuationAction], ContinuationResult] = {}

    def continue_after_application(
        self,
        offer: ContinuationOffer,
        *,
        action: ContinuationAction,
        timeout_seconds: float,
        cancelled: Callable[[], bool] = lambda: False,
    ) -> ContinuationResult:
        if timeout_seconds <= 0:
            raise ValueError("continuation timeout must be positive")
        key = (offer.correlation_id, action)
        previous = self._completed.get(key)
        if previous is not None:
            return previous
        result = self._terminal_result(offer, action=action, cancelled=cancelled)
        if result is None:
            result = self._adapter.continue_after_application(
                offer, action=action, timeout_seconds=timeout_seconds, cancelled=cancelled
            )
            if result.correlation_id != offer.correlation_id or result.capability != offer.capability:
                raise ValueError("continuation adapter returned mismatched evidence")
            if result.status not in {"resumed", "already_resumed", "failed", "manual_retry_required"}:
                raise ValueError("continuation adapter returned a non-terminal status")
        self._completed[key] = result
        self._record_attempt(offer, action, result)
        if result.status == "manual_retry_required":
            self._notify_manual_retry(offer, result)
        return result

    def _terminal_result(
        self, offer: ContinuationOffer, *, action: ContinuationAction, cancelled: Callable[[], bool]
    ) -> ContinuationResult | None:
        if action == "block":
            return self._result(offer, "blocked_not_resumed", "decision_blocked")
        if cancelled():
            return self._result(offer, "failed", "continuation_cancelled")
        if offer.capability == "unsupported":
            return self._result(offer, "unsupported", "harness_unsupported")
        if offer.capability == "retry-only":
            return self._result(offer, "manual_retry_required", "manual_retry_required")
        if offer.wait_deadline is not None and offer.wait_deadline <= self._now():
            return self._result(offer, "manual_retry_required", "wait_window_expired")
        return None

    def _result(self, offer: ContinuationOffer, status: ContinuationStatus, reason: str) -> ContinuationResult:
        return ContinuationResult(
            correlation_id=offer.correlation_id,
            capability=offer.capability,
            status=status,
            reason=reason,
            completed_at=self._now(),
            evidence_id=f"evidence-{offer.correlation_id[-16:]}",
        )


def capability_offer(
    *,
    correlation_id: str,
    harness: str,
    original_hook_attached: bool,
    wait_deadline: datetime | None,
    opaque_target_id: str | None = None,
    session_target_verified: bool = False,
    headless: bool = False,
    now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> ContinuationOffer:
    """Declare only a proven capability; named runtimes without transport downgrade explicitly."""

    normalized = harness.strip().lower()
    current_time = now()
    if normalized == "codex" and original_hook_attached and wait_deadline is not None and wait_deadline > current_time:
        capability: ContinuationCapability = "suspended-response"
    elif normalized == "codex" and not headless and session_target_verified:
        capability = "session-resume"
    elif normalized in {"codex", "pi", "omp", "oh-my-pi", "grok", "openclaw", "hermes"}:
        capability = "retry-only"
    else:
        capability = "unsupported"
    return ContinuationOffer(
        correlation_id=correlation_id,
        harness=normalized,
        capability=capability,
        original_hook_attached=original_hook_attached if capability == "suspended-response" else False,
        wait_deadline=wait_deadline if capability == "suspended-response" else None,
        opaque_target_id=opaque_target_id if capability == "session-resume" else None,
    )
