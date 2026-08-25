"""Transport-free harness continuation coordination for Cloud Review."""

from __future__ import annotations

import json
import multiprocessing
import queue
import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from typing import Generic, Literal, TypeVar
from uuid import uuid4

ContinuationCapability = Literal["suspended-response", "session-resume", "retry-only", "unsupported"]
ContinuationStatus = Literal[
    "resumed",
    "already_resumed",
    "manual_retry_required",
    "blocked_not_resumed",
    "unsupported",
    "failed",
    "waiting",
]
ContinuationAction = Literal["allow_once", "block"]
CAPABILITY_CONTRACT_VERSION = "guard.harness-continuation.v2"
_OPAQUE_IDENTIFIER_CHARACTERS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_")
_CORRELATION_PATTERN = re.compile(r"^gcr_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def _require_opaque_identifier(value: str | None, label: str) -> None:
    if value is None:
        return
    if not 8 <= len(value) <= 128 or any(character not in _OPAQUE_IDENTIFIER_CHARACTERS for character in value):
        raise ValueError(f"{label} must be a safe opaque identifier")


def _require_aware_datetime(value: datetime, label: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")


def _require_correlation_id(value: str) -> None:
    if _CORRELATION_PATTERN.fullmatch(value) is None:
        raise ValueError("continuation correlation_id violates the Guard Cloud Review contract")


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
        _require_correlation_id(self.correlation_id)
        _require_opaque_identifier(self.opaque_target_id, "opaque_target_id")
        if self.wait_deadline is not None:
            _require_aware_datetime(self.wait_deadline, "wait_deadline")
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
        _require_correlation_id(self.correlation_id)
        _require_opaque_identifier(self.evidence_id, "evidence_id")
        _require_aware_datetime(self.completed_at, "completed_at")
        if not self.reason or len(self.reason) > 128:
            raise ValueError("continuation result requires a bounded reason")


AttemptSink = Callable[[ContinuationOffer, ContinuationAction, ContinuationResult], None]
FallbackNotifier = Callable[[ContinuationOffer, ContinuationResult], None]
ExecutionPlan = TypeVar("ExecutionPlan")
IsolatedRunner = Callable[[ExecutionPlan, ContinuationOffer, ContinuationAction, float], ContinuationResult]


def _subprocess_plan_worker(
    runner: IsolatedRunner[ExecutionPlan],
    plan: ExecutionPlan,
    offer: ContinuationOffer,
    action: ContinuationAction,
    timeout_seconds: float,
    results: multiprocessing.Queue[ContinuationResult | str],
) -> None:
    """Run a serializable execution plan without inheriting daemon resources."""

    try:
        result = runner(plan, offer, action, timeout_seconds)
        results.put(result)
    except Exception:
        results.put("error")


class ContinuationCoordinator(Generic[ExecutionPlan]):
    """Idempotently records terminal continuation evidence outside a delivery lease."""

    def __init__(
        self,
        *,
        record_attempt: AttemptSink,
        notify_manual_retry: FallbackNotifier,
        isolated_plan: ExecutionPlan | None = None,
        isolated_runner: IsolatedRunner[ExecutionPlan] | None = None,
        now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ) -> None:
        self._record_attempt: AttemptSink = record_attempt
        self._notify_manual_retry: FallbackNotifier = notify_manual_retry
        self._isolated_plan: ExecutionPlan | None = isolated_plan
        self._isolated_runner: IsolatedRunner[ExecutionPlan] | None = isolated_runner
        self._now: Callable[[], datetime] = now
        self._completed: dict[tuple[str, ContinuationAction, str], ContinuationResult] = {}

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
        key = (offer.correlation_id, action, _offer_identity(offer))
        previous = self._completed.get(key)
        if previous is not None:
            return previous
        result = self._terminal_result(offer, action=action, cancelled=cancelled)
        if result is None:
            result = self._run_bounded_adapter(
                offer,
                action=action,
                timeout_seconds=timeout_seconds,
                cancelled=cancelled,
            )
            if result.correlation_id != offer.correlation_id or result.capability != offer.capability:
                raise ValueError("continuation adapter returned mismatched evidence")
            if result.status not in {"resumed", "already_resumed", "failed", "manual_retry_required", "waiting"}:
                raise ValueError("continuation adapter returned a non-terminal status")
        self._record_attempt(offer, action, result)
        if result.status != "waiting":
            self._completed[key] = result
        if result.status == "manual_retry_required":
            self._notify_manual_retry(offer, result)
        return result

    def _run_bounded_adapter(
        self,
        offer: ContinuationOffer,
        *,
        action: ContinuationAction,
        timeout_seconds: float,
        cancelled: Callable[[], bool],
    ) -> ContinuationResult:
        """Return promptly when an external harness adapter stops responding.

        A non-cooperative adapter runs in an isolated process and is terminated
        at the deadline, so a timeout cannot leak a daemon worker.
        """

        if self._isolated_plan is None or self._isolated_runner is None:
            return self._result(offer, "failed", "continuation_adapter_isolation_unavailable")
        context = multiprocessing.get_context("spawn")
        result_box: multiprocessing.Queue[ContinuationResult | str] = context.Queue(maxsize=1)

        worker = context.Process(
            target=_subprocess_plan_worker,
            args=(self._isolated_runner, self._isolated_plan, offer, action, timeout_seconds, result_box),
            name="hol-guard-continuation",
        )
        try:
            try:
                worker.start()
            except (AttributeError, OSError, TypeError, ValueError):
                return self._result(offer, "failed", "continuation_adapter_isolation_unavailable")
            deadline = time.monotonic() + timeout_seconds
            while worker.is_alive() and not cancelled() and time.monotonic() < deadline:
                worker.join(min(0.01, max(0.0, deadline - time.monotonic())))
            if worker.is_alive():
                worker.terminate()
                worker.join(1.0)
                if worker.is_alive():
                    worker.kill()
                    worker.join(1.0)
                return self._result(
                    offer, "failed", "continuation_cancelled" if cancelled() else "continuation_adapter_timeout"
                )
            if cancelled():
                return self._result(offer, "failed", "continuation_cancelled")
            try:
                result = result_box.get(timeout=0.2)
            except queue.Empty:
                return self._result(offer, "failed", "continuation_adapter_missing_result")
            if isinstance(result, str):
                return self._result(offer, "failed", "continuation_adapter_failed")
            return result
        finally:
            result_box.close()
            result_box.join_thread()

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
            evidence_id=f"evidence-{uuid4().hex}",
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


def _offer_identity(offer: ContinuationOffer) -> str:
    """Bind idempotency to every security-relevant offer field, not correlation alone."""

    document = {
        "capability": offer.capability,
        "contractVersion": offer.contract_version,
        "deadline": offer.wait_deadline.isoformat() if offer.wait_deadline is not None else None,
        "harness": offer.harness,
        "hookAttached": offer.original_hook_attached,
        "target": offer.opaque_target_id,
    }
    return sha256(json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
