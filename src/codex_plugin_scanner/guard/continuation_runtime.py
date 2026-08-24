"""Store-backed execution of the transport-free continuation contract."""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from hashlib import sha256
from typing import Final, cast
from uuid import uuid4

from .adapters.contracts import contract_for
from .codex_resume import defer_request_resume_to_live_hook, retry_request_resume
from .continuation_contract import (
    CAPABILITY_CONTRACT_VERSION,
    ContinuationAction,
    ContinuationCoordinator,
    ContinuationOffer,
    ContinuationResult,
    ContinuationStatus,
    capability_offer,
)
from .store import GuardStore

_SESSION_KEYS = (
    "codex_thread_id",
    "thread_id",
    "threadId",
    "conversation_id",
    "conversationId",
    "session_id",
    "sessionId",
)
_DEADLINE_KEYS = ("codex_browser_wait_deadline_at", "browser_wait_deadline_at")
_TERMINAL_STATUSES: Final = frozenset(
    {"resumed", "already_resumed", "manual_retry_required", "blocked_not_resumed", "unsupported", "failed"}
)


def continue_request_after_application(
    store: GuardStore,
    *,
    request_row: Mapping[str, object],
    action: str,
    now: str,
    timeout_seconds: float = 5.0,
    cancelled: Callable[[], bool] = lambda: False,
) -> dict[str, object]:
    """Continue one locally applied request without taking over Cloud delivery."""

    request_id = _required_text(request_row.get("request_id"), "continuation_request_id_missing")
    normalized_action = _continuation_action(action)
    observed_at = _parse_aware_timestamp(now)
    offer = _offer_from_request(store, request_row=request_row, request_id=request_id, observed_at=observed_at)
    existing = store.get_request_resume(request_id)
    previous = _previous_result(existing, offer=offer, action=normalized_action)
    if previous is not None:
        return _payload(offer, previous, replayed=True)
    adapter = _StoreContinuationAdapter(store=store, request_id=request_id, observed_at=now)
    coordinator = ContinuationCoordinator(
        adapter,
        record_attempt=lambda offer, action, result: _persist_attempt(
            store,
            request_id=request_id,
            action=action,
            offer=offer,
            result=result,
            now=now,
        ),
        notify_manual_retry=lambda offer, result: _notify_manual_retry(
            store,
            request_id=request_id,
            offer=offer,
            result=result,
            now=now,
        ),
        now=lambda: observed_at,
    )
    result = coordinator.continue_after_application(
        offer,
        action=normalized_action,
        timeout_seconds=timeout_seconds,
        cancelled=cancelled,
    )
    return _payload(offer, result, replayed=False)


class _StoreContinuationAdapter:
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
                # A saved decision is not proof that the hook consumed it.
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


def _offer_from_request(
    store: GuardStore,
    *,
    request_row: Mapping[str, object],
    request_id: str,
    observed_at: datetime,
) -> ContinuationOffer:
    harness = _canonical_harness(request_row.get("harness"))
    operation = store.get_guard_operation_for_approval_request(request_id)
    metadata: Mapping[str, object] = _mapping(operation.get("metadata")) if isinstance(operation, Mapping) else {}
    deadline = _first_aware_timestamp(metadata, _DEADLINE_KEYS)
    original_hook_attached = (
        harness == "codex"
        and metadata.get("codex_hook_waits_for_browser_approval") is True
        and deadline is not None
        and deadline > observed_at
    )
    raw_target = _first_text(metadata, _SESSION_KEYS)
    session_target_verified = harness == "codex" and not original_hook_attached and raw_target is not None
    opaque_target_id = _opaque_target_id(harness, raw_target)
    return capability_offer(
        correlation_id=request_id,
        harness=harness,
        original_hook_attached=original_hook_attached,
        wait_deadline=deadline,
        opaque_target_id=opaque_target_id,
        session_target_verified=session_target_verified,
        headless=False,
        now=lambda: observed_at,
    )


def _persist_attempt(
    store: GuardStore,
    *,
    request_id: str,
    action: ContinuationAction,
    offer: ContinuationOffer,
    result: ContinuationResult,
    now: str,
) -> None:
    operation = store.get_guard_operation_for_approval_request(request_id)
    operation_id = _text(operation.get("operation_id")) if isinstance(operation, Mapping) else None
    raw_session_id = _operation_session_id(operation)
    store.seed_request_resume(
        request_id=request_id,
        operation_id=operation_id,
        harness=offer.harness,
        strategy=_strategy(offer, result),
        supported=offer.capability in {"suspended-response", "session-resume"},
        thread_id=raw_session_id,
        now=now,
    )
    prior = store.get_request_resume(request_id)
    attempt_count = _attempt_count(prior)
    # `retry_request_resume` already records the actual Codex app-server send.
    # The contract evidence enriches that same attempt instead of double-counting it.
    if offer.harness == "codex" and offer.capability == "session-resume" and isinstance(prior, Mapping):
        existing_attempt_count = prior.get("attempt_count")
        if isinstance(existing_attempt_count, int) and not isinstance(existing_attempt_count, bool):
            attempt_count = existing_attempt_count
    store.update_request_resume(
        request_id=request_id,
        resolution_action="allow" if action == "allow_once" else "block",
        strategy=_strategy(offer, result),
        supported=offer.capability in {"suspended-response", "session-resume"},
        status=_persisted_resume_status(offer, result),
        reason=result.reason,
        message=None,
        last_error=result.reason if result.status == "failed" else None,
        attempt_count=attempt_count,
        last_attempt_at=now,
        sent_at=now if result.status in {"resumed", "already_resumed"} else None,
        now=now,
        continuation_contract_version=CAPABILITY_CONTRACT_VERSION,
        continuation_capability=offer.capability,
        continuation_status=result.status,
        continuation_reason=result.reason,
        continuation_evidence=[{"evidenceId": result.evidence_id, "status": result.status}],
        continuation_offer_hash=_offer_hash(offer),
        continuation_action=action,
        continuation_completed_at=result.completed_at.isoformat(),
        continuation_cancelled_at=now if result.reason == "continuation_cancelled" else None,
    )
    _update_operation(store, operation=operation, result=result, action=action, now=now)
    store.add_event(
        "review.continuation.attempt",
        {
            "action": action,
            "capability": offer.capability,
            "evidence_id": result.evidence_id,
            "harness": offer.harness,
            "request_id": request_id,
            "status": result.status,
        },
        now,
    )
    if offer.harness != "codex":
        store.add_event(
            "harness/operation_resume",
            {
                "action": "allow" if action == "allow_once" else "block",
                "harness": offer.harness,
                "operation_id": operation_id,
                "request_id": request_id,
                "status": _storage_status(result.status),
            },
            now,
        )


def _notify_manual_retry(
    store: GuardStore,
    *,
    request_id: str,
    offer: ContinuationOffer,
    result: ContinuationResult,
    now: str,
) -> None:
    store.add_event(
        "review.continuation.manual_retry_required",
        {
            "evidence_id": result.evidence_id,
            "harness": offer.harness,
            "request_id": request_id,
            "reason": result.reason,
        },
        now,
    )


def _update_operation(
    store: GuardStore,
    *,
    operation: Mapping[str, object] | None,
    result: ContinuationResult,
    action: ContinuationAction,
    now: str,
) -> None:
    if not isinstance(operation, Mapping):
        return
    operation_id = _text(operation.get("operation_id"))
    session_id = _text(operation.get("session_id"))
    operation_type = _text(operation.get("operation_type"))
    harness = _text(operation.get("harness"))
    if operation_id is None or session_id is None or operation_type is None or harness is None:
        return
    metadata = dict(_mapping(operation.get("metadata")))
    metadata["continuation"] = {
        "action": action,
        "capability": result.capability,
        "evidence_id": result.evidence_id,
        "reason": result.reason,
        "status": result.status,
    }
    approval_request_ids = _string_list(operation.get("approval_request_ids"))
    status = {
        "resumed": "resumed",
        "already_resumed": "resumed",
        "manual_retry_required": "manual_retry_required",
        "blocked_not_resumed": "blocked",
        "failed": "continuation_failed",
    }.get(result.status, "waiting_on_approval")
    _ = store.upsert_guard_operation(
        operation_id=operation_id,
        session_id=session_id,
        harness=harness,
        operation_type=operation_type,
        status=status,
        approval_request_ids=approval_request_ids,
        resume_token=_text(operation.get("resume_token")),
        metadata=metadata,
        now=now,
    )


def _previous_result(
    value: Mapping[str, object] | None,
    *,
    offer: ContinuationOffer,
    action: ContinuationAction,
) -> ContinuationResult | None:
    if not isinstance(value, Mapping):
        return None
    if value.get("continuation_offer_hash") != _offer_hash(offer) or value.get("continuation_action") != action:
        return None
    status = _persisted_terminal_status(_text(value.get("continuation_status")))
    if status is None:
        return None
    completed_at = _first_aware_timestamp(value, ("continuation_completed_at",))
    evidence = _mapping_list(value.get("continuation_evidence"))
    evidence_id = _text(evidence[0].get("evidenceId")) if evidence else None
    if completed_at is None or evidence_id is None:
        return None
    return ContinuationResult(
        correlation_id=offer.correlation_id,
        capability=offer.capability,
        status=status,
        reason=_bounded_reason(_text(value.get("continuation_reason")) or status),
        completed_at=completed_at,
        evidence_id=evidence_id,
    )


def _payload(offer: ContinuationOffer, result: ContinuationResult, *, replayed: bool) -> dict[str, object]:
    status = _public_status(result.status)
    if offer.harness == "codex" and result.status in {"manual_retry_required", "blocked_not_resumed"}:
        status = "skipped"
    reason = _public_reason(offer, result)
    detail = {
        "capability": offer.capability,
        "completedAt": result.completed_at.isoformat(),
        "evidenceId": result.evidence_id,
        "harness": offer.harness,
        "message": _public_message(offer, result),
        "reason": reason,
        "status": status,
        "strategy": _strategy(offer, result),
        "supported": result.status != "blocked_not_resumed"
        and offer.capability in {"suspended-response", "session-resume"},
    }
    payload: dict[str, object] = {
        "continuationCapability": offer.capability,
        "continuationCompletedAt": result.completed_at.isoformat(),
        "continuationEvidenceId": result.evidence_id,
        "continuationReason": result.reason,
        "continuationStatus": result.status,
        "resumeCompletedAt": result.completed_at.isoformat(),
        "resumeReason": reason,
        "resumeStatus": status,
    }
    if offer.harness == "codex":
        payload["codexResume"] = detail
        payload["codex_resume"] = detail
    else:
        payload["harnessResume"] = detail
        payload["harness_resume"] = detail
    if result.status == "manual_retry_required" and not replayed:
        payload["localManualRetryNotification"] = True
    return payload


def _result(
    offer: ContinuationOffer,
    status: ContinuationStatus,
    reason: str,
    observed_at: str,
) -> ContinuationResult:
    return ContinuationResult(
        correlation_id=offer.correlation_id,
        capability=offer.capability,
        status=status,
        reason=_bounded_reason(reason),
        completed_at=_parse_aware_timestamp(observed_at),
        evidence_id=f"evidence-{uuid4().hex}",
    )


def _continuation_action(value: str) -> ContinuationAction:
    if value in {"allow", "allow_once"}:
        return "allow_once"
    if value == "block":
        return "block"
    raise ValueError("continuation_action_invalid")


def _canonical_harness(value: object) -> str:
    text = _text(value)
    if text is None:
        return "unknown"
    contract = contract_for(text)
    return contract.harness if contract is not None else text.lower()


def _operation_session_id(operation: Mapping[str, object] | None) -> str | None:
    if not isinstance(operation, Mapping):
        return None
    return _first_text(_mapping(operation.get("metadata")), _SESSION_KEYS) or _text(operation.get("session_id"))


def _opaque_target_id(harness: str, raw_target: str | None) -> str | None:
    if raw_target is None:
        return None
    return f"target-{sha256(f'{harness}:{raw_target}'.encode()).hexdigest()[:32]}"


def _offer_hash(offer: ContinuationOffer) -> str:
    document = {
        "capability": offer.capability,
        "contractVersion": offer.contract_version,
        "correlationId": offer.correlation_id,
        "harness": offer.harness,
        "hookAttached": offer.original_hook_attached,
        "target": offer.opaque_target_id,
        "waitDeadline": offer.wait_deadline.isoformat() if offer.wait_deadline is not None else None,
    }
    encoded = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return sha256(encoded).hexdigest()


def _public_status(value: str) -> str:
    return {
        "waiting": "pending",
        "resumed": "sent",
        "already_resumed": "already_sent",
        "blocked_not_resumed": "blocked",
    }.get(value, value)


def _storage_status(value: str) -> str:
    return _public_status(value)


def _persisted_resume_status(offer: ContinuationOffer, result: ContinuationResult) -> str:
    if offer.harness == "codex" and result.status in {"manual_retry_required", "blocked_not_resumed"}:
        return "skipped"
    return _storage_status(result.status)


def _public_reason(offer: ContinuationOffer, result: ContinuationResult) -> str:
    if offer.harness == "codex" and result.status == "blocked_not_resumed":
        return "blocked_not_resumed"
    if offer.harness == "codex" and result.status == "waiting":
        return "live_hook_waiting"
    return result.reason


def _public_message(offer: ContinuationOffer, result: ContinuationResult) -> str | None:
    if offer.harness != "codex":
        return None
    if result.status == "waiting":
        return (
            "Decision saved. Codex is still waiting for this browser decision, so HOL Guard will let the "
            "original Codex action continue without starting a second headless run."
        )
    if result.status == "manual_retry_required":
        return (
            "Decision saved. HOL Guard could not find the original Codex chat to message. Return to Codex and retry "
            "the same request; this approval is now saved."
        )
    if result.status == "failed":
        return (
            "Decision saved. HOL Guard could not send Codex a continuation message in the original chat. Return to "
            "Codex and retry the same request; this approval is now saved."
        )
    if result.status == "blocked_not_resumed":
        return "Decision saved. HOL Guard blocked this Codex request and will not resume or retry it."
    return None


def _strategy(offer: ContinuationOffer, result: ContinuationResult) -> str:
    if result.status == "blocked_not_resumed":
        return "manual-only"
    if offer.capability == "suspended-response":
        return "codex-live-hook"
    if offer.capability == "session-resume":
        return "codex-app-server-thread"
    return "manual-only"


def _attempt_count(value: Mapping[str, object] | None) -> int:
    previous = value.get("attempt_count") if isinstance(value, Mapping) else None
    return previous + 1 if isinstance(previous, int) and not isinstance(previous, bool) else 1


def _parse_aware_timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("continuation_time_invalid") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("continuation_time_invalid")
    return parsed.astimezone(timezone.utc)


def _first_aware_timestamp(mapping: Mapping[str, object], keys: tuple[str, ...]) -> datetime | None:
    for key in keys:
        value = _text(mapping.get(key))
        if value is None:
            continue
        try:
            return _parse_aware_timestamp(value)
        except ValueError:
            continue
    return None


def _required_text(value: object, error: str) -> str:
    result = _text(value)
    if result is None:
        raise ValueError(error)
    return result


def _first_text(mapping: Mapping[str, object], keys: tuple[str, ...]) -> str | None:
    for key in keys:
        value = _text(mapping.get(key))
        if value is not None:
            return value
    return None


def _mapping(value: object) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        return {}
    mapping = cast(Mapping[object, object], value)
    return {key: item for key, item in mapping.items() if isinstance(key, str)}


def _mapping_list(value: object) -> list[Mapping[str, object]]:
    if not isinstance(value, list):
        return []
    return [_mapping(cast(object, item)) for item in cast(list[object], value) if isinstance(item, Mapping)]


def _string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in cast(list[object], value) if isinstance(item, str)]


def _text(value: object) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


def _bounded_reason(value: str) -> str:
    return value[:128] if value else "continuation_failed"


def _persisted_terminal_status(value: str | None) -> ContinuationStatus | None:
    if value not in _TERMINAL_STATUSES:
        return None
    return cast(ContinuationStatus, value)
