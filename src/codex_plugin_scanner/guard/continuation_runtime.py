"""Store-backed execution of the transport-free continuation contract."""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from datetime import datetime
from hashlib import sha256
from typing import Final

from .adapters.contracts import contract_for
from .codex_app_server_target import codex_app_server_target_reachable
from .codex_live_hook_target import codex_live_hook_wait_deadline
from .continuation_contract import (
    CAPABILITY_CONTRACT_VERSION,
    ContinuationAction,
    ContinuationCoordinator,
    ContinuationOffer,
    ContinuationResult,
    capability_offer,
)
from .continuation_payload import (
    attempt_count as _attempt_count,
)
from .continuation_payload import (
    continuation_events as _continuation_events,
)
from .continuation_payload import (
    continuation_payload as _payload,
)
from .continuation_payload import (
    continuation_result as _result,
)
from .continuation_payload import (
    continuation_strategy as _strategy,
)
from .continuation_payload import (
    mapping_value as _mapping,
)
from .continuation_payload import (
    offer_hash as _offer_hash,
)
from .continuation_payload import (
    operation_update_payload as _operation_update_payload,
)
from .continuation_payload import (
    parse_aware_timestamp as _parse_aware_timestamp,
)
from .continuation_payload import (
    persisted_resume_status as _persisted_resume_status,
)
from .continuation_payload import (
    previous_result as _previous_result,
)
from .continuation_payload import (
    text_value as _text,
)
from .continuation_snapshot import canonical_continuation_correlation_id
from .continuation_worker import (
    StoreContinuationPlan,
    run_store_continuation_plan,
)
from .desktop_notifications import DesktopApprovalNotification, notify_pending_approval_once
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
_CLAIM_LEASE_SECONDS: Final = 30.0
_run_store_continuation_plan = run_store_continuation_plan


def continue_request_after_application(
    store: GuardStore,
    *,
    request_row: Mapping[str, object],
    action: str,
    now: str,
    timeout_seconds: float = 5.0,
    cancelled: Callable[[], bool] = lambda: False,
    headless: bool = True,
) -> dict[str, object]:
    """Continue one locally applied request without taking over Cloud delivery."""

    request_id = _required_text(request_row.get("request_id"), "continuation_request_id_missing")
    normalized_action = _continuation_action(action)
    observed_at = _parse_aware_timestamp(now)
    offer = _offer_from_request(
        store,
        request_row=request_row,
        request_id=request_id,
        observed_at=observed_at,
        headless=headless,
    )
    existing = store.get_request_resume(request_id)
    previous = _previous_result(existing, offer=offer, action=normalized_action)
    if previous is not None:
        _persist_attempt(
            store,
            request_id=request_id,
            action=normalized_action,
            offer=offer,
            result=previous,
            now=now,
        )
        return _payload(offer, previous, replayed=True)
    offer_hash = _offer_hash(offer)
    claim_id = store.claim_continuation_attempt(
        request_id=request_id,
        offer_hash=offer_hash,
        action=normalized_action,
        now=now,
        lease_seconds=max(_CLAIM_LEASE_SECONDS, timeout_seconds + 5.0),
    )
    if claim_id is None:
        wait_deadline = time.monotonic() + min(timeout_seconds, 0.5)
        while True:
            existing = store.get_request_resume(request_id)
            previous = _previous_result(existing, offer=offer, action=normalized_action)
            if previous is not None:
                _persist_attempt(
                    store,
                    request_id=request_id,
                    action=normalized_action,
                    offer=offer,
                    result=previous,
                    now=now,
                )
                return _payload(offer, previous, replayed=True)
            if time.monotonic() >= wait_deadline:
                break
            time.sleep(0.01)
        return _payload(offer, _result(offer, "waiting", "continuation_claimed", now), replayed=True)
    coordinator = ContinuationCoordinator(
        record_attempt=lambda offer, action, result: _persist_attempt(
            store,
            request_id=request_id,
            action=action,
            offer=offer,
            result=result,
            now=now,
            claim_id=claim_id,
        ),
        notify_manual_retry=lambda offer, result: _notify_manual_retry(
            store,
            request_id=request_id,
            offer=offer,
            result=result,
            now=now,
        ),
        now=lambda: observed_at,
        isolated_plan=StoreContinuationPlan(
            guard_home=str(store.guard_home),
            request_id=request_id,
            observed_at=now,
        ),
        isolated_runner=_run_store_continuation_plan,
    )
    result = coordinator.continue_after_application(
        offer,
        action=normalized_action,
        timeout_seconds=timeout_seconds,
        cancelled=cancelled,
    )
    authoritative = _previous_result(store.get_request_resume(request_id), offer=offer, action=normalized_action)
    if authoritative is not None:
        return _payload(offer, authoritative, replayed=authoritative.evidence_id != result.evidence_id)
    return _payload(offer, result, replayed=False)


def _offer_from_request(
    store: GuardStore,
    *,
    request_row: Mapping[str, object],
    request_id: str,
    observed_at: datetime,
    headless: bool,
    operation_override: Mapping[str, object] | None = None,
) -> ContinuationOffer:
    harness = _canonical_harness(request_row.get("harness"))
    operation = operation_override or store.get_guard_operation_for_approval_request(request_id)
    metadata: Mapping[str, object] = _mapping(operation.get("metadata")) if isinstance(operation, Mapping) else {}
    deadline = codex_live_hook_wait_deadline(store, operation=operation, metadata=metadata) if operation else None
    original_hook_attached = harness == "codex" and deadline is not None and deadline > observed_at
    raw_target = _first_text(metadata, _SESSION_KEYS)
    session_target_verified = (
        harness == "codex"
        and not original_hook_attached
        and raw_target is not None
        and codex_app_server_target_reachable(metadata)
    )
    opaque_target_id = _opaque_target_id(harness, raw_target)
    return capability_offer(
        correlation_id=canonical_continuation_correlation_id(
            request_id=request_id,
            request_row=request_row,
            operation_metadata=metadata,
        ),
        harness=harness,
        original_hook_attached=original_hook_attached,
        wait_deadline=deadline,
        opaque_target_id=opaque_target_id,
        session_target_verified=session_target_verified,
        headless=headless,
        now=lambda: observed_at,
    )


def continuation_offer_payload(
    store: GuardStore,
    *,
    request_row: Mapping[str, object],
    now: str,
    headless: bool,
    operation: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Serialize only capability facts that a Cloud reviewer may safely consume."""

    request_id = _required_text(request_row.get("request_id"), "continuation_request_id_missing")
    offer = _offer_from_request(
        store,
        request_row=request_row,
        request_id=request_id,
        observed_at=_parse_aware_timestamp(now),
        headless=headless,
        operation_override=operation,
    )
    return {
        "correlationId": offer.correlation_id,
        "capability": offer.capability,
        "hookAttached": offer.original_hook_attached,
        "opaqueTargetId": offer.opaque_target_id,
        "waitDeadline": offer.wait_deadline.isoformat() if offer.wait_deadline is not None else None,
    }


def record_live_hook_completion(
    store: GuardStore,
    *,
    request_id: str,
    action: str,
    now: str,
) -> dict[str, object] | None:
    """Record proof that the original browser-waiting Codex hook consumed a decision."""

    request = store.get_approval_request(request_id)
    if not isinstance(request, Mapping):
        return None
    normalized_action = _continuation_action(action)
    offer = _offer_from_request(
        store,
        request_row=request,
        request_id=request_id,
        observed_at=_parse_aware_timestamp(now),
        headless=False,
    )
    if offer.capability != "suspended-response":
        return None
    previous = _previous_result(store.get_request_resume(request_id), offer=offer, action=normalized_action)
    if previous is not None and previous.status != "waiting":
        return _payload(offer, previous, replayed=True)
    if normalized_action == "allow_once":
        result = _result(offer, "resumed", "live_hook_completed", now)
    else:
        result = _result(offer, "blocked_not_resumed", "blocked_not_resumed", now)
    _persist_attempt(store, request_id=request_id, action=normalized_action, offer=offer, result=result, now=now)
    authoritative = _previous_result(store.get_request_resume(request_id), offer=offer, action=normalized_action)
    return _payload(offer, authoritative or result, replayed=authoritative is not None)


def _persist_attempt(
    store: GuardStore,
    *,
    request_id: str,
    action: ContinuationAction,
    offer: ContinuationOffer,
    result: ContinuationResult,
    now: str,
    claim_id: str | None = None,
) -> None:
    operation = store.get_guard_operation_for_approval_request(request_id)
    operation_id = _text(operation.get("operation_id")) if isinstance(operation, Mapping) else None
    raw_session_id = _operation_session_id(operation)
    prior = store.get_request_resume(request_id)
    attempt_count = _attempt_count(prior)
    # `retry_request_resume` already records the actual Codex app-server send.
    # The contract evidence enriches that same attempt instead of double-counting it.
    if offer.harness == "codex" and offer.capability == "session-resume" and isinstance(prior, Mapping):
        existing_attempt_count = prior.get("attempt_count")
        if isinstance(existing_attempt_count, int) and not isinstance(existing_attempt_count, bool):
            attempt_count = existing_attempt_count
    events = _continuation_events(
        request_id=request_id,
        operation_id=operation_id,
        action=action,
        offer=offer,
        result=result,
    )
    operation_update = _operation_update_payload(operation, result=result, action=action, now=now)
    _ = store.finalize_continuation_attempt(
        request_id=request_id,
        offer_hash=_offer_hash(offer),
        action=action,
        claim_id=claim_id,
        evidence_id=result.evidence_id,
        terminal=result.status != "waiting",
        resume_seed={
            "operation_id": operation_id,
            "harness": offer.harness,
            "strategy": _strategy(offer, result),
            "supported": offer.capability in {"suspended-response", "session-resume"},
            "thread_id": raw_session_id,
        },
        resume_update={
            "resolution_action": "allow" if action == "allow_once" else "block",
            "strategy": _strategy(offer, result),
            "supported": offer.capability in {"suspended-response", "session-resume"},
            "status": _persisted_resume_status(offer, result),
            "reason": result.reason,
            "message": None,
            "last_error": result.reason if result.status == "failed" else None,
            "attempt_count": attempt_count,
            "last_attempt_at": now,
            "sent_at": now if result.status in {"resumed", "already_resumed"} else None,
            "continuation_contract_version": CAPABILITY_CONTRACT_VERSION,
            "continuation_capability": offer.capability,
            "continuation_status": result.status,
            "continuation_reason": result.reason,
            "continuation_evidence": [
                {
                    "correlationId": offer.correlation_id,
                    "evidenceId": result.evidence_id,
                    "status": result.status,
                }
            ],
            "continuation_offer_hash": _offer_hash(offer),
            "continuation_action": action,
            "continuation_completed_at": result.completed_at.isoformat(),
            "continuation_cancelled_at": now if result.reason == "continuation_cancelled" else None,
        },
        operation_update=operation_update,
        events=events,
        now=now,
    )


def _notify_manual_retry(
    store: GuardStore,
    *,
    request_id: str,
    offer: ContinuationOffer,
    result: ContinuationResult,
    now: str,
) -> None:
    _ = result, now
    request = store.get_approval_request(request_id)
    if not isinstance(request, Mapping):
        return
    approval_url = _text(request.get("approval_url")) or ""
    _ = notify_pending_approval_once(
        DesktopApprovalNotification(
            request_id=f"continuation-{request_id}",
            title="HOL Guard requires a manual retry",
            message=f"{offer.harness.title()} cannot continue this approved action automatically. Retry it locally.",
            approval_url=approval_url,
        )
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
