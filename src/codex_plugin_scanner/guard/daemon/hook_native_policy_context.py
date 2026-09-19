"""Content-free native policy context at isolated hook process boundaries."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Protocol, cast

from ..native_policy_decision_context import NativePolicyDecisionContext
from .hook_process_worker import HookProcessReview


def capture_result_context(
    publisher: object, edge: Mapping[str, object]
) -> tuple[bool, NativePolicyDecisionContext | None]:
    capture = getattr(publisher, "capture_policy_decision_context", None)
    if not callable(capture):
        # Scoped results require the same-lock capture barrier, including rows
        # whose authenticated source legitimately has no canonical identity.
        return False, None
    binding = edge.get("policy_binding")
    if not isinstance(binding, Mapping):
        return False, None
    try:
        result = capture(binding, edge.get("receipt"))
        if not isinstance(result, tuple) or len(result) != 2:
            return False, None
        accepted, context = cast(tuple[object, object], result)
    except Exception:
        return False, None
    if accepted is not True or (
        context is not None
        and (not isinstance(context, NativePolicyDecisionContext) or not context.matches_receipt(edge.get("receipt")))
    ):
        return False, None
    return True, context


def native_process_result(worker: object, payload: object, route: object) -> dict[str, object]:
    response: dict[str, object] = {"payload": payload, "reason_code": None, "route": route}
    receipt = getattr(worker, "last_native_decision_receipt", None)
    if isinstance(receipt, dict):
        response["receipt"] = receipt
        context = getattr(worker, "_last_native_policy_context", None)
        if isinstance(context, NativePolicyDecisionContext):
            if not context.matches_receipt(receipt):
                raise ValueError("native process policy context does not match its receipt")
            response["policy_context"] = context.to_dict()
    return response


def policy_context_from_process_result(result: Mapping[str, object]) -> NativePolicyDecisionContext | None:
    if "policy_context" not in result:
        return None
    context = NativePolicyDecisionContext.from_mapping(result["policy_context"])
    if context is None or not context.matches_receipt(result.get("receipt")):
        raise ValueError("native process policy context is invalid")
    return context


class _NativeReceiptWriter(Protocol):
    def submit_native_decision_receipt(
        self, receipt: Mapping[str, object], *, policy_context: NativePolicyDecisionContext | None = None
    ) -> bool: ...


def submit_native_review_receipt(writer: _NativeReceiptWriter, review: HookProcessReview) -> bool:
    if review.receipt is None:
        return False
    if review.policy_context is None:
        return writer.submit_native_decision_receipt(review.receipt)
    return writer.submit_native_decision_receipt(review.receipt, policy_context=review.policy_context)
