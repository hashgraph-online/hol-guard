"""Authoritative composition of current policy with saved approval evidence.

A saved approval is evidence that an exact, previously reviewed request may
proceed.  It is not a policy input and therefore cannot lower a newly computed
``require-reapproval``, ``sandbox-required``, or ``block`` action.  This module
keeps that exception to the normal action lattice explicit and independently
testable: an exact, valid saved ``allow`` may satisfy only a current ``review``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from ..action_lattice import (
    UNKNOWN_GUARD_ACTION_REASON,
    GuardActionNormalization,
    most_restrictive_guard_action,
    normalize_guard_action_result,
)
from ..models import GuardAction

ApprovalReuseStatus = Literal["accepted", "rejected", "not-applicable"]
ApprovalReuseValidationFailure = Literal[
    "approval_reuse_identity_changed",
    "approval_reuse_content_changed",
    "approval_reuse_capability_changed",
    "approval_reuse_policy_changed",
    "approval_reuse_sandbox_changed",
    "approval_reuse_expired",
    "approval_reuse_integrity_failure",
    "approval_reuse_claim_failed",
    "approval_reuse_launch_identity_unverified",
    "approval_reuse_context_changed_after_claim",
]

APPROVAL_REUSE_ACCEPTED = "approval_reuse_accepted"
APPROVAL_REUSE_NO_SAVED_DECISION = "approval_reuse_no_saved_decision"
APPROVAL_REUSE_CURRENT_ACTION_UNKNOWN = "approval_reuse_current_action_unknown"
APPROVAL_REUSE_SAVED_ACTION_UNKNOWN = "approval_reuse_saved_action_unknown"
APPROVAL_REUSE_CURRENT_BLOCK = "approval_reuse_current_block"
APPROVAL_REUSE_SANDBOX_REQUIRED = "approval_reuse_sandbox_required"
APPROVAL_REUSE_REAPPROVAL_REQUIRED = "approval_reuse_reapproval_required"
APPROVAL_REUSE_CURRENT_ACTION_NOT_REVIEW = "approval_reuse_current_action_not_review"
APPROVAL_REUSE_SAVED_ACTION_NOT_ALLOW = "approval_reuse_saved_action_not_allow"
APPROVAL_REUSE_SAVED_BLOCK = "approval_reuse_saved_block"
APPROVAL_REUSE_CLAIM_FAILED = "approval_reuse_claim_failed"
APPROVAL_REUSE_LAUNCH_IDENTITY_UNVERIFIED = "approval_reuse_launch_identity_unverified"
APPROVAL_REUSE_CONTEXT_CHANGED_AFTER_CLAIM = "approval_reuse_context_changed_after_claim"


@dataclass(frozen=True, slots=True)
class ApprovalReuseDecision:
    """Result of composing current authority with optional saved evidence."""

    action: GuardAction
    status: ApprovalReuseStatus
    reason_code: str
    current_action: GuardAction
    saved_action: GuardAction | None
    should_claim: bool
    current_normalization_reason_code: str | None = None
    saved_normalization_reason_code: str | None = None
    original_current_action: str | None = None
    original_saved_action: str | None = None
    original_current_type: str = "str"
    original_saved_type: str | None = None

    @property
    def accepted(self) -> bool:
        return self.status == "accepted"

    def to_evidence(self) -> dict[str, object]:
        """Return stable, non-secret diagnostics for receipts and UI evidence."""

        return {
            "action": self.action,
            "status": self.status,
            "reason_code": self.reason_code,
            "current_action": self.current_action,
            "saved_action": self.saved_action,
            "should_claim": self.should_claim,
            "current_normalization_reason_code": self.current_normalization_reason_code,
            "saved_normalization_reason_code": self.saved_normalization_reason_code,
            "original_current_action": self.original_current_action,
            "original_saved_action": self.original_saved_action,
            "original_current_type": self.original_current_type,
            "original_saved_type": self.original_saved_type,
        }


def evaluate_approval_reuse(
    current_action: object,
    saved_action: object | None = None,
    *,
    saved_decision_present: bool | None = None,
    validation_reason: ApprovalReuseValidationFailure | None = None,
) -> ApprovalReuseDecision:
    """Compose a recomputed action with saved approval evidence.

    ``None`` means no saved decision unless ``saved_decision_present`` is set
    explicitly.  The explicit flag lets untyped persistence callers distinguish
    absence from a malformed stored row whose ``action`` value is null.
    """

    current = normalize_guard_action_result(current_action, unknown_action="block")
    present = saved_action is not None if saved_decision_present is None else saved_decision_present
    if not present:
        reason_code = (
            APPROVAL_REUSE_CURRENT_ACTION_UNKNOWN
            if current.reason_code == UNKNOWN_GUARD_ACTION_REASON
            else APPROVAL_REUSE_NO_SAVED_DECISION
        )
        return _decision(
            action=current.action,
            status="rejected" if current.reason_code is not None else "not-applicable",
            reason_code=reason_code,
            current=current,
        )

    saved = normalize_guard_action_result(saved_action, unknown_action="require-reapproval")
    conservative_action = most_restrictive_guard_action(current.action, saved.action, unknown_action="block")
    if current.reason_code is not None:
        return _decision(
            action=conservative_action,
            status="rejected",
            reason_code=APPROVAL_REUSE_CURRENT_ACTION_UNKNOWN,
            current=current,
            saved=saved,
        )
    if validation_reason is not None:
        if validation_reason == "approval_reuse_integrity_failure":
            # A matching integrity-invalid local authority may have contained
            # a stronger action than the other valid row selected by lookup.
            # Ordinary stale approval evidence is unnecessary when current
            # policy independently allows a request, but a tampered authority
            # cannot be ignored on that basis.  Require a fresh decision while
            # preserving an already stronger sandbox/block result.
            conservative_action = most_restrictive_guard_action(
                conservative_action,
                "require-reapproval",
                unknown_action="block",
            )
        return _decision(
            action=conservative_action,
            status="rejected",
            reason_code=validation_reason,
            current=current,
            saved=saved,
        )
    if saved.reason_code is not None:
        return _decision(
            action=conservative_action,
            status="rejected",
            reason_code=APPROVAL_REUSE_SAVED_ACTION_UNKNOWN,
            current=current,
            saved=saved,
        )
    if saved.action == "block":
        return _decision(
            action="block",
            status="accepted",
            reason_code=APPROVAL_REUSE_SAVED_BLOCK,
            current=current,
            saved=saved,
        )
    if current.action == "block":
        return _decision(
            action="block",
            status="rejected",
            reason_code=APPROVAL_REUSE_CURRENT_BLOCK,
            current=current,
            saved=saved,
        )
    if current.action == "sandbox-required":
        return _decision(
            action="sandbox-required",
            status="rejected",
            reason_code=APPROVAL_REUSE_SANDBOX_REQUIRED,
            current=current,
            saved=saved,
        )
    if current.action == "require-reapproval":
        return _decision(
            action=conservative_action,
            status="rejected",
            reason_code=APPROVAL_REUSE_REAPPROVAL_REQUIRED,
            current=current,
            saved=saved,
        )
    if current.action == "review" and saved.action == "allow":
        return _decision(
            action="allow",
            status="accepted",
            reason_code=APPROVAL_REUSE_ACCEPTED,
            current=current,
            saved=saved,
            should_claim=True,
        )
    if saved.action == "allow":
        return _decision(
            action=current.action,
            status="not-applicable",
            reason_code=APPROVAL_REUSE_CURRENT_ACTION_NOT_REVIEW,
            current=current,
            saved=saved,
        )
    return _decision(
        action=conservative_action,
        status="rejected",
        reason_code=APPROVAL_REUSE_SAVED_ACTION_NOT_ALLOW,
        current=current,
        saved=saved,
    )


def _decision(
    *,
    action: GuardAction,
    status: ApprovalReuseStatus,
    reason_code: str,
    current: GuardActionNormalization,
    saved: GuardActionNormalization | None = None,
    should_claim: bool = False,
) -> ApprovalReuseDecision:
    return ApprovalReuseDecision(
        action=action,
        status=status,
        reason_code=reason_code,
        current_action=current.action,
        saved_action=saved.action if saved is not None else None,
        should_claim=should_claim,
        current_normalization_reason_code=current.reason_code,
        saved_normalization_reason_code=saved.reason_code if saved is not None else None,
        original_current_action=current.original_action,
        original_saved_action=saved.original_action if saved is not None else None,
        original_current_type=current.original_type,
        original_saved_type=saved.original_type if saved is not None else None,
    )
