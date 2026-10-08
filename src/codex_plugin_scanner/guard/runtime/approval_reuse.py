"""Resident authority for composing current policy with saved approval evidence.

A saved approval is evidence that an exact, previously reviewed request may
proceed. It is not a policy input and therefore cannot lower a newly computed
``sandbox-required`` or ``block`` action. A newly issued local approval may
satisfy the exact ``require-reapproval`` request that created it. A durable
exact-action approval may also satisfy an identical request when the caller has
independently verified its retained, integrity-bound authority.

The resident ``approval_reuse_decide`` op is the sole authority for this
composition; there is no in-process Python evaluator. ``evaluate_approval_reuse``
returns ``None`` only when the resident cannot answer (transport failure: no
bound home, runtime unavailable, capability absent, timeout, overload, or an
undecodable envelope). ``None`` preserves the caller's current evaluation —
no saved approval is claimed — matching the resident's own
``no_saved_decision``/``not-applicable`` composition rather than re-running a
superseded Python path. A well-formed envelope whose decision payload fails
strict validation raises :class:`ApprovalReuseMalformedResultError`: malformed
resident output must never be conflated with a successful no-decision and must
never grant reuse.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Literal, cast

from ..action_lattice import is_guard_action
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
    "approval_reuse_provider_account_unverified",
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
APPROVAL_REUSE_AUTHORITY_UNAVAILABLE = "approval_reuse_authority_unavailable"

_APPROVAL_REUSE_STATUSES: frozenset[str] = frozenset({"accepted", "rejected", "not-applicable"})


class ApprovalReuseMalformedResultError(RuntimeError):
    """The resident returned a well-formed envelope whose decision payload
    failed strict validation.

    Distinct from a transport ``None``: the resident answered, but the answer
    is not a trustworthy ``ApprovalReuseDecision``. Callers must not treat it
    as a successful no-decision and must not claim a saved approval on it.
    """


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
    saved_artifact_hash_is_context_token: bool | None = None

    @property
    def accepted(self) -> bool:
        return self.status == "accepted"

    def to_evidence(self) -> dict[str, object]:
        """Return stable, non-secret diagnostics for receipts and UI evidence."""

        evidence: dict[str, object] = {
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
        if self.saved_artifact_hash_is_context_token is not None:
            evidence["saved_artifact_hash_is_context_token"] = self.saved_artifact_hash_is_context_token
        return evidence


def with_saved_artifact_hash_provenance(
    reuse: ApprovalReuseDecision,
    stored_artifact_hash: object,
) -> ApprovalReuseDecision:
    """Record whether the saved approval was bound to the context-token contract.

    A rejected saved approval whose stored hash predates the context-token
    format is stale-format evidence: it could never have bound to the current
    request, so its rejection is housekeeping rather than the invalidation of
    a live approval.  Emit layers use this non-secret flag to distinguish the
    two cases without exposing either hash value.
    """

    if not isinstance(stored_artifact_hash, str) or not stored_artifact_hash:
        return reuse
    from .approval_context import parse_approval_context_token

    return replace(
        reuse,
        saved_artifact_hash_is_context_token=parse_approval_context_token(stored_artifact_hash) is not None,
    )


def approval_reuse_authority_unavailable(current_action: object) -> ApprovalReuseDecision:
    """Compose the transport-failure projection for a recomputed action.

    The resident is the sole authority; when it cannot be reached the caller
    must preserve its current evaluation. This constructor returns the
    wire-equivalent of that preservation: the caller's action unchanged, no
    saved approval claimed, status ``not-applicable``. It exists so event
    surfaces that require an ``ApprovalReuseDecision`` DTO can record the
    unchanged evaluation without inventing an approval grant.
    """

    action = current_action if is_guard_action(current_action) else "block"
    return ApprovalReuseDecision(
        action=action,  # type: ignore[arg-type]
        status="not-applicable",
        reason_code=APPROVAL_REUSE_AUTHORITY_UNAVAILABLE,
        current_action=action,  # type: ignore[arg-type]
        saved_action=None,
        should_claim=False,
    )


def evaluate_approval_reuse(
    current_action: object,
    saved_action: object | None = None,
    *,
    saved_decision_present: bool | None = None,
    validation_reason: ApprovalReuseValidationFailure | None = None,
    fresh_local_approval: bool = False,
    durable_exact_approval: bool = False,
    deadline_monotonic: float | None = None,
) -> ApprovalReuseDecision | None:
    """Compose a recomputed action with saved approval evidence in the resident.

    ``None`` means no saved decision unless ``saved_decision_present`` is set
    explicitly.  The explicit flag lets untyped persistence callers distinguish
    absence from a malformed stored row whose ``action`` value is null.

    ``fresh_local_approval`` identifies short-lived, integrity-bound authority
    created by the user's immediately preceding review. Persistent policy must
    never set it.

    ``durable_exact_approval`` identifies a retained, non-expiring approval-gate
    allow whose exact context token and integrity were verified by the caller.
    Broader saved policy and manually-authored policy must never set it.

    Returns ``None`` when the resident cannot service the call (the established
    transport contract shared with ``native_approval_gate``): callers preserve
    their current evaluation unchanged and must not claim a saved approval.
    Raises :class:`ApprovalReuseMalformedResultError` when the resident answers
    with a payload that fails strict decision validation — a malformed answer
    is not a successful no-decision and never grants reuse.
    Sequential compositions for one request share ``deadline_monotonic``.
    """
    # RTM-032: the resident is the sole authority for this composition. There
    # is no Python fallback evaluator.
    from ..native_approval_reuse import approval_reuse_decide_native
    from ..native_context import context_digest_guard_home

    native_home = context_digest_guard_home()
    if native_home is None:
        return None
    native_payload = approval_reuse_decide_native(
        current_action,
        saved_action,
        saved_decision_present=saved_decision_present,
        validation_reason=validation_reason,
        fresh_local_approval=fresh_local_approval,
        durable_exact_approval=durable_exact_approval,
        guard_home=native_home,
        deadline_monotonic=deadline_monotonic,
    )
    if native_payload is None:
        return None
    return _decision_from_native_payload(native_payload)


def _native_str(payload: dict[str, object], key: str) -> str | None:
    value = payload.get(key)
    return value if isinstance(value, str) else None


def _decision_from_native_payload(payload: object) -> ApprovalReuseDecision:
    """Rebuild an ``ApprovalReuseDecision`` from the resident op payload.

    ``payload`` is the ``ApprovalReuseDecision.to_evidence()`` dict emitted by
    the ``approval_reuse_decide`` resident op.  Every meaningful decision
    field is strictly validated — actions against the canonical lattice,
    ``status`` against the closed set, ``should_claim`` as a real bool — so
    malformed resident output raises
    :class:`ApprovalReuseMalformedResultError` instead of silently coercing
    into a decision that could grant an unverifiable claim.
    """

    if not isinstance(payload, dict):
        raise ApprovalReuseMalformedResultError("approval_reuse payload is not an object")
    action = _native_str(payload, "action")
    current_action = _native_str(payload, "current_action")
    saved_action = payload.get("saved_action")
    status = _native_str(payload, "status")
    reason_code = _native_str(payload, "reason_code")
    should_claim = payload.get("should_claim")
    original_current_type = _native_str(payload, "original_current_type") or "str"
    if (
        not is_guard_action(action)
        or not is_guard_action(current_action)
        or (saved_action is not None and not is_guard_action(saved_action))
        or status not in _APPROVAL_REUSE_STATUSES
        or not reason_code
        or not reason_code.strip()
        or not isinstance(should_claim, bool)
    ):
        raise ApprovalReuseMalformedResultError("approval_reuse payload failed decision validation")
    return ApprovalReuseDecision(
        action=action,
        status=cast(ApprovalReuseStatus, status),
        reason_code=reason_code,
        current_action=current_action,
        saved_action=cast("GuardAction | None", saved_action),
        should_claim=should_claim,
        current_normalization_reason_code=_native_str(payload, "current_normalization_reason_code"),
        saved_normalization_reason_code=_native_str(payload, "saved_normalization_reason_code"),
        original_current_action=_native_str(payload, "original_current_action"),
        original_saved_action=_native_str(payload, "original_saved_action"),
        original_current_type=original_current_type,
        original_saved_type=_native_str(payload, "original_saved_type"),
    )
