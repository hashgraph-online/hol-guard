"""Execution-ownership grading and enforcement.

Implements a frozen ``ExecutionOwnershipGrade`` enum and a pure
``resolve_execution_ownership`` function that enforces:

- Rerouting to a provider/remote is permitted ONLY for
  ``GUARD_OWNED_LOCAL`` or ``DELEGABLE_REMOTE_AUTHENTICATED``.
- When ``can_return_result`` is ``False`` the grade MUST degrade to
  ``DECISION_ONLY`` — a hook can never claim relocated execution or
  achieved assurance it cannot return.
- Decades ``DECISION_ONLY``, ``DEGRADED_OBSERVE_ONLY``, and ``UNSUPPORTED``
  can never be upgraded to an owned or delegable grade.
"""

from __future__ import annotations

from enum import Enum
from typing import Final


class ExecutionOwnershipGrade(str, Enum):
    """Ownership grade for an execution request.

    Ordered from strongest (most trusted) to weakest (most restricted):
    """

    #: Guard fully owns and executes locally; no delegation.
    GUARD_OWNED_LOCAL = "guard-owned-local"

    #: Delegation to a remote provider is permissible after authentication.
    DELEGABLE_REMOTE_AUTHENTICATED = "delegable-remote-authenticated"

    #: Guard made a decision; no relocated execution.
    DECISION_ONLY = "decision-only"

    #: Observation-only with degraded trust posture.
    DEGRADED_OBSERVE_ONLY = "degraded-observe-only"

    #: Unsupported execution target; no ownership claim possible.
    UNSUPPORTED = "unsupported"


# Monotonic downgrade ladder: a weaker grade can always replace a stronger
# one, but never the reverse.
_WEAK_GRADES: Final = frozenset(
    {
        ExecutionOwnershipGrade.DECISION_ONLY,
        ExecutionOwnershipGrade.DEGRADED_OBSERVE_ONLY,
        ExecutionOwnershipGrade.UNSUPPORTED,
    }
)

# Grades that are permitted to reroute to a provider/remote.
_DELEGABLE_GRADES: Final = frozenset(
    {
        ExecutionOwnershipGrade.GUARD_OWNED_LOCAL,
        ExecutionOwnershipGrade.DELEGABLE_REMOTE_AUTHENTICATED,
    }
)


def _require_execution_ownership_grade(value: object) -> ExecutionOwnershipGrade:
    if not isinstance(value, ExecutionOwnershipGrade):
        raise ValueError("grade must be an ExecutionOwnershipGrade")
    return value


def resolve_execution_ownership(
    grade: object,
    *,
    can_return_result: bool = True,
    reroute_to_remote: bool = False,
) -> ExecutionOwnershipGrade:
    """Resolve the effective execution-ownership grade.

    Enforces monotonic downgrade discipline:

    1. **No upgrade path.** Grades in ``_WEAK_GRADES`` can never be upgraded
       to ``GUARD_OWNED_LOCAL`` or ``DELEGABLE_REMOTE_AUTHENTICATED``.
       The caller is responsible for passing a valid grade; this function
       refuses to elevate weak grades silently.
    2. **Can-return-result constraint.** When ``can_return_result`` is
       ``False`` the grade MUST degrade to ``DECISION_ONLY``.
    3. **Delegation constraint.** When ``reroute_to_remote`` is ``True`` the
       caller intends to delegate to a provider/remote, so the effective grade
       must be in ``_DELEGABLE_GRADES``; otherwise it degrades to
       ``DECISION_ONLY`` rather than claiming a delegation it cannot perform.
    """
    validated = _require_execution_ownership_grade(grade)

    # Rule 2: can't return result → force DECISION_ONLY.
    if not can_return_result:
        return ExecutionOwnershipGrade.DECISION_ONLY

    # Rule 3: an intent to reroute requires a delegable grade.
    if reroute_to_remote and validated not in _DELEGABLE_GRADES:
        return ExecutionOwnershipGrade.DECISION_ONLY

    return validated
