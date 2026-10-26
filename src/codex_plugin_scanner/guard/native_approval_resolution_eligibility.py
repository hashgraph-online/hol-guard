"""Resident bridge for the ``approval_resolution_eligibility`` op.

Rust owns whether a stored approval row can accept a user's answer: an
unreadable decision contract and an action outside the lattice both make the
row inconsistent, and ``block`` and ``sandbox-required`` are terminal. The
resident already applied that ladder to the rows its approval sweep projects,
so this module ships the two surfaces the rule reads and returns the resident's
answers in the caller's order. Nothing is recomputed here: when the resident is
unavailable the caller raises rather than deciding a row is resolvable.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from uuid import uuid4

from .native_context import _resolve_digest_home, ensure_resident_prerequisite
from .native_execution import _resident_request
from .native_store_policy import _payload

APPROVAL_RESOLUTION_ELIGIBILITY_FEATURE = "approval-resolution-eligibility-v1"
_REQUEST_SCHEMA = "guard-approval-resolution-eligibility-request.v1"
_RESULT_SCHEMA = "guard-approval-resolution-eligibility-result.v1"
_TIMEOUT_SECONDS = 10.0
_MAX_REQUEST_BYTES = 4 * 1024 * 1024
# Mirrors ``APPROVAL_RESOLUTION_ELIGIBILITY_MAX_ITEMS`` in the contract: the
# resident refuses a request carrying more rows than this, so a sweep over an
# unbounded set of pending rows asks in batches rather than being refused.
_MAX_ITEMS_PER_REQUEST = 1024


class ApprovalResolutionEligibilityUnavailableError(RuntimeError):
    """Raised when the resident cannot answer which rows are resolvable."""


def native_approval_resolution_block_reasons(
    requests: Sequence[Mapping[str, object]],
    *,
    guard_home: Path | None = None,
) -> list[str | None]:
    """Return one block reason, or ``None``, per row in the caller's order."""

    if not requests:
        return []
    home = Path(_resolve_digest_home(guard_home))
    if not ensure_resident_prerequisite(home):
        raise ApprovalResolutionEligibilityUnavailableError
    answers: list[str | None] = []
    for start in range(0, len(requests), _MAX_ITEMS_PER_REQUEST):
        batch = requests[start : start + _MAX_ITEMS_PER_REQUEST]
        answers.extend(_block_reasons_for_batch(batch, home))
    return answers


def _block_reasons_for_batch(
    requests: Sequence[Mapping[str, object]],
    home: Path,
) -> list[str | None]:
    """Ask the resident about one batch the contract is willing to accept."""

    wire: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": f"approval-resolution-eligibility-{uuid4().hex}",
        "items": [
            {
                "policy_action": request.get("policy_action"),
                "decision_contract_error": request.get("decision_contract_error"),
            }
            for request in requests
        ],
    }
    try:
        response = _resident_request(
            operation="approval_resolution_eligibility",
            request=wire,
            guard_home=home,
            timeout_seconds=_TIMEOUT_SECONDS,
            required_feature=APPROVAL_RESOLUTION_ELIGIBILITY_FEATURE,
            response_schema=_RESULT_SCHEMA,
            max_request_bytes=_MAX_REQUEST_BYTES,
            record_success=False,
        )
    except (TypeError, ValueError, OSError, RuntimeError):
        raise ApprovalResolutionEligibilityUnavailableError from None
    payload = _payload(response, wire, home)
    if not isinstance(payload, dict):
        raise ApprovalResolutionEligibilityUnavailableError
    reasons = payload.get("reasons")
    if not isinstance(reasons, list) or len(reasons) != len(requests):
        raise ApprovalResolutionEligibilityUnavailableError
    answers: list[str | None] = []
    for reason in reasons:
        if reason is None:
            answers.append(None)
        elif isinstance(reason, str) and reason:
            answers.append(reason)
        else:
            raise ApprovalResolutionEligibilityUnavailableError
    return answers
