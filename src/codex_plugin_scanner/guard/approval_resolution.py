"""Eligibility checks for resolving queued Guard approvals.

The rule itself lives in the resident, next to the approval sweep that already
applied it to the rows it projects. This module only narrows a stored row to
the two surfaces the rule reads and turns the resident's answer into the
refusal the mutation boundaries raise, so a row cannot become resolvable here
because the resident could not be reached.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path

from .native_approval_resolution_eligibility import (
    native_approval_resolution_block_reasons,
)

TERMINAL_POLICY_ACTION_NOT_RESOLVABLE = "terminal_policy_action_not_resolvable"


def approval_resolution_block_reasons(
    requests: Sequence[Mapping[str, object]],
    *,
    guard_home: Path | None = None,
) -> list[str | None]:
    """Return why each canonical approval row cannot accept a resolution.

    One call covers the whole batch, so a sweep holding the write lock asks the
    resident once rather than once per row.
    """

    return native_approval_resolution_block_reasons(requests, guard_home=guard_home)


def approval_resolution_block_reason(
    request: Mapping[str, object],
    *,
    guard_home: Path | None = None,
) -> str | None:
    """Return why a canonical approval row cannot accept a user resolution."""

    return approval_resolution_block_reasons([request], guard_home=guard_home)[0]


def require_resolvable_approval_request(
    request: Mapping[str, object],
    *,
    guard_home: Path | None = None,
) -> None:
    """Reject terminal or contract-invalid approval rows at mutation boundaries."""

    reason = approval_resolution_block_reason(request, guard_home=guard_home)
    if reason is not None:
        raise ValueError(reason)
