"""Native action projections for untyped persistence and API boundaries."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from .decision_projection_boundaries import CanonicalApprovalDecision as CanonicalApprovalDecision
from .decision_projection_boundaries import canonical_approval_decision as canonical_approval_decision
from .models import GuardAction
from .native_decisions import artifact_transport_fields
from .native_signal_projection import NativeSignalProjectionError, signal_projection

# Leave framing and home-path headroom below the resident's 4 MiB request cap.
# ASCII encoding also bounds the canonical digest representation of Unicode.
_PROJECTION_BATCH_BYTES = 3 * 1024 * 1024
_PROJECTION_SIZE_REFUSALS = frozenset(
    {
        "native_runner_authority_request_too_large",
        "native_runner_authority_response_too_large",
        "native_runner_authority_projection_batch_too_large",
    }
)
_UNREADABLE_DECISION = "unreadable"
_UNREADABLE_ACTION_MAX_LENGTH = 64


@dataclass(frozen=True, slots=True)
class CanonicalReceiptDecision:
    """One native receipt action and synchronized envelope fields."""

    policy_decision: GuardAction
    action_envelope_json: dict[str, object] | None
    contract_error: str | None = None


@dataclass(frozen=True, slots=True)
class CanonicalApprovalSurfaces:
    """Approval fields synchronized by a single native evaluation."""

    policy_action: GuardAction
    decision_v2_json: dict[str, object]
    action_envelope_json: dict[str, object] | None
    contract_error: str | None = None


def canonical_receipt_decision(
    policy_decision: object,
    action_envelope_json: object,
    *,
    reject_contradiction: bool,
    guard_home: Path | None = None,
) -> CanonicalReceiptDecision:
    return CanonicalReceiptDecision(
        **signal_projection(
            "projection_receipt",
            {"action": policy_decision, "envelope": action_envelope_json, "reject": reject_contradiction},
            guard_home=guard_home,
        )
    )


def canonical_approval_surfaces(
    policy_action: object,
    decision_v2_json: object,
    action_envelope_json: object,
    *,
    reject_contradiction: bool,
    guard_home: Path | None = None,
) -> CanonicalApprovalSurfaces:
    return CanonicalApprovalSurfaces(
        **signal_projection(
            "projection_surfaces",
            {
                "action": policy_action,
                "decision": decision_v2_json,
                "envelope": action_envelope_json,
                "reject": reject_contradiction,
            },
            guard_home=guard_home,
        )
    )


def canonical_approval_artifact(
    artifact: Mapping[str, object], *, guard_home: Path | None = None
) -> CanonicalApprovalSurfaces:
    return CanonicalApprovalSurfaces(
        **signal_projection(
            "projection_artifact_surfaces", {"artifact": artifact_transport_fields(artifact)}, guard_home=guard_home
        )
    )


def canonical_approval_surfaces_batch(
    inputs: Sequence[tuple[object, object, object]],
    *,
    guard_home: Path | None = None,
) -> list[CanonicalApprovalSurfaces]:
    """Project ordered rows within request, response and row-count limits."""

    result: list[CanonicalApprovalSurfaces] = []
    rows: list[dict[str, object]] = []
    size = 0
    for action, decision, envelope in inputs:
        row: dict[str, object] = {"action": action, "decision": decision, "envelope": envelope}
        try:
            row_size = len(json.dumps(row, separators=(",", ":"), allow_nan=False).encode("utf-8")) + 1
        except (TypeError, ValueError, UnicodeEncodeError):
            row = _unreadable_row(row)
            row_size = len(json.dumps(row, separators=(",", ":")).encode("utf-8")) + 1
        if rows and (len(rows) == 128 or size + row_size > _PROJECTION_BATCH_BYTES):
            result.extend(_project_approval_rows(rows, guard_home=guard_home))
            rows, size = [], 0
        rows.append(row)
        size += row_size
    if rows:
        result.extend(_project_approval_rows(rows, guard_home=guard_home))
    return result


def _project_approval_rows(
    rows: list[dict[str, object]], *, guard_home: Path | None
) -> list[CanonicalApprovalSurfaces]:
    try:
        projected = signal_projection(
            "projection_surfaces_batch", {"rows": rows, "reject": False}, guard_home=guard_home
        )
    except NativeSignalProjectionError as error:
        # A bound size refusal proves availability. Split aggregates; a single
        # oversized row is projected again as unreadable so it fails closed
        # without hiding the rest of the page.
        if str(error) not in _PROJECTION_SIZE_REFUSALS:
            raise
        if len(rows) == 1:
            if rows[0].get("decision") == _UNREADABLE_DECISION:
                raise
            return _project_approval_rows([_unreadable_row(rows[0])], guard_home=guard_home)
        midpoint = len(rows) // 2
        return _project_approval_rows(rows[:midpoint], guard_home=guard_home) + _project_approval_rows(
            rows[midpoint:], guard_home=guard_home
        )
    return [CanonicalApprovalSurfaces(**row) for row in projected]


def _unreadable_row(row: Mapping[str, object]) -> dict[str, object]:
    """Replace stored fields the resident cannot receive with a non-object decision.

    The native projection treats a non-object decision as inconsistent, so the
    row fails closed with a contract error at the stored action or stricter.
    """
    action = row.get("action")
    if not isinstance(action, str) or len(action) > _UNREADABLE_ACTION_MAX_LENGTH:
        action = None
    else:
        try:
            action.encode("utf-8")
        except UnicodeEncodeError:
            action = None
    return {"action": action, "decision": _UNREADABLE_DECISION, "envelope": None}
