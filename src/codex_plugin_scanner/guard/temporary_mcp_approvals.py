"""Bounded approvals for routine browser MCP capabilities.

The native runtime decides which grants a filed browser intent may carry, and
for one pick, the selector it is filed under and when it runs out. Python only
ships the filed intent and records the answer.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from .models import PolicyDecision
from .native_runner_authority import NativeRunnerAuthorityError, native_runner_authority

_KIND: Final = "temporary_mcp_grant"
_BATCH: Final = 256
_SELECTION_FIELDS: Final = (
    "target",
    "duration",
    "expires_at",
    "server_name",
    "server_identity_hash",
    "category",
    "artifact_id",
)


@dataclass(frozen=True, slots=True)
class TemporaryMcpGrantSelection:
    target: str
    duration: str
    expires_at: str
    server_name: str
    server_identity_hash: str
    category: str
    artifact_id: str


def temporary_mcp_approval_payload(
    request: Mapping[str, object], *, guard_home: Path | None = None
) -> dict[str, object] | None:
    return temporary_mcp_approval_payloads([request], guard_home=guard_home)[0]


def temporary_mcp_approval_payloads(
    requests: Sequence[Mapping[str, object]], *, guard_home: Path | None = None
) -> list[dict[str, object] | None]:
    """What the approval card may offer for each request, in order.

    A request that files no browser intent can carry no grant, so it is
    answered without a round-trip. A resident that cannot answer offers
    nothing: the request keeps its once-only choices.
    """

    answers: list[dict[str, object] | None] = [None] * len(requests)
    asking = [index for index, request in enumerate(requests) if isinstance(request.get("browser_intent"), Mapping)]
    for start in range(0, len(asking), _BATCH):
        batch = asking[start : start + _BATCH]
        try:
            payload = native_runner_authority(
                _KIND,
                {"browser_intents": [requests[index]["browser_intent"] for index in batch]},
                guard_home=guard_home,
            )
        except NativeRunnerAuthorityError:
            continue
        approvals = payload.get("approvals")
        if not isinstance(approvals, list) or len(approvals) != len(batch):
            continue
        for index, approval in zip(batch, approvals, strict=True):
            answers[index] = approval if isinstance(approval, dict) else None
    return answers


def parse_temporary_mcp_grant_selection(
    request: Mapping[str, object],
    *,
    target: object,
    duration: object,
    now: str,
    guard_home: Path | None = None,
) -> TemporaryMcpGrantSelection:
    """The resident's answer for one pick; a pick it refuses raises its code."""

    artifact_id = request.get("artifact_id")
    artifact_hash = request.get("artifact_hash")
    payload = native_runner_authority(
        _KIND,
        {
            "browser_intent": request.get("browser_intent"),
            "selection": {
                "target": target,
                "duration": duration,
                "now": now,
                "artifact_id": artifact_id if isinstance(artifact_id, str) else "",
                "artifact_hash": artifact_hash if isinstance(artifact_hash, str) else "",
            },
        },
        guard_home=guard_home,
    )
    refusal = payload.get("refusal")
    if isinstance(refusal, str) and refusal:
        raise ValueError(refusal)
    selection = payload.get("selection")
    values = [selection.get(key) for key in _SELECTION_FIELDS] if isinstance(selection, dict) else []
    if len(values) != len(_SELECTION_FIELDS) or not all(isinstance(value, str) and value for value in values):
        raise NativeRunnerAuthorityError("native_temporary_mcp_grant_invalid")
    return TemporaryMcpGrantSelection(*(str(value) for value in values))


def temporary_mcp_grant_decision(
    *,
    harness: str,
    selection: TemporaryMcpGrantSelection,
    reason: str | None,
) -> PolicyDecision:
    return PolicyDecision(
        harness=harness,
        scope="artifact",
        action="allow",
        artifact_id=selection.artifact_id,
        reason=reason,
        source="approval-gate",
        expires_at=selection.expires_at,
    )
