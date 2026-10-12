"""Approval proof predicates answered by the native runtime.

The store selects saved approval rows; the resident decides what a selected
row proves: its claim disposition, whether it is exact fresh local tool
approval, whether a claim lookup outcome keeps a consumed claim usable, and
whether a claimed row still authorizes the post-claim review. Python sends the
rows verbatim and presents the answers.

``native_approval_proof`` raises ``NativeApprovalProofError`` for anything but
a bound, strictly decoded ``ok`` answer. The predicate helpers below turn that
error into the fail-closed value (no disposition, no proof), never an allow.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol
from uuid import uuid4

from .native_context import _canonical_request_sha256, _resolve_digest_home
from .native_execution import _resident_request

APPROVAL_PROOF_FEATURE = "approval-proof-v1"
_REQUEST_SCHEMA = "guard-approval-proof-request.v1"
_RESULT_SCHEMA = "guard-approval-proof-result.v1"
_PAYLOAD_KEYS = frozenset({"accepted", "claim_disposition"})
_RESIDENT_CODE = re.compile(r"^native_approval_proof_[a-z_]{1,64}$")
_UNAVAILABLE = "native_approval_proof_unavailable"
_TIMEOUT_SECONDS = 5.0

ApprovalReuseClaimDisposition = Literal["consumed", "retained"]


class _ToolArtifact(Protocol):
    @property
    def harness(self) -> str: ...

    @property
    def artifact_id(self) -> str: ...


class NativeApprovalProofError(RuntimeError):
    """No authoritative proof answer; ``code`` says why, for diagnostics only."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class ApprovalProofOutcome:
    accepted: bool
    claim_disposition: ApprovalReuseClaimDisposition | None


def native_approval_proof(query: Mapping[str, object], *, guard_home: Path | None = None) -> ApprovalProofOutcome:
    """Return the resident's answer to one proof query, or raise.

    The op is pure, so ``guard_home`` only selects which resident answers; the
    bound context-digest home (else the process default home) is used when the
    caller has no store home.
    """

    try:
        guard_home = _resolve_digest_home(guard_home)
    except (OSError, RuntimeError, ValueError):
        raise NativeApprovalProofError("native_approval_proof_home_unbound") from None
    request: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": f"approval-proof-{uuid4().hex}",
        "query": dict(query),
    }
    try:
        digest = "sha256:" + _canonical_request_sha256(request)
    except (TypeError, ValueError):
        raise NativeApprovalProofError("native_approval_proof_request_invalid") from None
    response = _resident_request(
        operation="approval_proof_decide",
        request=request,
        guard_home=guard_home,
        timeout_seconds=_TIMEOUT_SECONDS,
        required_feature=APPROVAL_PROOF_FEATURE,
        response_schema=_RESULT_SCHEMA,
    )
    if (
        response is None
        or response.get("schema") != _RESULT_SCHEMA
        or response.get("request_id") != request["request_id"]
        or response.get("request_sha256") != digest
    ):
        raise NativeApprovalProofError(_UNAVAILABLE)
    status, code = response.get("status"), response.get("code")
    if status == "error":
        reason = code if isinstance(code, str) and _RESIDENT_CODE.fullmatch(code) else _UNAVAILABLE
        raise NativeApprovalProofError(reason)
    if status != "ok" or code != "ok":
        raise NativeApprovalProofError(_UNAVAILABLE)
    payload = response.get("payload")
    if not isinstance(payload, dict) or set(payload) != _PAYLOAD_KEYS:
        raise NativeApprovalProofError("native_approval_proof_payload_invalid")
    accepted, disposition = payload["accepted"], payload["claim_disposition"]
    if not isinstance(accepted, bool) or disposition not in (None, "consumed", "retained"):
        raise NativeApprovalProofError("native_approval_proof_payload_invalid")
    return ApprovalProofOutcome(accepted, disposition)


def _accepted(query: Mapping[str, object], guard_home: Path | None = None) -> bool:
    try:
        return native_approval_proof(query, guard_home=guard_home).accepted
    except NativeApprovalProofError:
        return False


def approval_reuse_claim_disposition(
    decision: Mapping[str, object],
    *,
    guard_home: Path | None = None,
) -> ApprovalReuseClaimDisposition | None:
    """What a successful claim does to the selected ``allow``; ``None`` if unclaimable."""

    try:
        return native_approval_proof(
            {"kind": "claim_disposition", "decision": dict(decision)},
            guard_home=guard_home,
        ).claim_disposition
    except NativeApprovalProofError:
        return None


def fresh_lookup_preserves_claim(reason_code: str | None, *, guard_home: Path | None = None) -> bool:
    return _accepted({"kind": "lookup_preserves_claim", "reason_code": reason_code}, guard_home)


def fresh_local_tool_approval_matches(
    decision: Mapping[str, object] | None,
    *,
    artifact: _ToolArtifact,
    artifact_hash: str,
    guard_home: Path | None = None,
) -> bool:
    """Exact fresh local proof for this tool call; not integrity or launch authority."""

    return _accepted(
        {
            "kind": "fresh_tool_approval",
            "decision": None if decision is None else dict(decision),
            "harness": artifact.harness,
            "artifact_id": artifact.artifact_id,
            "artifact_hash": artifact_hash,
        },
        guard_home,
    )


def fresh_claim_allows_reapproval(
    *,
    claim_disposition: str | None,
    reason_code: str | None,
    decision: Mapping[str, object] | None,
    artifact: _ToolArtifact,
    artifact_hash: str,
    guard_home: Path | None = None,
) -> bool:
    return _accepted(
        {
            "kind": "fresh_claim_allows_reapproval",
            "claim_disposition": claim_disposition,
            "reason_code": reason_code,
            "decision": None if decision is None else dict(decision),
            "harness": artifact.harness,
            "artifact_id": artifact.artifact_id,
            "artifact_hash": artifact_hash,
        },
        guard_home,
    )


def claimed_approval_authorizes_postclaim_review(
    *,
    claim_disposition: str | None,
    claimed_decision: Mapping[str, object] | None,
    current_decision: Mapping[str, object] | None,
    guard_home: Path | None = None,
) -> bool:
    """Whether the claimed saved proof may lower a fresh review after claiming."""

    return _accepted(
        {
            "kind": "postclaim_review_authorized",
            "claim_disposition": claim_disposition,
            "claimed_decision": None if claimed_decision is None else dict(claimed_decision),
            "current_decision": None if current_decision is None else dict(current_decision),
        },
        guard_home,
    )


__all__ = [
    "APPROVAL_PROOF_FEATURE",
    "ApprovalProofOutcome",
    "ApprovalReuseClaimDisposition",
    "NativeApprovalProofError",
    "approval_reuse_claim_disposition",
    "claimed_approval_authorizes_postclaim_review",
    "fresh_claim_allows_reapproval",
    "fresh_local_tool_approval_matches",
    "fresh_lookup_preserves_claim",
    "native_approval_proof",
]
