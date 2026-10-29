"""Authenticated, digest-bound grants for read-only local CLI capabilities."""

from __future__ import annotations

import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal, cast
from uuid import uuid4

from .models import PolicyDecision
from .native_context import _canonical_request_sha256, _resolve_existing_digest_home, ensure_resident_prerequisite
from .native_execution import _resident_request

LocalToolGrantTarget = Literal["capability", "version"]
LocalToolGrantDuration = Literal["15m", "1h", "5h", "version", "always"]

LOCAL_TOOL_ELIGIBILITY_FEATURE: Final = "local-tool-eligibility-v1"
_ELIGIBILITY_REQUEST_SCHEMA: Final = "guard-local-tool-eligibility-request.v1"
_ELIGIBILITY_RESULT_SCHEMA: Final = "guard-local-tool-eligibility-result.v1"
_ELIGIBILITY_TIMEOUT_SECONDS: Final = 10.0
# The request carries the caller environment, which the launch identity binds.
_ELIGIBILITY_MAX_REQUEST_BYTES: Final = 2 * 1024 * 1024
_ELIGIBILITY_PAYLOAD_KEYS: Final = frozenset(
    {"tool_name", "tool_identity_hash", "capability", "read_only_reason", "trust_basis", "indefinite_allowed"}
)
LOCAL_TOOL_GRANT_FEATURE: Final = "local-tool-grant-v1"
_GRANT_REQUEST_SCHEMA: Final = "guard-local-tool-grant-request.v1"
_GRANT_RESULT_SCHEMA: Final = "guard-local-tool-grant-result.v1"
_GRANT_TIMEOUT_SECONDS: Final = 10.0
# Filed evidence only; no environment travels with a grant question.
_GRANT_MAX_REQUEST_BYTES: Final = 1024 * 1024


class LocalToolGrantUnavailableError(RuntimeError):
    """The resident could not say what a grant for this request may be."""


@dataclass(frozen=True, slots=True)
class LocalToolApprovalEligibility:
    tool_name: str
    tool_identity_hash: str
    capability: str
    read_only_reason: str
    trust_basis: Literal["verified-files", "package-profile"] = "verified-files"
    indefinite_allowed: bool = False

    def to_evidence(self) -> dict[str, object]:
        return {
            "source": "trusted_local_tool",
            "version": 1,
            "eligible": True,
            "tool_name": self.tool_name,
            "tool_identity_hash": self.tool_identity_hash,
            "capability": self.capability,
            "read_only_reason": self.read_only_reason,
            "trust_basis": self.trust_basis,
            "indefinite_allowed": self.indefinite_allowed,
        }


@dataclass(frozen=True, slots=True)
class LocalToolGrantSelection:
    """One pick the resident accepted, with the policy row it filed for it."""

    target: LocalToolGrantTarget
    duration: LocalToolGrantDuration
    expires_at: str | None
    tool_name: str
    capability: str
    decision: Mapping[str, object]


def local_tool_approval_eligibility(
    command: str,
    *,
    cwd: Path,
    home_dir: Path | None,
) -> LocalToolApprovalEligibility | None:
    """Ask the resident whether the command may carry a reusable local tool grant.

    Any missing, failed or malformed answer is ``None``: not eligible, never
    more permissive.
    """

    try:
        request: dict[str, object] = {
            "schema": _ELIGIBILITY_REQUEST_SCHEMA,
            "request_id": f"local-tool-eligibility-{uuid4().hex}",
            "command": command,
            "cwd": str(cwd),
            "home_dir": None if home_dir is None else str(home_dir),
            "user_home": str(Path.home()),
            "launch_env": dict(os.environ),
        }
        digest = "sha256:" + _canonical_request_sha256(request)
        guard_home = _resolve_existing_digest_home(None)
        if not ensure_resident_prerequisite(guard_home):
            return None
        response = _resident_request(
            operation="local_tool_eligibility",
            request=request,
            guard_home=guard_home,
            timeout_seconds=_ELIGIBILITY_TIMEOUT_SECONDS,
            required_feature=LOCAL_TOOL_ELIGIBILITY_FEATURE,
            response_schema=_ELIGIBILITY_RESULT_SCHEMA,
            max_request_bytes=_ELIGIBILITY_MAX_REQUEST_BYTES,
        )
    except Exception:
        return None
    answer = _accepted(response, request_id=request["request_id"], digest=digest, schema=_ELIGIBILITY_RESULT_SCHEMA)
    return None if answer is None else _eligibility_from_payload(answer.get("payload"))


def _eligibility_from_payload(payload: object) -> LocalToolApprovalEligibility | None:
    if not isinstance(payload, dict) or set(payload) != _ELIGIBILITY_PAYLOAD_KEYS:
        return None
    fields = cast(dict[str, object], payload)
    tool_name, identity_hash = fields["tool_name"], fields["tool_identity_hash"]
    capability, read_only_reason = fields["capability"], fields["read_only_reason"]
    trust_basis, indefinite_allowed = fields["trust_basis"], fields["indefinite_allowed"]
    if (
        not isinstance(tool_name, str)
        or _nonempty_string(tool_name) is None
        or not isinstance(identity_hash, str)
        or not _is_sha256(identity_hash)
        or not isinstance(capability, str)
        or _nonempty_string(capability) is None
        or not isinstance(read_only_reason, str)
        or _nonempty_string(read_only_reason) is None
        or not isinstance(trust_basis, str)
        or trust_basis not in {"verified-files", "package-profile"}
        or not isinstance(indefinite_allowed, bool)
        or (indefinite_allowed and trust_basis != "package-profile")
    ):
        return None
    return LocalToolApprovalEligibility(
        tool_name=tool_name,
        tool_identity_hash=identity_hash,
        capability=capability,
        read_only_reason=read_only_reason,
        trust_basis=cast(Literal["verified-files", "package-profile"], trust_basis),
        indefinite_allowed=indefinite_allowed,
    )


def local_tool_approval_payload(request: Mapping[str, object]) -> dict[str, object] | None:
    """What the approval card may offer for this request's filed evidence.

    A resident that cannot answer offers nothing: the request keeps its
    once-only choices rather than a grant Python shaped on its own.

    Every row of an approval queue passes through here, and almost none of them
    were filed by the local-tool scanner. A request whose evidence never names
    that source can carry no grant whatever the resident says, so it is answered
    without a round-trip. That is a narrower answer, never a wider one: which of
    the entries that do name it is eligible stays the resident's to decide.
    """

    if not _names_a_local_tool(request):
        return None
    payload = _grant_payload(request, None)
    approval = None if payload is None else payload.get("approval")
    return cast(dict[str, object], approval) if isinstance(approval, dict) else None


def parse_local_tool_grant_selection(
    request: Mapping[str, object],
    *,
    target: object,
    duration: object,
    now: str,
    harness: str,
    reason: str | None,
) -> LocalToolGrantSelection:
    """Have the resident judge one pick against the request's filed evidence.

    A pick the evidence does not allow raises its refusal code, as the local
    parse did. A resident that cannot answer raises rather than falling back:
    nothing else may decide what a grant covers or when it runs out.
    """

    payload = _grant_payload(
        request,
        {
            "harness": harness,
            "target": target,
            "duration": duration,
            "now": now,
            "reason": reason,
        },
    )
    if payload is None:
        raise LocalToolGrantUnavailableError("native_local_tool_grant_unavailable")
    refusal = payload.get("refusal")
    if isinstance(refusal, str) and refusal:
        raise ValueError(refusal)
    selection = payload.get("selection")
    approval = payload.get("approval")
    if not isinstance(selection, dict) or not isinstance(approval, dict):
        raise LocalToolGrantUnavailableError("native_local_tool_grant_unavailable")
    chosen = cast(dict[str, object], selection)
    offered = cast(dict[str, object], approval)
    expires_at = chosen.get("expires_at")
    decision = chosen.get("decision")
    if not isinstance(decision, dict) or not (expires_at is None or isinstance(expires_at, str)):
        raise LocalToolGrantUnavailableError("native_local_tool_grant_unavailable")
    selected = LocalToolGrantSelection(
        target=cast(LocalToolGrantTarget, _required_text(chosen.get("target"))),
        duration=cast(LocalToolGrantDuration, _required_text(chosen.get("duration"))),
        expires_at=expires_at,
        tool_name=_required_text(offered.get("tool_name")),
        capability=_required_text(offered.get("capability")),
        decision=cast(dict[str, object], decision),
    )
    # Read the filed row here, where nothing has been written yet. Left until
    # the resolution files it, a malformed reply would fail after the approval
    # gate had already been required and a policy row may already exist.
    local_tool_grant_decision(selected)
    return selected


def local_tool_grant_decision(selection: LocalToolGrantSelection) -> PolicyDecision:
    """The policy row the resident filed for an accepted pick."""

    decision = selection.decision
    if decision.get("scope") != "artifact" or decision.get("action") != "allow":
        raise LocalToolGrantUnavailableError("native_local_tool_grant_unavailable")
    reason = decision.get("reason")
    return PolicyDecision(
        harness=_required_text(decision.get("harness")),
        scope="artifact",
        action="allow",
        artifact_id=_required_text(decision.get("artifact_id")),
        reason=reason if isinstance(reason, str) else None,
        source=_required_text(decision.get("source")),
        expires_at=selection.expires_at,
    )


def _grant_payload(request: Mapping[str, object], selection: dict[str, object] | None) -> dict[str, object] | None:
    """The resident's answer for this request's evidence, or ``None``."""

    try:
        native_request: dict[str, object] = {
            "schema": _GRANT_REQUEST_SCHEMA,
            "request_id": f"local-tool-grant-{uuid4().hex}",
            "scanner_evidence": _filed_evidence(request),
            "selection": selection,
        }
        digest = "sha256:" + _canonical_request_sha256(native_request)
        guard_home = _resolve_existing_digest_home(None)
        if not ensure_resident_prerequisite(guard_home):
            return None
        response = _resident_request(
            operation="local_tool_grant",
            request=native_request,
            guard_home=guard_home,
            timeout_seconds=_GRANT_TIMEOUT_SECONDS,
            required_feature=LOCAL_TOOL_GRANT_FEATURE,
            response_schema=_GRANT_RESULT_SCHEMA,
            max_request_bytes=_GRANT_MAX_REQUEST_BYTES,
        )
    except Exception:
        return None
    answer = _accepted(response, request_id=native_request["request_id"], digest=digest, schema=_GRANT_RESULT_SCHEMA)
    payload = None if answer is None else answer.get("payload")
    return cast(dict[str, object], payload) if isinstance(payload, dict) else None


def _accepted(
    response: dict[str, object] | None,
    *,
    request_id: object,
    digest: str,
    schema: str,
) -> dict[str, object] | None:
    """The reply, when it is this request's, intact and successful."""

    if (
        response is None
        or response.get("schema") != schema
        or response.get("request_id") != request_id
        or response.get("request_sha256") != digest
        or response.get("status") != "ok"
        or response.get("code") != "ok"
    ):
        return None
    return response


def _filed_evidence(request: Mapping[str, object]) -> list[dict[str, object]]:
    """The request's scanner evidence as plain JSON objects.

    The entries are untrusted; the resident decides which of them, if any,
    names an eligible trusted local tool.
    """

    evidence = request.get("scanner_evidence")
    if not isinstance(evidence, Sequence) or isinstance(evidence, str):
        return []
    items = cast(Sequence[object], evidence)
    return [dict(cast(Mapping[str, object], item)) for item in items if isinstance(item, Mapping)]


def _names_a_local_tool(request: Mapping[str, object]) -> bool:
    """Whether any filed entry claims the local-tool scanner as its source.

    The claim is untrusted and proves nothing on its own. Its absence is what
    matters: without it there is no entry a grant could ever rest on.
    """

    return any(entry.get("source") == "trusted_local_tool" for entry in _filed_evidence(request))


def _required_text(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise LocalToolGrantUnavailableError("native_local_tool_grant_unavailable")
    return value


def _nonempty_string(value: object) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


def _is_sha256(value: str | None) -> bool:
    return value is not None and len(value) == 64 and all(character in "0123456789abcdef" for character in value)
