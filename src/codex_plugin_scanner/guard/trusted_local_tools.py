"""Authenticated, digest-bound grants for read-only local CLI capabilities."""

from __future__ import annotations

import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path
from typing import Final, Literal, cast
from uuid import uuid4

from .models import GuardAction, PolicyDecision
from .native_context import _canonical_request_sha256, _resolve_existing_digest_home, ensure_resident_prerequisite
from .native_execution import _resident_request

LocalToolGrantTarget = Literal["capability", "version"]
LocalToolGrantDuration = Literal["15m", "1h", "5h", "version", "always"]

LOCAL_TOOL_GRANT_TARGETS: Final = ("capability", "version")
LOCAL_TOOL_GRANT_DURATIONS: Final = ("15m", "1h", "5h", "version", "always")
_DURATION_SECONDS: Final = {"15m": 900, "1h": 3600, "5h": 18000}
_SELECTOR_PREFIX: Final = "local-tool-grant:v1"
_POLICY_SOURCE: Final = "trusted-local-tool"
LOCAL_TOOL_ELIGIBILITY_FEATURE: Final = "local-tool-eligibility-v1"
_ELIGIBILITY_REQUEST_SCHEMA: Final = "guard-local-tool-eligibility-request.v1"
_ELIGIBILITY_RESULT_SCHEMA: Final = "guard-local-tool-eligibility-result.v1"
_ELIGIBILITY_TIMEOUT_SECONDS: Final = 10.0
# The request carries the caller environment, which the launch identity binds.
_ELIGIBILITY_MAX_REQUEST_BYTES: Final = 2 * 1024 * 1024
_ELIGIBILITY_PAYLOAD_KEYS: Final = frozenset(
    {"tool_name", "tool_identity_hash", "capability", "read_only_reason", "trust_basis", "indefinite_allowed"}
)
_HARD_RISK_EXCLUSIONS: Final = (
    "shell_chaining",
    "shell_redirection",
    "embedded_execution",
    "environment_override",
    "unresolved_entrypoint",
    "mutating_capability",
    "untrusted_output_processor",
)


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

    def to_payload(self) -> dict[str, object]:
        package_profile = self.trust_basis == "package-profile"
        reusable_durations = (
            ("15m", "1h", "5h", "always")
            if package_profile and self.indefinite_allowed
            else ("15m", "1h", "5h")
            if package_profile
            else LOCAL_TOOL_GRANT_DURATIONS[:-1]
        )
        return {
            **self.to_evidence(),
            "allowed_targets": ["capability"] if package_profile else list(LOCAL_TOOL_GRANT_TARGETS),
            "allowed_durations": [
                "once",
                *reusable_durations,
            ],
            "hard_risk_exclusions": list(_HARD_RISK_EXCLUSIONS),
        }


@dataclass(frozen=True, slots=True)
class LocalToolGrantSelection:
    target: LocalToolGrantTarget
    duration: LocalToolGrantDuration
    expires_at: str | None
    eligibility: LocalToolApprovalEligibility


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
    if (
        response is None
        or response.get("schema") != _ELIGIBILITY_RESULT_SCHEMA
        or response.get("request_id") != request["request_id"]
        or response.get("request_sha256") != digest
        or response.get("status") != "ok"
        or response.get("code") != "ok"
    ):
        return None
    return _eligibility_from_payload(response.get("payload"))


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
    eligibility = _eligibility_from_request(request)
    return eligibility.to_payload() if eligibility is not None else None


def parse_local_tool_grant_selection(
    request: Mapping[str, object],
    *,
    target: object,
    duration: object,
    now: str,
) -> LocalToolGrantSelection:
    eligibility = _eligibility_from_request(request)
    if eligibility is None:
        raise ValueError("local_tool_approval_ineligible")
    if target not in LOCAL_TOOL_GRANT_TARGETS:
        raise ValueError("invalid_local_tool_grant_target")
    allowed_targets = cast(list[object], eligibility.to_payload()["allowed_targets"])
    if target not in allowed_targets:
        raise ValueError("invalid_local_tool_grant_target")
    if duration not in LOCAL_TOOL_GRANT_DURATIONS:
        raise ValueError("invalid_local_tool_grant_duration")
    allowed_durations = cast(list[object], eligibility.to_payload()["allowed_durations"])
    if duration not in allowed_durations:
        raise ValueError("invalid_local_tool_grant_duration")
    typed_target: LocalToolGrantTarget = target
    typed_duration: LocalToolGrantDuration = duration
    expires_at: str | None = None
    if typed_duration not in {"version", "always"}:
        parsed_now = datetime.fromisoformat(now.replace("Z", "+00:00"))
        if parsed_now.tzinfo is None:
            parsed_now = parsed_now.replace(tzinfo=timezone.utc)
        expires_at = (
            parsed_now.astimezone(timezone.utc) + timedelta(seconds=_DURATION_SECONDS[typed_duration])
        ).isoformat()
    return LocalToolGrantSelection(typed_target, typed_duration, expires_at, eligibility)


def local_tool_grant_decision(
    *,
    harness: str,
    selection: LocalToolGrantSelection,
    reason: str | None,
) -> PolicyDecision:
    return PolicyDecision(
        harness=harness,
        scope="artifact",
        action="allow",
        artifact_id=local_tool_grant_selector(
            selection.eligibility,
            target=selection.target,
        ),
        reason=reason,
        source=_POLICY_SOURCE,
        expires_at=selection.expires_at,
    )


_GRANT_REUSING_ACTIONS: frozenset[GuardAction] = frozenset({"review", "require-reapproval"})


def matching_local_tool_grant(
    *,
    store: object,
    harness: str,
    eligibility: LocalToolApprovalEligibility | None,
    current_action: GuardAction,
) -> dict[str, object] | None:
    """The saved grant a reviewable command may reuse, or ``None``.

    The resident derives each target's selector and decides which row counts as
    a grant; the recomputed action travels with the probe so the gate on it is
    applied in the same place.

    A command the policy already allowed or blocked cannot reuse a grant, so it
    is answered here rather than paying for the evidence load and the resident
    round trip that answer would need. The resident applies the same gate.
    """
    if eligibility is None or current_action not in _GRANT_REUSING_ACTIONS:
        return None
    resolver = getattr(store, "resolve_local_tool_grant", None)
    if not callable(resolver):
        return None
    decision = resolver(
        harness,
        tool_identity_hash=eligibility.tool_identity_hash,
        capability=eligibility.capability,
        current_action=current_action,
    )
    return dict(cast(Mapping[str, object], decision)) if isinstance(decision, Mapping) else None


def local_tool_grant_selector(
    eligibility: LocalToolApprovalEligibility,
    *,
    target: LocalToolGrantTarget,
) -> str:
    capability = eligibility.capability if target == "capability" else "*"
    capability_hash = sha256(capability.encode("utf-8")).hexdigest()
    return f"{_SELECTOR_PREFIX}:{eligibility.tool_identity_hash}:{target}:{capability_hash}"


def _eligibility_from_request(request: Mapping[str, object]) -> LocalToolApprovalEligibility | None:
    evidence = request.get("scanner_evidence")
    if not isinstance(evidence, Sequence) or isinstance(evidence, str):
        return None
    for item in evidence:
        if not isinstance(item, Mapping):
            continue
        normalized_item = dict(cast(Mapping[str, object], item))
        if normalized_item.get("source") != "trusted_local_tool":
            continue
        tool_name = _nonempty_string(normalized_item.get("tool_name"))
        identity_hash = _nonempty_string(normalized_item.get("tool_identity_hash"))
        capability = _nonempty_string(normalized_item.get("capability"))
        read_only_reason = _nonempty_string(normalized_item.get("read_only_reason"))
        trust_basis = normalized_item.get("trust_basis", "verified-files")
        if (
            normalized_item.get("eligible") is True
            and tool_name is not None
            and identity_hash is not None
            and _is_sha256(identity_hash)
            and capability is not None
            and read_only_reason is not None
            and trust_basis in {"verified-files", "package-profile"}
        ):
            return LocalToolApprovalEligibility(
                tool_name,
                identity_hash,
                capability,
                read_only_reason,
                cast(Literal["verified-files", "package-profile"], trust_basis),
                bool(normalized_item.get("indefinite_allowed", False)),
            )
    return None


def _nonempty_string(value: object) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


def _is_sha256(value: str | None) -> bool:
    return value is not None and len(value) == 64 and all(character in "0123456789abcdef" for character in value)
