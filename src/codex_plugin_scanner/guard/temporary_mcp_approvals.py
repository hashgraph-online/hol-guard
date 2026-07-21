"""Bounded approvals for routine browser MCP capabilities."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from typing import Final, Literal, cast

from .models import PolicyDecision
from .runtime.browser_mcp_intent import GuardBrowserAutomationIntentV1

TemporaryMcpGrantTarget = Literal["exact", "category", "server"]
TemporaryMcpGrantDuration = Literal["15m", "1h", "5h"]

TEMPORARY_MCP_GRANT_TARGETS: Final = ("exact", "category", "server")
TEMPORARY_MCP_GRANT_DURATIONS: Final = ("15m", "1h", "5h")
_DURATION_SECONDS: Final = {"15m": 900, "1h": 3600, "5h": 18000}
_INTENT_CATEGORIES: Final = {
    "browser.navigation": "browser_navigation",
    "browser.inspect": "browser_inspection",
    "browser.interact": "browser_interaction",
}
_ELIGIBLE_CATEGORIES: Final = frozenset(_INTENT_CATEGORIES.values())
_INFORMATIONAL_CATEGORIES: Final = frozenset({"browser_external_domain"})
_HARD_RISK_EXCLUSIONS: Final = (
    "browser_transfer",
    "browser_privileged",
    "browser_sensitive_surface",
    "browser_shared_profile",
    "secret_access",
    "filesystem_access",
    "command_execution",
    "destructive_mutation",
    "privileged_system_mutation",
    "tool_schema_mismatch",
)
_SELECTOR_PREFIX: Final = "mcp-temporary-grant:v1"


@dataclass(frozen=True, slots=True)
class TemporaryMcpApprovalEligibility:
    server_identity_hash: str
    server_name: str
    category: str
    target_label: str | None = None

    def to_payload(self) -> dict[str, object]:
        return {
            "version": 1,
            "eligible": True,
            "server_name": self.server_name,
            "server_identity_hash": self.server_identity_hash,
            "category": self.category,
            "target_label": self.target_label,
            "allowed_targets": list(TEMPORARY_MCP_GRANT_TARGETS),
            "allowed_durations": ["once", *TEMPORARY_MCP_GRANT_DURATIONS],
            "hard_risk_exclusions": list(_HARD_RISK_EXCLUSIONS),
        }


@dataclass(frozen=True, slots=True)
class TemporaryMcpGrantSelection:
    target: TemporaryMcpGrantTarget
    duration: TemporaryMcpGrantDuration
    expires_at: str
    eligibility: TemporaryMcpApprovalEligibility


def temporary_mcp_approval_payload(request: Mapping[str, object]) -> dict[str, object] | None:
    eligibility = eligibility_from_browser_intent(request.get("browser_intent"))
    return eligibility.to_payload() if eligibility is not None else None


def eligibility_from_browser_intent(value: object) -> TemporaryMcpApprovalEligibility | None:
    if not isinstance(value, Mapping):
        return None
    intent_payload = cast(Mapping[str, object], value)
    identity_hash = _nonempty_string(intent_payload.get("mcp_server_identity_hash"))
    server_name = _nonempty_string(intent_payload.get("mcp_server_name"))
    intent = _nonempty_string(intent_payload.get("intent"))
    category = _INTENT_CATEGORIES.get(intent or "")
    risk_categories = _string_set(intent_payload.get("risk_categories"))
    if identity_hash is None or server_name is None or category is None:
        return None
    if category not in risk_categories:
        return None
    if not risk_categories.issubset({category, *_INFORMATIONAL_CATEGORIES}):
        return None
    target_label = _nonempty_string(intent_payload.get("target_domain")) or _nonempty_string(
        intent_payload.get("target_origin")
    )
    return TemporaryMcpApprovalEligibility(identity_hash, server_name, category, target_label)


def eligibility_for_runtime_call(
    browser_intent: GuardBrowserAutomationIntentV1 | None,
    risk_categories: Sequence[str],
) -> TemporaryMcpApprovalEligibility | None:
    if browser_intent is None:
        return None
    return eligibility_from_browser_intent(
        {
            "intent": browser_intent.intent,
            "mcp_server_identity_hash": browser_intent.mcp_server_identity_hash,
            "mcp_server_name": browser_intent.mcp_server_name,
            "target_domain": browser_intent.target_domain,
            "target_origin": browser_intent.target_origin,
            "risk_categories": list(risk_categories),
        }
    )


def parse_temporary_mcp_grant_selection(
    request: Mapping[str, object],
    *,
    target: object,
    duration: object,
    now: str,
) -> TemporaryMcpGrantSelection:
    eligibility = eligibility_from_browser_intent(request.get("browser_intent"))
    if eligibility is None:
        raise ValueError("temporary_mcp_approval_ineligible")
    if target not in TEMPORARY_MCP_GRANT_TARGETS:
        raise ValueError("invalid_mcp_grant_target")
    if duration not in TEMPORARY_MCP_GRANT_DURATIONS:
        raise ValueError("invalid_mcp_grant_duration")
    parsed_now = datetime.fromisoformat(now.replace("Z", "+00:00"))
    if parsed_now.tzinfo is None:
        parsed_now = parsed_now.replace(tzinfo=timezone.utc)
    typed_target: TemporaryMcpGrantTarget = target
    typed_duration: TemporaryMcpGrantDuration = duration
    expires_at = (
        parsed_now.astimezone(timezone.utc) + timedelta(seconds=_DURATION_SECONDS[typed_duration])
    ).isoformat()
    return TemporaryMcpGrantSelection(typed_target, typed_duration, expires_at, eligibility)


def temporary_mcp_grant_decision(
    *,
    harness: str,
    selection: TemporaryMcpGrantSelection,
    reason: str | None,
    artifact_id: str,
    artifact_hash: str,
) -> PolicyDecision:
    selector = (
        temporary_mcp_exact_grant_selector(artifact_id, artifact_hash)
        if selection.target == "exact"
        else temporary_mcp_grant_selector(
            selection.eligibility.server_identity_hash,
            selection.eligibility.category if selection.target == "category" else None,
        )
    )
    return PolicyDecision(
        harness=harness,
        scope="artifact",
        action="allow",
        artifact_id=selector,
        reason=reason,
        source="approval-gate",
        expires_at=selection.expires_at,
    )


def temporary_mcp_grant_selector(server_identity_hash: str, category: str | None = None) -> str:
    suffix = f":category:{category}" if category is not None else ":server"
    return f"{_SELECTOR_PREFIX}:{server_identity_hash}{suffix}"


def temporary_mcp_exact_grant_selector(artifact_id: str, artifact_hash: str) -> str:
    digest = sha256(f"{artifact_id}\0{artifact_hash}".encode()).hexdigest()
    return f"{_SELECTOR_PREFIX}:exact:{digest}"


def runtime_grant_selectors(
    browser_intent: GuardBrowserAutomationIntentV1 | None,
    risk_categories: Sequence[str],
    *,
    artifact_id: str,
    artifact_hash: str,
) -> tuple[str, ...]:
    eligibility = eligibility_for_runtime_call(browser_intent, risk_categories)
    if eligibility is None:
        return ()
    return (
        temporary_mcp_exact_grant_selector(artifact_id, artifact_hash),
        temporary_mcp_grant_selector(eligibility.server_identity_hash, eligibility.category),
        temporary_mcp_grant_selector(eligibility.server_identity_hash),
    )


def _nonempty_string(value: object) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


def _string_set(value: object) -> set[str]:
    if not isinstance(value, Sequence) or isinstance(value, str):
        return set()
    return {item for item in value if isinstance(item, str)}
