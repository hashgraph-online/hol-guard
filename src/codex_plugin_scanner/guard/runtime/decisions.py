"""Typed runtime decisions for Guard pause and approval UX."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Literal

from codex_plugin_scanner.guard.models import GuardAction
from codex_plugin_scanner.guard.runtime.signals import (
    RiskConfidenceLabel,
    RiskSignalV2,
)

GuardDecisionAction = Literal["allow", "warn", "ask", "block"]

_ACTION_MESSAGES: dict[GuardAction, tuple[GuardDecisionAction, str, str, str]] = {
    "allow": (
        "allow",
        "Allowed by policy",
        "Policy allows this action.",
        "HOL Guard allowed this action because policy already trusts it.",
    ),
    "warn": (
        "warn",
        "Risk signals found",
        "HOL Guard noticed risk signals, but policy allows the harness to continue.",
        "Review the warning if this action was unexpected.",
    ),
    "review": (
        "ask",
        "Approval required",
        "HOL Guard needs your approval before this action can run.",
        "Choose an approval scope, then retry in the harness.",
    ),
    "sandbox-required": (
        "ask",
        "Sandbox review required",
        "HOL Guard wants this action reviewed and run in a sandboxed path.",
        "Run it in a sandbox or choose a scoped approval before retrying.",
    ),
    "require-reapproval": (
        "ask",
        "Fresh approval required",
        "HOL Guard needs a fresh approval because this action changed.",
        "Choose the smallest approval scope that matches your intent, then retry.",
    ),
    "block": (
        "block",
        "Blocked by policy",
        "HOL Guard blocked this action.",
        "Review the details before changing policy or retrying.",
    ),
}


@dataclass(frozen=True, slots=True)
class GuardDecisionV2:
    """Product-facing Guard decision with harness and dashboard copy."""

    action: GuardDecisionAction
    reason: str
    user_title: str
    user_body: str
    harness_message: str
    dashboard_primary_detail: str
    approval_scopes: tuple[str, ...]
    retry_instruction: str | None
    signals: tuple[RiskSignalV2, ...]
    confidence: RiskConfidenceLabel

    def to_dict(self) -> dict[str, object]:
        return {
            "action": self.action,
            "reason": self.reason,
            "user_title": self.user_title,
            "user_body": self.user_body,
            "harness_message": self.harness_message,
            "dashboard_primary_detail": self.dashboard_primary_detail,
            "approval_scopes": list(self.approval_scopes),
            "retry_instruction": self.retry_instruction,
            "signals": [signal.to_dict() for signal in self.signals],
            "confidence": self.confidence,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> GuardDecisionV2:
        return cls(
            action=_parse_action(payload.get("action")),
            reason=_required_string(payload, "reason"),
            user_title=_required_string(payload, "user_title"),
            user_body=_required_string(payload, "user_body"),
            harness_message=_required_string(payload, "harness_message"),
            dashboard_primary_detail=_required_string(payload, "dashboard_primary_detail"),
            approval_scopes=_parse_string_tuple(payload.get("approval_scopes"), "approval_scopes"),
            retry_instruction=_optional_string(payload, "retry_instruction"),
            signals=_parse_signals(payload.get("signals")),
            confidence=_parse_confidence(payload.get("confidence")),
        )


def decision_from_legacy_policy_action(
    policy_action: GuardAction,
    *,
    reason: str,
    signals: Sequence[RiskSignalV2] = (),
) -> GuardDecisionV2:
    action, user_title, harness_message, retry_instruction = _ACTION_MESSAGES[policy_action]
    signal_tuple = tuple(signals)
    confidence = _highest_confidence(signal_tuple)
    dashboard_detail = _dashboard_detail_from_signals(signal_tuple, harness_message)
    harness_detail = _harness_message_from_signals(signal_tuple, harness_message)
    return GuardDecisionV2(
        action=action,
        reason=reason,
        user_title=user_title,
        user_body=dashboard_detail,
        harness_message=harness_detail,
        dashboard_primary_detail=dashboard_detail,
        approval_scopes=_approval_scopes_for_action(action),
        retry_instruction=None if action in {"allow", "warn"} else retry_instruction,
        signals=signal_tuple,
        confidence=confidence,
    )


def _approval_scopes_for_action(action: GuardDecisionAction) -> tuple[str, ...]:
    if action != "ask":
        return ()
    return ("artifact", "workspace", "publisher", "harness")


def _dashboard_detail_from_signals(signals: tuple[RiskSignalV2, ...], fallback: str) -> str:
    if not signals:
        return fallback
    if _has_data_flow_exfiltration_signal(signals):
        return (
            "Source-to-sink route: local secret -> network host. "
            "This command sends local secret to network host without exposing the raw secret in Guard evidence."
        )
    strongest = max(signals, key=lambda item: _confidence_rank(item.confidence))
    return strongest.plain_reason


def _harness_message_from_signals(signals: tuple[RiskSignalV2, ...], fallback: str) -> str:
    if _has_data_flow_exfiltration_signal(signals):
        return "HOL Guard paused this action because it sends local secret to network host."
    return fallback


def _has_data_flow_exfiltration_signal(signals: tuple[RiskSignalV2, ...]) -> bool:
    return any(
        signal.detector == "data_flow.exfiltration" or signal.signal_id.startswith("data-flow:") for signal in signals
    )


def _highest_confidence(signals: tuple[RiskSignalV2, ...]) -> RiskConfidenceLabel:
    if not signals:
        return "likely"
    return max((signal.confidence for signal in signals), key=_confidence_rank)


def _confidence_rank(confidence: RiskConfidenceLabel) -> int:
    match confidence:
        case "strong":
            return 3
        case "likely":
            return 2
        case "weak":
            return 1


def _parse_action(value: object) -> GuardDecisionAction:
    match value:
        case "allow":
            return "allow"
        case "warn":
            return "warn"
        case "ask":
            return "ask"
        case "block":
            return "block"
        case _:
            raise ValueError("action must be a known Guard decision action")


def _parse_confidence(value: object) -> RiskConfidenceLabel:
    match value:
        case "weak":
            return "weak"
        case "likely":
            return "likely"
        case "strong":
            return "strong"
        case _:
            raise ValueError("confidence must be a known confidence label")


def _parse_signals(value: object) -> tuple[RiskSignalV2, ...]:
    if not isinstance(value, list):
        raise ValueError("signals must be a list")
    signals: list[RiskSignalV2] = []
    for item in value:
        if not isinstance(item, Mapping):
            raise ValueError(f"signal item must be an object, got {type(item).__name__}")
        signals.append(RiskSignalV2.from_dict(item))
    return tuple(signals)


def _parse_string_tuple(value: object, key: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item.strip() for item in value):
        raise ValueError(f"{key} must be a list of non-empty strings")
    return tuple(value)


def _required_string(payload: Mapping[str, object], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{key} must be a non-empty string")
    return value


def _optional_string(payload: Mapping[str, object], key: str) -> str | None:
    value = payload.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{key} must be a string or null")
    return value
