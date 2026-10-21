"""Typed runtime decisions for Guard pause and approval UX."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, fields
from types import MappingProxyType
from typing import Any, Literal

from codex_plugin_scanner.guard.models import GuardAction
from codex_plugin_scanner.guard.runtime.signals import (
    RiskConfidenceLabel,
    RiskSignalV2,
)

from ..native_decisions import decision_authority

GuardDecisionAction = Literal["allow", "warn", "ask", "block"]
AUTHORITATIVE_DECISION_SCHEMA_VERSION = 1
AUTHORITATIVE_DECISION_INCONSISTENT = "authoritative_decision_inconsistent"


def _signals(payload: Sequence[Mapping[str, Any]]) -> tuple[RiskSignalV2, ...]:
    """Project already native-validated signal fields without re-evaluation."""

    return tuple(RiskSignalV2(**dict(item)) for item in payload)


@dataclass(frozen=True, slots=True)
class GuardDecisionV2:
    """Immutable presentation DTO; Rust builds and validates its fields."""

    guard_action: GuardAction
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
    package_review_cloud_reason_code: str | None = None

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "guard_action": self.guard_action,
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
        if self.package_review_cloud_reason_code is not None:
            payload["package_review_cloud_reason_code"] = self.package_review_cloud_reason_code
        return payload

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> GuardDecisionV2:
        return _v2(decision_authority("decision_v2_decode", {"payload": dict(payload)}))


@dataclass(frozen=True, slots=True)
class GuardDecisionEnforcementState:
    """Native-validated execution and persistence projection."""

    blocking: bool
    authority_finalized: bool
    launch_permitted: bool
    prompt_required: bool
    sandbox_required: bool
    snapshot_permitted: bool

    def to_dict(self) -> dict[str, bool]:
        return {field.name: getattr(self, field.name) for field in fields(GuardDecisionEnforcementState)}

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> GuardDecisionEnforcementState:
        return cls(**decision_authority("decision_enforcement_decode", {"payload": dict(payload)}))


@dataclass(frozen=True, slots=True)
class AuthoritativeGuardDecision:
    """Immutable native decision, never a launch permit."""

    schema_version: int
    action: GuardAction
    source: str
    reason: str
    composition_trace: Mapping[str, object]
    signals: tuple[RiskSignalV2, ...]
    enforcement: GuardDecisionEnforcementState
    decision_v2: GuardDecisionV2

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "action": self.action,
            "source": self.source,
            "reason": self.reason,
            "composition_trace": dict(self.composition_trace),
            "signals": [signal.to_dict() for signal in self.signals],
            "enforcement": self.enforcement.to_dict(),
            "decision_v2": self.decision_v2.to_dict(),
        }

    def to_artifact_projection(self) -> dict[str, object]:
        return {
            "authoritative_decision": self.to_dict(),
            "policy_action": self.action,
            "decision_v2_json": self.decision_v2.to_dict(),
            "policy_composition": dict(self.composition_trace),
            "verdict_action": self.action,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> AuthoritativeGuardDecision:
        return _authoritative(decision_authority("decision_authoritative_decode", {"payload": dict(payload)}))


def _v2(payload: Mapping[str, Any]) -> GuardDecisionV2:
    values = dict(payload)
    values["approval_scopes"] = tuple(values["approval_scopes"])
    values["signals"] = _signals(values["signals"])
    return GuardDecisionV2(**values)


def _authoritative(payload: Mapping[str, Any]) -> AuthoritativeGuardDecision:
    values = dict(payload)
    values["composition_trace"] = MappingProxyType(dict(values["composition_trace"]))
    values["signals"] = _signals(values["signals"])
    values["enforcement"] = GuardDecisionEnforcementState(**values["enforcement"])
    values["decision_v2"] = _v2(values["decision_v2"])
    return AuthoritativeGuardDecision(**values)


def project_native_authoritative_decision(payload: dict[str, Any]) -> AuthoritativeGuardDecision:
    """Project a decision already bound by another native operation, without RPC."""
    from ..native_decisions import _shape

    _shape(payload, "authoritative")
    return _authoritative(payload)


def build_authoritative_decision(
    action: GuardAction,
    *,
    reason: str,
    composition_trace: Mapping[str, object],
    signals: Sequence[RiskSignalV2] = (),
    authority_finalized: bool,
    source: str = "composed-consumer-policy",
) -> AuthoritativeGuardDecision:
    return _authoritative(
        decision_authority(
            "decision_build",
            {
                "action": action,
                "reason": reason,
                "composition_trace": dict(composition_trace),
                "signals": [signal.to_dict() for signal in signals],
                "authority_finalized": authority_finalized,
                "source": source,
            },
        )
    )


def authoritative_decision_from_artifact(
    payload: Mapping[str, object],
    *,
    require_authoritative: bool = False,
) -> AuthoritativeGuardDecision:
    return _authoritative(
        decision_authority(
            "decision_artifact_decode",
            {
                "payload": dict(payload),
                "require_authoritative": require_authoritative,
            },
        )
    )


def decision_from_legacy_policy_action(
    policy_action: GuardAction,
    *,
    reason: str,
    signals: Sequence[RiskSignalV2] = (),
) -> GuardDecisionV2:
    return _v2(
        decision_authority(
            "decision_legacy",
            {
                "action": policy_action,
                "reason": reason,
                "signals": [signal.to_dict() for signal in signals],
            },
        )
    )
