"""Immutable, content-free provenance captured from an accepted native result."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import cast

from .action_lattice import is_guard_action
from .models import GuardAction
from .native_decision_receipt import validate_native_decision_receipt
from .policy_publication_binding import PolicyPublicationBinding
from .policy_rule_identity import POLICY_RULE_IDENTITY_FIELDS, PolicyRuleIdentity

_SCHEMA = "guard.native-policy-decision.v1"
_DIGEST = re.compile(r"[0-9a-f]{64}", re.ASCII)
_UTC_INSTANT = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?(?:Z|\+00:00)", re.ASCII
)
_HARNESS = re.compile(r"[a-z0-9][a-z0-9-]{0,63}", re.ASCII)
_BINDING_FIELDS = frozenset(
    {
        "policy_generation",
        "policy_digest",
        "source_input_digest",
        "runtime_identity",
        "resident_generation",
        "selected_decision_id",
    }
)
_FIELDS = frozenset(
    {
        "schemaVersion",
        "nativeDecisionId",
        "recordedAt",
        "harness",
        "eventName",
        "decision",
        "policyAction",
        "observedPolicyAction",
        "observeMode",
        "publication",
        "snapshot",
        *POLICY_RULE_IDENTITY_FIELDS,
    }
)


def _positive(value: object) -> bool:
    return type(value) is int and 0 < cast(int, value) <= (1 << 53) - 1


def _digest(value: object) -> bool:
    return isinstance(value, str) and _DIGEST.fullmatch(value) is not None


@dataclass(frozen=True, slots=True)
class NativePolicyDecisionContext:
    """Decision attribution only; an allow never attests execution or completion."""

    native_decision_id: str
    recorded_at: str
    harness: str
    decision: str
    policy_action: GuardAction
    observed_policy_action: GuardAction | None
    observe_mode: bool
    identity: PolicyRuleIdentity
    policy_generation: int
    policy_digest: str
    source_input_digest: str
    runtime_identity: str
    resident_generation: int
    selected_decision_id: int

    def __post_init__(self) -> None:
        if not isinstance(self.identity, PolicyRuleIdentity):
            raise ValueError("native policy identity must be typed")
        if len(self.identity.policy_version) > 16 or int(self.identity.policy_version) > (1 << 53) - 1:
            raise ValueError("native canonical revision must be a safe integer")
        if self.identity.publication is not None and not _positive(self.identity.publication.bundle_version):
            raise ValueError("native publication version must be a safe positive integer")
        if not all(
            _positive(value) for value in (self.policy_generation, self.resident_generation, self.selected_decision_id)
        ):
            raise ValueError("native policy binding generations must be positive integers")
        if not all(
            _digest(value)
            for value in (self.native_decision_id, self.policy_digest, self.source_input_digest, self.runtime_identity)
        ):
            raise ValueError("native policy binding digests must be canonical SHA-256")
        if not isinstance(self.harness, str) or _HARNESS.fullmatch(self.harness) is None:
            raise ValueError("native policy harness must be bounded")
        if (
            type(self.observe_mode) is not bool
            or not isinstance(self.decision, str)
            or self.decision not in {"allow", "deny"}
            or not is_guard_action(self.policy_action)
        ):
            raise ValueError("native policy outcome must be explicit")
        if self.decision != ("allow" if self.policy_action in {"allow", "warn"} else "deny"):
            raise ValueError("native policy action must match its actual decision")
        if (self.observe_mode and (self.decision != "allow" or not is_guard_action(self.observed_policy_action))) or (
            not self.observe_mode and self.observed_policy_action is not None
        ):
            raise ValueError("native observed outcome must match its mode")
        if (
            not isinstance(self.recorded_at, str)
            or len(self.recorded_at) > 40
            or _UTC_INSTANT.fullmatch(self.recorded_at) is None
        ):
            raise ValueError("native policy recording time must be bounded")
        instant = datetime.fromisoformat(self.recorded_at.replace("Z", "+00:00"))
        if instant.tzinfo is None or instant.utcoffset() != timezone.utc.utcoffset(instant):
            raise ValueError("native policy recording time must be UTC")

    def binding(self) -> dict[str, object]:
        return {name: getattr(self, name) for name in _BINDING_FIELDS}

    def to_dict(self) -> dict[str, object]:
        return {
            "schemaVersion": _SCHEMA,
            "nativeDecisionId": self.native_decision_id,
            "recordedAt": self.recorded_at,
            "harness": self.harness,
            "eventName": "PreToolUse",
            "decision": self.decision,
            "policyAction": self.policy_action,
            "observedPolicyAction": self.observed_policy_action,
            "observeMode": self.observe_mode,
            **self.identity.to_dict(),
            "publication": self.identity.publication.to_dict() if self.identity.publication else None,
            "snapshot": self.binding(),
        }

    def matches_receipt(self, receipt: object) -> bool:
        value = validate_native_decision_receipt(receipt)
        if value is None:
            return False
        return all(
            value[name] == expected and type(value[name]) is type(expected)
            for name, expected in {
                "decision_id": self.native_decision_id,
                "harness": self.harness,
                "event_name": "PreToolUse",
                "decision": self.decision,
                "policy_action": self.policy_action,
                "observed_policy_action": self.observed_policy_action,
                "observe_mode": self.observe_mode,
                "policy_generation": self.policy_generation,
                "policy_digest": self.policy_digest,
                "runtime_identity": self.runtime_identity,
            }.items()
        )

    @classmethod
    def from_mapping(cls, value: object) -> NativePolicyDecisionContext | None:
        if not isinstance(value, Mapping) or set(value) != _FIELDS:
            return None
        binding = value.get("snapshot")
        if (
            value["schemaVersion"] != _SCHEMA
            or value["eventName"] != "PreToolUse"
            or not isinstance(binding, Mapping)
            or set(binding) != _BINDING_FIELDS
        ):
            return None
        identity = PolicyRuleIdentity.from_mapping(value)
        publication = PolicyPublicationBinding.from_mapping(value["publication"])
        if identity is None or (value["publication"] is not None and publication is None):
            return None
        try:
            return cls(
                native_decision_id=cast(str, value["nativeDecisionId"]),
                recorded_at=cast(str, value["recordedAt"]),
                harness=cast(str, value["harness"]),
                decision=cast(str, value["decision"]),
                policy_action=cast(GuardAction, value["policyAction"]),
                observed_policy_action=cast(GuardAction | None, value["observedPolicyAction"]),
                observe_mode=cast(bool, value["observeMode"]),
                identity=PolicyRuleIdentity(identity.policy_id, identity.rule_id, identity.policy_version, publication),
                policy_generation=cast(int, binding["policy_generation"]),
                policy_digest=cast(str, binding["policy_digest"]),
                source_input_digest=cast(str, binding["source_input_digest"]),
                runtime_identity=cast(str, binding["runtime_identity"]),
                resident_generation=cast(int, binding["resident_generation"]),
                selected_decision_id=cast(int, binding["selected_decision_id"]),
            )
        except (TypeError, ValueError, OverflowError):
            return None


def safe_native_policy_decision(value: object) -> dict[str, object] | None:
    context = NativePolicyDecisionContext.from_mapping(value)
    return context.to_dict() if context is not None else None


def capture_native_policy_decision(
    *, binding: Mapping[str, object], receipt: object, identity: PolicyRuleIdentity
) -> NativePolicyDecisionContext | None:
    """Call only while the publisher holds its accepted-publication barrier."""
    validated = validate_native_decision_receipt(receipt)
    if validated is None:
        return None
    context = NativePolicyDecisionContext.from_mapping(
        {
            "schemaVersion": _SCHEMA,
            "nativeDecisionId": validated["decision_id"],
            "recordedAt": datetime.now(timezone.utc).isoformat(),
            "harness": validated["harness"],
            "eventName": validated["event_name"],
            "decision": validated["decision"],
            "policyAction": validated["policy_action"],
            "observedPolicyAction": validated["observed_policy_action"],
            "observeMode": validated["observe_mode"],
            **identity.to_dict(),
            "publication": identity.publication.to_dict() if identity.publication else None,
            "snapshot": dict(binding),
        }
    )
    return context if context is not None and context.matches_receipt(validated) else None
