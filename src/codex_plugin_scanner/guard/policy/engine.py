"""Guard policy evaluation helpers."""

from __future__ import annotations

from collections.abc import Sequence

from ..config import GuardConfig
from ..models import GuardAction
from ..runtime.decisions import GuardDecisionV2, decision_from_legacy_policy_action
from ..runtime.signals import RiskSignalV2

VALID_GUARD_ACTIONS = {"allow", "warn", "review", "block", "sandbox-required", "require-reapproval"}
SAFE_CHANGED_HASH_ACTION: GuardAction = "require-reapproval"
SAFE_DEFAULT_ACTION: GuardAction = "require-reapproval"
_GUARD_ACTION_SEVERITY = {
    "allow": 0,
    "warn": 1,
    "review": 2,
    "require-reapproval": 3,
    "sandbox-required": 4,
    "block": 5,
}


def decide_action(
    configured_action: str | None,
    default_action: str | None,
    config: GuardConfig,
    changed: bool,
) -> GuardAction:
    """Resolve the effective policy action."""

    if configured_action in VALID_GUARD_ACTIONS:
        return configured_action
    if changed:
        if config.changed_hash_action in VALID_GUARD_ACTIONS:
            return config.changed_hash_action
        return SAFE_CHANGED_HASH_ACTION
    if default_action in VALID_GUARD_ACTIONS:
        return default_action
    if config.default_action in VALID_GUARD_ACTIONS:
        return config.default_action
    return SAFE_DEFAULT_ACTION


def build_decision_v2(
    policy_action: GuardAction,
    *,
    reason: str,
    signals: Sequence[RiskSignalV2] = (),
) -> GuardDecisionV2:
    return decision_from_legacy_policy_action(policy_action, reason=reason, signals=signals)


def decide_action_with_v2(
    configured_action: str | None,
    default_action: str | None,
    config: GuardConfig,
    changed: bool,
    *,
    reason: str,
    signals: Sequence[RiskSignalV2] = (),
) -> tuple[GuardAction, GuardDecisionV2]:
    action = decide_action(
        configured_action=configured_action,
        default_action=default_action,
        config=config,
        changed=changed,
    )
    return action, build_decision_v2(action, reason=reason, signals=signals)


def guard_action_severity(action: str) -> int:
    """Return a stable ordering for comparing Guard enforcement actions."""

    return _GUARD_ACTION_SEVERITY.get(action, -1)
