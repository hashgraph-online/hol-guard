"""Guard policy evaluation helpers."""

from __future__ import annotations

from collections.abc import Sequence

from ..action_lattice import guard_action_severity as guard_action_severity
from ..action_lattice import normalize_guard_action
from ..config import GuardConfig
from ..models import GUARD_ACTION_VALUES, GuardAction
from ..runtime.decisions import GuardDecisionV2, decision_from_legacy_policy_action
from ..runtime.signals import RiskSignalV2

VALID_GUARD_ACTIONS = frozenset(GUARD_ACTION_VALUES)
SAFE_CHANGED_HASH_ACTION: GuardAction = "require-reapproval"
SAFE_DEFAULT_ACTION: GuardAction = "require-reapproval"


def decide_action(
    configured_action: str | None,
    default_action: str | None,
    config: GuardConfig,
    changed: bool,
) -> GuardAction:
    """Resolve the effective policy action."""

    if configured_action is not None:
        return normalize_guard_action(configured_action, unknown_action=SAFE_DEFAULT_ACTION)
    if changed:
        return normalize_guard_action(
            config.changed_hash_action,
            unknown_action=SAFE_CHANGED_HASH_ACTION,
        )
    if default_action is not None:
        return normalize_guard_action(default_action, unknown_action=SAFE_DEFAULT_ACTION)
    return normalize_guard_action(
        config.default_action,
        unknown_action=SAFE_DEFAULT_ACTION,
    )


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
