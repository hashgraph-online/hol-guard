"""Guard policy evaluation helpers."""

from __future__ import annotations

from ..config import GuardConfig
from ..models import GuardAction

VALID_GUARD_ACTIONS = {"allow", "warn", "review", "block", "require-reapproval"}
SAFE_CHANGED_HASH_ACTION: GuardAction = "require-reapproval"
SAFE_DEFAULT_ACTION: GuardAction = "require-reapproval"


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
