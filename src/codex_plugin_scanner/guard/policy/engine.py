"""Guard policy evaluation helpers."""

from __future__ import annotations

from ..config import GuardConfig
from ..models import GuardAction


def decide_action(
    configured_action: str | None,
    default_action: str | None,
    config: GuardConfig,
    changed: bool,
) -> GuardAction:
    """Resolve the effective policy action."""

    if configured_action in {"allow", "warn", "review", "block", "require-reapproval"}:
        return configured_action
    if changed:
        return config.changed_hash_action
    if default_action in {"allow", "warn", "review", "block", "require-reapproval"}:
        return default_action
    return config.default_action
