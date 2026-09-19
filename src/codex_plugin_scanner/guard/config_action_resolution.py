"""Resolve local selectors without allowing them to erase managed requirements."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING

from .action_lattice import most_restrictive_guard_action, normalize_guard_action
from .models import GuardAction

if TYPE_CHECKING:
    from .config import GuardConfig


def _join_optional(*actions: GuardAction | None) -> GuardAction | None:
    present = tuple(action for action in actions if action is not None)
    return most_restrictive_guard_action(*present) if present else None


def _managed_value(settings: Mapping[str, object], key: str) -> GuardAction | None:
    if key not in settings:
        return None
    value = settings[key]
    if isinstance(value, Mapping):
        value = value.get("action", value.get("default_action", value))
    return normalize_guard_action(value, unknown_action="block")


def _managed_selector(settings: Mapping[str, object], key: str, selector: str | None) -> GuardAction | None:
    if key not in settings or selector is None:
        return None
    values = settings[key]
    if not isinstance(values, Mapping):
        return "block"
    return _managed_value(values, selector)


def managed_configured_action(
    config: GuardConfig, harness: str, artifact_id: str | None, publisher: str | None
) -> GuardAction | None:
    """Preserve precedence within the managed source, separately from local overrides."""
    if config.managed_policy is None:
        return None
    settings = config.managed_policy.settings
    for key, selector in (("artifacts", artifact_id), ("publishers", publisher), ("harnesses", harness)):
        action = _managed_selector(settings, key, selector)
        if action is not None:
            return action
    return _managed_value(settings, "default_action")


def managed_risk_action(config: GuardConfig, risk_class: str, harness: str | None) -> GuardAction | None:
    if config.managed_policy is None:
        return None
    settings = config.managed_policy.settings
    if "harness_risk_actions" in settings and harness is not None:
        harnesses = settings["harness_risk_actions"]
        if not isinstance(harnesses, Mapping):
            return "block"
        if harness in harnesses:
            actions = harnesses[harness]
            if not isinstance(actions, Mapping):
                return "block"
            selected = _managed_value(actions, risk_class)
            if selected is not None:
                return selected
    selected = _managed_selector(settings, "risk_actions", risk_class)
    if selected is not None:
        return selected
    # Only explicitly managed posture/level settings establish these defaults.
    # An otherwise empty managed profile does not invent a separate policy.
    if "protection_posture" in settings and "security_level" not in config.managed_locked_settings:
        from .protection_posture import resolve_posture_defaults

        posture = settings["protection_posture"]
        defaults = resolve_posture_defaults(posture) if isinstance(posture, str) else None
        return defaults.get(risk_class) if defaults is not None else "block"
    if "security_level" in settings:
        from .config import SECURITY_LEVEL_RISK_ACTIONS

        level = settings["security_level"]
        defaults = SECURITY_LEVEL_RISK_ACTIONS.get(level) if isinstance(level, str) else None
        return defaults.get(risk_class) if defaults is not None else "block"
    return None


def resolve_artifact_or_publisher_action(
    config: GuardConfig, artifact_id: str | None, publisher: str | None
) -> GuardAction | None:
    if artifact_id is not None and config.artifact_actions is not None and artifact_id in config.artifact_actions:
        return config.artifact_actions[artifact_id]
    if publisher is not None and config.publisher_actions is not None and publisher in config.publisher_actions:
        return config.publisher_actions[publisher]
    return None


def _selected_action(
    config: GuardConfig, harness: str, artifact_id: str | None, publisher: str | None
) -> GuardAction | None:
    action = resolve_artifact_or_publisher_action(config, artifact_id, publisher)
    if action is None and config.harness_actions is not None:
        action = config.harness_actions.get(harness)
    return action


def resolve_configured_action(
    config: GuardConfig, harness: str, artifact_id: str | None, publisher: str | None
) -> GuardAction | None:
    # Retain later authenticated runtime overlays as well as both loaded origins.
    current = _selected_action(config, harness, artifact_id, publisher)
    managed = managed_configured_action(config, harness, artifact_id, publisher)
    local = None
    if config.local_policy_origin is not None:
        local = _selected_action(config.local_policy_origin, harness, artifact_id, publisher)
        if local is None and managed is not None:
            local = config.local_policy_origin.default_action
    return _join_optional(current, local, managed)


def _selected_risk(config: GuardConfig, risk_class: str, harness: str | None) -> GuardAction | None:
    action: GuardAction | None = None
    if harness is not None and config.harness_risk_actions is not None:
        action = config.harness_risk_actions.get(harness, {}).get(risk_class)
    if action is None and config.risk_actions is not None:
        action = config.risk_actions.get(risk_class)
    return action


def resolve_configured_risk_action(config: GuardConfig, risk_class: str, *, harness: str | None) -> GuardAction | None:
    current = _selected_risk(config, risk_class, harness)
    managed = managed_risk_action(config, risk_class, harness)
    local = None
    if config.local_policy_origin is not None:
        local = _selected_risk(config.local_policy_origin, risk_class, harness)
        if local is None and managed is not None:
            from .config import _posture_or_level_defaults

            local = _posture_or_level_defaults(config.local_policy_origin).get(risk_class)
    return _join_optional(current, local, managed)


def managed_runtime_floor(
    config: GuardConfig,
    *,
    harness: str,
    artifact_id: str,
    publisher: str | None,
    risk_classes: Sequence[str],
) -> GuardAction | None:
    """Catalog permission grants cannot suppress a separate managed origin."""
    actions: list[GuardAction | None] = [managed_risk_action(config, risk, harness) for risk in risk_classes]
    actions.append(managed_configured_action(config, harness, artifact_id, publisher))
    return _join_optional(*actions)
