"""Effective native policy normalization and conservative composition."""

from __future__ import annotations

import hashlib
import os
from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING, cast

from .native_policy_snapshot_codec import (
    _normalized_harness_selector_v3,
    _valid_bounded_string_v3,
    _valid_selector_key_v3,
)
from .native_policy_snapshot_constants import (
    _ACTION_SEVERITY,
    _POSTURE_SEVERITY,
    _REDACTION_SEVERITY,
    _SANDBOX_SEVERITY,
    _SECURITY_LEVEL_SEVERITY,
    _VALID_ACTIONS,
    _VALID_POSTURES,
    _VALID_REDACTION_LEVELS,
    _VALID_RISK_ACTION_KEYS,
    _VALID_SANDBOX_ANALYSIS,
    _VALID_SECURITY_LEVELS,
    POLICY_SNAPSHOT_MAX_HARNESS_ENTRIES,
    POLICY_SNAPSHOT_MAX_MAP_ENTRIES,
    NativePolicySnapshotError,
)

if TYPE_CHECKING:
    from .config import GuardConfig


def _normalize_scope_text_v3(value: str) -> str:
    """Canonicalize a guard-home identity across Windows path aliases."""
    if os.name == "nt":
        normalized = value.replace("/", "\\")
        folded = normalized.casefold()
        if folded.startswith("\\\\?\\unc\\"):
            normalized = "\\\\" + normalized[8:]
        elif folded.startswith("\\\\?\\"):
            normalized = normalized[4:]
        while len(normalized) > 3 and normalized.endswith("\\"):
            normalized = normalized[:-1]
        return normalized.casefold()
    if value.startswith("/private/"):
        return value[len("/private") :]
    return value


def _scope_digest_v3(guard_home: Path) -> str:
    try:
        canonical = str(guard_home.expanduser().resolve(strict=False))
    except (OSError, RuntimeError, ValueError):
        canonical = str(guard_home)
    canonical = _normalize_scope_text_v3(canonical)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _config_value(config: GuardConfig | Mapping[str, object], name: str, default: object = None) -> object:
    if isinstance(config, Mapping):
        return config.get(name, default)
    return getattr(config, name, default)


def _action_value(config: GuardConfig | Mapping[str, object], name: str, default: str) -> str:
    value = _config_value(config, name, default)
    if not isinstance(value, str) or value not in _VALID_ACTIONS:
        raise NativePolicySnapshotError("native_policy_snapshot_policy_invalid")
    return value


def _string_map(value: object, *, risk_keys: bool = False, selector_keys: bool = False) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, Mapping) or len(value) > POLICY_SNAPSHOT_MAX_MAP_ENTRIES:
        raise NativePolicySnapshotError("native_policy_snapshot_policy_invalid")
    result: dict[str, str] = {}
    for key, action in value.items():
        if (
            not _valid_bounded_string_v3(key)
            or (selector_keys and not _valid_selector_key_v3(key))
            or (risk_keys and key not in _VALID_RISK_ACTION_KEYS)
            or not isinstance(action, str)
            or action not in _VALID_ACTIONS
        ):
            raise NativePolicySnapshotError("native_policy_snapshot_policy_invalid")
        assert isinstance(key, str)
        result[key] = action
    return result


def _harness_risk_map(value: object) -> dict[str, dict[str, str]]:
    if value is None:
        return {}
    if not isinstance(value, Mapping) or len(value) > POLICY_SNAPSHOT_MAX_HARNESS_ENTRIES:
        raise NativePolicySnapshotError("native_policy_snapshot_policy_invalid")
    result: dict[str, dict[str, str]] = {}
    for harness, actions in value.items():
        if not _valid_selector_key_v3(harness):
            raise NativePolicySnapshotError("native_policy_snapshot_policy_invalid")
        assert isinstance(harness, str)
        canonical = _normalized_harness_selector_v3(harness)
        if canonical is None:
            raise NativePolicySnapshotError("native_policy_snapshot_policy_invalid")
        current = _string_map(actions, risk_keys=True)
        previous = next(
            (existing for key, existing in result.items() if _normalized_harness_selector_v3(key) == canonical),
            None,
        )
        if previous is not None and previous != current:
            raise NativePolicySnapshotError("native_policy_snapshot_policy_invalid")
        result[harness] = current
    return result


def _harness_action_map(value: object) -> dict[str, str]:
    result = _string_map(value, selector_keys=True)
    canonical: dict[str, str] = {}
    for key, action in result.items():
        normalized = _normalized_harness_selector_v3(key)
        if normalized is None:
            raise NativePolicySnapshotError("native_policy_snapshot_policy_invalid")
        previous = canonical.get(normalized)
        if previous is not None and previous != action:
            raise NativePolicySnapshotError("native_policy_snapshot_policy_invalid")
        canonical[normalized] = action
    return result


def effective_native_policy_v3(config: GuardConfig | Mapping[str, object]) -> dict[str, object]:
    """Build the bounded effective policy consumed by native hook decisions."""

    risk_value: object = _config_value(config, "risk_actions")
    if not isinstance(config, Mapping):
        # The posture/level defaults are enforcement inputs even when no TOML
        # risk_actions override exists. Keep this import lazy to avoid a
        # config/native-runtime import cycle during ordinary hook startup.
        from .config import _effective_risk_actions

        risk_value = _effective_risk_actions(config)
    else:
        risk_value = risk_value or {}
    posture = _config_value(config, "protection_posture", "protected")
    security_level = _config_value(config, "security_level", "balanced")
    sandbox_analysis = _config_value(config, "sandbox_analysis", "off")
    redaction_level = _config_value(config, "receipt_redaction_level", "full")
    if (
        not isinstance(posture, str)
        or posture not in _VALID_POSTURES
        or not isinstance(security_level, str)
        or security_level not in _VALID_SECURITY_LEVELS
        or not isinstance(sandbox_analysis, str)
        or sandbox_analysis not in _VALID_SANDBOX_ANALYSIS
        or not isinstance(redaction_level, str)
        or redaction_level not in _VALID_REDACTION_LEVELS
    ):
        raise NativePolicySnapshotError("native_policy_snapshot_policy_invalid")
    return {
        "protection_posture": posture,
        "security_level": security_level,
        "default_action": _action_value(config, "default_action", "warn"),
        "unknown_publisher_action": _action_value(config, "unknown_publisher_action", "review"),
        "changed_hash_action": _action_value(config, "changed_hash_action", "require-reapproval"),
        "new_network_domain_action": _action_value(config, "new_network_domain_action", "warn"),
        "subprocess_action": _action_value(config, "subprocess_action", "warn"),
        "risk_actions": _string_map(risk_value, risk_keys=True),
        "harness_risk_actions": _harness_risk_map(_config_value(config, "harness_risk_actions")),
        "harness_actions": _harness_action_map(_config_value(config, "harness_actions")),
        "publisher_actions": _string_map(_config_value(config, "publisher_actions")),
        "artifact_actions": _string_map(_config_value(config, "artifact_actions")),
        "sandbox_analysis": sandbox_analysis,
        "receipt_redaction_level": redaction_level,
    }


def _stricter_action(left: object, right: object) -> str:
    if not isinstance(left, str) or left not in _ACTION_SEVERITY:
        raise NativePolicySnapshotError("native_policy_snapshot_policy_invalid")
    if not isinstance(right, str) or right not in _ACTION_SEVERITY:
        raise NativePolicySnapshotError("native_policy_snapshot_policy_invalid")
    return left if _ACTION_SEVERITY[left] >= _ACTION_SEVERITY[right] else right


_SCALAR_ACTION_FIELDS = (
    "default_action",
    "unknown_publisher_action",
    "changed_hash_action",
    "new_network_domain_action",
    "subprocess_action",
)
_MAP_FIELDS = ("risk_actions", "publisher_actions", "artifact_actions")


def _merge_scalar_actions(
    policies: tuple[Mapping[str, object], ...],
    merged: dict[str, object],
) -> None:
    for field in _SCALAR_ACTION_FIELDS:
        value = policies[0].get(field)
        for policy in policies[1:]:
            value = _stricter_action(value, policy.get(field))
        merged[field] = value


def _merge_action_maps(
    policies: tuple[Mapping[str, object], ...],
    merged: dict[str, object],
) -> None:
    for field in _MAP_FIELDS:
        values: dict[str, str] = {}
        for policy in policies:
            mapping = policy.get(field)
            if not isinstance(mapping, Mapping):
                raise NativePolicySnapshotError("native_policy_snapshot_policy_invalid")
            for key, action in mapping.items():
                if not isinstance(key, str):
                    raise NativePolicySnapshotError("native_policy_snapshot_policy_invalid")
                values[key] = _stricter_action(values.get(key, "allow"), action)
        merged[field] = values


def _merge_harness_actions(
    policies: tuple[Mapping[str, object], ...],
) -> dict[str, str]:
    actions_by_selector: dict[str, str] = {}
    aliases_by_selector: dict[str, list[str]] = {}
    for policy in policies:
        mapping = policy.get("harness_actions")
        if not isinstance(mapping, Mapping):
            raise NativePolicySnapshotError("native_policy_snapshot_policy_invalid")
        for harness, action in mapping.items():
            if not isinstance(harness, str):
                raise NativePolicySnapshotError("native_policy_snapshot_policy_invalid")
            selector = _normalized_harness_selector_v3(harness)
            if selector is None:
                raise NativePolicySnapshotError("native_policy_snapshot_policy_invalid")
            actions_by_selector[selector] = _stricter_action(actions_by_selector.get(selector, "allow"), action)
            aliases = aliases_by_selector.setdefault(selector, [])
            if harness not in aliases:
                aliases.append(harness)
    return {
        alias: actions_by_selector[selector] for selector, aliases in aliases_by_selector.items() for alias in aliases
    }


def _merge_harness_risk_actions(
    policies: tuple[Mapping[str, object], ...],
) -> dict[str, dict[str, str]]:
    actions_by_selector: dict[str, dict[str, str]] = {}
    aliases_by_selector: dict[str, list[str]] = {}
    for policy in policies:
        mapping = policy.get("harness_risk_actions")
        if not isinstance(mapping, Mapping):
            raise NativePolicySnapshotError("native_policy_snapshot_policy_invalid")
        for harness, risk_actions in mapping.items():
            if not isinstance(harness, str) or not isinstance(risk_actions, Mapping):
                raise NativePolicySnapshotError("native_policy_snapshot_policy_invalid")
            selector = _normalized_harness_selector_v3(harness)
            if selector is None:
                raise NativePolicySnapshotError("native_policy_snapshot_policy_invalid")
            target = actions_by_selector.setdefault(selector, {})
            aliases = aliases_by_selector.setdefault(selector, [])
            if harness not in aliases:
                aliases.append(harness)
            for risk_class, action in risk_actions.items():
                if not isinstance(risk_class, str):
                    raise NativePolicySnapshotError("native_policy_snapshot_policy_invalid")
                target[risk_class] = _stricter_action(target.get(risk_class, "allow"), action)
    return {
        alias: dict(actions_by_selector[selector])
        for selector, aliases in aliases_by_selector.items()
        for alias in aliases
    }


def _merge_named_floor(
    policies: tuple[Mapping[str, object], ...],
    merged: dict[str, object],
    field: str,
    severity: Mapping[str, int],
) -> None:
    values = [policy.get(field) for policy in policies]
    if not all(isinstance(value, str) and value in severity for value in values):
        raise NativePolicySnapshotError("native_policy_snapshot_policy_invalid")
    typed_values = cast(list[str], values)
    merged[field] = max(typed_values, key=lambda value: severity[value])


def _merge_effective_native_policies(
    policies: tuple[Mapping[str, object], ...],
) -> dict[str, object]:
    """Compile home, workspace, and managed overlays into one native policy.

    A resident has one authenticated snapshot per Guard home. When more than
    one workspace is observed, composing selector maps by the lattice maximum
    gives every workspace the strongest effective floor without placing a raw
    workspace path or a Python decision in the native request. MDM overlays
    are already applied by ``load_guard_config`` before this compiler runs.
    """

    if not policies:
        raise NativePolicySnapshotError("native_policy_snapshot_policy_invalid")
    merged = dict(policies[0])
    _merge_scalar_actions(policies, merged)
    _merge_action_maps(policies, merged)
    merged["harness_actions"] = _merge_harness_actions(policies)
    merged["harness_risk_actions"] = _merge_harness_risk_actions(policies)
    _merge_named_floor(policies, merged, "protection_posture", _POSTURE_SEVERITY)
    _merge_named_floor(policies, merged, "security_level", _SECURITY_LEVEL_SEVERITY)
    # Derive mode from the selected posture so an observe-only workspace
    # overlay cannot downgrade a protected or extra-careful home policy.
    merged["mode"] = "observe" if merged["protection_posture"] == "watch" else "enforce"
    _merge_named_floor(policies, merged, "sandbox_analysis", _SANDBOX_SEVERITY)
    _merge_named_floor(policies, merged, "receipt_redaction_level", _REDACTION_SEVERITY)
    return merged
