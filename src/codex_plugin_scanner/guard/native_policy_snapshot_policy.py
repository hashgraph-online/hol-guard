"""Scope identity and store-sourced action helpers for native policy snapshots.

The effective policy itself is derived and composed by the native runtime; see
``native_policy_effective``.
"""

from __future__ import annotations

import hashlib
import os
from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING

from .native_policy_snapshot_codec import _valid_bounded_string_v3
from .native_policy_snapshot_constants import (
    _ACTION_SEVERITY,
    _VALID_ACTIONS,
    POLICY_SNAPSHOT_MAX_MAP_ENTRIES,
    POLICY_SNAPSHOT_MAX_MCP_TOOL_ACTIONS,
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


def _string_map(value: object, *, max_entries: int = POLICY_SNAPSHOT_MAX_MAP_ENTRIES) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, Mapping) or len(value) > max_entries:
        raise NativePolicySnapshotError("native_policy_snapshot_policy_invalid")
    result: dict[str, str] = {}
    for key, action in value.items():
        if not _valid_bounded_string_v3(key) or not isinstance(action, str) or action not in _VALID_ACTIONS:
            raise NativePolicySnapshotError("native_policy_snapshot_policy_invalid")
        assert isinstance(key, str)
        result[key] = action
    return result


def _provider_action_map(value: object) -> dict[str, str]:
    from .runtime.mcp_provider_permissions import valid_provider_action_selector

    actions = _string_map(value, max_entries=POLICY_SNAPSHOT_MAX_MCP_TOOL_ACTIONS)
    if any(
        action not in {"review", "block"} or not valid_provider_action_selector(key) for key, action in actions.items()
    ):
        raise NativePolicySnapshotError("native_policy_snapshot_provider_actions_invalid")
    return actions


def _stricter_action(left: object, right: object) -> str:
    if not isinstance(left, str) or left not in _ACTION_SEVERITY:
        raise NativePolicySnapshotError("native_policy_snapshot_policy_invalid")
    if not isinstance(right, str) or right not in _ACTION_SEVERITY:
        raise NativePolicySnapshotError("native_policy_snapshot_policy_invalid")
    return left if _ACTION_SEVERITY[left] >= _ACTION_SEVERITY[right] else right
