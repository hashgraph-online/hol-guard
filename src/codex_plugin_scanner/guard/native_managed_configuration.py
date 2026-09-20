"""Strict separate-origin MDM input for an explicitly negotiated V4 consumer."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

from .action_lattice import normalize_guard_action
from .config_action_resolution import managed_risk_action
from .native_policy_snapshot_codec import _canonical_json_bytes_v3
from .native_policy_snapshot_constants import (
    _EFFECTIVE_POLICY_FIELDS,
    _VALID_RISK_ACTION_KEYS,
    NativePolicySnapshotError,
)
from .native_policy_snapshot_policy import effective_native_policy_v3

if TYPE_CHECKING:
    from .config import GuardConfig

MANAGED_CONFIGURATION_FEATURE = "policy-managed-config-floor-v1"
MANAGED_CONFIGURATION_SCHEMA = "guard-native-managed-config.v1"
MANAGED_CONFIGURATION_INPUT_KEY = "_managed_config"
_INVALID = "native_policy_managed_configuration_invalid"


@dataclass(frozen=True, slots=True, repr=False)
class NativeManagedConfiguration:
    source_digest: str
    mode: str
    _policy_json: str
    default_action_present: bool

    def __post_init__(self) -> None:
        if (
            type(self.default_action_present) is not bool
            or not isinstance(self.source_digest, str)
            or re.fullmatch("[0-9a-f]{64}", self.source_digest) is None
            or not isinstance(self.mode, str)
            or self.mode not in {"enforce", "observe"}
            or not isinstance(self._policy_json, str)
        ):
            raise NativePolicySnapshotError(_INVALID)
        try:
            if len(self._policy_json.encode("utf-8")) > 128 * 1024:
                raise NativePolicySnapshotError(_INVALID)
            policy: object = json.loads(self._policy_json)
            if not isinstance(policy, dict) or set(policy) != _EFFECTIVE_POLICY_FIELDS:
                raise NativePolicySnapshotError(_INVALID)
            normalized = effective_native_policy_v3(cast(Mapping[str, object], policy))
            if _canonical_json_bytes_v3(normalized).decode() != self._policy_json:
                raise NativePolicySnapshotError(_INVALID)
        except (TypeError, ValueError, UnicodeError) as error:
            raise NativePolicySnapshotError(_INVALID) from error

    @classmethod
    def from_mapping(cls, value: object) -> NativeManagedConfiguration:
        if not isinstance(value, Mapping) or set(value) != {
            "schema",
            "source_digest",
            "mode",
            "effective_policy",
            "default_action_present",
        }:
            raise NativePolicySnapshotError(_INVALID)
        if value["schema"] != MANAGED_CONFIGURATION_SCHEMA:
            raise NativePolicySnapshotError(_INVALID)
        digest, mode = value["source_digest"], value["mode"]
        if not isinstance(digest, str) or not isinstance(mode, str):
            raise NativePolicySnapshotError(_INVALID)
        present = value["default_action_present"]
        if type(present) is not bool:
            raise NativePolicySnapshotError(_INVALID)
        return cls(digest, mode, _canonical_json_bytes_v3(value["effective_policy"]).decode(), present)

    def to_mapping(self) -> dict[str, object]:
        return {
            "schema": MANAGED_CONFIGURATION_SCHEMA,
            "source_digest": self.source_digest,
            "mode": self.mode,
            "effective_policy": json.loads(self._policy_json),
            "default_action_present": self.default_action_present,
        }


def _actions(value: object, *, risks: bool = False) -> dict[str, str]:
    from .config import _action_map_value

    if not isinstance(value, Mapping):
        raise NativePolicySnapshotError(_INVALID)
    result: dict[str, str] = {}
    for key, action in value.items():
        if not isinstance(key, str) or (risks and key not in _VALID_RISK_ACTION_KEYS):
            raise NativePolicySnapshotError(_INVALID)
        result[key] = normalize_guard_action(_action_map_value(action), unknown_action="block")
    return result


def project_managed_configuration(config: GuardConfig) -> NativeManagedConfiguration | None:
    """Preserve managed hierarchy before flattening loses its source identity."""
    policy = config.managed_policy
    if policy is None:
        return None
    settings = policy.settings
    action_fields = (
        "default_action",
        "unknown_publisher_action",
        "changed_hash_action",
        "new_network_domain_action",
        "subprocess_action",
    )
    relevant = {
        *action_fields,
        "risk_actions",
        "harness_risk_actions",
        "harnesses",
        "publishers",
        "artifacts",
        "security_level",
        "protection_posture",
    }
    if not relevant.intersection(settings):
        return None
    harness_risks = settings.get("harness_risk_actions", {})
    if not isinstance(harness_risks, Mapping):
        raise NativePolicySnapshotError(_INVALID)
    # Validate every declared risk before constructing the resolved source map.
    _actions(settings.get("risk_actions", {}), risks=True)
    resolved_harnesses: dict[str, dict[str, str]] = {}
    for harness, values in harness_risks.items():
        if not isinstance(harness, str):
            raise NativePolicySnapshotError(_INVALID)
        resolved_harnesses[harness] = _actions(values, risks=True)
    effective: dict[str, object] = {
        **{
            field: normalize_guard_action(settings.get(field, "allow"), unknown_action="block")
            for field in action_fields
        },
        "protection_posture": "protected",
        "security_level": "custom",
        "risk_actions": {risk: managed_risk_action(config, risk, None) or "allow" for risk in _VALID_RISK_ACTION_KEYS},
        "harness_risk_actions": resolved_harnesses,
        "harness_actions": _actions(settings.get("harnesses", {})),
        "publisher_actions": _actions(settings.get("publishers", {})),
        "artifact_actions": _actions(settings.get("artifacts", {})),
        "sandbox_analysis": "off",
        "receipt_redaction_level": "none",
    }
    # Mode is the actual resolved mode, not a new per-origin mode policy.
    mode = "observe" if config.mode == "observe" or config.protection_posture == "watch" else "enforce"
    return NativeManagedConfiguration(
        policy.content_hash, mode, _canonical_json_bytes_v3(effective).decode(), "default_action" in settings
    )
