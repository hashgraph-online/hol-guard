"""Bounded policy inputs bound into an exact runtime approval context."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .config import GuardConfig


def _current_fields(config: GuardConfig) -> dict[str, object]:
    """Return effective settings that can change enforcement or risk evidence."""

    return {
        "artifact_actions": dict(config.artifact_actions or {}),
        "changed_hash_action": config.changed_hash_action,
        "default_action": config.default_action,
        "harness_actions": dict(config.harness_actions or {}),
        "harness_risk_actions": {
            harness: dict(actions) for harness, actions in (config.harness_risk_actions or {}).items()
        },
        "install_owner": config.install_owner,
        "managed_locked_settings": list(config.managed_locked_settings),
        "managed_policy_hash": config.managed_policy_hash,
        "managed_policy_status": config.managed_policy_status,
        "mode": config.mode,
        **(
            {
                "protection_posture": config.protection_posture,
                "protection_posture_explicit": True,
            }
            if config.protection_posture_explicit
            else {}
        ),
        "new_network_domain_action": config.new_network_domain_action,
        "publisher_actions": dict(config.publisher_actions or {}),
        "risk_actions": dict(config.risk_actions or {}),
        "runtime_detector_disabled_ids": list(config.runtime_detector_disabled_ids),
        "runtime_detector_registry": config.runtime_detector_registry,
        "runtime_detector_timeout_ms": config.runtime_detector_timeout_ms,
        "security_level": config.security_level,
        "subprocess_action": config.subprocess_action,
        "unknown_publisher_action": config.unknown_publisher_action,
    }


def runtime_hook_effective_policy_config(config: GuardConfig) -> dict[str, object]:
    value = _current_fields(config)
    if config.local_policy_origin is not None:
        # One acyclic loaded origin, not recursive dataclass serialization.
        value["local_policy_origin"] = _current_fields(config.local_policy_origin)
    return value
