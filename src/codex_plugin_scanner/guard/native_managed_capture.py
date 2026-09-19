"""Preserve loaded configuration origins at off-path publication boundaries."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
from typing import TYPE_CHECKING

from .native_managed_configuration import (
    MANAGED_CONFIGURATION_INPUT_KEY,
    NativeManagedConfiguration,
    project_managed_configuration,
)
from .native_policy_snapshot_codec import _digest_v3
from .native_policy_snapshot_constants import NativePolicySnapshotError
from .native_policy_snapshot_policy import _merge_effective_native_policies, effective_native_policy_v3

if TYPE_CHECKING:
    from .config import GuardConfig
    from .native_policy_authority_read import NativeVerifiedPolicyInputs


def configuration_origin(config: GuardConfig | Mapping[str, object]) -> NativeManagedConfiguration | None:
    if isinstance(config, Mapping):
        return (
            NativeManagedConfiguration.from_mapping(config[MANAGED_CONFIGURATION_INPUT_KEY])
            if MANAGED_CONFIGURATION_INPUT_KEY in config
            else None
        )
    return project_managed_configuration(config)


def compile_configuration_origins(configs: tuple[GuardConfig, ...]) -> dict[str, object]:
    if not configs:
        raise NativePolicySnapshotError("native_policy_snapshot_policy_invalid")
    origins = tuple(project_managed_configuration(config) for config in configs)
    if any(origin != origins[0] for origin in origins):
        raise NativePolicySnapshotError("native_policy_managed_configuration_source_mismatch")
    policies: list[dict[str, object]] = []
    for config, origin in zip(configs, origins, strict=True):
        if origin is not None and config.local_policy_origin is None:
            raise NativePolicySnapshotError("native_policy_local_configuration_origin_missing")
        local = config.local_policy_origin if origin is not None else config
        assert local is not None
        policy = effective_native_policy_v3(local)
        # Keep the composed non-action settings. Only selectors and actions
        # require independent origins; copying the local privacy/sandbox fields
        # here would discard stronger managed settings already loaded.
        composed = effective_native_policy_v3(config)
        for field in ("protection_posture", "security_level", "sandbox_analysis", "receipt_redaction_level"):
            policy[field] = composed[field]
        policies.append(policy | {"mode": config.mode})
    compiled = _merge_effective_native_policies(tuple(policies))
    if origins[0] is not None:
        if compiled["mode"] != origins[0].mode:
            raise NativePolicySnapshotError("native_policy_managed_configuration_mode_mismatch")
        compiled[MANAGED_CONFIGURATION_INPUT_KEY] = origins[0].to_mapping()
    return compiled


def bind_configuration_origin(
    config: Mapping[str, object], inputs: NativeVerifiedPolicyInputs
) -> NativeVerifiedPolicyInputs:
    origin = configuration_origin(config)
    if origin is None:
        return inputs
    return replace(
        inputs,
        authority=replace(inputs.authority, managed_config=origin),
        input_digest=_digest_v3({"base_input_digest": inputs.input_digest, "managed_config": origin.to_mapping()}),
    )
