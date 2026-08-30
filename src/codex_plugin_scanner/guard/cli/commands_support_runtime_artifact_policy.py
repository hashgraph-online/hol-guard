"""Runtime artifact policy composition for catalog permissions and risk floors."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from ..action_lattice import coerce_guard_action, most_restrictive_guard_action, normalize_guard_action
from ..config import GuardConfig, resolve_risk_action
from ..models import GuardAction, GuardArtifact
from ..policy.engine import SAFE_CHANGED_HASH_ACTION
from .commands_support_prompts import _prompt_requires_hard_block
from .commands_support_runtime_resolution import _canonical_harness_name


def _resolve_harness_risk_action(config: GuardConfig, risk_class: str, *, harness: str) -> str | None:
    if config.harness_risk_actions is None:
        return None
    harness_actions = config.harness_risk_actions.get(harness)
    if harness_actions is not None and risk_class in harness_actions:
        return harness_actions[risk_class]
    return None


def _resolve_configured_risk_action(config: GuardConfig, risk_class: str, *, harness: str) -> str | None:
    harness_action = _resolve_harness_risk_action(config, risk_class, harness=harness)
    if harness_action is not None:
        return harness_action
    if config.risk_actions is not None and risk_class in config.risk_actions:
        return config.risk_actions[risk_class]
    return None


def _runtime_artifact_guard_default_action(artifact: GuardArtifact) -> GuardAction | None:
    value = artifact.metadata.get("guard_default_action")
    return normalize_guard_action(value, unknown_action="require-reapproval") if value is not None else None


def _runtime_artifact_command_action_floor(artifact: GuardArtifact) -> GuardAction | None:
    if "command_action_floor" not in artifact.metadata:
        return None
    return normalize_guard_action(artifact.metadata.get("command_action_floor"), unknown_action="block")


def _runtime_artifact_has_explicit_permission_allow(artifact: GuardArtifact) -> bool:
    if _runtime_artifact_command_action_floor(artifact) != "allow":
        return False
    resolution = artifact.metadata.get("extension_control_resolution")
    if not isinstance(resolution, Mapping) or resolution.get("blocked") is not False:
        return False
    permission_ids = resolution.get("explicitly_enabled_permission_ids")
    if (
        not isinstance(permission_ids, Sequence)
        or isinstance(permission_ids, str)
        or not permission_ids
        or any(not isinstance(item, str) or not item.startswith("command.") for item in permission_ids)
    ):
        return False
    decision = artifact.metadata.get("command_decision_plane")
    if not isinstance(decision, Mapping) or decision.get("action") != "allow":
        return False
    routes = decision.get("proof_routes")
    reasons = decision.get("controlling_reasons")
    return (
        isinstance(routes, Sequence)
        and not isinstance(routes, str)
        and "verified" in routes
        and isinstance(reasons, Sequence)
        and not isinstance(reasons, str)
        and any(
            isinstance(reason, Mapping)
            and reason.get("source") == "control"
            and reason.get("reason_code") == "control.explicitly-enabled-permission"
            for reason in reasons
        )
    )


def _runtime_artifact_policy_action(config: GuardConfig, artifact: GuardArtifact, harness: str) -> GuardAction:
    from .commands_support_runtime_policy import _apply_explicit_posture_action, _runtime_artifact_risk_classes

    if _prompt_requires_hard_block(artifact):
        return "block"
    canonical_harness = _canonical_harness_name(harness)
    configured_override = config.resolve_action_override(
        canonical_harness,
        artifact.artifact_id,
        artifact.publisher,
    )
    command_action_floor = _runtime_artifact_command_action_floor(artifact)
    explicit_permission_allow = _runtime_artifact_has_explicit_permission_allow(artifact)
    pytest_restricted_sandbox = (
        artifact.metadata.get("action_class") == "pytest repository-code execution"
        and artifact.metadata.get("reason_code") == "pytest_restricted_profile_required"
        and isinstance(artifact.metadata.get("restricted_profile_version"), str)
    )

    def with_config_policy(action: GuardAction) -> GuardAction:
        # Artifact/publisher/harness settings are more-specific than the global
        # default. An explicitly enabled catalog permission already accepted the
        # command's cataloged risks, so global risk_actions must not re-raise them.
        current_config_action = (
            configured_override
            if configured_override is not None
            else ("allow" if explicit_permission_allow else config.default_action)
        )
        effective_command_floor = (
            None
            if action == "sandbox-required" and pytest_restricted_sandbox
            else command_action_floor
        )
        actions = (action, current_config_action, effective_command_floor)
        return most_restrictive_guard_action(*(item for item in actions if item is not None))

    risk_classes = _runtime_artifact_risk_classes(artifact)
    if explicit_permission_allow:
        harness_risk_actions: list[GuardAction] = []
        for risk_class in risk_classes:
            harness_action = _resolve_harness_risk_action(config, risk_class, harness=canonical_harness)
            if harness_action is None:
                continue
            applied = _apply_explicit_posture_action(config, artifact, risk_class, harness_action)
            if coerce_guard_action(applied) is not None:
                harness_risk_actions.append(applied)
        if harness_risk_actions:
            return with_config_policy(most_restrictive_guard_action(*harness_risk_actions))
        return with_config_policy(command_action_floor or "allow")
    has_configured_risk_action = any(
        _resolve_configured_risk_action(config, risk_class, harness=canonical_harness) for risk_class in risk_classes
    )
    if has_configured_risk_action:
        risk_actions = [
            _resolve_configured_risk_action(config, risk_class, harness=canonical_harness)
            or resolve_risk_action(config, risk_class, harness=canonical_harness)
            for risk_class in risk_classes
        ]
        resolved_actions = [
            _apply_explicit_posture_action(config, artifact, risk_class, action)
            for risk_class, action in zip(risk_classes, risk_actions, strict=True)
            if coerce_guard_action(action) is not None
        ]
        if resolved_actions:
            return with_config_policy(most_restrictive_guard_action(*resolved_actions))
    guard_default_action = _runtime_artifact_guard_default_action(artifact)
    if guard_default_action == "sandbox-required" and pytest_restricted_sandbox:
        return with_config_policy(guard_default_action)
    risk_actions = [resolve_risk_action(config, risk_class, harness=canonical_harness) for risk_class in risk_classes]
    resolved_actions = [
        _apply_explicit_posture_action(config, artifact, risk_class, action)
        for risk_class, action in zip(risk_classes, risk_actions, strict=True)
        if coerce_guard_action(action) is not None
    ]
    if resolved_actions:
        resolved = most_restrictive_guard_action(*resolved_actions)
        resolved_with_default = (
            most_restrictive_guard_action(resolved, guard_default_action)
            if guard_default_action is not None
            else resolved
        )
        return with_config_policy(resolved_with_default)
    if guard_default_action is not None:
        return with_config_policy(guard_default_action)
    return with_config_policy(SAFE_CHANGED_HASH_ACTION)
