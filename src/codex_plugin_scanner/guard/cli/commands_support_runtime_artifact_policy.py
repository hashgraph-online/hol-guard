"""Runtime artifact policy facts for the native configured-policy action.

The resident owns the verdict. This module projects the guard config, ships
the artifact for the resident to read its own facts from, and records the
protection events the answer returns.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import cast

from ..action_lattice import normalize_guard_action
from ..config import GuardConfig
from ..harness_posture import harness_posture_override
from ..models import GuardAction, GuardArtifact
from ..native_hook_artifact_compose import native_hook_compose
from ..native_hook_artifact_facts import native_hook_artifact_facts
from ..protection_events import record_protection_event
from .commands_support_runtime_resolution import _canonical_harness_name


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


def _typed_text(value: object) -> str | None:
    # A non-string setting normalizes to the unknown action natively, as it did here.
    return value if value is None or isinstance(value, str) else ""


def runtime_policy_config_facts(config: GuardConfig, harness: str) -> dict[str, object]:
    canonical_harness = _canonical_harness_name(harness)
    return {
        "default_action": config.default_action,
        "risk_actions": dict(config.risk_actions or {}),
        "harness_risk_actions": {name: dict(actions) for name, actions in (config.harness_risk_actions or {}).items()},
        "security_level": config.security_level,
        "protection_posture": config.protection_posture,
        "protection_posture_explicit": bool(config.protection_posture_explicit),
        "managed_locks_level": "security_level" in config.managed_locked_settings,
        "harness": canonical_harness,
        "harness_posture_override": harness_posture_override(config, canonical_harness),
    }


def runtime_policy_artifact_facts(
    config: GuardConfig,
    artifact: GuardArtifact,
    harness: str,
    *,
    guard_home: Path | None = None,
) -> dict[str, object]:
    """Return the resident's facts for ``artifact``."""

    return runtime_policy_artifact_facts_batch(config, ((artifact, harness),), guard_home=guard_home)[0]


def runtime_policy_artifact_facts_batch(
    config: GuardConfig,
    artifacts: Sequence[tuple[GuardArtifact, str]],
    *,
    guard_home: Path | None = None,
) -> list[dict[str, object]]:
    """Return the resident's facts for each ``(artifact, harness)`` pair.

    Only the configured override is still read here: it is a settings lookup
    for this artifact, publisher and harness, not a reading of the artifact.
    Everything the verdict turns on comes from the resident, so an unavailable
    one raises instead of letting this side describe the artifact.

    One evaluation's artifacts are asked for together, so reading facts costs
    the hook a single resident round trip however many artifacts it holds.
    """

    return native_hook_artifact_facts(
        [
            {
                "artifact_type": artifact.artifact_type,
                "metadata": artifact.metadata,
                "configured_override": _typed_text(
                    config.resolve_action_override(
                        _canonical_harness_name(harness), artifact.artifact_id, artifact.publisher
                    )
                ),
            }
            for artifact, harness in artifacts
        ],
        guard_home=guard_home if guard_home is not None else config.guard_home,
    )


def record_policy_auto_stops(config: GuardConfig, events: object) -> None:
    for event in cast("list[dict[str, object]]", events):
        record_protection_event(config.guard_home, "guard.protection.auto_stop", event)


def _runtime_artifact_policy_action(
    config: GuardConfig,
    artifact: GuardArtifact,
    harness: str,
    *,
    guard_home: Path | None = None,
) -> GuardAction:
    answer = native_hook_compose(
        "config_action",
        {
            "policy_config": runtime_policy_config_facts(config, harness),
            "artifact": runtime_policy_artifact_facts(config, artifact, harness, guard_home=guard_home),
        },
        guard_home=guard_home,
    )
    record_policy_auto_stops(config, answer["auto_stop_events"])
    return cast(GuardAction, answer["action"])
