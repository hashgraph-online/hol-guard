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
from ..native_hook_artifact_facts import HookArtifactFactsUnavailableError, native_hook_artifact_facts
from ..protection_events import record_protection_event
from .commands_support_runtime_resolution import _canonical_harness_name


def _runtime_artifact_command_action_floor(artifact: GuardArtifact) -> GuardAction | None:
    if "command_action_floor" not in artifact.metadata:
        return None
    return normalize_guard_action(artifact.metadata.get("command_action_floor"), unknown_action="block")


def artifact_fact_risk_classes(facts: Mapping[str, object]) -> list[str]:
    """The risk classes the resident read off one artifact."""

    classes = facts.get("risk_classes")
    if not isinstance(classes, list) or not all(isinstance(item, str) for item in classes):
        raise HookArtifactFactsUnavailableError
    return cast("list[str]", classes)


def artifact_fact_content_hash(facts: Mapping[str, object]) -> str:
    """The digest the resident hashed the artifact to.

    A saved approval is keyed by this value, so a missing or empty answer is
    no answer: the hook fails closed rather than keying a decision by a digest
    this side computed.
    """

    digest = facts.get("content_sha256")
    if not isinstance(digest, str) or not digest:
        raise HookArtifactFactsUnavailableError
    return digest


def artifact_fact_skip_native_floor(facts: Mapping[str, object]) -> bool:
    """Whether the resident says the native command floor is skipped.

    A missing or non-boolean answer is no answer: the hook fails closed rather
    than guessing whether the floor applies.
    """

    skipped = facts.get("skip_native_floor")
    if not isinstance(skipped, bool):
        raise HookArtifactFactsUnavailableError
    return skipped


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
    hash_metadata: Sequence[Mapping[str, object] | None] | None = None,
) -> list[dict[str, object]]:
    """Return the resident's facts for each ``(artifact, harness)`` pair.

    Only the configured override is still read here: it is a settings lookup
    for this artifact, publisher and harness, not a reading of the artifact.
    Everything the verdict turns on comes from the resident, so an unavailable
    one raises instead of letting this side describe the artifact.

    One evaluation's artifacts are asked for together, so reading facts costs
    the hook a single resident round trip however many artifacts it holds.

    ``hash_metadata`` names, per artifact, the metadata whose digest keys a
    saved approval for it; the resident answers ``content_sha256`` for each
    artifact given one. A hook stamps its runtime posture onto the artifact's
    metadata after fixing that identity, so the identity metadata is passed
    rather than re-read from the artifact here.
    """

    if hash_metadata is not None and len(hash_metadata) != len(artifacts):
        raise ValueError("hash_metadata must name one entry per artifact")
    identity_metadata = tuple(hash_metadata) if hash_metadata is not None else (None,) * len(artifacts)
    entries: list[dict[str, object]] = []
    for (artifact, harness), identity in zip(artifacts, identity_metadata, strict=True):
        entry: dict[str, object] = {
            "artifact_type": artifact.artifact_type,
            "metadata": artifact.metadata,
            "configured_override": _typed_text(
                config.resolve_action_override(
                    _canonical_harness_name(harness), artifact.artifact_id, artifact.publisher
                )
            ),
        }
        if identity is not None:
            # The digest is taken over the artifact's identity, so the fields
            # it covers ride along only for the caller that asked for one.
            entry.update(
                {
                    "artifact_id": artifact.artifact_id,
                    "name": artifact.name,
                    "harness": artifact.harness,
                    "source_scope": artifact.source_scope,
                    "config_path": artifact.config_path,
                    "command": artifact.command,
                    "args": list(artifact.args),
                    "url": artifact.url,
                    "transport": artifact.transport,
                    "publisher": artifact.publisher,
                    "hash_metadata": identity,
                }
            )
        entries.append(entry)
    return native_hook_artifact_facts(
        entries,
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
