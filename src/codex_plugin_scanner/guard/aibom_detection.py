"""Shared AIBOM artifact discovery facade for Guard inventory.

The native resident owns every discovery rule: instruction and standards
documents, cursor rules, Codex skill inventory and enablement rules, the Codex
marketplace, the detection merge plan and the MCP server digests. This module
only anchors paths, ships typed inputs through ``native_runner_authority`` and
applies the returned plan to the caller's own artifacts. Discovery, merge and
skill inventory fail closed with :class:`NativeAibomError` when the resident
cannot answer.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .models import GuardArtifact, HarnessDetection
from .native_path_anchor import anchor_to_process_directory
from .native_runner_authority import NativeRunnerAuthorityError, native_runner_authority

INVENTORY_ITEM_KINDS: tuple[str, ...] = (
    "agent",
    "daemon_plugin",
    "harness",
    "model_provider",
    "package",
    "prompt_pack",
    "skill",
    "mcp_server",
    "mcp_tool",
    "plugin",
    "channel",
    "hook",
    "overlay",
    "repository",
    "container_image",
    "policy",
    "secret_reference",
    "network_endpoint",
)


class NativeAibomError(ValueError):
    """The native resident could not supply a bound AIBOM discovery answer."""


# Discovery kinds hash instruction documents, walk docs/* and compute skill
# directory identities in one resident call, so they get a wider budget than
# the default launch-path deadline while staying inside the envelope cap.
_AIBOM_DISCOVERY_TIMEOUT_SECONDS = 8.0


def _native(kind: str, args: Mapping[str, Any]) -> dict[str, Any]:
    try:
        return native_runner_authority(kind, args, timeout_seconds=_AIBOM_DISCOVERY_TIMEOUT_SECONDS)
    except NativeRunnerAuthorityError as error:
        raise NativeAibomError(str(error)) from error


def _private_metadata_from_wire(item: Mapping[str, Any]) -> dict[str, object]:
    """The unredacted MCP arguments and environment a native kind passes privately."""

    private = item.get("runtime_private_metadata")
    if private is None:
        return {}
    if not isinstance(private, dict):
        raise NativeAibomError("native_runner_authority_result_invalid")
    if set(private) == {"managed_mcp_origin", "managed_guard_home"}:
        origin = private["managed_mcp_origin"]
        guard_home = private["managed_guard_home"]
        if (
            not isinstance(origin, list)
            or len(origin) != 2
            or not all(isinstance(value, str) for value in origin)
            or not isinstance(guard_home, str)
        ):
            raise NativeAibomError("native_runner_authority_result_invalid")
        return {"managed_mcp_origin": tuple(origin), "managed_guard_home": guard_home}
    args = private.get("mcp_args")
    environment = private.get("mcp_env")
    if (
        set(private) != {"mcp_args", "mcp_env"}
        or not isinstance(args, list)
        or not all(isinstance(value, str) for value in args)
        or not isinstance(environment, dict)
        or not all(isinstance(key, str) and isinstance(value, str) for key, value in environment.items())
    ):
        raise NativeAibomError("native_runner_authority_result_invalid")
    return {"mcp_args": tuple(args), "mcp_env": dict(environment)}


def _artifact_from_wire(item: object) -> GuardArtifact:
    if not isinstance(item, dict):
        raise NativeAibomError("native_runner_authority_result_invalid")
    texts = ("artifact_id", "name", "harness", "artifact_type", "source_scope", "config_path")
    optional = ("command", "url", "transport", "publisher")
    args = item.get("args")
    metadata = item.get("metadata")
    if (
        not all(isinstance(item.get(key), str) for key in texts)
        or not all(item.get(key) is None or isinstance(item.get(key), str) for key in optional)
        or not isinstance(args, list)
        or not all(isinstance(value, str) for value in args)
        or not isinstance(metadata, dict)
    ):
        raise NativeAibomError("native_runner_authority_result_invalid")
    return GuardArtifact(
        artifact_id=item["artifact_id"],
        name=item["name"],
        harness=item["harness"],
        artifact_type=item["artifact_type"],
        source_scope=item["source_scope"],
        config_path=item["config_path"],
        command=item["command"],
        args=tuple(args),
        url=item["url"],
        transport=item["transport"],
        publisher=item["publisher"],
        metadata=metadata,
        runtime_private_metadata=_private_metadata_from_wire(item),
    )


def native_adapter_detection(
    kind: str, request: Mapping[str, Any]
) -> tuple[tuple[GuardArtifact, ...], tuple[str, ...]]:
    """Run a native adapter-detection kind and return its artifacts and found paths."""

    artifacts, found_paths, _warnings = native_adapter_detection_with_warnings(kind, request)
    return artifacts, found_paths


def native_adapter_detection_with_warnings(
    kind: str, request: Mapping[str, Any]
) -> tuple[tuple[GuardArtifact, ...], tuple[str, ...], tuple[str, ...]]:
    """Run a native adapter-detection kind and return artifacts, found paths and warnings."""

    return detection_from_payload(_native(kind, request))


def native_adapter_detection_payload(kind: str, request: Mapping[str, Any]) -> dict[str, Any]:
    """The raw answer of a native adapter-detection kind, for a caller that may be asked again."""

    return _native(kind, request)


def detection_from_payload(
    payload: Mapping[str, Any],
) -> tuple[tuple[GuardArtifact, ...], tuple[str, ...], tuple[str, ...]]:
    """Artifacts, found paths and warnings from a native adapter-detection answer."""

    found_paths = payload.get("found_paths")
    if not isinstance(found_paths, list) or not all(isinstance(path, str) for path in found_paths):
        raise NativeAibomError("native_runner_authority_result_invalid")
    warnings = payload.get("warnings", [])
    if not isinstance(warnings, list) or not all(isinstance(warning, str) for warning in warnings):
        raise NativeAibomError("native_runner_authority_result_invalid")
    return _artifacts_from_payload(payload), tuple(found_paths), tuple(warnings)


def _artifacts_from_payload(payload: Mapping[str, Any]) -> tuple[GuardArtifact, ...]:
    items = payload.get("artifacts")
    if not isinstance(items, list):
        raise NativeAibomError("native_runner_authority_result_invalid")
    return tuple(_artifact_from_wire(item) for item in items)


def _workspace_request(harness: str, workspace_dir: Path) -> dict[str, object]:
    return {"harness": harness, "workspace_dir": anchor_to_process_directory(workspace_dir)}


def discover_shared_workspace_aibom_artifacts(
    harness: str,
    *,
    home_dir: Path,
    workspace_dir: Path,
) -> tuple[GuardArtifact, ...]:
    _ = home_dir  # Retained for API compatibility; skill containment is workspace-relative.
    payload = _native("aibom_workspace_artifacts", _workspace_request(harness, workspace_dir))
    return _artifacts_from_payload(payload)


def discover_codex_skill_artifacts(
    harness: str,
    *,
    home_dir: Path,
    workspace_dir: Path | None,
) -> tuple[GuardArtifact, ...]:
    user_home = os.path.expanduser("~")
    request: dict[str, object] = {
        "harness": harness,
        "home_dir": anchor_to_process_directory(home_dir),
        "workspace_dir": None if workspace_dir is None else anchor_to_process_directory(workspace_dir),
        "user_home": None if user_home == "~" else user_home,
    }
    return _artifacts_from_payload(_native("aibom_codex_skills", request))


def extend_codex_runtime_inventory(
    detection: HarnessDetection,
    *,
    home_dir: Path,
    workspace_dir: Path | None,
) -> HarnessDetection:
    """Replace Codex skill inventory with home + workspace discovery and enablement rules."""

    if detection.harness != "codex":
        return detection
    skill_artifacts = discover_codex_skill_artifacts(
        detection.harness,
        home_dir=home_dir,
        workspace_dir=workspace_dir,
    )
    merged = [artifact for artifact in detection.artifacts if artifact.artifact_type != "skill"]
    found_paths = list(detection.config_paths)
    for artifact in skill_artifacts:
        merged.append(artifact)
        found_paths.append(artifact.config_path)
    return HarnessDetection(
        harness=detection.harness,
        installed=detection.installed,
        command_available=detection.command_available,
        config_paths=tuple(dict.fromkeys(found_paths)),
        artifacts=tuple(merged),
        warnings=detection.warnings,
    )


def _merge_plan(detection: HarnessDetection, workspace_dir: Path) -> dict[str, Any]:
    request = _workspace_request(detection.harness, workspace_dir)
    request["existing"] = [
        {
            "artifact_id": artifact.artifact_id,
            "artifact_type": artifact.artifact_type,
            "harness": artifact.harness,
            "config_path": artifact.config_path if isinstance(artifact.config_path, str) else None,
        }
        for artifact in detection.artifacts
    ]
    return _native("aibom_workspace_plan", request)


def extend_detection_with_workspace_aibom(
    detection: HarnessDetection,
    *,
    home_dir: Path,
    workspace_dir: Path | None,
) -> HarnessDetection:
    if workspace_dir is None:
        return detection
    plan = _merge_plan(detection, workspace_dir)
    extra_count = plan.get("extra_count")
    replacements = plan.get("replacements")
    appended = plan.get("appended")
    found_paths = plan.get("found_paths")
    if (
        not isinstance(extra_count, int)
        or not isinstance(replacements, list)
        or not isinstance(appended, list)
        or not isinstance(found_paths, list)
        or not all(isinstance(path, str) for path in found_paths)
    ):
        raise NativeAibomError("native_runner_authority_result_invalid")
    if extra_count == 0:
        return detection
    merged = list(detection.artifacts)
    for replacement in replacements:
        index = replacement.get("index") if isinstance(replacement, dict) else None
        if not isinstance(index, int) or isinstance(index, bool) or not 0 <= index < len(merged):
            raise NativeAibomError("native_runner_authority_result_invalid")
        merged[index] = _artifact_from_wire(replacement.get("artifact"))
    merged.extend(_artifact_from_wire(item) for item in appended)
    return HarnessDetection(
        harness=detection.harness,
        installed=detection.installed,
        command_available=detection.command_available,
        config_paths=tuple(dict.fromkeys([*detection.config_paths, *found_paths])),
        artifacts=tuple(merged),
        warnings=detection.warnings,
    )
