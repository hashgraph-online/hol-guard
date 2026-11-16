"""Requests the harness adapter base sends to the native ``harness_diagnostics`` kind."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Any, TypeVar

from ..models import GuardArtifact, HarnessDetection

_T = TypeVar("_T")

# The native request parser refuses any JSON array wider than 4096 entries, so
# every list crosses in chunks that the runtime joins back in order.
_NATIVE_JSON_WIDTH = 4096
_SETUP_STATUSES = ("active", "broken", "partial", "not_found")


def _chunks(items: Sequence[_T]) -> list[list[_T]]:
    return [list(items[start : start + _NATIVE_JSON_WIDTH]) for start in range(0, len(items), _NATIVE_JSON_WIDTH)]


def _artifacts_request(artifacts: Sequence[GuardArtifact]) -> list[list[dict[str, object]]]:
    return _chunks(
        [
            {
                "artifact_type": artifact.artifact_type,
                "command": artifact.command,
                "args": _chunks(artifact.args),
                "harness": artifact.harness,
            }
            for artifact in artifacts
        ]
    )


def _detection_request(detection: HarnessDetection) -> dict[str, object]:
    return {
        "config_paths": _chunks(detection.config_paths),
        "command_available": detection.command_available,
        "artifacts": _artifacts_request(detection.artifacts),
    }


def _harness_diagnostics(op: str, valid: Callable[[object], bool], **fields: object) -> Any:
    """The native ``harness_diagnostics`` answer to ``op``, which it returns under the op's own name."""

    from ..native_runner_authority import NativeRunnerAuthorityError, native_runner_authority

    value = native_runner_authority("harness_diagnostics", {"op": op, **fields}).get(op)
    if not valid(value):
        raise NativeRunnerAuthorityError("harness diagnostics answer is malformed")
    return value


def _launcher_artifact(payload: dict[str, Any]) -> GuardArtifact:
    """The Guard launcher artifact the native ``launcher_artifact`` answer describes."""

    from ..native_runner_authority import NativeRunnerAuthorityError

    keys = ("artifact_id", "name", "harness", "artifact_type", "source_scope", "config_path", "command")
    texts: list[str] = []
    for key in keys:
        value = payload.get(key)
        if not isinstance(value, str):
            raise NativeRunnerAuthorityError("harness diagnostics answer is malformed")
        texts.append(value)
    metadata = payload.get("metadata")
    if not isinstance(metadata, dict):
        raise NativeRunnerAuthorityError("harness diagnostics answer is malformed")
    artifact_id, name, harness, artifact_type, source_scope, config_path, command = texts
    return GuardArtifact(
        artifact_id=artifact_id,
        name=name,
        harness=harness,
        artifact_type=artifact_type,
        source_scope=source_scope,
        config_path=config_path,
        command=command,
        metadata=metadata,
    )


def _diagnostic_setup_status(
    detection: HarnessDetection,
    warnings: list[str],
    *,
    command_absence_proves_uninstalled: bool = True,
) -> str:
    return _harness_diagnostics(
        "setup_status",
        lambda value: value in _SETUP_STATUSES,
        command_absence_proves_uninstalled=command_absence_proves_uninstalled,
        detection=_detection_request(detection),
        warnings=_chunks(warnings),
    )


def artifacts_use_guard(artifacts: Sequence[GuardArtifact]) -> bool:
    """Whether any artifact is Guard's launcher, Guard's command, or a command line naming Guard."""

    if not artifacts:
        return False
    return _harness_diagnostics(
        "uses_guard", lambda value: isinstance(value, bool), artifacts=_artifacts_request(artifacts)
    )
