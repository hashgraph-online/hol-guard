"""Requests the harness adapter base sends to the native ``harness_diagnostics`` kind."""

from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any, TypeVar

from .models import GuardArtifact, HarnessDetection

_T = TypeVar("_T")

# The native request parser refuses any JSON array wider than 4096 entries, so
# every list crosses in chunks that the runtime joins back in order.
_NATIVE_JSON_WIDTH = 4096


def _chunks(items: Sequence[_T]) -> list[list[_T]]:
    return [list(items[start : start + _NATIVE_JSON_WIDTH]) for start in range(0, len(items), _NATIVE_JSON_WIDTH)]


def _shown(artifact: GuardArtifact) -> dict[str, object]:
    serialized: dict[str, Any] = artifact.to_dict()
    serialized["args"] = _chunks(serialized.get("args") or [])
    return serialized


def _artifacts_request(artifacts: Sequence[GuardArtifact], *, shown: bool = False) -> list[list[dict[str, object]]]:
    return _chunks(
        [
            {
                "artifact_type": artifact.artifact_type,
                "command": artifact.command,
                "args": _chunks(artifact.args),
                "harness": artifact.harness,
                **({"serialized": _shown(artifact)} if shown else {}),
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


def _runtime_probe_request(runtime_probe: dict[str, object] | None) -> object:
    return None if runtime_probe is None else json.loads(json.dumps(runtime_probe, default=str))


def _harness_diagnostics(op: str, valid: Callable[[object], bool], **fields: object) -> Any:
    """The native ``harness_diagnostics`` answer to ``op``, which it returns under the op's own name."""

    from .native_runner_authority import NativeRunnerAuthorityError, native_runner_authority

    value = native_runner_authority("harness_diagnostics", {"op": op, **fields}).get(op)
    if not valid(value):
        raise NativeRunnerAuthorityError("harness diagnostics answer is malformed")
    return value


def guard_warnings(
    harness: str,
    executable: str,
    command_absence_proves_uninstalled: bool,
    detection: HarnessDetection,
    runtime_probe: dict[str, object] | None,
) -> list[str]:
    """The detection's own warnings followed by the ones the native runtime adds."""

    added = _harness_diagnostics(
        "warnings",
        lambda value: isinstance(value, list) and all(isinstance(item, str) for item in value),
        harness=harness,
        executable=executable,
        command_absence_proves_uninstalled=command_absence_proves_uninstalled,
        runtime_probe=_runtime_probe_request(runtime_probe),
        detection=_detection_request(detection),
    )
    return [*detection.warnings, *added]


def native_diagnostics(
    *,
    harness: str,
    executable: str,
    command_absence_proves_uninstalled: bool,
    guard_home: Path,
    launcher_names: Sequence[str],
    detection: HarnessDetection,
    runtime_probe: dict[str, object] | None,
    warnings: Sequence[str] | None,
) -> dict[str, object]:
    """The doctor report the native runtime builds for one detected harness.

    ``warnings`` is the final list a harness words itself, or ``None`` for the
    warnings the runtime words from the detection.
    """

    # The caller's working directory, for a relative Guard home, is not in the
    # resident request envelope yet, so a relative home is refused natively.
    return _harness_diagnostics(
        "diagnostics",
        lambda value: isinstance(value, dict),
        harness=harness,
        executable=executable,
        command_absence_proves_uninstalled=command_absence_proves_uninstalled,
        guard_home=str(guard_home),
        names=list(launcher_names),
        warnings=None if warnings is None else _chunks(warnings),
        runtime_probe=_runtime_probe_request(runtime_probe),
        detection={
            "installed": detection.installed,
            "command_available": detection.command_available,
            "config_paths": _chunks(detection.config_paths),
            "artifacts": _artifacts_request(detection.artifacts, shown=True),
            "warnings": _chunks(detection.warnings),
        },
    )


def shell_command(command: Sequence[str], *, windows: bool | None = None) -> str:
    """The shell command line the native runtime escapes ``command`` into."""

    return _harness_diagnostics(
        "shell_command",
        lambda value: isinstance(value, str),
        command=list(command),
        windows=windows,
    )


def artifacts_use_guard(artifacts: Sequence[GuardArtifact]) -> bool:
    """Whether any artifact is Guard's launcher, Guard's command, or a command line naming Guard."""

    if not artifacts:
        return False
    return _harness_diagnostics(
        "uses_guard", lambda value: isinstance(value, bool), artifacts=_artifacts_request(artifacts)
    )
