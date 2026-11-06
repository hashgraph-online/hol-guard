"""Trusted Grok executable discovery and registration.

The native runtime (`grok-executable --stdin`) verifies the launcher's
location, ownership and content hash, keeps the registration and builds the
launch environment. This module finds the PATH candidate and frames requests.
"""

from __future__ import annotations

import os
import shutil
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, cast

from ..mdm.runtime_request import runtime_answer
from .base import HarnessContext, _which_from_user_directories

_FEATURE = "native-grok-executable-v1"
_COMMAND = "grok-executable"
_SCHEMA = "grok-executable.v1"
_OUTPUT_LIMIT = 256 * 1024
_TIMEOUT_SECONDS = 30.0
_GROK_EXECUTABLE_NAMES = ("grok",)
_GROK_WINDOWS_EXECUTABLE_NAMES = ("grok.exe", "grok.cmd", "grok.bat", "grok.com")
_WINDOWS_ROOT_VARIABLES = ("ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA")
_UNAVAILABLE = "The Guard runtime could not verify the Grok executable."
_SOURCES = ("automatic", "explicit", "registration")

GrokExecutableSource = Literal["automatic", "explicit", "registration"]


@dataclass(frozen=True, slots=True)
class TrustedGrokExecutable:
    """An absolute Grok launcher whose path and content were locally verified."""

    path: Path
    content_sha256: str
    source: GrokExecutableSource


@dataclass(frozen=True, slots=True)
class GrokExecutableResolution:
    """Trusted executable resolution or a non-sensitive rejection reason."""

    executable: TrustedGrokExecutable | None
    error: str | None = None


def grok_executable_names(*, windows: bool | None = None) -> tuple[str, ...]:
    """Return platform-specific Grok command names, including Windows shims."""

    is_windows = os.name == "nt" if windows is None else windows
    return _GROK_WINDOWS_EXECUTABLE_NAMES if is_windows else _GROK_EXECUTABLE_NAMES


def resolve_trusted_grok_executable(context: HarnessContext) -> GrokExecutableResolution:
    """Resolve Grok without accepting workspace or relative PATH executables."""

    explicit = context.executable_overrides.get("grok")
    fields: dict[str, object] = {"candidate": _which_grok(context.home_dir)}
    if isinstance(explicit, str):
        fields["explicit"] = explicit
    answer = _answer("resolve", context, fields)
    return _UNAVAILABLE_RESOLUTION if answer is None else _resolution(answer)


def register_trusted_grok_executable(
    context: HarnessContext,
    executable: TrustedGrokExecutable,
) -> TrustedGrokExecutable:
    """Persist an explicitly selected executable and bind it to its content hash."""

    answer = _answer("register", context, {"path": str(executable.path)})
    if answer is None:
        raise OSError(_UNAVAILABLE)
    resolution = _resolution(answer)
    if resolution.executable is not None:
        return resolution.executable
    message = resolution.error or "The selected Grok executable is no longer trusted."
    if answer.get("trusted") is True:
        raise OSError(message)
    raise FileNotFoundError(message)


def sanitized_grok_launch_environment(
    context: HarnessContext,
    inherited: Mapping[str, str],
) -> dict[str, str]:
    """Remove code-loader variables and unsafe PATH entries for the Grok process."""

    answer = _answer(
        "launch-env",
        context,
        {
            "path_value": inherited.get("PATH"),
            "grok_home": inherited.get("GROK_HOME"),
            "env_keys": sorted(inherited),
        },
    )
    path = None if answer is None else answer.get("path")
    dropped = None if answer is None else answer.get("drop")
    if not isinstance(path, str) or not isinstance(dropped, list):
        raise OSError(_UNAVAILABLE)
    removed = {key for key in cast(list[object], dropped) if isinstance(key, str)}
    environment = {key: value for key, value in inherited.items() if key not in removed}
    environment["PATH"] = path
    return environment


_UNAVAILABLE_RESOLUTION = GrokExecutableResolution(None, _UNAVAILABLE)


def _which_grok(home: Path) -> str | None:
    for name in grok_executable_names():
        candidate = shutil.which(name) or _which_from_user_directories(name, home)
        if candidate is not None:
            return candidate
    return None


def _answer(op: str, context: HarnessContext, fields: Mapping[str, object]) -> dict[str, object] | None:
    workspace = context.workspace_dir
    request: dict[str, object] = {
        "schema": _SCHEMA,
        "op": op,
        "guard_home": str(context.guard_home.absolute()),
        "home_dir": str(context.home_dir.absolute()),
        "workspace_dir": None if workspace is None else str(workspace.absolute()),
        "cwd": str(Path.cwd()),
        "windows_roots": _windows_roots(),
    }
    request.update({key: value for key, value in fields.items() if value is not None})
    return runtime_answer(
        _FEATURE,
        _COMMAND,
        request,
        output_limit=_OUTPUT_LIMIT,
        timeout_seconds=_TIMEOUT_SECONDS,
    )


def _windows_roots() -> list[str]:
    if os.name != "nt":
        return []
    return [value for name in _WINDOWS_ROOT_VARIABLES if (value := os.environ.get(name))]


def _resolution(answer: Mapping[str, object]) -> GrokExecutableResolution:
    executable = answer.get("executable")
    error = answer.get("error")
    if isinstance(executable, dict):
        fields = cast(dict[str, object], executable)
        path = fields.get("path")
        digest = fields.get("content_sha256")
        source = fields.get("source")
        if isinstance(path, str) and isinstance(digest, str) and source in _SOURCES:
            trusted = TrustedGrokExecutable(Path(path), digest, source)
            return GrokExecutableResolution(trusted)
    elif executable is None and isinstance(error, str):
        return GrokExecutableResolution(None, error)
    return _UNAVAILABLE_RESOLUTION


__all__ = [
    "GrokExecutableResolution",
    "TrustedGrokExecutable",
    "grok_executable_names",
    "register_trusted_grok_executable",
    "resolve_trusted_grok_executable",
    "sanitized_grok_launch_environment",
]
