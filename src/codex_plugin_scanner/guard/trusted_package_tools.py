"""Narrow read-only profiles for package-run CLI trust."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import cast
from urllib.parse import urlparse

from .runtime.approval_context import build_runtime_launch_identity
from .runtime.command_model import CommandSegment
from .runtime.command_tokens import executable_name
from .runtime.secret_file_request_services.request_models import classify_sensitive_path


@dataclass(frozen=True, slots=True)
class TrustedPackageToolProfile:
    tool_name: str
    capability: str
    read_only_reason: str
    identity_material: Mapping[str, object]
    indefinite_allowed: bool


def trusted_package_tool_profile(
    segment: CommandSegment,
    *,
    cwd: Path,
    home_dir: Path | None,
) -> TrustedPackageToolProfile | None:
    if executable_name(segment.executable) not in {"npx", "bunx"}:
        return None
    if segment.path_overridden or segment.wrapper_chain:
        return None
    runner = _verified_runner_identity(segment, cwd=cwd)
    if runner is None:
        return None
    return _impeccable_profile(segment, cwd=cwd, home_dir=home_dir, runner=runner)


def _impeccable_profile(
    segment: CommandSegment,
    *,
    cwd: Path,
    home_dir: Path | None,
    runner: Mapping[str, object],
) -> TrustedPackageToolProfile | None:
    arguments = list(segment.arguments)
    if not arguments:
        return None
    package_selector = arguments.pop(0)
    if not _is_impeccable_selector(package_selector):
        return None
    if tuple(segment.environment_names) not in {(), ("IMPECCABLE_CONTEXT_DIR",)}:
        return None
    if segment.environment_names and not _safe_context_directory(segment, cwd=cwd, home_dir=home_dir):
        return None
    if arguments and arguments[0] == "detect":
        _ = arguments.pop(0)
    elif arguments and arguments[0] == "skills":
        return None
    if not arguments:
        return None
    option_shape: list[str] = []
    paths: list[str] = []
    for argument in arguments:
        if argument in {"--json", "--fast"}:
            option_shape.append(argument)
            continue
        if argument.startswith("-"):
            return None
        if not _safe_local_path(argument, cwd=cwd, home_dir=home_dir):
            return None
        paths.append(argument)
    if not paths:
        return None
    return TrustedPackageToolProfile(
        tool_name="impeccable",
        capability="scan",
        read_only_reason="profile_impeccable_scan",
        identity_material={
            "profile": "impeccable-local-scan:v1",
            "package": {
                "name": "impeccable",
                "selector": package_selector,
                "trust_mode": "continuous-package-policy-veto",
            },
            "runner": runner,
            "options": sorted(option_shape),
            "environment_names": list(segment.environment_names),
        },
        indefinite_allowed=bool(re.fullmatch(r"impeccable@\d+\.\d+\.\d+", package_selector)),
    )


def _is_impeccable_selector(value: str) -> bool:
    return value == "impeccable" or bool(re.fullmatch(r"impeccable@(?:latest|\d+\.\d+\.\d+)", value))


def _verified_runner_identity(segment: CommandSegment, *, cwd: Path) -> dict[str, object] | None:
    identity = build_runtime_launch_identity(
        segment.executable,
        args=segment.arguments,
        structured_command=True,
        cwd=cwd,
    )
    executable = identity.get("executable")
    if not isinstance(executable, Mapping):
        return None
    normalized = dict(cast(Mapping[str, object], executable))
    if normalized.get("status") != "verified":
        return None
    return _stable_identity_mapping(normalized)


def _stable_identity_mapping(value: Mapping[str, object]) -> dict[str, object]:
    return {
        str(key): _stable_identity_value(item)
        for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        if key not in {"argument_sha256", "reuse_nonce", "script_args_sha256"}
    }


def _stable_identity_value(value: object) -> object:
    if isinstance(value, Mapping):
        return _stable_identity_mapping(dict(cast(Mapping[str, object], value)))
    if isinstance(value, Sequence) and not isinstance(value, str):
        return [_stable_identity_value(item) for item in value]
    return value


def _safe_context_directory(segment: CommandSegment, *, cwd: Path, home_dir: Path | None) -> bool:
    prefix = next((token for token in segment.tokens if token.startswith("IMPECCABLE_CONTEXT_DIR=")), None)
    if prefix is None:
        return False
    return _safe_local_path(prefix.split("=", 1)[1], cwd=cwd, home_dir=home_dir, require_directory=True)


def _safe_local_path(
    value: str,
    *,
    cwd: Path,
    home_dir: Path | None,
    require_directory: bool = False,
) -> bool:
    if not value or urlparse(value).scheme or any(marker in value for marker in ("$", "`", "*", "?", "[")):
        return False
    if value == "~" or value.startswith("~/"):
        if home_dir is None:
            return False
        expanded = home_dir if value == "~" else home_dir / value.removeprefix("~/")
    else:
        expanded = Path(value)
    candidate = expanded if expanded.is_absolute() else cwd / expanded
    try:
        resolved = candidate.resolve(strict=True)
    except OSError:
        return False
    if require_directory and not resolved.is_dir():
        return False
    if not require_directory and not (resolved.is_file() or resolved.is_dir()):
        return False
    if classify_sensitive_path(str(resolved), cwd=cwd, home_dir=home_dir) is not None:
        return False
    in_workspace = resolved == cwd or cwd in resolved.parents
    in_home = home_dir is not None and (resolved == home_dir or home_dir in resolved.parents)
    return in_workspace or in_home


__all__: Sequence[str] = ("TrustedPackageToolProfile", "trusted_package_tool_profile")
