"""Execution-context recovery for dependency-bound local Node routines."""

from __future__ import annotations

import json
import os
import re
from collections.abc import Mapping
from pathlib import Path
from typing import cast

from .jsonc import loads_jsonc
from .secret_file_request_services.docker_requests import (
    _shell_execution_context_validation_reason,
    shell_execution_context_starts_with_literal_cd,
)
from .secret_file_request_services.shell_static_safety import _leading_literal_cd_workspace_root
from .secret_file_request_services.shell_tokenization import _shell_segment_primary_command
from .shell_execution_context import ShellExecutionContext, ShellExecutionSegment, model_shell_execution_context

_RUNNER_PACKAGES = {"eslint": "eslint", "next": "next", "tsc": "typescript"}
_WRITE_FLAGS = {
    "--cache",
    "--cache-location",
    "--fix",
    "--fix-dry-run",
    "--fix-type",
    "--output-file",
}
_ESLINT_FLAGS = {"--no-cache", "--no-error-on-unmatched-pattern", "--no-warn-ignored", "--quiet"}


def routine_local_node_execution_context(
    command_text: str,
    *,
    home_dir: Path,
) -> ShellExecutionContext | None:
    """Recover one literal workspace switch followed by a local validation routine."""

    if any(marker in command_text for marker in ("$(", "`", "<(", ">(")):
        return None
    initial = model_shell_execution_context(
        command_text,
        cwd=home_dir,
        workspace_root=home_dir,
        home_dir=home_dir,
    )
    workspace = _leading_literal_cd_workspace_root(initial, home_dir=home_dir)
    if workspace is None or workspace == home_dir.resolve():
        return None
    context = model_shell_execution_context(
        command_text,
        cwd=workspace,
        workspace_root=workspace,
        home_dir=home_dir,
    )
    if (
        not shell_execution_context_starts_with_literal_cd(context)
        or _shell_execution_context_validation_reason(context) is not None
        or len(context.segments) not in {2, 3}
    ):
        return None

    runner = context.segments[1]
    command_name, command_index = _shell_segment_primary_command(list(runner.tokens))
    if command_name not in _RUNNER_PACKAGES or command_index is None or runner.control_before != ("&&",):
        return None
    if not _safe_environment(list(runner.tokens[:command_index]), runner=command_name):
        return None
    executable_token = runner.tokens[command_index]
    if executable_token != f"./node_modules/.bin/{command_name}":
        return None
    args = list(runner.tokens[command_index + 1 :])
    if args[-1:] == ["2>&1"]:
        _ = args.pop()
    if not _routine_args(command_name, args):
        return None
    if not _workspace_runner_is_bound(workspace, runner=command_name):
        return None
    if len(context.segments) == 3 and not _bounded_output_filter(context.segments[2]):
        return None
    return context


def _safe_environment(tokens: list[str], *, runner: str) -> bool:
    if runner != "next":
        return not tokens
    remaining = list(tokens)
    if remaining and re.fullmatch(r"HOL_NEXT_BUILD_CPUS=([1-9]|[1-5][0-9]|6[0-4])", remaining[0]):
        _ = remaining.pop(0)
    if remaining and _safe_node_options(remaining[0]):
        _ = remaining.pop(0)
    return not remaining


def _safe_node_options(token: str) -> bool:
    match = re.fullmatch(r"NODE_OPTIONS=--max-old-space-size=([1-9][0-9]{2,4})", token)
    return match is not None and 256 <= int(match.group(1)) <= 32768


def _routine_args(runner: str, args: list[str]) -> bool:
    if runner == "next":
        return args == ["build", "--webpack"]
    if runner == "tsc":
        return _typescript_args(args)
    return _eslint_args(args)


def _typescript_args(args: list[str]) -> bool:
    if not args or args.count("--noEmit") != 1:
        return False
    remaining = list(args)
    _ = remaining.pop(remaining.index("--noEmit"))
    if remaining[:2] == ["--pretty", "false"]:
        del remaining[:2]
    if remaining and remaining[0] in {"-p", "--project"}:
        _ = remaining.pop(0)
        if not remaining or not _safe_relative_config(remaining.pop(0)):
            return False
    return not remaining


def _eslint_args(args: list[str]) -> bool:
    if not args or any(
        token in _WRITE_FLAGS or any(token.startswith(f"{flag}=") for flag in _WRITE_FLAGS) for token in args
    ):
        return False
    targets: list[str] = []
    index = 0
    while index < len(args):
        token = args[index]
        if token in _ESLINT_FLAGS:
            index += 1
            continue
        if token == "--max-warnings":
            if index + 1 >= len(args) or not args[index + 1].isdigit():
                return False
            index += 2
            continue
        if token.startswith("-") or _dynamic_or_external(token):
            return False
        targets.append(token)
        index += 1
    return bool(targets)


def _safe_relative_config(token: str) -> bool:
    path = Path(token)
    return not path.is_absolute() and ".." not in path.parts and path.suffix == ".json"


def _dynamic_or_external(token: str) -> bool:
    return token.startswith(("/", "~")) or "$" in token or "`" in token or ".." in Path(token).parts


def _bounded_output_filter(segment: ShellExecutionSegment) -> bool:
    tokens = list(segment.tokens)
    control_before = segment.control_before
    name, index = _shell_segment_primary_command(tokens)
    if name not in {"head", "tail"} or index is None or control_before != ("|",):
        return False
    args = tokens[index + 1 :]
    return len(args) == 1 and bool(re.fullmatch(r"-[1-9][0-9]{0,2}", args[0]))


def _workspace_runner_is_bound(workspace: Path, *, runner: str) -> bool:
    package_name = _RUNNER_PACKAGES[runner]
    package_dir = workspace / "node_modules" / package_name
    package = _read_package_json(package_dir / "package.json")
    if package is None or package.get("name") != package_name:
        return False
    installed_version = package.get("version")
    declared_version = _declared_dependency_version(workspace, package_name)
    lockfiles = [workspace / name for name in ("bun.lock", "package-lock.json") if (workspace / name).exists()]
    if not isinstance(installed_version, str) or declared_version is None or len(lockfiles) != 1:
        return False
    locked_version = _locked_package_version(lockfiles[0], package_name)
    if locked_version != installed_version or not _semver_spec_matches(declared_version, installed_version):
        return False
    target = _package_bin_target(package, runner)
    if target is None:
        return False
    try:
        workspace_root = workspace.resolve(strict=True)
        package_root = package_dir.resolve(strict=True)
        executable = (workspace / "node_modules" / ".bin" / runner).resolve(strict=True)
        expected = (package_dir / target).resolve(strict=True)
        _ = package_root.relative_to(workspace_root)
        _ = executable.relative_to(package_root)
    except (OSError, RuntimeError, ValueError):
        return False
    return executable == expected and executable.is_file() and os.access(executable, os.X_OK)


def _package_bin_target(package: dict[str, object], runner: str) -> str | None:
    value = package.get("bin")
    if isinstance(value, str):
        return value if runner == package.get("name") else None
    if isinstance(value, Mapping):
        target = cast(Mapping[object, object], value).get(runner)
        return target if isinstance(target, str) else None
    return None


def _read_package_json(path: Path) -> dict[str, object] | None:
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 16 * 1024 * 1024:
            return None
        payload = cast(object, json.loads(path.read_text(encoding="utf-8")))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    typed = cast(dict[object, object], payload)
    return {key: value for key, value in typed.items() if isinstance(key, str)}


def _declared_dependency_version(workspace: Path, package_name: str) -> str | None:
    package = _read_package_json(workspace / "package.json")
    if package is None:
        return None
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        dependencies = package.get(section)
        if not isinstance(dependencies, Mapping):
            continue
        declared = cast(Mapping[object, object], dependencies).get(package_name)
        if isinstance(declared, str):
            return declared
    return None


def _locked_package_version(path: Path, package_name: str) -> str | None:
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 16 * 1024 * 1024:
            return None
        text = path.read_text(encoding="utf-8")
        lock = cast(object, loads_jsonc(text) if path.name == "bun.lock" else json.loads(text))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    if not isinstance(lock, dict):
        return None
    packages = cast(dict[object, object], lock).get("packages")
    if not isinstance(packages, dict):
        return None
    entries = cast(dict[object, object], packages)
    entry = entries.get(package_name if path.name == "bun.lock" else f"node_modules/{package_name}")
    if path.name == "bun.lock":
        if not isinstance(entry, list) or not entry or not isinstance(entry[0], str):
            return None
        prefix = f"{package_name}@"
        return entry[0][len(prefix) :] if entry[0].startswith(prefix) else None
    if not isinstance(entry, dict):
        return None
    version = cast(dict[object, object], entry).get("version")
    return version if isinstance(version, str) else None


def _semver_spec_matches(specifier: str, version: str) -> bool:
    if specifier == version and re.fullmatch(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?", version):
        return True
    requested = re.fullmatch(r"([~^]?)(\d+)\.(\d+)\.(\d+)", specifier)
    installed = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", version)
    if requested is None or installed is None:
        return False
    operator, major, minor, patch = requested.groups()
    minimum = (int(major), int(minor), int(patch))
    actual = tuple(int(value) for value in installed.groups())
    if actual < minimum:
        return False
    if operator == "^":
        return actual[0] == minimum[0] if minimum[0] else actual[:2] == minimum[:2]
    if operator == "~":
        return actual[:2] == minimum[:2]
    return actual == minimum


__all__ = ("routine_local_node_execution_context",)
