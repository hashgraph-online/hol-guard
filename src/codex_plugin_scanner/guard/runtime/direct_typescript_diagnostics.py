"""Proof-backed recognition for local TypeScript diagnostic filters."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Protocol

from .github_actions_read_workflow import shell_read_execution_environment_is_safe
from .shell_execution_context import ShellExecutionContext

_PATH_COMPONENT = r"(?:[A-Za-z0-9_-]|\\\.)+"
_TYPESCRIPT_DIAGNOSTIC_PATH_FILTER = re.compile(
    rf"^{_PATH_COMPONENT}(?:/{_PATH_COMPONENT})*(?:\|{_PATH_COMPONENT}(?:/{_PATH_COMPONENT})*)*$"
)
_NODE_CODE_LOADING_ENVIRONMENT = frozenset({"node_options", "node_path"})
_NPM_NON_EXECUTION_KEYS = frozenset(
    {
        "always-auth",
        "audit",
        "color",
        "fund",
        "loglevel",
        "progress",
        "registry",
        "strict-ssl",
    }
)
_NPM_REGISTRY_AUTH_SUFFIXES = (
    ":-auth",
    ":-authtoken",
    ":-password",
    ":always-auth",
    ":email",
    ":username",
)
_MAX_NPM_CONFIG_BYTES = 64 * 1024


class TrustedPathCommand(Protocol):
    def __call__(self, command: str, *, cwd: Path, home_dir: Path) -> bool: ...


def direct_typescript_diagnostic_filter_context(
    context: ShellExecutionContext,
    *,
    workspace: Path,
    home_dir: Path,
    trusted_path_command: TrustedPathCommand,
    workspace_typescript_is_bound: WorkspaceTypeScriptBinding,
) -> ShellExecutionContext | None:
    if not context.complete or len(context.segments) != 4:
        return None
    directory, compiler, grep, marker = context.segments
    if (
        directory.directory_operation != "cd"
        or directory.control_before
        or compiler.control_before != ("&&",)
        or compiler.effective_cwd != workspace
        or grep.control_before != ("|",)
        or marker.control_before != ("||",)
    ):
        return None
    compiler_tokens = list(compiler.tokens)
    if compiler_tokens[-1:] != ["2>&1"]:
        return None
    _ = compiler_tokens.pop()
    if (
        compiler_tokens != ["npx", "tsc", "--noEmit"]
        or not shell_read_execution_environment_is_safe(cwd=workspace)
        or _node_execution_environment_is_configurable(workspace, home_dir)
        or not trusted_path_command("npx", cwd=workspace, home_dir=home_dir)
        or not trusted_path_command("node", cwd=workspace, home_dir=home_dir)
        or not workspace_typescript_is_bound(workspace)
        or not _workspace_npx_typescript_runner_is_bound(workspace)
    ):
        return None
    if (
        len(grep.tokens) != 3
        or grep.tokens[:2] != ("grep", "-E")
        or len(grep.tokens[2]) > 512
        or _TYPESCRIPT_DIAGNOSTIC_PATH_FILTER.fullmatch(grep.tokens[2]) is None
        or not trusted_path_command("grep", cwd=workspace, home_dir=home_dir)
    ):
        return None
    if marker.tokens != ("echo", "NO_ERRORS_IN_TOUCHED_FILES"):
        return None
    return context


def _node_execution_environment_is_configurable(workspace: Path, home_dir: Path) -> bool:
    for key, value in os.environ.items():
        normalized_key = key.casefold()
        if value and (normalized_key in _NODE_CODE_LOADING_ENVIRONMENT or normalized_key.startswith("npm_config_")):
            return True
    return any(_npm_configuration_can_load_code(path) for path in (workspace / ".npmrc", home_dir / ".npmrc"))


def _npm_configuration_can_load_code(path: Path) -> bool:
    try:
        if not path.exists():
            return False
        if not path.is_file() or path.stat().st_size > _MAX_NPM_CONFIG_BYTES:
            return True
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        return True
    for line in lines:
        candidate = line.strip()
        if not candidate or candidate.startswith(("#", ";")):
            continue
        key, separator, _value = candidate.partition("=")
        if not separator:
            return True
        normalized_key = key.strip().casefold().replace("_", "-")
        if not _npm_configuration_key_is_nonexecuting(normalized_key):
            return True
    return False


def _npm_configuration_key_is_nonexecuting(key: str) -> bool:
    if key in _NPM_NON_EXECUTION_KEYS:
        return True
    if key.startswith("@") and key.endswith(":registry"):
        return True
    return key.startswith("//") and key.endswith(_NPM_REGISTRY_AUTH_SUFFIXES)


class WorkspaceTypeScriptBinding(Protocol):
    def __call__(self, workspace: Path) -> bool: ...


def _workspace_npx_typescript_runner_is_bound(workspace: Path) -> bool:
    bin_entry = workspace / "node_modules" / ".bin" / "tsc"
    compiler = workspace / "node_modules" / "typescript" / "bin" / "tsc"
    try:
        return bin_entry.is_symlink() and bin_entry.resolve(strict=True) == compiler.resolve(strict=True)
    except (OSError, RuntimeError):
        return False
