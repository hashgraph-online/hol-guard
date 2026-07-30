"""Proof-backed recognition for local TypeScript diagnostic filters."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Protocol

from .shell_execution_context import ShellExecutionContext

_PATH_COMPONENT = r"(?:[A-Za-z0-9_-]|\\\.)+"
_TYPESCRIPT_DIAGNOSTIC_PATH_FILTER = re.compile(
    rf"^{_PATH_COMPONENT}(?:/{_PATH_COMPONENT})*(?:\|{_PATH_COMPONENT}(?:/{_PATH_COMPONENT})*)*$"
)


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
        or not trusted_path_command("npx", cwd=workspace, home_dir=home_dir)
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


class WorkspaceTypeScriptBinding(Protocol):
    def __call__(self, workspace: Path) -> bool: ...


def _workspace_npx_typescript_runner_is_bound(workspace: Path) -> bool:
    bin_entry = workspace / "node_modules" / ".bin" / "tsc"
    compiler = workspace / "node_modules" / "typescript" / "bin" / "tsc"
    try:
        return bin_entry.is_symlink() and bin_entry.resolve(strict=True) == compiler.resolve(strict=True)
    except (OSError, RuntimeError):
        return False
